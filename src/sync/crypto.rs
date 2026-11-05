//! Device keys (Ed25519 for signing, converted to X25519 for sealing), sealed envelopes and the request signing string.
use anyhow::{Context, bail};
use chacha20poly1305::aead::{Aead, KeyInit, Payload as AeadPayload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use data_encoding::BASE64;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

const MSG_INFO: &[u8] = b"lzssh-msg-v1";

/// This device's identity. The seed is the 32-byte secret stored (DPAPI-wrapped) in device.json.
#[derive(Clone)]
pub struct DeviceKeys {
    signing: SigningKey,
}

impl DeviceKeys {
    pub fn from_secret(seed: &[u8; 32]) -> DeviceKeys {
        DeviceKeys { signing: SigningKey::from_bytes(seed) }
    }

    /// Lowercase hex public key: the device ID and its mailbox name.
    pub fn id(&self) -> String {
        hex::encode(self.signing.verifying_key().as_bytes())
    }

    pub fn public(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }

    fn x25519(&self) -> StaticSecret {
        StaticSecret::from(self.signing.to_scalar_bytes())
    }
}

/// Parses a hex device ID into its Ed25519 public key.
pub fn parse_id(id: &str) -> anyhow::Result<VerifyingKey> {
    let b: [u8; 32] = hex::decode(id).ok().and_then(|b| b.try_into().ok()).context("invalid device ID")?;
    VerifyingKey::from_bytes(&b).context("invalid device ID")
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    PairRequest,
    PairAccept,
    Payload,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::PairRequest => "pair_request",
            Kind::PairAccept => "pair_accept",
            Kind::Payload => "payload",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub v: u8,
    pub id: String,
    pub from: String,
    pub to: String,
    pub kind: Kind,
    pub salt: String,
    pub nonce: String,
    pub ct: String,
}

fn cipher(me: &DeviceKeys, peer: &str, salt: &[u8]) -> anyhow::Result<XChaCha20Poly1305> {
    let peer_x = XPublic::from(parse_id(peer)?.to_montgomery().to_bytes());
    let shared = me.x25519().diffie_hellman(&peer_x);
    anyhow::ensure!(shared.was_contributory(), "invalid device key");
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), shared.as_bytes()).expand(MSG_INFO, &mut key[..]).expect("32 bytes is a valid HKDF length");
    Ok(XChaCha20Poly1305::new_from_slice(&key[..]).expect("key is 32 bytes"))
}

fn aad(from: &str, to: &str, kind: Kind) -> String {
    format!("{from}|{to}|{}", kind.as_str())
}

/// Encrypts `plaintext` from this device to device `to`.
pub fn seal(me: &DeviceKeys, to: &str, kind: Kind, plaintext: &[u8]) -> anyhow::Result<Envelope> {
    let salt: [u8; 32] = crate::vault::random();
    let nonce: [u8; 24] = crate::vault::random();
    let from = me.id();
    let ad = aad(&from, to, kind);
    let ct = cipher(me, to, &salt)?
        .encrypt(&XNonce::from(nonce), AeadPayload { msg: plaintext, aad: ad.as_bytes() })
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    Ok(Envelope {
        v: 1,
        id: uuid::Uuid::new_v4().to_string(),
        from,
        to: to.to_string(),
        kind,
        salt: BASE64.encode(&salt),
        nonce: BASE64.encode(&nonce),
        ct: BASE64.encode(&ct),
    })
}

/// Decrypts an envelope addressed to this device; success also proves it came from `env.from`.
pub fn open(me: &DeviceKeys, env: &Envelope) -> anyhow::Result<Vec<u8>> {
    if env.v != 1 || env.to != me.id() {
        bail!("message is not for this device");
    }
    let salt = BASE64.decode(env.salt.as_bytes()).context("bad salt")?;
    let nonce: [u8; 24] = BASE64.decode(env.nonce.as_bytes()).ok().and_then(|n| n.try_into().ok()).context("bad nonce")?;
    let ct = BASE64.decode(env.ct.as_bytes()).context("bad ciphertext")?;
    let ad = aad(&env.from, &env.to, env.kind);
    cipher(me, &env.from, &salt)?
        .decrypt(&XNonce::from(nonce), AeadPayload { msg: &ct, aad: ad.as_bytes() })
        .map_err(|_| anyhow::anyhow!("message could not be decrypted"))
}

/// `lzssh-req-v1\n METHOD \n PATH \n TIME \n hex(sha256(body))`, shared with the Worker.
pub fn signing_string(method: &str, path: &str, time: u64, body: &[u8]) -> String {
    format!("lzssh-req-v1\n{method}\n{path}\n{time}\n{}", hex::encode(Sha256::digest(body)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    fn keys(b: u8) -> DeviceKeys {
        DeviceKeys::from_secret(&[b; 32])
    }

    #[test]
    fn id_matches_iroh_style_hex() {
        let k = keys(7);
        assert_eq!(k.id(), hex::encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes()));
        assert_eq!(k.id().len(), 64);
    }

    #[test]
    fn seal_open_roundtrip() {
        let (a, b) = (keys(1), keys(2));
        let e = seal(&a, &b.id(), Kind::Payload, b"hi").unwrap();
        assert_eq!(e.from, a.id());
        assert_eq!(open(&b, &e).unwrap(), b"hi");
    }

    #[test]
    fn wrong_recipient_fails() {
        let (a, b, c) = (keys(1), keys(2), keys(3));
        let mut e = seal(&a, &b.id(), Kind::Payload, b"hi").unwrap();
        assert!(open(&c, &e).is_err());
        e.to = c.id();
        assert!(open(&c, &e).is_err());
    }

    #[test]
    fn changed_aad_fails() {
        let (a, b, c) = (keys(1), keys(2), keys(3));
        let e = seal(&a, &b.id(), Kind::PairRequest, b"hi").unwrap();
        assert!(open(&b, &Envelope { kind: Kind::PairAccept, ..e.clone() }).is_err());
        assert!(open(&b, &Envelope { from: c.id(), ..e }).is_err());
    }

    #[test]
    fn kind_serializes_snake_case() {
        assert_eq!(serde_json::to_string(&Kind::PairRequest).unwrap(), "\"pair_request\"");
        assert_eq!(serde_json::to_string(&Kind::PairAccept).unwrap(), "\"pair_accept\"");
    }

    #[test]
    fn signing_string_exact() {
        assert_eq!(
            signing_string("POST", "/v1/mailbox/ab", 1700000000, b"{}"),
            "lzssh-req-v1\nPOST\n/v1/mailbox/ab\n1700000000\n44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
    }

    #[test]
    fn signature_verifies() {
        let k = keys(5);
        let sig = ed25519_dalek::Signature::from_bytes(&k.sign(b"msg"));
        assert!(parse_id(&k.id()).unwrap().verify(b"msg", &sig).is_ok());
    }
}

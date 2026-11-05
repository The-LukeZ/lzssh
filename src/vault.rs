//! PIN-protected secrets vault: Argon2id(PIN) key, XChaCha20-Poly1305 per value, DPAPI file wrap.
use crate::dpapi;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretKind {
    SshKey,
    FidoKey,
    Password,
}

impl SecretKind {
    pub fn label(self) -> &'static str {
        match self {
            SecretKind::SshKey => "SSH key",
            SecretKind::FidoKey => "FIDO key",
            SecretKind::Password => "Password",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlainSecret {
    pub id: Uuid,
    pub name: String,
    pub kind: SecretKind,
    pub public_key: Option<String>,
    pub material: Zeroizing<Vec<u8>>,
    pub passphrase: Option<Zeroizing<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMeta {
    pub id: Uuid,
    pub name: String,
    pub kind: SecretKind,
    pub public_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VaultError {
    #[error("PIN must be 6 digits")]
    InvalidPin,
    #[error("Wrong PIN")]
    WrongPin,
    #[error("Secret missing")]
    NotFound,
    #[error("Vault file is corrupt: {0}")]
    Corrupt(String),
    #[error("Vault I/O error: {0}")]
    Io(String),
}

/// Trims surrounding whitespace (pasted PINs often carry a newline) and requires 6 ASCII digits.
pub fn normalize_pin(input: &str) -> Result<String, VaultError> {
    let p = input.trim();
    if p.len() == 6 && p.bytes().all(|b| b.is_ascii_digit()) {
        Ok(p.to_string())
    } else {
        Err(VaultError::InvalidPin)
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct Entry {
    id: Uuid,
    name: String,
    kind: SecretKind,
    public_key: Option<String>,
    nonce: String,
    ct: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pp_nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pp_ct: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct FileFormat {
    version: u32,
    salt: String,
    check: String,
    entries: Vec<Entry>,
}

const CHECK: &[u8] = b"lzssh-ok";

pub struct Vault {
    path: PathBuf,
    salt: [u8; 16],
    key: Zeroizing<[u8; 32]>,
    /// `b64(nonce).b64(ct)` of CHECK; failing to decrypt it means a wrong PIN.
    check: String,
    entries: Vec<Entry>,
}

pub(crate) fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::fill(&mut b[..]);
    b
}

fn derive(pin: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let params = Params::new(64 * 1024, 3, 1, Some(32)).map_err(|e| VaultError::Corrupt(e.to_string()))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pin.as_bytes(), salt, &mut key[..])
        .map_err(|e| VaultError::Corrupt(e.to_string()))?;
    Ok(key)
}

fn b64d(s: &str) -> Result<Vec<u8>, VaultError> {
    BASE64.decode(s.as_bytes()).map_err(|e| VaultError::Corrupt(e.to_string()))
}

impl Vault {
    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new_from_slice(&self.key[..]).expect("key is 32 bytes")
    }

    fn seal(&self, plain: &[u8]) -> (String, String) {
        let nonce: [u8; 24] = random();
        let ct = self.cipher().encrypt(&XNonce::from(nonce), plain).expect("XChaCha20 encryption cannot fail");
        (BASE64.encode(&nonce), BASE64.encode(&ct))
    }

    fn open(&self, nonce: &str, ct: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let n: [u8; 24] = b64d(nonce)?.try_into().map_err(|_| VaultError::Corrupt("bad nonce".into()))?;
        let pt = self
            .cipher()
            .decrypt(&XNonce::from(n), b64d(ct)?.as_slice())
            .map_err(|_| VaultError::Corrupt("decryption failed".into()))?;
        Ok(Zeroizing::new(pt))
    }

    pub fn exists(path: &Path) -> bool {
        path.is_file()
    }

    pub fn create(path: &Path, pin: &str) -> Result<Vault, VaultError> {
        let pin = normalize_pin(pin)?;
        let salt: [u8; 16] = random();
        let key = derive(&pin, &salt)?;
        let mut v = Vault { path: path.to_path_buf(), salt, key, check: String::new(), entries: vec![] };
        let (n, c) = v.seal(CHECK);
        v.check = format!("{n}.{c}");
        Ok(v)
    }

    pub fn unlock(path: &Path, pin: &str) -> Result<Vault, VaultError> {
        let pin = normalize_pin(pin)?;
        let raw = std::fs::read(path).map_err(|e| VaultError::Io(e.to_string()))?;
        let json = dpapi::unprotect(&raw).map_err(|e| VaultError::Corrupt(e.to_string()))?;
        let f: FileFormat = serde_json::from_slice(&json).map_err(|e| VaultError::Corrupt(e.to_string()))?;
        let salt: [u8; 16] = b64d(&f.salt)?.try_into().map_err(|_| VaultError::Corrupt("bad salt".into()))?;
        let key = derive(&pin, &salt)?;
        let v = Vault { path: path.to_path_buf(), salt, key, check: f.check, entries: f.entries };
        let (n, c) = v.check.split_once('.').ok_or_else(|| VaultError::Corrupt("bad check".into()))?;
        match v.open(n, c) {
            Ok(pt) if pt.as_slice() == CHECK => Ok(v),
            _ => Err(VaultError::WrongPin),
        }
    }

    pub fn list(&self) -> Vec<SecretMeta> {
        self.entries
            .iter()
            .map(|e| SecretMeta { id: e.id, name: e.name.clone(), kind: e.kind, public_key: e.public_key.clone() })
            .collect()
    }

    pub fn meta(&self, id: Uuid) -> Option<SecretMeta> {
        self.list().into_iter().find(|m| m.id == id)
    }

    pub fn get(&self, id: Uuid) -> Result<PlainSecret, VaultError> {
        let e = self.entries.iter().find(|e| e.id == id).ok_or(VaultError::NotFound)?;
        let material = self.open(&e.nonce, &e.ct)?;
        let passphrase = match (&e.pp_nonce, &e.pp_ct) {
            (Some(n), Some(c)) => {
                let b = self.open(n, c)?;
                let s = String::from_utf8(b.to_vec()).map_err(|e| VaultError::Corrupt(e.to_string()))?;
                Some(Zeroizing::new(s))
            }
            _ => None,
        };
        Ok(PlainSecret { id: e.id, name: e.name.clone(), kind: e.kind, public_key: e.public_key.clone(), material, passphrase })
    }

    pub fn upsert(&mut self, s: PlainSecret) -> Result<(), VaultError> {
        let (nonce, ct) = self.seal(&s.material);
        let (pp_nonce, pp_ct) = match &s.passphrase {
            Some(p) if !p.is_empty() => {
                let (n, c) = self.seal(p.as_bytes());
                (Some(n), Some(c))
            }
            _ => (None, None),
        };
        let e = Entry { id: s.id, name: s.name, kind: s.kind, public_key: s.public_key, nonce, ct, pp_nonce, pp_ct };
        match self.entries.iter_mut().find(|x| x.id == e.id) {
            Some(x) => *x = e,
            None => self.entries.push(e),
        }
        Ok(())
    }

    pub fn remove(&mut self, id: Uuid) {
        self.entries.retain(|e| e.id != id);
    }

    pub fn save(&self) -> Result<(), VaultError> {
        let f = FileFormat { version: 1, salt: BASE64.encode(&self.salt), check: self.check.clone(), entries: self.entries.clone() };
        let json = serde_json::to_vec(&f).map_err(|e| VaultError::Io(e.to_string()))?;
        let wrapped = dpapi::protect(&json).map_err(|e| VaultError::Io(e.to_string()))?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, wrapped).map_err(|e| VaultError::Io(e.to_string()))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| VaultError::Io(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use zeroize::Zeroizing;

    fn key_secret() -> PlainSecret {
        PlainSecret {
            id: Uuid::new_v4(),
            name: "id_ed25519".into(),
            kind: SecretKind::SshKey,
            public_key: Some("ssh-ed25519 AAAA test".into()),
            material: Zeroizing::new(b"-----BEGIN OPENSSH PRIVATE KEY-----SECRETMATERIAL".to_vec()),
            passphrase: Some(Zeroizing::new("pw".into())),
        }
    }

    #[test] fn normalize_pin_trims_paste() { assert_eq!(normalize_pin(" 123456\r\n").unwrap(), "123456"); }
    #[test] fn normalize_pin_rejects_bad() { for p in ["12345","1234567","12a456",""] { assert!(matches!(normalize_pin(p), Err(VaultError::InvalidPin))); } }
    #[test] fn invalid_pin_message() { assert_eq!(VaultError::InvalidPin.to_string(), "PIN must be 6 digits"); }

    #[test] fn vault_create_unlock_roundtrip() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("secrets.json");
        assert!(!Vault::exists(&p));
        let mut v = Vault::create(&p, "123456").unwrap();
        let s = key_secret();
        v.upsert(s.clone()).unwrap();
        v.save().unwrap();
        assert!(Vault::exists(&p));
        let v2 = Vault::unlock(&p, "123456\n").unwrap();
        let g = v2.get(s.id).unwrap();
        assert_eq!(*g.material, *s.material);
        assert_eq!(g.passphrase.as_deref().map(|x| x.as_str()), Some("pw"));
        assert_eq!(v2.list().len(), 1);
        assert_eq!(v2.list()[0].public_key.as_deref(), Some("ssh-ed25519 AAAA test"));
    }
    #[test] fn vault_wrong_pin() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("secrets.json");
        Vault::create(&p, "123456").unwrap().save().unwrap();
        assert!(matches!(Vault::unlock(&p, "654321"), Err(VaultError::WrongPin)));
    }
    #[test] fn vault_file_has_no_plaintext() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("secrets.json");
        let mut v = Vault::create(&p, "123456").unwrap();
        v.upsert(key_secret()).unwrap();
        v.save().unwrap();
        let raw = std::fs::read(&p).unwrap();
        assert!(!raw.windows(14).any(|w| w == b"SECRETMATERIAL"));
    }
    #[test] fn get_unknown_is_not_found() {
        let d = tempfile::tempdir().unwrap();
        let v = Vault::create(&d.path().join("s.json"), "123456").unwrap();
        assert!(matches!(v.get(Uuid::new_v4()), Err(VaultError::NotFound)));
    }
    #[test] fn remove_deletes() {
        let d = tempfile::tempdir().unwrap();
        let mut v = Vault::create(&d.path().join("s.json"), "123456").unwrap();
        let s = key_secret();
        v.upsert(s.clone()).unwrap();
        v.remove(s.id);
        assert!(v.list().is_empty());
    }
}

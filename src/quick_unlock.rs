//! Quick unlock: get a stable secret from Windows Hello or a FIDO2 security key.
//!
//! - Windows Hello: a per-user Hello key (RSA, PKCS#1 v1.5) signs a stored random challenge. The
//!   signature is deterministic, so it serves as the secret (same approach as KeePassXC).
//! - Security key: WebAuthn hmac-secret/PRF output for a stored credential ID and salt.
//!
//! The vault turns the secret into a wrapping key for its own key (see `Vault::add_unlock_method`).
//! All functions block while Windows shows its dialog: call them from a worker thread.
use crate::vault::{UnlockKind, UnlockMethod, random};
use anyhow::{Context, anyhow, bail};
use data_encoding::BASE64;
use uuid::Uuid;
use windows::Security::Credentials::{KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Win32::Foundation::HWND;
use windows::Win32::Networking::WindowsWebServices::*;
use windows::Win32::UI::WindowsAndMessaging::{FindWindowW, GetForegroundWindow, SetForegroundWindow};
use windows::core::{Array, BOOL, HSTRING, PCWSTR, w};
use zeroize::Zeroizing;

const HELLO_KEY_NAME: &str = "lzssh-vault";
const RP_ID: PCWSTR = w!("lzssh:");
const TIMEOUT_MS: u32 = 60_000;
/// HRESULT for "the user cancelled" from webauthn.dll.
const NTE_USER_CANCELLED: i32 = 0x8009_0036_u32 as i32;

pub type Secret = Zeroizing<Vec<u8>>;

/// Our window, captured on the UI thread so Windows can parent its dialogs to it.
#[derive(Clone, Copy)]
pub struct Owner(usize);

impl Owner {
    pub fn current() -> Owner {
        Owner(unsafe { GetForegroundWindow() }.0 as usize)
    }
    fn hwnd(self) -> HWND {
        HWND(self.0 as *mut _)
    }
}

pub fn hello_available() -> bool {
    KeyCredentialManager::IsSupportedAsync().and_then(|op| op.join()).unwrap_or(false)
}

pub fn security_key_available() -> bool {
    // hmac-secret salts in GetAssertion need WebAuthn API version 4 (Windows 11).
    unsafe { WebAuthNGetApiVersionNumber() >= 4 }
}

/// Creates a new quick-unlock method. Security keys ask for two touches (create, then read).
pub fn enroll(kind: UnlockKind, name: &str, owner: Owner) -> anyhow::Result<(UnlockMethod, Secret)> {
    let challenge: [u8; 32] = random();
    let (credential_id, secret) = match kind {
        UnlockKind::WindowsHello => {
            let cred = hello_key(true)?;
            (None, hello_sign(&cred, &challenge)?)
        }
        UnlockKind::SecurityKey => {
            let id = make_credential(owner)?;
            let s = hmac_secret(owner, &id, &challenge)?;
            (Some(BASE64.encode(&id)), s)
        }
    };
    let m = UnlockMethod { id: Uuid::new_v4(), kind, name: name.to_string(), challenge: BASE64.encode(&challenge), credential_id };
    Ok((m, secret))
}

/// Asks Windows Hello / the security key for the method's secret.
pub fn authenticate(m: &UnlockMethod, owner: Owner) -> anyhow::Result<Secret> {
    let challenge = BASE64.decode(m.challenge.as_bytes()).context("bad challenge")?;
    match m.kind {
        UnlockKind::WindowsHello => hello_sign(&hello_key(false)?, &challenge),
        UnlockKind::SecurityKey => {
            let id = BASE64.decode(m.credential_id.as_deref().unwrap_or_default().as_bytes()).context("bad credential ID")?;
            hmac_secret(owner, &id, &challenge)
        }
    }
}

fn hello_status(s: KeyCredentialStatus) -> anyhow::Error {
    match s {
        KeyCredentialStatus::UserCanceled => anyhow!("Cancelled"),
        KeyCredentialStatus::NotFound => anyhow!("Windows Hello key not found. Set up quick unlock again."),
        KeyCredentialStatus::SecurityDeviceLocked => anyhow!("Windows Hello is locked. Try again later."),
        KeyCredentialStatus::UserPrefersPassword => anyhow!("Cancelled (use your PIN)"),
        s => anyhow!("Windows Hello failed (status {})", s.0),
    }
}

/// Opens lzssh's Hello key; with `create`, makes it first if it does not exist yet.
fn hello_key(create: bool) -> anyhow::Result<KeyCredential> {
    let name = HSTRING::from(HELLO_KEY_NAME);
    let _focus = FocusHelloDialog::start();
    if create {
        let r = KeyCredentialManager::RequestCreateAsync(&name, KeyCredentialCreationOption::FailIfExists)?.join()?;
        match r.Status()? {
            KeyCredentialStatus::Success => return Ok(r.Credential()?),
            KeyCredentialStatus::CredentialAlreadyExists => {}
            s => return Err(hello_status(s)),
        }
    }
    let r = KeyCredentialManager::OpenAsync(&name)?.join()?;
    match r.Status()? {
        KeyCredentialStatus::Success => Ok(r.Credential()?),
        s => Err(hello_status(s)),
    }
}

fn hello_sign(cred: &KeyCredential, challenge: &[u8]) -> anyhow::Result<Secret> {
    let _focus = FocusHelloDialog::start();
    let r = cred.RequestSignAsync(&CryptographicBuffer::CreateFromByteArray(challenge)?)?.join()?;
    if r.Status()? != KeyCredentialStatus::Success {
        return Err(hello_status(r.Status()?));
    }
    let mut out = Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(&r.Result()?, &mut out)?;
    Ok(Zeroizing::new(out.to_vec()))
}

/// The Hello prompt of a desktop app tends to open behind the app window. While a Hello call runs,
/// bring its window to the front once it appears.
struct FocusHelloDialog(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl FocusHelloDialog {
    fn start() -> Self {
        use std::sync::atomic::Ordering;
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let s = stop.clone();
        std::thread::spawn(move || {
            for _ in 0..40 {
                if s.load(Ordering::Relaxed) {
                    return;
                }
                if let Ok(h) = unsafe { FindWindowW(w!("Credential Dialog Xaml Host"), PCWSTR::null()) } {
                    let _ = unsafe { SetForegroundWindow(h) };
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
        });
        FocusHelloDialog(stop)
    }
}

impl Drop for FocusHelloDialog {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

fn webauthn_error(e: windows::core::Error) -> anyhow::Error {
    if e.code().0 == NTE_USER_CANCELLED {
        anyhow!("Cancelled")
    } else {
        anyhow!("Security key failed: {}", e.message())
    }
}

/// `clientDataJSON` for a native app: Windows only hashes it; nobody verifies it.
pub(crate) fn client_data_json(kind: &str, challenge: &[u8]) -> Vec<u8> {
    let c = data_encoding::BASE64URL_NOPAD.encode(challenge);
    format!(r#"{{"type":"{kind}","challenge":"{c}","origin":"lzssh:"}}"#).into_bytes()
}

/// Registers a non-resident credential with hmac-secret on a security key; returns its ID.
fn make_credential(owner: Owner) -> anyhow::Result<Vec<u8>> {
    let rp = WEBAUTHN_RP_ENTITY_INFORMATION { dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION, pwszId: RP_ID, pwszName: w!("lzssh"), pwszIcon: PCWSTR::null() };
    let mut user_id: [u8; 16] = random();
    let user = WEBAUTHN_USER_ENTITY_INFORMATION {
        dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
        cbId: user_id.len() as u32,
        pbId: user_id.as_mut_ptr(),
        pwszName: w!("lzssh vault"),
        pwszIcon: PCWSTR::null(),
        pwszDisplayName: w!("lzssh vault"),
    };
    let mut alg = WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
        dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
        pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        lAlg: WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
    };
    let params = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS { cCredentialParameters: 1, pCredentialParameters: &mut alg };
    let mut cd_json = client_data_json("webauthn.create", &random::<32>());
    let cd = WEBAUTHN_CLIENT_DATA {
        dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        cbClientDataJSON: cd_json.len() as u32,
        pbClientDataJSON: cd_json.as_mut_ptr(),
        pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
    };
    let mut enable = BOOL(1);
    let mut ext = WEBAUTHN_EXTENSION {
        pwszExtensionIdentifier: WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET,
        cbExtension: size_of::<BOOL>() as u32,
        pvExtension: (&raw mut enable).cast(),
    };
    let opts = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
        dwVersion: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_4,
        dwTimeoutMilliseconds: TIMEOUT_MS,
        Extensions: WEBAUTHN_EXTENSIONS { cExtensions: 1, pExtensions: &mut ext },
        dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
        dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
        dwAttestationConveyancePreference: WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        ..Default::default()
    };
    unsafe {
        let att = WebAuthNAuthenticatorMakeCredential(owner.hwnd(), &rp, &user, &params, &cd, Some(&opts)).map_err(webauthn_error)?;
        let a = &*att;
        let id = std::slice::from_raw_parts(a.pbCredentialId, a.cbCredentialId as usize).to_vec();
        WebAuthNFreeCredentialAttestation(Some(att));
        if id.is_empty() {
            bail!("Security key returned no credential");
        }
        Ok(id)
    }
}

/// Gets the hmac-secret/PRF output for `salt` from the credential `id`.
fn hmac_secret(owner: Owner, id: &[u8], salt: &[u8]) -> anyhow::Result<Secret> {
    let mut id = id.to_vec();
    let mut cred = WEBAUTHN_CREDENTIAL { dwVersion: WEBAUTHN_CREDENTIAL_CURRENT_VERSION, cbId: id.len() as u32, pbId: id.as_mut_ptr(), pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY };
    let mut salt = salt.to_vec();
    let mut first = WEBAUTHN_HMAC_SECRET_SALT { cbFirst: salt.len() as u32, pbFirst: salt.as_mut_ptr(), ..Default::default() };
    let mut values = WEBAUTHN_HMAC_SECRET_SALT_VALUES { pGlobalHmacSalt: &mut first, ..Default::default() };
    let mut cd_json = client_data_json("webauthn.get", &random::<32>());
    let cd = WEBAUTHN_CLIENT_DATA {
        dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        cbClientDataJSON: cd_json.len() as u32,
        pbClientDataJSON: cd_json.as_mut_ptr(),
        pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
    };
    let opts = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
        dwVersion: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6,
        dwTimeoutMilliseconds: TIMEOUT_MS,
        CredentialList: WEBAUTHN_CREDENTIALS { cCredentials: 1, pCredentials: &mut cred },
        dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
        dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
        pHmacSecretSaltValues: &mut values,
        ..Default::default()
    };
    unsafe {
        let a = WebAuthNAuthenticatorGetAssertion(owner.hwnd(), RP_ID, &cd, Some(&opts)).map_err(webauthn_error)?;
        let r = &*a;
        let out = if r.dwVersion >= WEBAUTHN_ASSERTION_VERSION_3 && !r.pHmacSecret.is_null() && (*r.pHmacSecret).cbFirst >= 32 {
            let h = &*r.pHmacSecret;
            Some(Zeroizing::new(std::slice::from_raw_parts(h.pbFirst, h.cbFirst as usize).to_vec()))
        } else {
            None
        };
        WebAuthNFreeAssertion(a);
        out.ok_or_else(|| anyhow!("This security key does not support hmac-secret"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_data_is_json_with_b64url_challenge() {
        let v: serde_json::Value = serde_json::from_slice(&client_data_json("webauthn.get", &[0xfb, 0xff])).unwrap();
        assert_eq!(v["type"], "webauthn.get");
        assert_eq!(v["challenge"], "-_8");
    }
}

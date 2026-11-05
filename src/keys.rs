//! Helpers for importing OpenSSH private key files (plain, encrypted, FIDO handles).

/// Check that `private` is a usable OpenSSH private key and return its public key line.
/// A sibling `.pub` file's content wins if given. Encrypted keys require the right passphrase.
pub fn public_key_for(private: &[u8], sibling_pub: Option<&str>, passphrase: Option<&str>) -> Result<String, String> {
    let k = ssh_key::PrivateKey::from_openssh(private).map_err(|e| format!("Not an OpenSSH private key: {e}"))?;
    if k.is_encrypted() {
        let pw = passphrase.filter(|p| !p.is_empty()).ok_or("Key is encrypted: enter its passphrase")?;
        k.decrypt(pw.as_bytes()).map_err(|_| "Wrong passphrase".to_string())?;
    }
    if let Some(p) = sibling_pub.map(str::trim).filter(|p| !p.is_empty()) {
        return Ok(p.to_string());
    }
    k.public_key().to_openssh().map_err(|e| e.to_string())
}

/// Windows OpenSSH ssh-keygen: its ssh-sk-helper talks to Windows WebAuthn, so key creation
/// shows the native Windows security-key dialog (YubiKey touch/PIN or Windows Hello).
pub const SSH_KEYGEN_EXE: &str = r"C:\Windows\System32\OpenSSH\ssh-keygen.exe";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FidoType {
    /// Works with YubiKey and most hardware keys.
    Ed25519Sk,
    /// Works with hardware keys and Windows Hello (which only supports ES256).
    EcdsaSk,
}

impl FidoType {
    pub fn label(self) -> &'static str {
        match self {
            FidoType::Ed25519Sk => "ed25519-sk (security key, e.g. YubiKey)",
            FidoType::EcdsaSk => "ecdsa-sk (security key or Windows Hello)",
        }
    }
}

pub fn fido_keygen_args(t: FidoType, out: &std::path::Path, comment: &str) -> Vec<String> {
    let t = match t {
        FidoType::Ed25519Sk => "ed25519-sk",
        FidoType::EcdsaSk => "ecdsa-sk",
    };
    ["-q", "-t", t, "-f"].into_iter().map(String::from).chain([out.to_string_lossy().into_owned()]).chain(["-N", "", "-C", comment].map(String::from)).collect()
}

/// Generated FIDO key: the private handle file contents and the public key line.
pub struct FidoKey {
    pub handle: zeroize::Zeroizing<Vec<u8>>,
    pub public_key: String,
}

/// Run ssh-keygen (blocking, shows the Windows security-key dialog) and read the result.
/// Temporary files in `work_dir` are removed afterwards.
pub fn create_fido_key(t: FidoType, work_dir: &std::path::Path, comment: &str) -> Result<FidoKey, String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = work_dir.join(format!("new-sk-{}", uuid::Uuid::new_v4()));
    let pub_path = std::path::PathBuf::from(format!("{}.pub", out.display()));
    let res = std::process::Command::new(SSH_KEYGEN_EXE)
        .args(fido_keygen_args(t, &out, comment))
        .stdin(std::process::Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    let result = match res {
        Err(e) => Err(format!("Could not run ssh-keygen: {e}")),
        Ok(o) if !o.status.success() => {
            let msg = String::from_utf8_lossy(&o.stderr).trim().to_string();
            Err(if msg.is_empty() { "Key creation cancelled or failed".into() } else { msg })
        }
        Ok(_) => match (std::fs::read(&out), std::fs::read_to_string(&pub_path)) {
            (Ok(h), Ok(p)) => Ok(FidoKey { handle: zeroize::Zeroizing::new(h), public_key: p.trim().to_string() }),
            _ => Err("ssh-keygen did not write the key files".into()),
        },
    };
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&pub_path);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::rand_core::OsRng;

    fn key() -> ssh_key::PrivateKey {
        ssh_key::PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap()
    }

    #[test]
    fn derives_public_key() {
        let k = key();
        let pem = k.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let pk = public_key_for(pem.as_bytes(), None, None).unwrap();
        assert!(pk.starts_with("ssh-ed25519 "));
    }

    #[test]
    fn prefers_sibling_pub() {
        let pem = key().to_openssh(ssh_key::LineEnding::LF).unwrap();
        assert_eq!(public_key_for(pem.as_bytes(), Some("ssh-ed25519 AAAA me@pc\r\n"), None).unwrap(), "ssh-ed25519 AAAA me@pc");
    }

    #[test]
    fn encrypted_key_needs_right_passphrase() {
        let pem = key().encrypt(&mut OsRng, "pw").unwrap().to_openssh(ssh_key::LineEnding::LF).unwrap();
        assert!(public_key_for(pem.as_bytes(), None, None).is_err());
        assert!(public_key_for(pem.as_bytes(), None, Some("bad")).is_err());
        assert!(public_key_for(pem.as_bytes(), None, Some("pw")).is_ok());
    }

    #[test]
    fn fido_keygen_args_shape() {
        let out = std::path::Path::new(r"C:\run\new_sk");
        let a = fido_keygen_args(FidoType::EcdsaSk, out, "lzssh yubikey");
        assert_eq!(a, vec!["-q", "-t", "ecdsa-sk", "-f", r"C:\run\new_sk", "-N", "", "-C", "lzssh yubikey"]);
        assert_eq!(fido_keygen_args(FidoType::Ed25519Sk, out, "x")[2], "ed25519-sk");
        assert_eq!(SSH_KEYGEN_EXE, r"C:\Windows\System32\OpenSSH\ssh-keygen.exe");
    }

    #[test]
    fn garbage_rejected() {
        assert!(public_key_for(b"not a key", None, None).is_err());
    }
}

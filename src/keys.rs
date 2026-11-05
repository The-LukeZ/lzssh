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
    fn garbage_rejected() {
        assert!(public_key_for(b"not a key", None, None).is_err());
    }
}

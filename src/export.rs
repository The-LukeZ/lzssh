//! Remote shell command that appends a public key to ~/.ssh/authorized_keys (idempotent).

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExportError {
    #[error("Not a valid single-line OpenSSH public key")]
    InvalidKey,
}

const PREFIXES: &[&str] = &["ssh-", "ecdsa-sha2-", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-"];

pub fn authorized_keys_command(public_key: &str) -> Result<String, ExportError> {
    let k = public_key.trim();
    let ok = !k.is_empty() && !k.contains(['\'', '\n', '\r']) && PREFIXES.iter().any(|p| k.starts_with(p));
    if !ok {
        return Err(ExportError::InvalidKey);
    }
    // Parse and re-serialize: the line ends up inside quotes on the wt/ssh/remote shell command
    // line, so only a real key with a comment reduced to a safe charset may pass.
    let mut pk = ssh_key::PublicKey::from_openssh(k).map_err(|_| ExportError::InvalidKey)?;
    let comment: String = pk.comment().chars().filter(|c| c.is_ascii_alphanumeric() || "._@-".contains(*c)).collect();
    pk.set_comment(comment);
    let line = pk.to_openssh().map_err(|_| ExportError::InvalidKey)?;
    let k = line.trim();
    Ok(format!(
        "umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys && (grep -qxF '{k}' ~/.ssh/authorized_keys || echo '{k}' >> ~/.ssh/authorized_keys) && echo 'lzssh: key installed'"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn command_contains_key_and_is_idempotent_shape() { let k = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJoxV0vl7DuSwGZ+FD9pSwNdq0R2d9OYxj5H8o6xTQxS test"; let c = authorized_keys_command(k).unwrap(); assert!(c.contains(&format!("grep -qxF '{k}'"))); assert!(c.contains("chmod 600 ~/.ssh/authorized_keys")); }
    #[test] fn rejects_quote_and_multiline() { assert!(authorized_keys_command("ssh-ed25519 AA'A").is_err()); assert!(authorized_keys_command("ssh-ed25519 A\nB").is_err()); }
    fn sk_key() -> String {
        let ed = ssh_key::public::Ed25519PublicKey([7u8; 32]);
        let pk = ssh_key::PublicKey::new(ssh_key::public::KeyData::SkEd25519(ssh_key::public::SkEd25519::new(ed, "ssh:")), "yk");
        pk.to_openssh().unwrap()
    }
    #[test] fn accepts_sk_keys() { let k = sk_key(); assert!(k.starts_with("sk-ssh-ed25519@openssh.com ")); assert!(authorized_keys_command(&k).unwrap().contains(&k)); }
    #[test] fn unsafe_comment_chars_stripped() {
        let real = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJoxV0vl7DuSwGZ+FD9pSwNdq0R2d9OYxj5H8o6xTQxS";
        let c = authorized_keys_command(&format!("{real} me\"&$(calc)|x@pc")).unwrap();
        assert!(!c.contains("$(") && !c.contains('"') && !c.contains(")|x"));
        assert!(c.contains(&format!("'{real} mecalcx@pc'")));
    }
    #[test] fn rejects_bad_base64() { assert!(authorized_keys_command("ssh-ed25519 AA&&calc").is_err()); }
    #[test] fn rejects_non_key() { assert!(authorized_keys_command("rm -rf /").is_err()); assert!(authorized_keys_command("").is_err()); }
    #[test] fn trailing_newline_trimmed() { let k = sk_key(); assert!(authorized_keys_command(&format!("{k}\r\n")).unwrap().contains(&format!("'{k}'"))); }
}

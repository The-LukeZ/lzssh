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
    Ok(format!(
        "umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys && (grep -qxF '{k}' ~/.ssh/authorized_keys || echo '{k}' >> ~/.ssh/authorized_keys) && echo 'lzssh: key installed'"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn command_contains_key_and_is_idempotent_shape() { let c = authorized_keys_command("ssh-ed25519 AAAA test").unwrap(); assert!(c.contains("grep -qxF 'ssh-ed25519 AAAA test'")); assert!(c.contains("chmod 600 ~/.ssh/authorized_keys")); }
    #[test] fn rejects_quote_and_multiline() { assert!(authorized_keys_command("ssh-ed25519 AA'A").is_err()); assert!(authorized_keys_command("ssh-ed25519 A\nB").is_err()); }
    #[test] fn accepts_sk_keys() { assert!(authorized_keys_command("sk-ssh-ed25519@openssh.com AAAA yk").is_ok()); assert!(authorized_keys_command("sk-ecdsa-sha2-nistp256@openssh.com AAAA").is_ok()); }
    #[test] fn rejects_non_key() { assert!(authorized_keys_command("rm -rf /").is_err()); assert!(authorized_keys_command("").is_err()); }
    #[test] fn trailing_newline_trimmed() { assert!(authorized_keys_command("ssh-rsa AAAA x\r\n").unwrap().contains("'ssh-rsa AAAA x'")); }
}

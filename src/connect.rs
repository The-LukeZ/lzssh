//! Build `ssh.exe` invocations for hosts and launch them in Windows Terminal.
use crate::model::{Auth, Host};
use crate::vault::{PlainSecret, Vault, VaultError};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Always the Windows OpenSSH client: it talks to Windows WebAuthn for FIDO keys.
/// Never the `ssh` on PATH (Git's ssh.exe cannot do FIDO via Windows Hello/WebAuthn).
pub const SSH_EXE: &str = r"C:\Windows\System32\OpenSSH\ssh.exe";

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshInvocation {
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnectError {
    #[error("Host has no address")]
    NoAddress,
    #[error("Secret missing")]
    SecretMissing,
    #[error("Key error: {0}")]
    Key(String),
    #[error("Could not open terminal: {0}")]
    Launch(String),
}

pub fn prepare_connect(host: &Host, vault: &Vault, run_dir: &Path, prefer_v6: bool) -> Result<SshInvocation, ConnectError> {
    let addr = host.target(prefer_v6).ok_or(ConnectError::NoAddress)?;
    let secret = vault.get(host.auth.secret_id()).map_err(|e| match e {
        VaultError::NotFound => ConnectError::SecretMissing,
        other => ConnectError::Key(other.to_string()),
    })?;
    let mut args: Vec<String> = Vec::new();
    match host.auth {
        Auth::Key { .. } | Auth::Fido { .. } => {
            let key = materialize_key(&secret, run_dir)?;
            args.extend(["-i".into(), key.to_string_lossy().into_owned(), "-o".into(), "IdentitiesOnly=yes".into()]);
        }
        Auth::Password { .. } => {
            args.extend(["-o".into(), "PreferredAuthentications=password,keyboard-interactive".into()]);
        }
    }
    args.extend(["-p".into(), host.port.to_string(), format!("{}@{}", host.username.trim(), addr)]);
    Ok(SshInvocation { program: SSH_EXE.into(), args, env: vec![] })
}

/// Absolute path under `%SystemRoot%\System32`, so PATH cannot substitute a planted binary.
fn system32(exe: &str) -> PathBuf {
    PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into())).join("System32").join(exe)
}

/// Windows Terminal's per-user app execution alias; falls back to PATH lookup if absent.
fn wt_exe() -> PathBuf {
    dirs::data_local_dir()
        .map(|d| d.join(r"Microsoft\WindowsApps\wt.exe"))
        .filter(|p| p.exists())
        .unwrap_or_else(|| PathBuf::from("wt.exe"))
}

/// Restrict a path to the current user only (Windows OpenSSH refuses keys readable by others).
fn restrict_acl(path: &Path) -> Result<(), ConnectError> {
    let user = match (std::env::var("USERDOMAIN"), std::env::var("USERNAME")) {
        (Ok(d), Ok(u)) => format!("{d}\\{u}"),
        (_, Ok(u)) => u,
        _ => return Err(ConnectError::Key("USERNAME not set".into())),
    };
    let out = Command::new(system32("icacls.exe"))
        .arg(path)
        .args(["/inheritance:r", "/grant:r", &format!("{user}:F")])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| ConnectError::Key(format!("icacls: {e}")))?;
    if !out.status.success() {
        return Err(ConnectError::Key(format!("icacls failed: {}", String::from_utf8_lossy(&out.stdout).trim())));
    }
    Ok(())
}

/// Write the secret's private material to `<run_dir>/<secret_id>` (passphrase removed) with a user-only ACL.
pub fn materialize_key(secret: &PlainSecret, run_dir: &Path) -> Result<PathBuf, ConnectError> {
    let path = run_dir.join(secret.id.to_string());
    let bytes: zeroize::Zeroizing<Vec<u8>> = match secret.passphrase.as_ref().filter(|p| !p.is_empty()) {
        Some(pw) => {
            let k = ssh_key::PrivateKey::from_openssh(&secret.material[..]).map_err(|e| ConnectError::Key(e.to_string()))?;
            let k = if k.is_encrypted() {
                k.decrypt(pw.as_bytes()).map_err(|_| ConnectError::Key("wrong key passphrase".into()))?
            } else {
                k
            };
            let pem = k.to_openssh(ssh_key::LineEnding::LF).map_err(|e| ConnectError::Key(e.to_string()))?;
            zeroize::Zeroizing::new(pem.as_bytes().to_vec())
        }
        None => secret.material.clone(),
    };
    let _ = std::fs::remove_file(&path);
    // Lock the empty file down first, then write; on any failure remove it so no key is left behind.
    let result = std::fs::write(&path, b"")
        .map_err(|e| ConnectError::Key(e.to_string()))
        .and_then(|_| restrict_acl(&path))
        .and_then(|_| std::fs::write(&path, &bytes[..]).map_err(|e| ConnectError::Key(e.to_string())));
    if let Err(e) = result {
        let _ = std::fs::remove_file(&path);
        return Err(e);
    }
    Ok(path)
}

/// Quote one argument for a Windows command line.
fn quote(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_string();
    }
    let mut s = String::from('"');
    let mut backslashes = 0;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                s.push_str(&"\\".repeat(backslashes * 2 + 1));
                s.push('"');
                backslashes = 0;
            }
            _ => {
                s.push_str(&"\\".repeat(backslashes));
                s.push(c);
                backslashes = 0;
            }
        }
    }
    s.push_str(&"\\".repeat(backslashes * 2));
    s.push('"');
    s
}

/// Command line for the tab. With env vars, wrap in `cmd /c` because the tab may be
/// hosted by an already running Windows Terminal process that does not inherit our env.
fn tab_command_line(inv: &SshInvocation) -> String {
    let mut cmd = std::iter::once(quote(&inv.program)).chain(inv.args.iter().map(|a| quote(a))).collect::<Vec<_>>().join(" ");
    if !inv.env.is_empty() {
        let sets: String = inv.env.iter().map(|(k, v)| format!("set \"{k}={v}\"&& ")).collect();
        cmd = format!("cmd.exe /c \"{sets}{cmd}\"");
    }
    cmd
}

pub fn launch_in_terminal(title: &str, inv: &SshInvocation) -> Result<(), ConnectError> {
    let line = tab_command_line(inv);
    // wt treats ';' as a command separator; escape it so remote commands survive.
    let wt_line = format!("new-tab --title {} {}", quote(title), line.replace(';', "\\;"));
    let wt = Command::new(wt_exe()).raw_arg(&wt_line).envs(inv.env.iter().cloned()).spawn();
    if wt.is_ok() {
        return Ok(());
    }
    // Fallback: no Windows Terminal installed, open a classic console window.
    Command::new(&inv.program)
        .args(&inv.args)
        .envs(inv.env.iter().cloned())
        .creation_flags(CREATE_NEW_CONSOLE)
        .spawn()
        .map(|_| ())
        .map_err(|e| ConnectError::Launch(e.to_string()))
}

/// Remove decrypted key files. Called on start and on exit.
pub fn clean_run_dir(run_dir: &Path) {
    if let Ok(rd) = std::fs::read_dir(run_dir) {
        for e in rd.flatten() {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Auth, Host};
    use crate::vault::{PlainSecret, SecretKind, Vault};
    use uuid::Uuid;
    use zeroize::Zeroizing;

    fn host(auth: Auth) -> Host {
        Host {
            id: Uuid::new_v4(),
            folder_id: None,
            name: "web".into(),
            ipv4: Some("10.0.0.5".into()),
            ipv6: None,
            port: 2222,
            username: "luke".into(),
            auth,
        }
    }

    fn secret(kind: SecretKind, material: &[u8]) -> PlainSecret {
        PlainSecret {
            id: Uuid::new_v4(),
            name: "k".into(),
            kind,
            public_key: None,
            material: Zeroizing::new(material.to_vec()),
            passphrase: None,
        }
    }

    fn vault_with(s: &PlainSecret, dir: &Path) -> Vault {
        let mut v = Vault::create(&dir.join("secrets.json"), "123456").unwrap();
        v.upsert(s.clone()).unwrap();
        v
    }

    #[test]
    fn key_invocation_args() {
        let d = tempfile::tempdir().unwrap();
        let s = secret(SecretKind::SshKey, b"KEYDATA\n");
        let v = vault_with(&s, d.path());
        let inv = prepare_connect(&host(Auth::Key { secret_id: s.id }), &v, d.path(), false).unwrap();
        assert_eq!(inv.program, SSH_EXE);
        let key = d.path().join(s.id.to_string()).to_string_lossy().to_string();
        assert_eq!(inv.args, vec!["-i", key.as_str(), "-o", "IdentitiesOnly=yes", "-p", "2222", "luke@10.0.0.5"]);
        assert!(inv.env.is_empty());
    }

    #[test]
    fn ipv6_brackets_stripped() {
        let d = tempfile::tempdir().unwrap();
        let s = secret(SecretKind::SshKey, b"KEYDATA\n");
        let v = vault_with(&s, d.path());
        let mut h = host(Auth::Key { secret_id: s.id });
        h.ipv4 = None;
        h.ipv6 = Some("[2001:db8::1]".into());
        let inv = prepare_connect(&h, &v, d.path(), false).unwrap();
        assert_eq!(inv.args.last().unwrap(), "luke@2001:db8::1");
        h.ipv6 = Some("fe80::1%3".into());
        let inv = prepare_connect(&h, &v, d.path(), false).unwrap();
        assert_eq!(inv.args.last().unwrap(), "luke@fe80::1%3");
    }

    #[test]
    fn missing_secret_errors() {
        let d = tempfile::tempdir().unwrap();
        let s = secret(SecretKind::SshKey, b"x");
        let v = vault_with(&s, d.path());
        let r = prepare_connect(&host(Auth::Key { secret_id: Uuid::new_v4() }), &v, d.path(), false);
        assert!(matches!(r, Err(ConnectError::SecretMissing)));
        assert_eq!(ConnectError::SecretMissing.to_string(), "Secret missing");
    }

    #[test]
    fn password_invocation_args() {
        let d = tempfile::tempdir().unwrap();
        let s = secret(SecretKind::Password, b"pw");
        let v = vault_with(&s, d.path());
        let inv = prepare_connect(&host(Auth::Password { secret_id: s.id }), &v, d.path(), false).unwrap();
        assert_eq!(inv.args, vec!["-o", "PreferredAuthentications=password,keyboard-interactive", "-p", "2222", "luke@10.0.0.5"]);
    }

    #[test]
    fn passphrase_removed_on_materialize() {
        use ssh_key::rand_core::OsRng;
        let d = tempfile::tempdir().unwrap();
        let k = ssh_key::PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap();
        let enc = k.encrypt(&mut OsRng, "pw").unwrap();
        let pem = enc.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let mut s = secret(SecretKind::SshKey, pem.as_bytes());
        s.passphrase = Some(Zeroizing::new("pw".into()));
        let p = materialize_key(&s, d.path()).unwrap();
        let back = ssh_key::PrivateKey::from_openssh(std::fs::read(&p).unwrap()).unwrap();
        assert!(!back.is_encrypted());
        assert_eq!(back.public_key(), k.public_key());
    }

    #[test]
    fn wrong_passphrase_is_key_error() {
        use ssh_key::rand_core::OsRng;
        let d = tempfile::tempdir().unwrap();
        let k = ssh_key::PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap();
        let pem = k.encrypt(&mut OsRng, "pw").unwrap().to_openssh(ssh_key::LineEnding::LF).unwrap();
        let mut s = secret(SecretKind::SshKey, pem.as_bytes());
        s.passphrase = Some(Zeroizing::new("nope".into()));
        assert!(matches!(materialize_key(&s, d.path()), Err(ConnectError::Key(_))));
    }

    #[test]
    fn fido_material_written_verbatim() {
        let d = tempfile::tempdir().unwrap();
        let s = secret(SecretKind::FidoKey, b"...handle...");
        let p = materialize_key(&s, d.path()).unwrap();
        assert_eq!(std::fs::read(p).unwrap(), b"...handle...");
    }

    #[test]
    fn clean_run_dir_removes_files() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("x"), b"k").unwrap();
        clean_run_dir(d.path());
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
    }
}

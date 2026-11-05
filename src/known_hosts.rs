//! Read and edit OpenSSH's known_hosts (`%USERPROFILE%\.ssh\known_hosts` for Windows OpenSSH).
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownHost {
    /// 0-based line index in the file.
    pub line: usize,
    /// Exact original line (without line ending), used to verify before deleting.
    pub raw: String,
    pub marker: Option<String>,
    pub hosts: String,
    pub hashed: bool,
    pub key_type: String,
    pub fingerprint: String,
}

pub fn default_path() -> PathBuf {
    dirs::home_dir().unwrap_or_default().join(".ssh").join("known_hosts")
}

fn parse(line: usize, raw: &str) -> Option<KnownHost> {
    let t = raw.trim();
    if t.is_empty() || t.starts_with('#') {
        return None;
    }
    let mut parts = t.split_whitespace();
    let mut first = parts.next()?;
    let mut marker = None;
    if first.starts_with('@') {
        marker = Some(first.to_string());
        first = parts.next()?;
    }
    let key_type = parts.next()?;
    let b64 = parts.next()?;
    let pk = ssh_key::PublicKey::from_openssh(&format!("{key_type} {b64}")).ok()?;
    Some(KnownHost {
        line,
        raw: raw.to_string(),
        marker,
        hosts: first.to_string(),
        hashed: first.starts_with("|1|"),
        key_type: key_type.to_string(),
        fingerprint: pk.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
    })
}

pub fn load(path: &Path) -> anyhow::Result<Vec<KnownHost>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.into()),
    };
    Ok(text.lines().enumerate().filter_map(|(i, l)| parse(i, l.trim_end_matches('\r'))).collect())
}

/// Delete exactly this entry's line; refuses if the file changed since it was loaded.
pub fn remove(path: &Path, entry: &KnownHost) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(path)?;
    let mut lines: Vec<&str> = text.split_inclusive('\n').collect();
    let current = lines.get(entry.line).map(|l| l.trim_end_matches(['\r', '\n']));
    anyhow::ensure!(current == Some(entry.raw.as_str()), "known_hosts changed on disk; reload and try again");
    lines.remove(entry.line);
    let tmp = path.with_extension("lzssh.tmp");
    std::fs::write(&tmp, lines.concat())?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIJoxV0vl7DuSwGZ+FD9pSwNdq0R2d9OYxj5H8o6xTQxS";

    fn file(dir: &std::path::Path) -> std::path::PathBuf {
        let p = dir.join("known_hosts");
        let body = format!(
            "# comment\n\nweb.example.com,10.0.0.5 ssh-ed25519 {KEY}\n|1|abc=|def= ssh-ed25519 {KEY}\n[git.example.com]:2222 ssh-ed25519 {KEY} note\r\ngarbage line\n"
        );
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn parses_entries_and_skips_junk() {
        let d = tempfile::tempdir().unwrap();
        let e = load(&file(d.path())).unwrap();
        assert_eq!(e.len(), 3);
        assert_eq!(e[0].hosts, "web.example.com,10.0.0.5");
        assert_eq!(e[0].key_type, "ssh-ed25519");
        assert!(e[0].fingerprint.starts_with("SHA256:"));
        assert!(!e[0].hashed);
        assert!(e[1].hashed);
        assert_eq!(e[2].hosts, "[git.example.com]:2222");
    }

    #[test]
    fn missing_file_is_empty() {
        let d = tempfile::tempdir().unwrap();
        assert!(load(&d.path().join("nope")).unwrap().is_empty());
    }

    #[test]
    fn remove_deletes_only_that_line() {
        let d = tempfile::tempdir().unwrap();
        let p = file(d.path());
        let e = load(&p).unwrap();
        remove(&p, &e[0]).unwrap();
        let after = std::fs::read_to_string(&p).unwrap();
        assert!(!after.contains("web.example.com"));
        assert!(after.contains("# comment"));
        assert!(after.contains("garbage line"));
        assert_eq!(load(&p).unwrap().len(), 2);
    }

    #[test]
    fn remove_refuses_if_file_changed() {
        let d = tempfile::tempdir().unwrap();
        let p = file(d.path());
        let e = load(&p).unwrap();
        std::fs::write(&p, "other.host ssh-ed25519 AAAA\n").unwrap();
        assert!(remove(&p, &e[0]).is_err());
    }
}

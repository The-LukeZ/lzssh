use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Folder {
    pub id: Uuid,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Auth {
    Password { secret_id: Uuid },
    Key { secret_id: Uuid },
    Fido { secret_id: Uuid },
}

impl Auth {
    pub fn secret_id(&self) -> Uuid {
        match *self {
            Auth::Password { secret_id } | Auth::Key { secret_id } | Auth::Fido { secret_id } => secret_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Host {
    pub id: Uuid,
    pub folder_id: Option<Uuid>,
    pub name: String,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub port: u16,
    pub username: String,
    pub auth: Auth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HostError {
    #[error("Enter an IPv4 or IPv6 address")]
    NoAddress,
    #[error("Enter a username")]
    NoUsername,
    #[error("Enter a name")]
    NoName,
    #[error("Port must be 1-65535")]
    BadPort,
}

fn set(v: &Option<String>) -> Option<&str> {
    v.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

impl Host {
    pub fn validate(&self) -> Result<(), HostError> {
        if self.name.trim().is_empty() {
            return Err(HostError::NoName);
        }
        if set(&self.ipv4).is_none() && set(&self.ipv6).is_none() {
            return Err(HostError::NoAddress);
        }
        if self.username.trim().is_empty() {
            return Err(HostError::NoUsername);
        }
        if self.port == 0 {
            return Err(HostError::BadPort);
        }
        Ok(())
    }

    pub fn has_both(&self) -> bool {
        set(&self.ipv4).is_some() && set(&self.ipv6).is_some()
    }

    /// Address to connect to: IPv4 if set, else IPv6; `prefer_v6` picks IPv6 when set.
    /// IPv6 is returned without surrounding brackets.
    pub fn target(&self, prefer_v6: bool) -> Option<String> {
        let v6 = set(&self.ipv6).map(|s| s.trim_start_matches('[').trim_end_matches(']').to_string());
        let v4 = set(&self.ipv4).map(str::to_string);
        if prefer_v6 { v6.or(v4) } else { v4.or(v6) }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Store {
    pub folders: Vec<Folder>,
    pub hosts: Vec<Host>,
}

impl Store {
    pub fn load(path: &Path) -> anyhow::Result<Store> {
        match std::fs::read(path) {
            Ok(b) => Ok(serde_json::from_slice(&b)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Store::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn sample() -> Host {
        Host {
            id: Uuid::new_v4(),
            folder_id: None,
            name: "web".into(),
            ipv4: Some("10.0.0.5".into()),
            ipv6: None,
            port: 22,
            username: "luke".into(),
            auth: Auth::Key { secret_id: Uuid::new_v4() },
        }
    }
    fn sample_both() -> Host {
        let mut h = sample();
        h.ipv6 = Some("[2001:db8::1]".into());
        h
    }

    #[test] fn validate_requires_address() { let mut h = sample(); h.ipv4 = None; h.ipv6 = None; assert_eq!(h.validate(), Err(HostError::NoAddress)); }
    #[test] fn validate_empty_strings_are_unset() { let mut h = sample(); h.ipv4 = Some("  ".into()); h.ipv6 = Some("".into()); assert_eq!(h.validate(), Err(HostError::NoAddress)); }
    #[test] fn validate_requires_username() { let mut h = sample(); h.username = "  ".into(); assert_eq!(h.validate(), Err(HostError::NoUsername)); }
    #[test] fn validate_rejects_port_zero() { let mut h = sample(); h.port = 0; assert_eq!(h.validate(), Err(HostError::BadPort)); }
    #[test] fn validate_ok() { assert_eq!(sample().validate(), Ok(())); }
    #[test] fn target_prefers_ipv4() { let h = sample_both(); assert_eq!(h.target(false).unwrap(), "10.0.0.5"); assert_eq!(h.target(true).unwrap(), "2001:db8::1"); }
    #[test] fn ipv6_only_used_when_no_ipv4() { let mut h = sample_both(); h.ipv4 = None; assert_eq!(h.target(false).unwrap(), "2001:db8::1"); }
    #[test] fn store_roundtrip_and_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("hosts.json");
        assert_eq!(Store::load(&p).unwrap(), Store::default());
        let f = Folder { id: Uuid::new_v4(), name: "prod".into() };
        let mut h = sample(); h.folder_id = Some(f.id);
        let s = Store { folders: vec![f], hosts: vec![h] };
        s.save(&p).unwrap();
        assert_eq!(Store::load(&p).unwrap(), s);
    }
}

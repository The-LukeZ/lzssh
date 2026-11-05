//! This device's identity (Ed25519 secret key, DPAPI-wrapped on disk), display name, sync server and paired devices.
use crate::dpapi;
pub use crate::sync::mailbox::ServerConfig;
use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairedDevice {
    /// Device ID: lowercase hex Ed25519 public key.
    pub node_id: String,
    pub name: String,
}

/// First `n` characters of an ID for display; safe on any string.
pub fn short_id(id: &str, n: usize) -> String {
    id.chars().take(n).collect()
}

pub const DEFAULT_SERVER: &str = "https://lzssh.thelukez.com";

#[derive(Debug, Clone)]
pub struct Device {
    pub secret_key: [u8; 32],
    pub name: String,
    pub paired: Vec<PairedDevice>,
    pub server: Option<ServerConfig>,
}

#[derive(Serialize, Deserialize)]
struct OnDiskServer {
    url: String,
    /// base64(DPAPI(access token)).
    token: String,
}

#[derive(Serialize, Deserialize)]
struct OnDisk {
    name: String,
    /// base64(DPAPI(secret key bytes)).
    secret_key: String,
    paired: Vec<PairedDevice>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    server: Option<OnDiskServer>,
}

impl Device {
    pub fn load_or_create(path: &Path) -> anyhow::Result<Device> {
        match std::fs::read(path) {
            Ok(b) => {
                let d: OnDisk = serde_json::from_slice(&b)?;
                let raw = dpapi::unprotect(&BASE64.decode(d.secret_key.as_bytes())?)?;
                let secret_key: [u8; 32] = raw.try_into().map_err(|_| anyhow::anyhow!("device key has wrong length"))?;
                let server = match d.server {
                    Some(s) => {
                        let token = String::from_utf8(dpapi::unprotect(&BASE64.decode(s.token.as_bytes())?)?)?;
                        Some(ServerConfig { url: s.url, token })
                    }
                    None => None,
                };
                Ok(Device { secret_key, name: d.name, paired: d.paired, server })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let d = Device {
                    secret_key: crate::vault::random(),
                    name: std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Windows PC".into()),
                    paired: vec![],
                    server: None,
                };
                d.save(path)?;
                Ok(d)
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let server = match &self.server {
            Some(s) => Some(OnDiskServer { url: s.url.clone(), token: BASE64.encode(&dpapi::protect(s.token.as_bytes())?) }),
            None => None,
        };
        let d = OnDisk { name: self.name.clone(), secret_key: BASE64.encode(&dpapi::protect(&self.secret_key)?), paired: self.paired.clone(), server };
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&d)?)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_created_once_and_key_wrapped() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("device.json");
        let mut a = Device::load_or_create(&p).unwrap();
        assert!(!a.name.is_empty());
        a.paired.push(PairedDevice { node_id: "ab".into(), name: "laptop".into() });
        a.save(&p).unwrap();
        let b = Device::load_or_create(&p).unwrap();
        assert_eq!(a.secret_key, b.secret_key);
        assert_eq!(b.paired, a.paired);
        let raw = std::fs::read(&p).unwrap();
        assert!(!raw.windows(32).any(|w| w == a.secret_key));
        assert!(!String::from_utf8_lossy(&raw).contains(&hex::encode(a.secret_key)));
    }

    #[test]
    fn server_token_wrapped_and_optional() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("device.json");
        let mut a = Device::load_or_create(&p).unwrap();
        assert_eq!(a.server, None);
        a.server = Some(ServerConfig { url: DEFAULT_SERVER.into(), token: "tok-123".into() });
        a.save(&p).unwrap();
        let b = Device::load_or_create(&p).unwrap();
        assert_eq!(b.server, a.server);
        assert!(!String::from_utf8_lossy(&std::fs::read(&p).unwrap()).contains("tok-123"));
        // A file written before the server field existed still loads.
        let old = serde_json::json!({"name": "x", "secret_key": BASE64.encode(&dpapi::protect(&[1u8; 32]).unwrap()), "paired": []});
        std::fs::write(&p, old.to_string()).unwrap();
        assert_eq!(Device::load_or_create(&p).unwrap().server, None);
    }

    #[test]
    fn short_id_never_panics() {
        assert_eq!(short_id("abcdef0123456789ff", 8), "abcdef01");
        assert_eq!(short_id("ab", 8), "ab");
        assert_eq!(short_id("äöüäöüäöüä", 3), "äöü");
    }
}

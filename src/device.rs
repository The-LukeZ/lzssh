//! This device's identity (iroh secret key, DPAPI-wrapped on disk), display name and paired devices.
use crate::dpapi;
use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairedDevice {
    /// iroh endpoint ID, lowercase hex.
    pub node_id: String,
    pub name: String,
}

/// First `n` characters of an ID for display; safe on any string.
pub fn short_id(id: &str, n: usize) -> String {
    id.chars().take(n).collect()
}

#[derive(Debug, Clone)]
pub struct Device {
    pub secret_key: [u8; 32],
    pub name: String,
    pub paired: Vec<PairedDevice>,
}

#[derive(Serialize, Deserialize)]
struct OnDisk {
    name: String,
    /// base64(DPAPI(secret key bytes)).
    secret_key: String,
    paired: Vec<PairedDevice>,
}

impl Device {
    pub fn load_or_create(path: &Path) -> anyhow::Result<Device> {
        match std::fs::read(path) {
            Ok(b) => {
                let d: OnDisk = serde_json::from_slice(&b)?;
                let raw = dpapi::unprotect(&BASE64.decode(d.secret_key.as_bytes())?)?;
                let secret_key: [u8; 32] = raw.try_into().map_err(|_| anyhow::anyhow!("device key has wrong length"))?;
                Ok(Device { secret_key, name: d.name, paired: d.paired })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let d = Device {
                    secret_key: crate::vault::random(),
                    name: std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Windows PC".into()),
                    paired: vec![],
                };
                d.save(path)?;
                Ok(d)
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let d = OnDisk { name: self.name.clone(), secret_key: BASE64.encode(&dpapi::protect(&self.secret_key)?), paired: self.paired.clone() };
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
    fn short_id_never_panics() {
        assert_eq!(short_id("abcdef0123456789ff", 8), "abcdef01");
        assert_eq!(short_id("ab", 8), "ab");
        assert_eq!(short_id("äöüäöüäöüä", 3), "äöü");
    }
}

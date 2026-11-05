//! Pairing code: `LZ1-` + base32(node_id || secret || relay_url), grouped by 5 for reading aloud/typing.
use anyhow::{Context, bail};
use data_encoding::BASE32_NOPAD;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairCode {
    pub node_id: [u8; 32],
    pub relay_url: Option<String>,
    pub secret: [u8; 32],
}

pub fn encode(c: &PairCode) -> String {
    let mut raw = Vec::with_capacity(64 + 64);
    raw.extend_from_slice(&c.node_id);
    raw.extend_from_slice(&c.secret);
    if let Some(r) = &c.relay_url {
        raw.extend_from_slice(r.as_bytes());
    }
    let b32 = BASE32_NOPAD.encode(&raw);
    let groups: Vec<&str> = b32.as_bytes().chunks(5).map(|g| std::str::from_utf8(g).expect("base32 is ascii")).collect();
    format!("LZ1-{}", groups.join("-"))
}

pub fn decode(s: &str) -> anyhow::Result<PairCode> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace() && *c != '-').collect::<String>().to_ascii_uppercase();
    let Some(body) = clean.strip_prefix("LZ1") else { bail!("Not an lzssh pairing code (must start with LZ1-)") };
    let raw = BASE32_NOPAD.decode(body.as_bytes()).context("Pairing code contains invalid characters")?;
    if raw.len() < 64 {
        bail!("Pairing code is too short");
    }
    let relay = std::str::from_utf8(&raw[64..]).context("Pairing code is damaged")?;
    if !relay.is_empty() {
        let host = relay.strip_prefix("https://").context("Pairing code has an invalid relay address")?;
        let ok = relay.len() <= 200 && host.chars().all(|c| c.is_ascii_alphanumeric() || ".-/:".contains(c));
        anyhow::ensure!(ok, "Pairing code has an invalid relay address");
    }
    Ok(PairCode {
        node_id: raw[..32].try_into().expect("length checked"),
        secret: raw[32..64].try_into().expect("length checked"),
        relay_url: Some(relay.to_string()).filter(|r| !r.is_empty()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PairCode {
        PairCode { node_id: [7u8; 32], relay_url: Some("https://euc1-1.relay.n0.iroh.link./".into()), secret: [9u8; 32] }
    }

    #[test]
    fn code_roundtrip_and_tolerant() {
        let c = sample();
        let s = encode(&c);
        assert!(s.starts_with("LZ1-"));
        assert_eq!(decode(&s).unwrap(), c);
        let messy = format!("  {}\n", s.to_lowercase().replace('-', " - ").replace("lz1 - ", "lz1-\r\n"));
        assert_eq!(decode(&messy).unwrap(), c);
        let no_relay = PairCode { relay_url: None, ..sample() };
        assert_eq!(decode(&encode(&no_relay)).unwrap(), no_relay);
    }

    #[test]
    fn missing_prefix_errors() {
        let s = encode(&sample());
        assert!(decode(&s[4..]).is_err());
        assert!(decode("LZ1-AAAA").is_err());
        assert!(decode("").is_err());
    }

    #[test]
    fn bad_relay_rejected() {
        for r in ["http://evil.example/", "file:///c:/x", &format!("https://{}.example/", "a".repeat(300))] {
            let c = PairCode { relay_url: Some(r.to_string()), ..sample() };
            assert!(decode(&encode(&c)).is_err(), "{r}");
        }
    }

    #[test]
    fn groups_of_five() {
        let s = encode(&sample());
        assert!(s[4..].split('-').all(|g| g.len() <= 5 && !g.is_empty()));
    }
}

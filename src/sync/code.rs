//! Pairing code: `LZ2-` + base32(device key 32 | secret 16 | token_len u8 | token | server URL), grouped by 5.
use anyhow::{Context, bail, ensure};
use data_encoding::BASE32_NOPAD;

const PREFIX: &str = "LZ2";
const FIXED: usize = 32 + 16 + 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairCode {
    /// Ed25519 public key of the device showing the code.
    pub device: [u8; 32],
    /// One-time pairing secret S.
    pub secret: [u8; 16],
    /// Access token of the sync server.
    pub token: String,
    /// Sync server base URL, `https://…`.
    pub server: String,
}

fn check_server(s: &str) -> anyhow::Result<()> {
    let host = s.strip_prefix("https://").context("Pairing code has an invalid server address")?;
    let ok = s.len() <= 200 && !host.is_empty() && host.chars().all(|c| c.is_ascii_alphanumeric() || ".-:/".contains(c));
    ensure!(ok, "Pairing code has an invalid server address");
    Ok(())
}

fn check_token(t: &str) -> anyhow::Result<()> {
    ensure!(!t.is_empty() && t.len() <= 255 && t.bytes().all(|b| (0x21..=0x7e).contains(&b)), "Pairing code has an invalid access token");
    Ok(())
}

pub fn encode(c: &PairCode) -> String {
    let mut raw = Vec::with_capacity(FIXED + c.token.len() + c.server.len());
    raw.extend_from_slice(&c.device);
    raw.extend_from_slice(&c.secret);
    raw.push(u8::try_from(c.token.len()).expect("token is at most 255 bytes"));
    raw.extend_from_slice(c.token.as_bytes());
    raw.extend_from_slice(c.server.as_bytes());
    let b32 = BASE32_NOPAD.encode(&raw);
    let groups: Vec<&str> = b32.as_bytes().chunks(5).map(|g| std::str::from_utf8(g).expect("base32 is ascii")).collect();
    format!("{PREFIX}-{}", groups.join("-"))
}

pub fn decode(s: &str) -> anyhow::Result<PairCode> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace() && *c != '-').collect::<String>().to_ascii_uppercase();
    let Some(body) = clean.strip_prefix(PREFIX) else { bail!("Not an lzssh pairing code (must start with LZ2-)") };
    let raw = BASE32_NOPAD.decode(body.as_bytes()).context("Pairing code contains invalid characters")?;
    ensure!(raw.len() > FIXED, "Pairing code is too short");
    let token_len = raw[48] as usize;
    let rest = &raw[FIXED..];
    ensure!(token_len > 0 && token_len < rest.len(), "Pairing code is damaged");
    let token = std::str::from_utf8(&rest[..token_len]).context("Pairing code is damaged")?.to_string();
    let server = std::str::from_utf8(&rest[token_len..]).context("Pairing code is damaged")?.to_string();
    check_token(&token)?;
    check_server(&server)?;
    Ok(PairCode {
        device: raw[..32].try_into().expect("length checked"),
        secret: raw[32..48].try_into().expect("length checked"),
        token,
        server,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PairCode {
        PairCode { device: [7u8; 32], secret: [9u8; 16], token: "tok+en/=123".into(), server: "https://lzssh.thelukez.com".into() }
    }

    #[test]
    fn code_roundtrip_and_tolerant() {
        let c = sample();
        let s = encode(&c);
        assert!(s.starts_with("LZ2-"));
        assert_eq!(decode(&s).unwrap(), c);
        let messy = format!("  {}\n", s.to_lowercase().replace('-', " - ").replace("lz2 - ", "lz2-\r\n"));
        assert_eq!(decode(&messy).unwrap(), c);
    }

    #[test]
    fn missing_prefix_errors() {
        let s = encode(&sample());
        assert!(decode(&s[4..]).is_err());
        assert!(decode("LZ2-AAAA").is_err());
        assert!(decode("").is_err());
    }

    #[test]
    fn bad_server_rejected() {
        for r in ["http://evil.example/", "file:///c:/x", &format!("https://{}.example/", "a".repeat(300)), "https://"] {
            let c = PairCode { server: r.to_string(), ..sample() };
            assert!(decode(&encode(&c)).is_err(), "{r}");
        }
    }

    #[test]
    fn token_length_checked() {
        let c = PairCode { token: String::new(), ..sample() };
        assert!(decode(&encode(&c)).is_err());
        // token_len byte pointing past the end
        let mut raw = vec![7u8; 32];
        raw.extend_from_slice(&[9u8; 16]);
        raw.push(200);
        raw.extend_from_slice(b"short");
        assert!(decode(&format!("LZ2-{}", BASE32_NOPAD.encode(&raw))).is_err());
    }

    #[test]
    fn groups_of_five() {
        let s = encode(&sample());
        assert!(s[4..].split('-').all(|g| g.len() <= 5 && !g.is_empty()));
    }
}

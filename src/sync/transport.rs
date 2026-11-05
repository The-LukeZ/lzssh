//! Talking to the mailbox Worker: signed HTTPS requests, plus an in-memory server for tests.
use super::crypto::{DeviceKeys, Envelope, signing_string};
use data_encoding::BASE64;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    #[error("Sync server rejected the clock of this PC. Check the Windows time.")]
    Clock,
    #[error("Sync server rejected the access token.")]
    Auth,
    #[error("Not allowed. The other device may have removed this one; pair again.")]
    Forbidden,
    #[error("Request was replayed.")]
    Replay,
    #[error("Too much data for one message (limit 1 MiB).")]
    TooLarge,
    #[error("The other device's mailbox is full. Open lzssh there first.")]
    Full,
    #[error("Sync server error: {0}")]
    Server(String),
    #[error("Sync server not reachable: {0}")]
    Network(String),
}

pub trait Transport: Send + 'static {
    /// This device's ID (its own mailbox).
    fn me(&self) -> String;
    /// Drops an envelope into `env.to`'s mailbox.
    fn post(&self, env: &Envelope, ticket: Option<&[u8; 32]>) -> Result<(), TransportError>;
    fn list(&self) -> Result<Vec<Envelope>, TransportError>;
    fn delete(&self, id: &str) -> Result<(), TransportError>;
    fn allow(&self, peer: &str) -> Result<(), TransportError>;
    fn disallow(&self, peer: &str) -> Result<(), TransportError>;
    fn set_pairing(&self, ticket_hash: [u8; 32], expires: u64) -> Result<(), TransportError>;
}

const MAX_RESPONSE: u64 = 32 * 1024 * 1024;

pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Maps a non-success HTTP status from the Worker to an error.
pub fn map_status(status: u16, body: &str) -> TransportError {
    match status {
        401 if body.contains("\"clock\"") => TransportError::Clock,
        401 => TransportError::Auth,
        403 => TransportError::Forbidden,
        409 => TransportError::Replay,
        413 => TransportError::TooLarge,
        507 => TransportError::Full,
        s => TransportError::Server(format!("HTTP {s}")),
    }
}

/// Authorization and signature headers for one request.
pub fn signed_headers(keys: &DeviceKeys, token: &str, method: &str, path: &str, body: &[u8], now: u64) -> Vec<(&'static str, String)> {
    let nonce = hex::encode(crate::vault::random::<16>());
    let sig = keys.sign(signing_string(method, path, now, &nonce, body).as_bytes());
    vec![
        ("Authorization", format!("Bearer {token}")),
        ("X-Lz-Device", keys.id()),
        ("X-Lz-Time", now.to_string()),
        ("X-Lz-Nonce", nonce),
        ("X-Lz-Sig", BASE64.encode(&sig)),
    ]
}

pub struct HttpTransport {
    server: String,
    token: Zeroizing<String>,
    keys: DeviceKeys,
    agent: ureq::Agent,
}

impl HttpTransport {
    pub fn new(server: &str, token: &str, keys: DeviceKeys) -> Self {
        let agent = ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(30))).build().into();
        HttpTransport { server: server.trim_end_matches('/').to_string(), token: Zeroizing::new(token.to_string()), keys, agent }
    }

    fn request(&self, method: &str, path: &str, body: &[u8], ticket: Option<&[u8; 32]>) -> Result<String, TransportError> {
        let url = format!("{}{path}", self.server);
        let headers = signed_headers(&self.keys, &self.token, method, path, body, unix_now());
        let net = |e: ureq::Error| TransportError::Network(e.to_string());
        macro_rules! with_headers {
            ($req:expr) => {{
                let mut r = $req;
                for (k, v) in &headers {
                    r = r.header(*k, v);
                }
                if let Some(t) = ticket {
                    r = r.header("X-Lz-Pair-Ticket", hex::encode(t));
                }
                r
            }};
        }
        let mut resp = match method {
            "GET" => with_headers!(self.agent.get(&url)).call(),
            "DELETE" => with_headers!(self.agent.delete(&url)).call(),
            "POST" => with_headers!(self.agent.post(&url)).header("Content-Type", "application/json").send(body),
            "PUT" if body.is_empty() => with_headers!(self.agent.put(&url)).send_empty(),
            "PUT" => with_headers!(self.agent.put(&url)).header("Content-Type", "application/json").send(body),
            m => unreachable!("unsupported method {m}"),
        }
        .map_err(net)?;
        let status = resp.status().as_u16();
        // A full mailbox lists up to 20 MiB; ureq's default read limit is 10 MB.
        let text = resp.body_mut().with_config().limit(MAX_RESPONSE).read_to_string().map_err(net)?;
        if (200..300).contains(&status) { Ok(text) } else { Err(map_status(status, &text)) }
    }

    fn mailbox(&self) -> String {
        format!("/v1/mailbox/{}", self.keys.id())
    }
}

impl Transport for HttpTransport {
    fn me(&self) -> String {
        self.keys.id()
    }

    fn post(&self, env: &Envelope, ticket: Option<&[u8; 32]>) -> Result<(), TransportError> {
        let body = serde_json::to_vec(env).map_err(|e| TransportError::Server(e.to_string()))?;
        self.request("POST", &format!("/v1/mailbox/{}", env.to), &body, ticket).map(|_| ())
    }

    fn list(&self) -> Result<Vec<Envelope>, TransportError> {
        #[derive(serde::Deserialize)]
        struct List {
            messages: Vec<serde_json::Value>,
        }
        let text = self.request("GET", &self.mailbox(), b"", None)?;
        let l: List = serde_json::from_str(&text).map_err(|e| TransportError::Server(e.to_string()))?;
        // Skip anything that does not parse as an envelope rather than failing the whole poll.
        Ok(l.messages.into_iter().filter_map(|m| serde_json::from_value(m).ok()).collect())
    }

    fn delete(&self, id: &str) -> Result<(), TransportError> {
        self.request("DELETE", &format!("{}/{id}", self.mailbox()), b"", None).map(|_| ())
    }

    fn allow(&self, peer: &str) -> Result<(), TransportError> {
        self.request("PUT", &format!("{}/allow/{peer}", self.mailbox()), b"", None).map(|_| ())
    }

    fn disallow(&self, peer: &str) -> Result<(), TransportError> {
        self.request("DELETE", &format!("{}/allow/{peer}", self.mailbox()), b"", None).map(|_| ())
    }

    fn set_pairing(&self, ticket_hash: [u8; 32], expires: u64) -> Result<(), TransportError> {
        let body = serde_json::json!({ "ticket_hash": hex::encode(ticket_hash), "expires": expires }).to_string();
        self.request("PUT", &format!("{}/pairing", self.mailbox()), body.as_bytes(), None).map(|_| ())
    }
}

#[cfg(test)]
pub use mem::{MemServer, MemTransport};

#[cfg(test)]
mod mem {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Box_ {
        messages: Vec<Envelope>,
        allow: HashSet<String>,
        pairing: Option<([u8; 32], u64)>,
    }

    #[derive(Default)]
    struct State {
        boxes: HashMap<String, Box_>,
        now: Option<u64>,
        posts: usize,
        fail: Vec<TransportError>,
    }

    /// In-memory stand-in for the Worker, applying the same permission rules.
    #[derive(Clone, Default)]
    pub struct MemServer(Arc<Mutex<State>>);

    impl MemServer {
        pub fn transport(&self, keys: &DeviceKeys) -> MemTransport {
            MemTransport { server: self.clone(), me: keys.id() }
        }
        pub fn set_now(&self, unix: u64) {
            self.0.lock().unwrap().now = Some(unix);
        }
        /// Number of accepted posts so far.
        pub fn posts(&self) -> usize {
            self.0.lock().unwrap().posts
        }
        /// Makes the next calls fail with these errors, in order.
        pub fn fail_next(&self, errs: Vec<TransportError>) {
            self.0.lock().unwrap().fail = errs;
        }
    }

    pub struct MemTransport {
        server: MemServer,
        me: String,
    }

    impl MemTransport {
        fn with<R>(&self, f: impl FnOnce(&mut State, u64) -> Result<R, TransportError>) -> Result<R, TransportError> {
            let mut s = self.server.0.lock().unwrap();
            if !s.fail.is_empty() {
                return Err(s.fail.remove(0));
            }
            let now = s.now.unwrap_or_else(unix_now);
            f(&mut s, now)
        }
    }

    impl Transport for MemTransport {
        fn me(&self) -> String {
            self.me.clone()
        }

        fn post(&self, env: &Envelope, ticket: Option<&[u8; 32]>) -> Result<(), TransportError> {
            let me = self.me.clone();
            self.with(|s, now| {
                if env.from != me {
                    return Err(TransportError::Server("HTTP 400".into()));
                }
                let b = s.boxes.entry(env.to.clone()).or_default();
                if env.to != me && !b.allow.contains(&me) {
                    // Only a pair_request with the current, unexpired ticket gets in; the ticket is then used up.
                    let by_ticket = match (ticket, b.pairing) {
                        (Some(t), Some((hash, exp))) => {
                            env.kind == super::super::crypto::Kind::PairRequest && exp >= now && <[u8; 32]>::from(Sha256::digest(t)) == hash
                        }
                        _ => false,
                    };
                    if !by_ticket {
                        return Err(TransportError::Forbidden);
                    }
                    b.pairing = None;
                }
                if !b.messages.iter().any(|m| m.id == env.id) {
                    b.messages.push(env.clone());
                }
                s.posts += 1;
                Ok(())
            })
        }

        fn list(&self) -> Result<Vec<Envelope>, TransportError> {
            self.with(|s, _| Ok(s.boxes.get(&self.me).map(|b| b.messages.clone()).unwrap_or_default()))
        }

        fn delete(&self, id: &str) -> Result<(), TransportError> {
            self.with(|s, _| {
                s.boxes.entry(self.me.clone()).or_default().messages.retain(|m| m.id != id);
                Ok(())
            })
        }

        fn allow(&self, peer: &str) -> Result<(), TransportError> {
            self.with(|s, _| {
                s.boxes.entry(self.me.clone()).or_default().allow.insert(peer.to_string());
                Ok(())
            })
        }

        fn disallow(&self, peer: &str) -> Result<(), TransportError> {
            self.with(|s, _| {
                s.boxes.entry(self.me.clone()).or_default().allow.remove(peer);
                Ok(())
            })
        }

        fn set_pairing(&self, ticket_hash: [u8; 32], expires: u64) -> Result<(), TransportError> {
            self.with(|s, now| {
                if expires <= now {
                    return Err(TransportError::Server("HTTP 400".into()));
                }
                s.boxes.entry(self.me.clone()).or_default().pairing = Some((ticket_hash, expires.min(now + 600)));
                Ok(())
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::crypto::{Kind, parse_id, seal};
    use ed25519_dalek::Verifier;
    use sha2::{Digest, Sha256};

    fn keys(b: u8) -> DeviceKeys {
        DeviceKeys::from_secret(&[b; 32])
    }

    #[test]
    fn signed_headers_cover_body() {
        let k = keys(1);
        let h = signed_headers(&k, "t", "POST", "/v1/mailbox/x", b"{}", 1700000000);
        let h2 = signed_headers(&k, "t", "POST", "/v1/mailbox/x", b"{}", 1700000000);
        let get = |n: &str| h.iter().find(|(k, _)| *k == n).map(|(_, v)| v.clone()).unwrap();
        assert_eq!(get("Authorization"), "Bearer t");
        assert_eq!(get("X-Lz-Device"), k.id());
        assert_eq!(get("X-Lz-Time"), "1700000000");
        let sig: [u8; 64] = BASE64.decode(get("X-Lz-Sig").as_bytes()).unwrap().try_into().unwrap();
        let nonce = get("X-Lz-Nonce");
        assert_eq!(nonce.len(), 32);
        let sig2 = h2.iter().find(|(k, _)| *k == "X-Lz-Sig").map(|(_, v)| v.clone()).unwrap();
        assert_ne!(sig2, get("X-Lz-Sig"), "the same request twice must not repeat the signature");
        let msg = signing_string("POST", "/v1/mailbox/x", 1700000000, &nonce, b"{}");
        assert!(parse_id(&k.id()).unwrap().verify(msg.as_bytes(), &ed25519_dalek::Signature::from_bytes(&sig)).is_ok());
        let other = signing_string("POST", "/v1/mailbox/x", 1700000000, &nonce, b"{ }");
        assert!(parse_id(&k.id()).unwrap().verify(other.as_bytes(), &ed25519_dalek::Signature::from_bytes(&sig)).is_err());
    }

    #[test]
    fn http_error_messages() {
        assert_eq!(map_status(401, r#"{"error":"clock"}"#), TransportError::Clock);
        assert_eq!(map_status(401, r#"{"error":"token"}"#), TransportError::Auth);
        assert_eq!(map_status(403, ""), TransportError::Forbidden);
        assert_eq!(map_status(413, ""), TransportError::TooLarge);
        assert_eq!(map_status(507, ""), TransportError::Full);
        assert_eq!(map_status(500, ""), TransportError::Server("HTTP 500".into()));
        assert!(TransportError::Clock.to_string().contains("clock"));
        assert!(TransportError::Forbidden.to_string().contains("pair again"));
    }

    /// A full mailbox (up to 20 MiB) must still list; ureq's default read limit is 10 MB.
    #[test]
    fn list_reads_large_response() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let body = format!("{{\"messages\":[]{}}}", " ".repeat(12 * 1024 * 1024));
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let head = format!("HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: {}
Connection: close

", body.len());
            s.write_all(head.as_bytes()).unwrap();
            s.write_all(body.as_bytes()).unwrap();
        });
        let t = HttpTransport::new(&format!("http://127.0.0.1:{port}"), "t", keys(1));
        assert_eq!(t.list(), Ok(vec![]));
    }

    #[test]
    fn mem_server_enforces_allow_list() {
        let srv = MemServer::default();
        let (a, b) = (keys(1), keys(2));
        let (ta, tb) = (srv.transport(&a), srv.transport(&b));
        let env = seal(&b, &a.id(), Kind::Payload, b"x").unwrap();
        assert_eq!(tb.post(&env, None), Err(TransportError::Forbidden));
        ta.allow(&b.id()).unwrap();
        tb.post(&env, None).unwrap();
        assert_eq!(ta.list().unwrap(), vec![env]);
    }

    #[test]
    fn mem_server_ticket_single_use_and_expiry() {
        let srv = MemServer::default();
        srv.set_now(1000);
        let (a, b) = (keys(1), keys(2));
        let (ta, tb) = (srv.transport(&a), srv.transport(&b));
        let ticket = [5u8; 32];
        ta.set_pairing(Sha256::digest(ticket).into(), 1600).unwrap();
        let req = || seal(&b, &a.id(), Kind::PairRequest, b"x").unwrap();
        tb.post(&req(), Some(&ticket)).unwrap();
        assert_eq!(tb.post(&req(), Some(&ticket)), Err(TransportError::Forbidden));
        ta.set_pairing(Sha256::digest(ticket).into(), 1600).unwrap();
        srv.set_now(1601);
        assert_eq!(tb.post(&req(), Some(&ticket)), Err(TransportError::Forbidden));
    }
}

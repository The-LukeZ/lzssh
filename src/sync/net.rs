//! iroh networking: pairing (ALPN_PAIR) and push sync (ALPN_SYNC) on a background tokio runtime.
use super::code::{self, PairCode};
use super::payload::Payload;
use crate::device::PairedDevice;
use iroh::address_lookup::MemoryLookup;
use iroh::endpoint::{Connection, RecvStream, SendStream, presets};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, SecretKey, TransportAddr};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

pub const ALPN_PAIR: &[u8] = b"lzssh/pair/1";
pub const ALPN_SYNC: &[u8] = b"lzssh/sync/1";
const MAX_MSG: u32 = 16 * 1024 * 1024;
const PAIR_TTL: Duration = Duration::from_secs(10 * 60);
const IO_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub enum NetCmd {
    StartPairing,
    EnterCode(String),
    Send { to: String, payload: Payload },
}

#[derive(Debug, Clone)]
pub enum NetEvent {
    Ready { node_id: String },
    PairCode(String),
    Paired(PairedDevice),
    Received { from: String, payload: Payload },
    Sent { to: String },
    SendFailed { to: String, error: String },
    Error(String),
}

/// Production uses n0 relays + n0 address lookup. `local()` is for tests: no relays,
/// in-process address book, so two endpoints in one process can find each other.
#[derive(Clone)]
pub enum NetConfig {
    N0,
    Local(MemoryLookup),
}

impl NetConfig {
    pub fn local() -> Self {
        NetConfig::Local(MemoryLookup::new())
    }
}

#[derive(Serialize, Deserialize)]
struct PairRequest {
    secret: String,
    name: String,
}

#[derive(Serialize, Deserialize)]
struct PairReply {
    ok: bool,
    #[serde(default)]
    name: String,
}

#[derive(Serialize, Deserialize)]
struct SyncReply {
    ok: bool,
}

pub fn id_hex(id: &EndpointId) -> String {
    hex::encode(id.as_bytes())
}

fn parse_id(s: &str) -> anyhow::Result<EndpointId> {
    let b: [u8; 32] = hex::decode(s.trim())?.try_into().map_err(|_| anyhow::anyhow!("bad node id"))?;
    Ok(EndpointId::from_bytes(&b)?)
}

async fn write_msg<T: Serialize>(send: &mut SendStream, msg: &T) -> anyhow::Result<()> {
    let body = serde_json::to_vec(msg)?;
    send.write_all(&(body.len() as u32).to_be_bytes()).await?;
    send.write_all(&body).await?;
    Ok(())
}

async fn read_msg<T: DeserializeOwned>(recv: &mut RecvStream) -> anyhow::Result<T> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len);
    anyhow::ensure!(len <= MAX_MSG, "message too large");
    let mut body = vec![0u8; len as usize];
    recv.read_exact(&mut body).await?;
    Ok(serde_json::from_slice(&body)?)
}

struct State {
    endpoint: Endpoint,
    name: String,
    paired: Arc<RwLock<Vec<PairedDevice>>>,
    /// Current pairing secret and when it was issued; single use.
    pending: Mutex<Option<([u8; 32], Instant)>>,
    events: Sender<NetEvent>,
}

impl State {
    fn emit(&self, e: NetEvent) {
        let _ = self.events.send(e);
    }

    fn add_paired(&self, d: PairedDevice) {
        let mut p = self.paired.write().expect("paired lock poisoned");
        match p.iter_mut().find(|x| x.node_id == d.node_id) {
            Some(x) => x.name = d.name.clone(),
            None => p.push(d.clone()),
        }
        drop(p);
        self.emit(NetEvent::Paired(d));
    }

    fn is_paired(&self, id: &EndpointId) -> bool {
        let hex = id_hex(id);
        self.paired.read().expect("paired lock poisoned").iter().any(|d| d.node_id == hex)
    }

    /// Takes the pending secret if it matches and has not expired.
    fn take_secret(&self, s: &[u8]) -> bool {
        let mut p = self.pending.lock().expect("pending lock poisoned");
        match *p {
            Some((secret, at)) if at.elapsed() < PAIR_TTL && s == secret => {
                *p = None;
                true
            }
            _ => false,
        }
    }
}

async fn handle_pair(st: &State, conn: Connection) -> anyhow::Result<()> {
    let (mut send, mut recv) = conn.accept_bi().await?;
    let req: PairRequest = read_msg(&mut recv).await?;
    let ok = hex::decode(&req.secret).map(|s| st.take_secret(&s)).unwrap_or(false);
    write_msg(&mut send, &PairReply { ok, name: if ok { st.name.clone() } else { String::new() } }).await?;
    send.finish()?;
    if ok {
        st.add_paired(PairedDevice { node_id: id_hex(&conn.remote_id()), name: req.name });
    }
    conn.closed().await;
    Ok(())
}

async fn handle_sync(st: &State, conn: Connection) -> anyhow::Result<()> {
    let from = conn.remote_id();
    if !st.is_paired(&from) {
        conn.close(1u32.into(), b"not paired");
        return Ok(());
    }
    let (mut send, mut recv) = conn.accept_bi().await?;
    let payload: Payload = read_msg(&mut recv).await?;
    write_msg(&mut send, &SyncReply { ok: true }).await?;
    send.finish()?;
    st.emit(NetEvent::Received { from: id_hex(&from), payload });
    conn.closed().await;
    Ok(())
}

async fn accept_loop(st: Arc<State>) {
    while let Some(incoming) = st.endpoint.accept().await {
        let st = st.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(_) => return,
            };
            let alpn = conn.alpn().to_vec();
            let r = if alpn == ALPN_PAIR {
                tokio::time::timeout(IO_TIMEOUT, handle_pair(&st, conn)).await
            } else if alpn == ALPN_SYNC {
                tokio::time::timeout(IO_TIMEOUT, handle_sync(&st, conn)).await
            } else {
                Ok(Ok(()))
            };
            if let Ok(Err(e)) = r {
                st.emit(NetEvent::Error(format!("Incoming connection failed: {e}")));
            }
        });
    }
}

async fn start_pairing(st: &State) -> anyhow::Result<String> {
    // Wait briefly for a home relay so the code carries one; fine to proceed without it.
    let _ = tokio::time::timeout(Duration::from_secs(10), st.endpoint.online()).await;
    let secret: [u8; 32] = crate::vault::random();
    *st.pending.lock().expect("pending lock poisoned") = Some((secret, Instant::now()));
    let relay_url = st.endpoint.addr().relay_urls().next().map(|u| u.to_string());
    Ok(code::encode(&PairCode { node_id: *st.endpoint.id().as_bytes(), relay_url, secret }))
}

async fn enter_code(st: &State, code_str: &str) -> anyhow::Result<PairedDevice> {
    let c = code::decode(code_str)?;
    let id = EndpointId::from_bytes(&c.node_id)?;
    let mut addr = EndpointAddr::new(id);
    if let Some(r) = c.relay_url.as_deref().and_then(|r| r.parse::<RelayUrl>().ok()) {
        addr = addr.with_addrs([TransportAddr::Relay(r)]);
    }
    let conn = st.endpoint.connect(addr, ALPN_PAIR).await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    write_msg(&mut send, &PairRequest { secret: hex::encode(c.secret), name: st.name.clone() }).await?;
    send.finish()?;
    let reply: PairReply = read_msg(&mut recv).await?;
    conn.close(0u32.into(), b"done");
    anyhow::ensure!(reply.ok, "Pairing code is wrong, expired or already used");
    Ok(PairedDevice { node_id: id_hex(&id), name: reply.name })
}

async fn send_payload(st: &State, to: &str, payload: &Payload) -> anyhow::Result<()> {
    let id = parse_id(to)?;
    let conn = st.endpoint.connect(EndpointAddr::new(id), ALPN_SYNC).await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    write_msg(&mut send, payload).await?;
    send.finish()?;
    let reply: SyncReply = read_msg(&mut recv).await.map_err(|_| anyhow::anyhow!("receiver refused the transfer"))?;
    conn.close(0u32.into(), b"done");
    anyhow::ensure!(reply.ok, "receiver refused the transfer");
    Ok(())
}

async fn bind(secret_key: [u8; 32], net: &NetConfig) -> anyhow::Result<Endpoint> {
    let alpns = vec![ALPN_PAIR.to_vec(), ALPN_SYNC.to_vec()];
    let sk = SecretKey::from_bytes(&secret_key);
    let ep = match net {
        NetConfig::N0 => Endpoint::builder(presets::N0).secret_key(sk).alpns(alpns).bind().await?,
        NetConfig::Local(book) => {
            let ep = Endpoint::builder(presets::Minimal)
                .secret_key(sk)
                .alpns(alpns)
                .relay_mode(RelayMode::Disabled)
                .address_lookup(book.clone())
                .bind()
                .await?;
            book.add_endpoint_info(ep.addr());
            ep
        }
    };
    Ok(ep)
}

pub fn spawn(secret_key: [u8; 32], name: String, paired: Arc<RwLock<Vec<PairedDevice>>>) -> (Sender<NetCmd>, Receiver<NetEvent>) {
    spawn_with(secret_key, name, paired, NetConfig::N0)
}

pub fn spawn_with(
    secret_key: [u8; 32],
    name: String,
    paired: Arc<RwLock<Vec<PairedDevice>>>,
    net: NetConfig,
) -> (Sender<NetCmd>, Receiver<NetEvent>) {
    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel::<NetCmd>();
    let (ev_tx, ev_rx) = std::sync::mpsc::channel::<NetEvent>();
    std::thread::Builder::new()
        .name("lzssh-net".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = ev_tx.send(NetEvent::Error(format!("Network runtime failed: {e}")));
                    return;
                }
            };
            rt.block_on(async move {
                let endpoint = match bind(secret_key, &net).await {
                    Ok(e) => e,
                    Err(e) => {
                        let _ = ev_tx.send(NetEvent::Error(format!("Network start failed: {e}")));
                        return;
                    }
                };
                let st = Arc::new(State { endpoint, name, paired, pending: Mutex::new(None), events: ev_tx });
                st.emit(NetEvent::Ready { node_id: id_hex(&st.endpoint.id()) });
                tokio::spawn(accept_loop(st.clone()));
                // Bridge the blocking std receiver into async land.
                let (atx, mut arx) = tokio::sync::mpsc::unbounded_channel();
                std::thread::spawn(move || {
                    while let Ok(c) = cmd_rx.recv() {
                        if atx.send(c).is_err() {
                            break;
                        }
                    }
                });
                while let Some(cmd) = arx.recv().await {
                    let st = st.clone();
                    tokio::spawn(async move {
                        match cmd {
                            NetCmd::StartPairing => match start_pairing(&st).await {
                                Ok(c) => st.emit(NetEvent::PairCode(c)),
                                Err(e) => st.emit(NetEvent::Error(format!("Could not start pairing: {e}"))),
                            },
                            NetCmd::EnterCode(c) => match tokio::time::timeout(IO_TIMEOUT, enter_code(&st, &c)).await {
                                Ok(Ok(d)) => st.add_paired(d),
                                Ok(Err(e)) => st.emit(NetEvent::Error(format!("Pairing failed: {e}"))),
                                Err(_) => st.emit(NetEvent::Error("Pairing failed: other device not reachable".into())),
                            },
                            NetCmd::Send { to, payload } => match tokio::time::timeout(IO_TIMEOUT, send_payload(&st, &to, &payload)).await {
                                Ok(Ok(())) => st.emit(NetEvent::Sent { to }),
                                Ok(Err(e)) => st.emit(NetEvent::SendFailed { to, error: e.to_string() }),
                                Err(_) => st.emit(NetEvent::SendFailed { to, error: "timed out".into() }),
                            },
                        }
                    });
                }
                st.endpoint.close().await;
            });
        })
        .expect("spawn network thread");
    (cmd_tx, ev_rx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Auth, Folder, Host};
    use std::time::Duration;
    use uuid::Uuid;

    const T: Duration = Duration::from_secs(20);

    struct Peer {
        tx: Sender<NetCmd>,
        rx: Receiver<NetEvent>,
        paired: Arc<RwLock<Vec<PairedDevice>>>,
        id: String,
    }

    fn peer(name: &str, net: &NetConfig) -> Peer {
        let paired = Arc::new(RwLock::new(Vec::new()));
        let (tx, rx) = spawn_with(rand_key(), name.into(), paired.clone(), net.clone());
        let id = match rx.recv_timeout(T).unwrap() {
            NetEvent::Ready { node_id } => node_id,
            e => panic!("expected Ready, got {e:?}"),
        };
        Peer { tx, rx, paired, id }
    }

    fn rand_key() -> [u8; 32] {
        crate::vault::random()
    }

    /// Next event that is not a log-only Error, or panic on timeout.
    fn next(p: &Peer) -> NetEvent {
        p.rx.recv_timeout(T).expect("no event within timeout")
    }

    fn code(a: &Peer) -> String {
        a.tx.send(NetCmd::StartPairing).unwrap();
        match next(a) {
            NetEvent::PairCode(c) => c,
            e => panic!("expected PairCode, got {e:?}"),
        }
    }

    fn payload() -> Payload {
        let f = Folder { id: Uuid::new_v4(), name: "F".into() };
        let h = Host {
            id: Uuid::new_v4(),
            folder_id: Some(f.id),
            name: "h".into(),
            ipv4: Some("10.0.0.1".into()),
            ipv6: None,
            port: 22,
            username: "u".into(),
            auth: Auth::Key { secret_id: Uuid::new_v4() },
        };
        Payload { folders: vec![f], hosts: vec![h], secrets: vec![] }
    }

    fn pair(a: &Peer, b: &Peer) {
        let c = code(a);
        b.tx.send(NetCmd::EnterCode(c)).unwrap();
        match next(b) {
            NetEvent::Paired(d) => assert_eq!((d.node_id.as_str(), d.name.as_str()), (a.id.as_str(), "A")),
            e => panic!("B expected Paired, got {e:?}"),
        }
        match next(a) {
            NetEvent::Paired(d) => assert_eq!((d.node_id.as_str(), d.name.as_str()), (b.id.as_str(), "B")),
            e => panic!("A expected Paired, got {e:?}"),
        }
    }

    #[test]
    fn pair_then_send() {
        let net = NetConfig::local();
        let (a, b) = (peer("A", &net), peer("B", &net));
        pair(&a, &b);
        assert_eq!(a.paired.read().unwrap().len(), 1);
        assert_eq!(b.paired.read().unwrap().len(), 1);
        let p = payload();
        b.tx.send(NetCmd::Send { to: a.id.clone(), payload: p.clone() }).unwrap();
        match next(&a) {
            NetEvent::Received { from, payload } => {
                assert_eq!(from, b.id);
                assert_eq!(payload.hosts, p.hosts);
                assert_eq!(payload.folders, p.folders);
            }
            e => panic!("A expected Received, got {e:?}"),
        }
        assert!(matches!(next(&b), NetEvent::Sent { to } if to == a.id));
    }

    #[test]
    fn wrong_secret_rejected() {
        let net = NetConfig::local();
        let (a, b) = (peer("A", &net), peer("B", &net));
        let mut c = code::decode(&code(&a)).unwrap();
        c.secret[0] ^= 1;
        b.tx.send(NetCmd::EnterCode(code::encode(&c))).unwrap();
        assert!(matches!(next(&b), NetEvent::Error(_)));
        assert!(a.rx.recv_timeout(Duration::from_secs(1)).is_err(), "A must not emit Paired");
        assert!(a.paired.read().unwrap().is_empty());
    }

    #[test]
    fn code_single_use() {
        let net = NetConfig::local();
        let (a, b, c) = (peer("A", &net), peer("B", &net), peer("C", &net));
        let s = code(&a);
        b.tx.send(NetCmd::EnterCode(s.clone())).unwrap();
        assert!(matches!(next(&b), NetEvent::Paired(_)));
        assert!(matches!(next(&a), NetEvent::Paired(_)));
        c.tx.send(NetCmd::EnterCode(s)).unwrap();
        assert!(matches!(next(&c), NetEvent::Error(_)));
        assert_eq!(a.paired.read().unwrap().len(), 1);
    }

    #[test]
    fn unpaired_sender_rejected() {
        let net = NetConfig::local();
        let (a, c) = (peer("A", &net), peer("C", &net));
        c.tx.send(NetCmd::Send { to: a.id.clone(), payload: payload() }).unwrap();
        assert!(matches!(next(&c), NetEvent::SendFailed { to, .. } if to == a.id));
        assert!(a.rx.recv_timeout(Duration::from_secs(1)).is_err(), "A must not emit Received");
    }
}

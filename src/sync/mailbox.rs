//! Mailbox sync: pairing and sending through the Worker, driven by a synchronous `Core` on a background thread.
use super::code::{self, PairCode};
use super::crypto::{DeviceKeys, Envelope, Kind, open, parse_id, seal};
use super::payload::Payload;
use super::transport::{HttpTransport, Transport, TransportError, unix_now};
use crate::device::PairedDevice;
use data_encoding::BASE64;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// How long a shown pairing code stays valid.
pub const PAIR_TTL: u64 = 10 * 60;
/// Largest envelope the Worker accepts.
pub const MAX_ENVELOPE: usize = 1024 * 1024;
const POLL_SLOW: Duration = Duration::from_secs(20);
const POLL_FAST: Duration = Duration::from_secs(2);
const NO_SERVER: &str = "Set the sync server on the Devices screen.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    pub url: String,
    pub token: String,
}

#[derive(Debug)]
pub enum NetCmd {
    StartPairing,
    EnterCode(String),
    Send { to: String, payload: Payload },
    /// The received message was applied; remove it from the mailbox.
    Ack(String),
    /// Stop accepting messages from this device.
    Unpair(String),
}

#[derive(Debug)]
pub enum NetEvent {
    Ready { node_id: String },
    PairCode(String),
    Paired(PairedDevice),
    /// Stays in the mailbox until `NetCmd::Ack(id)`.
    Received { id: String, from: String, payload: Payload },
    Sent { to: String },
    SendFailed { to: String, error: String },
    /// A pairing code brought a different server; persist it.
    ServerChanged(ServerConfig),
    Error(String),
}

/// Plaintext of `pair_request` (with `mac`) and `pair_accept` (without).
#[derive(Serialize, Deserialize)]
struct PairHello {
    name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    mac: String,
}

fn ticket_for(secret: &[u8; 16]) -> [u8; 32] {
    Sha256::new().chain_update(b"lzssh-pair-ticket").chain_update(secret).finalize().into()
}

fn pair_mac(secret: &[u8; 16]) -> Hmac<Sha256> {
    Hmac::<Sha256>::new_from_slice(secret).expect("HMAC takes any key length")
}

pub type MakeTransport<T> = Box<dyn Fn(&ServerConfig, DeviceKeys) -> T + Send>;

pub struct Core<T: Transport> {
    keys: DeviceKeys,
    name: String,
    paired: Arc<RwLock<Vec<PairedDevice>>>,
    server: Option<ServerConfig>,
    transport: Option<T>,
    make: MakeTransport<T>,
    /// Secret behind the code currently shown, and when it was created.
    pending: Option<([u8; 16], u64)>,
    /// Devices we sent a pair_request to and expect a pair_accept from.
    awaiting: HashSet<String>,
    /// Payloads handed to the UI and not yet acknowledged.
    emitted: HashSet<String>,
    last_error: Option<String>,
}

impl<T: Transport> Core<T> {
    pub fn new(keys: DeviceKeys, name: String, paired: Arc<RwLock<Vec<PairedDevice>>>, server: Option<ServerConfig>, make: MakeTransport<T>) -> Self {
        let transport = server.as_ref().map(|s| make(s, keys.clone()));
        Core { keys, name, paired, server, transport, make, pending: None, awaiting: HashSet::new(), emitted: HashSet::new(), last_error: None }
    }

    pub fn id(&self) -> String {
        self.keys.id()
    }

    /// Poll fast while a code is shown or a pairing answer is due.
    pub fn fast_poll(&self) -> bool {
        self.pending.is_some() || !self.awaiting.is_empty()
    }

    fn is_paired(&self, id: &str) -> bool {
        self.paired.read().expect("paired lock").iter().any(|d| d.node_id == id)
    }

    fn add_paired(&self, d: PairedDevice) {
        let mut p = self.paired.write().expect("paired lock");
        match p.iter_mut().find(|x| x.node_id == d.node_id) {
            Some(x) => x.name = d.name,
            None => p.push(d),
        }
    }

    /// Emits an error once until it changes or a request succeeds.
    fn report(&mut self, out: &mut Vec<NetEvent>, msg: String) {
        if self.last_error.as_ref() != Some(&msg) {
            out.push(NetEvent::Error(msg.clone()));
            self.last_error = Some(msg);
        }
    }

    fn transport_or_report(&mut self, out: &mut Vec<NetEvent>) -> Option<&T> {
        if self.transport.is_none() {
            self.report(out, NO_SERVER.into());
        }
        self.transport.as_ref()
    }

    /// Re-registers every paired device in this device's allow list.
    pub fn start(&mut self) -> Vec<NetEvent> {
        let mut out = Vec::new();
        let ids: Vec<String> = self.paired.read().expect("paired lock").iter().map(|d| d.node_id.clone()).collect();
        let Some(t) = self.transport.as_ref() else { return out };
        let failed = ids.iter().map(|id| t.allow(id)).find_map(Result::err);
        if let Some(e) = failed {
            self.report(&mut out, e.to_string());
        }
        out
    }

    pub fn start_pairing(&mut self, now: u64) -> Vec<NetEvent> {
        let mut out = Vec::new();
        let (Some(t), Some(server)) = (self.transport.as_ref(), self.server.clone()) else {
            self.report(&mut out, NO_SERVER.into());
            return out;
        };
        let secret: [u8; 16] = crate::vault::random();
        match t.set_pairing(Sha256::digest(ticket_for(&secret)).into(), now + PAIR_TTL) {
            Ok(()) => {
                self.pending = Some((secret, now));
                out.push(NetEvent::PairCode(code::encode(&PairCode { device: self.keys.public(), secret, token: server.token, server: server.url })));
            }
            Err(e) => out.push(NetEvent::Error(format!("Could not start pairing: {e}"))),
        }
        out
    }

    pub fn enter_code(&mut self, code_str: &str) -> Vec<NetEvent> {
        let mut out = Vec::new();
        if let Err(e) = self.try_enter_code(code_str, &mut out) {
            out.push(NetEvent::Error(format!("Pairing failed: {e}")));
        }
        out
    }

    fn try_enter_code(&mut self, code_str: &str, out: &mut Vec<NetEvent>) -> anyhow::Result<()> {
        let c = code::decode(code_str)?;
        let peer = hex::encode(c.device);
        parse_id(&peer)?;
        anyhow::ensure!(peer != self.id(), "this code was created on this device");
        let cfg = ServerConfig { url: c.server.clone(), token: c.token.clone() };
        if self.server.as_ref() != Some(&cfg) {
            self.transport = Some((self.make)(&cfg, self.keys.clone()));
            self.server = Some(cfg.clone());
            out.push(NetEvent::ServerChanged(cfg));
        }
        let t = self.transport.as_ref().expect("set above");
        t.allow(&peer)?;
        let mac = pair_mac(&c.secret).chain_update(self.keys.public()).finalize().into_bytes();
        let hello = PairHello { name: self.name.clone(), mac: BASE64.encode(&mac) };
        let env = seal(&self.keys, &peer, Kind::PairRequest, &serde_json::to_vec(&hello)?)?;
        t.post(&env, Some(&ticket_for(&c.secret)))?;
        self.awaiting.insert(peer);
        Ok(())
    }

    pub fn send(&mut self, to: &str, p: &Payload) -> Vec<NetEvent> {
        let mut out = Vec::new();
        let failed = |e: String| NetEvent::SendFailed { to: to.to_string(), error: e };
        if self.transport_or_report(&mut out).is_none() {
            out.push(failed(NO_SERVER.into()));
            return out;
        }
        let t = self.transport.as_ref().expect("checked above");
        let env = match serde_json::to_vec(p).map_err(anyhow::Error::from).and_then(|b| seal(&self.keys, to, Kind::Payload, &b)) {
            Ok(e) => e,
            Err(e) => {
                out.push(failed(e.to_string()));
                return out;
            }
        };
        if serde_json::to_vec(&env).map_or(usize::MAX, |b| b.len()) > MAX_ENVELOPE {
            out.push(failed(TransportError::TooLarge.to_string()));
            return out;
        }
        out.push(match t.post(&env, None) {
            Ok(()) => NetEvent::Sent { to: to.to_string() },
            Err(e) => failed(e.to_string()),
        });
        out
    }

    pub fn poll(&mut self, now: u64) -> Vec<NetEvent> {
        let mut out = Vec::new();
        if self.pending.is_some_and(|(_, at)| now > at + PAIR_TTL) {
            self.pending = None;
        }
        let Some(t) = self.transport_or_report(&mut out) else { return out };
        let msgs = match t.list() {
            Ok(m) => m,
            Err(e) => {
                self.report(&mut out, e.to_string());
                return out;
            }
        };
        self.last_error = None;
        for env in msgs {
            if self.emitted.contains(&env.id) {
                continue;
            }
            let keep = self.handle(&env, &mut out);
            if !keep {
                if let Some(t) = self.transport.as_ref() {
                    let _ = t.delete(&env.id);
                }
            }
        }
        out
    }

    /// Handles one message; returns true if it must stay in the mailbox (payload waiting for Ack).
    fn handle(&mut self, env: &Envelope, out: &mut Vec<NetEvent>) -> bool {
        let Ok(plain) = open(&self.keys, env) else { return false };
        match env.kind {
            Kind::PairRequest => {
                let Ok(hello) = serde_json::from_slice::<PairHello>(&plain) else { return false };
                let Some((secret, _)) = self.pending else { return false };
                let Ok(from_key) = parse_id(&env.from) else { return false };
                let Ok(mac) = BASE64.decode(hello.mac.as_bytes()) else { return false };
                if pair_mac(&secret).chain_update(from_key.as_bytes()).verify_slice(&mac).is_err() {
                    return false;
                }
                self.pending = None;
                let d = PairedDevice { node_id: env.from.clone(), name: hello.name };
                self.add_paired(d.clone());
                if let Some(t) = self.transport.as_ref() {
                    let accept = PairHello { name: self.name.clone(), mac: String::new() };
                    let sent = t
                        .allow(&env.from)
                        .map_err(anyhow::Error::from)
                        .and_then(|_| Ok(seal(&self.keys, &env.from, Kind::PairAccept, &serde_json::to_vec(&accept)?)?))
                        .and_then(|e| Ok(t.post(&e, None)?));
                    if let Err(e) = sent {
                        out.push(NetEvent::Error(format!("Paired, but could not answer {}: {e}", d.name)));
                    }
                }
                out.push(NetEvent::Paired(d));
                false
            }
            Kind::PairAccept => {
                if !self.awaiting.remove(&env.from) {
                    return false;
                }
                let Ok(hello) = serde_json::from_slice::<PairHello>(&plain) else { return false };
                let d = PairedDevice { node_id: env.from.clone(), name: hello.name };
                self.add_paired(d.clone());
                out.push(NetEvent::Paired(d));
                false
            }
            Kind::Payload => {
                if !self.is_paired(&env.from) {
                    return false;
                }
                let Ok(payload) = serde_json::from_slice::<Payload>(&plain) else { return false };
                self.emitted.insert(env.id.clone());
                out.push(NetEvent::Received { id: env.id.clone(), from: env.from.clone(), payload });
                true
            }
        }
    }

    pub fn ack(&mut self, id: &str) -> Vec<NetEvent> {
        let mut out = Vec::new();
        self.emitted.remove(id);
        if let Some(t) = self.transport.as_ref() {
            if let Err(e) = t.delete(id) {
                out.push(NetEvent::Error(format!("Could not clear the mailbox: {e}")));
            }
        }
        out
    }

    pub fn unpair(&mut self, id: &str) -> Vec<NetEvent> {
        let mut out = Vec::new();
        self.awaiting.remove(id);
        if let Some(t) = self.transport.as_ref() {
            if let Err(e) = t.disallow(id) {
                out.push(NetEvent::Error(format!("Could not block the removed device on the sync server: {e}")));
            }
        }
        out
    }

    pub fn handle_cmd(&mut self, cmd: NetCmd) -> Vec<NetEvent> {
        match cmd {
            NetCmd::StartPairing => self.start_pairing(unix_now()),
            NetCmd::EnterCode(c) => self.enter_code(&c),
            NetCmd::Send { to, payload } => self.send(&to, &payload),
            NetCmd::Ack(id) => self.ack(&id),
            NetCmd::Unpair(id) => self.unpair(&id),
        }
    }
}

pub fn spawn(seed: [u8; 32], name: String, paired: Arc<RwLock<Vec<PairedDevice>>>, server: Option<ServerConfig>) -> (Sender<NetCmd>, Receiver<NetEvent>) {
    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel::<NetCmd>();
    let (ev_tx, ev_rx) = std::sync::mpsc::channel::<NetEvent>();
    std::thread::Builder::new()
        .name("lzssh-sync".into())
        .spawn(move || {
            let keys = DeviceKeys::from_secret(&seed);
            let make: MakeTransport<HttpTransport> = Box::new(|cfg, k| HttpTransport::new(&cfg.url, &cfg.token, k));
            let mut core = Core::new(keys, name, paired, server, make);
            let emit = |evs: Vec<NetEvent>| evs.into_iter().all(|e| ev_tx.send(e).is_ok());
            if !emit(vec![NetEvent::Ready { node_id: core.id() }]) || !emit(core.start()) {
                return;
            }
            let mut next_poll = Instant::now();
            loop {
                let now = Instant::now();
                if now >= next_poll {
                    if !emit(core.poll(unix_now())) {
                        return;
                    }
                    next_poll = Instant::now() + if core.fast_poll() { POLL_FAST } else { POLL_SLOW };
                }
                match cmd_rx.recv_timeout(next_poll.saturating_duration_since(Instant::now())) {
                    Ok(cmd) => {
                        if !emit(core.handle_cmd(cmd)) {
                            return;
                        }
                        if core.fast_poll() {
                            next_poll = next_poll.min(Instant::now() + POLL_FAST);
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => return,
                }
            }
        })
        .expect("spawn sync thread");
    (cmd_tx, ev_rx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Auth, Folder, Host};
    use crate::sync::transport::{MemServer, MemTransport};
    use uuid::Uuid;

    const T0: u64 = 1_800_000_000;
    const URL: &str = "https://lzssh.example";

    fn core(srv: &MemServer, name: &str) -> Core<MemTransport> {
        core_with(srv, name, Arc::new(RwLock::new(Vec::new())), crate::vault::random())
    }

    fn core_with(srv: &MemServer, name: &str, paired: Arc<RwLock<Vec<PairedDevice>>>, seed: [u8; 32]) -> Core<MemTransport> {
        let s = srv.clone();
        let cfg = ServerConfig { url: URL.into(), token: "tok".into() };
        Core::new(DeviceKeys::from_secret(&seed), name.into(), paired, Some(cfg), Box::new(move |_, k| s.transport(&k)))
    }

    fn payload(host_name: &str) -> Payload {
        let f = Folder { id: Uuid::new_v4(), name: "F".into() };
        let h = Host {
            id: Uuid::new_v4(),
            folder_id: Some(f.id),
            name: host_name.into(),
            ipv4: Some("10.0.0.1".into()),
            ipv6: None,
            port: 22,
            username: "u".into(),
            auth: Auth::Key { secret_id: Uuid::new_v4() },
        };
        Payload { folders: vec![f], hosts: vec![h], secrets: vec![] }
    }

    fn code_of(evs: Vec<NetEvent>) -> String {
        match evs.into_iter().next() {
            Some(NetEvent::PairCode(c)) => c,
            e => panic!("expected PairCode, got {e:?}"),
        }
    }

    fn paired_names(evs: &[NetEvent]) -> Vec<(String, String)> {
        evs.iter().filter_map(|e| if let NetEvent::Paired(d) = e { Some((d.node_id.clone(), d.name.clone())) } else { None }).collect()
    }

    fn pair(a: &mut Core<MemTransport>, b: &mut Core<MemTransport>) {
        let c = code_of(a.start_pairing(T0));
        assert!(b.enter_code(&c).is_empty());
        assert_eq!(paired_names(&a.poll(T0 + 1)), vec![(b.id(), "B".to_string())]);
        assert_eq!(paired_names(&b.poll(T0 + 2)), vec![(a.id(), "A".to_string())]);
    }

    #[test]
    fn pair_then_send() {
        let srv = MemServer::default();
        srv.set_now(T0);
        let (mut a, mut b) = (core(&srv, "A"), core(&srv, "B"));
        pair(&mut a, &mut b);
        assert_eq!(a.paired.read().unwrap().len(), 1);
        assert_eq!(b.paired.read().unwrap().len(), 1);
        assert!(!a.fast_poll() && !b.fast_poll());
        let p = payload("h");
        assert!(matches!(b.send(&a.id(), &p).as_slice(), [NetEvent::Sent { to }] if *to == a.id()));
        let evs = a.poll(T0 + 3);
        let id = match evs.as_slice() {
            [NetEvent::Received { id, from, payload }] => {
                assert_eq!(*from, b.id());
                assert_eq!(payload.hosts, p.hosts);
                id.clone()
            }
            e => panic!("expected Received, got {e:?}"),
        };
        assert!(a.ack(&id).is_empty());
        assert!(a.poll(T0 + 4).is_empty());
        assert!(srv.transport(&a.keys).list().unwrap().is_empty());
    }

    #[test]
    fn wrong_secret_rejected() {
        let srv = MemServer::default();
        srv.set_now(T0);
        let (mut a, mut b) = (core(&srv, "A"), core(&srv, "B"));
        let mut c = code::decode(&code_of(a.start_pairing(T0))).unwrap();
        c.secret[0] ^= 1;
        // Wrong S also means a wrong ticket: the server refuses it.
        assert!(matches!(b.enter_code(&code::encode(&c)).as_slice(), [NetEvent::Error(_)]));
        assert!(paired_names(&a.poll(T0 + 1)).is_empty());
        assert!(a.paired.read().unwrap().is_empty());
    }

    #[test]
    fn wrong_mac_rejected() {
        let srv = MemServer::default();
        srv.set_now(T0);
        let (mut a, b) = (core(&srv, "A"), core(&srv, "B"));
        let c = code::decode(&code_of(a.start_pairing(T0))).unwrap();
        // Right ticket, but the HMAC is made with another secret.
        let hello = PairHello { name: "B".into(), mac: BASE64.encode(&pair_mac(&[1; 16]).chain_update(b.keys.public()).finalize().into_bytes()) };
        let env = seal(&b.keys, &a.id(), Kind::PairRequest, &serde_json::to_vec(&hello).unwrap()).unwrap();
        srv.transport(&b.keys).post(&env, Some(&ticket_for(&c.secret))).unwrap();
        assert!(paired_names(&a.poll(T0 + 1)).is_empty());
        assert!(a.paired.read().unwrap().is_empty());
    }

    #[test]
    fn expired_code_rejected() {
        let srv = MemServer::default();
        srv.set_now(T0);
        let (mut a, mut b) = (core(&srv, "A"), core(&srv, "B"));
        let c = code_of(a.start_pairing(T0));
        assert!(b.enter_code(&c).is_empty());
        assert!(paired_names(&a.poll(T0 + PAIR_TTL + 1)).is_empty());
        assert!(a.paired.read().unwrap().is_empty());
        assert!(!a.fast_poll());
    }

    #[test]
    fn code_single_use() {
        let srv = MemServer::default();
        srv.set_now(T0);
        let (mut a, mut b, mut c) = (core(&srv, "A"), core(&srv, "B"), core(&srv, "C"));
        let code = code_of(a.start_pairing(T0));
        assert!(b.enter_code(&code).is_empty());
        assert_eq!(paired_names(&a.poll(T0 + 1)).len(), 1);
        assert!(matches!(c.enter_code(&code).as_slice(), [NetEvent::Error(e)] if e.contains("pair again")));
        assert!(a.poll(T0 + 2).is_empty());
        assert_eq!(a.paired.read().unwrap().len(), 1);
    }

    #[test]
    fn unpaired_sender_rejected() {
        let srv = MemServer::default();
        let (a, mut c) = (core(&srv, "A"), core(&srv, "C"));
        assert!(matches!(c.send(&a.id(), &payload("h")).as_slice(), [NetEvent::SendFailed { to, .. }] if *to == a.id()));
    }

    #[test]
    fn send_to_device_that_removed_us_fails() {
        let srv = MemServer::default();
        srv.set_now(T0);
        let (mut a, mut b) = (core(&srv, "A"), core(&srv, "B"));
        pair(&mut a, &mut b);
        assert!(a.unpair(&b.id()).is_empty());
        assert!(matches!(b.send(&a.id(), &payload("h")).as_slice(), [NetEvent::SendFailed { error, .. }] if error.contains("pair again")));
    }

    #[test]
    fn unacked_message_not_reemitted_but_kept() {
        let srv = MemServer::default();
        srv.set_now(T0);
        let seed_a = crate::vault::random();
        let paired_a = Arc::new(RwLock::new(Vec::new()));
        let mut a = core_with(&srv, "A", paired_a.clone(), seed_a);
        let mut b = core(&srv, "B");
        pair(&mut a, &mut b);
        b.send(&a.id(), &payload("h"));
        assert_eq!(a.poll(T0 + 3).len(), 1);
        assert!(a.poll(T0 + 4).is_empty());
        let mut a2 = core_with(&srv, "A", paired_a, seed_a);
        assert!(matches!(a2.poll(T0 + 5).as_slice(), [NetEvent::Received { .. }]));
    }

    #[test]
    fn start_reregisters_allow_list() {
        let srv = MemServer::default();
        let (sa, sb): ([u8; 32], [u8; 32]) = (crate::vault::random(), crate::vault::random());
        let (ida, idb) = (DeviceKeys::from_secret(&sa).id(), DeviceKeys::from_secret(&sb).id());
        let pa = Arc::new(RwLock::new(vec![PairedDevice { node_id: idb.clone(), name: "B".into() }]));
        let pb = Arc::new(RwLock::new(vec![PairedDevice { node_id: ida.clone(), name: "A".into() }]));
        let (mut a, mut b) = (core_with(&srv, "A", pa, sa), core_with(&srv, "B", pb, sb));
        assert!(matches!(b.send(&ida, &payload("h")).as_slice(), [NetEvent::SendFailed { .. }]));
        assert!(a.start().is_empty());
        assert!(b.start().is_empty());
        assert!(matches!(b.send(&ida, &payload("h")).as_slice(), [NetEvent::Sent { .. }]));
        assert!(matches!(a.poll(unix_now()).as_slice(), [NetEvent::Received { .. }]));
    }

    #[test]
    fn poll_errors_toast_once_until_success() {
        let srv = MemServer::default();
        let mut a = core(&srv, "A");
        srv.fail_next(vec![TransportError::Clock, TransportError::Clock]);
        assert!(matches!(a.poll(T0).as_slice(), [NetEvent::Error(e)] if e.contains("clock")));
        assert!(a.poll(T0).is_empty());
        assert!(a.poll(T0).is_empty());
        srv.fail_next(vec![TransportError::Clock]);
        assert!(matches!(a.poll(T0).as_slice(), [NetEvent::Error(_)]));
    }

    #[test]
    fn no_server_reports_once() {
        let srv = MemServer::default();
        let s = srv.clone();
        let mut a: Core<MemTransport> =
            Core::new(DeviceKeys::from_secret(&[3; 32]), "A".into(), Arc::new(RwLock::new(Vec::new())), None, Box::new(move |_, k| s.transport(&k)));
        assert!(matches!(a.poll(T0).as_slice(), [NetEvent::Error(e)] if e == NO_SERVER));
        assert!(a.poll(T0).is_empty());
        assert!(matches!(a.start_pairing(T0).as_slice(), []));
    }

    #[test]
    fn oversized_payload_refused_locally() {
        let srv = MemServer::default();
        srv.set_now(T0);
        let (mut a, mut b) = (core(&srv, "A"), core(&srv, "B"));
        pair(&mut a, &mut b);
        let before = srv.posts();
        let evs = b.send(&a.id(), &payload(&"x".repeat(1_100_000)));
        assert!(matches!(evs.as_slice(), [NetEvent::SendFailed { error, .. }] if error.contains("limit 1 MiB")));
        assert_eq!(srv.posts(), before);
    }

    #[test]
    fn code_from_other_server_switches_server() {
        let srv = MemServer::default();
        srv.set_now(T0);
        let mut a = core(&srv, "A");
        let s = srv.clone();
        let mut b: Core<MemTransport> =
            Core::new(DeviceKeys::from_secret(&[4; 32]), "B".into(), Arc::new(RwLock::new(Vec::new())), None, Box::new(move |_, k| s.transport(&k)));
        let evs = b.enter_code(&code_of(a.start_pairing(T0)));
        assert!(matches!(evs.as_slice(), [NetEvent::ServerChanged(c)] if c.url == URL && c.token == "tok"));
        assert_eq!(paired_names(&a.poll(T0 + 1)).len(), 1);
    }

    /// Runs against a real Worker: `LZSSH_TEST_SERVER=http://127.0.0.1:8787 LZSSH_TEST_TOKEN=… cargo test -- --ignored live_`.
    #[test]
    #[ignore]
    fn live_pair_and_send() {
        let (Ok(url), Ok(token)) = (std::env::var("LZSSH_TEST_SERVER"), std::env::var("LZSSH_TEST_TOKEN")) else {
            panic!("set LZSSH_TEST_SERVER and LZSSH_TEST_TOKEN");
        };
        let cfg = ServerConfig { url, token };
        let mk = |name: &str| {
            let make: MakeTransport<HttpTransport> = Box::new(|c, k| HttpTransport::new(&c.url, &c.token, k));
            Core::new(DeviceKeys::from_secret(&crate::vault::random()), name.into(), Arc::new(RwLock::new(Vec::new())), Some(cfg.clone()), make)
        };
        let (mut a, mut b) = (mk("A"), mk("B"));
        let c = code_of(a.start_pairing(unix_now()));
        assert!(b.enter_code(&c).is_empty());
        assert_eq!(paired_names(&a.poll(unix_now())), vec![(b.id(), "B".to_string())]);
        assert_eq!(paired_names(&b.poll(unix_now())), vec![(a.id(), "A".to_string())]);
        assert!(matches!(b.send(&a.id(), &payload("live")).as_slice(), [NetEvent::Sent { .. }]));
        let id = match a.poll(unix_now()).as_slice() {
            [NetEvent::Received { id, payload, .. }] => {
                assert_eq!(payload.hosts[0].name, "live");
                id.clone()
            }
            e => panic!("expected Received, got {e:?}"),
        };
        assert!(a.ack(&id).is_empty());
        assert!(a.poll(unix_now()).is_empty());
    }
}

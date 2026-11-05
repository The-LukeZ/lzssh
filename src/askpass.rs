//! SSH_ASKPASS bridge: ssh.exe runs `lzssh.exe` (with LZSSH_ASKPASS=1) as its askpass helper;
//! that helper asks the running app for the password over a per-user named pipe, using a
//! single-use token that only the launched ssh process received in its environment.
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::ServerOptions;
pub use zeroize::Zeroizing;

pub const PIPE_NAME: &str = r"\\.\pipe\lzssh-askpass";
const TOKEN_TTL: Duration = Duration::from_secs(60);

/// token -> (password, issued at). Single use, expires after 60 s.
pub type Registry = Arc<Mutex<HashMap<String, (Zeroizing<String>, Instant)>>>;

pub fn register(reg: &Registry, password: Zeroizing<String>) -> String {
    let token = hex::encode(crate::vault::random::<16>());
    let mut r = reg.lock().expect("askpass lock");
    r.retain(|_, (_, at)| at.elapsed() < TOKEN_TTL);
    r.insert(token.clone(), (password, Instant::now()));
    token
}

/// Removes and returns the password for a live token.
pub fn take(reg: &Registry, token: &str) -> Option<Zeroizing<String>> {
    let (pw, at) = reg.lock().expect("askpass lock").remove(token)?;
    (at.elapsed() < TOKEN_TTL).then_some(pw)
}

async fn handle(mut pipe: tokio::net::windows::named_pipe::NamedPipeServer, reg: Registry) -> anyhow::Result<()> {
    let mut line = String::new();
    let (rd, _) = tokio::io::split(&mut pipe);
    let mut rd = tokio::io::BufReader::new(rd);
    tokio::time::timeout(Duration::from_secs(5), rd.read_line(&mut line)).await??;
    drop(rd);
    let reply = match take(&reg, line.trim()) {
        Some(pw) => Zeroizing::new(format!("{}\n", pw.as_str())),
        None => Zeroizing::new(String::new()),
    };
    pipe.write_all(reply.as_bytes()).await?;
    pipe.flush().await?;
    let _ = pipe.disconnect();
    Ok(())
}

pub async fn serve_on(name: String, reg: Registry) -> anyhow::Result<()> {
    let mut server = ServerOptions::new().first_pipe_instance(true).reject_remote_clients(true).create(&name)?;
    loop {
        server.connect().await?;
        let connected = server;
        server = ServerOptions::new().reject_remote_clients(true).create(&name)?;
        tokio::spawn(handle(connected, reg.clone()));
    }
}

pub async fn serve(reg: Registry) -> anyhow::Result<()> {
    serve_on(PIPE_NAME.to_string(), reg).await
}

/// Start the pipe server on its own thread/runtime. Returns the registry to register passwords in.
pub fn spawn_server() -> Registry {
    let reg = Registry::default();
    let r = reg.clone();
    std::thread::Builder::new()
        .name("lzssh-askpass".into())
        .spawn(move || {
            if let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() {
                let _ = rt.block_on(serve(r));
            }
        })
        .expect("spawn askpass thread");
    reg
}

/// Client side (blocking): send the token, read the password line.
pub fn request(pipe: &str, token: &str) -> anyhow::Result<Zeroizing<String>> {
    // Retry briefly: the pipe may not exist yet, or all instances may be busy (ERROR_PIPE_BUSY).
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut f = loop {
        match std::fs::OpenOptions::new().read(true).write(true).open(pipe) {
            Ok(f) => break f,
            Err(e) if Instant::now() < deadline && (e.kind() == std::io::ErrorKind::NotFound || e.raw_os_error() == Some(231)) => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(e.into()),
        }
    };
    f.write_all(format!("{token}\n").as_bytes())?;
    f.flush()?;
    let mut line = Zeroizing::new(String::new());
    BufReader::new(f).read_line(&mut line)?;
    anyhow::ensure!(line.ends_with('\n'), "no password for this token");
    Ok(Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_string()))
}

/// Entry point when ssh.exe runs us as SSH_ASKPASS. Prints the password; exit 1 on failure.
pub fn client_main() -> i32 {
    let Ok(token) = std::env::var("LZSSH_ASKPASS_TOKEN") else { return 1 };
    match request(PIPE_NAME, &token) {
        Ok(pw) => {
            println!("{}", pw.as_str());
            0
        }
        Err(_) => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn pipe_roundtrip_single_use() {
        let name = format!(r"\\.\pipe\lzssh-askpass-test-{}", uuid::Uuid::new_v4());
        let reg = Registry::default();
        tokio::spawn({ let (n, r) = (name.clone(), reg.clone()); async move { if let Err(e) = serve_on(n, r).await { eprintln!("SERVE ERR: {e:?}"); } } });
        let token = register(&reg, Zeroizing::new("s3cret".into()));
        assert_eq!(token.len(), 32);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
        let (n, t) = (name.clone(), token.clone());
        let first = tokio::task::spawn_blocking(move || request(&n, &t)).await.unwrap();
        assert_eq!(first.unwrap().as_str(), "s3cret");
        let second = tokio::task::spawn_blocking(move || request(&name, &token)).await.unwrap();
        assert!(second.is_err());
    }

    #[test]
    fn expired_token_not_served() {
        let reg = Registry::default();
        let t = register(&reg, Zeroizing::new("x".into()));
        reg.lock().unwrap().get_mut(&t).unwrap().1 -= std::time::Duration::from_secs(61);
        assert!(take(&reg, &t).is_none());
    }
}

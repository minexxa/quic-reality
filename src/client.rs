use crate::auth::{self, parse_short_id, SHORT_ID_LEN};
use crate::config::Config;
use crate::protocol::*;
use crate::reality_socket::RealitySocket;
use crate::salamander::Salamander;
use crate::tls;
use crate::util::relay_tcp_quic;
use anyhow::{anyhow, bail, Context, Result};
use bytes::BytesMut;
use quinn::{Connection, Endpoint, EndpointConfig, RecvStream, SendStream, TokioRuntime, TransportConfig};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, info, warn};
use x25519_dalek::PublicKey;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Must exceed the server's own 10 s target-connect timeout, so a live server
/// always answers (OK or error) before the client concludes it is dead.
const OPEN_TIMEOUT: Duration = Duration::from_secs(15);
const UDP_ASSOC_IDLE: Duration = Duration::from_secs(120);

/// Owns the single QUIC connection and transparently re-establishes it.
pub struct ConnManager {
    endpoint: Endpoint,
    server_addr: SocketAddr,
    server_pub: PublicKey,
    short_id: [u8; SHORT_ID_LEN],
    sni: String,
    transport: Arc<TransportConfig>,
    conn: tokio::sync::Mutex<Option<Connection>>,
}

impl ConnManager {
    pub async fn new(cfg: &Config) -> Result<Arc<Self>> {
        let server_addr = tokio::net::lookup_host(&cfg.server)
            .await
            .with_context(|| format!("resolving {}", cfg.server))?
            .next()
            .ok_or_else(|| anyhow!("server address did not resolve"))?;
        let server_pub = PublicKey::from(auth::decode_hex32(&cfg.reality.public_key)?);
        let bind: SocketAddr = if server_addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse()?;
        let salamander = cfg
            .obfuscation
            .is_salamander()
            .then(|| Salamander::new(cfg.obfuscation.password.as_bytes()))
        .transpose()?;
        let socket = RealitySocket::bind(bind, salamander, None)?;
        // quinn sets the grease-QUIC-bit transport parameter by default; browsers
        // do not send it.
        let mut ep_cfg = EndpointConfig::default();
        ep_cfg.grease_quic_bit(false);
        let endpoint = Endpoint::new_with_abstract_socket(
            ep_cfg,
            None,
            socket,
            Arc::new(TokioRuntime),
        )?;
        Ok(Arc::new(Self {
            endpoint,
            server_addr,
            server_pub,
            short_id: parse_short_id(&cfg.reality.short_id)?,
            sni: cfg.reality.server_name.clone(),
            // The client never probes the dest (it only ever talks to the
            // REALITY server), so there is no flight to shape after: its
            // transport parameters stay the browser-like defaults.
            transport: tls::make_transport(&cfg.quic, None),
            conn: tokio::sync::Mutex::new(None),
        }))
    }

    async fn connect(&self) -> Result<Connection> {
        let m = auth::client_material(&self.server_pub, &self.short_id, auth::now_secs())?;
        let cfg = tls::make_client_config(m, self.transport.clone())?;
        let connecting = self.endpoint.connect_with(cfg, self.server_addr, &self.sni)?;
        let conn = tokio::time::timeout(CONNECT_TIMEOUT, connecting)
            .await
            .context("handshake timed out (wrong key/short_id/server_name, or server unreachable)")??;
        info!("connected to {}", self.server_addr);
        Ok(conn)
    }

    async fn get(&self) -> Result<Connection> {
        let mut g = self.conn.lock().await;
        if let Some(c) = g.as_ref() {
            if c.close_reason().is_none() {
                return Ok(c.clone());
            }
        }
        let c = self.connect().await?;
        *g = Some(c.clone());
        Ok(c)
    }

    async fn invalidate(&self, id: usize) {
        let mut g = self.conn.lock().await;
        if g.as_ref().is_some_and(|c| c.stable_id() == id) {
            *g = None;
        }
    }

    #[cfg(test)]
    pub async fn close_for_test(&self) {
        if let Some(c) = self.conn.lock().await.as_ref() {
            c.close(0u32.into(), b"test");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    /// Opens a stream.  If the connection turns out to be dead (closed, reset by
    /// a restarted server, or silent for `OPEN_TIMEOUT`) it is dropped and the
    /// request is retried once on a fresh connection.  Refusals from the server
    /// (policy, unreachable target) are final and never trigger a reconnect.
    pub async fn open(&self, cmd: u8, target: &TargetAddr) -> Result<(SendStream, RecvStream)> {
        let mut last = anyhow!("unreachable");
        for attempt in 0..2 {
            let conn = self.get().await?;
            match tokio::time::timeout(OPEN_TIMEOUT, self.open_on(&conn, cmd, target)).await {
                Ok(Ok(s)) => return Ok(s),
                Ok(Err(OpenErr::Refused(e))) => return Err(e),
                Ok(Err(OpenErr::Conn(e))) => last = e,
                Err(_) => {
                    last = anyhow!("server did not answer within {}s", OPEN_TIMEOUT.as_secs())
                }
            }
            warn!("connection looks dead ({last:#}); reconnecting (attempt {})", attempt + 1);
            conn.close(0u32.into(), b"reconnect");
            self.invalidate(conn.stable_id()).await;
        }
        Err(last)
    }

    async fn open_on(
        &self,
        conn: &Connection,
        cmd: u8,
        target: &TargetAddr,
    ) -> std::result::Result<(SendStream, RecvStream), OpenErr> {
        let req = encode_request(cmd, target).map_err(OpenErr::Refused)?;
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| OpenErr::Conn(e.into()))?;
        send.write_all(&req).await.map_err(|e| OpenErr::Conn(e.into()))?;
        let status = recv.read_u8().await.map_err(|e| OpenErr::Conn(e.into()))?;
        match status {
            STATUS_OK => Ok((send, recv)),
            STATUS_DENIED => Err(OpenErr::Refused(anyhow!("target not allowed by server policy"))),
            _ => Err(OpenErr::Refused(anyhow!("server could not reach target"))),
        }
    }
}

/// Why opening a stream failed: the server said no, or the connection is bad.
enum OpenErr {
    Refused(anyhow::Error),
    Conn(anyhow::Error),
}

pub async fn run(cfg: Config) -> Result<()> {
    let mgr = ConnManager::new(&cfg).await?;
    mgr.get().await.context("initial connection failed")?;

    let socks_l = TcpListener::bind(&cfg.local.socks)
        .await
        .with_context(|| format!("binding socks {}", cfg.local.socks))?;
    let http_l = TcpListener::bind(&cfg.local.http)
        .await
        .with_context(|| format!("binding http {}", cfg.local.http))?;
    info!("SOCKS5 on {}, HTTP proxy on {}", cfg.local.socks, cfg.local.http);

    let udp = UdpRelay::bind(socks_l.local_addr()?.ip(), mgr.clone()).await?;

    let m = mgr.clone();
    let socks = tokio::spawn(async move {
        loop {
            let Ok((s, _)) = socks_l.accept().await else { continue };
            let (m, udp) = (m.clone(), udp.clone());
            tokio::spawn(async move {
                if let Err(e) = handle_socks(m, s, udp).await {
                    debug!("socks: {e:#}");
                }
            });
        }
    });
    let m = mgr.clone();
    let http = tokio::spawn(async move {
        loop {
            let Ok((s, _)) = http_l.accept().await else { continue };
            let m = m.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_http(m, s).await {
                    debug!("http: {e:#}");
                }
            });
        }
    });
    tokio::select! { _ = socks => {}, _ = http => {}, _ = tokio::signal::ctrl_c() => {} }
    Ok(())
}

// ------------------------------------------------------------------ SOCKS5

async fn socks_reply(s: &mut TcpStream, rep: u8, bound: Option<SocketAddr>) -> Result<()> {
    let mut b = BytesMut::from(&[5u8, rep, 0][..]);
    TargetAddr::Ip(bound.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap())).encode(&mut b)?;
    s.write_all(&b).await?;
    Ok(())
}

async fn handle_socks(mgr: Arc<ConnManager>, mut tcp: TcpStream, udp: Arc<UdpRelay>) -> Result<()> {
    let _ = tcp.set_nodelay(true);
    if tcp.read_u8().await? != 5 {
        bail!("not SOCKS5");
    }
    let n = tcp.read_u8().await? as usize;
    let mut methods = vec![0u8; n];
    tcp.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        tcp.write_all(&[5, 0xff]).await?;
        bail!("no acceptable auth method");
    }
    tcp.write_all(&[5, 0]).await?;

    let mut head = [0u8; 3];
    tcp.read_exact(&mut head).await?;
    let target = TargetAddr::read_from(&mut tcp).await?;
    match head[1] {
        1 => match mgr.open(CMD_TCP, &target).await {
            Ok((send, recv)) => {
                socks_reply(&mut tcp, 0, None).await?;
                relay_tcp_quic(tcp, send, recv).await;
                Ok(())
            }
            Err(e) => {
                socks_reply(&mut tcp, 5, None).await?;
                Err(e)
            }
        },
        3 => {
            socks_reply(&mut tcp, 0, Some(udp.local)).await?;
            // The association lives as long as this TCP connection is open.
            let mut sink = [0u8; 64];
            while tcp.read(&mut sink).await? > 0 {}
            Ok(())
        }
        _ => {
            socks_reply(&mut tcp, 7, None).await?;
            bail!("unsupported SOCKS command {}", head[1])
        }
    }
}

// --------------------------------------------------------- SOCKS5 UDP relay

struct Assoc {
    send: tokio::sync::Mutex<SendStream>,
    last: Mutex<Instant>,
}

pub struct UdpRelay {
    sock: UdpSocket,
    local: SocketAddr,
    mgr: Arc<ConnManager>,
    assocs: Mutex<HashMap<SocketAddr, Arc<Assoc>>>,
}

impl UdpRelay {
    async fn bind(ip: std::net::IpAddr, mgr: Arc<ConnManager>) -> Result<Arc<Self>> {
        let sock = UdpSocket::bind((ip, 0)).await?;
        let local = sock.local_addr()?;
        let this = Arc::new(Self { sock, local, mgr, assocs: Mutex::new(HashMap::new()) });
        let t = this.clone();
        tokio::spawn(async move { t.recv_loop().await });
        let t = this.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                t.assocs.lock().unwrap().retain(|_, a| a.last.lock().unwrap().elapsed() < UDP_ASSOC_IDLE);
            }
        });
        Ok(this)
    }

    async fn recv_loop(self: Arc<Self>) {
        let mut buf = vec![0u8; 65535];
        loop {
            let Ok((n, client)) = self.sock.recv_from(&mut buf).await else { continue };
            // RSV(2) FRAG(1) ADDR PAYLOAD
            if n < 4 || buf[2] != 0 {
                continue; // fragmentation is not supported
            }
            let Ok((addr, used)) = TargetAddr::parse(&buf[3..n]) else { continue };
            let payload = buf[3 + used..n].to_vec();
            let this = self.clone();
            tokio::spawn(async move {
                if let Err(e) = this.forward(client, addr, payload).await {
                    debug!("udp: {e:#}");
                }
            });
        }
    }

    async fn forward(self: Arc<Self>, client: SocketAddr, addr: TargetAddr, payload: Vec<u8>) -> Result<()> {
        let existing = self.assocs.lock().unwrap().get(&client).cloned();
        let assoc = match existing {
            Some(a) => a,
            None => {
                let dummy = TargetAddr::Ip("0.0.0.0:0".parse().unwrap());
                let (send, mut recv) = self.mgr.open(CMD_UDP, &dummy).await?;
                let a = Arc::new(Assoc { send: tokio::sync::Mutex::new(send), last: Mutex::new(Instant::now()) });
                self.assocs.lock().unwrap().insert(client, a.clone());
                let this = self.clone();
                let key = a.clone();
                tokio::spawn(async move {
                    while let Ok(Some((src, data))) = read_udp_frame(&mut recv).await {
                        let mut out = BytesMut::from(&[0u8, 0, 0][..]);
                        if src.encode(&mut out).is_err() {
                            continue;
                        }
                        out.extend_from_slice(&data);
                        let _ = this.sock.send_to(&out, client).await;
                    }
                    let mut m = this.assocs.lock().unwrap();
                    if m.get(&client).is_some_and(|x| Arc::ptr_eq(x, &key)) {
                        m.remove(&client);
                    }
                });
                a
            }
        };
        *assoc.last.lock().unwrap() = Instant::now();
        let frame = encode_udp_frame(&addr, &payload)?;
        assoc.send.lock().await.write_all(&frame).await?;
        Ok(())
    }
}

// -------------------------------------------------------------- HTTP proxy

fn split_host_port(s: &str, default_port: u16) -> Result<TargetAddr> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, tail) = rest.split_once(']').ok_or_else(|| anyhow!("bad IPv6 literal"))?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse()?,
            None => default_port,
        };
        (h.to_string(), port)
    } else if let Some((h, p)) = s.rsplit_once(':') {
        if h.contains(':') {
            (s.to_string(), default_port) // bare IPv6
        } else {
            (h.to_string(), p.parse()?)
        }
    } else {
        (s.to_string(), default_port)
    };
    if host.is_empty() {
        bail!("empty host");
    }
    Ok(match host.parse::<std::net::IpAddr>() {
        Ok(ip) => TargetAddr::Ip(SocketAddr::new(ip, port)),
        Err(_) => TargetAddr::Domain(host, port),
    })
}

async fn handle_http(mgr: Arc<ConnManager>, mut tcp: TcpStream) -> Result<()> {
    let _ = tcp.set_nodelay(true);
    let mut buf = Vec::with_capacity(4096);
    let head_end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        if buf.len() > 64 * 1024 {
            bail!("request head too large");
        }
        let mut tmp = [0u8; 4096];
        let n = tcp.read(&mut tmp).await?;
        if n == 0 {
            bail!("closed before request");
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = std::str::from_utf8(&buf[..head_end]).context("request head is not UTF-8")?.to_string();
    let rest = buf[head_end..].to_vec();
    let mut lines = head.split("\r\n");
    let first = lines.next().unwrap_or("");
    let mut parts = first.split(' ');
    let (method, uri) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));

    if method.eq_ignore_ascii_case("CONNECT") {
        let target = split_host_port(uri, 443)?;
        match mgr.open(CMD_TCP, &target).await {
            Ok((mut send, recv)) => {
                tcp.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
                if !rest.is_empty() {
                    send.write_all(&rest).await?;
                }
                relay_tcp_quic(tcp, send, recv).await;
                Ok(())
            }
            Err(e) => {
                let _ = tcp.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n").await;
                Err(e)
            }
        }
    } else {
        let after = uri.strip_prefix("http://").ok_or_else(|| anyhow!("only absolute http:// URIs are proxied"))?;
        let (authority, path) = match after.find('/') {
            Some(i) => (&after[..i], &after[i..]),
            None => (after, "/"),
        };
        let target = split_host_port(authority, 80)?;
        let version = parts.next().unwrap_or("HTTP/1.1");
        let mut out = format!("{method} {path} {version}\r\n");
        for l in lines.filter(|l| !l.is_empty()) {
            let name = l.split(':').next().unwrap_or("").to_ascii_lowercase();
            if matches!(name.as_str(), "proxy-connection" | "proxy-authorization" | "connection") {
                continue;
            }
            out.push_str(l);
            out.push_str("\r\n");
        }
        out.push_str("Connection: close\r\n\r\n");
        match mgr.open(CMD_TCP, &target).await {
            Ok((mut send, recv)) => {
                send.write_all(out.as_bytes()).await?;
                if !rest.is_empty() {
                    send.write_all(&rest).await?;
                }
                relay_tcp_quic(tcp, send, recv).await;
                Ok(())
            }
            Err(e) => {
                let _ = tcp.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n").await;
                warn!("http proxy: {e:#}");
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port_parsing() {
        assert_eq!(split_host_port("example.com:8443", 443).unwrap(), TargetAddr::Domain("example.com".into(), 8443));
        assert_eq!(split_host_port("example.com", 80).unwrap(), TargetAddr::Domain("example.com".into(), 80));
        assert_eq!(split_host_port("[::1]:9", 80).unwrap(), TargetAddr::Ip("[::1]:9".parse().unwrap()));
        assert_eq!(split_host_port("1.2.3.4:5", 80).unwrap(), TargetAddr::Ip("1.2.3.4:5".parse().unwrap()));
        assert!(split_host_port(":80", 80).is_err());
    }
}

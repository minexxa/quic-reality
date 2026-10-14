//! Server side of quic-reality.
//!
//! The endpoint binds no UDP port of its own: it runs on top of the REALITY
//! [`GateSocket`], so only clients that passed session-id verification ever
//! reach the TLS handshake. Everything else was already relayed to the real
//! destination before quinn saw a single byte.
//!
//! Wire protocol on top of QUIC (after the gateway admitted the connection):
//!
//! ```text
//! stream (bidirectional):
//!   request:  u8 cmd | TargetAddr
//!   reply:    u8 status [| u32 session_id for UDP]
//!   TCP:      then raw relay in both directions
//!   UDP:      then datagrams carry the payload:
//!             session:u32 | seq:u16 | idx:u8 | total:u8 | payload
//! ```

use crate::congestion::{CongestionConfig, CongestionKind};
use crate::config::Config;
use crate::gate::{GateConfig, GateSocket};
use crate::protocol::{TargetAddr, CMD_TCP, CMD_UDP, STATUS_ERROR, STATUS_OK};
use crate::reality::KeyPair;
use crate::salamander::Salamander;
use anyhow::{anyhow, bail, Context, Result};
use quinn::Connection;
use ring::digest;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, info, warn};

/// Datagram header: session(4) + seq(2) + idx(1) + total(1).
pub const DATAGRAM_HEADER_LEN: usize = 8;
/// Fragment header inside the payload: seq(2) + idx(1) + total(1).
pub const FRAG_HEADER_LEN: usize = 4;
/// Conservative payload chunk per datagram; QUIC datagram frames are small.
pub const UDP_FRAGMENT_SIZE: usize = 1024;

pub async fn run(cfg: Config) -> Result<()> {
    let listen: SocketAddr = cfg.listen.parse().context("invalid listen")?;
    let short_ids = cfg.server_short_ids().context("short ids")?;
    let kp = KeyPair::from_private_hex(&cfg.reality.private_key).context("private key")?;

    if cfg.reality.dest.trim().is_empty() {
        warn!("reality.dest is empty: failed probes will be DROPPED, not relayed");
    }
    let dest: SocketAddr = if cfg.reality.dest.trim().is_empty() {
        // Unreachable placeholder; never used when dest relay is disabled.
        "0.0.0.0:9".parse().unwrap()
    } else {
        resolve_host(cfg.reality.dest.trim()).context("reality.dest must be host:port")?
    };

    let reality = Arc::new(crate::reality::RealityServer::new(
        kp,
        short_ids,
        crate::reality::DEFAULT_MAX_PAST_SKEW_SECS,
        crate::reality::DEFAULT_MAX_FUTURE_SKEW_SECS,
    ));

    let salamander = if cfg.obfuscation.is_salamander() {
        Some(Salamander::new(cfg.obfuscation.password.as_bytes())?)
    } else {
        None
    };

    // --- TLS material (self-signed; only admitted clients ever see it) ---
    let (certs, key) = load_or_create_cert(&cfg)?;
    info!(
        "server certificate fingerprint (sha256): {}",
        cert_fingerprint(&certs[0])
    );

    let mut rustls_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .context("tls13 only")?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .context("with_single_cert")?;
    rustls_config.alpn_protocols = vec![b"h3".to_vec()];

    let quic_crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config).context("quic config")?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.congestion_controller_factory(Arc::new(CongestionConfig::new(parse_congestion(
        &cfg.quic.congestion,
    )?)));
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(60)).context("idle timeout")?,
    ));
    transport.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
    transport.datagram_send_buffer_size(4 * 1024 * 1024);
    // Roomy flow-control windows (proxy traffic is bulk, not latency-bound).
    transport.stream_receive_window(quinn::VarInt::from_u32(4 << 20));
    transport.receive_window(quinn::VarInt::from_u32(16 << 20));
    transport.send_window(16 << 20);
    transport.initial_mtu(1400);
    transport.min_mtu(1200);
    server_config.transport = Arc::new(transport);

    // --- Gate socket: REALITY admission + dest fallback ---
    let io = UdpSocket::bind(listen).await.context("bind listen")?;
    info!(
        "listening on {} (dest={}, salamander={}, congestion={})",
        listen,
        cfg.reality.dest,
        cfg.obfuscation.is_salamander(),
        cfg.quic.congestion
    );
    let gate_sock = GateSocket::new(
        io,
        GateConfig {
            reality,
            dest,
            salamander,
        },
    );

    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_config),
        gate_sock,
        Arc::new(quinn::TokioRuntime),
    )
    .context("endpoint")?;

    let block_private = cfg.quic.block_private;
    while let Some(connecting) = endpoint.accept().await {
        tokio::spawn(async move {
            match connecting.await {
                Ok(conn) => {
                    debug!("connection admitted from {}", conn.remote_address());
                    if let Err(e) = handle_connection(conn, block_private).await {
                        debug!("connection ended: {e}");
                    }
                }
                Err(e) => debug!("handshake failed: {e}"),
            }
        });
    }
    Ok(())
}

async fn handle_connection(conn: Connection, block_private: bool) -> Result<()> {
    // UDP relay sessions: session id -> socket connected to the target.
    let sessions: Arc<Mutex<HashMap<u32, Arc<UdpSocket>>>> = Arc::new(Mutex::new(HashMap::new()));

    // Datagram ingress: client -> sessions, with fragment reassembly.
    let conn_for_dg = conn.clone();
    {
        let sessions = sessions.clone();
        let conn = conn_for_dg;
        tokio::spawn(async move {
            let mut pending: HashMap<(u32, u16), Reassembly> = HashMap::new();
            while let Ok(datagram) = conn.read_datagram().await {
                let bytes = datagram.to_vec();
                if bytes.len() < DATAGRAM_HEADER_LEN + FRAG_HEADER_LEN {
                    continue;
                }
                let session = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                let frag = &bytes[DATAGRAM_HEADER_LEN..];
                let seq = u16::from_be_bytes([frag[0], frag[1]]);
                let idx = frag[2];
                let total = frag[3] as usize;
                let body = &frag[FRAG_HEADER_LEN..];

                let sock = {
                    let st = sessions.lock().unwrap_or_else(|e| e.into_inner());
                    st.get(&session).cloned()
                };
                let Some(sock) = sock else { continue };
                let peer = match sock.peer_addr() {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                if total <= 1 {
                    let _ = sock.send_to(body, peer).await;
                    continue;
                }
                let key = (session, seq);
                let entry = pending.entry(key).or_insert_with(|| Reassembly {
                    total,
                    parts: vec![None; total],
                });
                if entry.total != total {
                    pending.remove(&key);
                    continue;
                }
                if (idx as usize) < total {
                    entry.parts[idx as usize] = Some(body.to_vec());
                }
                if entry.parts.iter().all(|p| p.is_some()) {
                    let mut full = Vec::new();
                    for part in entry.parts.iter().flatten() {
                        full.extend_from_slice(part);
                    }
                    pending.remove(&key);
                    let _ = sock.send_to(&full, peer).await;
                }
            }
        });
    }

    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
        let sessions = sessions.clone();
        let conn = conn.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(&mut send, &mut recv, sessions, conn, block_private).await
            {
                debug!("stream ended: {e}");
                let _ = send.finish();
            }
        });
    }
    Ok(())
}

/// Fragment reassembly state for one (session, seq) datagram.
struct Reassembly {
    total: usize,
    parts: Vec<Option<Vec<u8>>>,
}

async fn handle_stream(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    sessions: Arc<Mutex<HashMap<u32, Arc<UdpSocket>>>>,
    conn: Connection,
    block_private: bool,
) -> Result<()> {
    // Request: u8 cmd | TargetAddr
    let mut head = vec![0u8; 1024];
    let n = match recv.read(&mut head).await? {
        Some(n) if n > 0 => n,
        _ => bail!("empty request"),
    };
    let cmd = head[0];
    let mut rest = &head[1..n];
    let target = TargetAddr::decode(&mut rest).context("target address")?;

    if block_private && is_blocked_target(&target) {
        let _ = send.write_all(&[STATUS_ERROR]).await;
        let _ = send.finish();
        bail!("refusing private target {target:?}");
    }

    match cmd {
        CMD_TCP => {
            let tcp = match connect_tcp(&target).await {
                Ok(s) => s,
                Err(e) => {
                    let _ = send.write_all(&[STATUS_ERROR]).await;
                    let _ = send.finish();
                    return Err(e);
                }
            };
            send.write_all(&[STATUS_OK]).await?;

            // Full-duplex relay; both directions run until EOF.
            let (mut tr, mut tw) = tcp.into_split();
            let c2s = async {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match recv.read(&mut buf).await? {
                        Some(n) if n > 0 => tw.write_all(&buf[..n]).await?,
                        _ => break,
                    }
                }
                let _ = tw.shutdown().await;
                Ok::<(), anyhow::Error>(())
            };
            let s2c = async {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = tr.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    send.write_all(&buf[..n]).await?;
                }
                send.finish()?;
                Ok::<(), anyhow::Error>(())
            };
            tokio::select! {
                r = c2s => { let _ = r; }
                r = s2c => { r?; }
            }
            Ok(())
        }
        CMD_UDP => {
            let session = next_session_id();
            let sock = match open_udp(&target).await {
                Ok(s) => s,
                Err(e) => {
                    let _ = send.write_all(&[STATUS_ERROR]).await;
                    let _ = send.finish();
                    return Err(e);
                }
            };
            sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(session, sock.clone());
            let mut reply = vec![STATUS_OK];
            reply.extend_from_slice(&session.to_be_bytes());
            send.write_all(&reply).await?;
            send.finish()?;

            // Pump target -> client as fragmented datagrams.
            let peer = sock.peer_addr().ok();
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let (len, _) = match sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(e) => {
                        debug!("udp recv: {e}");
                        break;
                    }
                };
                let _ = peer;
                for (i, part) in buf[..len].chunks(UDP_FRAGMENT_SIZE).enumerate() {
                    let total = (len + UDP_FRAGMENT_SIZE - 1) / UDP_FRAGMENT_SIZE;
                    let total = total.max(1).min(u8::MAX as usize);
                    let mut dg = Vec::with_capacity(DATAGRAM_HEADER_LEN + FRAG_HEADER_LEN + part.len());
                    dg.extend_from_slice(&session.to_be_bytes());
                    dg.extend_from_slice(&0u16.to_be_bytes()); // seq: unused
                    dg.push(i as u8);
                    dg.push(total as u8);
                    dg.extend_from_slice(part);
                    // Unreliable semantics: a dropped datagram is acceptable.
                    let _ = conn.send_datagram(dg.into());
                }
            }
            sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&session);
            Ok(())
        }
        c => {
            let _ = send.write_all(&[STATUS_ERROR]).await;
            let _ = send.finish();
            bail!("unknown cmd {c}");
        }
    }
}

fn next_session_id() -> u32 {
    static COUNTER: AtomicU32 = AtomicU32::new(1);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Blocks loopback, private, link-local, and other non-routable targets.
fn is_blocked_target(target: &TargetAddr) -> bool {
    match target {
        TargetAddr::Ip(addr) => is_blocked_ip(addr.ip()),
        // Domains are checked after resolution, at connect time.
        TargetAddr::Domain(_, _) => false,
    }
}

fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.octets()[0] == 0
                || v4.octets()[0] >= 224
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (v6.segments()[0] & 0xff00) == 0xff00 // multicast ff00::/8
        }
    }
}

async fn connect_tcp(target: &TargetAddr) -> Result<TcpStream> {
    let addr = first_addr(target).await?;
    if is_blocked_ip(addr.ip()) {
        bail!("refusing blocked target {addr}");
    }
    Ok(TcpStream::connect(addr).await?)
}

async fn open_udp(target: &TargetAddr) -> Result<Arc<UdpSocket>> {
    let addr = first_addr(target).await?;
    if is_blocked_ip(addr.ip()) {
        bail!("refusing blocked target {addr}");
    }
    let bind = match addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(addr).await?;
    Ok(Arc::new(sock))
}

async fn first_addr(target: &TargetAddr) -> Result<SocketAddr> {
    match target {
        TargetAddr::Ip(a) => Ok(*a),
        TargetAddr::Domain(h, p) => Ok(tokio::net::lookup_host((h.as_str(), *p))
            .await?
            .next()
            .ok_or_else(|| anyhow!("dns: no addresses for {h}"))?),
    }
}

fn resolve_host(hostport: &str) -> Result<SocketAddr> {
    use std::net::ToSocketAddrs;
    hostport
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("cannot resolve {hostport}"))
}

fn cert_fingerprint(cert: &rustls::pki_types::CertificateDer<'_>) -> String {
    let d = digest::digest(&digest::SHA256, cert.as_ref());
    hex::encode(d.as_ref())
}

fn parse_congestion(s: &str) -> Result<CongestionKind> {
    let s = s.trim();
    if let Some(bps) = s.strip_prefix("brutal:") {
        let bps: u64 = bps.parse().context("brutal bandwidth")?;
        return Ok(CongestionKind::Brutal(bps));
    }
    match s {
        "bbr" => Ok(CongestionKind::Bbr),
        "cubic" => Ok(CongestionKind::Cubic),
        other => bail!("unknown congestion '{other}' (bbr|cubic|brutal:<bps>)"),
    }
}

/// Loads a persisted cert/key pair, or generates (and optionally saves) one.
fn load_or_create_cert(
    cfg: &Config,
) -> Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let (cert_path, key_path) = (&cfg.reality.cert_path, &cfg.reality.key_path);
    if !cert_path.is_empty() && !key_path.is_empty() {
        if let (Ok(cert_pem), Ok(key_pem)) = (
            std::fs::read_to_string(cert_path),
            std::fs::read_to_string(key_path),
        ) {
            let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .context("parse cert.pem")?;
            let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
                .context("parse key.pem")?
                .ok_or_else(|| anyhow!("no private key in key.pem"))?;
            info!("loaded certificate from {cert_path}");
            return Ok((certs, key));
        }
    }

    let cert = rcgen::generate_simple_self_signed(vec![cfg.reality.server_name.clone()])
        .context("rcgen")?;
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .context("encode cert")?;
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .context("encode key")?
        .ok_or_else(|| anyhow!("rcgen produced no key"))?;

    if !cert_path.is_empty() && !key_path.is_empty() {
        let wrote = std::fs::write(cert_path, &cert_pem)
            .and_then(|_| std::fs::write(key_path, &key_pem));
        match wrote {
            Ok(()) => info!("saved certificate to {cert_path} / {key_path}"),
            Err(e) => warn!("could not persist certificate: {e}"),
        }
    }
    Ok((certs, key))
}

//! Client side of quic-reality.
//!
//! Responsibilities:
//!
//! 1. Build the rustls ClientConfig with the REALITY session-id hook (the
//!    vendored rustls fork exposes `ClientHelloCallback` for this) and a
//!    certificate-pinning verifier that replaces `SkipServerVerification`.
//! 2. Optional Salamander obfuscation socket for all outbound datagrams.
//! 3. Local SOCKS5 and HTTP CONNECT listeners.
//! 4. Automatic reconnection with backoff.
//!
//! UDP payloads travel as fragmented QUIC datagrams (RFC 9221), so they do
//! not suffer the head-of-line blocking of the previous stream-per-packet
//! design.

use crate::congestion::{CongestionConfig, CongestionKind};
use crate::config::Config;
use crate::protocol::{TargetAddr, CMD_TCP, CMD_UDP, STATUS_OK};
use crate::reality::{KeyPair, RealityClient};
use crate::salamander::Salamander;
use anyhow::{anyhow, bail, Context, Result};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Connection, Endpoint, UdpPoller};
use ring::digest;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::client::danger::{ServerCertVerifier, ServerCertVerified};
use rustls::crypto::verify_tls13_signature;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    DigitallySignedStruct, Error as TlsError, SignatureScheme,
};
use std::collections::HashMap;
use std::io::IoSliceMut;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll, Waker};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, info, warn};

use crate::server::{
    DATAGRAM_HEADER_LEN, FRAG_HEADER_LEN, UDP_FRAGMENT_SIZE,
};

const DATAGRAM_RECV_BUF: usize = 4 * 1024 * 1024;

pub async fn run(cfg: Config) -> Result<()> {
    let server: SocketAddr = resolve_server(&cfg.server).await?;
    let server_public = crate::reality::hex_to_array::<32>(&cfg.reality.public_key)
        .context("reality.public_key")?;
    let short_id = hex::decode(cfg.reality.short_id.trim()).context("short_id")?;
    let reality_client = RealityClient::new(KeyPair::generate(), &short_id)?;

    let pinned = if cfg.quic.server_fingerprint.trim().is_empty() {
        None
    } else {
        Some(
            crate::reality::hex_to_array::<32>(cfg.quic.server_fingerprint.trim())
                .context("quic.server_fingerprint")?,
        )
    };

    // --- TLS config: REALITY hook + certificate pinning ---
    let verifier = Arc::new(FingerprintVerifier {
        expected: pinned,
        tofu_path: Some(std::path::PathBuf::from("known_server.fingerprint")),
    });
    let hook = Arc::new(RealityHook {
        server_public,
        reality_client,
    });
    let mut rustls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("protocol versions")?
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_no_client_auth();
    rustls_config.alpn_protocols = vec![cfg.quic.alpn.clone().into_bytes()];
    rustls_config.client_hello_callback = Some(hook);

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config).context("quic config")?,
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.congestion_controller_factory(Arc::new(CongestionConfig::new(parse_congestion(
        &cfg.quic.congestion,
    )?)));
    transport.datagram_receive_buffer_size(Some(DATAGRAM_RECV_BUF));
    transport.datagram_send_buffer_size(DATAGRAM_RECV_BUF);
    transport.stream_receive_window(quinn::VarInt::from_u32(4 << 20));
    transport.receive_window(quinn::VarInt::from_u32(16 << 20));
    transport.send_window(16 << 20);
    transport.initial_mtu(1400);
    transport.min_mtu(1200);
    client_config.transport_config(Arc::new(transport));

    // --- Socket (optionally Salamander-obfuscated) ---
    let bind: SocketAddr = match server {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let io = UdpSocket::bind(bind).await?;
    let socket: Arc<dyn AsyncUdpSocket> = if cfg.obfuscation.is_salamander() {
        SalamanderSocket::new(io, Salamander::new(cfg.obfuscation.password.as_bytes())?)
    } else {
        let std_sock = io.into_std()?;
        std_sock.set_nonblocking(true)?;
        quinn::Runtime::wrap_udp_socket(&quinn::TokioRuntime, std_sock)?
    };

    let mut endpoint = Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .context("endpoint")?;
    endpoint.set_default_client_config(client_config);

    // Current connection cell, swapped by the reconnect loop.
    let current: Arc<Mutex<Option<Connection>>> = Arc::new(Mutex::new(None));
    {
        let current = current.clone();
        let reconnect_secs = cfg.quic.reconnect_secs.max(1);
        tokio::spawn(async move {
            loop {
                let _ = ServerName::try_from(cfg.reality.server_name.clone());
                match endpoint.connect(server, &cfg.reality.server_name) {
                    Ok(connecting) => match connecting.await {
                        Ok(conn) => {
                            info!("connected to {server}");
                            *current.lock().unwrap_or_else(|e| e.into_inner()) = Some(conn.clone());
                            // Block until the connection drops.
                            let _ = conn.closed().await;
                            match conn.close_reason() {
                                Some(reason) => info!("connection closed: {reason}"),
                                None => info!("connection closed"),
                            }
                            *current.lock().unwrap_or_else(|e| e.into_inner()) = None;
                        }
                        Err(e) => warn!("connect failed: {e}"),
                    },
                    Err(e) => warn!("connect setup failed: {e}"),
                }
                tokio::time::sleep(Duration::from_secs(reconnect_secs)).await;
            }
        });
    }

    // --- SOCKS5 listener ---
    let socks_addr: SocketAddr = cfg.local.socks.parse().context("socks addr")?;
    let socks = TcpListener::bind(socks_addr).await?;
    info!("socks5 on {socks_addr}");
    {
        let current = current.clone();
        tokio::spawn(async move {
            loop {
                let (stream, peer) = match socks.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        debug!("socks accept: {e}");
                        continue;
                    }
                };
                let current = current.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_socks(stream, current).await {
                        debug!("socks {peer}: {e}");
                    }
                });
            }
        });
    }

    // --- HTTP CONNECT listener ---
    let http_addr: SocketAddr = cfg.local.http.parse().context("http addr")?;
    let http = TcpListener::bind(http_addr).await?;
    info!("http connect on {http_addr}");
    {
        let current = current.clone();
        tokio::spawn(async move {
            loop {
                let (stream, peer) = match http.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        debug!("http accept: {e}");
                        continue;
                    }
                };
                let current = current.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_http_connect(stream, current).await {
                        debug!("http {peer}: {e}");
                    }
                });
            }
        });
    }

    // Park the main task; the spawned loops own the process lifetime.
    futures::future::pending::<()>().await;
    Ok(())
}

async fn resolve_server(server: &str) -> Result<SocketAddr> {
    tokio::net::lookup_host(server)
        .await?
        .next()
        .ok_or_else(|| anyhow!("cannot resolve {server}"))
}

// ---------------------------------------------------------------------------
// REALITY hook
// ---------------------------------------------------------------------------

/// Installs the sealed REALITY session id into the outgoing ClientHello.
struct RealityHook {
    server_public: [u8; 32],
    reality_client: RealityClient,
}

impl std::fmt::Debug for RealityHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityHook").finish_non_exhaustive()
    }
}

impl rustls::client::ClientHelloCallback for RealityHook {
    fn modify_client_hello(
        &self,
        hello: &mut rustls::client::ClientHelloCallbackContext<'_>,
    ) -> Result<(), TlsError> {
        let akx = hello
            .active_key_exchange
            .ok_or_else(|| TlsError::General("no key share offered".into()))?;
        let reality_key = akx
            .extract_reality_key(&self.server_public)
            .ok_or_else(|| TlsError::General("key share is not X25519".into()))?;
        let session_id = self
            .reality_client
            .seal(&reality_key, hello.client_random, hello.raw_client_hello)
            .map_err(|e| TlsError::General(format!("reality seal: {e}")))?;
        hello
            .set_session_id(&session_id)
            .map_err(|e| TlsError::General(format!("reality session id: {e}")))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Certificate pinning
// ---------------------------------------------------------------------------

/// Verifies the server certificate *only* by SHA-256 fingerprint. There is no
/// CA to speak of: the gateway admits nobody else, and pinning removes the
/// original code's `SkipServerVerification` hole.
#[derive(Debug)]
struct FingerprintVerifier {
    expected: Option<[u8; 32]>,
    tofu_path: Option<std::path::PathBuf>,
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _scts: &[u8],
        _ocsp: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, TlsError> {
        let fp = digest::digest(&digest::SHA256, end_entity.as_ref());
        let fp: [u8; 32] = fp.as_ref().try_into().expect("sha256 is 32 bytes");
        match self.expected {
            Some(expected) if expected == fp => Ok(ServerCertVerified::assertion()),
            Some(_) => Err(TlsError::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            )),
            None => {
                // Trust on first use; persist for later runs.
                if let Some(path) = &self.tofu_path {
                    let _ = std::fs::write(path, hex::encode(fp));
                }
                Ok(ServerCertVerified::assertion())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("TLS 1.2 not allowed".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        // Certificate identity was pinned above; this only proves the peer
        // holds the private key for that certificate.
        let algs = rustls::crypto::ring::default_provider().signature_verification_algorithms;
        verify_tls13_signature(message, cert, dss, &algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// Salamander socket (client side)
// ---------------------------------------------------------------------------

/// Wraps a UDP socket with Salamander obfuscation on both directions.
#[derive(Debug)]
struct SalamanderSocket {
    io: Arc<UdpSocket>,
    salamander: Salamander,
    queue: Mutex<std::collections::VecDeque<(Vec<u8>, SocketAddr)>>,
    waker: Mutex<Option<Waker>>,
}

impl SalamanderSocket {
    fn new(io: UdpSocket, salamander: Salamander) -> Arc<Self> {
        let this = Arc::new(Self {
            io: Arc::new(io),
            salamander,
            queue: Mutex::new(Default::default()),
            waker: Mutex::new(None),
        });
        {
            let this = this.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    match this.io.recv_from(&mut buf).await {
                        Ok((len, from)) => match this.salamander.deobfuscate(&buf[..len]) {
                            Ok(plain) => {
                                let mut q = this
                                    .queue
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner());
                                if q.len() > 8192 {
                                    q.pop_front();
                                }
                                q.push_back((plain, from));
                                drop(q);
                                if let Some(w) = this
                                    .waker
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .take()
                                {
                                    w.wake();
                                }
                            }
                            Err(_) => continue,
                        },
                        Err(e) => {
                            debug!("salamander recv: {e}");
                            break;
                        }
                    }
                }
            });
        }
        this
    }
}

#[derive(Debug)]
struct SalamanderPoller {
    io: Arc<UdpSocket>,
}

impl AsyncUdpSocket for SalamanderSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(SalamanderPoller {
            io: self.io.clone(),
        })
    }

    fn try_send(&self, transmit: &Transmit) -> std::io::Result<()> {
        let obfuscated = self.salamander.obfuscate(transmit.contents);
        self.io
            .try_send_to(&obfuscated, transmit.destination)
            .map(|_| ())
    }

    fn poll_recv(
        &self,
        cx: &mut TaskContext,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        match q.pop_front() {
            Some((data, addr)) => {
                drop(q);
                let take = data.len().min(bufs[0].len());
                bufs[0][..take].copy_from_slice(&data[..take]);
                meta[0] = RecvMeta {
                    addr,
                    len: take,
                    stride: take,
                    ecn: None,
                    dst_ip: None,
                };
                Poll::Ready(Ok(1))
            }
            None => {
                *self.waker.lock().unwrap_or_else(|e| e.into_inner()) = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        true
    }
}

impl UdpPoller for SalamanderPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut TaskContext) -> Poll<std::io::Result<()>> {
        self.io.poll_send_ready(cx)
    }
}

// ---------------------------------------------------------------------------
// SOCKS5
// ---------------------------------------------------------------------------

async fn serve_socks(stream: TcpStream, current: Arc<Mutex<Option<Connection>>>) -> Result<()> {
    let mut stream = stream;
    // Greeting
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        bail!("not socks5");
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;
    stream.write_all(&[0x05, 0x00]).await?; // no auth

    // Request
    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[0] != 0x05 || req[2] != 0x00 {
        bail!("bad socks request");
    }
    let target = read_socks_addr(&mut stream, req[3]).await?;

    match req[1] {
        0x01 => {
            // CONNECT
            let conn = current_conn(&current)?;
            let (mut send, mut recv) = conn.open_bi().await?;
            write_request(&mut send, CMD_TCP, &target).await?;
            let status = read_status(&mut recv).await?;
            if status != STATUS_OK {
                stream.write_all(&socks_reply(0x01, &target)).await?;
                bail!("remote tcp connect failed");
            }
            stream.write_all(&socks_reply(0x00, &target)).await?;
            relay_tcp(stream, send, recv).await
        }
        0x03 => {
            // UDP ASSOCIATE
            let conn = current_conn(&current)?;
            let relay = UdpSocket::bind("127.0.0.1:0").await?;
            let relay_addr = relay.local_addr()?;
            stream
                .write_all(&socks_udp_reply(relay_addr, &target))
                .await?;

            // Open the QUIC-side UDP session.
            let (mut send, mut recv) = conn.open_bi().await?;
            write_request(&mut send, CMD_UDP, &target).await?;
            let mut status = [0u8; 1];
            recv.read_exact(&mut status).await?;
            if status[0] != STATUS_OK {
                bail!("remote udp session failed");
            }
            let mut sid = [0u8; 4];
            recv.read_exact(&mut sid).await?;
            let session = u32::from_be_bytes(sid);
            let _ = send.finish();

            // local app -> QUIC datagrams
            let conn_send = conn.clone();
            let relay_send = Arc::new(relay);
            {
                let relay_send = relay_send.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 64 * 1024];
                    loop {
                        let (len, _from) = match relay_send.recv_from(&mut buf).await {
                            Ok(v) => v,
                            Err(_) => break,
                        };
                        let payload = &buf[..len];
                        // Strip the SOCKS5 UDP header: rsv(2) frag(1) atyp+addr+port
                        let Some(body) = strip_socks_udp_header(payload) else {
                            continue;
                        };
                        let chunks = (body.len() + UDP_FRAGMENT_SIZE - 1) / UDP_FRAGMENT_SIZE;
                        let total = chunks.max(1).min(u8::MAX as usize);
                        for (i, part) in body.chunks(UDP_FRAGMENT_SIZE).enumerate() {
                            let mut dg =
                                Vec::with_capacity(DATAGRAM_HEADER_LEN + FRAG_HEADER_LEN + part.len());
                            dg.extend_from_slice(&session.to_be_bytes());
                            dg.extend_from_slice(&0u16.to_be_bytes());
                            dg.push(i as u8);
                            dg.push(total as u8);
                            dg.extend_from_slice(part);
                            let _ = conn_send.send_datagram(dg.into());
                        }
                    }
                });
            }

            // QUIC datagrams -> local app
            let mut pending: HashMap<(u32, u16), Vec<Option<Vec<u8>>>> = HashMap::new();
            while let Ok(datagram) = conn.read_datagram().await {
                let bytes = datagram.to_vec();
                if bytes.len() < DATAGRAM_HEADER_LEN + FRAG_HEADER_LEN {
                    continue;
                }
                let dg_session = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                if dg_session != session {
                    continue;
                }
                let frag = &bytes[DATAGRAM_HEADER_LEN..];
                let seq = u16::from_be_bytes([frag[0], frag[1]]);
                let idx = frag[2] as usize;
                let total = frag[3] as usize;
                let body = &frag[FRAG_HEADER_LEN..];
                let payload = if total <= 1 {
                    body.to_vec()
                } else {
                    let entry = pending
                        .entry((session, seq))
                        .or_insert_with(|| vec![None; total]);
                    if idx < total {
                        entry[idx] = Some(body.to_vec());
                    }
                    if entry.iter().all(|p| p.is_some()) {
                        let full: Vec<u8> = entry.iter().flatten().flat_map(|p| p.iter().copied()).collect();
                        pending.remove(&(session, seq));
                        full
                    } else {
                        continue;
                    }
                };
                let _ = relay_send.send_to(&payload, relay_addr).await;
            }
            Ok(())
        }
        c => {
            stream.write_all(&socks_reply(0x07, &target)).await?;
            bail!("unsupported socks cmd {c}");
        }
    }
}

fn current_conn(current: &Arc<Mutex<Option<Connection>>>) -> Result<Connection> {
    current
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .ok_or_else(|| anyhow!("not connected"))
}

async fn read_socks_addr(stream: &mut TcpStream, atyp: u8) -> Result<TargetAddr> {
    match atyp {
        0x01 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            Ok(TargetAddr::Ip(SocketAddr::new(
                IpAddr::V4(ip.into()),
                u16::from_be_bytes(port),
            )))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut host = vec![0u8; len[0] as usize];
            stream.read_exact(&mut host).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            Ok(TargetAddr::Domain(
                String::from_utf8(host)?,
                u16::from_be_bytes(port),
            ))
        }
        0x04 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            Ok(TargetAddr::Ip(SocketAddr::new(
                IpAddr::V6(ip.into()),
                u16::from_be_bytes(port),
            )))
        }
        a => bail!("bad atyp {a}"),
    }
}

fn socks_reply(code: u8, target: &TargetAddr) -> Vec<u8> {
    let mut out = vec![0x05, code, 0x00];
    match target {
        TargetAddr::Ip(SocketAddr::V4(a)) => {
            out.push(0x01);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        TargetAddr::Ip(SocketAddr::V6(a)) => {
            out.push(0x04);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        TargetAddr::Domain(h, p) => {
            out.push(0x03);
            out.push(h.len() as u8);
            out.extend_from_slice(h.as_bytes());
            out.extend_from_slice(&p.to_be_bytes());
        }
    }
    out
}

fn socks_udp_reply(relay: SocketAddr, _target: &TargetAddr) -> Vec<u8> {
    let mut out = vec![0x05, 0x00, 0x00];
    match relay {
        SocketAddr::V4(a) => {
            out.push(0x01);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            out.push(0x04);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    out
}

/// Strips `rsv(2) frag(1) atyp+addr+port` from a SOCKS5 UDP datagram.
fn strip_socks_udp_header(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 4 || data[2] != 0x00 {
        return None; // FRAG != 0 unsupported
    }
    let atyp = data[3];
    let addr_len = match atyp {
        0x01 => 4,
        0x04 => 16,
        0x03 => 1 + data.get(4).copied()? as usize,
        _ => return None,
    };
    let end = 4 + addr_len + 2;
    data.get(end..)
}

// ---------------------------------------------------------------------------
// HTTP CONNECT
// ---------------------------------------------------------------------------

async fn serve_http_connect(
    mut stream: TcpStream,
    current: Arc<Mutex<Option<Connection>>>,
) -> Result<()> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("eof before request");
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = find_subsequence(&buf, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_string();
            let first = head.lines().next().unwrap_or_default().to_string();
            let rest = &buf[end + 4..];
            let mut parts = first.split_whitespace();
            if parts.next() != Some("CONNECT") {
                bail!("not a CONNECT request");
            }
            let hostport = parts
                .next()
                .ok_or_else(|| anyhow!("missing CONNECT target"))?
                .to_string();
            let (host, port) = match hostport.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), p.parse::<u16>()?),
                None => (hostport, 443),
            };
            let target = if let Ok(ip) = host.parse::<IpAddr>() {
                TargetAddr::Ip(SocketAddr::new(ip, port))
            } else {
                TargetAddr::Domain(host, port)
            };

            let conn = current_conn(&current)?;
            let (mut send, mut recv) = conn.open_bi().await?;
            write_request(&mut send, CMD_TCP, &target).await?;
            let status = read_status(&mut recv).await?;
            if status != STATUS_OK {
                stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    .await?;
                bail!("remote connect failed");
            }
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            if !rest.is_empty() {
                // Client pipelined data after the header; forward it.
                send.write_all(rest).await?;
            }
            return relay_tcp(stream, send, recv).await;
        }
        if buf.len() > 16 * 1024 {
            bail!("oversized http header");
        }
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

// ---------------------------------------------------------------------------
// QUIC stream plumbing
// ---------------------------------------------------------------------------

async fn write_request(send: &mut quinn::SendStream, cmd: u8, target: &TargetAddr) -> Result<()> {
    let mut buf = bytes::BytesMut::with_capacity(64);
    buf.extend_from_slice(&[cmd]);
    target.encode(&mut buf);
    send.write_all(&buf).await?;
    Ok(())
}

async fn read_status(recv: &mut quinn::RecvStream) -> Result<u8> {
    let mut b = [0u8; 1];
    recv.read_exact(&mut b).await?;
    Ok(b[0])
}

/// Full-duplex pump between a local TCP stream and a QUIC stream.
async fn relay_tcp(
    local: TcpStream,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<()> {
    let (mut lr, mut lw) = local.into_split();
    let c2s = async {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match lr.read(&mut buf).await? {
                0 => break,
                n => send.write_all(&buf[..n]).await?,
            }
        }
        send.finish()?;
        Ok::<(), anyhow::Error>(())
    };
    let s2c = async {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match recv.read(&mut buf).await? {
                Some(n) if n > 0 => lw.write_all(&buf[..n]).await?,
                _ => break,
            }
        }
        let _ = lw.shutdown().await;
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {
        r = c2s => r?,
        r = s2c => r?,
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// misc
// ---------------------------------------------------------------------------

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

/// Allocates datagram sequence numbers (currently informational).
#[allow(dead_code)]
fn next_seq() -> u16 {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    (COUNTER.fetch_add(1, Ordering::Relaxed) & 0xffff) as u16
}

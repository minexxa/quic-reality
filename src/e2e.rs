//! End-to-end tests with real quinn endpoints on loopback.

use crate::auth::{self, KeyPair};
use crate::client::ConnManager;
use crate::config::Config;
use crate::protocol::*;
use crate::server;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

const SNI: &str = "www.example.com";

/// A stock QUIC server with its own certificate, playing "the real website".
///
/// It speaks h3 (like every real HTTP/3 site) so the dest probe can complete a
/// handshake against it, which puts every authenticated e2e connection through
/// the mimicry path: suite, certificate size and session tickets shaped after
/// whatever this decoy negotiates.
struct Decoy {
    addr: SocketAddr,
    cert_der: Vec<u8>,
    _ep: quinn::Endpoint,
}

fn decoy() -> Decoy {
    let ck = rcgen::generate_simple_self_signed(vec![SNI.to_string()]).unwrap();
    let cert_der = ck.cert.der().to_vec();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der());
    let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![ck.cert.der().clone()], key.into())
    .unwrap();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let cfg =
        quinn::ServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(crypto).unwrap()));
    let ep = quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = ep.local_addr().unwrap();
    let ep2 = ep.clone();
    tokio::spawn(async move {
        let mut keep = Vec::new();
        while let Some(inc) = ep2.accept().await {
            if let Ok(c) = inc.await {
                keep.push(c);
            }
        }
    });
    Decoy { addr, cert_der, _ep: ep }
}

/// A ticketer that emits tickets of *exact* NewSessionTicket message lengths.
///
/// rustls frames the ticket it gets from the ticketer into a message of
/// `ticket + 49` bytes (see `ticket::NST_OVERHEAD`), so padding the blob to
/// `target - 49` makes the dest's messages land on the chosen lengths.
#[derive(Debug)]
struct ExactTicketer {
    targets: std::sync::Mutex<std::collections::VecDeque<usize>>,
}

impl ExactTicketer {
    fn new(targets: &[usize]) -> Self {
        Self {
            targets: std::sync::Mutex::new(targets.iter().copied().collect()),
        }
    }
}

impl rustls::server::ProducesTickets for ExactTicketer {
    fn enabled(&self) -> bool {
        true
    }
    fn lifetime(&self) -> u32 {
        7200
    }
    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        let target = self
            .targets
            .lock()
            .unwrap()
            .pop_front()?;
        let mut blob = plain.to_vec();
        blob.resize(target.saturating_sub(crate::ticket::NST_OVERHEAD), 0x5a);
        Some(blob)
    }
    fn decrypt(&self, _ciphertext: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

/// A fake dest with a deliberately non-default shape: AES-256-GCM, a three
/// certificate chain around 4 KiB, and two NewSessionTickets of exact, odd
/// lengths.  Whatever it negotiates must be replayed by authenticated
/// connections (see `authenticated_handshake_replays_a_non_default_dest_shape`).
struct ShapedDecoy {
    addr: SocketAddr,
    /// Length of the Certificate message the dest sends, framing included
    /// (`4 + 1 + 3 + Σ(3 + der + 2)`).
    cert_msg_len: usize,
    /// Length of each NewSessionTicket message the dest sends, in order.
    nst_lens: Vec<usize>,
    _ep: quinn::Endpoint,
}

fn shaped_decoy() -> ShapedDecoy {
    // The leaf the "site" presents, plus a padded intermediate and a root, so
    // the Certificate message carries a chain far bigger than our single
    // temporary certificate would be on its own.
    let leaf = rcgen::generate_simple_self_signed(vec![SNI.to_string()]).unwrap();
    let mut mid_params = rcgen::CertificateParams::new(vec!["mid.example.com".to_string()]).unwrap();
    mid_params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(&[2, 999, 2], vec![0x5a; 3600]));
    let mid = mid_params.self_signed(&rcgen::KeyPair::generate().unwrap()).unwrap();
    let root = rcgen::generate_simple_self_signed(vec!["root.example.com".to_string()]).unwrap();
    let chain = vec![leaf.cert.der().clone(), mid.der().clone(), root.cert.der().clone()];
    let cert_msg_len = 4 + 1 + 3
        + chain
            .iter()
            .map(|c| 3 + c.as_ref().len() + 2)
            .sum::<usize>();
    let nst_lens = vec![300, 500];

    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(leaf.key_pair.serialize_der());
    let mut provider = rustls::crypto::ring::default_provider();
    // Pin AES-256-GCM the same way our server pins the dest's suite: sort it
    // first (0x1301 must stay in the list for quinn's Initial keys) and let
    // the server ignore the client's preference order.
    provider
        .cipher_suites
        .sort_by_key(|s| u16::from(s.suite()) != 0x1302);
    let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key.into())
        .unwrap();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    crypto.ignore_client_order = true;
    crypto.max_early_data_size = 0;
    crypto.send_tls13_tickets = nst_lens.len();
    crypto.ticketer = Arc::new(ExactTicketer::new(&nst_lens));
    let cfg = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto).unwrap(),
    ));
    let ep = quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = ep.local_addr().unwrap();
    let ep2 = ep.clone();
    tokio::spawn(async move {
        let mut keep = Vec::new();
        while let Some(inc) = ep2.accept().await {
            if let Ok(c) = inc.await {
                keep.push(c);
            }
        }
    });
    ShapedDecoy {
        addr,
        cert_msg_len,
        nst_lens,
        _ep: ep,
    }
}

/// A plain QUIC client that knows nothing about REALITY (a "prober").
///
/// Like every real QUIC client it offers `h3` - RFC 9001 §8.1 makes ALPN
/// mandatory, so a prober without it could not talk to a real QUIC site either.
async fn probe(server: SocketAddr, trust: &[u8]) -> anyhow::Result<()> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(trust.to_vec()))?;
    let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let cc = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())?;
    ep.set_default_client_config(cc);
    let conn = tokio::time::timeout(Duration::from_secs(5), ep.connect(server, SNI)?).await??;
    conn.close(0u32.into(), b"bye");
    Ok(())
}

struct Env {
    srv: server::Running,
    decoy: Decoy,
    pubkey: String,
}

fn server_config(
    dest: SocketAddr,
    priv_hex: &str,
    allow_private: bool,
    salamander: bool,
    mimic_dest: bool,
) -> Config {
    let obf = if salamander { "[obfuscation]\ntype='salamander'\npassword='pw-123'\n" } else { "" };
    let s = format!(
        "mode='server'\nlisten='127.0.0.1:0'\n[reality]\nprivate_key='{priv_hex}'\nshort_id='0123456789abcdef'\nserver_name='{SNI}'\ndest='{dest}'\nmimic_dest={mimic_dest}\n[security]\nallow_private_targets={allow_private}\n{obf}"
    );
    toml::from_str(&s).unwrap()
}

fn client_config(server: SocketAddr, pubkey: &str, short_id: &str, salamander: bool) -> Config {
    let obf = if salamander { "[obfuscation]\ntype='salamander'\npassword='pw-123'\n" } else { "" };
    let s = format!(
        "mode='client'\nserver='{server}'\n[reality]\npublic_key='{pubkey}'\nshort_id='{short_id}'\nserver_name='{SNI}'\n{obf}"
    );
    toml::from_str(&s).unwrap()
}

async fn env(allow_private: bool, salamander: bool) -> Env {
    let decoy = decoy();
    let kp = KeyPair::generate();
    let srv = server::start(&server_config(decoy.addr, &kp.private_hex(), allow_private, salamander, true))
        .await
        .unwrap();
    Env { srv, decoy, pubkey: kp.public_hex() }
}

async fn tcp_echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

async fn echo_roundtrip(mgr: &ConnManager, echo: SocketAddr, payload: &[u8]) {
    let (mut send, mut recv) = mgr.open(CMD_TCP, &TargetAddr::Ip(echo)).await.unwrap();
    send.write_all(payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), recv.read_exact(&mut got)).await.unwrap().unwrap();
    assert_eq!(got, payload);
}

#[tokio::test]
async fn authenticated_client_can_proxy_tcp() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "quic_reality=debug",
        ))
        .with_writer(std::io::stderr)
        .try_init();
    let e = env(true, false).await;
    let echo = tcp_echo().await;
    let mgr = ConnManager::new(&client_config(e.srv.local_addr, &e.pubkey, "0123456789abcdef", false)).await.unwrap();
    echo_roundtrip(&mgr, echo, b"hello through quic-reality").await;
    // large transfer, both directions
    let big: Vec<u8> = (0..2_000_000u32).map(|i| (i % 251) as u8).collect();
    echo_roundtrip(&mgr, echo, &big).await;
}

/// The hysteria-style brutal controller must proxy traffic like any other:
/// the whole pipeline (auth, streams, framing) runs over a connection whose
/// congestion window and pacing come from a fixed bandwidth instead of BBR.
#[tokio::test]
async fn brutal_congestion_control_proxies_traffic() {
    let decoy = decoy();
    let kp = KeyPair::generate();
    let server_cfg: Config = toml::from_str(&format!(
        "mode='server'\nlisten='127.0.0.1:0'\n[reality]\nprivate_key='{}'\nshort_id='0123456789abcdef'\nserver_name='{SNI}'\ndest='{}'\n[security]\nallow_private_targets=true\n[quic]\ncongestion='brutal'\nbrutal_bandwidth='1 Gbps'\n",
        kp.private_hex(),
        decoy.addr
    ))
    .unwrap();
    server_cfg.validate().unwrap();
    let srv = server::start(&server_cfg).await.unwrap();
    let echo = tcp_echo().await;
    let client_cfg: Config = toml::from_str(&format!(
        "mode='client'\nserver='{}'\n[reality]\npublic_key='{}'\nshort_id='0123456789abcdef'\nserver_name='{SNI}'\n[quic]\ncongestion='brutal'\nbrutal_bandwidth='1 Gbps'\n",
        srv.local_addr,
        kp.public_hex()
    ))
    .unwrap();
    client_cfg.validate().unwrap();
    let mgr = ConnManager::new(&client_cfg).await.unwrap();
    echo_roundtrip(&mgr, echo, b"hello over brutal").await;
    let big: Vec<u8> = (0..2_000_000u32).map(|i| (i % 251) as u8).collect();
    echo_roundtrip(&mgr, echo, &big).await;
}

#[tokio::test]
async fn prober_receives_the_decoys_real_certificate() {
    let e = env(true, false).await;
    // The prober only trusts the DECOY's certificate; the handshake can only
    // succeed if the answers really come from the decoy through our relay.
    probe(e.srv.local_addr, &e.decoy.cert_der).await.expect("prober must complete a handshake with the decoy");
    assert!(e.srv.auth.active_relays() >= 1);
}

#[tokio::test]
async fn wrong_short_id_is_treated_as_a_prober() {
    let e = env(true, false).await;
    let mgr = ConnManager::new(&client_config(e.srv.local_addr, &e.pubkey, "ffffffffffffffff", false)).await.unwrap();
    let r = mgr.open(CMD_TCP, &TargetAddr::Ip("127.0.0.1:9".parse().unwrap())).await;
    let err = format!("{:#}", r.expect_err("must fail")).to_lowercase();
    // It reached the decoy, whose certificate is not a REALITY certificate:
    // the client rejects the flight (non-Ed25519 CertificateVerify, or the
    // HMAC check if the scheme had matched).
    assert!(
        err.contains("reality") || err.contains("certificate") || err.contains("handshake"),
        "{err}"
    );
}

#[tokio::test]
async fn wrong_server_key_cannot_authenticate() {
    let e = env(true, false).await;
    let other = KeyPair::generate().public_hex();
    let mgr = ConnManager::new(&client_config(e.srv.local_addr, &other, "0123456789abcdef", false)).await.unwrap();
    assert!(mgr.open(CMD_TCP, &TargetAddr::Ip("127.0.0.1:9".parse().unwrap())).await.is_err());
}

#[tokio::test]
async fn private_targets_are_denied_by_default() {
    let e = env(false, false).await;
    let echo = tcp_echo().await;
    let mgr = ConnManager::new(&client_config(e.srv.local_addr, &e.pubkey, "0123456789abcdef", false)).await.unwrap();
    let err = mgr.open(CMD_TCP, &TargetAddr::Ip(echo)).await.expect_err("must be denied");
    assert!(format!("{err:#}").contains("not allowed"), "{err:#}");
}

#[tokio::test]
async fn client_reconnects_after_the_connection_dies() {
    let e = env(true, false).await;
    let echo = tcp_echo().await;
    let mgr = ConnManager::new(&client_config(e.srv.local_addr, &e.pubkey, "0123456789abcdef", false)).await.unwrap();
    echo_roundtrip(&mgr, echo, b"first").await;
    mgr.close_for_test().await;
    echo_roundtrip(&mgr, echo, b"second, on a fresh connection").await;
}

#[tokio::test]
async fn udp_association_roundtrip() {
    let e = env(true, false).await;
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut b = [0u8; 2048];
        while let Ok((n, from)) = echo.recv_from(&mut b).await {
            let _ = echo.send_to(&b[..n], from).await;
        }
    });
    let mgr = ConnManager::new(&client_config(e.srv.local_addr, &e.pubkey, "0123456789abcdef", false)).await.unwrap();
    let dummy = TargetAddr::Ip("0.0.0.0:0".parse().unwrap());
    let (mut send, mut recv) = mgr.open(CMD_UDP, &dummy).await.unwrap();
    send.write_all(&encode_udp_frame(&TargetAddr::Ip(echo_addr), b"ping").unwrap()).await.unwrap();
    let (src, data) = tokio::time::timeout(Duration::from_secs(5), read_udp_frame(&mut recv))
        .await.unwrap().unwrap().unwrap();
    assert_eq!(data, b"ping");
    assert_eq!(src, TargetAddr::Ip(echo_addr));
}

#[tokio::test]
async fn salamander_mode_authenticated_and_prober() {
    let e = env(true, true).await;
    let echo = tcp_echo().await;
    let mgr = ConnManager::new(&client_config(e.srv.local_addr, &e.pubkey, "0123456789abcdef", true)).await.unwrap();
    echo_roundtrip(&mgr, echo, b"obfuscated hello").await;
    // A plain (non-obfuscated) QUIC prober is still relayed raw to the decoy.
    probe(e.srv.local_addr, &e.decoy.cert_der).await.expect("prober must still see the decoy");
}

/// Capture the very first datagram a REALITY client emits and feed it to the
/// classifier: fresh -> Pass, same-flow retransmit -> Pass, replay elsewhere -> Relay.
#[tokio::test]
async fn replayed_client_hello_is_relayed_not_accepted() {
    use crate::reality_socket::Verdict;
    let e = env(true, false).await;
    let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sink_addr = sink.local_addr().unwrap();
    let mgr = ConnManager::new(&client_config(sink_addr, &e.pubkey, "0123456789abcdef", false)).await.unwrap();
    let h = tokio::spawn(async move { let _ = mgr.open(CMD_TCP, &TargetAddr::Ip("127.0.0.1:9".parse().unwrap())).await; });
    let mut buf = vec![0u8; 2048];
    let (n, client_addr) = tokio::time::timeout(Duration::from_secs(5), sink.recv_from(&mut buf)).await.unwrap().unwrap();
    h.abort();
    let first = &buf[..n];
    assert!(n >= 1200, "client Initial must be padded to 1200 bytes");

    let a = &e.srv.auth;
    let other: SocketAddr = "127.0.0.1:55555".parse().unwrap();
    assert_eq!(a.classify(first, client_addr), Verdict::Pass, "fresh authenticated Initial");
    assert_eq!(a.classify(first, client_addr), Verdict::Pass, "retransmit from the same flow");
    assert_eq!(a.classify(first, other), Verdict::Relay, "replay from another address");
    // junk and truncated packets never panic and go to the decoy
    assert_eq!(a.classify(&first[..40], other), Verdict::Relay);
    assert_eq!(a.classify(&[0u8; 5], other), Verdict::Relay);
    let _ = auth::now_secs();
}


/// The hand-written key schedule must work for every TLS 1.3 suite it offers
/// (SHA-256, SHA-384 and ChaCha20-Poly1305 take different code paths).
#[tokio::test]
async fn every_offered_tls13_suite_completes_a_handshake() {
    use crate::chrome_tls::LAST_NEGOTIATED;
    use crate::tls::TEST_FORCE_SUITE;
    for suite in [0x1301u16, 0x1302, 0x1303] {
        TEST_FORCE_SUITE.with(|c| c.set(suite));
        LAST_NEGOTIATED.with(|c| c.set(0));
        let e = env(true, false).await;
        let echo = tcp_echo().await;
        let mgr = ConnManager::new(&client_config(e.srv.local_addr, &e.pubkey, "0123456789abcdef", false))
            .await
            .unwrap();
        echo_roundtrip(&mgr, echo, format!("suite {suite:#06x}").as_bytes()).await;
        let big: Vec<u8> = (0..500_000u32).map(|i| (i % 253) as u8).collect();
        echo_roundtrip(&mgr, echo, &big).await;
        assert_eq!(LAST_NEGOTIATED.with(|c| c.get()), suite, "server was forced to {suite:#06x}");
    }
    TEST_FORCE_SUITE.with(|c| c.set(0));
}

/// The heart of dest mimicry: an authenticated connection's handshake must
/// come out shaped like the dest's own - the negotiated suite, the certificate
/// size, the post-handshake session tickets and the transport parameters the
/// probe recorded.
#[tokio::test]
async fn authenticated_handshake_is_shaped_after_the_dest() {
    use crate::chrome_tls::{LAST_CERT_DER_LEN, LAST_NEGOTIATED, LAST_NST_COUNT, LAST_PEER_TP};
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("quic_reality=debug"))
        .with_writer(std::io::stderr)
        .try_init();
    let e = env(true, false).await;
    let echo = tcp_echo().await;
    let mgr = ConnManager::new(&client_config(e.srv.local_addr, &e.pubkey, "0123456789abcdef", false))
        .await
        .unwrap();
    // Count only what this connection sees (the manager connects lazily).
    LAST_NEGOTIATED.with(|c| c.set(0));
    LAST_CERT_DER_LEN.with(|c| c.set(0));
    LAST_NST_COUNT.with(|c| c.set(0));
    LAST_PEER_TP.with(|t| *t.borrow_mut() = None);
    echo_roundtrip(&mgr, echo, b"shaped like the dest").await;
    // The decoy negotiated AES-128-GCM for this very ClientHello...
    assert_eq!(LAST_NEGOTIATED.with(|c| c.get()), 0x1301);
    // ...its certificate is exactly as long as the decoy's own...
    assert_eq!(LAST_CERT_DER_LEN.with(|c| c.get()), e.decoy.cert_der.len());
    // ...and the dest's two NewSessionTickets are replayed after the handshake.
    assert_eq!(LAST_NST_COUNT.with(|c| c.get()), 2);
    // The transport parameters the client receives are the decoy's own (it
    // runs quinn's defaults): 30 s idle, 100 streams either way, and the
    // stream window verbatim.  quinn's default connection window is
    // `VarInt::MAX`, which the proxy clamps rather than advertise.
    let tp = LAST_PEER_TP
        .with(|t| t.borrow().clone())
        .expect("the client received transport parameters");
    assert_eq!(tp.max_idle_timeout_ms, Some(30_000));
    assert_eq!(tp.initial_max_data, Some(64 * 1024 * 1024));
    assert_eq!(tp.initial_max_stream_data_bidi, Some(1_250_000));
    assert_eq!(tp.initial_max_streams_bidi, Some(100));
    assert_eq!(tp.initial_max_streams_uni, Some(100));
}

/// A dest with a non-default shape must be replayed just as exactly: the
/// suite it pinned (AES-256-GCM, not the AES-128 both peers prefer), the
/// length of its multi-certificate Certificate message, and the exact sizes
/// of its two NewSessionTickets.
#[tokio::test]
async fn authenticated_handshake_replays_a_non_default_dest_shape() {
    use crate::chrome_tls::{LAST_CERT_DER_LEN, LAST_NEGOTIATED, LAST_NST_COUNT, LAST_NST_LENS};
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("quic_reality=debug"))
        .with_writer(std::io::stderr)
        .try_init();
    let decoy = shaped_decoy();
    let kp = KeyPair::generate();
    let srv = server::start(&server_config(decoy.addr, &kp.private_hex(), true, false, true))
        .await
        .unwrap();
    let echo = tcp_echo().await;
    let mgr = ConnManager::new(&client_config(srv.local_addr, &kp.public_hex(), "0123456789abcdef", false))
        .await
        .unwrap();
    LAST_NEGOTIATED.with(|c| c.set(0));
    LAST_CERT_DER_LEN.with(|c| c.set(0));
    LAST_NST_COUNT.with(|c| c.set(0));
    LAST_NST_LENS.with(|l| l.borrow_mut().clear());
    echo_roundtrip(&mgr, echo, b"non-default shape").await;
    // The dest pinned AES-256-GCM; the client must see exactly that suite...
    assert_eq!(LAST_NEGOTIATED.with(|c| c.get()), 0x1302);
    // ...a certificate whose message is exactly as long as the dest's whole
    // three-certificate chain (our single temporary certificate is padded to
    // `chain message - 13`)...
    assert_eq!(
        LAST_CERT_DER_LEN.with(|c| c.get()),
        decoy.cert_msg_len - 13
    );
    // ...and the dest's two NewSessionTickets at their exact lengths.
    assert_eq!(LAST_NST_COUNT.with(|c| c.get()), 2);
    assert_eq!(LAST_NST_LENS.with(|l| l.borrow().clone()), decoy.nst_lens);
}

/// The control for both tests above: with `mimic_dest = false` the server
/// never probes, and the handshake keeps its own defaults - the suite the
/// client prefers (not the dest's pinned AES-256), no session tickets, and a
/// certificate unrelated to the dest's chain length.
#[tokio::test]
async fn mimicry_off_keeps_the_default_handshake() {
    use crate::chrome_tls::{LAST_CERT_DER_LEN, LAST_NEGOTIATED, LAST_NST_COUNT, LAST_NST_LENS};
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("quic_reality=debug"))
        .with_writer(std::io::stderr)
        .try_init();
    let decoy = shaped_decoy();
    let kp = KeyPair::generate();
    let srv = server::start(&server_config(decoy.addr, &kp.private_hex(), true, false, false))
        .await
        .unwrap();
    let echo = tcp_echo().await;
    let mgr = ConnManager::new(&client_config(srv.local_addr, &kp.public_hex(), "0123456789abcdef", false))
        .await
        .unwrap();
    LAST_NEGOTIATED.with(|c| c.set(0));
    LAST_CERT_DER_LEN.with(|c| c.set(0));
    LAST_NST_COUNT.with(|c| c.set(0));
    LAST_NST_LENS.with(|l| l.borrow_mut().clear());
    echo_roundtrip(&mgr, echo, b"no mimicry").await;
    // Nobody probed, so nothing was shaped: the client's own suite preference
    // (AES-128-GCM) wins, not the dest's pinned AES-256...
    assert_eq!(LAST_NEGOTIATED.with(|c| c.get()), 0x1301);
    // ...no NewSessionTickets are emitted at all...
    assert_eq!(LAST_NST_COUNT.with(|c| c.get()), 0);
    assert!(LAST_NST_LENS.with(|l| l.borrow().is_empty()));
    // ...and the certificate has nothing to do with the dest's 4 KiB chain.
    let shaped_len = decoy.cert_msg_len - 13;
    assert_ne!(LAST_CERT_DER_LEN.with(|c| c.get()), shaped_len);
}

/// A dest that cannot be reached must never gate the proxy: the probe fails,
/// the failure is cached (cooldown, no probe storm), and authenticated
/// clients are served on the default handshake.
#[tokio::test]
async fn unreachable_dest_never_gates_the_proxy() {
    use crate::chrome_tls::{LAST_NEGOTIATED, LAST_NST_COUNT};
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("quic_reality=debug"))
        .with_writer(std::io::stderr)
        .try_init();
    // A port that was bound and immediately dropped: nothing answers on it.
    let dead = {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap()
    };
    let kp = KeyPair::generate();
    let srv = server::start(&server_config(dead, &kp.private_hex(), true, false, true))
        .await
        .unwrap();
    // The prewarmed probe fails; the SNI stays in the cache (with its
    // cooldown) instead of being retried per connection.
    let m = srv.mimicry.as_ref().expect("mimicry is enabled");
    for _ in 0..100 {
        if m.cached() > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(m.cached(), 1, "the failed probe left a cooldown entry");
    assert!(
        srv.auth.flight(SNI).await.is_none(),
        "an unreachable dest yields no flight"
    );
    // And the proxy still serves authenticated clients.
    let echo = tcp_echo().await;
    let mgr = ConnManager::new(&client_config(srv.local_addr, &kp.public_hex(), "0123456789abcdef", false))
        .await
        .unwrap();
    LAST_NEGOTIATED.with(|c| c.set(0));
    LAST_NST_COUNT.with(|c| c.set(0));
    echo_roundtrip(&mgr, echo, b"dest is down").await;
    assert_eq!(LAST_NEGOTIATED.with(|c| c.get()), 0x1301);
    assert_eq!(LAST_NST_COUNT.with(|c| c.get()), 0);
}

struct ServerProc {
    stop: std::sync::mpsc::Sender<()>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ServerProc {
    /// Kill the server abruptly: its runtime and socket vanish, no CONNECTION_CLOSE is sent.
    fn crash(mut self) {
        let _ = self.stop.send(());
        self.thread.take().unwrap().join().unwrap();
    }
}

fn spawn_server(cfg: Config) -> Result<(ServerProc, SocketAddr), String> {
    let (addr_tx, addr_rx) = std::sync::mpsc::channel();
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    let thread = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        match rt.block_on(server::start(&cfg)) {
            Ok(r) => {
                let _ = addr_tx.send(Ok(r.local_addr));
                drop(r);
                let _ = stop_rx.recv();
                rt.shutdown_background();
            }
            Err(e) => {
                let _ = addr_tx.send(Err(e.to_string()));
            }
        }
    });
    let addr = addr_rx.recv().unwrap()?;
    Ok((ServerProc { stop: stop_tx, thread: Some(thread) }, addr))
}

/// A crashed-and-restarted server (same key, same port) must not leave clients
/// hanging for their idle timeout: the restarted server recognises the old
/// connection IDs and answers with a stateless reset, so the client reconnects at once.
#[tokio::test]
async fn client_recovers_quickly_after_a_server_crash_and_restart() {
    let decoy = decoy();
    let kp = KeyPair::generate();
    let port = {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap().port()
    };
    let mk = || {
        let mut c = server_config(decoy.addr, &kp.private_hex(), true, false, true);
        c.listen = format!("127.0.0.1:{port}");
        c
    };
    let (proc_a, addr) = spawn_server(mk()).unwrap();
    let echo = tcp_echo().await;
    let mgr = ConnManager::new(&client_config(addr, &kp.public_hex(), "0123456789abcdef", false)).await.unwrap();
    echo_roundtrip(&mgr, echo, b"before the crash").await;

    proc_a.crash();
    let mut restarted = None;
    for _ in 0..40 {
        match spawn_server(mk()) {
            Ok(p) => {
                restarted = Some(p);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    let _proc_b = restarted.expect("the port must become free again");

    let t0 = std::time::Instant::now();
    let (mut send, mut recv) = tokio::time::timeout(Duration::from_secs(20), mgr.open(CMD_TCP, &TargetAddr::Ip(echo)))
        .await
        .expect("request must not hang")
        .expect("request must succeed on a fresh connection");
    send.write_all(b"after the restart").await.unwrap();
    let mut got = [0u8; 17];
    recv.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"after the restart");
    let took = t0.elapsed();
    println!("recovery after crash+restart took {took:?}");
    assert!(took < Duration::from_secs(5), "recovery took {took:?}; the stateless reset path is not working");
}

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
struct Decoy {
    addr: SocketAddr,
    cert_der: Vec<u8>,
    _ep: quinn::Endpoint,
}

fn decoy() -> Decoy {
    let ck = rcgen::generate_simple_self_signed(vec![SNI.to_string()]).unwrap();
    let cert_der = ck.cert.der().to_vec();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der());
    let cfg = quinn::ServerConfig::with_single_cert(vec![ck.cert.der().clone()], key.into()).unwrap();
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

/// A plain QUIC client that knows nothing about REALITY (a "prober").
async fn probe(server: SocketAddr, trust: &[u8]) -> anyhow::Result<()> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(trust.to_vec()))?;
    let cc = quinn::ClientConfig::with_root_certificates(Arc::new(roots))?;
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

fn server_config(dest: SocketAddr, priv_hex: &str, allow_private: bool, salamander: bool) -> Config {
    let obf = if salamander { "[obfuscation]\ntype='salamander'\npassword='pw-123'\n" } else { "" };
    let s = format!(
        "mode='server'\nlisten='127.0.0.1:0'\n[reality]\nprivate_key='{priv_hex}'\nshort_id='0123456789abcdef'\nserver_name='{SNI}'\ndest='{dest}'\n[security]\nallow_private_targets={allow_private}\n{obf}"
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
    let srv = server::start(&server_config(decoy.addr, &kp.private_hex(), allow_private, salamander))
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
    let err = format!("{:#}", r.expect_err("must fail"));
    // It reached the decoy, whose certificate is not a REALITY certificate.
    assert!(err.contains("REALITY") || err.contains("certificate") || err.contains("handshake"), "{err}");
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
        let mut c = server_config(decoy.addr, &kp.private_hex(), true, false);
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

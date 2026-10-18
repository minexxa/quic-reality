use crate::auth::KeyPair;
use crate::cid::HmacCid;
use crate::config::{Config, QuicConfig};
use crate::mimic::Mimicry;
use crate::protocol::*;
use crate::reality_socket::{RealitySocket, RelayLimits, ServerAuth};
use crate::salamander::Salamander;
use crate::tls;
use crate::util::{is_public_ip, relay_tcp_quic};
use anyhow::{anyhow, bail, Context, Result};
use quinn::{Endpoint, EndpointConfig, RecvStream, SendStream, TokioRuntime};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, info, warn};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

async fn resolve_dest(dest: &str, listen: &SocketAddr) -> Result<Option<SocketAddr>> {
    if dest.trim().is_empty() {
        return Ok(None);
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(dest)
        .await
        .with_context(|| format!("resolving reality.dest {dest}"))?
        .collect();
    // The relay socket family must be reachable from this host.
    let pick = addrs
        .iter()
        .find(|a| a.is_ipv4() == listen.is_ipv4())
        .or_else(|| addrs.iter().find(|a| a.is_ipv4()))
        .or_else(|| addrs.first())
        .copied()
        .ok_or_else(|| anyhow!("reality.dest {dest} did not resolve"))?;
    Ok(Some(pick))
}

/// A running server (accept loop already spawned).
pub struct Running {
    #[allow(dead_code)]
    pub local_addr: SocketAddr,
    #[allow(dead_code)]
    pub public_key_hex: String,
    #[allow(dead_code)]
    pub endpoint: Endpoint,
    #[allow(dead_code)]
    pub auth: Arc<ServerAuth>,
    /// Test-only handle to the dest probe cache (see `Mimicry::cached`).
    #[cfg(test)]
    pub mimicry: Option<Arc<Mimicry>>,
}

pub async fn run(cfg: Config) -> Result<()> {
    let _running = start(&cfg).await?;
    std::future::pending::<()>().await;
    Ok(())
}

pub async fn start(cfg: &Config) -> Result<Running> {
    let kp = KeyPair::from_private_hex(&cfg.reality.private_key)?;
    let listen: SocketAddr = cfg.listen.parse().context("`listen` must be ip:port")?;
    let dest = resolve_dest(&cfg.reality.dest, &listen).await?;

    let base = tls::make_base_server_crypto()?;
    // Keys derived from the long-term private key survive restarts (see cid::derive_keys).
    let (cid_key, reset_key) = crate::cid::derive_keys(&kp.private.to_bytes());
    let cid = HmacCid::from_key(cid_key);
    // Dest handshake mimicry: probe the real site's QUIC handshake once per
    // SNI (cached, prewarmed below) and replay its shape for authenticated
    // clients - the reference implementation's record-length padding, ported
    // to QUIC messages.  A probe that fails must never gate the proxy, so a
    // broken probe endpoint degrades to the default handshake.
    let mimicry = match Mimicry::new(cfg.reality.mimic_dest, dest) {
        Ok(m) => m,
        Err(e) => {
            warn!("dest handshake mimicry disabled: {e}");
            None
        }
    };
    let server_names = cfg.server_names();
    if let Some(m) = &mimicry {
        m.prewarm(&server_names);
    }
    let auth = ServerAuth::new(
        kp.private.clone(),
        cfg.short_ids()?,
        server_names,
        cfg.reality.max_time_skew_secs,
        base.clone(),
        cid.clone(),
        dest,
        RelayLimits {
            upload: Some(cfg.reality.limit_fallback_upload),
            download: Some(cfg.reality.limit_fallback_download),
        },
        mimicry.clone(),
    );
    let salamander = cfg
        .obfuscation
        .is_salamander()
        .then(|| Salamander::new(cfg.obfuscation.password.as_bytes()))
        .transpose()?;
    let socket = RealitySocket::bind(listen, salamander, Some(auth.clone()))?;

    let mut ep_cfg = EndpointConfig::new(Arc::new(ring::hmac::Key::new(
        ring::hmac::HMAC_SHA256,
        &reset_key,
    )));
    let cid_for_endpoint = cid.clone();
    ep_cfg.cid_generator(move || Box::new(cid_for_endpoint.clone()));

    let transport = tls::make_transport(&cfg.quic, None);
    let mut base_cfg = quinn::ServerConfig::with_crypto(base);
    base_cfg.transport_config(transport.clone());
    let endpoint = Endpoint::new_with_abstract_socket(
        ep_cfg,
        Some(base_cfg),
        socket,
        Arc::new(TokioRuntime),
    )?;

    let local_addr = endpoint.local_addr()?;
    info!("listening on {local_addr}");
    info!("public_key = {}", kp.public_hex());
    match dest {
        Some(d) => info!("unauthenticated traffic is relayed to {d} ({})", cfg.reality.dest),
        None => warn!("reality.dest is empty: probes get silence instead of a real site (weaker camouflage)"),
    }
    if cfg.security.allow_private_targets {
        warn!("allow_private_targets=true: clients may reach private/loopback addresses");
    }

    let allow_private = cfg.security.allow_private_targets;
    let accept_ep = endpoint.clone();
    let accept_auth = auth.clone();
    let accept_quic = cfg.quic.clone();
    tokio::spawn(async move {
        while let Some(incoming) = accept_ep.accept().await {
            let auth = accept_auth.clone();
            let quic = accept_quic.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_incoming(incoming, auth, quic, allow_private).await {
                    debug!("connection ended: {e:#}");
                }
            });
        }
    });
    Ok(Running {
        local_addr,
        public_key_hex: kp.public_hex(),
        endpoint,
        auth,
        #[cfg(test)]
        mimicry,
    })
}

async fn handle_incoming(
    incoming: quinn::Incoming,
    auth: Arc<ServerAuth>,
    quic: QuicConfig,
    allow_private: bool,
) -> Result<()> {
    let peer = incoming.remote_address();
    let dcid = incoming.orig_dst_cid();
    // quinn only ever sees datagrams that passed the REALITY check, so this
    // lookup succeeds for every legitimate connection.
    let Some(pa) = auth.lookup(peer, &dcid) else {
        incoming.refuse();
        bail!("no authentication record for {peer}");
    };
    // The dest's probed flight shapes this connection's handshake *and* its
    // transport parameters; a missing one (mimicry off, probe failed) keeps
    // the defaults.
    let flight = auth.flight(&pa.server_name).await;
    let transport = tls::make_transport(&quic, flight.as_deref());
    let cfg = tls::make_conn_server_config(&pa.auth_key, flight.as_deref(), transport)?;
    let conn = incoming.accept_with(Arc::new(cfg))?.await?;
    info!("client connected from {peer} (sni {})", pa.server_name);

    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(s) => s,
            Err(quinn::ConnectionError::ApplicationClosed(_))
            | Err(quinn::ConnectionError::ConnectionClosed(_))
            | Err(quinn::ConnectionError::LocallyClosed)
            | Err(quinn::ConnectionError::TimedOut) => break,
            Err(e) => return Err(e.into()),
        };
        tokio::spawn(async move {
            if let Err(e) = handle_stream(send, recv, allow_private).await {
                debug!("stream error: {e:#}");
            }
        });
    }
    info!("client {peer} disconnected");
    Ok(())
}

/// Resolve and filter the target. Returns `None` if every address is forbidden.
async fn resolve_target(target: &TargetAddr, allow_private: bool) -> Result<Option<Vec<SocketAddr>>> {
    let addrs: Vec<SocketAddr> = match target {
        TargetAddr::Ip(a) => vec![*a],
        TargetAddr::Domain(h, p) => tokio::net::lookup_host((h.as_str(), *p)).await?.collect(),
    };
    if addrs.is_empty() {
        bail!("target did not resolve");
    }
    let allowed: Vec<SocketAddr> = addrs
        .into_iter()
        .filter(|a| allow_private || is_public_ip(a.ip()))
        .collect();
    Ok(if allowed.is_empty() { None } else { Some(allowed) })
}

async fn handle_stream(mut send: SendStream, mut recv: RecvStream, allow_private: bool) -> Result<()> {
    let (cmd, target) = tokio::time::timeout(REQUEST_TIMEOUT, read_request(&mut recv))
        .await
        .context("request timed out")??;
    match cmd {
        CMD_TCP => proxy_tcp(send, recv, target, allow_private).await,
        CMD_UDP => proxy_udp(send, recv, allow_private).await,
        c => {
            let _ = send.write_all(&[STATUS_ERROR]).await;
            bail!("unknown command {c}")
        }
    }
}

async fn proxy_tcp(
    mut send: SendStream,
    recv: RecvStream,
    target: TargetAddr,
    allow_private: bool,
) -> Result<()> {
    let addrs = match resolve_target(&target, allow_private).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            let _ = send.write_all(&[STATUS_DENIED]).await;
            bail!("target {target:?} is not allowed");
        }
        Err(e) => {
            let _ = send.write_all(&[STATUS_ERROR]).await;
            return Err(e);
        }
    };
    let mut last_err = None;
    let mut tcp = None;
    for a in addrs {
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(a)).await {
            Ok(Ok(s)) => {
                tcp = Some(s);
                break;
            }
            Ok(Err(e)) => last_err = Some(anyhow!(e)),
            Err(_) => last_err = Some(anyhow!("connect timeout")),
        }
    }
    let Some(tcp) = tcp else {
        let _ = send.write_all(&[STATUS_ERROR]).await;
        return Err(last_err.unwrap_or_else(|| anyhow!("connect failed")));
    };
    let _ = tcp.set_nodelay(true);
    send.write_all(&[STATUS_OK]).await?;
    debug!("TCP → {target:?}");
    relay_tcp_quic(tcp, send, recv).await;
    Ok(())
}

async fn proxy_udp(mut send: SendStream, mut recv: RecvStream, allow_private: bool) -> Result<()> {
    // Dual-stack socket; v4 destinations are used as v4-mapped addresses.
    let sock = match UdpSocket::bind("[::]:0").await {
        Ok(s) => s,
        Err(_) => UdpSocket::bind("0.0.0.0:0").await?,
    };
    let v6 = sock.local_addr()?.is_ipv6();
    send.write_all(&[STATUS_OK]).await?;

    let sock = Arc::new(sock);
    let rx_sock = sock.clone();
    let down = async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, from) = rx_sock.recv_from(&mut buf).await?;
            let src = SocketAddr::new(from.ip().to_canonical(), from.port());
            let frame = encode_udp_frame(&TargetAddr::Ip(src), &buf[..n])?;
            send.write_all(&frame).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let up = async move {
        while let Some((addr, payload)) = read_udp_frame(&mut recv).await? {
            let Some(addrs) = resolve_target(&addr, allow_private).await.ok().flatten() else {
                continue; // forbidden or unresolvable: drop the datagram
            };
            let mut to = addrs[0];
            if v6 {
                if let IpAddr::V4(v4) = to.ip() {
                    to = SocketAddr::new(IpAddr::V6(v4.to_ipv6_mapped()), to.port());
                }
            }
            let _ = sock.send_to(&payload, to).await;
        }
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {
        r = up => r,
        r = down => r,
    }
}

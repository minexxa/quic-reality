//! A `quinn::AsyncUdpSocket` that implements the REALITY decision *before* QUIC.
//!
//! Server side, for every received datagram:
//!
//! 1. its destination CID was minted by us (HMAC)  -> hand to quinn;
//! 2. it is a first Initial whose ClientHello proves knowledge of the server key
//!    (see `auth`), is fresh, and is not a replay    -> hand to quinn;
//! 3. anything else (scanners, GFW probes, replays, stray traffic) is relayed to
//!    the real `dest` site and the site's answers are relayed back, so a prober
//!    sees the genuine site's behaviour and certificate. quinn never sees it.
//!
//! The optional Salamander layer wraps the whole thing; when it is on, the
//! decision is made on the de-obfuscated bytes and failures are relayed *raw*.

use crate::auth::{self, SHORT_ID_LEN};
use crate::cid::{HmacCid, CID_LEN};
use crate::initial::{self, Header};
use crate::salamander::Salamander;
use anyhow::{anyhow, bail, Result};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Runtime, TokioRuntime, UdpPoller};
use std::collections::HashMap;
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};
use tracing::{debug, trace, warn};
use x25519_dalek::StaticSecret;

const PENDING_TTL: Duration = Duration::from_secs(120);
const RELAY_IDLE: Duration = Duration::from_secs(60);
const MAX_RELAYS: usize = 4096;
const MAX_SEEN: usize = 200_000;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Give the datagram to quinn.
    Pass,
    /// Relay it to the decoy site.
    Relay,
    /// Silently drop it (no decoy configured).
    Drop,
}

/// Result of a successful REALITY authentication, kept until quinn accepts.
#[derive(Clone)]
pub struct PendingAuth {
    pub auth_key: [u8; 32],
    pub server_name: String,
    expires: Instant,
}

struct Seen {
    peer: SocketAddr,
    dcid: Vec<u8>,
    expires: Instant,
}

struct Table {
    pending: HashMap<(SocketAddr, Vec<u8>), PendingAuth>,
    seen: HashMap<[u8; 32], Seen>,
    last_purge: Instant,
}

struct Relay {
    upstream: tokio::net::UdpSocket,
    last: Mutex<Instant>,
}

pub struct ServerAuth {
    secret: StaticSecret,
    short_ids: Vec<[u8; SHORT_ID_LEN]>,
    server_names: Vec<String>,
    max_skew: u64,
    crypto: Arc<QuicServerConfig>,
    cid: HmacCid,
    dest: Option<SocketAddr>,
    table: Mutex<Table>,
    relays: Mutex<HashMap<SocketAddr, Arc<Relay>>>,
    inner: OnceLock<Arc<dyn AsyncUdpSocket>>,
}

impl ServerAuth {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        secret: StaticSecret,
        short_ids: Vec<[u8; SHORT_ID_LEN]>,
        server_names: Vec<String>,
        max_skew: u64,
        crypto: Arc<QuicServerConfig>,
        cid: HmacCid,
        dest: Option<SocketAddr>,
    ) -> Arc<Self> {
        Arc::new(Self {
            secret,
            short_ids,
            server_names,
            max_skew,
            crypto,
            cid,
            dest,
            table: Mutex::new(Table {
                pending: HashMap::new(),
                seen: HashMap::new(),
                last_purge: Instant::now(),
            }),
            relays: Mutex::new(HashMap::new()),
            inner: OnceLock::new(),
        })
    }

    /// Authentication result for a connection quinn is about to accept.
    pub fn lookup(&self, peer: SocketAddr, dcid: &[u8]) -> Option<PendingAuth> {
        lock(&self.table)
            .pending
            .get(&(peer, dcid.to_vec()))
            .filter(|p| p.expires > Instant::now())
            .cloned()
    }

    fn is_pending(&self, peer: SocketAddr, dcid: &[u8]) -> bool {
        self.lookup(peer, dcid).is_some()
    }

    pub fn classify(&self, data: &[u8], peer: SocketAddr) -> Verdict {
        let fallback = if self.dest.is_some() {
            Verdict::Relay
        } else {
            Verdict::Drop
        };
        let Some(h) = initial::parse_header(data, CID_LEN) else {
            return fallback;
        };
        let dcid = h.dcid();
        // Stateless: only we can mint such a CID (covers every post-handshake
        // packet, also after the client's address changed).
        if self.cid.is_valid(dcid) {
            return Verdict::Pass;
        }
        match h {
            Header::Short { .. } => fallback,
            Header::Long { is_initial, .. } => {
                // Retransmits / follow-ups that still use the client's original DCID.
                if self.is_pending(peer, dcid) {
                    return Verdict::Pass;
                }
                if !is_initial {
                    return fallback;
                }
                match self.try_auth(data, peer, dcid) {
                    Ok(()) => Verdict::Pass,
                    Err(e) => {
                        trace!("unauthenticated initial from {peer}: {e}");
                        fallback
                    }
                }
            }
        }
    }

    fn try_auth(&self, data: &[u8], peer: SocketAddr, dcid: &[u8]) -> Result<()> {
        let init = initial::parse_client_initial(&*self.crypto, data)?;
        let sni = init.sni.ok_or_else(|| anyhow!("no SNI"))?;
        if !self.server_names.iter().any(|n| *n == sni) {
            bail!("SNI {sni} is not served");
        }
        let v = auth::verify_client_hello(
            &self.secret,
            &self.short_ids,
            self.max_skew,
            &init.random,
            &init.key_share,
            &sni,
            auth::now_secs(),
        )?;

        let now = Instant::now();
        let seen_ttl = Duration::from_secs(self.max_skew * 2 + 10);
        let mut t = lock(&self.table);
        if t.last_purge.elapsed() > Duration::from_secs(5) || t.seen.len() >= MAX_SEEN {
            t.seen.retain(|_, s| s.expires > now);
            t.pending.retain(|_, p| p.expires > now);
            t.last_purge = now;
        }
        match t.seen.get(&init.random) {
            // Same flow retransmitting its first packet.
            Some(s) if s.peer == peer && s.dcid == dcid => {}
            Some(_) => bail!("replayed ClientHello"),
            None => {
                if t.seen.len() >= MAX_SEEN {
                    bail!("replay table full");
                }
                t.seen.insert(
                    init.random,
                    Seen {
                        peer,
                        dcid: dcid.to_vec(),
                        expires: now + seen_ttl,
                    },
                );
            }
        }
        t.pending.insert(
            (peer, dcid.to_vec()),
            PendingAuth {
                auth_key: v.auth_key,
                server_name: sni,
                expires: now + PENDING_TTL,
            },
        );
        Ok(())
    }

    // ---- decoy relay ------------------------------------------------------

    /// Send bytes straight to `peer` from the listening port.
    fn send_raw(&self, peer: SocketAddr, data: &[u8]) {
        if let Some(inner) = self.inner.get() {
            let _ = inner.try_send(&Transmit {
                destination: peer,
                ecn: None,
                contents: data,
                segment_size: None,
                src_ip: None,
            });
        }
    }

    fn relay(self: &Arc<Self>, peer: SocketAddr, data: &[u8], stride: usize) {
        let Some(dest) = self.dest else { return };
        let relay = {
            let mut map = lock(&self.relays);
            match map.get(&peer) {
                Some(r) => r.clone(),
                None => {
                    if map.len() >= MAX_RELAYS {
                        return;
                    }
                    let bind = if dest.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
                    let sock = match std::net::UdpSocket::bind(bind).and_then(|s| {
                        s.connect(dest)?;
                        s.set_nonblocking(true)?;
                        tokio::net::UdpSocket::from_std(s)
                    }) {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("cannot create decoy relay socket: {e}");
                            return;
                        }
                    };
                    let r = Arc::new(Relay {
                        upstream: sock,
                        last: Mutex::new(Instant::now()),
                    });
                    map.insert(peer, r.clone());
                    let this = self.clone();
                    let task = r.clone();
                    tokio::spawn(async move { this.relay_task(peer, task).await });
                    r
                }
            }
        };
        *lock(&relay.last) = Instant::now();
        for chunk in data.chunks(stride.max(1)) {
            let _ = relay.upstream.try_send(chunk);
        }
    }

    async fn relay_task(self: Arc<Self>, peer: SocketAddr, relay: Arc<Relay>) {
        let mut buf = vec![0u8; 65535];
        loop {
            match tokio::time::timeout(Duration::from_secs(5), relay.upstream.recv(&mut buf)).await
            {
                Ok(Ok(n)) => {
                    *lock(&relay.last) = Instant::now();
                    self.send_raw(peer, &buf[..n]);
                }
                // ICMP "port unreachable" from the decoy shows up as an error on
                // a connected UDP socket; it must not tear the relay down.
                Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionRefused => {}
                Ok(Err(_)) => break,
                Err(_) => {
                    if lock(&relay.last).elapsed() > RELAY_IDLE {
                        break;
                    }
                }
            }
        }
        let mut map = lock(&self.relays);
        if map.get(&peer).is_some_and(|r| Arc::ptr_eq(r, &relay)) {
            map.remove(&peer);
        }
    }

    #[allow(dead_code)]
    pub fn active_relays(&self) -> usize {
        lock(&self.relays).len()
    }
}

/// UDP socket handed to quinn.
pub struct RealitySocket {
    inner: Arc<dyn AsyncUdpSocket>,
    salamander: Option<Salamander>,
    server: Option<Arc<ServerAuth>>,
}

impl fmt::Debug for RealitySocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealitySocket")
            .field("local", &self.inner.local_addr().ok())
            .field("salamander", &self.salamander.is_some())
            .field("server", &self.server.is_some())
            .finish()
    }
}

impl RealitySocket {
    pub fn bind(
        addr: SocketAddr,
        salamander: Option<Salamander>,
        server: Option<Arc<ServerAuth>>,
    ) -> io::Result<Arc<Self>> {
        let sock = std::net::UdpSocket::bind(addr)?;
        sock.set_nonblocking(true)?;
        let inner = TokioRuntime.wrap_udp_socket(sock)?;
        if let Some(s) = &server {
            let _ = s.inner.set(inner.clone());
        }
        Ok(Arc::new(Self {
            inner,
            salamander,
            server,
        }))
    }
}

impl AsyncUdpSocket for RealitySocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        match &self.salamander {
            None => self.inner.try_send(transmit),
            Some(s) => {
                // Salamander runs with segmentation offload disabled, so
                // `contents` is always exactly one datagram.
                let wire = s.obfuscate(transmit.contents);
                self.inner.try_send(&Transmit {
                    destination: transmit.destination,
                    ecn: transmit.ecn,
                    contents: &wire,
                    segment_size: None,
                    src_ip: transmit.src_ip,
                })
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // Fast path: a plain client socket has nothing to filter.
        if self.server.is_none() && self.salamander.is_none() {
            return self.inner.poll_recv(cx, bufs, meta);
        }
        loop {
            let n = ready!(self.inner.poll_recv(cx, bufs, meta))?;
            let mut kept = 0;
            for i in 0..n {
                let m = meta[i];
                let len = m.len;
                let stride = m.stride.max(1);

                // Plain QUIC bytes of this datagram (first segment if coalesced).
                let deobfuscated: Option<Vec<u8>> = self.salamander.as_ref().and_then(|s| {
                    let mut tmp = bufs[i][..len].to_vec();
                    s.deobfuscate_in_place(&mut tmp).map(|nl| {
                        tmp.truncate(nl);
                        tmp
                    })
                });
                let pass = match &self.server {
                    None => self.salamander.is_none() || deobfuscated.is_some(),
                    Some(srv) => {
                        let view: &[u8] = match (&self.salamander, &deobfuscated) {
                            (Some(_), Some(d)) => d,
                            (Some(_), None) => &[],
                            (None, _) => &bufs[i][..len.min(stride)],
                        };
                        match srv.classify(view, m.addr) {
                            Verdict::Pass => true,
                            Verdict::Relay => {
                                srv.relay(m.addr, &bufs[i][..len], stride);
                                false
                            }
                            Verdict::Drop => false,
                        }
                    }
                };
                if !pass {
                    continue;
                }

                match deobfuscated {
                    Some(d) => {
                        if d.len() > bufs[kept].len() {
                            continue;
                        }
                        bufs[kept][..d.len()].copy_from_slice(&d);
                        meta[kept] = m;
                        meta[kept].len = d.len();
                        meta[kept].stride = d.len();
                    }
                    None => {
                        if kept != i {
                            let (head, tail) = bufs.split_at_mut(i);
                            head[kept][..len].copy_from_slice(&tail[0][..len]);
                            meta[kept] = m;
                        }
                    }
                }
                kept += 1;
            }
            if kept > 0 {
                return Poll::Ready(Ok(kept));
            }
            debug!("filtered {n} datagram(s), polling again");
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        if self.salamander.is_some() {
            1
        } else {
            self.inner.max_transmit_segments()
        }
    }

    fn max_receive_segments(&self) -> usize {
        if self.salamander.is_some() {
            1
        } else {
            self.inner.max_receive_segments()
        }
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

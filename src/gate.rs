//! The REALITY gateway socket.
//!
//! Every inbound UDP datagram passes through here *before* quinn sees it:
//!
//! 1. Optional Salamander de-obfuscation.
//! 2. Connection lookup by client 4-tuple:
//!    - admitted  → straight into quinn's receive queue
//!    - nat'ed    → forwarded to the real destination (per-client socket)
//!    - unknown   → try to decrypt the QUIC Initial and verify the REALITY
//!                  session id; admit on success, otherwise start NAT relay
//!
//! The NAT relay is what makes failed probes *look* like the real site: the
//! prober's packets reach the actual destination and the destination's replies
//! come back through per-client sockets, so a scanner sees the genuine TLS
//! certificate chain of the target site.
//!
//! On the send path, quinn's datagrams are optionally Salamander-obfuscated
//! before hitting the wire.

use std::collections::HashMap;
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

use crate::reality::RealityServer;
use crate::salamander::Salamander;

/// NAT entries idle for longer than this are dropped.
const NAT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// How often the idle sweep runs.
const SWEEP_INTERVAL: Duration = Duration::from_secs(15);
/// Bound on admitted-datagram queue growth (backpressure via drop).
const RECV_QUEUE_MAX: usize = 4096;

/// Configuration for the gateway.
#[derive(Clone)]
pub struct GateConfig {
    pub reality: Arc<RealityServer>,
    /// Real site that failed probes are relayed to (host:port).
    pub dest: SocketAddr,
    /// Optional Salamander obfuscation layer.
    pub salamander: Option<Salamander>,
}

#[derive(Debug)]
enum ConnState {
    Admitted { last: Instant },
    Nat { last: Instant },
}

impl ConnState {
    fn last(&self) -> Instant {
        match self {
            Self::Admitted { last } | Self::Nat { last } => *last,
        }
    }
    fn touch(&mut self) {
        match self {
            Self::Admitted { last } | Self::Nat { last } => *last = Instant::now(),
        }
    }
}

#[derive(Debug)]
struct GateInner {
    /// Client-facing socket (the one bound to the public port).
    io: Arc<UdpSocket>,
    dest_addr: SocketAddr,
    reality: Arc<RealityServer>,
    salamander: Option<Salamander>,
    state: Mutex<GateState>,
    /// Datagrams admitted for quinn, consumed by `poll_recv`.
    recv_queue: Mutex<std::collections::VecDeque<(Vec<u8>, SocketAddr)>>,
    recv_waker: Mutex<Option<Waker>>,
    /// Channel used to publish per-client NAT sockets to their relay tasks.
    nat_tx: mpsc::UnboundedSender<NatJob>,
    stats: GateStats,
}

#[derive(Debug, Default)]
struct GateStats {
    admitted: AtomicU64,
    rejected: AtomicU64,
    nat_relayed: AtomicU64,
}

struct GateState {
    conns: HashMap<SocketAddr, ConnState>,
    nat_socks: HashMap<SocketAddr, Arc<UdpSocket>>,
}

impl std::fmt::Debug for GateState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GateState")
            .field("conns", &self.conns.len())
            .field("nat_socks", &self.nat_socks.len())
            .finish()
    }
}

/// A newly created NAT relay: client 4-tuple + destination-bound socket.
struct NatJob {
    client: SocketAddr,
    sock: Arc<UdpSocket>,
}

/// The socket quinn sees. Implements `quinn::AsyncUdpSocket` so the endpoint
/// binds to no port of its own — all traffic flows through the gate.
#[derive(Debug, Clone)]
pub struct GateSocket {
    inner: Arc<GateInner>,
}

impl GateSocket {
    /// Builds the gateway and spawns its background tasks.
    ///
    /// `io` must already be bound to the public listen address.
    pub fn new(io: UdpSocket, cfg: GateConfig) -> Arc<Self> {
        let (nat_tx, nat_rx) = mpsc::unbounded_channel::<NatJob>();
        let inner = Arc::new(GateInner {
            io: Arc::new(io),
            dest_addr: cfg.dest,
            reality: cfg.reality,
            salamander: cfg.salamander,
            state: Mutex::new(GateState {
                conns: HashMap::new(),
                nat_socks: HashMap::new(),
            }),
            recv_queue: Mutex::new(Default::default()),
            recv_waker: Mutex::new(None),
            nat_tx,
            stats: GateStats::default(),
        });
        let this = Arc::new(Self {
            inner: inner.clone(),
        });

        // 1. client-facing receive loop
        {
            let inner = inner.clone();
            tokio::spawn(async move { client_recv_loop(inner).await });
        }
        // 2. NAT relay spawner
        {
            let inner = inner.clone();
            tokio::spawn(async move { nat_spawn_loop(inner, nat_rx).await });
        }
        // 3. idle sweeper
        {
            let inner = inner.clone();
            tokio::spawn(async move { sweep_loop(inner).await });
        }
        this
    }

    pub fn stats_snapshot(&self) -> (u64, u64, u64) {
        let s = &self.inner.stats;
        (
            s.admitted.load(Ordering::Relaxed),
            s.rejected.load(Ordering::Relaxed),
            s.nat_relayed.load(Ordering::Relaxed),
        )
    }

    fn push_recv(&self, data: Vec<u8>, from: SocketAddr) {
        let mut q = self.inner.recv_queue.lock().unwrap_or_else(|e| e.into_inner());
        if q.len() >= RECV_QUEUE_MAX {
            q.pop_front(); // drop oldest: backpressure
        }
        q.push_back((data, from));
        drop(q);
        let mut w = self
            .inner
            .recv_waker
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(waker) = w.take() {
            waker.wake();
        }
    }
}

/// Main inbound loop: everything from clients lands here first.
async fn client_recv_loop(inner: Arc<GateInner>) {
    let mut buf = vec![0u8; 65536];
    loop {
        let (len, from) = match inner.io.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!("gate recv error: {e}");
                continue;
            }
        };
        let raw = &buf[..len];

        // Optional Salamander layer.
        let plain: Vec<u8> = match &inner.salamander {
            Some(s) => match s.deobfuscate(raw) {
                Ok(p) => p,
                Err(_) => {
                    // Not a Salamander packet at all — treat as a probe.
                    trace!("salamander decode failed from {from}; relaying to dest");
                    start_or_reuse_nat(&inner, from, raw).await;
                    continue;
                }
            },
            None => raw.to_vec(),
        };

        // Known connection?
        let known = {
            let mut st = inner.state.lock().unwrap_or_else(|e| e.into_inner());
            match st.conns.get_mut(&from) {
                Some(ConnState::Admitted { last }) => {
                    *last = Instant::now();
                    Some(true)
                }
                Some(ConnState::Nat { last }) => {
                    *last = Instant::now();
                    Some(false)
                }
                None => None,
            }
        };

        match known {
            Some(true) => {
                // Admitted: hand the plaintext datagram to quinn.
                let this = GateSocket {
                    inner: inner.clone(),
                };
                this.push_recv(plain, from);
            }
            Some(false) => {
                start_or_reuse_nat(&inner, from, raw).await;
            }
            None => {
                match classify(&inner, &plain) {
                    Ok(()) => {
                        debug!("REALITY admission granted to {from}");
                        inner.stats.admitted.fetch_add(1, Ordering::Relaxed);
                        inner
                            .state
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .conns
                            .insert(
                                from,
                                ConnState::Admitted {
                                    last: Instant::now(),
                                },
                            );
                        let this = GateSocket {
                            inner: inner.clone(),
                        };
                        this.push_recv(plain, from);
                    }
                    Err(reason) => {
                        debug!("REALITY admission denied to {from}: {reason:?}");
                        inner.stats.rejected.fetch_add(1, Ordering::Relaxed);
                        start_or_reuse_nat(&inner, from, raw).await;
                    }
                }
            }
        }
    }
}

/// Verifies the REALITY token inside the datagram's QUIC Initial.
fn classify(inner: &GateInner, datagram: &[u8]) -> Result<(), &'static str> {
    let pkt = crate::quic_initial::decrypt_initial(datagram)
        .map_err(|e| {
            trace!("initial parse: {e}");
            "not a decryptable QUIC v1 Initial"
        })?
        .ok_or("no Initial packet")?;
    let ch = crate::quic_initial::extract_client_hello(&pkt.payload).map_err(|e| {
        trace!("client hello: {e}");
        "no ClientHello in Initial"
    })?;
    let key_share = ch
        .x25519_key_share
        .as_ref()
        .ok_or("ClientHello without X25519 key share")?;
    inner
        .reality
        .open(&ch.random, &ch.session_id, key_share, &ch.zeroed_sid_message)
        .map(|_| ())
        .map_err(|e| {
            trace!("reality: {e}");
            "REALITY authentication failed"
        })
}

/// Relays a probe datagram to the real destination, creating the per-client
/// socket on first sight.
async fn start_or_reuse_nat(inner: &Arc<GateInner>, from: SocketAddr, payload: &[u8]) {
    let existing = {
        let st = inner.state.lock().unwrap_or_else(|e| e.into_inner());
        st.nat_socks.get(&from).cloned()
    };
    let sock = match existing {
        Some(s) => s,
        None => {
            let bind = match from {
                SocketAddr::V4(_) => "0.0.0.0:0",
                SocketAddr::V6(_) => "[::]:0",
            };
            let s = match UdpSocket::bind(bind).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("nat bind failed: {e}");
                    return;
                }
            };
            if let Err(e) = s.connect(inner.dest_addr).await {
                warn!("nat connect to {} failed: {e}", inner.dest_addr);
                return;
            }
            let s = Arc::new(s);
            inner
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .nat_socks
                .insert(from, s.clone());
            let _ = inner.nat_tx.send(NatJob {
                client: from,
                sock: s.clone(),
            });
            s
        }
    };

    // NAT entries expire; refresh the bookkeeping.
    {
        let mut st = inner.state.lock().unwrap_or_else(|e| e.into_inner());
        st.conns
            .entry(from)
            .and_modify(|c| c.touch())
            .or_insert(ConnState::Nat {
                last: Instant::now(),
            });
    }
    if let Err(e) = sock.send(payload).await {
        trace!("nat send to {} failed: {e}", inner.dest_addr);
    }
    inner.stats.nat_relayed.fetch_add(1, Ordering::Relaxed);
}

/// Spawns a relay task per NAT socket: destination replies flow back to the
/// original client through the gate socket.
async fn nat_spawn_loop(inner: Arc<GateInner>, mut rx: mpsc::UnboundedReceiver<NatJob>) {
    while let Some(job) = rx.recv().await {
        let inner = inner.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match job.sock.recv(&mut buf).await {
                    Ok(0) => break,
                    Ok(len) => {
                        let out = match &inner.salamander {
                            Some(s) => s.obfuscate(&buf[..len]),
                            None => buf[..len].to_vec(),
                        };
                        if let Err(e) = inner.io.send_to(&out, job.client).await {
                            trace!("nat reply to {} failed: {e}", job.client);
                            break;
                        }
                    }
                    Err(e) => {
                        trace!("nat recv from dest ended: {e}");
                        break;
                    }
                }
            }
            // Client went away: drop the entry.
            let mut st = inner.state.lock().unwrap_or_else(|e| e.into_inner());
            st.nat_socks.remove(&job.client);
            if matches!(st.conns.get(&job.client), Some(ConnState::Nat { .. })) {
                st.conns.remove(&job.client);
            }
        });
    }
}

/// Drops NAT entries that have been idle too long.
async fn sweep_loop(inner: Arc<GateInner>) {
    loop {
        tokio::time::sleep(SWEEP_INTERVAL).await;
        let now = Instant::now();
        let mut st = inner.state.lock().unwrap_or_else(|e| e.into_inner());
        let expired: Vec<SocketAddr> = st
            .conns
            .iter()
            .filter(|(_, c)| now.duration_since(c.last()) > NAT_IDLE_TIMEOUT)
            .map(|(a, _)| *a)
            .collect();
        for addr in expired {
            st.conns.remove(&addr);
            st.nat_socks.remove(&addr);
        }
    }
}

impl AsyncUdpSocket for GateSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(GatePoller {
            io: self.inner.io.clone(),
        })
    }

    fn try_send(&self, transmit: &Transmit) -> std::io::Result<()> {
        let payload = match &self.inner.salamander {
            Some(s) => s.obfuscate(transmit.contents),
            None => transmit.contents.to_vec(),
        };
        self.inner
            .io
            .try_send_to(&payload, transmit.destination)
            .map(|_| ())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        let mut q = self
            .inner
            .recv_queue
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match q.pop_front() {
            Some((data, addr)) => {
                drop(q);
                let mut copied = 0usize;
                for (i, slice) in bufs.iter_mut().enumerate() {
                    if i >= meta.len() {
                        break;
                    }
                    let take = data.len().saturating_sub(copied).min(slice.len());
                    if take == 0 {
                        break;
                    }
                    slice[..take].copy_from_slice(&data[copied..copied + take]);
                    meta[i] = RecvMeta {
                        addr,
                        len: take,
                        stride: take,
                        ecn: None,
                        dst_ip: None,
                    };
                    copied += take;
                }
                if copied == 0 {
                    // Datagram larger than the provided buffer; report truncation
                    // by delivering what fits with a reduced len.
                    return Poll::Ready(Ok(0));
                }
                Poll::Ready(Ok(1))
            }
            None => {
                *self
                    .inner
                    .recv_waker
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        // Salamander adds 8 bytes of salt per datagram; allow IP fragmentation
        // rather than failing the send.
        true
    }
}

/// Write-readiness poller backed by the gate socket itself.
#[derive(Debug)]
struct GatePoller {
    io: Arc<UdpSocket>,
}

impl UdpPoller for GatePoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<std::io::Result<()>> {
        self.io.poll_send_ready(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_socket_is_clone_send_sync() {
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<GateSocket>();
    }
}

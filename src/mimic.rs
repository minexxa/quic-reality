//! Dest handshake probing - the QUIC port of REALITY's "connect to dest first".
//!
//! # Why
//!
//! xtls/reality authenticates *before* committing to a server identity, and to
//! stay indistinguishable from the real site it then replays the dest's
//! handshake in shape: the temporary certificate is padded to the dest's
//! certificate size, every handshake record is padded to the length of the
//! corresponding dest record, and NewSessionTickets of the dest's exact
//! recorded lengths follow the handshake (`tls.go` `Server()`, `conn.go`
//! `out.encrypt`, `record_detect.go`).
//!
//! QUIC has no record layer, so the observable unit is the handshake *message*
//! and the packets carrying it. This module therefore probes the dest - the
//! real QUIC site unauthenticated traffic is relayed to - with the very
//! ClientHello a real client sends (see [`crate::chrome_tls`]), records the
//! dest's flight, and hands the server side a [`DestFlight`] to replay it in
//! shape: negotiated cipher suite, certificate size, NewSessionTicket sizes
//! and count, and the transport parameters the dest advertises.
//!
//! # When it runs
//!
//! Once per SNI, cached for [`FLIGHT_TTL`], with single-flight de-duplication
//! so concurrent connections share one probe - the same shape as the
//! reference's startup `DetectPostHandshakeRecordsLens` probe. A probe that
//! fails (dest unreachable, no h3, timeout) costs [`FAIL_COOLDOWN`] before the
//! next attempt and otherwise falls back to the server's default handshake:
//! the dest is only a camouflage reference, it must never gate the proxy.

use crate::chrome_tls::{self, ChromeClientConfig, Recorder};
use anyhow::Result;
use quinn::{ClientConfig, Endpoint, TransportConfig};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::OnceCell;
use tracing::{debug, info, warn};

/// How long a successfully probed flight stays fresh. Certificates rotate and
/// servers change; half an hour keeps the replay current without probing on
/// every connection.
const FLIGHT_TTL: Duration = Duration::from_secs(30 * 60);
/// Cooldown after a failed probe: an unreachable dest must not turn every new
/// connection into a doomed probe attempt.
const FAIL_COOLDOWN: Duration = Duration::from_secs(10);
/// Budget for connect + TLS handshake of one probe.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// Post-handshake window in which the dest's NewSessionTickets are collected.
const NST_WINDOW: Duration = Duration::from_millis(300);

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The subset of the dest's QUIC transport parameters quinn lets us set.
///
/// Raw TP bytes are recorded from the dest's EncryptedExtensions; the fields
/// below are the ones with a quinn `TransportConfig` setter (RFC 9000 §18.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DestTransportParams {
    pub max_idle_timeout_ms: Option<u64>,
    pub max_udp_payload: Option<u64>,
    pub initial_max_data: Option<u64>,
    pub initial_max_stream_data_bidi: Option<u64>,
    pub initial_max_streams_bidi: Option<u64>,
    pub initial_max_streams_uni: Option<u64>,
    pub ack_delay_exponent: Option<u8>,
    pub max_ack_delay_ms: Option<u64>,
    pub active_connection_id_limit: Option<u64>,
}

/// One QUIC varint (RFC 9000 §16).
fn varint(d: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *d.get(*pos)?;
    let len = 1usize << (first >> 6);
    let bytes = d.get(*pos..*pos + len)?;
    let mut v = (first & 0x3f) as u64;
    for b in &bytes[1..] {
        v = (v << 8) | *b as u64;
    }
    *pos += len;
    Some(v)
}

/// Parse the transport parameters a server sent (RFC 9000 §18.2 parameter
/// table). Every parameter is `id || len || value`; the values we care about
/// are single varints, everything else is skipped by its declared length. A
/// malformed parameter stops the parse and keeps what was read before it.
pub fn parse_transport_params(raw: &[u8]) -> DestTransportParams {
    let mut p = DestTransportParams::default();
    let mut pos = 0usize;
    while pos < raw.len() {
        let Some(id) = varint(raw, &mut pos) else { break };
        let Some(len) = varint(raw, &mut pos) else { break };
        let end = match pos.checked_add(len as usize) {
            Some(e) if e <= raw.len() => e,
            _ => break,
        };
        // Read the value as a varint bounded by the declared length, then skip
        // to the parameter end regardless (e.g. len-0 flags, longer values).
        let val = if end > pos { varint(&raw[..end], &mut pos) } else { None };
        pos = end;
        match id {
            // RFC 9000 §18.2 / IANA transport-parameter table.  0x06
            // (bidi_remote) is deliberately not recorded: endpoints set both
            // bidi stream windows to the same value, so 0x05 carries it.  0x07
            // (stream_data_uni) is not needed either - quinn cannot set the
            // unidirectional window separately anyway.
            0x01 => p.max_idle_timeout_ms = val,
            0x03 => p.max_udp_payload = val,
            0x04 => p.initial_max_data = val,
            0x05 => p.initial_max_stream_data_bidi = val,
            0x08 => p.initial_max_streams_bidi = val,
            0x09 => p.initial_max_streams_uni = val,
            0x0a => p.ack_delay_exponent = val.map(|v| v as u8),
            0x0b => p.max_ack_delay_ms = val,
            0x0e => p.active_connection_id_limit = val,
            _ => {}
        }
    }
    p
}

/// The dest's handshake flight, replayed in shape by authenticated connections.
#[derive(Debug, Clone)]
pub struct DestFlight {
    /// The cipher suite the dest negotiated for this client hello.
    pub suite: u16,
    /// Target DER length of our single temporary certificate, derived from
    /// the dest's Certificate message so ours comes out exactly as long:
    /// `msg_len - 13`, because a Certificate message carrying one certificate
    /// is `4 (handshake header) + 1 (request context) + 3 (certificate list)
    /// + 3 (certificate entry) + der + 2 (entry extensions)`.
    ///
    /// The dest may send a chain; the target only has to make *our* message
    /// as long as the dest's total.
    pub cert_der_len: usize,
    /// Size of every NewSessionTicket message the dest sends, in order.
    pub nst_lens: Vec<usize>,
    /// Lifetime the dest's tickets carry (seconds).
    pub ticket_lifetime: u32,
    /// The dest's transport parameters (settable subset).
    pub tp: DestTransportParams,
}

impl DestFlight {
    fn from_recorded(r: &chrome_tls::Recorded) -> Option<Self> {
        let cert_msg_len = r.cert_msg_len?;
        // Certificate message = header(4) + context(1) + list(3) + entry(3)
        // + der + entry extensions(2), for a single-certificate chain like
        // ours (rustls `CertificateEntry` carries a u16 extensions field).
        let cert_der_len = cert_msg_len.checked_sub(13)?;
        Some(Self {
            suite: r.suite?,
            cert_der_len,
            nst_lens: r.nst.iter().map(|(len, _)| *len).collect(),
            ticket_lifetime: r.nst.first().map_or(7200, |(_, lt)| *lt),
            tp: parse_transport_params(&r.tp),
        })
    }
}

struct CacheEntry {
    /// The current probe generation. `get_or_init` gives single-flight: the
    /// first caller probes, concurrent callers await the same future.
    cell: Arc<OnceCell<Option<Arc<DestFlight>>>>,
    /// When this generation goes stale and the next caller re-probes.
    fresh_until: Instant,
}

/// Probes the dest and caches one flight per SNI.
pub struct Mimicry {
    endpoint: Arc<Endpoint>,
    dest: Option<SocketAddr>,
    enabled: bool,
    inner: Mutex<HashMap<String, CacheEntry>>,
}

impl Mimicry {
    /// `None` when mimicry is disabled or no dest is configured - the server
    /// then keeps its default handshake, exactly as before.
    pub fn new(enabled: bool, dest: Option<SocketAddr>) -> std::io::Result<Option<Arc<Self>>> {
        if !enabled || dest.is_none() {
            return Ok(None);
        }
        let bind = if dest.is_some_and(|d| d.is_ipv4()) {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let endpoint = Endpoint::client(bind.parse().expect("valid bind addr"))?;
        info!("dest handshake mimicry enabled, probing with a fresh QUIC client");
        Ok(Some(Arc::new(Self {
            endpoint: Arc::new(endpoint),
            dest,
            enabled: true,
            inner: Mutex::new(HashMap::new()),
        })))
    }

    /// The dest's flight for `sni`: cached, probed on miss, `None` on any
    /// failure (the caller then uses the default handshake).
    pub async fn flight(&self, sni: &str) -> Option<Arc<DestFlight>> {
        if !self.enabled {
            return None;
        }
        let dest = self.dest?;

        let (cell, mine) = {
            let mut map = lock(&self.inner);
            let now = Instant::now();
            let entry = map.entry(sni.to_owned()).or_insert_with(|| CacheEntry {
                cell: Arc::new(OnceCell::new()),
                fresh_until: now, // stale until the first probe reports back
            });
            if entry.fresh_until <= now {
                // Expired or never probed: start a new generation. A probe
                // still running from the previous generation finishes into
                // the old cell and is dropped with it.
                entry.cell = Arc::new(OnceCell::new());
                entry.fresh_until = now + FLIGHT_TTL;
                (entry.cell.clone(), true)
            } else {
                (entry.cell.clone(), false)
            }
        };

        let endpoint = self.endpoint.clone();
        let sni_owned = sni.to_owned();
        let flight = cell
            .get_or_init(|| async move { probe(&endpoint, dest, &sni_owned).await.map(Arc::new) })
            .await
            .clone();

        if mine {
            // Successes stay fresh for the full TTL; failures only for the
            // cooldown, so a dest that recovers is picked up quickly.
            let ttl = if flight.is_some() {
                FLIGHT_TTL
            } else {
                FAIL_COOLDOWN
            };
            let mut map = lock(&self.inner);
            if let Some(e) = map.get_mut(sni) {
                if Arc::ptr_eq(&e.cell, &cell) {
                    e.fresh_until = Instant::now() + ttl;
                }
            }
        }
        flight
    }

    /// Prewarm every SNI the server serves, in the background, so the first
    /// client connection does not pay for the probe.
    pub fn prewarm(self: &Arc<Self>, snis: &[String]) {
        for sni in snis {
            let this = self.clone();
            let sni = sni.clone();
            tokio::spawn(async move {
                if let Some(f) = this.flight(&sni).await {
                    info!(
                        "dest flight for {sni}: suite {:#06x}, cert {} B, {} ticket(s)",
                        f.suite,
                        f.cert_der_len,
                        f.nst_lens.len()
                    );
                } else {
                    debug!("dest probe for {sni} failed; using the default handshake");
                }
            });
        }
    }

    /// Number of cached SNIs (tests).
    #[cfg(test)]
    pub fn cached(&self) -> usize {
        lock(&self.inner).len()
    }
}

async fn probe_connect(
    endpoint: &Endpoint,
    cfg: ClientConfig,
    dest: SocketAddr,
    sni: &str,
) -> Result<quinn::Connection> {
    let connecting = endpoint.connect_with(cfg, dest, sni)?;
    Ok(connecting.await?)
}
/// One probe: a real QUIC connection to the dest with a recording client.
async fn probe(
    endpoint: &Endpoint,
    dest: SocketAddr,
    sni: &str,
) -> Option<DestFlight> {
    let recorder: Recorder = Arc::new(Mutex::new(chrome_tls::Recorded::default()));
    let crypto = Arc::new(ChromeClientConfig::probe(recorder.clone()));
    let mut transport = TransportConfig::default();
    // A probe is throwaway: a short idle timeout and no keep-alive.
    transport.max_idle_timeout(Some(
        Duration::from_secs(5).try_into().expect("idle timeout fits"),
    ));
    let mut cfg = ClientConfig::new(crypto);
    cfg.transport_config(Arc::new(transport));

    let conn = match tokio::time::timeout(
        PROBE_TIMEOUT,
        probe_connect(endpoint, cfg, dest, sni),
    )
    .await
    {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            debug!("probe to {dest} ({sni}) failed: {e:#}");
            return None;
        }
        Err(_) => {
            debug!("probe to {dest} ({sni}) timed out");
            return None;
        }
    };

    // The dest's NewSessionTickets follow its Finished, usually in the same
    // flight but sometimes a beat later; quinn delivers them to the session's
    // `read_handshake`, which records them.
    tokio::time::sleep(NST_WINDOW).await;

    let flight = DestFlight::from_recorded(&lock(&recorder));
    conn.close(0u32.into(), b"probe");
    if let Some(f) = &flight {
        debug!(
            "probed {dest} ({sni}): suite {:#06x}, cert {} B, tickets {:?}",
            f.suite,
            f.cert_der_len,
            f.nst_lens
        );
    } else {
        warn!("dest {dest} ({sni}) sent no usable flight");
    }
    flight
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_params_parse_the_documented_ids() {
        // Encode one `id || len || value` parameter with proper varints.
        fn param(v: &mut Vec<u8>, id: u64, val: u64) {
            let mut enc = Vec::new();
            if val < 64 {
                enc.push(val as u8);
            } else if val < 16384 {
                enc.push(0x40 | (val >> 8) as u8);
                enc.push(val as u8);
            } else if val < 1 << 30 {
                enc.push(0x80 | (val >> 24) as u8);
                enc.extend_from_slice(&(val as u32).to_be_bytes()[1..]);
            } else {
                enc.push(0xc0 | (val >> 56) as u8);
                enc.extend_from_slice(&val.to_be_bytes());
            }
            let mut idenc = Vec::new();
            if id < 64 {
                idenc.push(id as u8);
            } else {
                idenc.push(0x40 | (id >> 8) as u8);
                idenc.push(id as u8);
            }
            v.extend_from_slice(&idenc);
            v.push(enc.len() as u8);
            v.extend_from_slice(&enc);
        }
        let mut v = Vec::new();
        param(&mut v, 0x01, 250); // max_idle_timeout
        param(&mut v, 0x03, 1450); // max_udp_payload_size
        param(&mut v, 0x04, 1024 * 1024); // initial_max_data
        param(&mut v, 0x05, 256 * 1024); // initial_max_stream_data_bidi_local
        param(&mut v, 0x08, 100); // initial_max_streams_bidi
        param(&mut v, 0x09, 7); // initial_max_streams_uni
        param(&mut v, 0x0a, 3); // ack_delay_exponent
        param(&mut v, 0x0b, 25); // max_ack_delay
        v.extend_from_slice(&[0x0c, 0x00]); // disable_active_migration: empty
        param(&mut v, 0x0e, 4); // active_connection_id_limit
        let p = parse_transport_params(&v);
        assert_eq!(p.max_idle_timeout_ms, Some(250));
        assert_eq!(p.max_udp_payload, Some(1450));
        assert_eq!(p.initial_max_data, Some(1024 * 1024));
        assert_eq!(p.initial_max_stream_data_bidi, Some(256 * 1024));
        assert_eq!(p.initial_max_streams_bidi, Some(100));
        assert_eq!(p.initial_max_streams_uni, Some(7));
        assert_eq!(p.ack_delay_exponent, Some(3));
        assert_eq!(p.max_ack_delay_ms, Some(25));
        assert_eq!(p.active_connection_id_limit, Some(4));
    }

    #[test]
    fn transport_params_garbage_yields_defaults() {
        assert_eq!(parse_transport_params(&[]), DestTransportParams::default());
        // truncated parameter: id without value
        assert_eq!(parse_transport_params(&[0x01]), DestTransportParams::default());
        // a two-byte varint id we do not know, with a value: skipped
        assert_eq!(
            parse_transport_params(&[0x40, 0x40, 0x01, 0x63]),
            DestTransportParams::default()
        );
    }

    #[test]
    fn flight_from_recorded_computes_cert_and_ticket_targets() {
        let mut r = chrome_tls::Recorded::default();
        assert!(DestFlight::from_recorded(&r).is_none(), "needs suite + cert");
        r.suite = Some(0x1302);
        r.cert_msg_len = Some(5000);
        // NST messages of 210 and 305 bytes, lifetime 7200.
        r.nst = vec![(210, 7200), (305, 7200)];
        r.tp = vec![0x01, 0x01, 0x0a];
        let f = DestFlight::from_recorded(&r).unwrap();
        assert_eq!(f.suite, 0x1302);
        assert_eq!(f.cert_der_len, 5000 - 13);
        assert_eq!(f.nst_lens, vec![210, 305]);
        assert_eq!(f.ticket_lifetime, 7200);
        assert_eq!(f.tp.max_idle_timeout_ms, Some(10));
    }

    #[test]
    fn flight_without_tickets_uses_the_default_lifetime() {
        let r = chrome_tls::Recorded {
            suite: Some(0x1301),
            cert_msg_len: Some(400),
            ..Default::default()
        };
        let f = DestFlight::from_recorded(&r).unwrap();
        assert!(f.nst_lens.is_empty());
        assert_eq!(f.ticket_lifetime, 7200);
        assert_eq!(f.cert_der_len, 387);
    }
}

//! rustls / quinn configuration for the REALITY handshake.
//!
//! Client: a hand-written TLS 1.3 session ([`crate::chrome_tls`]) that emits a
//! Chrome ClientHello - GREASE, Chrome's cipher suite order and Chrome's
//! extension order - carrying our authenticated `random` and the single X25519
//! key share Chrome sends.  rustls cannot do this: it always emits its own
//! hello, and the hello cannot be rewritten afterwards, because TLS 1.3 binds
//! its Finished messages to a hash of the handshake that actually went over
//! the wire.
//!
//! Server: a fresh `rustls::ServerConfig` per accepted connection that serves the
//! temporary REALITY certificate. Unauthenticated traffic never reaches it.

use crate::auth::ClientMaterial;
use crate::cert;
use crate::chrome_tls;
use crate::config::{Congestion, QuicConfig};
use crate::mimic::DestFlight;
use crate::ticket::PaddedTicketer;
use anyhow::{anyhow, Result};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{TransportConfig, VarInt};
use rustls::server::{ClientHello, ProducesTickets, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};

pub const ALPN: &[u8] = b"h3";

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Configuration for one outbound connection.
///
/// The REALITY material is moved in here: both the ephemeral key share and the
/// proof are single-use, so a config is never shared between connections.
pub fn make_client_config(
    m: ClientMaterial,
    transport: Arc<TransportConfig>,
) -> Result<quinn::ClientConfig> {
    let crypto = Arc::new(chrome_tls::ChromeClientConfig::new(m));
    let mut cfg = quinn::ClientConfig::new(crypto);
    cfg.transport_config(transport);
    Ok(cfg)
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct FixedCert(Option<Arc<CertifiedKey>>);

impl ResolvesServerCert for FixedCert {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.clone()
    }
}

#[cfg(test)]
thread_local! {
    /// Test hook: when non-zero, the server offers only this TLS 1.3 suite.
    /// Takes precedence over the dest's suite so e2e tests can force one.
    pub static TEST_FORCE_SUITE: std::cell::Cell<u16> = const { std::cell::Cell::new(0) };
}

/// Pin the negotiated suite to `id` by making it the provider's first
/// preference.  The suite cannot simply be *removed*: quinn derives the QUIC
/// Initial keys from TLS 1.3 AES-128-GCM and refuses a provider without it
/// (`initial_suite_from_provider`), so the rest of the list stays and
/// `ignore_client_order` (set by the caller on success) makes the server pick
/// its own preference.  `false` if this build cannot serve `id` at all.
fn pin_suite(provider: &mut rustls::crypto::CryptoProvider, id: u16) -> bool {
    if !provider
        .cipher_suites
        .iter()
        .any(|s| u16::from(s.suite()) == id)
    {
        warn!("dest negotiated suite {id:#06x}, which this build cannot serve; keeping the default");
        return false;
    }
    provider
        .cipher_suites
        .sort_by_key(|s| u16::from(s.suite()) != id);
    true
}

/// The per-connection rustls server config.
///
/// `suite`, `ticketer` and `n_tickets` come from the dest's probed flight (see
/// [`crate::mimic`]) and make the handshake shape match the dest's; `None`/`0`
/// keeps the default handshake.
fn server_crypto(
    ck: Option<Arc<CertifiedKey>>,
    suite: Option<u16>,
    ticketer: Option<Arc<dyn ProducesTickets>>,
    n_tickets: usize,
) -> Result<Arc<QuicServerConfig>> {
    let mut provider = rustls::crypto::ring::default_provider();
    // The test hook wins over the dest's suite so e2e tests can pin one.
    #[cfg(test)]
    let suite = {
        let forced = TEST_FORCE_SUITE.with(|c| c.get());
        if forced != 0 { Some(forced) } else { suite }
    };
    let pinned = suite.is_some_and(|id| pin_suite(&mut provider, id));
    let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(FixedCert(ck)));
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    crypto.max_early_data_size = 0;
    crypto.send_tls13_tickets = n_tickets;
    crypto.ignore_client_order = pinned;
    if let Some(t) = ticketer {
        crypto.ticketer = t;
    }
    Ok(Arc::new(
        QuicServerConfig::try_from(crypto).map_err(|e| anyhow!("quic server crypto: {e}"))?,
    ))
}

/// Config with no certificate: used to derive Initial keys and as the endpoint
/// default. A connection is never accepted with it.
pub fn make_base_server_crypto() -> Result<Arc<QuicServerConfig>> {
    server_crypto(None, None, None, 0)
}

/// Per-connection server config serving the temporary REALITY certificate.
///
/// With a probed `flight` the handshake is shaped after the dest: the
/// negotiated suite, the certificate's DER length and the post-handshake
/// NewSessionTickets all match what the dest sends.  Without one - mimicry
/// disabled, probe failed, no dest configured - the handshake keeps the
/// previous shape: default suite, minimal certificate, no tickets.
pub fn make_conn_server_config(
    auth_key: &[u8; 32],
    flight: Option<&DestFlight>,
    transport: Arc<TransportConfig>,
) -> Result<quinn::ServerConfig> {
    let (ck, suite, ticketer, n_tickets) = match flight {
        Some(f) => {
            let ck = Arc::new(cert::mint(auth_key, Some(f.cert_der_len))?);
            let tickets: Arc<dyn ProducesTickets> =
                Arc::new(PaddedTicketer::new(f.nst_lens.clone(), f.ticket_lifetime));
            (Some(ck), Some(f.suite), Some(tickets), f.nst_lens.len())
        }
        None => (Some(Arc::new(cert::mint(auth_key, None)?)), None, None, 0),
    };
    let mut cfg =
        quinn::ServerConfig::with_crypto(server_crypto(ck, suite, ticketer, n_tickets)?);
    cfg.transport_config(transport);
    Ok(cfg)
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// Flow-control windows copied from the dest are floored here: a proxy that
/// throttles itself to a tiny advertised window cannot move bulk data, and
/// real sites do advertise values this small.
const MIN_WINDOW: u64 = 1024 * 1024;
/// ...and capped here: the window is only an advertisement, but granting a
/// multi-gigabyte window per stream invites a buffer blow-up on a slow relay.
const MAX_WINDOW: u64 = 64 * 1024 * 1024;
/// The dest's idle timeout is clamped into this range: below 5 s a merely
/// chatty path reaps live connections, above 300 s a dead one pins resources.
const MIN_IDLE_SECS: u64 = 5;
const MAX_IDLE_SECS: u64 = 300;

/// Idle timeout in **seconds** to advertise for a dest that sent `ms`
/// milliseconds. `0` means the dest *disabled* its idle timeout
/// (RFC 9000 §18.2) and is mirrored: the negotiated timeout then falls back
/// to the client's own value, exactly what a direct connection to that dest
/// would negotiate.  Anything else is clamped to
/// [`MIN_IDLE_SECS`]..=[`MAX_IDLE_SECS`].
fn dest_idle_secs(ms: u64) -> u64 {
    if ms == 0 {
        0
    } else {
        (ms / 1000).clamp(MIN_IDLE_SECS, MAX_IDLE_SECS)
    }
}

/// Flow-control window in bytes to advertise for a dest that sent `v`,
/// clamped to [`MIN_WINDOW`]..=[`MAX_WINDOW`].
fn dest_window(v: u64) -> u64 {
    v.clamp(MIN_WINDOW, MAX_WINDOW)
}

/// Stream limit to advertise for a dest that sent `v`.  A dest that allows no
/// streams of a direction cannot be copied - this proxy needs one
/// bidirectional stream per connection for its request - so `0` keeps our
/// default.
fn dest_streams(v: u64) -> Option<u64> {
    (v > 0).then_some(v)
}

pub fn make_transport(q: &QuicConfig, flight: Option<&DestFlight>) -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    t.max_idle_timeout(Some(
        Duration::from_secs(q.idle_timeout_secs.max(MIN_IDLE_SECS))
            .try_into()
            .expect("idle timeout fits in a VarInt"),
    ));
    if q.keep_alive_secs > 0 {
        t.keep_alive_interval(Some(Duration::from_secs(q.keep_alive_secs)));
    }
    // Flow-control limits are advertised in the ClientHello's transport
    // parameters, so they are set to the round numbers browsers use (6 MiB per
    // stream, 15 MiB per connection, 100 bidirectional / 103 unidirectional
    // streams) instead of quinn-specific values.
    t.stream_receive_window(VarInt::from_u32(6 * 1024 * 1024));
    t.receive_window(VarInt::from_u32(15 * 1024 * 1024));
    t.send_window(32 * 1024 * 1024);
    t.max_concurrent_bidi_streams(VarInt::from_u32(100));
    t.max_concurrent_uni_streams(VarInt::from_u32(103));
    // Proxying is stream based; do not advertise the DATAGRAM extension.
    t.datagram_receive_buffer_size(None);
    // The dest's own transport parameters, probed with the real site's
    // handshake (see [`crate::mimic`]): an authenticated connection then
    // advertises the same flow-control shape a direct connection to the dest
    // would see.  Clamped values are logged - mimicry never degrades
    // silently.  Parameters quinn cannot set (ack_delay_exponent,
    // active_connection_id_limit, max_udp_payload, max_ack_delay) are
    // deliberately not covered.
    if let Some(f) = flight {
        let tp = &f.tp;
        if let Some(ms) = tp.max_idle_timeout_ms {
            let secs = dest_idle_secs(ms);
            if secs == 0 {
                debug!("dest disabled its idle timeout; mirroring it (the client's own timeout applies)");
                t.max_idle_timeout(Some(VarInt::from_u32(0).into()));
            } else {
                if secs * 1000 != ms {
                    debug!("dest idle timeout {ms} ms clamped to {secs} s");
                }
                t.max_idle_timeout(Some(
                    Duration::from_secs(secs).try_into().expect("idle timeout fits in a VarInt"),
                ));
            }
        }
        if let Some(v) = tp.initial_max_data {
            let w = dest_window(v);
            if w != v {
                debug!("dest initial_max_data {v} B clamped to {w} B");
            }
            t.receive_window(VarInt::try_from(w).expect("clamped window fits a VarInt"));
        }
        if let Some(v) = tp.initial_max_stream_data_bidi {
            let w = dest_window(v);
            if w != v {
                debug!("dest initial_max_stream_data_bidi {v} B clamped to {w} B");
            }
            t.stream_receive_window(VarInt::try_from(w).expect("clamped window fits a VarInt"));
        }
        if let Some(v) = tp.initial_max_streams_bidi.and_then(dest_streams) {
            t.max_concurrent_bidi_streams(VarInt::try_from(v).expect("stream limit fits a VarInt"));
        }
        if let Some(v) = tp.initial_max_streams_uni.and_then(dest_streams) {
            t.max_concurrent_uni_streams(VarInt::try_from(v).expect("stream limit fits a VarInt"));
        }
    }
    match q.congestion {
        Congestion::Bbr => {
            t.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        }
        Congestion::Cubic => {
            t.congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
        }
        Congestion::NewReno => {
            t.congestion_controller_factory(Arc::new(quinn::congestion::NewRenoConfig::default()));
        }
        Congestion::Brutal => {
            t.congestion_controller_factory(Arc::new(crate::brutal::BrutalConfig::new(
                q.brutal_bps(),
                q.brutal_disable_loss_compensation,
            )));
            // Brutal's window is exactly one bandwidth-delay product, which
            // on low-delay paths is only a few packets. quinn's default ACK
            // policy (every other ack-eliciting packet) degenerates to the
            // 25 ms MaxAckDelay timer whenever the window holds a single
            // packet, stretching the effective RTT and collapsing the send
            // rate to a fraction of the configured bandwidth. Requesting one
            // immediate ACK per ack-eliciting packet (QUIC ACK Frequency
            // extension, draft-ietf-quic-ack-frequency) keeps the window
            // recycling at the true RTT. quinn-proto only sends the request
            // when the peer advertises `min_ack_delay` (all quinn peers do),
            // so non-quinn peers silently keep the default policy.
            t.ack_frequency_config(Some({
                let mut c = quinn_proto::AckFrequencyConfig::default();
                c.ack_eliciting_threshold(quinn::VarInt::from_u32(0));
                c.max_ack_delay(Some(Duration::from_millis(1)));
                c
            }));
        }
    }
    Arc::new(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dest_idle_zero_mirrors_disabled() {
        // RFC 9000 §18.2: 0 means "no idle timeout" - not "5 seconds".
        assert_eq!(dest_idle_secs(0), 0);
    }

    #[test]
    fn dest_idle_is_clamped_to_the_proxy_range() {
        assert_eq!(dest_idle_secs(30_000), 30);
        assert_eq!(dest_idle_secs(999), MIN_IDLE_SECS);
        assert_eq!(dest_idle_secs(600_000), MAX_IDLE_SECS);
        assert_eq!(dest_idle_secs(u64::MAX), MAX_IDLE_SECS);
        // sub-second remainders floor, they do not round up into the range.
        assert_eq!(dest_idle_secs(4_999), MIN_IDLE_SECS);
    }

    #[test]
    fn dest_windows_are_clamped_both_ways() {
        assert_eq!(dest_window(64 * 1024), MIN_WINDOW);
        assert_eq!(dest_window(2 << 40), MAX_WINDOW);
        assert_eq!(dest_window(4 * 1024 * 1024), 4 * 1024 * 1024);
        assert_eq!(dest_window(u64::MAX), MAX_WINDOW);
    }

    #[test]
    fn dest_stream_limit_zero_keeps_the_default() {
        assert_eq!(dest_streams(0), None);
        assert_eq!(dest_streams(100), Some(100));
        assert_eq!(dest_streams(u64::MAX), Some(u64::MAX));
    }
}

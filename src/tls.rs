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
use anyhow::{anyhow, Result};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{TransportConfig, VarInt};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::sync::Arc;
use std::time::Duration;

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
    pub static TEST_FORCE_SUITE: std::cell::Cell<u16> = const { std::cell::Cell::new(0) };
}

fn server_crypto(ck: Option<Arc<CertifiedKey>>) -> Result<Arc<QuicServerConfig>> {
    #[allow(unused_mut)]
    let mut provider = rustls::crypto::ring::default_provider();
    #[cfg(test)]
    let forced = TEST_FORCE_SUITE.with(|c| c.get());
    #[cfg(test)]
    if forced != 0 {
        // The Initial-key suite (AES-128-GCM) must stay available, so the hook
        // reorders instead of removing: with `ignore_client_order` the server's
        // first choice wins.
        provider
            .cipher_suites
            .sort_by_key(|s| u16::from(s.suite()) != forced);
    }
    let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(FixedCert(ck)));
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    crypto.max_early_data_size = 0;
    crypto.send_tls13_tickets = 0;
    #[cfg(test)]
    if forced != 0 {
        crypto.ignore_client_order = true;
    }
    Ok(Arc::new(
        QuicServerConfig::try_from(crypto).map_err(|e| anyhow!("quic server crypto: {e}"))?,
    ))
}

/// Config with no certificate: used to derive Initial keys and as the endpoint
/// default. A connection is never accepted with it.
pub fn make_base_server_crypto() -> Result<Arc<QuicServerConfig>> {
    server_crypto(None)
}

/// Per-connection server config serving the temporary REALITY certificate.
pub fn make_conn_server_config(
    auth_key: &[u8; 32],
    transport: Arc<TransportConfig>,
) -> Result<quinn::ServerConfig> {
    let ck = cert::mint(auth_key)?;
    let mut cfg = quinn::ServerConfig::with_crypto(server_crypto(Some(Arc::new(ck)))?);
    cfg.transport_config(transport);
    Ok(cfg)
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

pub fn make_transport(q: &QuicConfig) -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    t.max_idle_timeout(Some(
        Duration::from_secs(q.idle_timeout_secs.max(5))
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

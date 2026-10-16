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
    let crypto = Arc::new(chrome_tls::ChromeClientConfig::new(&m));
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

fn server_crypto(ck: Option<Arc<CertifiedKey>>) -> Result<Arc<QuicServerConfig>> {
    let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(FixedCert(ck)));
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    crypto.max_early_data_size = 0;
    crypto.send_tls13_tickets = 0;
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
    server_name: &str,
    transport: Arc<TransportConfig>,
) -> Result<quinn::ServerConfig> {
    let ck = cert::mint(auth_key, server_name)?;
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
    t.stream_receive_window(VarInt::from_u32(8 * 1024 * 1024));
    t.receive_window(VarInt::from_u32(32 * 1024 * 1024));
    t.send_window(32 * 1024 * 1024);
    t.max_concurrent_bidi_streams(VarInt::from_u32(512));
    t.max_concurrent_uni_streams(VarInt::from_u32(16));
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
    }
    Arc::new(t)
}

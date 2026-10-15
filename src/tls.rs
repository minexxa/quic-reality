//! rustls / quinn configuration for the REALITY handshake.
//!
//! Client: rustls is given a custom `SecureRandom` and X25519 key-exchange group
//! so that the ClientHello it emits carries our authenticated `random` and our
//! pre-generated ephemeral key share. Both hooks are consumed synchronously
//! inside `Endpoint::connect_with`, so a thread-local hand-off is race free.
//!
//! Server: a fresh `rustls::ServerConfig` per accepted connection that serves the
//! temporary REALITY certificate. Unauthenticated traffic never reaches it.

use crate::auth::ClientMaterial;
use crate::cert;
use crate::config::{Congestion, QuicConfig};
use anyhow::{anyhow, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{TransportConfig, VarInt};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{
    ActiveKeyExchange, CryptoProvider, GetRandomFailed, SecureRandom, SharedSecret,
    SupportedKxGroup, WebPkiSupportedAlgorithms,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{DigitallySignedStruct, NamedGroup, SignatureScheme};
use std::cell::RefCell;
use std::sync::Arc;
use std::time::Duration;
use x25519_dalek::{PublicKey, StaticSecret};

pub const ALPN: &[u8] = b"h3";

// ---------------------------------------------------------------------------
// Client: hand our ClientHello material to rustls
// ---------------------------------------------------------------------------

struct Pending {
    secret: Option<StaticSecret>,
    public: [u8; 32],
    random: Option<[u8; 32]>,
}

thread_local! {
    static PENDING: RefCell<Option<Pending>> = const { RefCell::new(None) };
}

/// Runs `f` (which must start the QUIC handshake synchronously) with `m` staged
/// for rustls. Whatever was not consumed is dropped afterwards.
pub fn with_client_material<R>(m: ClientMaterial, f: impl FnOnce() -> R) -> R {
    PENDING.with(|p| {
        *p.borrow_mut() = Some(Pending {
            secret: Some(m.secret),
            public: m.public,
            random: Some(m.random),
        })
    });
    let out = f();
    PENDING.with(|p| *p.borrow_mut() = None);
    out
}

#[derive(Debug)]
struct RealityRandom;

impl SecureRandom for RealityRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        if buf.len() == 32 {
            let staged = PENDING.with(|p| p.borrow_mut().as_mut().and_then(|p| p.random.take()));
            if let Some(r) = staged {
                buf.copy_from_slice(&r);
                return Ok(());
            }
        }
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), buf)
            .map_err(|_| GetRandomFailed)
    }
}

#[derive(Debug)]
struct RealityKx;

struct ActiveKx {
    secret: StaticSecret,
    public: [u8; 32],
}

impl SupportedKxGroup for RealityKx {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let (secret, public) = PENDING
            .with(|p| {
                p.borrow_mut()
                    .as_mut()
                    .and_then(|p| p.secret.take().map(|s| (s, p.public)))
            })
            .ok_or_else(|| rustls::Error::General("REALITY key share was not staged".into()))?;
        Ok(Box::new(ActiveKx { secret, public }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

impl ActiveKeyExchange for ActiveKx {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let peer: [u8; 32] = peer_pub_key
            .try_into()
            .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
        let shared = self.secret.diffie_hellman(&PublicKey::from(peer));
        if !shared.was_contributory() {
            return Err(rustls::PeerMisbehaved::InvalidKeyShare.into());
        }
        Ok(SharedSecret::from(&shared.as_bytes()[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

static REALITY_RANDOM: RealityRandom = RealityRandom;
static REALITY_KX: RealityKx = RealityKx;

fn client_provider() -> CryptoProvider {
    let mut p = rustls::crypto::ring::default_provider();
    p.secure_random = &REALITY_RANDOM;
    p.kx_groups = vec![&REALITY_KX];
    p
}

/// Accepts exactly one kind of server: one that holds the REALITY private key.
#[derive(Debug)]
struct RealityVerifier {
    auth_key: [u8; 32],
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for RealityVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if !intermediates.is_empty() {
            return Err(rustls::Error::General("unexpected intermediates".into()));
        }
        cert::check(end_entity.as_ref(), &self.auth_key)
            .map_err(|e| rustls::Error::General(e.to_string()))?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    // The CertificateVerify signature really is checked: it proves the peer holds
    // the private key of the HMAC-authenticated certificate.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

pub fn make_client_config(
    auth_key: [u8; 32],
    transport: Arc<TransportConfig>,
) -> Result<quinn::ClientConfig> {
    let provider = Arc::new(client_provider());
    let verifier = Arc::new(RealityVerifier {
        auth_key,
        algs: provider.signature_verification_algorithms,
    });
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    crypto.resumption = rustls::client::Resumption::disabled();
    crypto.enable_early_data = false;

    let quic = QuicClientConfig::try_from(Arc::new(crypto))
        .map_err(|e| anyhow!("quic client crypto: {e}"))?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(quic));
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

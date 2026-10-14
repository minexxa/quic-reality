//! REALITY-style authentication (ported from Xray REALITY / reality-rs).
//!
//! Protocol layout, identical on both sides:
//!
//! ```text
//! reality_key = X25519(priv, peer_pub)                       // 32B
//! sealing_key = HKDF-SHA256(salt=client_random[0..20],
//!                          ikm=reality_key, info="REALITY")  // 32B (AES-128 uses [..16])
//! nonce       = client_random[20..32]                        // 12B
//! header      = version(3) || rsv(1) || ts_be32(4) || short_id(8)  // 16B plaintext
//! session_id  = AES-128-GCM(sealing_key[..16], nonce,
//!                           aad=ClientHello-with-zeroed-sid,
//!                           header)                          // 32B (16 ct + 16 tag)
//! ```
//!
//! The client seals the header into the TLS session_id; the gateway opens it
//! from the ClientHello extracted out of the QUIC Initial packet. A valid tag
//! plus an in-window timestamp plus a known short_id admits the connection;
//! anything else is transparently relayed to the real destination.

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, NONCE_LEN};
use ring::hkdf::HKDF_SHA256;
use ring::rand::{SecureRandom, SystemRandom};
use x25519_dalek::{PublicKey, StaticSecret};

pub const VERSION: [u8; 3] = [1, 0, 0];
pub const HEADER_LEN: usize = 16;
pub const SESSION_ID_LEN: usize = 32;
pub const REALITY_INFO: &[u8] = b"REALITY";
pub const SHORT_ID_LEN: usize = 8;

/// Default timestamp tolerance: older headers are replayed, future ones are skew.
pub const DEFAULT_MAX_PAST_SKEW_SECS: u32 = 300;
pub const DEFAULT_MAX_FUTURE_SKEW_SECS: u32 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RealityError {
    BadKeyLen { actual: usize, expected: usize },
    BadHex(String),
    BadShortIdLen { actual: usize, maximum: usize },
    Seal(String),
    Open(String),
    /// Authentication failed: bad tag, unknown short id, or bad version.
    AuthFailed,
    /// Header timestamp outside the accepted window (replay/clock skew).
    TimestampOutOfWindow { ts: u32, now: u32 },
    /// Duplicate session id observed inside the replay window.
    Replay,
}

impl fmt::Display for RealityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadKeyLen { actual, expected } => {
                write!(f, "key must be {expected} bytes, got {actual}")
            }
            Self::BadHex(s) => write!(f, "invalid hex: {s}"),
            Self::BadShortIdLen { actual, maximum } => {
                write!(f, "short id must be <= {maximum} bytes, got {actual}")
            }
            Self::Seal(s) => write!(f, "seal failed: {s}"),
            Self::Open(s) => write!(f, "open failed: {s}"),
            Self::AuthFailed => write!(f, "REALITY authentication failed"),
            Self::TimestampOutOfWindow { ts, now } => {
                write!(f, "REALITY timestamp {ts} outside window (now {now})")
            }
            Self::Replay => write!(f, "REALITY session id replay detected"),
        }
    }
}

impl std::error::Error for RealityError {}

/// X25519 static key pair. The private scalar is persisted so the same key
/// survives restarts (a new key would invalidate every deployed client).
#[derive(Clone)]
pub struct KeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let rng = SystemRandom::new();
        let mut scalar = [0u8; 32];
        rng.fill(&mut scalar).expect("system rng");
        let secret = StaticSecret::from(scalar);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn from_private_hex(hex_str: &str) -> Result<Self, RealityError> {
        let scalar = hex_to_array::<32>(hex_str)?;
        let secret = StaticSecret::from(scalar);
        let public = PublicKey::from(&secret);
        Ok(Self { secret, public })
    }

    pub fn private_hex(&self) -> String {
        hex::encode(self.secret.to_bytes())
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.public.as_bytes())
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Raw private scalar. Clients recover a KeyPair from persisted hex, so
    /// exposing it adds no new attack surface.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// REALITY shared secret: X25519(self private, peer public).
    pub fn reality_key(&self, peer_public: &[u8]) -> Option<[u8; 32]> {
        let peer: [u8; 32] = peer_public.try_into().ok()?;
        Some(self.secret.diffie_hellman(&PublicKey::from(peer)).to_bytes())
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &self.public_hex())
            .finish_non_exhaustive()
    }
}

/// Derives the per-connection sealing key.
///
/// `HKDF-SHA256(salt=client_random[0..20], ikm=reality_key, info="REALITY")`,
/// matching Xray REALITY byte for byte.
pub fn derive_sealing_key(reality_key: &[u8], client_random: &[u8; 32]) -> [u8; 32] {
    let prk = ring::hkdf::Salt::new(HKDF_SHA256, &client_random[..20]).extract(reality_key);
    let mut key = [0u8; 32];
    prk.expand(&[REALITY_INFO], Len32)
        .expect("32 bytes is a valid HKDF output length")
        .fill(&mut key)
        .expect("32 bytes is a valid HKDF output length");
    key
}

/// `ring::hkdf::KeyType` shim yielding a fixed 32-byte output.
struct Len32;

impl ring::hkdf::KeyType for Len32 {
    fn len(&self) -> usize {
        32
    }
}

/// The 16-byte plaintext header carried inside the session id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealityHeader {
    pub version: [u8; 3],
    pub rsv: u8,
    pub timestamp: u32,
    /// Left-padded to 8 bytes; trailing zero padding is significant.
    pub short_id: [u8; SHORT_ID_LEN],
}

impl RealityHeader {
    pub fn new(timestamp: u32, short_id: &[u8]) -> Result<Self, RealityError> {
        if short_id.len() > SHORT_ID_LEN {
            return Err(RealityError::BadShortIdLen {
                actual: short_id.len(),
                maximum: SHORT_ID_LEN,
            });
        }
        let mut padded = [0u8; SHORT_ID_LEN];
        padded[..short_id.len()].copy_from_slice(short_id);
        Ok(Self {
            version: VERSION,
            rsv: 0,
            timestamp,
            short_id: padded,
        })
    }

    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..3].copy_from_slice(&self.version);
        out[3] = self.rsv;
        out[4..8].copy_from_slice(&self.timestamp.to_be_bytes());
        out[8..16].copy_from_slice(&self.short_id);
        out
    }

    pub fn from_bytes(bytes: &[u8; HEADER_LEN]) -> Self {
        let mut short_id = [0u8; SHORT_ID_LEN];
        short_id.copy_from_slice(&bytes[8..16]);
        Self {
            version: [bytes[0], bytes[1], bytes[2]],
            rsv: bytes[3],
            timestamp: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            short_id,
        }
    }
}

/// Client-side sealer. Produces the 32-byte session id for a ClientHello.
pub struct RealityClient {
    keypair: KeyPair,
    short_id: Vec<u8>,
}

impl RealityClient {
    pub fn new(keypair: KeyPair, short_id: &[u8]) -> Result<Self, RealityError> {
        if short_id.len() > SHORT_ID_LEN {
            return Err(RealityError::BadShortIdLen {
                actual: short_id.len(),
                maximum: SHORT_ID_LEN,
            });
        }
        Ok(Self {
            keypair,
            short_id: short_id.to_vec(),
        })
    }

    pub fn keypair(&self) -> &KeyPair {
        &self.keypair
    }

    pub fn short_id(&self) -> &[u8] {
        &self.short_id
    }

    /// Seals the REALITY header into a session id.
    ///
    /// * `reality_key` — X25519(ephemeral client private, server static public),
    ///   obtained from the rustls fork hook
    ///   (`active_key_exchange.extract_reality_key(server_public)`)
    /// * `client_random` — the ClientHello random (salt/nonce source)
    /// * `aad` — encoded ClientHello with the session id bytes zeroed
    pub fn seal(
        &self,
        reality_key: &[u8],
        client_random: &[u8; 32],
        aad: &[u8],
    ) -> Result<[u8; SESSION_ID_LEN], RealityError> {
        if reality_key.len() != 32 {
            return Err(RealityError::BadKeyLen {
                actual: reality_key.len(),
                expected: 32,
            });
        }
        let sealing_key = derive_sealing_key(reality_key, client_random);
        let header = RealityHeader::new(now_secs(), &self.short_id)?;
        let nonce_bytes: [u8; NONCE_LEN] = client_random[20..32]
            .try_into()
            .map_err(|_| RealityError::Seal("client random too short".into()))?;

        let key = UnboundKey::new(&AES_128_GCM, &sealing_key[..16])
            .map_err(|e| RealityError::Seal(e.to_string()))?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = header.to_bytes().to_vec();
        LessSafeKey::new(key)
            .seal_in_place_separate_tag(nonce, Aad::from(aad), &mut in_out)
            .map_err(|e| RealityError::Seal(e.to_string()))
            .map(|tag| {
                let mut out = [0u8; SESSION_ID_LEN];
                out[..HEADER_LEN].copy_from_slice(&in_out);
                out[HEADER_LEN..].copy_from_slice(tag.as_ref());
                out
            })
    }
}

/// Server-side verifier, bound to one static key pair and a short-id set.
#[derive(Debug)]
pub struct RealityServer {
    keypair: KeyPair,
    short_ids: Vec<Vec<u8>>,
    max_past_skew: u32,
    max_future_skew: u32,
    replay: Mutex<ReplayCache>,
}

impl RealityServer {
    pub fn new(
        keypair: KeyPair,
        short_ids: Vec<Vec<u8>>,
        max_past_skew: u32,
        max_future_skew: u32,
    ) -> Self {
        Self {
            keypair,
            short_ids,
            max_past_skew,
            max_future_skew,
            replay: Mutex::new(ReplayCache::new(max_past_skew as usize + 16)),
        }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.keypair.public_bytes()
    }

    /// Opens and validates a session id observed in a ClientHello.
    ///
    /// * `client_random` — ClientHello random
    /// * `session_id` — the 32-byte wire session id
    /// * `client_key_share` — the X25519 key share from the ClientHello
    /// * `aad` — encoded ClientHello with session id bytes zeroed
    ///
    /// Returns the decoded header on success. Failure means the packet is not
    /// from an authenticated client: the gateway relays it to the real site.
    pub fn open(
        &self,
        client_random: &[u8; 32],
        session_id: &[u8],
        client_key_share: &[u8],
        aad: &[u8],
    ) -> Result<RealityHeader, RealityError> {
        if session_id.len() != SESSION_ID_LEN {
            return Err(RealityError::AuthFailed);
        }
        let reality_key = self
            .keypair
            .reality_key(client_key_share)
            .ok_or(RealityError::AuthFailed)?;
        let sealing_key = derive_sealing_key(&reality_key, client_random);
        let nonce_bytes: [u8; NONCE_LEN] = client_random[20..32]
            .try_into()
            .map_err(|_| RealityError::AuthFailed)?;

        let key = UnboundKey::new(&AES_128_GCM, &sealing_key[..16])
            .map_err(|_| RealityError::AuthFailed)?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = session_id.to_vec();
        let plaintext = LessSafeKey::new(key)
            .open_in_place(nonce, Aad::from(aad), &mut in_out)
            .map_err(|_| RealityError::AuthFailed)?;
        if plaintext.len() != HEADER_LEN {
            return Err(RealityError::AuthFailed);
        }
        let mut header_bytes = [0u8; HEADER_LEN];
        header_bytes.copy_from_slice(plaintext);
        let header = RealityHeader::from_bytes(&header_bytes);

        if header.version != VERSION {
            return Err(RealityError::AuthFailed);
        }
        if !self
            .short_ids
            .iter()
            .any(|id| id.as_slice() == &header.short_id[..])
        {
            return Err(RealityError::AuthFailed);
        }

        let now = now_secs();
        let skew_past = now.saturating_sub(header.timestamp);
        let skew_future = header.timestamp.saturating_sub(now);
        if skew_past > self.max_past_skew || skew_future > self.max_future_skew {
            return Err(RealityError::TimestampOutOfWindow {
                ts: header.timestamp,
                now,
            });
        }

        let mut replay = self.replay.lock().unwrap_or_else(|e| e.into_inner());
        if !replay.check_and_insert(session_id, now) {
            return Err(RealityError::Replay);
        }
        Ok(header)
    }
}

/// Bounded map of session ids seen recently, keyed by expiry second.
#[derive(Debug)]
struct ReplayCache {
    seen: HashMap<[u8; SESSION_ID_LEN], u32>,
    ttl: usize,
}

impl ReplayCache {
    fn new(ttl: usize) -> Self {
        Self {
            seen: HashMap::new(),
            ttl: ttl.max(16),
        }
    }

    /// Returns true if this session id is new; false on replay.
    fn check_and_insert(&mut self, session_id: &[u8], now: u32) -> bool {
        self.evict(now);
        let mut key = [0u8; SESSION_ID_LEN];
        if session_id.len() != SESSION_ID_LEN {
            return false;
        }
        key.copy_from_slice(session_id);
        if self.seen.contains_key(&key) {
            return false;
        }
        self.seen.insert(key, now);
        true
    }

    fn evict(&mut self, now: u32) {
        let ttl = self.ttl as u32;
        self.seen
            .retain(|_, inserted| now.saturating_sub(*inserted) <= ttl);
    }
}

/// X25519(raw private scalar, peer public).
fn ecdh(private: &[u8], peer_public: &[u8]) -> Option<[u8; 32]> {
    let scalar: [u8; 32] = private.try_into().ok()?;
    let peer: [u8; 32] = peer_public.try_into().ok()?;
    let secret = StaticSecret::from(scalar);
    let shared = secret.diffie_hellman(&PublicKey::from(peer)).to_bytes();
    if shared.iter().all(|b| *b == 0) {
        return None;
    }
    Some(shared)
}

pub fn now_secs() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

pub fn hex_to_array<const N: usize>(s: &str) -> Result<[u8; N], RealityError> {
    let raw = hex::decode(s.trim()).map_err(|e| RealityError::BadHex(e.to_string()))?;
    if raw.len() != N {
        return Err(RealityError::BadKeyLen {
            actual: raw.len(),
            expected: N,
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&raw);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keypair() -> KeyPair {
        KeyPair::from_private_hex(&"11".repeat(32)).unwrap()
    }

    /// (ephemeral client keypair, reality_key)
    fn client_side(server: &KeyPair) -> (KeyPair, [u8; 32]) {
        let client = KeyPair::generate();
        let rk = ecdh(&client.secret_bytes(), &server.public_bytes()).unwrap();
        (client, rk)
    }

    #[test]
    fn seal_open_roundtrip() {
        let server = test_keypair();
        let verifier = RealityServer::new(
            server.clone(),
            vec![b"01234567".to_vec()],
            DEFAULT_MAX_PAST_SKEW_SECS,
            DEFAULT_MAX_FUTURE_SKEW_SECS,
        );
        let (client, rk) = client_side(&server);

        let client_random = [7u8; 32];
        let aad = b"fake client hello with zeroed session id placeholder bytes";

        let rc = RealityClient::new(client.clone(), b"01234567").unwrap();
        let session_id = rc.seal(&rk, &client_random, aad).unwrap();

        let header = verifier
            .open(&client_random, &session_id, &client.public_bytes(), aad)
            .unwrap();
        assert_eq!(header.timestamp, now_secs());
        assert_eq!(&header.short_id[..], b"01234567");
    }

    #[test]
    fn wrong_key_share_fails() {
        let server = test_keypair();
        let verifier =
            RealityServer::new(server.clone(), vec![b"01234567".to_vec()], 300, 5);
        let (client, rk) = client_side(&server);
        let attacker = KeyPair::generate();
        let rc = RealityClient::new(client.clone(), b"01234567").unwrap();
        let session_id = rc.seal(&rk, &[7u8; 32], b"aad").unwrap();
        // attacker replays with their own key share: ECDH yields a different key
        assert!(verifier
            .open(&[7u8; 32], &session_id, &attacker.public_bytes(), b"aad")
            .is_err());
    }

    #[test]
    fn replay_detected() {
        let server = test_keypair();
        let verifier =
            RealityServer::new(server.clone(), vec![b"01234567".to_vec()], 300, 5);
        let (client, rk) = client_side(&server);
        let rc = RealityClient::new(client.clone(), b"01234567").unwrap();
        let session_id = rc.seal(&rk, &[7u8; 32], b"aad").unwrap();
        assert!(verifier
            .open(&[7u8; 32], &session_id, &client.public_bytes(), b"aad")
            .is_ok());
        assert!(matches!(
            verifier.open(&[7u8; 32], &session_id, &client.public_bytes(), b"aad"),
            Err(RealityError::Replay)
        ));
    }

    #[test]
    fn tampered_session_id_fails() {
        let server = test_keypair();
        let verifier =
            RealityServer::new(server.clone(), vec![b"01234567".to_vec()], 300, 5);
        let (client, rk) = client_side(&server);
        let rc = RealityClient::new(client.clone(), b"01234567").unwrap();
        let mut session_id = rc.seal(&rk, &[7u8; 32], b"aad").unwrap();
        session_id[0] ^= 0xff;
        assert!(verifier
            .open(&[7u8; 32], &session_id, &client.public_bytes(), b"aad")
            .is_err());
    }

    #[test]
    fn tampered_aad_fails() {
        let server = test_keypair();
        let verifier =
            RealityServer::new(server.clone(), vec![b"01234567".to_vec()], 300, 5);
        let (client, rk) = client_side(&server);
        let rc = RealityClient::new(client.clone(), b"01234567").unwrap();
        let session_id = rc.seal(&rk, &[7u8; 32], b"aad").unwrap();
        assert!(verifier
            .open(&[7u8; 32], &session_id, &client.public_bytes(), b"tampered")
            .is_err());
    }

    #[test]
    fn unknown_short_id_fails() {
        let server = test_keypair();
        let verifier =
            RealityServer::new(server.clone(), vec![b"01234567".to_vec()], 300, 5);
        let (client, rk) = client_side(&server);
        let rc = RealityClient::new(client.clone(), b"76543210").unwrap();
        let session_id = rc.seal(&rk, &[7u8; 32], b"aad").unwrap();
        assert!(verifier
            .open(&[7u8; 32], &session_id, &client.public_bytes(), b"aad")
            .is_err());
    }

    #[test]
    fn stale_timestamp_fails() {
        let server = test_keypair();
        let verifier =
            RealityServer::new(server.clone(), vec![b"01234567".to_vec()], 300, 5);
        let (client, rk) = client_side(&server);
        let sealing_key = derive_sealing_key(&rk, &[7u8; 32]);
        let header = RealityHeader::new(now_secs() - 10_000, b"01234567").unwrap();
        let nonce_bytes: [u8; NONCE_LEN] = [7u8; 32][20..32].try_into().unwrap();
        let key = UnboundKey::new(&AES_128_GCM, &sealing_key[..16]).unwrap();
        let mut in_out = header.to_bytes().to_vec();
        let tag = LessSafeKey::new(key)
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(b"aad"),
                &mut in_out,
            )
            .unwrap();
        let mut session_id = [0u8; 32];
        session_id[..16].copy_from_slice(&in_out);
        session_id[16..].copy_from_slice(tag.as_ref());
        assert!(matches!(
            verifier.open(&[7u8; 32], &session_id, &client.public_bytes(), b"aad"),
            Err(RealityError::TimestampOutOfWindow { .. })
        ));
    }

    #[test]
    fn multiple_short_ids_supported() {
        let server = test_keypair();
        let verifier = RealityServer::new(
            server.clone(),
            vec![b"aaaaaaaa".to_vec(), b"01234567".to_vec()],
            300,
            5,
        );
        let (client, rk) = client_side(&server);
        let rc = RealityClient::new(client.clone(), b"aaaaaaaa").unwrap();
        let session_id = rc.seal(&rk, &[7u8; 32], b"aad").unwrap();
        assert!(verifier
            .open(&[7u8; 32], &session_id, &client.public_bytes(), b"aad")
            .is_ok());
    }
}

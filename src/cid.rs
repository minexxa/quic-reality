//! Connection IDs that only this server can mint.
//!
//! quinn's built-in `HashedConnectionIdGenerator` uses a non-cryptographic hash
//! with a 40-bit check, which an on-path observer could invert after seeing a few
//! CIDs. Here a CID is `nonce(8) || HMAC-SHA256(key, nonce)[..8]`.
//!
//! Because the server can recognise its own CIDs statelessly, every post-handshake
//! packet (and every packet after a client address change) is classified without
//! a lookup table, while packets carrying an unknown CID are sent to the decoy.

use hmac::{Hmac, Mac};
use quinn::ConnectionIdGenerator;
use quinn_proto::InvalidCid;
use rand::RngCore;
use sha2::Sha256;
use std::sync::Arc;
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;

pub const CID_LEN: usize = 16;
const NONCE_LEN: usize = 8;

#[derive(Clone)]
pub struct HmacCid {
    key: Arc<[u8; 32]>,
}

impl HmacCid {
    #[cfg(test)]
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Self { key: Arc::new(key) }
    }

    /// CID key derived from a long-term secret, so connection IDs stay valid
    /// across server restarts (see `derive_keys`).
    pub fn from_key(key: [u8; 32]) -> Self {
        Self { key: Arc::new(key) }
    }

    fn tag(&self, nonce: &[u8]) -> HmacSha256 {
        let mut mac = HmacSha256::new_from_slice(&self.key[..]).expect("any key length");
        mac.update(nonce);
        mac
    }

    /// Constant-time check that `cid` was minted by this key.
    pub fn is_valid(&self, cid: &[u8]) -> bool {
        if cid.len() != CID_LEN {
            return false;
        }
        let (nonce, sig) = cid.split_at(NONCE_LEN);
        self.tag(nonce).verify_truncated_left(sig).is_ok()
    }
}

impl ConnectionIdGenerator for HmacCid {
    fn generate_cid(&mut self) -> quinn::ConnectionId {
        let mut cid = [0u8; CID_LEN];
        rand::thread_rng().fill_bytes(&mut cid[..NONCE_LEN]);
        let full = self.tag(&cid[..NONCE_LEN]).finalize().into_bytes();
        cid[NONCE_LEN..].copy_from_slice(&full[..CID_LEN - NONCE_LEN]);
        quinn::ConnectionId::new(&cid)
    }

    fn validate(&self, cid: &quinn::ConnectionId) -> Result<(), InvalidCid> {
        if self.is_valid(cid) {
            Ok(())
        } else {
            Err(InvalidCid)
        }
    }

    fn cid_len(&self) -> usize {
        CID_LEN
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}

/// Derives the CID-MAC key and the stateless-reset key from the server's
/// long-term private key.
///
/// Why: with random per-process keys a restarted server no longer recognises the
/// CIDs of connections that were open before the restart, so it forwards the
/// clients' packets to the decoy and the clients only notice after their idle
/// timeout.  With stable keys the restarted server accepts those packets (the
/// CID MAC still verifies), has no such connection, and answers with a
/// *stateless reset* whose token the client already holds, so the client drops
/// the dead connection and reconnects immediately.
pub fn derive_keys(server_private: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    use hkdf::Hkdf;
    let hk = Hkdf::<Sha256>::new(Some(b"quic-reality persistent keys v1"), server_private);
    let mut cid = [0u8; 32];
    let mut reset = [0u8; 32];
    hk.expand(b"cid mac key", &mut cid).expect("32 bytes");
    hk.expand(b"stateless reset key", &mut reset).expect("32 bytes");
    (cid, reset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_keys_are_stable_distinct_and_secret_dependent() {
        let (c1, r1) = derive_keys(&[1u8; 32]);
        let (c2, r2) = derive_keys(&[1u8; 32]);
        let (c3, _) = derive_keys(&[2u8; 32]);
        assert_eq!((c1, r1), (c2, r2));
        assert_ne!(c1, r1);
        assert_ne!(c1, c3);
        // a CID minted before a "restart" still validates after it
        let mut before = HmacCid::from_key(c1);
        let cid = before.generate_cid();
        assert!(HmacCid::from_key(c2).is_valid(&cid));
    }

    #[test]
    fn minted_cids_validate_and_foreign_ones_do_not() {
        let mut g = HmacCid::new();
        let cid = g.generate_cid();
        assert!(g.is_valid(&cid));
        let other = HmacCid::new();
        assert!(!other.is_valid(&cid));
        let mut bad = cid.to_vec();
        bad[15] ^= 1;
        assert!(!g.is_valid(&bad));
        assert!(!g.is_valid(&bad[..8]));
    }
}

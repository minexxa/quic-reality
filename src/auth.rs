//! REALITY-style authentication primitives.
//!
//! Where the proof lives
//! ---------------------
//! The proof is carried inside the TLS ClientHello that quinn/rustls put in the
//! first QUIC Initial packet, so the server can decide *before* any QUIC state is
//! created whether a datagram comes from a legitimate client or from a prober:
//!
//! * the ClientHello `key_share` is the client's ephemeral X25519 key `E`;
//! * `K = X25519(e, S)` where `S` is the server's static public key
//!   (only the client and the server can compute it);
//! * the ClientHello `random` (32 bytes) is an AES-256-GCM ciphertext+tag of
//!   `version | reserved | timestamp | short_id`, keyed from `K`, with the
//!   `key_share` and SNI as associated data. It is indistinguishable from random.
//!
//! The server proves it also knows `K` by signing its throw-away Ed25519
//! certificate with `HMAC-SHA512(auth_key, cert_public_key)` (Xray's trick), which
//! the client checks instead of trusting any CA. Unlike the previous version of
//! this project, the server private key is really required to authenticate, the
//! client really authenticates the server, and replays are detected upstream.

use anyhow::{anyhow, bail, Context, Result};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use sha2::{Sha256, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

pub const PROTO_VERSION: u8 = 1;
pub const SHORT_ID_LEN: usize = 8;
const HKDF_INFO: &[u8] = b"quic-reality v1";
const AAD_LABEL: &[u8] = b"qr1";

#[derive(Clone)]
pub struct KeyPair {
    pub private: StaticSecret,
    pub public: PublicKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let private = StaticSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&private);
        Self { private, public }
    }

    pub fn from_private_hex(hex_str: &str) -> Result<Self> {
        let arr = decode_hex32(hex_str).context("invalid private key")?;
        let private = StaticSecret::from(arr);
        let public = PublicKey::from(&private);
        Ok(Self { private, public })
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.public.as_bytes())
    }

    pub fn private_hex(&self) -> String {
        hex::encode(self.private.to_bytes())
    }
}

pub fn decode_hex32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s.trim()).context("not valid hex")?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| anyhow!("expected 32 bytes (64 hex chars)"))
}

/// Parse a short id: 0..=16 hex chars, left aligned and zero padded to 8 bytes.
pub fn parse_short_id(s: &str) -> Result<[u8; SHORT_ID_LEN]> {
    let s = s.trim();
    if s.len() > SHORT_ID_LEN * 2 || !s.len().is_multiple_of(2) {
        bail!("short_id must be an even number of hex chars, at most 16");
    }
    let bytes = hex::decode(s).context("short_id is not valid hex")?;
    let mut out = [0u8; SHORT_ID_LEN];
    out[..bytes.len()].copy_from_slice(&bytes);
    Ok(out)
}

struct SessionKeys {
    seal_key: [u8; 32],
    nonce: [u8; 12],
    auth_key: [u8; 32],
}

fn derive(dh: &[u8; 32], eph_pub: &[u8; 32]) -> SessionKeys {
    // salt = ephemeral public key: binds every derived value to this connection.
    let hk = Hkdf::<Sha256>::new(Some(eph_pub), dh);
    let mut okm = [0u8; 32 + 12 + 32];
    hk.expand(HKDF_INFO, &mut okm).expect("hkdf length is valid");
    let mut k = SessionKeys {
        seal_key: [0; 32],
        nonce: [0; 12],
        auth_key: [0; 32],
    };
    k.seal_key.copy_from_slice(&okm[..32]);
    k.nonce.copy_from_slice(&okm[32..44]);
    k.auth_key.copy_from_slice(&okm[44..]);
    k
}

fn aad(eph_pub: &[u8; 32], sni: &str) -> Vec<u8> {
    let mut a = Vec::with_capacity(AAD_LABEL.len() + 32 + sni.len());
    a.extend_from_slice(AAD_LABEL);
    a.extend_from_slice(eph_pub);
    a.extend_from_slice(sni.to_ascii_lowercase().as_bytes());
    a
}

fn aead_key(k: &[u8; 32]) -> Result<LessSafeKey> {
    Ok(LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, k).map_err(|_| anyhow!("bad aead key"))?,
    ))
}

/// Everything the client needs to build one authenticated ClientHello.
pub struct ClientMaterial {
    pub secret: StaticSecret,
    pub public: [u8; 32],
    /// Value to place in the ClientHello `random` field.
    pub random: [u8; 32],
    /// Used to verify the server's temporary certificate.
    pub auth_key: [u8; 32],
}

pub fn build_client_material(
    server_pub: &PublicKey,
    short_id: &[u8; SHORT_ID_LEN],
    sni: &str,
    now_secs: u64,
) -> Result<ClientMaterial> {
    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let public = *PublicKey::from(&secret).as_bytes();
    let shared = secret.diffie_hellman(server_pub);
    if !shared.was_contributory() {
        bail!("server public key is a low-order point");
    }
    let keys = derive(shared.as_bytes(), &public);

    let mut plain = [0u8; 16];
    plain[0] = PROTO_VERSION;
    plain[4..8].copy_from_slice(&(now_secs as u32).to_be_bytes());
    plain[8..16].copy_from_slice(short_id);

    let mut buf = plain.to_vec();
    aead_key(&keys.seal_key)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(keys.nonce),
            Aad::from(aad(&public, sni)),
            &mut buf,
        )
        .map_err(|_| anyhow!("seal failed"))?;
    let random = <[u8; 32]>::try_from(buf.as_slice()).map_err(|_| anyhow!("unexpected length"))?;

    Ok(ClientMaterial {
        secret,
        public,
        random,
        auth_key: keys.auth_key,
    })
}

/// Successful server-side verification of a ClientHello.
#[derive(Clone)]
pub struct Verified {
    pub auth_key: [u8; 32],
}

pub fn verify_client_hello(
    server_secret: &StaticSecret,
    short_ids: &[[u8; SHORT_ID_LEN]],
    max_skew_secs: u64,
    random: &[u8; 32],
    eph_pub: &[u8; 32],
    sni: &str,
    now_secs: u64,
) -> Result<Verified> {
    let shared = server_secret.diffie_hellman(&PublicKey::from(*eph_pub));
    if !shared.was_contributory() {
        bail!("low-order client key");
    }
    let keys = derive(shared.as_bytes(), eph_pub);

    let mut buf = random.to_vec();
    let plain = aead_key(&keys.seal_key)?
        .open_in_place(
            Nonce::assume_unique_for_key(keys.nonce),
            Aad::from(aad(eph_pub, sni)),
            &mut buf,
        )
        .map_err(|_| anyhow!("AEAD open failed"))?;
    if plain.len() != 16 {
        bail!("unexpected plaintext length");
    }
    if plain[0] != PROTO_VERSION || plain[1..4] != [0, 0, 0] {
        bail!("unsupported version");
    }
    let ts = u32::from_be_bytes([plain[4], plain[5], plain[6], plain[7]]) as u64;
    if now_secs.abs_diff(ts) > max_skew_secs {
        bail!("timestamp outside allowed window");
    }
    // Constant time over the whole list, no early exit.
    let mut ok = false;
    for sid in short_ids {
        ok |= bool::from(subtle::ConstantTimeEq::ct_eq(&sid[..], &plain[8..16]));
    }
    if !ok {
        bail!("unknown short_id");
    }
    Ok(Verified {
        auth_key: keys.auth_key,
    })
}

type HmacSha512 = Hmac<Sha512>;

/// 64-byte value placed in the X.509 signature field of the temporary certificate.
pub fn cert_signature(auth_key: &[u8; 32], ed25519_pub: &[u8; 32]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(auth_key).expect("hmac accepts any key length");
    mac.update(ed25519_pub);
    let out = mac.finalize().into_bytes();
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&out);
    sig
}

pub fn verify_cert_signature(auth_key: &[u8; 32], ed25519_pub: &[u8; 32], sig: &[u8]) -> bool {
    let mut mac = HmacSha512::new_from_slice(auth_key).expect("hmac accepts any key length");
    mac.update(ed25519_pub);
    mac.verify_slice(sig).is_ok()
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (KeyPair, [u8; 8]) {
        (KeyPair::generate(), parse_short_id("0123456789abcdef").unwrap())
    }

    #[test]
    fn roundtrip_and_shared_auth_key() {
        let (kp, sid) = setup();
        let now = 1_700_000_000;
        let m = build_client_material(&kp.public, &sid, "www.example.com", now).unwrap();
        let v = verify_client_hello(&kp.private, &[sid], 60, &m.random, &m.public, "www.example.com", now + 5)
            .unwrap();
        assert_eq!(v.auth_key, m.auth_key);
    }

    #[test]
    fn rejects_wrong_server_key() {
        let (kp, sid) = setup();
        let other = KeyPair::generate();
        let m = build_client_material(&kp.public, &sid, "a.example", 1000).unwrap();
        assert!(verify_client_hello(&other.private, &[sid], 60, &m.random, &m.public, "a.example", 1000).is_err());
    }

    #[test]
    fn the_public_key_alone_is_not_enough_to_forge() {
        // The attacker knows the server public key but not the short id.
        let (kp, sid) = setup();
        let bad = parse_short_id("ffffffffffffffff").unwrap();
        let m = build_client_material(&kp.public, &bad, "a.example", 1000).unwrap();
        assert!(verify_client_hello(&kp.private, &[sid], 60, &m.random, &m.public, "a.example", 1000).is_err());
    }

    #[test]
    fn rejects_stale_timestamp_wrong_sni_and_tampering() {
        let (kp, sid) = setup();
        let m = build_client_material(&kp.public, &sid, "a.example", 1000).unwrap();
        assert!(verify_client_hello(&kp.private, &[sid], 60, &m.random, &m.public, "a.example", 2000).is_err());
        assert!(verify_client_hello(&kp.private, &[sid], 60, &m.random, &m.public, "b.example", 1000).is_err());
        let mut r = m.random;
        r[0] ^= 1;
        assert!(verify_client_hello(&kp.private, &[sid], 60, &r, &m.public, "a.example", 1000).is_err());
        let mut e = m.public;
        e[0] ^= 1;
        assert!(verify_client_hello(&kp.private, &[sid], 60, &m.random, &e, "a.example", 1000).is_err());
    }

    #[test]
    fn random_differs_each_time() {
        let (kp, sid) = setup();
        let a = build_client_material(&kp.public, &sid, "a.example", 1000).unwrap();
        let b = build_client_material(&kp.public, &sid, "a.example", 1000).unwrap();
        assert_ne!(a.random, b.random);
    }

    #[test]
    fn cert_signature_needs_the_auth_key() {
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        let pubk = [9u8; 32];
        let sig = cert_signature(&k1, &pubk);
        assert!(verify_cert_signature(&k1, &pubk, &sig));
        assert!(!verify_cert_signature(&k2, &pubk, &sig));
        assert!(!verify_cert_signature(&k1, &[8u8; 32], &sig));
    }

    #[test]
    fn short_id_parsing() {
        assert_eq!(parse_short_id("").unwrap(), [0u8; 8]);
        assert_eq!(parse_short_id("ab").unwrap()[0], 0xab);
        assert!(parse_short_id("abc").is_err());
        assert!(parse_short_id("00112233445566778899").is_err());
    }
}

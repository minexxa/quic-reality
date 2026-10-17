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
//!   `version | reserved | timestamp | short_id`, keyed from `K`. The whole
//!   ClientHello is the associated data - with the `random` field itself zeroed
//!   while the tag is computed, because the ciphertext is what sits there (the
//!   same chicken-and-egg trick xtls/reality uses for `session_id`). Every
//!   byte of the hello - cipher suites, extensions, GREASE, the SNI, the very
//!   key share - is therefore authenticated, and the ciphertext is
//!   indistinguishable from random.
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

/// TLS handshake message type of a ClientHello.
const HS_CLIENT_HELLO: u8 = 0x01;

/// Offset of the `random` field inside a ClientHello handshake message:
/// the handshake header (4 bytes) plus `legacy_version` (2 bytes).
pub const HELLO_RANDOM_OFFSET: usize = 6;

/// A copy of `hello` with the `random` field zeroed: the associated data both
/// sides use while computing the AEAD tag. The proof rides in `random`, so it
/// cannot authenticate itself; everything else in the hello can and does.
pub fn hello_with_zeroed_random(hello: &[u8]) -> Option<Vec<u8>> {
    let end = HELLO_RANDOM_OFFSET + 32;
    if hello.len() < end || hello[0] != HS_CLIENT_HELLO {
        return None;
    }
    let mut h = hello.to_vec();
    h[HELLO_RANDOM_OFFSET..end].fill(0);
    Some(h)
}

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

fn aead_key(k: &[u8; 32]) -> Result<LessSafeKey> {
    Ok(LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, k).map_err(|_| anyhow!("bad aead key"))?,
    ))
}

/// Client side, phase one: the ephemeral X25519 key pair and everything derived
/// from it. Cheap, and independent of the ClientHello that is about to be
/// built - the proof is sealed afterwards, against the finished hello.
pub struct ClientMaterial {
    pub secret: StaticSecret,
    pub public: [u8; 32],
    /// Sealed into the proof at phase two.
    short_id: [u8; SHORT_ID_LEN],
    now_secs: u64,
    keys: SessionKeys,
}

impl ClientMaterial {
    /// The key the server proves possession of by signing its temporary
    /// certificate with `HMAC-SHA512(auth_key, cert_public_key)`.
    pub fn auth_key(&self) -> [u8; 32] {
        self.keys.auth_key
    }

    /// Client side, phase two: seal the proof for a ClientHello that already
    /// carries `public` in its key_share and an all-zero `random`. The AAD is
    /// the entire hello, so tampering with any byte of it - the cipher suites,
    /// the extensions, the SNI, the key share - invalidates the proof.
    pub fn seal_proof(&self, hello: &[u8]) -> Result<[u8; 32]> {
        let end = HELLO_RANDOM_OFFSET + 32;
        if hello.len() < end || hello[0] != HS_CLIENT_HELLO {
            bail!("not a ClientHello");
        }
        if hello[HELLO_RANDOM_OFFSET..end].iter().any(|&b| b != 0) {
            bail!("the random field must be zero while the proof is sealed");
        }
        let mut plain = [0u8; 16];
        plain[0] = PROTO_VERSION;
        plain[4..8].copy_from_slice(&(self.now_secs as u32).to_be_bytes());
        plain[8..16].copy_from_slice(&self.short_id);

        let mut buf = plain.to_vec();
        aead_key(&self.keys.seal_key)?
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(self.keys.nonce),
                Aad::from(hello),
                &mut buf,
            )
            .map_err(|_| anyhow!("seal failed"))?;
        <[u8; 32]>::try_from(buf.as_slice()).map_err(|_| anyhow!("unexpected length"))
    }
}

/// Phase one of the client handshake: generate the ephemeral key pair.
pub fn client_material(
    server_pub: &PublicKey,
    short_id: &[u8; SHORT_ID_LEN],
    now_secs: u64,
) -> Result<ClientMaterial> {
    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let public = *PublicKey::from(&secret).as_bytes();
    let shared = secret.diffie_hellman(server_pub);
    if !shared.was_contributory() {
        bail!("server public key is a low-order point");
    }
    Ok(ClientMaterial {
        secret,
        public,
        short_id: *short_id,
        now_secs,
        keys: derive(shared.as_bytes(), &public),
    })
}

/// Successful server-side verification of a ClientHello.
#[derive(Clone)]
pub struct Verified {
    pub auth_key: [u8; 32],
}

/// Server side: open the proof in `random` and check it against `hello`, the
/// complete ClientHello it arrived in (its `random` field is zeroed internally).
pub fn verify_client_hello(
    server_secret: &StaticSecret,
    short_ids: &[[u8; SHORT_ID_LEN]],
    max_skew_secs: u64,
    random: &[u8; 32],
    eph_pub: &[u8; 32],
    hello: &[u8],
    now_secs: u64,
) -> Result<Verified> {
    let shared = server_secret.diffie_hellman(&PublicKey::from(*eph_pub));
    if !shared.was_contributory() {
        bail!("low-order client key");
    }
    let keys = derive(shared.as_bytes(), eph_pub);

    let aad = hello_with_zeroed_random(hello).ok_or_else(|| anyhow!("malformed ClientHello"))?;
    let mut buf = random.to_vec();
    let plain = aead_key(&keys.seal_key)?
        .open_in_place(
            Nonce::assume_unique_for_key(keys.nonce),
            Aad::from(aad),
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

    const PARAMS: &[u8] = &[0x01, 0x01, 0x05];

    /// A Chrome hello for `m` with the proof sealed in: exactly the bytes a
    /// client would put on the wire.
    fn wire(m: &ClientMaterial, sni: &str) -> (Vec<u8>, [u8; 32]) {
        let mut hello =
            crate::chrome_tls::build_client_hello(sni, &[0u8; 32], &m.public, PARAMS);
        let random = m.seal_proof(&hello).unwrap();
        hello[HELLO_RANDOM_OFFSET..HELLO_RANDOM_OFFSET + 32].copy_from_slice(&random);
        (hello, random)
    }

    #[test]
    fn roundtrip_and_shared_auth_key() {
        let (kp, sid) = setup();
        let now = 1_700_000_000;
        let m = client_material(&kp.public, &sid, now).unwrap();
        let (hello, random) = wire(&m, "www.example.com");
        let v = verify_client_hello(&kp.private, &[sid], 60, &random, &m.public, &hello, now + 5)
            .unwrap();
        assert_eq!(v.auth_key, m.auth_key());
    }

    #[test]
    fn rejects_wrong_server_key() {
        let (kp, sid) = setup();
        let other = KeyPair::generate();
        let m = client_material(&kp.public, &sid, 1000).unwrap();
        let (hello, random) = wire(&m, "a.example");
        assert!(verify_client_hello(&other.private, &[sid], 60, &random, &m.public, &hello, 1000).is_err());
    }

    #[test]
    fn the_public_key_alone_is_not_enough_to_forge() {
        // The attacker knows the server public key but not the short id.
        let (kp, sid) = setup();
        let bad = parse_short_id("ffffffffffffffff").unwrap();
        let m = client_material(&kp.public, &bad, 1000).unwrap();
        let (hello, random) = wire(&m, "a.example");
        assert!(verify_client_hello(&kp.private, &[sid], 60, &random, &m.public, &hello, 1000).is_err());
    }

    #[test]
    fn rejects_stale_timestamp_wrong_sni_and_tampering() {
        let (kp, sid) = setup();
        let now = 1_700_000_000;
        let m = client_material(&kp.public, &sid, now).unwrap();
        let (hello, random) = wire(&m, "a.example");
        assert!(verify_client_hello(&kp.private, &[sid], 60, &random, &m.public, &hello, now + 1000).is_err());
        // The same proof presented with a hello built for a different SNI:
        // the AAD no longer matches.
        let (other, _) = wire(&m, "b.example");
        assert!(verify_client_hello(&kp.private, &[sid], 60, &random, &m.public, &other, now).is_err());
        let mut r = random;
        r[0] ^= 1;
        assert!(verify_client_hello(&kp.private, &[sid], 60, &r, &m.public, &hello, now).is_err());
        let mut e = m.public;
        e[0] ^= 1;
        assert!(verify_client_hello(&kp.private, &[sid], 60, &random, &e, &hello, now).is_err());
    }

    #[test]
    fn every_hello_byte_outside_random_is_authenticated() {
        let (kp, sid) = setup();
        let now = 1_700_000_000;
        let m = client_material(&kp.public, &sid, now).unwrap();
        let (hello, random) = wire(&m, "www.example.com");
        let end = HELLO_RANDOM_OFFSET + 32;
        for i in (0..hello.len()).filter(|i| !(*i >= HELLO_RANDOM_OFFSET && *i < end)) {
            let mut bad = hello.clone();
            bad[i] ^= 0x01;
            assert!(
                verify_client_hello(&kp.private, &[sid], 60, &random, &m.public, &bad, now)
                    .is_err(),
                "hello byte {i} is not covered by the AEAD tag"
            );
        }
    }

    #[test]
    fn sealing_requires_a_zeroed_random() {
        let (kp, sid) = setup();
        let m = client_material(&kp.public, &sid, 1000).unwrap();
        let mut hello =
            crate::chrome_tls::build_client_hello("a.example", &[0u8; 32], &m.public, PARAMS);
        hello[HELLO_RANDOM_OFFSET] = 1;
        assert!(m.seal_proof(&hello).is_err());
        assert!(m.seal_proof(&hello[..40]).is_err());
    }

    #[test]
    fn random_differs_each_time() {
        let (kp, sid) = setup();
        let a = client_material(&kp.public, &sid, 1000).unwrap();
        let b = client_material(&kp.public, &sid, 1000).unwrap();
        let (_, ra) = wire(&a, "a.example");
        let (_, rb) = wire(&b, "a.example");
        assert_ne!(ra, rb);
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

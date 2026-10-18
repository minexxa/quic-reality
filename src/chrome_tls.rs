//! Chrome-fingerprint TLS 1.3 client for QUIC.
//!
//! # Why this module exists
//!
//! REALITY is a wire-format trick: the client hides its authentication proof in
//! the ClientHello `random` field, and the server answers with a throw-away
//! Ed25519 certificate whose X.509 signature slot carries
//! `HMAC-SHA512(auth_key, cert_public_key)`.  Whatever classifies the
//! connection - a prober, a DPI box, a fingerprinting service - looks at those
//! bytes, so the hello has to look like a browser's.
//!
//! rustls cannot produce that.  It always emits its own extension set, its own
//! order, no GREASE and two key shares, and the bytes cannot be rewritten
//! afterwards either, because TLS 1.3 binds its Finished messages to a
//! transcript hash of the handshake that was actually exchanged.  So the
//! client side of the handshake is implemented here and plugged into quinn
//! through its `crypto::ClientConfig` / `crypto::Session` extension points;
//! quinn keeps ownership of transport state, packet numbers and packet
//! protection.
//!
//! Only what QUIC needs from TLS is implemented: the TLS 1.3 key schedule
//! (RFC 8446 §7, with the QUIC labels from RFC 9001 §7.1), server
//! authentication and the Finished exchange.  The server side keeps using
//! rustls - it only ever receives, and its handshake does not have to
//! impersonate anybody - so this change is confined to the client.
//!
//! # How it plugs into quinn
//!
//! QUIC does not use the TLS record layer: handshake messages ride in CRYPTO
//! frames and quinn hands them to us as plain bytes.  We answer with the bytes
//! for the next CRYPTO frame plus the packet-protection keys of the level they
//! belong to.  quinn calls `write_handshake` right after `read_handshake` (and
//! whenever it has to retransmit), which is exactly what drives the key
//! switch: bytes returned together with a key change are still sent at the
//! *previous* level, so the client's Finished goes out under Handshake keys.

use crate::auth::{ClientMaterial, HELLO_RANDOM_OFFSET};
use crate::cert;
use bytes::BytesMut;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use quinn::crypto::{
    ClientConfig as CryptoClientConfig, CryptoError, ExportKeyingMaterialError, HeaderKey, KeyPair,
    Keys, PacketKey, Session as QuicSessionTrait,
};
use quinn::{ConnectError, ConnectionId, Side, TransportErrorCode};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::TransportError;
use rand::RngCore;
use ring::aead::quic::{
    Algorithm as HpAlgorithm, HeaderProtectionKey, AES_128 as HP_AES_128, AES_256 as HP_AES_256,
    CHACHA20 as HP_CHACHA20,
};
use ring::aead::{
    Aad, Algorithm as AeadAlgorithm, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM,
    CHACHA20_POLY1305,
};
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256, Sha384};
use std::collections::VecDeque;
use std::io::Cursor;
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;
use tracing::debug;
use x25519_dalek::{PublicKey, StaticSecret};

// ------------------------------------------------------------- handshake wires

const HS_CLIENT_HELLO: u8 = 0x01;
const HS_SERVER_HELLO: u8 = 0x02;
const HS_SESSION_TICKET: u8 = 0x04;
const HS_ENCRYPTED_EXTENSIONS: u8 = 0x08;
const HS_CERTIFICATE: u8 = 0x0b;
const HS_CERTIFICATE_VERIFY: u8 = 0x0f;
const HS_FINISHED: u8 = 0x14;
const HS_KEY_UPDATE: u8 = 0x18;

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_STATUS_REQUEST: u16 = 0x0005;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SCT: u16 = 0x0012;
const EXT_PADDING: u16 = 0x0015;
const EXT_COMPRESS_CERTIFICATE: u16 = 0x001b;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_PSK_MODES: u16 = 0x002d;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_QUIC_TP: u16 = 0x0039;
const EXT_APPLICATION_SETTINGS: u16 = 0x4469;
const EXT_ECH: u16 = 0xfe0d;

const GROUP_X25519: u16 = 0x001d;
const SIG_ED25519: u16 = 0x0807;
const VERSION_TLS13: u16 = 0x0304;
const VERSION_LEGACY: u16 = 0x0303;

/// RFC 8446 §6.2 alert numbers surfaced as QUIC crypto errors.
const ALERT_DECRYPT_ERROR: u8 = 0x33;
const ALERT_ILLEGAL_PARAMETER: u8 = 0x2f;

/// RFC 8701 reserved values. Chrome picks one at random for each GREASE slot.
const GREASE: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// Cipher suites offered in the QUIC ClientHello: the three TLS 1.3 suites in
/// BoringSSL's order.  RFC 9001 §4.2 forbids a QUIC client from offering
/// anything older than TLS 1.3, so the TLS 1.2 / CBC / RSA suites a browser puts
/// in its *TCP* hello are deliberately absent: a QUIC Initial that offers them
/// matches no real QUIC client.  A TLS 1.3 server picks the first one it also
/// supports, i.e. `0x1301`.
const CHROME_CIPHER_SUITES: [u16; 3] = [
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1302, // TLS_AES_256_GCM_SHA384
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
];

/// Signature algorithms Chrome offers.
const CHROME_SIGNATURE_ALGORITHMS: [u16; 8] = [
    0x0403, // ecdsa_secp256r1_sha256
    0x0804, // rsa_pss_rsae_sha256
    0x0401, // rsa_pkcs1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0805, // rsa_pss_rsae_sha384
    0x0501, // rsa_pkcs1_sha384
    0x0806, // rsa_pss_rsae_sha512
    0x0601, // rsa_pkcs1_sha512
];

/// RFC 9001 §5.2: the Initial salt of QUIC version 1.
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
    0xad, 0xcc, 0xbb, 0x7f, 0x0a,
];

/// RFC 8446 §4.1.3: the well-known random a HelloRetryRequest carries.
const HELLO_RETRY_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// RFC 9001 §5.8: the Retry integrity key and nonce of QUIC version 1.
const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_INTEGRITY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

/// Chrome keeps the ClientHello at a fixed size: padded back up to `PAD_TO`
/// so the length alone leaks nothing about the SNI or the ALPN.
const PAD_TO: usize = 512;

/// TLS 1.3 server CertificateVerify context string.
const SERVER_CV_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";

/// The only ALPN a REALITY QUIC connection ever offers.
const ALPN_H3: &[u8] = b"h3";

/// A TLS handshake message is at most 2^24-1 bytes, and REALITY's flights are a
/// few hundred.  Refusing anything bigger keeps a hostile peer from making us
/// buffer unbounded data before we have authenticated it.
const MAX_HANDSHAKE_MESSAGE: usize = 0x10_000;

// ---------------------------------------------------------------- wire helpers

fn push_u16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_be_bytes());
}

/// Handshake messages carry their length as a u24; TLS has no u24 type.
fn push_u24(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_be_bytes()[1..4]);
}

fn push_ext(v: &mut Vec<u8>, ty: u16, data: &[u8]) {
    push_u16(v, ty);
    push_u16(v, data.len() as u16);
    v.extend_from_slice(data);
}

/// `opaque x<0..2^16-1>`
fn len16(data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + data.len());
    push_u16(&mut v, data.len() as u16);
    v.extend_from_slice(data);
    v
}

/// Assemble one handshake message (type + u24 length + body).
fn handshake_msg(ty: u8, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + body.len());
    v.push(ty);
    push_u24(&mut v, body.len() as u32);
    v.extend_from_slice(body);
    v
}

/// Bounds-checked cursor over a handshake message body.
struct Reader<'a> {
    d: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    fn new(d: &'a [u8]) -> Self {
        Self { d, p: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], TlsErr> {
        let end = self
            .p
            .checked_add(n)
            .filter(|e| *e <= self.d.len())
            .ok_or(TlsErr::Bad("truncated handshake message"))?;
        let s = &self.d[self.p..end];
        self.p = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, TlsErr> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, TlsErr> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn vec8(&mut self) -> Result<&'a [u8], TlsErr> {
        let n = self.u8()? as usize;
        self.take(n)
    }

    fn vec16(&mut self) -> Result<&'a [u8], TlsErr> {
        let n = self.u16()? as usize;
        self.take(n)
    }

    fn vec24(&mut self) -> Result<&'a [u8], TlsErr> {
        let b = self.take(3)?;
        let n = ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize;
        self.take(n)
    }

    fn done(&self) -> bool {
        self.p >= self.d.len()
    }
}

/// Everything that can go wrong in here, mapped onto a QUIC transport error.
#[derive(Debug)]
enum TlsErr {
    /// The peer broke the protocol.
    Bad(&'static str),
    /// A TLS alert worth surfacing to the peer.
    Alert(u8),
    /// Our own key material was unusable - unreachable, but panic-free.
    Internal(&'static str),
}

impl TlsErr {
    const fn bad(what: &'static str) -> Self {
        Self::Bad(what)
    }

    const fn internal(what: &'static str) -> Self {
        Self::Internal(what)
    }

    fn transport(self) -> TransportError {
        let (code, reason) = match self {
            Self::Bad(what) => (TransportErrorCode::PROTOCOL_VIOLATION, what),
            Self::Internal(what) => (TransportErrorCode::INTERNAL_ERROR, what),
            Self::Alert(a) => (TransportErrorCode::crypto(a), "tls alert"),
        };
        debug!("REALITY/TLS: {reason}");
        TransportError {
            code,
            frame: None,
            reason: reason.into(),
        }
    }
}

// ------------------------------------------------------------- hashes and HKDF

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum HashAlg {
    Sha256,
    Sha384,
}

impl HashAlg {
    const fn len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
        }
    }

    fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => {
                let mut m = Hmac::<Sha256>::new_from_slice(key)
                    .expect("hmac accepts a key of any length");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
            Self::Sha384 => {
                let mut m = Hmac::<Sha384>::new_from_slice(key)
                    .expect("hmac accepts a key of any length");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
        }
    }

    /// RFC 5869 HKDF-Extract.
    fn extract(self, salt: &[u8], ikm: &[u8]) -> Prk {
        match self {
            Self::Sha256 => {
                let (_, hkdf) = Hkdf::<Sha256>::extract(Some(salt), ikm);
                Prk::new(self, HkdfInner::Sha256(hkdf))
            }
            Self::Sha384 => {
                let (_, hkdf) = Hkdf::<Sha384>::extract(Some(salt), ikm);
                Prk::new(self, HkdfInner::Sha384(hkdf))
            }
        }
    }

    /// Treat `secret` as an already-extracted pseudorandom key.
    fn prk(self, secret: &[u8]) -> Result<Prk, TlsErr> {
        match self {
            Self::Sha256 => Hkdf::<Sha256>::from_prk(secret)
            .map(|h| Prk::new(self, HkdfInner::Sha256(h)))
            .map_err(|_| TlsErr::internal("secret has the wrong length")),
            Self::Sha384 => Hkdf::<Sha384>::from_prk(secret)
            .map(|h| Prk::new(self, HkdfInner::Sha384(h)))
            .map_err(|_| TlsErr::internal("secret has the wrong length")),
        }
    }
}

#[derive(Clone)]
enum HkdfInner {
    Sha256(Hkdf<Sha256>),
    Sha384(Hkdf<Sha384>),
}

/// An HKDF-Extract output: the hash it belongs to plus a ready expander.
#[derive(Clone)]
struct Prk {
    alg: HashAlg,
    inner: HkdfInner,
}

impl Prk {
    fn new(alg: HashAlg, inner: HkdfInner) -> Self {
        Self { alg, inner }
    }

    /// `HKDF-Expand-Label` (RFC 8446 §7.1):
    /// `struct { uint16 length; opaque label<7..249>; opaque context<0..255>; }`
    fn expand_label(&self, label: &[u8], context: &[u8], len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
        info.extend_from_slice(&(len as u16).to_be_bytes());
        info.push((b"tls13 ".len() + label.len()) as u8);
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(label);
        info.push(context.len() as u8);
        info.extend_from_slice(context);

        let res = match &self.inner {
            HkdfInner::Sha256(h) => h.expand(&info, &mut out),
            HkdfInner::Sha384(h) => h.expand(&info, &mut out),
        };
        res.expect("hkdf output length is within bounds");
        out
    }

    /// `Derive-Secret(Secret, Label, Messages)`:
    /// `HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)`.
    fn derive(&self, label: &[u8], transcript: &[u8]) -> Vec<u8> {
        let h = self.alg.digest(transcript);
        self.expand_label(label, &h, self.alg.len())
    }
}

// ---------------------------------------------------------------- cipher suites

/// One TLS 1.3 cipher suite this client can speak.
struct Suite {
    id: u16,
    alg: HashAlg,
    aead: &'static AeadAlgorithm,
    hp: &'static HpAlgorithm,
}

static SUITES: [Suite; 3] = [
    Suite {
        id: 0x1301,
        alg: HashAlg::Sha256,
        aead: &AES_128_GCM,
        hp: &HP_AES_128,
    },
    Suite {
        id: 0x1302,
        alg: HashAlg::Sha384,
        aead: &AES_256_GCM,
        hp: &HP_AES_256,
    },
    Suite {
        id: 0x1303,
        alg: HashAlg::Sha256,
        aead: &CHACHA20_POLY1305,
        hp: &HP_CHACHA20,
    },
];

#[cfg(test)]
thread_local! {
    /// Test hook: the TLS 1.3 suite the last handshake on this thread negotiated.
    pub static LAST_NEGOTIATED: std::cell::Cell<u16> = const { std::cell::Cell::new(0) };
    /// Test hook: DER length of the last certificate this client accepted.
    pub static LAST_CERT_DER_LEN: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Test hook: NewSessionTicket messages received by the last handshake.
    pub static LAST_NST_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Test hook: the *lengths* of those NewSessionTicket messages, in order.
    /// Dest mimicry replays the dest's exact ticket sizes, so the lengths are
    /// as much of the contract as the count.
    pub static LAST_NST_LENS: std::cell::RefCell<Vec<usize>> = const { std::cell::RefCell::new(Vec::new()) };
    /// Test hook: the server's transport parameters as an *authenticated*
    /// client received them, restricted to the fields dest mimicry covers.
    /// Background probe sessions must not pollute it (same race as
    /// `LAST_NST_COUNT`).
    pub static LAST_PEER_TP: std::cell::RefCell<Option<crate::mimic::DestTransportParams>> =
        const { std::cell::RefCell::new(None) };
}

fn suite_by_id(id: u16) -> Result<&'static Suite, TlsErr> {
    SUITES
        .iter()
        .find(|s| s.id == id)
        .ok_or(TlsErr::Bad("server chose a cipher suite we did not offer"))
}

// ----------------------------------------------------- QUIC packet protection

/// QUIC header protection (RFC 9001 §5.4).
///
/// `ring` exposes only `new_mask`, so the first-byte and packet-number
/// masking follows "Header Protection Application" (RFC 9001 §5.4.1) - the same
/// code path quinn's rustls backend uses.
struct HpKey {
    key: HeaderProtectionKey,
}

impl HpKey {
    fn new(suite: &'static Suite, secret: &[u8]) -> Result<Self, TlsErr> {
        let alg = suite.alg;
        let material = alg
            .prk(secret)?
            .expand_label(b"quic hp", &[], suite.aead.key_len());
        let key = HeaderProtectionKey::new(suite.hp, &material)
            .map_err(|_| TlsErr::internal("header protection key"))?;
        Ok(Self { key })
    }

    /// RFC 9001 §5.4.1 header protection sample: the ciphertext starting four
    /// bytes past the packet number.
    fn mask_at(&self, pn_offset: usize, packet: &[u8]) -> Option<[u8; 5]> {
        let sample_len = self.sample_size();
        let sample = packet.get(pn_offset + 4..pn_offset + 4 + sample_len)?;
        self.key.new_mask(sample).ok()
    }

    /// Bits of the first byte the mask covers: the low 4 for long headers,
    /// the low 5 for short ones.
    fn mask_bits(first: u8) -> u8 {
        if first & 0x80 != 0 {
            0x0f
        } else {
            0x1f
        }
    }

    /// Receiver side: the first byte still carries the mask, so it must be
    /// unmasked before the packet number length can be read from its low bits.
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let Some(mask) = self.mask_at(pn_offset, packet) else {
            return;
        };
        let Some(first) = packet.first_mut() else {
            return;
        };
        let bits = Self::mask_bits(*first);
        *first ^= mask[0] & bits;
        let pn_len = ((*first & 0x03) as usize) + 1;
        let Some(pn) = packet.get_mut(pn_offset..pn_offset + pn_len) else {
            return;
        };
        for (dst, m) in pn.iter_mut().zip(&mask[1..]) {
            *dst ^= *m;
        }
    }

    /// Sender side: the packet number length is already encoded in the
    /// clear-text first byte, so it is read *before* the mask is applied.
    /// XORing it away first would corrupt the very bits being read.
    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let Some(mask) = self.mask_at(pn_offset, packet) else {
            return;
        };
        let Some(first) = packet.first_mut() else {
            return;
        };
        let bits = Self::mask_bits(*first);
        let pn_len = ((*first & 0x03) as usize) + 1;
        *first ^= mask[0] & bits;
        let Some(pn) = packet.get_mut(pn_offset..pn_offset + pn_len) else {
            return;
        };
        for (dst, m) in pn.iter_mut().zip(&mask[1..]) {
            *dst ^= *m;
        }
    }
}

impl HeaderKey for HpKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        HpKey::decrypt(self, pn_offset, packet)
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        HpKey::encrypt(self, pn_offset, packet)
    }

    fn sample_size(&self) -> usize {
        self.key.algorithm().sample_len()
    }
}

/// QUIC packet payload protection (RFC 9001 §5.3).
///
/// The nonce is the IV XOR the packet number (big endian, right aligned) and the
/// header - up to and including the *unprotected* packet number - is the AAD.
struct PpKey {
    key: LessSafeKey,
    iv: [u8; 12],
    confidentiality_limit: u64,
    integrity_limit: u64,
}

impl PpKey {
    fn new(suite: &'static Suite, secret: &[u8]) -> Result<Self, TlsErr> {
        let alg = suite.alg;
        let prk = alg.prk(secret)?;
        let key_len = suite.aead.key_len();
        let key_bytes = prk.expand_label(b"quic key", &[], key_len);
        let iv_bytes = prk.expand_label(b"quic iv", &[], 12);
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&iv_bytes);
        let key = LessSafeKey::new(
            UnboundKey::new(suite.aead, &key_bytes)
                .map_err(|_| TlsErr::internal("packet protection key"))?,
        );
        // RFC 9001 §6.6.
        let confidentiality_limit = if suite.id == 0x1303 {
            1 << 62
        } else {
            1 << 23
        };
        Ok(Self {
            key,
            iv,
            confidentiality_limit,
            integrity_limit: if suite.id == 0x1303 { 1 << 36 } else { 1 << 52 },
        })
    }

    fn nonce(&self, packet: u64) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[4..12].copy_from_slice(&packet.to_be_bytes());
        for (i, x) in n.iter_mut().enumerate() {
            *x ^= self.iv[i];
        }
        n
    }
}

impl PacketKey for PpKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        if buf.len() <= header_len + 16 {
            return;
        }
        let (aad, rest) = buf.split_at_mut(header_len);
        let split = rest.len() - 16;
        let (payload, tag_storage) = rest.split_at_mut(split);
        let tag = self
            .key
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(self.nonce(packet)),
                Aad::from(&*aad),
                payload,
            )
            .expect("packet encryption cannot fail");
        tag_storage.copy_from_slice(tag.as_ref());
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let plain = self
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(self.nonce(packet)),
                Aad::from(header),
                payload.as_mut(),
            )
            .map_err(|_| CryptoError)?;
        let n = plain.len();
        payload.truncate(n);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        16
    }

    fn confidentiality_limit(&self) -> u64 {
        self.confidentiality_limit
    }

    fn integrity_limit(&self) -> u64 {
        self.integrity_limit
    }
}

// ---------------------------------------------------------------- key material

/// Traffic secrets for one packet space, plus the suite they belong to.
#[derive(Clone)]
struct Level {
    suite: &'static Suite,
    local: Vec<u8>,
    remote: Vec<u8>,
}

impl Level {
    fn keys(&self) -> Keys {
        Keys {
            header: KeyPair {
                local: Box::new(HpKey::new(self.suite, &self.local).expect("hp key")),
                remote: Box::new(HpKey::new(self.suite, &self.remote).expect("hp key")),
            },
            packet: KeyPair {
                local: Box::new(PpKey::new(self.suite, &self.local).expect("packet key")),
                remote: Box::new(PpKey::new(self.suite, &self.remote).expect("packet key")),
            },
        }
    }

    /// RFC 9001 §6: the secrets of the *next* key phase, derived once from
    /// this one with `quic ku`.  quinn's contract (mirroring rustls
    /// `Secrets`) is that the level stashed for the first key update is
    /// already advanced once: `next_1rtt_keys()` then hands out the keys of
    /// the phase after the current one.
    fn advanced(&self) -> Level {
        let len = self.suite.alg.len();
        Level {
            suite: self.suite,
            local: kdf_expand_label(self.suite, &self.local, b"quic ku", len),
            remote: kdf_expand_label(self.suite, &self.remote, b"quic ku", len),
        }
    }

    /// RFC 9001 §6: keys for the next key update, then the secret moves on.
    fn next_packet_keys(&mut self) -> KeyPair<Box<dyn PacketKey>> {
        let keys = KeyPair {
            local: Box::new(PpKey::new(self.suite, &self.local).expect("packet key"))
                as Box<dyn PacketKey>,
            remote: Box::new(PpKey::new(self.suite, &self.remote).expect("packet key"))
                as Box<dyn PacketKey>,
        };
        *self = self.advanced();
        keys
    }
}

/// `HKDF-Expand-Label` straight from a secret: used for the values that are
/// not bound to the transcript (`quic key` / `quic iv` / `quic hp` / `quic ku`).
fn kdf_expand_label(suite: &'static Suite, secret: &[u8], label: &[u8], len: usize) -> Vec<u8> {
    suite
        .alg
        .prk(secret)
        .expect("secret lengths come from the key schedule")
        .expand_label(label, &[], len)
}

/// `Derive-Secret(Secret, Label, Messages)` (RFC 8446 §7.1): the label is expanded
/// with the hash of the transcript as its context.
fn derive_secret(prk: &Prk, label: &[u8], transcript: &[u8]) -> Vec<u8> {
    prk.derive(label, transcript)
}

// ------------------------------------------------------------------ ClientHello

/// `server_name` (RFC 6066): a single `host_name`.
fn sni_extension(sni: &str) -> Vec<u8> {
    let name = sni.as_bytes();
    let mut list = Vec::with_capacity(3 + name.len());
    list.push(0x00); // name_type: host_name
    push_u16(&mut list, name.len() as u16);
    list.extend_from_slice(name);
    len16(&list)
}

/// `ProtocolName protocol_name_list<2..2^16-1>`, with a u8 length per entry.
///
/// Used by `application_layer_protocol_negotiation` and `application_settings`.
fn proto_list(protos: &[&[u8]]) -> Vec<u8> {
    let mut list = Vec::new();
    for p in protos {
        list.push(p.len() as u8);
        list.extend_from_slice(p);
    }
    len16(&list)
}

/// `supported_groups` (RFC 8446 §4.2.7): GREASE first, X25519 preferred.
fn supported_groups(grease: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + 8);
    push_u16(&mut v, 8);
    push_u16(&mut v, grease);
    push_u16(&mut v, GROUP_X25519);
    push_u16(&mut v, 0x0017); // secp256r1
    push_u16(&mut v, 0x0018); // secp384r1
    v
}

/// `signature_algorithms` (RFC 8446 §4.2.3).
fn sigalgs_extension() -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + 2 * CHROME_SIGNATURE_ALGORITHMS.len());
    push_u16(&mut v, (2 * CHROME_SIGNATURE_ALGORITHMS.len()) as u16);
    for s in CHROME_SIGNATURE_ALGORITHMS {
        push_u16(&mut v, s);
    }
    v
}

/// `key_share` (RFC 8446 §4.2.8): a GREASE entry with a 1 byte placeholder
/// followed by the real X25519 share - the only group Chrome sends a key for.
fn keyshare_extension(grease: u16, share: &[u8; 32]) -> Vec<u8> {
    let mut list = Vec::with_capacity(5 + 36);
    push_u16(&mut list, grease);
    push_u16(&mut list, 1);
    list.push(0x00);
    push_u16(&mut list, GROUP_X25519);
    push_u16(&mut list, 32);
    list.extend_from_slice(share);
    len16(&list)
}

/// `supported_versions` (RFC 8446 §4.2.1).
fn supported_versions(grease: u16) -> Vec<u8> {
    // TLS 1.3 only: RFC 9001 §4.2 ("Clients MUST NOT offer TLS versions older
    // than 1.3"). The GREASE value keeps the list shaped like BoringSSL's.
    let mut v = Vec::with_capacity(5);
    v.push(4); // list length
    push_u16(&mut v, grease);
    push_u16(&mut v, VERSION_TLS13);
    v
}

/// Chrome's greased `encrypted_client_hello`.
///
/// The extension keeps its real code point and carries a fake `ECHConfigList`
/// (draft-ietf-tls-esni-17 §5): a random config id, a random HPKE
/// encapsulated key and a payload whose pre-encryption length BoringSSL picks
/// from {128, 160, 192, 224}.  It exists purely to keep ECH visible to
/// middleboxes, so it carries no client data.
fn grease_ech(rng: &mut dyn RngCore) -> Vec<u8> {
    const LENS: [usize; 4] = [128, 160, 192, 224];
    let payload_len = LENS[(rng.next_u32() as usize) % LENS.len()] + 16;
    let mut v = Vec::with_capacity(5 + 2 + 32 + 2 + payload_len);
    v.push(0x00); // type: client hello outer
    push_u16(&mut v, 0x0001); // KDF: HKDF-SHA256
    push_u16(&mut v, 0x0001); // AEAD: AES-128-GCM
    v.push(rng.next_u32() as u8); // config id
    push_u16(&mut v, 32);
    let mut enc = [0u8; 32];
    rng.fill_bytes(&mut enc);
    v.extend_from_slice(&enc);
    push_u16(&mut v, payload_len as u16);
    let mut payload = vec![0u8; payload_len];
    rng.fill_bytes(&mut payload);
    v.extend_from_slice(&payload);
    v
}

/// The ClientHello, byte for byte, as Chrome 120 would send it over QUIC.
///
/// The extension order below is BoringSSL's table order with a GREASE
/// extension injected at each end and SNI emitted first - what a Chrome hello
/// looks like on the wire, and the list uTLS copies in `HelloChrome_120`.  Two
/// things differ from the TCP version because QUIC requires it: there is no
/// session ticket payload (QUIC never resumes) and `quic_transport_parameters`
/// is appended.
pub fn build_client_hello(
    sni: &str,
    random: &[u8; 32],
    key_share: &[u8; 32],
    quic_params: &[u8],
) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let grease = |rng: &mut dyn RngCore| GREASE[(rng.next_u32() as usize) % GREASE.len()];
    let g_suite = grease(&mut rng);
    let g_ext1 = grease(&mut rng);
    let g_group = grease(&mut rng);
    let g_version = grease(&mut rng);
    // The two GREASE extensions must not collide: RFC 8701 gives each slot its
    // own value, and a repeated extension type is a parse error on strict
    // servers (rustls rejects the hello with `DuplicateExtension`).
    let g_ext2 = loop {
        let g = grease(&mut rng);
        if g != g_ext1 {
            break g;
        }
    };

    // Fixed part of the hello, up to and including the extension block length.
    const PREFIX: usize = 4 /* handshake header */
        + 2 /* legacy_version */
        + 32 /* random */
        + 1 /* session_id length */
        + 2 /* cipher suite length */
        + 2 * (CHROME_CIPHER_SUITES.len() + 1 /* the GREASE suite */)
        + 1 /* compression length */
        + 1 /* compression */
        + 2; /* extension block length */

    // Extensions that only exist for TLS 1.2 and earlier (extended_master_secret,
    // renegotiation_info, ec_point_formats, session_ticket) are not sent: a
    // TLS 1.3-only QUIC client has no use for them.  BoringSSL also permutes the
    // order of the remaining extensions on every connection (since Chrome 110),
    // so they are shuffled here too; the greased first and last slots stay put.
    let mut middle: Vec<(u16, Vec<u8>)> = vec![
        (EXT_SERVER_NAME, sni_extension(sni)),
        (EXT_SUPPORTED_GROUPS, supported_groups(g_group)),
        (EXT_ALPN, proto_list(&[b"h3"])),
        // status_request: an OCSP request with no responder ids / extensions.
        (EXT_STATUS_REQUEST, vec![0x01, 0x00, 0x00, 0x00, 0x00]),
        (EXT_SIGNATURE_ALGORITHMS, sigalgs_extension()),
        (EXT_SCT, Vec::new()),
        (EXT_KEY_SHARE, keyshare_extension(g_group, key_share)),
        (EXT_PSK_MODES, vec![0x01, 0x01]),
        (EXT_SUPPORTED_VERSIONS, supported_versions(g_version)),
        (EXT_QUIC_TP, quic_params.to_vec()),
        (EXT_COMPRESS_CERTIFICATE, vec![0x02, 0x00, 0x02]),
        (EXT_APPLICATION_SETTINGS, proto_list(&[b"h3"])),
        (EXT_ECH, grease_ech(&mut rng)),
    ];
    {
        use rand::seq::SliceRandom;
        middle.shuffle(&mut rng);
    }
    let mut exts = Vec::with_capacity(512);
    push_ext(&mut exts, g_ext1, &[]);
    for (ty, data) in &middle {
        push_ext(&mut exts, *ty, data);
    }
    push_ext(&mut exts, g_ext2, &[0x00]);

    // ... and finally the hello is padded back up to a constant size.
    let total = PREFIX + exts.len();
    let pad = if total > 0xff && total < PAD_TO {
        let mut n = PAD_TO - total;
        if n >= 5 {
            n -= 4; // the extension header we are about to write
        } else {
            n = 1;
        }
        Some(n)
    } else {
        None
    };

    let ext_len = exts.len() + pad.map_or(0, |n| n + 4);
    let mut hello = Vec::with_capacity(4 + PREFIX + ext_len);
    hello.push(HS_CLIENT_HELLO);
    push_u24(&mut hello, (PREFIX + ext_len - 4) as u32);
    hello.extend_from_slice(&VERSION_LEGACY.to_be_bytes());
    hello.extend_from_slice(random);
    hello.push(0x00); // session_id: QUIC offers no resumption
    push_u16(&mut hello, (2 * (CHROME_CIPHER_SUITES.len() + 1)) as u16);
    push_u16(&mut hello, g_suite); // Chrome greases the first cipher suite
    for s in CHROME_CIPHER_SUITES {
        push_u16(&mut hello, s);
    }
    hello.push(0x01);
    hello.push(0x00); // compression: null
    push_u16(&mut hello, ext_len as u16);
    hello.extend_from_slice(&exts);
    if let Some(n) = pad {
        push_ext(&mut hello, EXT_PADDING, &vec![0u8; n]);
    }
    hello
}

// --------------------------------------------------------------------- session

/// What a dest probe records from a server's TLS flight.
///
/// The server side of quic-reality serves a throw-away certificate whose only
/// job is authentication; to make an *authenticated* connection look like the
/// dest's real QUIC server, the flight the dest produces for this very
/// ClientHello is recorded once and replayed in shape (see [`crate::mimic`]).
#[derive(Debug, Default)]
pub struct Recorded {
    /// Negotiated TLS 1.3 cipher suite from the ServerHello.
    pub suite: Option<u16>,
    /// Total size of the Certificate handshake message (header included).
    pub cert_msg_len: Option<usize>,
    /// `(message size, lifetime)` of every NewSessionTicket.
    pub nst: Vec<(usize, u32)>,
    /// Raw `quic_transport_parameters` bytes from the EncryptedExtensions.
    pub tp: Vec<u8>,
}

/// Shared recording target of a probe session.
pub type Recorder = Arc<Mutex<Recorded>>;

/// Where we are in the TLS 1.3 handshake.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    AwaitServerHello,
    AwaitEncryptedExtensions,
    AwaitCertificate,
    AwaitCertificateVerify,
    AwaitFinished,
    Done,
}

/// A client TLS 1.3 session that speaks Chrome's ClientHello dialect.
pub struct ChromeSession {
    state: State,
    /// Hash of the negotiated suite: SHA-256 unless the ServerHello picks
    /// `0x1302`, the only suite here that uses SHA-384.
    alg: HashAlg,
    suite: Option<&'static Suite>,
    /// The client's ephemeral X25519 private key, from [`ClientMaterial`].
    priv_key: [u8; 32],
    /// Checks the HMAC in the server's temporary certificate.
    auth_key: [u8; 32],
    /// Handshake secret: the salt the master secret is extracted from.
    hs_secret: Option<Prk>,
    /// `finished_key` the server's Finished has to match.
    server_finished_key: Vec<u8>,
    /// `finished_key` our own Finished is keyed with: RFC 8446 §4.4.4
    /// expands it from `c hs traffic`, the client handshake traffic secret.
    /// Computed early because quinn takes the handshake `Level` (and with it
    /// any secret stored there) as soon as it is available.
    client_finished_key: Vec<u8>,
    /// Master secret, kept for `export_keying_material`.
    master: Option<Prk>,
    /// Transcript of `ClientHello .. server Finished`; the application
    /// traffic secrets and the exporter are bound to it.
    finished_transcript: Option<Vec<u8>>,
    /// Keys for the handshake packet space, handed to quinn exactly once.
    hs: Option<Level>,
    /// Keys for the application packet space, handed to quinn exactly once.
    app: Option<Level>,
    /// Application secrets, advanced on every key update.
    next: Option<Level>,
    /// Every handshake message in wire order, for the transcript hash.
    transcript: Vec<u8>,
    /// Bytes of the incoming flight that do not form a whole message yet.
    rx: Vec<u8>,
    /// Messages to hand to quinn; `true` = must go out under handshake keys.
    tx: VecDeque<(bool, Vec<u8>)>,
    peer_params: Option<TransportParameters>,
    alpn: Option<Vec<u8>>,
    peer_cert: Option<CertificateDer<'static>>,
    got_handshake_data: bool,
    /// Probe mode: the server is an ordinary TLS 1.3 endpoint (the dest), not a
    /// REALITY peer, so certificate authentication is skipped and the flight is
    /// recorded instead.
    probe: bool,
    recorder: Option<Recorder>,
}

impl ChromeSession {
    /// Routes one complete handshake message to the right handler.
    ///
    /// `before` is the transcript hash of everything preceding `msg`; both the
    /// CertificateVerify signature and the Finished verify_data are computed
    /// over that value, so it is captured before the message joins the
    /// transcript.
    fn handle(&mut self, msg: &[u8], before: &[u8]) -> Result<(), TlsErr> {
        if let Some(rec) = &self.recorder {
            let mut r = rec.lock().unwrap_or_else(|e| e.into_inner());
            match msg[0] {
                HS_CERTIFICATE => r.cert_msg_len = Some(msg.len()),
                // NewSessionTicket: lifetime(4) age_add(4) nonce_len(1) ...
                HS_SESSION_TICKET if msg.len() >= 8 => {
                    let lifetime = u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]);
                    r.nst.push((msg.len(), lifetime));
                }
                _ => {}
            }
        }
        match (self.state, msg[0]) {
            (State::AwaitServerHello, HS_SERVER_HELLO) => self.on_server_hello(&msg[4..]),
            (State::AwaitEncryptedExtensions, HS_ENCRYPTED_EXTENSIONS) => {
                self.on_encrypted_extensions(&msg[4..])
            }
            (State::AwaitCertificate, HS_CERTIFICATE) => self.on_certificate(&msg[4..]),
            (State::AwaitCertificateVerify, HS_CERTIFICATE_VERIFY) => {
                self.on_certificate_verify(&msg[4..], before)
            }
            (State::AwaitFinished, HS_FINISHED) => self.on_finished(&msg[4..], before),
            // NewSessionTicket / KeyUpdate.  A REALITY client never resumes and
            // quinn drives key updates itself, so there is nothing to do.
            (State::Done, HS_SESSION_TICKET) => {
                // Test hook counts what an *authenticated* client sees; probe
                // sessions (background dest probes) must not pollute it.
                #[cfg(test)]
                if !self.probe {
                    LAST_NST_COUNT.with(|c| c.set(c.get() + 1));
                    LAST_NST_LENS.with(|l| l.borrow_mut().push(msg.len()));
                }
                Ok(())
            }
            // RFC 9001 §6: a TLS KeyUpdate in QUIC is a connection error; QUIC
            // has its own key update mechanism.
            (State::Done, HS_KEY_UPDATE) => Err(TlsErr::bad("TLS KeyUpdate is not allowed in QUIC")),
            _ => Err(TlsErr::bad("unexpected handshake message")),
        }
    }

    fn on_server_hello(&mut self, body: &[u8]) -> Result<(), TlsErr> {
        let mut r = Reader::new(body);
        if r.u16()? != VERSION_LEGACY {
            return Err(TlsErr::bad("bad legacy_version in ServerHello"));
        }
        let random = r.take(32)?;
        if random == HELLO_RETRY_RANDOM {
            return Err(TlsErr::bad("HelloRetryRequest is not supported"));
        }
        if !r.vec8()?.is_empty() {
            return Err(TlsErr::bad("unexpected session id echo"));
        }
        let suite_id = r.u16()?;
        if r.u8()? != 0 {
            return Err(TlsErr::bad("bad legacy compression method"));
        }
        let exts = r.vec16()?;

        let suite = suite_by_id(suite_id)?;
        self.alg = suite.alg;
        #[cfg(test)]
        LAST_NEGOTIATED.with(|c| c.set(suite_id));
        self.suite = Some(suite);
        if let Some(rec) = &self.recorder {
            rec.lock().unwrap_or_else(|e| e.into_inner()).suite = Some(suite_id);
        }

        // supported_versions and key_share are mandatory in a TLS 1.3 ServerHello.
        // The server's transport parameters are NOT here: RFC 9001 §7.4 puts them
        // in EncryptedExtensions, which is where `on_encrypted_extensions` reads
        // them from.
        let mut version = None;
        let mut share = None;
        let mut er = Reader::new(exts);
        while !er.done() {
            let ty = er.u16()?;
            let data = er.vec16()?;
            match ty {
                EXT_SUPPORTED_VERSIONS => version = Some(Reader::new(data).u16()?),
                EXT_KEY_SHARE => {
                    let mut s = Reader::new(data);
                    let group = s.u16()?;
                    let key = s.vec16()?;
                    if group != GROUP_X25519 {
                        return Err(TlsErr::bad("unexpected key share group"));
                    }
                    if key.len() != 32 {
                        return Err(TlsErr::bad("bad key share length"));
                    }
                    share = Some(key.to_vec());
                }
                _ => {}
            }
        }

        if version != Some(VERSION_TLS13) {
            return Err(TlsErr::bad("server did not negotiate TLS 1.3"));
        }
        let peer_share = share.ok_or(TlsErr::Bad("ServerHello without a key share"))?;

        // The REALITY proof rides in `random` and is checked against the
        // certificate's HMAC later.  TLS authentication is the ordinary X25519
        // exchange against the server's ephemeral share.
        let mut peer = [0u8; 32];
        peer.copy_from_slice(peer_share.as_slice());
        let shared = StaticSecret::from(self.priv_key).diffie_hellman(&PublicKey::from(peer));
        if !shared.was_contributory() {
            return Err(TlsErr::Alert(ALERT_ILLEGAL_PARAMETER));
        }

        let alg = self.alg;
        let zeros = vec![0u8; alg.len()];
        let early = alg.extract(&zeros, &zeros);
        let pre_hs = derive_secret(&early, b"derived", &[]);
        let hs = alg.extract(&pre_hs, shared.as_bytes());

        // `self.transcript` holds exactly `ClientHello || ServerHello` now, so
        // this is Transcript-Hash(CH..SH).  Derive-Secret hashes the transcript
        // itself, so the raw messages go in.
        let c_hs = derive_secret(&hs, b"c hs traffic", &self.transcript);
        let s_hs = derive_secret(&hs, b"s hs traffic", &self.transcript);
        self.server_finished_key = kdf_expand_label(suite, &s_hs, b"finished", alg.len());
        self.client_finished_key = kdf_expand_label(suite, &c_hs, b"finished", alg.len());

        self.hs = Some(Level {
            suite,
            local: c_hs,
            remote: s_hs.clone(),
        });
        self.hs_secret = Some(hs);
        self.state = State::AwaitEncryptedExtensions;
        Ok(())
    }

    fn on_encrypted_extensions(&mut self, body: &[u8]) -> Result<(), TlsErr> {
        let mut r = Reader::new(body);
        let exts = r.vec16()?;
        let mut er = Reader::new(exts);
        while !er.done() {
            let ty = er.u16()?;
            let data = er.vec16()?;
            match ty {
                // RFC 9001 §7.4: the server's transport parameters ride here,
                // not in the ServerHello.
                EXT_QUIC_TP => {
                    if let Some(rec) = &self.recorder {
                        rec.lock().unwrap_or_else(|e| e.into_inner()).tp = data.to_vec();
                    }
                    let params = TransportParameters::read(
                        Side::Client,
                        &mut Cursor::new(data),
                    )
                    .map_err(|_| TlsErr::Bad("malformed transport parameters"))?;
                    // `TransportParameters` has no public field getters, so the
                    // test hook re-encodes the wire form and runs it through the
                    // same extractor the probe uses (mimic::parse_transport_params).
                    #[cfg(test)]
                    if !self.probe {
                        let mut buf = Vec::new();
                        params.write(&mut buf);
                        LAST_PEER_TP.with(|t| {
                            *t.borrow_mut() = Some(crate::mimic::parse_transport_params(&buf))
                        });
                    }
                    self.peer_params = Some(params);
                }
                EXT_ALPN => {
                    let mut s = Reader::new(data);
                    let list = s.vec16()?;
                    let mut ls = Reader::new(list);
                    let proto = ls.vec8()?.to_vec();
                    // We only ever offer "h3", so anything else means we are
                    // talking to something that does not run our protocol.
                    if proto != ALPN_H3 {
                        return Err(TlsErr::bad("server chose an ALPN we did not offer"));
                    }
                    self.alpn = Some(proto);
                }
                _ => {}
            }
        }
        if self.alpn.is_none() {
            return Err(TlsErr::bad("no ALPN in EncryptedExtensions"));
        }
        if self.peer_params.is_none() {
            return Err(TlsErr::Bad("EncryptedExtensions without QUIC transport parameters"));
        }
        self.state = State::AwaitCertificate;
        Ok(())
    }

    fn on_certificate(&mut self, body: &[u8]) -> Result<(), TlsErr> {
        let mut r = Reader::new(body);
        if !r.vec8()?.is_empty() {
            return Err(TlsErr::bad("unexpected certificate request context"));
        }
        let mut list = Reader::new(r.vec24()?);
        let cert = list.vec24()?;
        // REALITY serves a single certificate; whatever follows it is noise.
        self.peer_cert = Some(CertificateDer::from(cert.to_vec()));
        #[cfg(test)]
        LAST_CERT_DER_LEN.with(|c| c.set(cert.len()));
        self.state = State::AwaitCertificateVerify;
        Ok(())
    }

    fn on_certificate_verify(&mut self, body: &[u8], before: &[u8]) -> Result<(), TlsErr> {
        let mut r = Reader::new(body);
        let scheme = r.u16()?;
        let sig = r.vec16()?;
        if self.probe {
            // A probe only records the flight: the certificate is the dest's
            // real one, signed with whatever algorithm the dest uses. Nothing
            // here authenticates anything, so there is nothing to check.
            let _ = (scheme, sig, before);
            self.state = State::AwaitFinished;
            return Ok(());
        }
        if scheme != SIG_ED25519 {
            return Err(TlsErr::bad("unsupported CertificateVerify algorithm"));
        }
        let Some(cert) = self.peer_cert.as_ref() else {
            return Err(TlsErr::bad("CertificateVerify without a Certificate"));
        };
        // The HMAC in the certificate's signature slot is the server's proof
        // that it derived the same auth_key from the REALITY key exchange.
        cert::check(cert.as_ref(), &self.auth_key)
            .map_err(|_| TlsErr::Bad("REALITY certificate is not authentic"))?;

        let mut msg = Vec::with_capacity(64 + SERVER_CV_CONTEXT.len() + 1 + before.len());
        msg.extend_from_slice(&[0x20u8; 64]);
        msg.extend_from_slice(SERVER_CV_CONTEXT);
        msg.push(0x00);
        msg.extend_from_slice(before);
        let Some(pubkey) = cert::public_key(cert.as_ref()) else {
            return Err(TlsErr::Bad("certificate carries no Ed25519 key"));
        };
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pubkey.as_ref())
            .verify(&msg, sig)
            .map_err(|_| TlsErr::Alert(ALERT_DECRYPT_ERROR))?;
        self.state = State::AwaitFinished;
        Ok(())
    }
}

impl ChromeSession {
    fn on_finished(&mut self, body: &[u8], before: &[u8]) -> Result<(), TlsErr> {
        let expected = self.alg.hmac(&self.server_finished_key, before);
        if !bool::from(expected.as_slice().ct_eq(body)) {
            return Err(TlsErr::Alert(ALERT_DECRYPT_ERROR));
        }

        let alg = self.alg;
        let suite = self.suite.ok_or(TlsErr::Bad("no cipher suite"))?;
        let hs = self.hs_secret.as_ref().ok_or(TlsErr::Bad("no handshake secret"))?;

        // Master secret, then the two traffic secrets bound to the transcript
        // of `ClientHello .. server Finished`.  `self.transcript` holds exactly
        // those messages right now, and Derive-Secret hashes them itself.
        let zeros = vec![0u8; alg.len()];
        let pre_master = derive_secret(hs, b"derived", &[]);
        let master = alg.extract(&pre_master, &zeros);
        let after = alg.digest(&self.transcript);
        let c_ap = derive_secret(&master, b"c ap traffic", &self.transcript);
        let s_ap = derive_secret(&master, b"s ap traffic", &self.transcript);

        // Our Finished: RFC 8446 §4.4.4 expands `finished` from the sender's
        // *handshake* traffic secret — for the client that is `c hs traffic`,
        // not `c ap traffic` (which only keys the application data).  The key
        // was computed alongside the server's in `on_server_hello`, because
        // quinn claims the handshake `Level` as soon as it exists.
        let finished_key = self.client_finished_key.clone();
        let verify_data = alg.hmac(&finished_key, &after);
        let fin = handshake_msg(HS_FINISHED, &verify_data);
        let app = Level {
            suite,
            local: c_ap,
            remote: s_ap,
        };
        self.tx.push_back((true, fin));
        // The level kept for the first key update is advanced once already,
        // exactly like rustls' `KeyChange::OneRtt { next }`.
        self.next = Some(app.advanced());
        self.app = Some(app);
        self.master = Some(master);
        // Snapshot before our own Finished joins the transcript: the exporter
        // is bound to `ClientHello .. server Finished` (RFC 8446 §7.3).
        self.finished_transcript = Some(self.transcript.clone());
        self.state = State::Done;
        Ok(())
    }

    /// Reports the handshake data exactly once, the way quinn expects it.
    fn take_handshake_ready(&mut self) -> bool {
        if self.got_handshake_data {
            return false;
        }
        if self.alpn.is_some() || self.state == State::Done {
            self.got_handshake_data = true;
            return true;
        }
        false
    }
}

impl QuicSessionTrait for ChromeSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        // RFC 9001 §5.2: Initial keys are always AES-128-GCM with AES-128
        // header protection, no matter which suite is negotiated later.  The
        // "client in"/"server in" secrets take an *empty* context, which is not
        // the same as the hash of an empty transcript.
        let alg = HashAlg::Sha256;
        let early = alg.extract(&INITIAL_SALT_V1, dst_cid);
        let client = early.expand_label(b"client in", &[], alg.len());
        let server = early.expand_label(b"server in", &[], alg.len());
        let (local, remote) = match side {
            Side::Client => (client, server),
            Side::Server => (server, client),
        };
        let suite = &SUITES[0];
        Keys {
            header: KeyPair {
                local: Box::new(HpKey::new(suite, local.as_slice()).expect("hp key")),
                remote: Box::new(HpKey::new(suite, remote.as_slice()).expect("hp key")),
            },
            packet: KeyPair {
                local: Box::new(PpKey::new(suite, local.as_slice()).expect("packet key")),
                remote: Box::new(PpKey::new(suite, remote.as_slice()).expect("packet key")),
            },
        }
    }

    fn handshake_data(&self) -> Option<Box<dyn std::any::Any>> {
        if !self.got_handshake_data {
            return None;
        }
        Some(Box::new(quinn::crypto::rustls::HandshakeData {
            protocol: self.alpn.clone(),
            server_name: None,
        }))
    }

    fn peer_identity(&self) -> Option<Box<dyn std::any::Any>> {
        self.peer_cert.as_ref().map(|c| {
            let v: Vec<CertificateDer<'static>> = vec![c.clone()];
            Box::new(v) as Box<dyn std::any::Any>
        })
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        None
    }

    fn early_data_accepted(&self) -> Option<bool> {
        Some(false)
    }

    fn is_handshaking(&self) -> bool {
        self.state != State::Done
    }

    /// Feeds decrypted CRYPTO data to the handshake state machine.
    ///
    /// quinn hands over every byte it reassembles from CRYPTO frames; a message
    /// can straddle several calls, so incoming bytes are buffered until a whole
    /// message is available.
    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        self.rx.extend_from_slice(buf);
        while self.rx.len() >= 4 {
            let len = ((self.rx[1] as usize) << 16)
                | ((self.rx[2] as usize) << 8)
                | self.rx[3] as usize;
            if len > MAX_HANDSHAKE_MESSAGE || self.rx.len() < 4 + len {
                break;
            }
            let msg: Vec<u8> = self.rx.drain(..4 + len).collect();
            let before = self.alg.digest(&self.transcript);
            self.transcript.extend_from_slice(&msg);
            self.handle(&msg, &before).map_err(TlsErr::transport)?;
        }
        Ok(self.take_handshake_ready())
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        Ok(self.peer_params)
    }

    /// Hands the next batch of handshake bytes to quinn, together with the keys
    /// that change right after it.
    ///
    /// The rule quinn relies on: bytes returned alongside a key change are still
    /// written at the level that was in use *before* the change.  That is what
    /// keeps the ClientHello on Initial keys and the client Finished on
    /// Handshake keys, exactly as in RFC 9001 §4.1.4.
    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        loop {
            match self.tx.front() {
                // The next message needs the new keys; stop here so the caller
                // installs them before we emit it.
                Some(&(true, _)) if self.hs.is_some() => break,
                Some(_) => {
                    let Some((_, m)) = self.tx.pop_front() else { break };
                    self.transcript.extend_from_slice(&m);
                    buf.extend_from_slice(&m);
                }
                None => break,
            }
        }

        if let Some(l) = self.hs.take() {
            return Some(l.keys());
        }
        if let Some(l) = self.app.take() {
            return Some(l.keys());
        }
        None
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        self.next.as_mut().map(|l| l.next_packet_keys())
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        let Some(tag_start) = payload.len().checked_sub(16) else {
            return false;
        };
        // RFC 9001 §5.8: the integrity tag covers odcid-len || odcid || header || token.
        let mut pseudo = Vec::with_capacity(header.len() + payload.len() + orig_dst_cid.len() + 1);
        pseudo.push(orig_dst_cid.len() as u8);
        pseudo.extend_from_slice(orig_dst_cid);
        pseudo.extend_from_slice(header);
        let tag_start = tag_start + pseudo.len();
        pseudo.extend_from_slice(payload);

        let Ok(unbound) = UnboundKey::new(&AES_128_GCM, &RETRY_INTEGRITY_KEY_V1) else {
            return false;
        };
        let key = LessSafeKey::new(unbound);
        let (aad, tag) = pseudo.split_at_mut(tag_start);
        key.open_in_place(
            Nonce::assume_unique_for_key(RETRY_INTEGRITY_NONCE_V1),
            Aad::from(aad),
            tag,
        )
        .is_ok()
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        let (Some(master), Some(finished)) = (&self.master, &self.finished_transcript) else {
            return Err(ExportKeyingMaterialError)
        };
        let alg = self.alg;
        // RFC 8446 §7.3:
        //   TLS-Exporter(label, context, length) =
        //       HKDF-Expand-Label(Derive-Secret(Secret, label, ""),
        //                         "exporter", Hash(context), length)
        // with Secret = Derive-Secret(Master Secret, "exp master",
        //                             ClientHello..server Finished).
        let exporter = derive_secret(master, b"exp master", finished);
        // The wrapped step uses `Hash("")` as its context, which is what
        // `derive_secret` produces for an empty transcript.
        let wrapped = match alg.prk(&exporter) {
            Ok(p) => derive_secret(&p, label, &[]),
            Err(_) => return Err(ExportKeyingMaterialError),
        };
        let ctx = alg.digest(context);
        let out = match alg.prk(&wrapped) {
            Ok(p) => p.expand_label(b"exporter", &ctx, output.len()),
            Err(_) => return Err(ExportKeyingMaterialError),
        };
        output.copy_from_slice(&out);
        Ok(())
    }
}

/// Removes parameters that single quinn out from the encoded transport
/// parameters: `min_ack_delay` (draft ack-frequency, id 0xff04de1b), which quinn
/// advertises unconditionally and browsers do not send.  Unparseable input is
/// returned unchanged rather than guessed at.
fn sanitize_transport_params(raw: &[u8]) -> Vec<u8> {
    fn varint(b: &[u8], o: &mut usize) -> Option<u64> {
        let first = *b.get(*o)?;
        let len = 1usize << (first >> 6);
        let bytes = b.get(*o..*o + len)?;
        let mut v = (first & 0x3f) as u64;
        for x in &bytes[1..] {
            v = (v << 8) | *x as u64;
        }
        *o += len;
        Some(v)
    }
    const MIN_ACK_DELAY: u64 = 0xff04_de1b;
    let mut out = Vec::with_capacity(raw.len());
    let mut o = 0;
    while o < raw.len() {
        let start = o;
        let (Some(id), Some(len)) = (varint(raw, &mut o), varint(raw, &mut o)) else {
            return raw.to_vec();
        };
        let Some(end) = o.checked_add(len as usize).filter(|e| *e <= raw.len()) else {
            return raw.to_vec();
        };
        o = end;
        if id != MIN_ACK_DELAY {
            out.extend_from_slice(&raw[start..end]);
        }
    }
    out
}

/// quinn client crypto configuration that emits a Chrome ClientHello.
pub struct ChromeClientConfig {
    priv_key: [u8; 32],
    pub_key: [u8; 32],
    auth_key: [u8; 32],
    /// Seals the REALITY proof into the ClientHello in `start_session`: the
    /// AAD is the whole hello, so it can only be sealed once the hello is
    /// complete - with a zeroed `random`, which the ciphertext then replaces.
    /// `None` in probe mode, where there is no proof to seal.
    material: Option<ClientMaterial>,
    /// Probe mode: no REALITY authentication, the flight is recorded.
    probe: bool,
    recorder: Option<Recorder>,
}

impl ChromeClientConfig {
    /// One config per connection: both the key share and the REALITY proof
    /// are single-use, so the material is moved in and never reused.
    pub fn new(m: ClientMaterial) -> Self {
        Self {
            priv_key: m.secret.to_bytes(),
            pub_key: m.public,
            auth_key: m.auth_key(),
            material: Some(m),
            probe: false,
            recorder: None,
        }
    }

    /// A recording client used to probe a dest: the same hello shape a real
    /// client sends (same suites, same extensions, same order), but with a
    /// fresh ephemeral key, no REALITY proof and no certificate check. What it
    /// sees from the dest is the flight to mimic (see [`crate::mimic`]).
    pub fn probe(recorder: Recorder) -> Self {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        Self {
            priv_key: secret.to_bytes(),
            pub_key: PublicKey::from(&secret).to_bytes(),
            auth_key: [0u8; 32],
            material: None,
            probe: true,
            recorder: Some(recorder),
        }
    }

    fn make_session(&self, tx: VecDeque<(bool, Vec<u8>)>) -> ChromeSession {
        ChromeSession {
            state: State::AwaitServerHello,
            alg: HashAlg::Sha256,
            suite: None,
            priv_key: self.priv_key,
            auth_key: self.auth_key,
            hs_secret: None,
            server_finished_key: Vec::new(),
            client_finished_key: Vec::new(),
            master: None,
            finished_transcript: None,
            hs: None,
            app: None,
            next: None,
            transcript: Vec::new(),
            rx: Vec::with_capacity(4096),
            tx,
            peer_params: None,
            alpn: None,
            peer_cert: None,
            got_handshake_data: false,
            probe: self.probe,
            recorder: self.recorder.clone(),
        }
    }
}

impl CryptoClientConfig for ChromeClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn QuicSessionTrait>, ConnectError> {
        if !matches!(
            version,
            0xff00_001d..=0xff00_0020 | 0x0000_0001 | 0xff00_0021..=0xff00_0022
        ) {
            return Err(ConnectError::UnsupportedVersion);
        }
        if server_name.is_empty() {
            return Err(ConnectError::InvalidServerName(server_name.into()));
        }
        let mut quic_params = Vec::new();
        params.write(&mut quic_params);
        let quic_params = sanitize_transport_params(&quic_params);
        let hello = match &self.material {
            // The REALITY proof authenticates the whole hello, so the hello is
            // built first - with a zeroed `random`, the field the ciphertext
            // will occupy - sealed over, and only then patched. This is
            // xtls/reality's chicken-and-egg trick for `session_id`, one field
            // over: the tag can never cover itself.
            Some(m) => {
                let mut hello = build_client_hello(server_name, &[0u8; 32], &self.pub_key, &quic_params);
                let proof = m
                    .seal_proof(&hello)
                    .expect("sealing our own ClientHello cannot fail (quinn unwraps the equivalent rustls step)");
                hello[HELLO_RANDOM_OFFSET..HELLO_RANDOM_OFFSET + 32].copy_from_slice(&proof);
                hello
            }
            // Probe: an ordinary hello with a fresh random - nothing to seal.
            None => {
                let mut random = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut random);
                build_client_hello(server_name, &random, &self.pub_key, &quic_params)
            }
        };
        let mut tx = VecDeque::new();
        tx.push_back((false, hello));
        Ok(Box::new(self.make_session(tx)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_grease(x: u16) -> bool {
        (x & 0x0f0f) == 0x0a0a && (x >> 8) == (x & 0xff)
    }

    /// (cipher suites, extension types in wire order, supported_versions list)
    fn dissect(hello: &[u8]) -> (Vec<u16>, Vec<u16>, Vec<u16>) {
        let body = &hello[4..];
        let mut o = 2 + 32;
        o += 1 + body[o] as usize; // session id
        let cl = u16::from_be_bytes([body[o], body[o + 1]]) as usize;
        o += 2;
        let suites = (0..cl / 2)
            .map(|i| u16::from_be_bytes([body[o + 2 * i], body[o + 2 * i + 1]]))
            .collect();
        o += cl;
        o += 1 + body[o] as usize; // compression
        let el = u16::from_be_bytes([body[o], body[o + 1]]) as usize;
        o += 2;
        let exts = &body[o..o + el];
        let (mut types, mut versions, mut p) = (Vec::new(), Vec::new(), 0);
        while p < exts.len() {
            let t = u16::from_be_bytes([exts[p], exts[p + 1]]);
            let l = u16::from_be_bytes([exts[p + 2], exts[p + 3]]) as usize;
            if t == EXT_SUPPORTED_VERSIONS {
                let d = &exts[p + 4..p + 4 + l];
                versions = (0..d[0] as usize / 2)
                    .map(|i| u16::from_be_bytes([d[1 + 2 * i], d[2 + 2 * i]]))
                    .collect();
            }
            types.push(t);
            p += 4 + l;
        }
        (suites, types, versions)
    }

    #[test]
    fn initial_secrets_match_rfc9001_appendix_a() {
        // RFC 9001 A.1: client Initial keys for DCID 0x8394c8f03e515708.
        let dcid = hex::decode("8394c8f03e515708").unwrap();
        let early = HashAlg::Sha256.extract(&INITIAL_SALT_V1, &dcid);
        let client = early.expand_label(b"client in", &[], 32);
        assert_eq!(
            hex::encode(&client),
            "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
        );
        let prk = HashAlg::Sha256.prk(&client).unwrap();
        assert_eq!(hex::encode(prk.expand_label(b"quic key", &[], 16)), "1f369613dd76d5467730efcbe3b1a22d");
        assert_eq!(hex::encode(prk.expand_label(b"quic iv", &[], 12)), "fa044b2f42a3fd3b46fb255c");
        assert_eq!(hex::encode(prk.expand_label(b"quic hp", &[], 16)), "9f50449e04a0e810283a1e9933adedd2");
    }

    #[test]
    fn hello_is_tls13_only_shuffled_and_parseable() {
        let (random, share) = ([7u8; 32], [9u8; 32]);
        let mut orders = std::collections::HashSet::new();
        for _ in 0..40 {
            let h = build_client_hello("www.example.com", &random, &share, &[0x01, 0x01, 0x05]);
            let (suites, types, versions) = dissect(&h);

            let real: Vec<u16> = suites.iter().copied().filter(|s| !is_grease(*s)).collect();
            assert_eq!(real, CHROME_CIPHER_SUITES.to_vec(), "only TLS 1.3 suites");
            assert!(is_grease(suites[0]));
            assert_eq!(versions.len(), 2);
            assert!(is_grease(versions[0]) && versions[1] == VERSION_TLS13, "TLS 1.3 only: {versions:x?}");

            for legacy in [0x0017u16, 0xff01, 0x000b, 0x0023] {
                assert!(!types.contains(&legacy), "TLS<=1.2 extension {legacy:#x} must not be sent");
            }
            // A short hello gets a padding extension *after* the trailing GREASE
            // slot (as in browsers); ignore it when checking the greased frame.
            let core: Vec<u16> = types.iter().copied().filter(|t| *t != 0x0015).collect();
            assert!(is_grease(core[0]) && is_grease(*core.last().unwrap()), "greased first/last: {core:x?}");
            assert_ne!(core[0], *core.last().unwrap(), "the two GREASE slots differ");
            let mut sorted = types.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(sorted.len(), types.len(), "no duplicate extensions");
            orders.insert(types);

            // the server-side parser must still extract everything it needs
            let ci = crate::initial::parse_client_hello(&h).unwrap();
            assert_eq!((ci.random, ci.key_share), (random, share));
            assert_eq!(ci.sni.as_deref(), Some("www.example.com"));
            assert_eq!(ci.hello, h, "the parser must hand out the exact hello bytes");
        }
        assert!(orders.len() > 1, "extension order must vary between connections");
    }

    #[test]
    fn min_ack_delay_is_stripped_and_garbage_is_left_alone() {
        // id 0x01 len 1 | id 0xff04de1b (> 2^30, so an 8-byte varint) len 2 | id 0x04 len 1
        let mut v = vec![0x01, 0x01, 0x05];
        v.extend_from_slice(&[0xc0, 0, 0, 0, 0xff, 0x04, 0xde, 0x1b, 0x02, 0x47, 0xd0]);
        v.extend_from_slice(&[0x04, 0x01, 0x09]);
        assert_eq!(sanitize_transport_params(&v), vec![0x01, 0x01, 0x05, 0x04, 0x01, 0x09]);
        let truncated = &v[..v.len() - 1];
        assert_eq!(sanitize_transport_params(truncated), truncated.to_vec());
        assert_eq!(sanitize_transport_params(&[]), Vec::<u8>::new());
    }
}

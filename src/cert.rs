//! REALITY temporary certificates.
//!
//! The server mints a throw-away Ed25519 certificate for every authenticated
//! connection and overwrites the 64-byte X.509 signature with
//! `HMAC-SHA512(auth_key, cert_public_key)`. Only a peer that derived the same
//! `auth_key` (i.e. someone who knows the server's static private key) can
//! produce it, so the client can authenticate the server without any CA.
//!
//! The key pair is generated **once per process**, exactly like xtls/reality,
//! which builds its temporary certificate in `init()` and only rewrites the
//! signature slot per connection. Minting a fresh key pair per connection buys
//! nothing (the certificate is never seen by a prober, and the HMAC is what
//! authenticates it) and costs an Ed25519 key generation plus a self-signature
//! on every handshake.
//!
//! Ed25519 is not an accident: the HMAC is exactly 64 bytes wide, the width of
//! an Ed25519 signature, so it drops into the X.509 signature slot without
//! disturbing the DER length fields.  The catch is that a Chrome
//! `signature_algorithms` list does not offer ed25519, so a stock TLS server
//! would refuse to sign the CertificateVerify with the only algorithm this
//! certificate's key supports; see [`ForcedEd25519`].
//!
//! # Certificate size mimicry
//!
//! The reference implementation pads every handshake *record* to the length of
//! the dest's corresponding record, and the dest's certificate is the biggest
//! one by far.  QUIC has no record layer, so the observable unit is the
//! handshake message: a probe of the dest (see [`crate::mimic`]) records the
//! size of its Certificate message, and [`mint`] is asked for a certificate
//! whose DER makes our single-certificate message exactly that long.  The
//! padding rides in an unregistered custom extension (coarse, one DER byte per
//! content byte) plus the serial number length (fine, one byte per byte, no
//! length-field boundary inside 1..=20) - see [`build_padded`].  Templates are
//! cached per target length, so sizing costs a handful of Ed25519 signatures
//! once per (process, length).

use crate::auth;
use anyhow::{anyhow, bail, Result};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use tracing::warn;

/// Reads one DER TLV at `*pos`; returns (tag, content_start, content_end) and
/// advances `*pos` past the element.
fn tlv(d: &[u8], pos: &mut usize) -> Option<(u8, usize, usize)> {
    let tag = *d.get(*pos)?;
    let l0 = *d.get(*pos + 1)?;
    let (len, hdr) = if l0 < 0x80 {
        (l0 as usize, 2)
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || n > 3 {
            return None;
        }
        let mut v = 0usize;
        for i in 0..n {
            v = (v << 8) | *d.get(*pos + 2 + i)? as usize;
        }
        (v, 2 + n)
    };
    let start = *pos + hdr;
    let end = start.checked_add(len)?;
    if end > d.len() {
        return None;
    }
    *pos = end;
    Some((tag, start, end))
}

/// Offsets inside a certificate that REALITY cares about.
struct Layout {
    ed25519_pub: (usize, usize),
    signature: (usize, usize),
}

const ED25519_ALG: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];

/// A REALITY server never lets the client pick the CertificateVerify signature
/// algorithm.
///
/// The temporary certificate is Ed25519, but the client sends a pure Chrome
/// `signature_algorithms` list, which does not include ed25519 - a stock TLS
/// server answers `choose_scheme` with `None` there and aborts the handshake
/// with `no_signature_algorithms_in_common`.  xtls/reality solves the same
/// conflict by hard-wiring `hs.sigAlg = Ed25519` in its patched crypto/tls;
/// with a stock rustls server the equivalent is to answer `choose_scheme` as
/// if ed25519 had been offered.  Nothing is lost: the client is ours, it
/// verifies Ed25519 CertificateVerify messages, and a prober never sees this
/// certificate at all.
#[derive(Debug)]
struct ForcedEd25519(Arc<dyn SigningKey>);

impl SigningKey for ForcedEd25519 {
    fn choose_scheme(
        &self,
        _offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn Signer>> {
        self.0.choose_scheme(&[rustls::SignatureScheme::ED25519])
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.0.algorithm()
    }
}

fn layout(der: &[u8]) -> Option<Layout> {
    let mut p = 0;
    let (t, cert_s, cert_e) = tlv(der, &mut p)?;
    if t != 0x30 || cert_e != der.len() {
        return None;
    }
    let mut c = cert_s;
    let (t, tbs_s, tbs_e) = tlv(der, &mut c)?;
    if t != 0x30 {
        return None;
    }
    let _sigalg = tlv(der, &mut c)?;
    let (t, sig_s, sig_e) = tlv(der, &mut c)?;
    if t != 0x03 || sig_e - sig_s != 65 || der[sig_s] != 0 {
        return None; // not a 64-byte (Ed25519 style) signature
    }

    let mut q = tbs_s;
    let save = q;
    let (t, _, _) = tlv(der, &mut q)?;
    if t != 0xa0 {
        q = save; // no explicit version field
    }
    // serial, signature alg, issuer, validity, subject
    for _ in 0..5 {
        tlv(der, &mut q)?;
    }
    let (t, spki_s, spki_e) = tlv(der, &mut q)?;
    if t != 0x30 || spki_e > tbs_e {
        return None;
    }
    let mut s = spki_s;
    let (t, alg_s, alg_e) = tlv(der, &mut s)?;
    if t != 0x30 || &der[alg_s..alg_e] != ED25519_ALG {
        return None;
    }
    let (t, key_s, key_e) = tlv(der, &mut s)?;
    if t != 0x03 || key_e - key_s != 33 || der[key_s] != 0 {
        return None;
    }
    // NOTE: the parse deliberately stops at the subjectPublicKeyInfo.  The
    // padding extension (if any) sits after it inside the TBSCertificate and
    // must not influence any of the offsets above.
    Some(Layout {
        ed25519_pub: (key_s + 1, key_e),
        signature: (sig_s + 1, sig_e),
    })
}

/// OID of the padding extension: the ISO/IEC 9834 "examples" arc
/// (`joint-iso-itu-t(2) examples(999)`), which is unregistered and carries no
/// semantics.  Nothing parses it - it exists purely to make the certificate
/// DER come out at the dest's length.
const PAD_OID: &[u64] = &[2, 999, 1];

/// Certificates are never larger than this: a dest advertising a bigger
/// Certificate message is misbehaving, and 16 KiB is already a large real one.
const MAX_CERT_LEN: usize = 16 * 1024;

/// How many serial-number bytes the fine-tuning knob may use.  RFC 5280 caps
/// serials at 20 octets, and inside 1..=20 every byte adds exactly one DER
/// byte (the INTEGER length field stays one byte wide, no boundary).
const MAX_SERIAL_LEN: usize = 20;

/// The process-wide throw-away key pair: one Ed25519 key, shared by every
/// certificate template, exactly like the reference's `init()`.
struct ProcessKey {
    key: Arc<dyn SigningKey>,
    /// PKCS#8 DER of the same key, to re-sign a differently sized certificate.
    pkcs8: Vec<u8>,
}

/// One certificate DER of a particular size: the shared key's self-signed
/// certificate, padded to `der.len()` bytes.  Only the signature slot differs
/// per connection, so the DER is cloned and the slot rewritten on every `mint`.
struct Template {
    key: Arc<dyn SigningKey>,
    der: Vec<u8>,
    ed25519_pub: [u8; 32],
    signature: (usize, usize),
}

fn build_process_key() -> Result<ProcessKey> {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .map_err(|e| anyhow!("generate ed25519 key: {e}"))?;
    let pkcs8 = key_pair.serialize_der();
    let signing_key = rustls::crypto::ring::sign::any_eddsa_type(&PrivatePkcs8KeyDer::from(
        pkcs8.clone(),
    ))
    .map_err(|e| anyhow!("signing key: {e}"))?;
    Ok(ProcessKey {
        key: signing_key,
        pkcs8,
    })
}

static PROCESS_KEY: OnceLock<Result<ProcessKey, String>> = OnceLock::new();

fn process_key() -> Result<&'static ProcessKey> {
    PROCESS_KEY
        .get_or_init(|| build_process_key().map_err(|e| e.to_string()))
        .as_ref()
        .map_err(|e| anyhow!("temporary certificate key: {e}"))
}

/// Serial number bytes of exactly `len` octets.  The first byte is 0x01 so the
/// value stays positive and has no leading zero for yasna to strip, and every
/// remaining byte is fixed filler: the serial only has to be a stable length.
fn serial_bytes(len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    v.push(0x01);
    v.resize(len, 0x5a);
    v
}

/// Build one self-signed certificate: `content` bytes of padding extension and
/// a `serial`-byte serial number.
fn build_sized(pk: &ProcessKey, content: usize, serial: usize) -> Result<Template> {
    let key_pair = rcgen::KeyPair::try_from(pk.pkcs8.as_slice())
        .map_err(|e| anyhow!("reload ed25519 key: {e}"))?;
    // No subject alternative names: nothing ever name-checks this certificate
    // (our client verifies the HMAC instead, a prober never sees it), and the
    // reference implementation's temporary certificate carries no name either.
    let mut params = rcgen::CertificateParams::new(Vec::new())
        .map_err(|e| anyhow!("certificate params: {e}"))?;
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial_bytes(serial)));
    if content > 0 {
        // Deterministic filler: the content is never interpreted, it only has
        // to make the extension - and with it the certificate - come out at
        // the requested size.
        let pad: Vec<u8> = (0..content).map(|i| (i as u8).wrapping_mul(31).wrapping_add(7)).collect();
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(PAD_OID, pad));
    }
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| anyhow!("self-sign: {e}"))?;
    let der = cert.der().to_vec();

    let l = layout(&der).ok_or_else(|| anyhow!("unexpected certificate layout"))?;
    let ed25519_pub: [u8; 32] = der[l.ed25519_pub.0..l.ed25519_pub.1]
        .try_into()
        .map_err(|_| anyhow!("bad ed25519 public key"))?;
    Ok(Template {
        key: pk.key.clone(),
        der,
        ed25519_pub,
        signature: l.signature,
    })
}

/// Build a certificate whose DER is exactly `target` bytes long.
///
/// Two knobs, because one is not enough to hit every length: the extension
/// content moves the DER one byte per byte, but its length field (and the
/// length fields of the three structures wrapping it) each grow by one byte
/// at a boundary, which *skips* a handful of target values.  The serial number
/// has no such boundary inside 1..=20 and absorbs whatever the extension
/// cannot express exactly.
fn build_padded(pk: &ProcessKey, target: usize) -> Result<Template> {
    let (mut content, mut serial) = (0usize, 1usize);
    let mut best: Option<(usize, Template)> = None;
    for _ in 0..16 {
        let t = build_sized(pk, content, serial)?;
        let d = t.der.len();
        if d == target {
            return Ok(t);
        }
        let diff = target.abs_diff(d);
        if best.as_ref().is_none_or(|(bd, _)| diff < *bd) {
            best = Some((diff, t));
        }
        let delta = target as isize - d as isize;
        let ns = serial as isize + delta;
        if (1..=MAX_SERIAL_LEN as isize).contains(&ns) {
            // One-for-one: the next build is exact.
            serial = ns as usize;
            continue;
        }
        // The serial is at its limit; push the rest into the extension.
        let room = if delta > 0 {
            MAX_SERIAL_LEN - serial
        } else {
            serial - 1
        } as isize;
        let nc = content as isize + (delta - room);
        if nc < 0 {
            break;
        }
        content = nc as usize;
        serial = if delta > 0 { MAX_SERIAL_LEN } else { 1 };
    }
    match best {
        Some((0, t)) => Ok(t),
        Some((diff, t)) => {
            warn!("certificate length {diff} B off the dest's (target {target} B)");
            Ok(t)
        }
        None => Err(anyhow!("cannot build a certificate")),
    }
}

/// Cache key: `usize::MAX` is the default (minimal) certificate.
fn cache_key(target: Option<usize>) -> usize {
    target.unwrap_or(usize::MAX)
}

static TEMPLATES: std::sync::LazyLock<Mutex<HashMap<usize, Arc<Template>>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

fn template(target: Option<usize>) -> Result<Arc<Template>> {
    let key = cache_key(target);
    {
        let mut map = TEMPLATES.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(t) = map.get(&key) {
            return Ok(t.clone());
        }
        // Build without holding the lock across the (rare) slow path is not
        // worth the complexity: sizing is a handful of signatures, once per
        // target length per process.
        let t = match target {
            None => build_sized(process_key()?, 0, 1)?,
            Some(mut target) => {
                if target > MAX_CERT_LEN {
                    warn!(
                        "dest certificate target {target} B is absurd; clamping to {MAX_CERT_LEN} B"
                    );
                    target = MAX_CERT_LEN;
                }
                build_padded(process_key()?, target)?
            }
        };
        let t = Arc::new(t);
        map.insert(key, t.clone());
        Ok(t)
    }
}

/// Mint the temporary certificate for one connection: the shared key's
/// certificate at `target_len` bytes of DER (`None` = the minimal one), with
/// the REALITY HMAC of `auth_key` in its signature slot.
pub fn mint(auth_key: &[u8; 32], target_len: Option<usize>) -> Result<CertifiedKey> {
    let t = template(target_len)?;
    let mut der = t.der.clone();
    der[t.signature.0..t.signature.1]
        .copy_from_slice(&auth::cert_signature(auth_key, &t.ed25519_pub));
    Ok(CertifiedKey::new(
        vec![CertificateDer::from(der)],
        Arc::new(ForcedEd25519(t.key.clone())),
    ))
}

/// The Ed25519 public key a certificate was minted with.
///
/// The client needs it to check the TLS `CertificateVerify` signature: the
/// certificate authenticates itself with the HMAC, and the signature proves the
/// server holds the matching private key.
pub fn public_key(der: &[u8]) -> Option<[u8; 32]> {
    let l = layout(der)?;
    der[l.ed25519_pub.0..l.ed25519_pub.1].try_into().ok()
}

/// Client side: does this certificate carry a valid REALITY HMAC for `auth_key`?
pub fn check(der: &[u8], auth_key: &[u8; 32]) -> Result<()> {
    let l = layout(der).ok_or_else(|| anyhow!("certificate is not a REALITY certificate"))?;
    let pubkey: [u8; 32] = der[l.ed25519_pub.0..l.ed25519_pub.1].try_into()?;
    if !auth::verify_cert_signature(auth_key, &pubkey, &der[l.signature.0..l.signature.1]) {
        bail!("REALITY certificate signature mismatch");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minted_cert_verifies_only_with_the_same_key() {
        let key = [7u8; 32];
        let ck = mint(&key, None).unwrap();
        let der = ck.cert[0].as_ref();
        check(der, &key).unwrap();
        assert!(check(der, &[8u8; 32]).is_err());
    }

    #[test]
    fn ordinary_certificates_are_rejected() {
        let kp = rcgen::KeyPair::generate().unwrap(); // ECDSA P-256
        let cert = rcgen::CertificateParams::new(vec!["a.example".into()])
            .unwrap()
            .self_signed(&kp)
            .unwrap();
        assert!(check(cert.der(), &[1u8; 32]).is_err());
    }

    #[test]
    fn one_shared_key_per_process_only_the_hmac_differs() {
        let a = mint(&[1u8; 32], None).unwrap();
        let b = mint(&[2u8; 32], None).unwrap();
        // The key pair is process-wide, exactly like the reference's init();
        // only the signature slot - the REALITY HMAC - differs per connection.
        assert_eq!(
            public_key(a.cert[0].as_ref()),
            public_key(b.cert[0].as_ref())
        );
        assert_ne!(a.cert[0].as_ref(), b.cert[0].as_ref());
        check(a.cert[0].as_ref(), &[1u8; 32]).unwrap();
        check(b.cert[0].as_ref(), &[2u8; 32]).unwrap();
        assert!(check(a.cert[0].as_ref(), &[2u8; 32]).is_err());
    }

    #[test]
    fn padded_certificates_hit_the_target_length_exactly() {
        let base = mint(&[3u8; 32], None).unwrap().cert[0].as_ref().len();
        // Targets across the extension's own length-field boundaries, the
        // TBSCertificate boundary (~255) and a realistic site certificate.
        for target in [
            base + 1,
            base + 100,
            base + 300,
            base + 1000,
            2048,
            4096,
            8192,
        ] {
            let ck = mint(&[3u8; 32], Some(target)).unwrap();
            let der = ck.cert[0].as_ref();
            assert_eq!(der.len(), target, "target {target} not hit exactly");
            // The HMAC must still verify, and the parse must still find the
            // same key behind the padding extension.
            check(der, &[3u8; 32]).unwrap();
            assert!(check(der, &[4u8; 32]).is_err());
            assert_eq!(public_key(der), public_key(mint(&[3u8; 32], None).unwrap().cert[0].as_ref()));
        }
    }

    #[test]
    fn absurd_targets_are_clamped_not_fatal() {
        // A dest advertising a 100 KiB Certificate message must not break the
        // handshake; the certificate is clamped to MAX_CERT_LEN.
        let ck = mint(&[5u8; 32], Some(100 * 1024)).unwrap();
        assert_eq!(ck.cert[0].as_ref().len(), MAX_CERT_LEN);
        check(ck.cert[0].as_ref(), &[5u8; 32]).unwrap();
    }

    #[test]
    fn same_target_reuses_one_template() {
        let a = mint(&[9u8; 32], Some(3000)).unwrap();
        let b = mint(&[9u8; 32], Some(3000)).unwrap();
        // Same target: identical bytes except the HMAC slot.
        assert_eq!(a.cert[0].as_ref().len(), b.cert[0].as_ref().len());
        assert_eq!(a.cert[0].as_ref().len(), 3000);
    }
}

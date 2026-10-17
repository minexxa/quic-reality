//! REALITY temporary certificates.
//!
//! The server mints a throw-away Ed25519 certificate for every authenticated
//! connection and overwrites the 64-byte X.509 signature with
//! `HMAC-SHA512(auth_key, cert_public_key)`. Only a peer that derived the same
//! `auth_key` (i.e. someone who knows the server's static private key) can
//! produce it, so the client can authenticate the server without any CA.
//!
//! The key pair and the certificate itself are generated **once per process**,
//! exactly like xtls/reality, which builds its temporary certificate in
//! `init()` and only rewrites the signature slot per connection. Minting a
//! fresh key pair per connection buys nothing (the certificate is never seen
//! by a prober, and the HMAC is what authenticates it) and costs an Ed25519
//! key generation plus a self-signature on every handshake.
//!
//! Ed25519 is not an accident: the HMAC is exactly 64 bytes wide, the width of
//! an Ed25519 signature, so it drops into the X.509 signature slot without
//! disturbing the DER length fields.  The catch is that a Chrome
//! `signature_algorithms` list does not offer ed25519, so a stock TLS server
//! would refuse to sign the CertificateVerify with the only algorithm this
//! certificate's key supports; see [`ForcedEd25519`].

use crate::auth;
use anyhow::{anyhow, bail, Result};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use std::sync::{Arc, OnceLock};

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
    Some(Layout {
        ed25519_pub: (key_s + 1, key_e),
        signature: (sig_s + 1, sig_e),
    })
}

/// The process-wide throw-away certificate: one Ed25519 key pair and the DER
/// of a self-signed certificate for it. Only the signature slot differs per
/// connection, so the DER is cloned and the slot rewritten on every `mint`.
struct Template {
    key: Arc<dyn SigningKey>,
    der: Vec<u8>,
    ed25519_pub: [u8; 32],
    signature: (usize, usize),
}

fn build_template() -> Result<Template> {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .map_err(|e| anyhow!("generate ed25519 key: {e}"))?;
    // No subject alternative names: nothing ever name-checks this certificate
    // (our client verifies the HMAC instead, a prober never sees it), and the
    // reference implementation's temporary certificate carries no name either.
    let params = rcgen::CertificateParams::new(Vec::new())
        .map_err(|e| anyhow!("certificate params: {e}"))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| anyhow!("self-sign: {e}"))?;
    let der = cert.der().to_vec();

    let l = layout(&der).ok_or_else(|| anyhow!("unexpected certificate layout"))?;
    let ed25519_pub: [u8; 32] = der[l.ed25519_pub.0..l.ed25519_pub.1].try_into()?;
    let pkcs8 = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
    let signing_key = rustls::crypto::ring::sign::any_eddsa_type(&pkcs8)
        .map_err(|e| anyhow!("signing key: {e}"))?;
    Ok(Template {
        key: signing_key,
        der,
        ed25519_pub,
        signature: l.signature,
    })
}

static TEMPLATE: OnceLock<Result<Template, String>> = OnceLock::new();

fn template() -> Result<&'static Template> {
    TEMPLATE
        .get_or_init(|| build_template().map_err(|e| e.to_string()))
        .as_ref()
        .map_err(|e| anyhow!("temporary certificate: {e}"))
}

/// Mint the temporary certificate for one connection: the shared DER with the
/// REALITY HMAC of `auth_key` in its signature slot.
pub fn mint(auth_key: &[u8; 32]) -> Result<CertifiedKey> {
    let t = template()?;
    let mut der = t.der.clone();
    der[t.signature.0..t.signature.1].copy_from_slice(&auth::cert_signature(auth_key, &t.ed25519_pub));
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
        let ck = mint(&key).unwrap();
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
        let a = mint(&[1u8; 32]).unwrap();
        let b = mint(&[2u8; 32]).unwrap();
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
}

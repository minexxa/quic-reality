//! REALITY temporary certificates.
//!
//! The server mints a throw-away Ed25519 certificate for every authenticated
//! connection and overwrites the 64-byte X.509 signature with
//! `HMAC-SHA512(auth_key, cert_public_key)`. Only a peer that derived the same
//! `auth_key` (i.e. someone who knows the server's static private key) can
//! produce it, so the client can authenticate the server without any CA.

use crate::auth;
use anyhow::{anyhow, bail, Result};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;

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

/// Mint the temporary certificate (and its signing key) for one connection.
pub fn mint(auth_key: &[u8; 32], server_name: &str) -> Result<CertifiedKey> {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .map_err(|e| anyhow!("generate ed25519 key: {e}"))?;
    let params = rcgen::CertificateParams::new(vec![server_name.to_string()])
        .map_err(|e| anyhow!("certificate params: {e}"))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| anyhow!("self-sign: {e}"))?;
    let mut der = cert.der().to_vec();

    let l = layout(&der).ok_or_else(|| anyhow!("unexpected certificate layout"))?;
    let pubkey: [u8; 32] = der[l.ed25519_pub.0..l.ed25519_pub.1].try_into()?;
    let sig = auth::cert_signature(auth_key, &pubkey);
    der[l.signature.0..l.signature.1].copy_from_slice(&sig);

    let pkcs8 = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
    let signing_key = rustls::crypto::ring::sign::any_eddsa_type(&pkcs8)
        .map_err(|e| anyhow!("signing key: {e}"))?;
    Ok(CertifiedKey::new(vec![CertificateDer::from(der)], signing_key))
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
        let ck = mint(&key, "www.example.com").unwrap();
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
    fn every_cert_has_a_fresh_key() {
        let key = [1u8; 32];
        let a = mint(&key, "a.example").unwrap();
        let b = mint(&key, "a.example").unwrap();
        assert_ne!(a.cert[0].as_ref(), b.cert[0].as_ref());
    }
}

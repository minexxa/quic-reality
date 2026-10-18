//! Length-matching NewSessionTickets.
//!
//! The reference implementation probes the dest's post-handshake
//! NewSessionTicket records once at startup (`record_detect.go`) and, after
//! authenticating a client, emits tickets padded to the recorded lengths so the
//! post-handshake CRYPTO traffic matches the dest's (`tls.go`).
//!
//! QUIC has no record layer, so the observable unit is the handshake message:
//! a probe of the dest (see [`crate::mimic`]) records the size of each of its
//! NewSessionTicket *messages*, and [`PaddedTicketer`] hands rustls tickets
//! that make our messages come out exactly as long.  A rustls NewSessionTicket
//! message is
//!
//! ```text
//! 4  handshake header   4  lifetime   4  age_add
//! 1  nonce length      32  nonce      2  ticket length
//! 2  extensions length  N  ticket
//! ```
//!
//! i.e. `ticket = message_len - 49`, and the ticket is the only variable part.
//!
//! # Ticket framing
//!
//! The ticket itself is sealed with a process-wide AES-256-GCM key and padded
//! with zeros to the target length:
//!
//! ```text
//! 12  nonce   2  ciphertext length (big endian, outside the AEAD)   AEAD ciphertext + tag   zero padding
//! ```
//!
//! The length prefix has to stay outside the ciphertext: a decryptor must be
//! able to tell ciphertext from padding without already having decrypted.
//! Tickets are only ever consumed by this same process (a QUIC client never
//! resumes, and the REALITY client does not carry tickets either), so the
//! decrypt half exists for completeness and is unit-tested directly.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::server::ProducesTickets;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use tracing::warn;

/// Bytes of a NewSessionTicket handshake message that are not the ticket:
/// 4 (handshake header) + 4 (lifetime) + 4 (age_add) + 1 (nonce length) + 32
/// (nonce) + 2 (ticket length) + 2 (extensions length).
pub const NST_OVERHEAD: usize = 49;

/// `nonce(12) || ct_len(2)` - our framing around the AEAD output.
const FRAMING: usize = 14;
/// AES-GCM tag.
const TAG: usize = 16;

fn seal(key: &LessSafeKey, nonce: &[u8; 12], plain: &[u8]) -> Vec<u8> {
    let mut buf = plain.to_vec();
    key.seal_in_place_separate_tag(
        Nonce::assume_unique_for_key(*nonce),
        Aad::empty(),
        &mut buf,
    )
    .map(|tag| {
        buf.extend_from_slice(tag.as_ref());
        buf
    })
    .expect("sealing a ticket cannot fail")
}

fn open(key: &LessSafeKey, nonce: &[u8; 12], cipher: &[u8]) -> Option<Vec<u8>> {
    let mut buf = cipher.to_vec();
    let n = key
        .open_in_place(Nonce::assume_unique_for_key(*nonce), Aad::empty(), &mut buf)
        .ok()?
        .len();
    buf.truncate(n);
    Some(buf)
}

fn ticket_key() -> &'static LessSafeKey {
    static KEY: OnceLock<LessSafeKey> = OnceLock::new();
    KEY.get_or_init(|| {
        let rng = SystemRandom::new();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes).expect("system RNG cannot fail");
        LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &bytes).expect("AES-256-GCM accepts a 32-byte key"))
    })
}

/// A rustls ticketer whose tickets are padded to the dest's ticket sizes.
pub struct PaddedTicketer {
    lifetime: u32,
    /// NewSessionTicket message lengths still to emit, in the dest's order.
    targets: Mutex<VecDeque<usize>>,
    /// Warn once per process when a target is too small to pad to.
    warned: AtomicBool,
}

impl std::fmt::Debug for PaddedTicketer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PaddedTicketer")
            .field("lifetime", &self.lifetime)
            .finish_non_exhaustive()
    }
}

impl PaddedTicketer {
    /// `targets` are the dest's NewSessionTicket *message* lengths, in order;
    /// rustls calls `encrypt` once per configured ticket.
    pub fn new(targets: Vec<usize>, lifetime: u32) -> Self {
        Self {
            lifetime,
            targets: Mutex::new(targets.into_iter().collect()),
            warned: AtomicBool::new(false),
        }
    }
}

impl ProducesTickets for PaddedTicketer {
    fn enabled(&self) -> bool {
        true
    }

    fn lifetime(&self) -> u32 {
        self.lifetime
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        let mut nonce = [0u8; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .expect("system RNG cannot fail");
        let ct = seal(ticket_key(), &nonce, plain);
        let unpadded = FRAMING + ct.len();

        // The next ticket to emit - and the message length it must produce.
        let target = self
            .targets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop_front();
        let Some(ticket_len) = target.map(|t| t.saturating_sub(NST_OVERHEAD)) else {
            // No recorded length left (or an absurd one): emit unpadded rather
            // than skipping the ticket - the *count* is part of the shape.
            return Some(blob(nonce, ct, unpadded));
        };
        if ticket_len < unpadded {
            if self
                .warned
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                warn!(
                    "dest ticket length {} B cannot be matched (ours is at least {unpadded} B); sending unpadded",
                    ticket_len + NST_OVERHEAD
                );
            }
            return Some(blob(nonce, ct, unpadded));
        }
        Some(blob(nonce, ct, ticket_len))
    }

    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        if cipher.len() < FRAMING + TAG {
            return None;
        }
        let ct_len = u16::from_be_bytes([cipher[12], cipher[13]]) as usize;
        let end = FRAMING.checked_add(ct_len)?;
        if end > cipher.len() {
            return None;
        }
        let nonce: [u8; 12] = cipher[..12].try_into().ok()?;
        open(ticket_key(), &nonce, &cipher[FRAMING..end])
    }
}

fn blob(nonce: [u8; 12], ct: Vec<u8>, total: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&(ct.len() as u16).to_be_bytes());
    out.extend_from_slice(&ct);
    out.resize(total, 0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ticketer(targets: Vec<usize>) -> PaddedTicketer {
        PaddedTicketer::new(targets, 7200)
    }

    #[test]
    fn round_trip_through_padding() {
        let t = ticketer(vec![400]);
        let plain = b"server session state that is quite a bit longer than the ticket framing around it";
        let ticket = t.encrypt(plain).unwrap();
        // 400-byte message - 49 fixed = 351-byte ticket.
        assert_eq!(ticket.len(), 400 - NST_OVERHEAD);
        assert_eq!(t.decrypt(&ticket).unwrap(), plain);
        // The padding is zeros and carries no data.
        let ct_len = u16::from_be_bytes([ticket[12], ticket[13]]) as usize;
        assert!(ticket[FRAMING + ct_len..].iter().all(|b| *b == 0));
    }

    #[test]
    fn tickets_come_out_at_the_recorded_lengths_in_order() {
        let t = ticketer(vec![210, 305, 512]);
        let a = t.encrypt(b"state-a").unwrap();
        let b = t.encrypt(b"state-b").unwrap();
        let c = t.encrypt(b"state-c").unwrap();
        assert_eq!((a.len(), b.len(), c.len()), (210 - NST_OVERHEAD, 305 - NST_OVERHEAD, 512 - NST_OVERHEAD));
        // A fourth ticket has no recorded length: unpadded, but still sent.
        let d = t.encrypt(b"state-d").unwrap();
        assert!(d.len() < 210 - NST_OVERHEAD);
        assert_eq!(t.decrypt(&d).unwrap(), b"state-d");
    }

    #[test]
    fn tiny_targets_are_not_fatal() {
        // A dest NST smaller than our minimum ticket: the ticket is still
        // emitted (the count is part of the shape), just unpadded.
        let t = ticketer(vec![30]);
        let ticket = t.encrypt(b"state").unwrap();
        assert!(ticket.len() >= FRAMING + b"state".len() + TAG);
        assert_eq!(t.decrypt(&ticket).unwrap(), b"state");
    }

    #[test]
    fn garbage_fails_closed() {
        let t = ticketer(vec![400]);
        assert!(t.decrypt(&[]).is_none());
        assert!(t.decrypt(&[0u8; 40]).is_none());
        let ticket = t.encrypt(b"state").unwrap();
        let mut flipped = ticket.clone();
        *flipped.last_mut().unwrap() ^= 0xff; // corrupt the padding - fine
        assert_eq!(t.decrypt(&flipped).unwrap(), b"state");
        let mut ct = ticket.clone();
        ct[FRAMING] ^= 0xff; // corrupt the ciphertext
        assert!(t.decrypt(&ct).is_none());
        // A ciphertext length that runs past the ticket.
        let mut lying = ticket.clone();
        lying[12] = 0xff;
        lying[13] = 0xff;
        assert!(t.decrypt(&lying).is_none());
    }

    #[test]
    fn lifetime_comes_from_the_dest() {
        assert_eq!(ticketer(vec![300]).lifetime(), 7200);
        assert_eq!(PaddedTicketer::new(vec![], 60).lifetime(), 60);
    }
}

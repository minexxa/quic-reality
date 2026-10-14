//! Hysteria Salamander per-packet obfuscation (ported from hysteria-rust).
//!
//! Packet format: salt(8) || XOR(payload, BLAKE2b-256(password || salt))

use blake2::{Blake2bVar, digest::{Update, VariableOutput}};
use rand::RngCore;
use std::fmt;

pub const SALT_LENGTH: usize = 8;
const KEY_LENGTH: usize = 32;
const MIN_PASSWORD_LENGTH: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SalamanderError {
    PasswordTooShort,
    PacketTooShort,
}

impl fmt::Display for SalamanderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PasswordTooShort => write!(f, "password must be at least {MIN_PASSWORD_LENGTH} bytes"),
            Self::PacketTooShort => write!(f, "packet must contain {SALT_LENGTH}-byte salt + payload"),
        }
    }
}

impl std::error::Error for SalamanderError {}

#[derive(Debug, Clone)]
pub struct Salamander {
    password: Box<[u8]>,
}

impl Salamander {
    pub fn new(password: impl AsRef<[u8]>) -> Result<Self, SalamanderError> {
        let password = password.as_ref();
        if password.len() < MIN_PASSWORD_LENGTH {
            return Err(SalamanderError::PasswordTooShort);
        }
        Ok(Self { password: password.into() })
    }

    fn packet_key(&self, salt: &[u8; SALT_LENGTH]) -> [u8; KEY_LENGTH] {
        let mut hasher = Blake2bVar::new(KEY_LENGTH).expect("blake2b");
        hasher.update(&self.password);
        hasher.update(salt);
        let mut key = [0u8; KEY_LENGTH];
        hasher.finalize_variable(&mut key).expect("finalize");
        key
    }

    /// Prepend salt and XOR payload.
    pub fn obfuscate(&self, payload: &[u8]) -> Vec<u8> {
        let mut salt = [0u8; SALT_LENGTH];
        rand::thread_rng().fill_bytes(&mut salt);
        let key = self.packet_key(&salt);
        let mut output = Vec::with_capacity(SALT_LENGTH + payload.len());
        output.extend_from_slice(&salt);
        output.extend(
            payload
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ key[i % KEY_LENGTH]),
        );
        output
    }

    /// Strip salt and reverse XOR.
    pub fn deobfuscate(&self, packet: &[u8]) -> Result<Vec<u8>, SalamanderError> {
        if packet.len() <= SALT_LENGTH {
            return Err(SalamanderError::PacketTooShort);
        }
        let mut salt = [0u8; SALT_LENGTH];
        salt.copy_from_slice(&packet[..SALT_LENGTH]);
        let key = self.packet_key(&salt);
        let payload = &packet[SALT_LENGTH..];
        Ok(payload
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % KEY_LENGTH])
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let s = Salamander::new(b"test-password").unwrap();
        let plain = b"hello quic-reality packet";
        let ob = s.obfuscate(plain);
        let de = s.deobfuscate(&ob).unwrap();
        assert_eq!(de, plain);
    }
}

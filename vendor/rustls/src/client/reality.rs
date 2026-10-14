//! quic-reality fork: REALITY-style ClientHello modification hook.
//!
//! REALITY authentication embeds an AEAD-sealed header in the 32-byte legacy
//! session id of the ClientHello. This module provides the hook that lets an
//! application compute and install that session id just before the ClientHello
//! is encoded.
//!
//! The sealed header layout (see `quic-reality` crate `reality.rs`):
//!
//! ```text
//! version(3) || reserved(1) || timestamp_be32(4) || short_id(8)   = 16 bytes
//! session_id = AES-128-GCM(sealing_key, nonce, aad=raw_client_hello, header) || tag
//! ```
//!
//! where `sealing_key = HKDF-SHA256(salt=client_random[..20], ikm=reality_key,
//! info="REALITY")`, `nonce = client_random[20..32]` and `reality_key` is the
//! X25519 shared secret between the client's in-progress key exchange and the
//! server's static public key.

use crate::crypto::ActiveKeyExchange;
use crate::error::Error;
use core::fmt;

use pki_types::ServerName;

/// Context handed to a [`ClientHelloCallback`] after the ClientHello payload has
/// been assembled but before it is encoded onto the wire.
pub struct ClientHelloCallbackContext<'a> {
    /// The SNI this connection is using.
    pub server_name: &'a ServerName<'static>,
    /// The 32-byte ClientHello random.
    pub client_random: &'a [u8; 32],
    /// The in-progress key exchange, if a key share was offered.
    pub active_key_exchange: Option<&'a dyn ActiveKeyExchange>,
    /// The encoded ClientHello handshake message with the session id field
    /// zeroed (used as AEAD associated data).
    pub raw_client_hello: &'a [u8],
    /// Whether this hello is a retry after a HelloRetryRequest.
    pub is_retry: bool,
    /// Output slot filled by [`ClientHelloCallbackContext::set_session_id`].
    pub(crate) session_id: Option<[u8; 32]>,
}

impl ClientHelloCallbackContext<'_> {
    /// Sets the 32-byte legacy session id to place in the ClientHello.
    pub fn set_session_id(&mut self, session_id: &[u8]) -> Result<(), Error> {
        let bytes: [u8; 32] = session_id
            .try_into()
            .map_err(|_| Error::General("session id must be exactly 32 bytes".into()))?;
        self.session_id = Some(bytes);
        Ok(())
    }
}

impl fmt::Debug for ClientHelloCallbackContext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientHelloCallbackContext")
            .field("server_name", &self.server_name)
            .field("is_retry", &self.is_retry)
            .field("has_key_exchange", &self.active_key_exchange.is_some())
            .field("raw_client_hello_len", &self.raw_client_hello.len())
            .finish()
    }
}

/// Callback invoked once per ClientHello, after the payload is built and before
/// it is encoded. Used by REALITY-style clients to install the sealed
/// authentication session id.
pub trait ClientHelloCallback: fmt::Debug + Send + Sync {
    /// Inspect and optionally modify the ClientHello.
    fn modify_client_hello(&self, hello: &mut ClientHelloCallbackContext<'_>) -> Result<(), Error>;
}

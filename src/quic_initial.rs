//! QUIC v1 Initial packet decryption and ClientHello extraction.
//!
//! The gateway needs to look inside the client's very first packet *before*
//! letting quinn see it: the REALITY session id lives in the TLS ClientHello,
//! which rides in a CRYPTO frame inside the Initial. That means implementing
//! the QUIC initial key schedule (RFC 9001 §5.2), header-protection removal
//! (§5.4), and payload decryption (§5.3) for the client→server direction.
//!
//! Only what is needed to reach the ClientHello is implemented; anything that
//! is not a decryptable v1 Initial is reported as `NotInitial` so the gateway
//! can relay the datagram to the real destination.

use ring::aead::{quic, Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use ring::hmac;

/// RFC 9001 §5.2 initial salt for QUIC v1.
const INITIAL_SALT_V1: &[u8] = &[
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

const QUIC_VERSION_1: u32 = 0x0000_0001;
const MAX_DATAGRAM: usize = 2048;

#[derive(Debug)]
pub enum ParseError {
    TooShort,
    NotALongHeader,
    UnsupportedVersion(u32),
    BadConnectionId,
    BadLength,
    HeaderProtection,
    Decrypt,
    BadFrame(&'static str),
    NoClientHello,
    ClientHelloTruncated,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "datagram too short"),
            Self::NotALongHeader => write!(f, "not a QUIC long header"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported QUIC version {v:#x}"),
            Self::BadConnectionId => write!(f, "malformed connection id"),
            Self::BadLength => write!(f, "malformed packet length"),
            Self::HeaderProtection => write!(f, "header protection removal failed"),
            Self::Decrypt => write!(f, "payload decryption failed"),
            Self::BadFrame(m) => write!(f, "malformed frame: {m}"),
            Self::NoClientHello => write!(f, "Initial carried no ClientHello"),
            Self::ClientHelloTruncated => write!(f, "ClientHello incomplete"),
        }
    }
}

impl std::error::Error for ParseError {}

/// A decrypted QUIC v1 Initial packet (client→server direction).
#[derive(Debug)]
pub struct InitialPacket {
    pub dest_cid: Vec<u8>,
    pub src_cid: Vec<u8>,
    pub version: u32,
    pub packet_number: u64,
    /// Decrypted frames (PN + ciphertext, header protection removed).
    pub payload: Vec<u8>,
    /// Full wire bytes of this packet inside the datagram.
    pub wire: Vec<u8>,
}

/// ClientHello fields the gateway needs for REALITY verification.
#[derive(Debug)]
pub struct ClientHello {
    /// Complete ClientHello handshake message (type + len + body).
    pub message: Vec<u8>,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub x25519_key_share: Option<Vec<u8>>,
    pub sni: Option<String>,
    /// `message` with the session id bytes zeroed — the REALITY AEAD aad.
    pub zeroed_sid_message: Vec<u8>,
}

/// Parses and (if possible) decrypts the first Initial packet of a datagram.
///
/// Handles coalesced datagrams: the first v1 Initial wins; trailing packets
/// are ignored (they belong to the same connection and will be handled by
/// quinn after admission).
pub fn decrypt_initial(datagram: &[u8]) -> Result<Option<InitialPacket>, ParseError> {
    if datagram.len() < 7 {
        return Err(ParseError::TooShort);
    }
    let mut offset = 0usize;
    while offset < datagram.len() {
        match parse_one(datagram, offset)? {
            OnePacket::Initial(pkt) => return Ok(Some(pkt)),
            OnePacket::Skip(end) => offset = end,
            OnePacket::Stop => return Ok(None),
        }
    }
    Ok(None)
}

enum OnePacket {
    Initial(InitialPacket),
    Skip(usize),
    Stop,
}

fn parse_one(datagram: &[u8], offset: usize) -> Result<OnePacket, ParseError> {
    let buf = &datagram[offset..];
    if buf.is_empty() {
        return Ok(OnePacket::Stop);
    }
    let first = buf[0];
    if first & 0x80 == 0 {
        // Short header: not an Initial. Stop scanning.
        return Ok(OnePacket::Stop);
    }
    if buf.len() < 1 + 4 + 1 {
        return Err(ParseError::TooShort);
    }
    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    if version != QUIC_VERSION_1 {
        return Ok(OnePacket::Stop); // v2/draft/negotiation: let quinn handle it
    }
    let mut p = 1 + 4;
    let dcid_len = *buf.get(p).ok_or(ParseError::TooShort)? as usize;
    p += 1;
    if dcid_len > 20 || buf.len() < p + dcid_len {
        return Err(ParseError::BadConnectionId);
    }
    let dest_cid = buf[p..p + dcid_len].to_vec();
    p += dcid_len;
    let scid_len = *buf.get(p).ok_or(ParseError::TooShort)? as usize;
    p += 1;
    if scid_len > 20 || buf.len() < p + scid_len {
        return Err(ParseError::BadConnectionId);
    }
    let src_cid = buf[p..p + scid_len].to_vec();
    p += scid_len;

    // Initial-only: token length (varint)
    let (token_len, mut p) = read_varint(buf, p).ok_or(ParseError::TooShort)?;
    let token_len = token_len as usize;
    p = p
        .checked_add(token_len)
        .filter(|end| *end <= buf.len())
        .ok_or(ParseError::TooShort)?;
    // packet length (varint) — covers PN + payload
    let (length, p) = read_varint(buf, p).ok_or(ParseError::BadLength)?;
    let length = length as usize;
    if length < 4 + 16 || p + length > buf.len() {
        return Err(ParseError::BadLength);
    }
    let packet_end = p + length;
    let header_len = p; // up to and including the length field

    // The packet number starts at `p`; its real length hides behind header
    // protection. Derive the client initial keys from the destination cid.
    let keys = InitialKeys::new(&dest_cid);

    // Sample for HP removal: 4 bytes after the start of the PN field.
    if p + 4 + 16 > packet_end {
        return Err(ParseError::HeaderProtection);
    }
    let sample = &buf[p + 4..p + 4 + 16];
    let mask = keys
        .hp
        .new_mask(sample)
        .map_err(|_| ParseError::HeaderProtection)?;

    let mut first_byte = buf[0];
    first_byte ^= mask[0] & 0x0f;
    let pn_len = ((first_byte & 0x03) + 1) as usize;
    if p + pn_len > packet_end {
        return Err(ParseError::HeaderProtection);
    }

    // Reconstruct the PN with protection removed.
    let mut pn_bytes = [0u8; 4];
    for i in 0..pn_len {
        pn_bytes[pn_len - 1 - i] = buf[p + i] ^ mask[1 + i];
    }
    let packet_number = u32::from_be_bytes(pn_bytes) as u64;

    // AAD = the packet header with the real (decrypted) PN in place.
    let mut aad = buf[..header_len].to_vec();
    aad[0] = first_byte;
    for i in 0..pn_len {
        aad.push(pn_bytes[pn_len - 1 - i]);
    }

    // Nonce = iv XOR packet number (u64 big-endian, right aligned in 12 bytes).
    let mut nonce_bytes = keys.iv;
    let pn_be = packet_number.to_be_bytes();
    for i in 0..8 {
        nonce_bytes[4 + i] ^= pn_be[i];
    }

    let ciphertext = &buf[p + pn_len..packet_end];
    if ciphertext.len() < 16 {
        return Err(ParseError::Decrypt);
    }
    let mut in_out = ciphertext.to_vec();
    let key = UnboundKey::new(&AES_128_GCM, &keys.key).map_err(|_| ParseError::Decrypt)?;
    let plaintext = LessSafeKey::new(key)
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(&aad[..]),
            &mut in_out,
        )
        .map_err(|_| ParseError::Decrypt)?
        .to_vec();

    let mut wire = buf[..packet_end].to_vec();
    wire[0] = first_byte;
    for i in 0..pn_len {
        wire[p + i] = pn_bytes[pn_len - 1 - i];
    }

    Ok(OnePacket::Initial(InitialPacket {
        dest_cid,
        src_cid,
        version,
        packet_number,
        payload: plaintext,
        wire,
    }))
}

/// Extracts the first ClientHello from a decrypted Initial payload.
pub fn extract_client_hello(payload: &[u8]) -> Result<ClientHello, ParseError> {
    let mut crypto: Option<Vec<u8>> = None;
    let mut offset = 0usize;
    let mut crypto_offset: u64 = 0;
    while offset < payload.len() {
        let frame_type = payload[offset];
        if frame_type == 0x00 {
            offset += 1; // PADDING
            continue;
        }
        offset += 1;
        if frame_type == 0x06 {
            // CRYPTO
            let (off, o1) =
                read_varint(payload, offset).ok_or(ParseError::BadFrame("crypto offset"))?;
            let (len, o2) =
                read_varint(payload, o1).ok_or(ParseError::BadFrame("crypto length"))?;
            let len = len as usize;
            if o2 + len > payload.len() {
                return Err(ParseError::BadFrame("crypto overrun"));
            }
            if crypto_offset <= off {
                crypto_offset = off;
                crypto = Some(payload[o2..o2 + len].to_vec());
            }
            offset = o2 + len;
        } else if frame_type == 0x01 || frame_type == 0x04 {
            // ACK / ACK_ECN: largest ack, ack delay, ack range count, [first range]
            let (_largest, o1) =
                read_varint(payload, offset).ok_or(ParseError::BadFrame("ack"))?;
            let (_delay, o2) = read_varint(payload, o1).ok_or(ParseError::BadFrame("ack"))?;
            let (range_count, o3) =
                read_varint(payload, o2).ok_or(ParseError::BadFrame("ack"))?;
            let (_first, o4) = read_varint(payload, o3).ok_or(ParseError::BadFrame("ack"))?;
            let mut o = o4;
            for _ in 0..range_count {
                let (_gap, oa) = read_varint(payload, o).ok_or(ParseError::BadFrame("ack"))?;
                let (_len, ob) = read_varint(payload, oa).ok_or(ParseError::BadFrame("ack"))?;
                o = ob;
            }
            offset = o;
        } else {
            // Any other frame: bail — for the first flight the only frames are
            // PADDING, CRYPTO, ACK. Unknown frames mean we cannot safely locate
            // the ClientHello; treat as "no ClientHello".
            return Err(ParseError::BadFrame("unsupported frame in first flight"));
        }
    }

    let crypto = crypto.ok_or(ParseError::NoClientHello)?;
    parse_client_hello(&crypto, crypto_offset)
}

/// Parses a TLS ClientHello handshake message out of (possibly offset) CRYPTO data.
fn parse_client_hello(data: &[u8], stream_offset: u64) -> Result<ClientHello, ParseError> {
    // The ClientHello must start at the beginning of the crypto stream; a
    // non-zero offset means we have not collected from byte 0.
    if stream_offset != 0 {
        return Err(ParseError::ClientHelloTruncated);
    }
    let buf = data;
    if buf.len() < 4 || buf[0] != 0x01 {
        return Err(ParseError::NoClientHello);
    }
    let hs_len = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | buf[3] as usize;
    if 4 + hs_len > buf.len() {
        return Err(ParseError::ClientHelloTruncated);
    }
    let body = &buf[4..4 + hs_len];
    let mut o = 2; // client_version
    if body.len() < o + 32 {
        return Err(ParseError::ClientHelloTruncated);
    }
    let mut random = [0u8; 32];
    random.copy_from_slice(&body[o..o + 32]);
    o += 32;

    let sid_len = *body.get(o).ok_or(ParseError::ClientHelloTruncated)? as usize;
    o += 1;
    if body.len() < o + sid_len {
        return Err(ParseError::ClientHelloTruncated);
    }
    let session_id = body[o..o + sid_len].to_vec();
    let sid_offset_in_body = o;
    o += sid_len;

    // cipher suites
    let cs_len = read_u16(body, o).ok_or(ParseError::ClientHelloTruncated)? as usize;
    o += 2 + cs_len;
    // compression methods
    let cm_len = *body.get(o).ok_or(ParseError::ClientHelloTruncated)? as usize;
    o += 1 + cm_len;
    if body.len() < o + 2 {
        return Err(ParseError::ClientHelloTruncated);
    }
    let ext_len = read_u16(body, o).ok_or(ParseError::ClientHelloTruncated)? as usize;
    o += 2;
    if body.len() < o + ext_len {
        return Err(ParseError::ClientHelloTruncated);
    }
    let extensions = &body[o..o + ext_len];

    let mut key_share = None;
    let mut sni = None;
    let mut eo = 0usize;
    while eo + 4 <= extensions.len() {
        let ext_type = read_u16(extensions, eo).ok_or(ParseError::ClientHelloTruncated)?;
        let elen = read_u16(extensions, eo + 2).ok_or(ParseError::ClientHelloTruncated)? as usize;
        if eo + 4 + elen > extensions.len() {
            return Err(ParseError::ClientHelloTruncated);
        }
        let ext = &extensions[eo + 4..eo + 4 + elen];
        match ext_type {
            0x0000 => sni = parse_sni(ext),
            0x0033 => key_share = parse_x25519_key_share(ext),
            _ => {}
        }
        eo += 4 + elen;
    }

    let mut zeroed = buf[..4 + hs_len].to_vec();
    let zero_start = 4 + sid_offset_in_body;
    if zero_start + sid_len <= zeroed.len() {
        zeroed[zero_start..zero_start + sid_len].fill(0);
    }

    Ok(ClientHello {
        message: buf[..4 + hs_len].to_vec(),
        random,
        session_id,
        x25519_key_share: key_share,
        sni,
        zeroed_sid_message: zeroed,
    })
}

fn parse_sni(ext: &[u8]) -> Option<String> {
    let mut o = 0usize;
    let list_len = read_u16(ext, o)? as usize;
    o += 2;
    if o + list_len > ext.len() {
        return None;
    }
    let list = &ext[o..o + list_len];
    let mut lo = 0usize;
    while lo + 3 <= list.len() {
        let name_type = list[lo];
        let name_len = read_u16(list, lo + 1)? as usize;
        if lo + 3 + name_len > list.len() {
            return None;
        }
        if name_type == 0 {
            let name = std::str::from_utf8(&list[lo + 3..lo + 3 + name_len]).ok()?;
            return Some(name.to_ascii_lowercase());
        }
        lo += 3 + name_len;
    }
    None
}

fn parse_x25519_key_share(ext: &[u8]) -> Option<Vec<u8>> {
    let mut o = 0usize;
    let shares_len = read_u16(ext, o)? as usize;
    o += 2;
    if o + shares_len > ext.len() {
        return None;
    }
    let shares = &ext[o..o + shares_len];
    let mut so = 0usize;
    while so + 4 <= shares.len() {
        let group = read_u16(shares, so)?;
        let len = read_u16(shares, so + 2)? as usize;
        if so + 4 + len > shares.len() {
            return None;
        }
        if group == 0x001d {
            return Some(shares[so + 4..so + 4 + len].to_vec());
        }
        so += 4 + len;
    }
    None
}

fn read_u16(buf: &[u8], at: usize) -> Option<u16> {
    if at + 2 > buf.len() {
        return None;
    }
    Some(u16::from_be_bytes([buf[at], buf[at + 1]]))
}

/// Reads a QUIC variable-length integer (RFC 9000 §16).
pub fn read_varint(buf: &[u8], at: usize) -> Option<(u64, usize)> {
    if at >= buf.len() {
        return None;
    }
    let first = buf[at];
    let len = 1usize << (first >> 6);
    if at + len > buf.len() {
        return None;
    }
    let mut value = (first & 0x3f) as u64;
    for i in 1..len {
        value = (value << 8) | buf[at + i] as u64;
    }
    Some((value, at + len))
}

/// QUIC v1 client initial keys (client→server direction).
pub struct InitialKeys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: quic::HeaderProtectionKey,
    hp_key: [u8; 16],
}

impl InitialKeys {
    pub fn new(dest_cid: &[u8]) -> Self {
        // initial_secret = HKDF-Extract(salt, dcid)
        let initial_secret = hkdf_extract(INITIAL_SALT_V1, dest_cid);
        // client initial secret = Expand-Label(initial_secret, "client in", "")
        let mut client_secret = [0u8; 32];
        expand_label(&initial_secret, "client in", &mut client_secret);

        let mut key = [0u8; 16];
        expand_label(&client_secret, "quic key", &mut key);
        let mut iv = [0u8; 12];
        expand_label(&client_secret, "quic iv", &mut iv);
        let mut hp = [0u8; 16];
        expand_label(&client_secret, "quic hp", &mut hp);

        let hp_key = quic::HeaderProtectionKey::new(&quic::AES_128, &hp)
            .expect("16 bytes is a valid AES-128 key");
        Self {
            key,
            iv,
            hp: hp_key,
            hp_key: hp,
        }
    }

    /// Test-only accessor for the raw header-protection key bytes.
    pub fn hp_key_bytes_for_test(&self) -> &[u8; 16] {
        &self.hp_key
    }
}

/// HKDF-Extract(salt, ikm) = HMAC-Hash(salt, ikm).
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    let tag = hmac::sign(&key, ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// HKDF-Expand(prk, info, len).
fn hkdf_expand(prk: &[u8], info: &[u8], out: &mut [u8]) {
    let key = hmac::Key::new(hmac::HMAC_SHA256, prk);
    let mut block: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    let mut written = 0usize;
    while written < out.len() {
        let mut msg = block.clone();
        msg.extend_from_slice(info);
        msg.push(counter);
        let tag = hmac::sign(&key, &msg);
        block = tag.as_ref().to_vec();
        let take = (out.len() - written).min(block.len());
        out[written..written + take].copy_from_slice(&block[..take]);
        written += take;
        counter = counter.wrapping_add(1);
    }
}

/// QUIC/TLS HKDF-Expand-Label (RFC 9001 §5.1).
fn expand_label(secret: &[u8], label: &str, out: &mut [u8]) {
    let mut full_label = b"tls13 ".to_vec();
    full_label.extend_from_slice(label.as_bytes());
    let mut info = Vec::with_capacity(4 + full_label.len() + 1);
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(&full_label);
    info.push(0); // empty context
    hkdf_expand(secret, &info, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// QUIC variable-length integer encoder (test helper).
    fn put_varint(out: &mut Vec<u8>, value: u64) {
        if value < 64 {
            out.push(value as u8);
        } else if value < 16384 {
            out.push(0x40 | ((value >> 8) as u8));
            out.push((value & 0xff) as u8);
        } else if value < (1 << 30) {
            out.push(0x80 | ((value >> 24) as u8));
            out.push(((value >> 16) & 0xff) as u8);
            out.push(((value >> 8) & 0xff) as u8);
            out.push((value & 0xff) as u8);
        } else {
            out.push(0xc0);
            for i in 0..8 {
                out.push(((value >> (56 - 8 * i)) & 0xff) as u8);
            }
        }
    }

    /// Builds a minimal but complete v1 Initial carrying a ClientHello with the
    /// given session id, and returns (datagram, expected random, key share used).
    fn build_initial(
        client_scalar: [u8; 32],
        session_id: &[u8],
        dcid: &[u8],
        scid: &[u8],
    ) -> (Vec<u8>, [u8; 32], Vec<u8>) {
        use x25519_dalek::{PublicKey, StaticSecret};

        let secret = StaticSecret::from(client_scalar);
        let key_share = PublicKey::from(&secret).to_bytes().to_vec();
        let random = [0x42u8; 32];

        // --- ClientHello body ---
        let mut ch = Vec::new();
        ch.extend_from_slice(&[0x03, 0x03]); // client_version TLS 1.2
        ch.extend_from_slice(&random);
        ch.push(session_id.len() as u8);
        ch.extend_from_slice(session_id);
        ch.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // 1 cipher suite
        ch.extend_from_slice(&[0x01, 0x00]); // 1 compression method

        // extensions
        let mut key_share_ext = Vec::new();
        key_share_ext.extend_from_slice(&((4 + key_share.len()) as u16).to_be_bytes());
        key_share_ext.extend_from_slice(&[0x00, 0x1d]); // x25519
        key_share_ext.extend_from_slice(&(key_share.len() as u16).to_be_bytes());
        key_share_ext.extend_from_slice(&key_share);

        let mut sni_ext = Vec::new();
        let name = b"www.example.com";
        let list_len = 3 + name.len();
        sni_ext.extend_from_slice(&(list_len as u16).to_be_bytes());
        sni_ext.push(0);
        sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name);

        let mut exts = Vec::new();
        exts.extend_from_slice(&[0x00, 0x00]);
        exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni_ext);
        exts.extend_from_slice(&[0x00, 0x33]);
        exts.extend_from_slice(&(key_share_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&key_share_ext);
        ch.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        ch.extend_from_slice(&exts);

        // handshake message
        let mut hs = vec![0x01u8];
        hs.extend_from_slice(&[
            ((ch.len() >> 16) & 0xff) as u8,
            ((ch.len() >> 8) & 0xff) as u8,
            (ch.len() & 0xff) as u8,
        ]);
        hs.extend_from_slice(&ch);

        // CRYPTO frame (offset 0) + padding frames to reach >= 1200 total
        let mut plaintext = vec![0x06];
        plaintext.push(0); // offset varint
        put_varint(&mut plaintext, hs.len() as u64);
        plaintext.extend_from_slice(&hs);
        while plaintext.len() < 1200 - 16 {
            plaintext.push(0x00); // PADDING frames
        }

        // --- header (pn length 1) ---
        let mut header = Vec::new();
        header.push(0xc0); // long header, Initial, pn len = 1 (low bits 0b00)
        header.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
        header.push(dcid.len() as u8);
        header.extend_from_slice(dcid);
        header.push(scid.len() as u8);
        header.extend_from_slice(scid);
        header.extend_from_slice(&[0x00]); // token length 0
        let payload_len = 1 + plaintext.len() as u64 + 16; // pn + ct + tag
        put_varint(&mut header, payload_len);
        header.push(0x00); // packet number 0, one byte

        // --- encrypt payload (pn = 0, AAD = full header with plaintext pn) ---
        let keys = InitialKeys::new(dcid);
        let nonce = keys.iv; // XOR with pn 0
        let mut in_out = plaintext;
        let key = UnboundKey::new(&AES_128_GCM, &keys.key).unwrap();
        let tag = LessSafeKey::new(key)
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&header[..]),
                &mut in_out,
            )
            .unwrap();
        in_out.extend_from_slice(tag.as_ref());

        // --- header protection over the final layout ---
        // RFC 9001 §5.4.2: the sample starts 4 bytes after the start of the
        // packet number field. The payload begins pn_len bytes after that, so
        // for a 1-byte pn the sample sits at payload offset 3.
        let sample = &in_out[3..19];
        let mask = keys.hp.new_mask(sample).unwrap();
        header[0] ^= mask[0] & 0x0f;
        let pn_at = header.len() - 1;
        header[pn_at] ^= mask[1]; // the pn byte

        let mut datagram = header;
        datagram.extend_from_slice(&in_out);
        (datagram, random, key_share)
    }

    #[test]
    fn hkdf_expand_label_matches_rfc9001_test_vector() {
        // RFC 9001 Appendix A test vector for the initial keys.
        let dcid = hex::decode("8394c8f03e515708").unwrap();
        let keys = InitialKeys::new(&dcid);
        assert_eq!(
            hex::encode(keys.key),
            "1f369613dd76d5467730efcbe3b1a22d"
        );
        assert_eq!(
            hex::encode(keys.iv),
            "fa044b2f42a3fd3b46fb255c"
        );
        assert_eq!(
            hex::encode(keys.hp_key_bytes_for_test()),
            "9f50449e04a0e810283a1e9933adedd2"
        );
    }

    #[test]
    fn decrypt_initial_extracts_client_hello() {
        let dcid = [0x11u8; 16];
        let scid = [0x22u8; 8];
        let session_id = [0xABu8; 32];
        let (datagram, random, key_share) =
            build_initial([0x33u8; 32], &session_id, &dcid, &scid);
        let pkt = decrypt_initial(&datagram).unwrap().unwrap();
        assert_eq!(pkt.dest_cid, dcid);
        let ch = extract_client_hello(&pkt.payload).unwrap();
        assert_eq!(ch.random, random);
        assert_eq!(ch.session_id, session_id);
        assert_eq!(ch.x25519_key_share.as_deref(), Some(&key_share[..]));
        assert_eq!(ch.sni.as_deref(), Some("www.example.com"));
        // zeroed aad must differ from the message only inside the sid bytes
        assert_eq!(ch.message.len(), ch.zeroed_sid_message.len());
        assert_ne!(ch.message, ch.zeroed_sid_message);
    }

    #[test]
    fn garbage_datagram_is_not_initial() {
        let garbage = vec![0xffu8; 1300];
        assert!(decrypt_initial(&garbage).is_err() || decrypt_initial(&garbage).unwrap().is_none());
    }
}

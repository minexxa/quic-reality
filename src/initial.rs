//! Server-side inspection of a client's first QUIC Initial packet.
//!
//! Initial packet protection is keyed from the (public) destination connection ID
//! (RFC 9001 §5.2), so anyone - including this server, before it commits any
//! state - can decrypt the first flight and read the TLS ClientHello inside.
//! That is what makes REALITY-style "authenticate first, otherwise be somebody
//! else" possible on QUIC.

use anyhow::{anyhow, bail, Result};
use bytes::BytesMut;
use quinn::crypto::ServerConfig as CryptoServerConfig;
use quinn::ConnectionId;

pub const MAX_CID_LEN: usize = 20;
pub const QUIC_V1: u32 = 1;

#[derive(Debug, PartialEq, Eq)]
pub enum Header<'a> {
    Short {
        dcid: &'a [u8],
    },
    Long {
        version: u32,
        dcid: &'a [u8],
        is_initial: bool,
    },
}

impl<'a> Header<'a> {
    pub fn dcid(&self) -> &'a [u8] {
        match self {
            Header::Short { dcid } | Header::Long { dcid, .. } => dcid,
        }
    }
}

/// Cheap, allocation-free look at the invariant part of a QUIC header.
pub fn parse_header(d: &[u8], short_cid_len: usize) -> Option<Header<'_>> {
    let first = *d.first()?;
    if first & 0x80 == 0 {
        return Some(Header::Short {
            dcid: d.get(1..1 + short_cid_len)?,
        });
    }
    let version = u32::from_be_bytes(d.get(1..5)?.try_into().ok()?);
    let dl = *d.get(5)? as usize;
    if dl > MAX_CID_LEN {
        return None;
    }
    let dcid = d.get(6..6 + dl)?;
    Some(Header::Long {
        version,
        dcid,
        is_initial: version == QUIC_V1 && (first >> 4) & 0x3 == 0,
    })
}

fn varint(d: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *d.get(*pos)?;
    let len = 1usize << (first >> 6);
    let bytes = d.get(*pos..*pos + len)?;
    let mut v = (first & 0x3f) as u64;
    for b in &bytes[1..] {
        v = (v << 8) | *b as u64;
    }
    *pos += len;
    Some(v)
}

/// What the server needs from the ClientHello.
#[derive(Debug)]
pub struct ClientInitial {
    pub random: [u8; 32],
    pub key_share: [u8; 32],
    pub sni: Option<String>,
    /// The complete ClientHello handshake message, exactly as it arrived: the
    /// REALITY proof authenticates every byte of it (see `auth`).
    pub hello: Vec<u8>,
}

/// Decrypts the first Initial of `datagram` and parses the ClientHello inside.
/// The whole ClientHello must be in this packet; a hello split over several
/// packets is by definition not ours (our client's hello is small).
pub fn parse_client_initial(
    crypto: &dyn CryptoServerConfig,
    datagram: &[u8],
) -> Result<ClientInitial> {
    let hdr = parse_header(datagram, 0).ok_or_else(|| anyhow!("not a QUIC long header"))?;
    let Header::Long {
        version,
        dcid,
        is_initial: true,
    } = hdr
    else {
        bail!("not a v1 Initial");
    };
    debug_assert_eq!(version, QUIC_V1);

    // first(1) version(4) dcid_len(1) dcid scid_len(1) scid token_len token length
    let mut pos = 6 + dcid.len();
    let scid_len = *datagram.get(pos).ok_or_else(|| anyhow!("short"))? as usize;
    if scid_len > MAX_CID_LEN {
        bail!("bad scid length");
    }
    pos += 1 + scid_len;
    let token_len = varint(datagram, &mut pos).ok_or_else(|| anyhow!("short"))? as usize;
    pos = pos
        .checked_add(token_len)
        .filter(|p| *p <= datagram.len())
        .ok_or_else(|| anyhow!("token overruns packet"))?;
    let length = varint(datagram, &mut pos).ok_or_else(|| anyhow!("short"))? as usize;
    let pn_offset = pos;
    let packet_end = pn_offset
        .checked_add(length)
        .filter(|e| *e <= datagram.len())
        .ok_or_else(|| anyhow!("length overruns datagram"))?;

    let keys = crypto
        .initial_keys(version, &ConnectionId::new(dcid))
        .map_err(|_| anyhow!("unsupported version"))?;
    // rustls' header key panics on packets that are too short for the sample.
    if packet_end < pn_offset + 4 + keys.header.remote.sample_size() {
        bail!("packet too short for header protection sample");
    }

    let mut pkt = datagram[..packet_end].to_vec();
    keys.header.remote.decrypt(pn_offset, &mut pkt);
    let pn_len = (pkt[0] & 0x3) as usize + 1;
    let header_len = pn_offset + pn_len;
    if header_len >= packet_end {
        bail!("no payload");
    }
    let mut pn = 0u64;
    for b in &pkt[pn_offset..header_len] {
        pn = (pn << 8) | *b as u64;
    }
    let mut payload = BytesMut::from(&pkt[header_len..]);
    keys.packet
        .remote
        .decrypt(pn, &pkt[..header_len], &mut payload)
        .map_err(|_| anyhow!("initial decryption failed"))?;

    let hello = reassemble_crypto(&payload)?;
    parse_client_hello(&hello)
}

/// Collects CRYPTO frame data starting at offset 0.
fn reassemble_crypto(p: &[u8]) -> Result<Vec<u8>> {
    let mut chunks: Vec<(u64, &[u8])> = Vec::new();
    let mut pos = 0;
    while pos < p.len() {
        let ty = varint(p, &mut pos).ok_or_else(|| anyhow!("bad frame type"))?;
        match ty {
            0x00 | 0x01 => {}
            0x06 => {
                let off = varint(p, &mut pos).ok_or_else(|| anyhow!("bad crypto offset"))?;
                let len = varint(p, &mut pos).ok_or_else(|| anyhow!("bad crypto length"))? as usize;
                let end = pos
                    .checked_add(len)
                    .filter(|e| *e <= p.len())
                    .ok_or_else(|| anyhow!("crypto frame overruns packet"))?;
                chunks.push((off, &p[pos..end]));
                pos = end;
            }
            // A client's very first flight never acknowledges anything. Any other
            // frame type means this is not the packet we are looking for.
            _ => break,
        }
    }
    chunks.sort_by_key(|c| c.0);
    let mut out = Vec::new();
    for (off, data) in chunks {
        if off as usize > out.len() {
            bail!("gap in CRYPTO data");
        }
        let skip = out.len() - off as usize;
        if skip < data.len() {
            out.extend_from_slice(&data[skip..]);
        }
    }
    if out.is_empty() {
        bail!("no CRYPTO data");
    }
    Ok(out)
}

fn take<'a>(d: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8]> {
    let end = pos.checked_add(n).filter(|e| *e <= d.len()).ok_or_else(|| anyhow!("truncated"))?;
    let s = &d[*pos..end];
    *pos = end;
    Ok(s)
}

fn u16_at(d: &[u8], pos: &mut usize) -> Result<usize> {
    let b = take(d, pos, 2)?;
    Ok(u16::from_be_bytes([b[0], b[1]]) as usize)
}

/// Parses a complete TLS ClientHello handshake message.
pub fn parse_client_hello(hs: &[u8]) -> Result<ClientInitial> {
    if hs.len() < 4 || hs[0] != 1 {
        bail!("not a ClientHello");
    }
    let len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize;
    if 4 + len > hs.len() {
        bail!("ClientHello spans more than this packet");
    }
    let body = &hs[4..4 + len];
    let mut pos = 0;
    take(body, &mut pos, 2)?; // legacy_version
    let mut random = [0u8; 32];
    random.copy_from_slice(take(body, &mut pos, 32)?);
    let sid_len = take(body, &mut pos, 1)?[0] as usize;
    take(body, &mut pos, sid_len)?;
    let cs_len = u16_at(body, &mut pos)?;
    take(body, &mut pos, cs_len)?;
    let comp_len = take(body, &mut pos, 1)?[0] as usize;
    take(body, &mut pos, comp_len)?;
    let ext_len = u16_at(body, &mut pos)?;
    let exts = take(body, &mut pos, ext_len)?;

    let mut sni = None;
    let mut key_share = None;
    let mut ep = 0;
    while ep < exts.len() {
        let ty = u16_at(exts, &mut ep)?;
        let l = u16_at(exts, &mut ep)?;
        let data = take(exts, &mut ep, l)?;
        match ty {
            0x0000 => {
                let mut p = 0;
                let list_len = u16_at(data, &mut p)?;
                let list = take(data, &mut p, list_len)?;
                let mut lp = 0;
                while lp < list.len() {
                    let name_type = take(list, &mut lp, 1)?[0];
                    let nl = u16_at(list, &mut lp)?;
                    let name = take(list, &mut lp, nl)?;
                    if name_type == 0 {
                        sni = Some(
                            std::str::from_utf8(name)
                                .map_err(|_| anyhow!("SNI is not UTF-8"))?
                                .to_ascii_lowercase(),
                        );
                        break;
                    }
                }
            }
            0x0033 => {
                let mut p = 0;
                let list_len = u16_at(data, &mut p)?;
                let list = take(data, &mut p, list_len)?;
                let mut lp = 0;
                while lp < list.len() {
                    let group = u16_at(list, &mut lp)?;
                    let kl = u16_at(list, &mut lp)?;
                    let k = take(list, &mut lp, kl)?;
                    if group == 0x001d && kl == 32 {
                        let mut ks = [0u8; 32];
                        ks.copy_from_slice(k);
                        key_share = Some(ks);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(ClientInitial {
        random,
        key_share: key_share.ok_or_else(|| anyhow!("no X25519 key share"))?,
        sni,
        hello: hs[..4 + len].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_lengths() {
        let mut p = 0;
        assert_eq!(varint(&[0x25], &mut p), Some(37));
        let mut p = 0;
        assert_eq!(varint(&[0x7b, 0xbd], &mut p), Some(15293));
        let mut p = 0;
        assert_eq!(varint(&[0x9d, 0x7f, 0x3e, 0x7d], &mut p), Some(494_878_333));
        let mut p = 0;
        assert_eq!(varint(&[0x40], &mut p), None);
    }

    #[test]
    fn header_parsing() {
        // short header with 4-byte CID
        let d = [0x40, 1, 2, 3, 4, 9, 9];
        assert_eq!(parse_header(&d, 4), Some(Header::Short { dcid: &[1, 2, 3, 4] }));
        assert_eq!(parse_header(&d[..3], 4), None);
        // long header Initial v1, dcid len 2
        let d = [0xc0, 0, 0, 0, 1, 2, 0xaa, 0xbb, 0];
        assert_eq!(
            parse_header(&d, 0),
            Some(Header::Long {
                version: 1,
                dcid: &[0xaa, 0xbb],
                is_initial: true
            })
        );
        // oversize cid length is rejected
        let d = [0xc0, 0, 0, 0, 1, 40, 0, 0];
        assert_eq!(parse_header(&d, 0), None);
    }

    #[test]
    fn garbage_never_panics() {
        for len in 0..80usize {
            let d: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
            let _ = parse_header(&d, 16);
            let _ = parse_client_hello(&d);
            let _ = reassemble_crypto(&d);
        }
    }
}

//! Application protocol spoken inside an authenticated QUIC connection.
//!
//! There is no auth stream any more: a connection only exists if the REALITY
//! check on the first Initial succeeded.
//!
//! Every stream starts with `cmd(1) | address`, the server answers `status(1)`.
//!   * CMD_TCP: then raw bytes both ways.
//!   * CMD_UDP: then a sequence of frames both ways: `len(2) | address | payload`
//!     (the address is the destination upstream, the source downstream).

use anyhow::{bail, Result};
use bytes::{BufMut, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const CMD_TCP: u8 = 0x01;
pub const CMD_UDP: u8 = 0x03;

const ADDR_IPV4: u8 = 0x01;
const ADDR_DOMAIN: u8 = 0x03;
const ADDR_IPV6: u8 = 0x04;

pub const STATUS_OK: u8 = 0x00;
pub const STATUS_ERROR: u8 = 0x01;
pub const STATUS_DENIED: u8 = 0x02;

pub const MAX_UDP_FRAME: usize = 65_535;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl TargetAddr {
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        match self {
            TargetAddr::Ip(SocketAddr::V4(a)) => {
                buf.put_u8(ADDR_IPV4);
                buf.extend_from_slice(&a.ip().octets());
                buf.put_u16(a.port());
            }
            TargetAddr::Ip(SocketAddr::V6(a)) => {
                buf.put_u8(ADDR_IPV6);
                buf.extend_from_slice(&a.ip().octets());
                buf.put_u16(a.port());
            }
            TargetAddr::Domain(h, p) => {
                if h.is_empty() || h.len() > 255 {
                    bail!("domain name length out of range");
                }
                buf.put_u8(ADDR_DOMAIN);
                buf.put_u8(h.len() as u8);
                buf.extend_from_slice(h.as_bytes());
                buf.put_u16(*p);
            }
        }
        Ok(())
    }

    /// Reads exactly one address, consuming nothing beyond it.
    pub async fn read_from<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self> {
        let atyp = r.read_u8().await?;
        Ok(match atyp {
            ADDR_IPV4 => {
                let mut ip = [0u8; 4];
                r.read_exact(&mut ip).await?;
                let port = r.read_u16().await?;
                TargetAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
            }
            ADDR_IPV6 => {
                let mut ip = [0u8; 16];
                r.read_exact(&mut ip).await?;
                let port = r.read_u16().await?;
                TargetAddr::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
            }
            ADDR_DOMAIN => {
                let len = r.read_u8().await? as usize;
                if len == 0 {
                    bail!("empty domain");
                }
                let mut host = vec![0u8; len];
                r.read_exact(&mut host).await?;
                let port = r.read_u16().await?;
                TargetAddr::Domain(String::from_utf8(host)?, port)
            }
            a => bail!("unknown address type {a}"),
        })
    }

    /// Parse from an in-memory buffer; returns the address and bytes consumed.
    pub fn parse(data: &[u8]) -> Result<(Self, usize)> {
        let need = |n: usize| -> Result<()> {
            if data.len() < n {
                bail!("truncated address");
            }
            Ok(())
        };
        need(1)?;
        match data[0] {
            ADDR_IPV4 => {
                need(7)?;
                let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
                let port = u16::from_be_bytes([data[5], data[6]]);
                Ok((TargetAddr::Ip(SocketAddr::new(ip.into(), port)), 7))
            }
            ADDR_IPV6 => {
                need(19)?;
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&data[1..17]);
                let port = u16::from_be_bytes([data[17], data[18]]);
                Ok((TargetAddr::Ip(SocketAddr::new(Ipv6Addr::from(ip).into(), port)), 19))
            }
            ADDR_DOMAIN => {
                need(2)?;
                let len = data[1] as usize;
                need(2 + len + 2)?;
                let host = String::from_utf8(data[2..2 + len].to_vec())?;
                let port = u16::from_be_bytes([data[2 + len], data[3 + len]]);
                Ok((TargetAddr::Domain(host, port), 2 + len + 2))
            }
            a => bail!("unknown address type {a}"),
        }
    }
}

pub fn encode_request(cmd: u8, target: &TargetAddr) -> Result<BytesMut> {
    let mut buf = BytesMut::with_capacity(64);
    buf.put_u8(cmd);
    target.encode(&mut buf)?;
    Ok(buf)
}

pub async fn read_request<R: AsyncRead + Unpin>(r: &mut R) -> Result<(u8, TargetAddr)> {
    let cmd = r.read_u8().await?;
    Ok((cmd, TargetAddr::read_from(r).await?))
}

pub fn encode_udp_frame(addr: &TargetAddr, payload: &[u8]) -> Result<BytesMut> {
    let mut inner = BytesMut::with_capacity(payload.len() + 24);
    addr.encode(&mut inner)?;
    inner.extend_from_slice(payload);
    if inner.len() > MAX_UDP_FRAME {
        bail!("UDP frame too large");
    }
    let mut out = BytesMut::with_capacity(2 + inner.len());
    out.put_u16(inner.len() as u16);
    out.extend_from_slice(&inner);
    Ok(out)
}

/// Reads one UDP frame. `Ok(None)` means the stream ended cleanly.
pub async fn read_udp_frame<R: AsyncRead + Unpin>(
    r: &mut R,
) -> Result<Option<(TargetAddr, Vec<u8>)>> {
    let mut lb = [0u8; 2];
    match r.read_exact(&mut lb).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u16::from_be_bytes(lb) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    let (addr, used) = TargetAddr::parse(&buf)?;
    Ok(Some((addr, buf[used..].to_vec())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn request_roundtrip_all_address_kinds() {
        for t in [
            TargetAddr::Ip("1.2.3.4:80".parse().unwrap()),
            TargetAddr::Ip("[2001:db8::1]:443".parse().unwrap()),
            TargetAddr::Domain("example.com".into(), 8080),
        ] {
            let enc = encode_request(CMD_TCP, &t).unwrap();
            let mut r = &enc[..];
            let (cmd, got) = read_request(&mut r).await.unwrap();
            assert_eq!(cmd, CMD_TCP);
            assert_eq!(got, t);
            assert!(r.is_empty(), "must not over-read");
        }
    }

    #[tokio::test]
    async fn udp_frame_roundtrip() {
        let t = TargetAddr::Domain("dns.example".into(), 53);
        let f = encode_udp_frame(&t, b"hello").unwrap();
        let mut r = &f[..];
        let (a, p) = read_udp_frame(&mut r).await.unwrap().unwrap();
        assert_eq!(a, t);
        assert_eq!(p, b"hello");
        assert!(read_udp_frame(&mut r).await.unwrap().is_none());
    }
}

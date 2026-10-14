//! Application protocol after Reality auth.
//!
//! Stream 0: auth
//! Other streams:
//!   u8  cmd   (0x01=TCP, 0x03=UDP associate)
//!   ... address ...
//!   then data

use anyhow::{bail, Result};
use bytes::{Buf, BufMut, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const CMD_TCP: u8 = 0x01;
pub const CMD_UDP: u8 = 0x03;

pub const ADDR_IPV4: u8 = 0x01;
pub const ADDR_DOMAIN: u8 = 0x03;
pub const ADDR_IPV6: u8 = 0x04;

pub const STATUS_OK: u8 = 0x00;
pub const STATUS_ERROR: u8 = 0x01;

#[derive(Debug, Clone)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl TargetAddr {
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            TargetAddr::Ip(SocketAddr::V4(addr)) => {
                buf.put_u8(ADDR_IPV4);
                buf.extend_from_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            TargetAddr::Ip(SocketAddr::V6(addr)) => {
                buf.put_u8(ADDR_IPV6);
                buf.extend_from_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            TargetAddr::Domain(host, port) => {
                buf.put_u8(ADDR_DOMAIN);
                let b = host.as_bytes();
                buf.put_u8(b.len() as u8);
                buf.extend_from_slice(b);
                buf.put_u16(*port);
            }
        }
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self> {
        if buf.remaining() < 1 {
            bail!("truncated address");
        }
        match buf.get_u8() {
            ADDR_IPV4 => {
                if buf.remaining() < 6 {
                    bail!("truncated ipv4");
                }
                let mut ip = [0u8; 4];
                buf.copy_to_slice(&mut ip);
                let port = buf.get_u16();
                Ok(TargetAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)))
            }
            ADDR_IPV6 => {
                if buf.remaining() < 18 {
                    bail!("truncated ipv6");
                }
                let mut ip = [0u8; 16];
                buf.copy_to_slice(&mut ip);
                let port = buf.get_u16();
                Ok(TargetAddr::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port)))
            }
            ADDR_DOMAIN => {
                if buf.remaining() < 1 {
                    bail!("truncated domain len");
                }
                let len = buf.get_u8() as usize;
                if buf.remaining() < len + 2 {
                    bail!("truncated domain");
                }
                let mut host = vec![0u8; len];
                buf.copy_to_slice(&mut host);
                let host = String::from_utf8(host).map_err(|e| anyhow::anyhow!("utf8: {}", e))?;
                let port = buf.get_u16();
                Ok(TargetAddr::Domain(host, port))
            }
            a => bail!("unknown atyp {}", a),
        }
    }

    pub fn to_socket_addrs(&self) -> Result<Vec<SocketAddr>> {
        match self {
            TargetAddr::Ip(a) => Ok(vec![*a]),
            TargetAddr::Domain(h, p) => {
                let s = format!("{}:{}", h, p);
                Ok(s.to_socket_addrs()?.collect())
            }
        }
    }
}

use std::net::ToSocketAddrs;

pub fn encode_request(cmd: u8, target: &TargetAddr) -> BytesMut {
    let mut buf = BytesMut::with_capacity(64);
    buf.put_u8(cmd);
    target.encode(&mut buf);
    buf
}

pub fn decode_request(data: &[u8]) -> Result<(u8, TargetAddr)> {
    let mut buf = data;
    if buf.remaining() < 1 {
        bail!("empty");
    }
    let cmd = buf.get_u8();
    let addr = TargetAddr::decode(&mut buf)?;
    Ok((cmd, addr))
}

pub fn encode_udp_packet(addr: &TargetAddr, payload: &[u8]) -> BytesMut {
    let mut inner = BytesMut::new();
    addr.encode(&mut inner);
    inner.extend_from_slice(payload);
    let mut out = BytesMut::with_capacity(2 + inner.len());
    out.put_u16(inner.len() as u16);
    out.extend_from_slice(&inner);
    out
}


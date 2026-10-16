//! Shared helpers: bidirectional relay with correct half-close, target filtering.

use quinn::{RecvStream, SendStream};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const BUF: usize = 64 * 1024;

/// Copy TCP <-> QUIC stream. Each direction half-closes independently, so a
/// client that finished sending still receives the complete response (the old
/// `select!` version cancelled the other direction and truncated it).
pub async fn relay_tcp_quic(tcp: TcpStream, mut qs: SendStream, mut qr: RecvStream) {
    let (tr, mut tw) = tcp.into_split();
    let up = async {
        let mut r = BufReader::with_capacity(BUF, tr);
        let res = tokio::io::copy_buf(&mut r, &mut qs).await;
        let _ = qs.finish();
        res
    };
    let down = async {
        let mut r = BufReader::with_capacity(BUF, &mut qr);
        let res = tokio::io::copy_buf(&mut r, &mut tw).await;
        let _ = tw.shutdown().await;
        res
    };
    let _ = tokio::join!(up, down);
}

/// True for addresses an authenticated client may reach by default.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return public_v4(v4);
            }
            public_v6(v6)
        }
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local() // 169.254/16 incl. cloud metadata
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64/10 CGNAT
        || o[0] == 0
        || o[0] >= 240)
}

fn public_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00 // unique local
        || (s[0] & 0xffc0) == 0xfe80 // link local
        || (s[0] == 0x2001 && s[1] == 0x0db8)) // documentation
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ranges_are_blocked() {
        for ip in [
            "127.0.0.1", "10.1.2.3", "192.168.0.1", "172.16.5.5", "169.254.169.254",
            "100.64.0.1", "0.0.0.0", "224.0.0.1", "::1", "fe80::1", "fd00::1", "::ffff:10.0.0.1",
        ] {
            assert!(!is_public_ip(ip.parse().unwrap()), "{ip} should be blocked");
        }
        for ip in ["1.1.1.1", "8.8.8.8", "2606:4700::1111", "93.184.216.34"] {
            assert!(is_public_ip(ip.parse().unwrap()), "{ip} should be allowed");
        }
    }
}

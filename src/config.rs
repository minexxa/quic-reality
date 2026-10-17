use crate::auth;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// A bandwidth value, parsed into **bytes per second**.
///
/// Accepts hysteria-style strings with a decimal unit (`"100 Mbps"`,
/// `"512 kbps"`, `"1gbps"`, `"1 t"`) or a raw TOML integer, which - like
/// hysteria - is taken as a byte count per second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bandwidth(u64);

impl Bandwidth {
    /// Bytes per second.
    pub fn bytes_per_sec(&self) -> u64 {
        self.0
    }

    /// Raw bytes per second, for tests that need a number instead of a string.
    #[cfg(test)]
    pub const fn from_bytes_per_sec(v: u64) -> Self {
        Self(v)
    }
}

impl Serialize for Bandwidth {
    /// Serializes as the raw byte count, which deserializes back to the same
    /// value.
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for Bandwidth {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct BandwidthVisitor;

        impl serde::de::Visitor<'_> for BandwidthVisitor {
            type Value = Bandwidth;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(r#"a bandwidth string like "100 Mbps" or a byte count"#)
            }

            fn visit_u64<E>(self, v: u64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Bandwidth(v))
            }

            fn visit_i64<E>(self, v: i64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                u64::try_from(v)
                    .map(Bandwidth)
                    .map_err(|_| E::custom("bandwidth must not be negative"))
            }

            fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                parse_bandwidth(v).map(Bandwidth).map_err(E::custom)
            }
        }

        deserializer.deserialize_any(BandwidthVisitor)
    }
}

/// Parse a hysteria-style bandwidth string into bytes per second.
///
/// Decimal units (1000-based), bit values divided by 8, mirroring
/// hysteria's `utils.StringToBps`.
pub fn parse_bandwidth(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (value, unit) = s.split_at(split);
    if value.is_empty() {
        return Err(format!("invalid bandwidth {s:?}: missing value"));
    }
    let value: u64 = value
        .parse()
        .map_err(|e| format!("invalid bandwidth {s:?}: {e}"))?;
    let multiplier = match unit.trim().to_ascii_lowercase().as_str() {
        "b" | "bps" => 1,
        "k" | "kb" | "kbps" => 1_000,
        "m" | "mb" | "mbps" => 1_000_000,
        "g" | "gb" | "gbps" => 1_000_000_000,
        "t" | "tb" | "tbps" => 1_000_000_000_000,
        other => return Err(format!("invalid bandwidth {s:?}: unsupported unit {other:?}")),
    };
    value
        .checked_mul(multiplier)
        .and_then(|v| v.checked_div(8))
        .ok_or_else(|| format!("invalid bandwidth {s:?}: value too large"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub mode: Mode,
    #[serde(default)]
    pub listen: String,
    #[serde(default)]
    pub server: String,
    pub reality: RealityConfig,
    #[serde(default)]
    pub local: LocalConfig,
    #[serde(default)]
    pub obfuscation: ObfuscationConfig,
    #[serde(default)]
    pub quic: QuicConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Server,
    Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealityConfig {
    /// Server only. X25519 private key, hex.
    #[serde(default)]
    pub private_key: String,
    /// Client only. Server X25519 public key, hex.
    #[serde(default)]
    pub public_key: String,
    /// Up to 8 bytes of hex (0-16 chars). The client sends this one.
    #[serde(default)]
    pub short_id: String,
    /// Server only: additional accepted short ids.
    #[serde(default)]
    pub short_ids: Vec<String>,
    /// SNI sent by the client. Must be a name the decoy `dest` really serves.
    #[serde(default = "default_server_name")]
    pub server_name: String,
    /// Server only: more accepted SNI values.
    #[serde(default)]
    pub server_names: Vec<String>,
    /// Server only: real QUIC site (`host:port`) that unauthenticated traffic is
    /// transparently relayed to. Empty disables the fallback (probes get silence).
    #[serde(default)]
    pub dest: String,
    /// Server only: accepted clock difference of the ClientHello timestamp.
    #[serde(default = "default_skew")]
    pub max_time_skew_secs: u64,
    /// Server only: rate limit for decoy traffic on the prober -> decoy leg.
    /// REALITY's `limitFallbackUpload`. Unlimited by default.
    #[serde(default)]
    pub limit_fallback_upload: FallbackLimit,
    /// Server only: rate limit for decoy traffic on the decoy -> prober leg.
    /// REALITY's `limitFallbackDownload`. Unlimited by default.
    #[serde(default)]
    pub limit_fallback_download: FallbackLimit,
}

/// REALITY's `limitFallbackUpload` / `limitFallbackDownload`: a token bucket
/// for decoy (fallback) traffic, so a prober cannot use the relayed real site
/// as a free amplifier. All fields default to "no limit".
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct FallbackLimit {
    /// Bytes that pass unthrottled before the limit applies.
    #[serde(default)]
    pub after_bytes: u64,
    /// Sustained rate in bytes per second; unset or 0 means unlimited.
    #[serde(default)]
    pub bytes_per_sec: Option<Bandwidth>,
    /// Bucket capacity in bytes per second. Raised to `bytes_per_sec` when
    /// smaller, exactly like the reference implementation clamps it.
    #[serde(default)]
    pub burst_bytes_per_sec: Option<Bandwidth>,
}

impl FallbackLimit {
    /// `(rate, burst, after_bytes)`, or `None` when the limit is disabled.
    pub fn bucket_params(&self) -> Option<(u64, u64, u64)> {
        let rate = self.bytes_per_sec.map_or(0, |b| b.bytes_per_sec());
        if rate == 0 {
            return None;
        }
        let burst = self
            .burst_bytes_per_sec
            .map_or(rate, |b| b.bytes_per_sec())
            .max(rate);
        Some((rate, burst, self.after_bytes))
    }
}

fn default_server_name() -> String {
    "www.cloudflare.com".to_string()
}

fn default_skew() -> u64 {
    60
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalConfig {
    #[serde(default = "default_socks")]
    pub socks: String,
    #[serde(default = "default_http")]
    pub http: String,
}

impl Default for LocalConfig {
    fn default() -> Self {
        Self {
            socks: default_socks(),
            http: default_http(),
        }
    }
}

fn default_socks() -> String {
    "127.0.0.1:1080".to_string()
}

fn default_http() -> String {
    "127.0.0.1:8080".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ObfuscationConfig {
    /// "salamander" or empty. Off by default: it makes every datagram look like
    /// random noise, which is the opposite of looking like ordinary QUIC.
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub password: String,
}

impl ObfuscationConfig {
    pub fn is_salamander(&self) -> bool {
        self.kind.eq_ignore_ascii_case("salamander") && !self.password.is_empty()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Congestion {
    #[default]
    Bbr,
    Cubic,
    #[serde(rename = "newreno")]
    NewReno,
    /// Hysteria2-style fixed-rate congestion control (see [`crate::brutal`]).
    Brutal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicConfig {
    #[serde(default)]
    pub congestion: Congestion,
    /// Target bandwidth, e.g. "100 Mbps". Required when congestion = "brutal".
    #[serde(default)]
    pub brutal_bandwidth: Option<Bandwidth>,
    /// Pin the ACK-rate loss compensation at 1.0 (never inflate the window
    /// for loss). Hysteria's `disableLossCompensation`.
    #[serde(default)]
    pub brutal_disable_loss_compensation: bool,
    #[serde(default = "default_idle")]
    pub idle_timeout_secs: u64,
    /// 0 disables keep-alive pings.
    #[serde(default = "default_keepalive")]
    pub keep_alive_secs: u64,
    /// Deprecated and ignored: the old "chrome profile" only tweaked window sizes.
    #[serde(default)]
    pub chrome_parrot: Option<bool>,
}

impl QuicConfig {
    /// Bytes per second for the brutal controller; 0 when unset (rejected by
    /// `Config::validate` when brutal is selected).
    pub fn brutal_bps(&self) -> u64 {
        self.brutal_bandwidth.map_or(0, |b| b.bytes_per_sec())
    }
}

fn default_idle() -> u64 {
    20
}

fn default_keepalive() -> u64 {
    6
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            congestion: Congestion::default(),
            brutal_bandwidth: None,
            brutal_disable_loss_compensation: false,
            idle_timeout_secs: default_idle(),
            keep_alive_secs: default_keepalive(),
            chrome_parrot: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityConfig {
    /// Server only. By default an authenticated client may not reach loopback,
    /// private, link-local (cloud metadata!) or other non-public addresses.
    #[serde(default)]
    pub allow_private_targets: bool,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let cfg: Config = toml::from_str(&content).context("parsing config")?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        auth::parse_short_id(&self.reality.short_id).context("reality.short_id")?;
        for s in &self.reality.short_ids {
            auth::parse_short_id(s).context("reality.short_ids")?;
        }
        match self.mode {
            Mode::Server => {
                if self.reality.private_key.is_empty() {
                    bail!("server needs reality.private_key (run `keygen`)");
                }
                auth::decode_hex32(&self.reality.private_key).context("reality.private_key")?;
                if self.listen.is_empty() {
                    bail!("server needs `listen`");
                }
            }
            Mode::Client => {
                if self.reality.public_key.is_empty() || self.server.is_empty() {
                    bail!("client needs reality.public_key and `server`");
                }
                auth::decode_hex32(&self.reality.public_key).context("reality.public_key")?;
            }
        }
        if self.reality.server_name.is_empty() {
            bail!("reality.server_name must not be empty");
        }
        if self.quic.congestion == Congestion::Brutal
            && self
                .quic
                .brutal_bandwidth
                .is_none_or(|b| b.bytes_per_sec() == 0)
        {
            bail!(
                "quic.brutal_bandwidth (e.g. \"100 Mbps\") is required when quic.congestion = \"brutal\""
            );
        }
        Ok(())
    }

    /// Accepted SNI values (lowercase, de-duplicated).
    pub fn server_names(&self) -> Vec<String> {
        let mut v: Vec<String> = std::iter::once(&self.reality.server_name)
            .chain(self.reality.server_names.iter())
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// Accepted short ids.
    pub fn short_ids(&self) -> Result<Vec<[u8; auth::SHORT_ID_LEN]>> {
        let mut out = vec![auth::parse_short_id(&self.reality.short_id)?];
        for s in &self.reality.short_ids {
            out.push(auth::parse_short_id(s)?);
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    pub fn example_server() -> String {
        r#"mode = "server"
listen = "0.0.0.0:443"
log_level = "info"

[reality]
# quic-reality keygen
private_key = "REPLACE_PRIVATE_KEY_HEX"
short_id = "0123456789abcdef"
# Must be a name that `dest` really serves over HTTP/3.
server_name = "www.cloudflare.com"
# Probes and other unauthenticated traffic are relayed (as UDP) to this real site.
dest = "www.cloudflare.com:443"

# Optional: throttle the decoy relay so a prober cannot use the real site as a
# free amplifier. `after_bytes` pass freely, then the flow is held to
# `bytes_per_sec` with a burst of `burst_bytes_per_sec` (>= bytes_per_sec).
# [reality.limit_fallback_upload]
# after_bytes = 65536
# bytes_per_sec = "1 Mbps"
# burst_bytes_per_sec = "2 Mbps"
# [reality.limit_fallback_download]
# bytes_per_sec = "1 Mbps"

[quic]
congestion = "bbr"
# Hysteria2-style fixed-rate congestion control instead of BBR:
# congestion = "brutal"
# brutal_bandwidth = "100 Mbps"
# brutal_disable_loss_compensation = false

[security]
allow_private_targets = false

# Optional, off by default (makes traffic look like noise instead of QUIC):
# [obfuscation]
# type = "salamander"
# password = "change-me"
"#
        .to_string()
    }

    pub fn example_client(public_key: &str, server: &str) -> String {
        format!(
            r#"mode = "client"
server = "{server}"
log_level = "info"

[reality]
public_key = "{public_key}"
short_id = "0123456789abcdef"
server_name = "www.cloudflare.com"

[local]
socks = "127.0.0.1:1080"
http = "127.0.0.1:8080"

[quic]
congestion = "bbr"
# congestion = "brutal"
# brutal_bandwidth = "100 Mbps"
"#
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn examples_parse() {
        let kp = auth::KeyPair::generate();
        let s = Config::example_server().replace("REPLACE_PRIVATE_KEY_HEX", &kp.private_hex());
        let c: Config = toml::from_str(&s).unwrap();
        c.validate().unwrap();
        let c: Config = toml::from_str(&Config::example_client(&kp.public_hex(), "1.2.3.4:443")).unwrap();
        c.validate().unwrap();
        assert_eq!(c.server_names(), vec!["www.cloudflare.com".to_string()]);
    }

    #[test]
    fn legacy_obfuscation_and_chrome_parrot_fields_still_parse() {
        let kp = auth::KeyPair::generate();
        let s = format!(
            "mode='client'\nserver='1.2.3.4:443'\n[reality]\npublic_key='{}'\nshort_id='00'\n[obfuscation]\ntype='salamander'\npassword='abcd'\n[quic]\nchrome_parrot=true\n",
            kp.public_hex()
        );
        let c: Config = toml::from_str(&s).unwrap();
        assert!(c.obfuscation.is_salamander());
    }

    #[test]
    fn brutal_congestion_config() {
        let kp = auth::KeyPair::generate();
        let s = format!(
            "mode='client'\nserver='1.2.3.4:443'\n[reality]\npublic_key='{}'\nshort_id='00'\n[quic]\ncongestion='brutal'\nbrutal_bandwidth='100 Mbps'\n",
            kp.public_hex()
        );
        let c: Config = toml::from_str(&s).unwrap();
        c.validate().unwrap();
        assert_eq!(c.quic.congestion, Congestion::Brutal);
        assert_eq!(c.quic.brutal_bps(), 100_000_000 / 8);
        assert!(!c.quic.brutal_disable_loss_compensation);

        // A raw integer is a byte count per second, like hysteria.
        let s = format!(
            "mode='client'\nserver='1.2.3.4:443'\n[reality]\npublic_key='{}'\nshort_id='00'\n[quic]\ncongestion='brutal'\nbrutal_bandwidth=12500000\n",
            kp.public_hex()
        );
        let c: Config = toml::from_str(&s).unwrap();
        c.validate().unwrap();
        assert_eq!(c.quic.brutal_bps(), 12_500_000);
    }

    #[test]
    fn brutal_without_bandwidth_fails_validation() {
        let kp = auth::KeyPair::generate();
        let s = format!(
            "mode='client'\nserver='1.2.3.4:443'\n[reality]\npublic_key='{}'\nshort_id='00'\n[quic]\ncongestion='brutal'\n",
            kp.public_hex()
        );
        let c: Config = toml::from_str(&s).unwrap();
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("brutal_bandwidth"), "{err}");
    }

    #[test]
    fn fallback_limit_bucket_params() {
        // Default: unlimited.
        assert_eq!(FallbackLimit::default().bucket_params(), None);
        // Rate only: burst defaults to the rate.
        let l = FallbackLimit {
            after_bytes: 1024,
            bytes_per_sec: Some(Bandwidth(1000)),
            burst_bytes_per_sec: None,
        };
        assert_eq!(l.bucket_params(), Some((1000, 1000, 1024)));
        // A burst below the rate is raised to it, like the reference.
        let l = FallbackLimit {
            after_bytes: 0,
            bytes_per_sec: Some(Bandwidth(2000)),
            burst_bytes_per_sec: Some(Bandwidth(500)),
        };
        assert_eq!(l.bucket_params(), Some((2000, 2000, 0)));
        // Bytes without a rate is still unlimited.
        let l = FallbackLimit {
            after_bytes: 10,
            ..Default::default()
        };
        assert_eq!(l.bucket_params(), None);
    }

    #[test]
    fn fallback_limits_parse_from_toml() {
        let kp = auth::KeyPair::generate();
        let s = format!(
            "mode='server'\nlisten='1.2.3.4:443'\n[reality]\nprivate_key='{}'\nshort_id='00'\ndest='www.cloudflare.com:443'\n[reality.limit_fallback_upload]\nafter_bytes=4096\nbytes_per_sec='1 Mbps'\nburst_bytes_per_sec=250000\n[reality.limit_fallback_download]\nbytes_per_sec='512 kbps'\n",
            kp.private_hex()
        );
        let c: Config = toml::from_str(&s).unwrap();
        c.validate().unwrap();
        assert_eq!(
            c.reality.limit_fallback_upload.bucket_params(),
            Some((1_000_000 / 8, 250_000, 4096))
        );
        assert_eq!(
            c.reality.limit_fallback_download.bucket_params(),
            Some((512_000 / 8, 512_000 / 8, 0))
        );
    }

    #[test]
    fn bandwidth_parsing_matches_hysteria() {
        assert_eq!(parse_bandwidth("100 Mbps").unwrap(), 100_000_000 / 8);
        assert_eq!(parse_bandwidth("512 kbps").unwrap(), 512_000 / 8);
        assert_eq!(parse_bandwidth("1g").unwrap(), 1_000_000_000 / 8);
        assert_eq!(parse_bandwidth("1 tbps").unwrap(), 1_000_000_000_000 / 8);
        assert_eq!(parse_bandwidth("  42 bps ").unwrap(), 42 / 8);
        assert!(parse_bandwidth("100").is_err(), "a string needs a unit");
        assert!(parse_bandwidth("mbps").is_err(), "missing value");
        assert!(parse_bandwidth("100 pb").is_err(), "unsupported unit");
        assert!(parse_bandwidth("99999999999999999999 tbps").is_err(), "overflow");
    }
}

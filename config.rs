use crate::auth;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicConfig {
    #[serde(default)]
    pub congestion: Congestion,
    #[serde(default = "default_idle")]
    pub idle_timeout_secs: u64,
    /// 0 disables keep-alive pings.
    #[serde(default = "default_keepalive")]
    pub keep_alive_secs: u64,
    /// Deprecated and ignored: the old "chrome profile" only tweaked window sizes.
    #[serde(default)]
    pub chrome_parrot: Option<bool>,
}

fn default_idle() -> u64 {
    30
}

fn default_keepalive() -> u64 {
    10
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            congestion: Congestion::default(),
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

[quic]
congestion = "bbr"

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
}

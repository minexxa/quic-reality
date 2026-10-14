use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub mode: Mode,
    #[serde(default = "default_listen")]
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
    pub log_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Server,
    Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealityConfig {
    /// Server: static X25519 private key (hex). `keygen` prints one.
    #[serde(default)]
    pub private_key: String,
    /// Client: server static public key (hex).
    #[serde(default)]
    pub public_key: String,
    /// Client: one short id. Server: accepts any of `short_ids`.
    #[serde(default = "default_short_id")]
    pub short_id: String,
    /// Server: additional accepted short ids (hex).
    #[serde(default)]
    pub short_ids: Vec<String>,
    #[serde(default = "default_server_name")]
    pub server_name: String,
    /// Server: real site that failed probes are UDP-relayed to (host:port).
    /// Empty disables the fallback (probes are dropped instead).
    #[serde(default)]
    pub dest: String,
    /// Server: certificate persistence (PEM pair). Empty disables persistence.
    #[serde(default)]
    pub cert_path: String,
    #[serde(default)]
    pub key_path: String,
}

fn default_listen() -> String {
    "0.0.0.0:443".to_string()
}

fn default_short_id() -> String {
    "0123456789abcdef".to_string()
}

fn default_server_name() -> String {
    "www.cloudflare.com".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalConfig {
    #[serde(default = "default_socks")]
    pub socks: String,
    /// HTTP CONNECT proxy listen address
    #[serde(default = "default_http")]
    pub http: String,
}

fn default_socks() -> String {
    "127.0.0.1:1080".to_string()
}

fn default_http() -> String {
    "127.0.0.1:8080".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ObfuscationConfig {
    /// "salamander" or empty/none
    #[serde(default)]
    pub type_: String,
    #[serde(default, rename = "type")]
    pub type_field: String,
    #[serde(default)]
    pub password: String,
}

impl ObfuscationConfig {
    pub fn kind(&self) -> &str {
        if !self.type_field.is_empty() {
            &self.type_field
        } else {
            &self.type_
        }
    }

    pub fn is_salamander(&self) -> bool {
        self.kind().eq_ignore_ascii_case("salamander") && !self.password.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicConfig {
    /// ALPN offered by the client (should look like a real browser; "h3").
    #[serde(default = "default_alpn")]
    pub alpn: String,
    /// Congestion control: "bbr" (default), "cubic", or "brutal:<bytes-per-second>".
    #[serde(default = "default_congestion")]
    pub congestion: String,
    /// Server: refuse to relay requests targeting private/loopback addresses.
    #[serde(default = "default_true")]
    pub block_private: bool,
    /// Client: pinned SHA-256 fingerprint of the server certificate (hex).
    /// Empty means trust-on-first-use, recorded next to the config.
    #[serde(default)]
    pub server_fingerprint: String,
    /// Client: seconds between reconnect attempts after the connection drops.
    #[serde(default = "default_reconnect")]
    pub reconnect_secs: u64,
}

fn default_alpn() -> String {
    "h3".to_string()
}

fn default_congestion() -> String {
    "bbr".to_string()
}

fn default_reconnect() -> u64 {
    3
}

fn default_true() -> bool {
    true
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            alpn: default_alpn(),
            congestion: default_congestion(),
            block_private: true,
            server_fingerprint: String::new(),
            reconnect_secs: default_reconnect(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::Server,
            listen: "0.0.0.0:443".to_string(),
            server: String::new(),
            reality: RealityConfig {
                private_key: String::new(),
                public_key: String::new(),
                short_id: default_short_id(),
                short_ids: Vec::new(),
                server_name: default_server_name(),
                dest: String::new(),
                cert_path: String::new(),
                key_path: String::new(),
            },
            local: LocalConfig::default(),
            obfuscation: ObfuscationConfig::default(),
            quic: QuicConfig::default(),
            log_level: "info".to_string(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let cfg: Config = toml::from_str(&content)?;
        Ok(cfg)
    }

    /// All accepted short ids (hex-decoded), server side.
    pub fn server_short_ids(&self) -> anyhow::Result<Vec<Vec<u8>>> {
        let mut ids = vec![hex::decode(self.reality.short_id.trim())?];
        for id in &self.reality.short_ids {
            ids.push(hex::decode(id.trim())?);
        }
        Ok(ids)
    }

    pub fn example_server() -> String {
        r#"mode = "server"
listen = "0.0.0.0:8443"
log_level = "info"

[reality]
# cargo run -- keygen
private_key = "REPLACE_PRIVATE_KEY_HEX"
short_id = "0123456789abcdef"
server_name = "www.cloudflare.com"
# Failed probes are UDP-relayed to this real site so scanners see its genuine
# certificate. Empty = drop probes instead.
dest = "www.cloudflare.com:443"
# Persist the self-signed certificate across restarts (recommended).
cert_path = "cert.pem"
key_path = "key.pem"

[obfuscation]
# Salamander obfuscates every UDP datagram. NOTE: with Salamander on, probes
# relayed to `dest` arrive obfuscated and are dropped by the real site — the
# fallback only works if dest speaks the same Salamander password. Leave off
# when impersonating an ordinary TLS website.
type = ""
password = ""

[quic]
congestion = "bbr"          # bbr | cubic | brutal:<bytes-per-second>
block_private = true        # refuse to relay RFC1918/loopback targets
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

[obfuscation]
type = ""
password = ""

[quic]
alpn = "h3"
congestion = "bbr"
# Pin the server certificate fingerprint (hex, printed by the server on first
# run). Empty = trust on first use.
server_fingerprint = ""
reconnect_secs = 3
"#
        )
    }
}

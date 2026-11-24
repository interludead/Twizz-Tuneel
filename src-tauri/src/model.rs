use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Server {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub uri: String,
    pub latency_ms: Option<u128>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteRule {
    pub kind: String,
    pub value: String,
    pub route: String,
}

fn default_true() -> bool { true }
fn default_interval() -> u32 { 60 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub url: String,
    pub servers: Vec<Server>,
    #[serde(default)]
    pub rules: Vec<RouteRule>,
    #[serde(default)]
    pub rule_count: usize,
    pub updated_at: u64,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub priority: i32,
    #[serde(default = "default_interval")]
    pub update_interval_minutes: u32,
    #[serde(default = "default_true")]
    pub update_on_start: bool,
    #[serde(default)]
    pub upload_bytes: Option<u64>,
    #[serde(default)]
    pub download_bytes: Option<u64>,
    #[serde(default)]
    pub total_bytes: Option<u64>,
    #[serde(default)]
    pub expires_at: Option<u64>,
}

fn default_core_preference() -> String { "auto".to_string() }
fn default_kill_switch_mode() -> String { "session".to_string() }
fn default_dns_mode() -> String { "split".to_string() }
fn default_ipv6_mode() -> String { "block".to_string() }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectRequest {
    pub server: Server,
    pub mode: String,
    /// "auto", "sing-box", "xray" or "mihomo".
    #[serde(default = "default_core_preference")]
    pub core_preference: String,
    #[serde(default = "default_kill_switch_mode")]
    pub kill_switch_mode: String,
    pub allow_lan: bool,
    pub dns: String,
    #[serde(default = "default_dns_mode")]
    pub dns_mode: String,
    #[serde(default = "default_ipv6_mode")]
    pub ipv6_mode: String,
    #[serde(default)]
    pub rules: Vec<RouteRule>,
    #[serde(default)]
    pub routing_profile: RoutingProfile,
    #[serde(default = "default_true")]
    pub strict_route: bool,
    #[serde(default = "default_true")]
    pub secure_dns: bool,
    #[serde(default = "default_true")]
    pub dns_hijack: bool,
    #[serde(default = "default_true")]
    pub sniff: bool,
    #[serde(default)]
    pub ipv6: bool,
    #[serde(default)]
    pub block_quic: bool,
    #[serde(default = "default_true")]
    pub cache_enabled: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RoutingProfile {
    #[default]
    Custom,
    BypassRussia,
    ProxyRussiaBlocked,
}

impl RoutingProfile {
    pub fn sets(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::Custom => &[],
            Self::BypassRussia => &[
                ("twizz-ru-sites", "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/category-ru.srs"),
                ("twizz-ru-ip", "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/ru.srs"),
            ],
            Self::ProxyRussiaBlocked => &[
                ("twizz-ru-blocked-sites", "https://cdn.jsdelivr.net/gh/runetfreedom/russia-v2ray-rules-dat@release/sing-box/rule-set-geosite/geosite-ru-blocked.srs"),
                ("twizz-ru-blocked-ip", "https://cdn.jsdelivr.net/gh/runetfreedom/russia-v2ray-rules-dat@release/sing-box/rule-set-geoip/geoip-ru-blocked-community.srs"),
            ],
        }
    }

    pub fn routes(self) -> Option<(&'static str, &'static str)> {
        match self {
            Self::Custom => None,
            Self::BypassRussia => Some(("direct", "proxy")),
            Self::ProxyRussiaBlocked => Some(("proxy", "direct")),
        }
    }
}

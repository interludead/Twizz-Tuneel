use crate::model::Server;
use serde_json::json;
use url::Url;

/// Local SOCKS5 port used when a specialised protocol core (Xray / Mihomo)
/// handles the outbound and sing-box only provides TUN, DNS and routing.
pub const BRIDGE_PORT: u16 = 2081;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreKind {
    SingBox,
    Xray,
    Mihomo,
}

pub const ALL_CORES: [CoreKind; 3] = [CoreKind::SingBox, CoreKind::Xray, CoreKind::Mihomo];

impl CoreKind {
    pub fn id(self) -> &'static str {
        match self {
            CoreKind::SingBox => "sing-box",
            CoreKind::Xray => "xray",
            CoreKind::Mihomo => "mihomo",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            CoreKind::SingBox => "sing-box",
            CoreKind::Xray => "Xray-core",
            CoreKind::Mihomo => "Mihomo (Clash.Meta)",
        }
    }

    pub fn binary(self) -> &'static str {
        match self {
            CoreKind::SingBox => "sing-box.exe",
            CoreKind::Xray => "xray.exe",
            CoreKind::Mihomo => "mihomo.exe",
        }
    }

    pub fn from_id(value: &str) -> Option<CoreKind> {
        match value.trim().to_ascii_lowercase().as_str() {
            "sing-box" | "singbox" | "sing_box" => Some(CoreKind::SingBox),
            "xray" | "xray-core" | "xraycore" => Some(CoreKind::Xray),
            "mihomo" | "clash" | "clash-meta" | "clashmeta" | "mihomo-clash" => Some(CoreKind::Mihomo),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ServerProfile {
    pub protocol: String,
    /// Normalised stream transport: native, tcp, ws, grpc, http, httpupgrade, quic, xhttp, kcp.
    pub transport: String,
    /// none, tls or reality.
    pub security: String,
    pub flow: String,
}

fn normalize_transport(raw: &str) -> String {
    match raw {
        "" | "tcp" | "raw" | "none" | "original" => "tcp".to_string(),
        "h2" | "h2c" | "http" => "http".to_string(),
        "xhttp" | "splithttp" => "xhttp".to_string(),
        "kcp" | "mkcp" => "kcp".to_string(),
        other => other.to_string(),
    }
}

pub fn profile(server: &Server) -> Result<ServerProfile, String> {
    let url = Url::parse(&server.uri)
        .map_err(|error| format!("Некорректная ссылка сервера: {error}"))?;
    let value = |key: &str| -> String {
        url.query_pairs()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.into_owned())
            .unwrap_or_default()
    };

    let protocol = match server.protocol.trim().to_ascii_lowercase().as_str() {
        "hy2" => "hysteria2".to_string(),
        "ss" => "shadowsocks".to_string(),
        other => other.to_string(),
    };

    let transport = if matches!(protocol.as_str(), "hysteria2" | "hysteria" | "tuic" | "shadowsocks" | "anytls") {
        "native".to_string()
    } else {
        let raw = value("type");
        let raw = if raw.trim().is_empty() { value("network") } else { raw };
        normalize_transport(raw.trim().to_ascii_lowercase().as_str())
    };

    let public_key = value("pbk");
    let raw_security = value("security").trim().to_ascii_lowercase();
    let security = if !public_key.trim().is_empty() || raw_security == "reality" {
        "reality".to_string()
    } else if raw_security.is_empty() {
        if protocol == "vless" { "tls".to_string() } else { "tls".to_string() }
    } else if raw_security == "none" {
        "none".to_string()
    } else {
        "tls".to_string()
    };

    Ok(ServerProfile {
        protocol,
        transport,
        security,
        flow: value("flow"),
    })
}

pub fn transport_label(profile: &ServerProfile) -> String {
    match profile.transport.as_str() {
        "native" => "встроенный транспорт".to_string(),
        "tcp" => "TCP".to_string(),
        "ws" => "WebSocket".to_string(),
        "grpc" => "gRPC".to_string(),
        "http" => "HTTP/2".to_string(),
        "httpupgrade" => "HTTPUpgrade".to_string(),
        "quic" => "QUIC".to_string(),
        "xhttp" => "XHTTP (SplitHTTP)".to_string(),
        "kcp" => "mKCP".to_string(),
        other => other.to_ascii_uppercase(),
    }
}

pub fn protocol_label(profile: &ServerProfile) -> String {
    match profile.protocol.as_str() {
        "vless" => {
            if profile.security == "reality" {
                "VLESS Reality".to_string()
            } else {
                "VLESS".to_string()
            }
        }
        "trojan" => "Trojan".to_string(),
        "hysteria2" => "Hysteria2".to_string(),
        "vmess" => "VMess".to_string(),
        "tuic" => "TUIC".to_string(),
        "shadowsocks" => "Shadowsocks".to_string(),
        other => other.to_ascii_uppercase(),
    }
}

/// Capability matrix of the three bundled cores.
pub fn supports(core: CoreKind, profile: &ServerProfile) -> bool {
    // XTLS Vision only exists on the raw/TCP stream: offering it on ws/grpc/http
    // yields a core that starts, connects and moves no traffic.
    let flow = profile.flow.trim();
    if !flow.is_empty() && profile.transport != "tcp" {
        return false;
    }
    match core {
        CoreKind::SingBox => {
            matches!(
                profile.protocol.as_str(),
                "vless" | "trojan" | "hysteria2" | "vmess" | "shadowsocks" | "tuic" | "anytls"
            ) && matches!(
                profile.transport.as_str(),
                "native" | "tcp" | "ws" | "grpc" | "http" | "httpupgrade" | "quic"
            )
        }
        CoreKind::Xray => {
            // Keep the matrix in sync with xray_config::build, which only
            // implements these three protocols.
            matches!(
                profile.protocol.as_str(),
                "vless" | "trojan" | "vmess"
            ) && matches!(
                profile.transport.as_str(),
                "tcp" | "ws" | "grpc" | "http" | "httpupgrade" | "xhttp" | "kcp"
            )
        }
        CoreKind::Mihomo => {
            // Keep the matrix in sync with mihomo_config::build.
            matches!(
                profile.protocol.as_str(),
                "vless" | "trojan" | "vmess" | "hysteria2"
            ) && matches!(
                profile.transport.as_str(),
                "native" | "tcp" | "ws" | "grpc" | "http"
            )
        }
    }
}

#[derive(Clone, Debug)]
pub struct CorePlan {
    pub core: CoreKind,
    /// Some(port) when sing-box must chain into a specialised core over SOCKS5.
    pub bridge_port: Option<u16>,
    pub reason: String,
    pub profile: ServerProfile,
}

fn finish(core: CoreKind, profile: ServerProfile, reason: String) -> CorePlan {
    let bridge_port = if core == CoreKind::SingBox { None } else { Some(BRIDGE_PORT) };
    CorePlan { core, bridge_port, reason, profile }
}

/// Picks the core for a server. `preference` is "auto" or a core id.
pub fn plan(server: &Server, preference: &str) -> Result<CorePlan, String> {
    let profile = profile(server)?;
    let protocol = protocol_label(&profile);
    let transport = transport_label(&profile);
    let requested = preference.trim();

    if !requested.is_empty() && !requested.eq_ignore_ascii_case("auto") {
        let core = CoreKind::from_id(requested)
            .ok_or_else(|| format!("Неизвестное ядро \"{requested}\""))?;
        if !supports(core, &profile) {
            let fallback = ALL_CORES
                .iter()
                .copied()
                .find(|candidate| supports(*candidate, &profile));
            let hint = match fallback {
                Some(candidate) => format!(
                    " Этот сервер умеет обслуживать {}: включите режим \"Авто\".",
                    candidate.title()
                ),
                None => String::new(),
            };
            return Err(format!(
                "{} не поддерживает {} + {}.{hint}",
                core.title(),
                protocol,
                transport
            ));
        }
        return Ok(finish(
            core,
            profile,
            format!("Ядро выбрано вручную: {} · {protocol} + {transport}", core.title()),
        ));
    }

    for core in ALL_CORES {
        if supports(core, &profile) {
            let reason = format!(
                "Автовыбор: {} — единственное подходящее или приоритетное ядро для {protocol} + {transport}",
                core.title()
            );
            return Ok(finish(core, profile, reason));
        }
    }

    Err(format!(
        "Ни sing-box, ни Xray-core, ни Mihomo не поддерживают {protocol} + {transport}. Выберите другой сервер из подписки."
    ))
}

/// Compact JSON description used by the UI to show a core badge per server.
pub fn describe(server: &Server, preference: &str) -> serde_json::Value {
    match plan(server, preference) {
        Ok(plan) => json!({
            "id": server.id,
            "supported": true,
            "core": plan.core.id(),
            "core_title": plan.core.title(),
            "bridged": plan.bridge_port.is_some(),
            "protocol": protocol_label(&plan.profile),
            "transport": transport_label(&plan.profile),
            "reason": plan.reason
        }),
        Err(error) => json!({
            "id": server.id,
            "supported": false,
            "core": serde_json::Value::Null,
            "core_title": "—",
            "bridged": false,
            "reason": error
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(uri: &str, protocol: &str) -> Server {
        Server {
            id: "test".into(),
            name: "Test".into(),
            protocol: protocol.into(),
            host: "example.com".into(),
            port: 443,
            uri: uri.into(),
            latency_ms: None,
        }
    }

    #[test]
    fn reality_tcp_uses_sing_box_without_bridge() {
        let node = server(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&pbk=key&sid=ab&type=tcp&flow=xtls-rprx-vision#Node",
            "vless",
        );
        let plan = plan(&node, "auto").expect("plan");
        assert_eq!(plan.core, CoreKind::SingBox);
        assert!(plan.bridge_port.is_none());
    }

    #[test]
    fn xhttp_falls_back_to_xray_with_bridge() {
        let node = server(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=xhttp&path=/x&mode=auto#Node",
            "vless",
        );
        let plan = plan(&node, "auto").expect("plan");
        assert_eq!(plan.core, CoreKind::Xray);
        assert_eq!(plan.bridge_port, Some(BRIDGE_PORT));
    }

    #[test]
    fn hysteria2_is_rejected_by_xray_but_served_by_mihomo() {
        let node = server("hysteria2://secret@example.com:443?sni=example.com#Node", "hysteria2");
        let profile = profile(&node).expect("profile");
        assert!(!supports(CoreKind::Xray, &profile));
        assert!(supports(CoreKind::Mihomo, &profile));
        let forced = plan(&node, "mihomo").expect("plan");
        assert_eq!(forced.core, CoreKind::Mihomo);
        assert!(plan(&node, "xray").is_err());
    }

    #[test]
    fn mkcp_requires_xray() {
        let node = server(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=kcp&security=none#Node",
            "vless",
        );
        let plan = plan(&node, "auto").expect("plan");
        assert_eq!(plan.core, CoreKind::Xray);
    }
}

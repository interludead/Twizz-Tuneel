use crate::model::Server;
use serde_json::{json, Value};
use url::Url;

/// Builds an Xray-core configuration that exposes a local SOCKS5 inbound and
/// sends everything to the selected server. sing-box keeps TUN, DNS and routing,
/// Xray only owns the outbound protocol/transport (XHTTP, mKCP, Vision, ...).
pub fn build(server: &Server, listen_port: u16) -> Result<Value, String> {
    let url = Url::parse(&server.uri).map_err(|error| error.to_string())?;
    let value = |key: &str| -> String {
        url.query_pairs()
            .find(|(name, _)| name == key)
            .map(|(_, item)| item.into_owned())
            .unwrap_or_default()
    };
    let secret = percent_encoding::percent_decode_str(url.username())
        .decode_utf8_lossy()
        .into_owned();

    let outbound = match server.protocol.trim().to_ascii_lowercase().as_str() {
        "vless" => {
            let mut user = json!({"id": secret, "encryption": "none"});
            let flow = value("flow");
            if !flow.trim().is_empty() {
                user["flow"] = json!(flow);
            }
            json!({
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": server.host,
                        "port": server.port,
                        "users": [user]
                    }]
                },
                "streamSettings": stream_settings(&url, server)?
            })
        }
        "vmess" => json!({
            "tag": "proxy",
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": server.host,
                    "port": server.port,
                    "users": [{"id": secret, "alterId": 0, "security": "auto"}]
                }]
            },
            "streamSettings": stream_settings(&url, server)?
        }),
        "trojan" => json!({
            "tag": "proxy",
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": server.host,
                    "port": server.port,
                    "password": secret
                }]
            },
            "streamSettings": stream_settings(&url, server)?
        }),
        other => {
            return Err(format!(
                "Xray-core в LZT Tunnel не обслуживает протокол \"{other}\""
            ))
        }
    };

    Ok(json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "bridge-in",
            "listen": "127.0.0.1",
            "port": listen_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": true, "ip": "127.0.0.1"},
            "sniffing": {"enabled": false}
        }],
        "outbounds": [
            outbound,
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "block", "protocol": "blackhole", "settings": {}}
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{"type": "field", "network": "tcp,udp", "outboundTag": "proxy"}]
        }
    }))
}

fn stream_settings(url: &Url, server: &Server) -> Result<Value, String> {
    let value = |key: &str| -> String {
        url.query_pairs()
            .find(|(name, _)| name == key)
            .map(|(_, item)| item.into_owned())
            .unwrap_or_default()
    };
    let raw_transport = {
        let direct = value("type");
        if direct.trim().is_empty() { value("network") } else { direct }
    };
    let transport = raw_transport.trim().to_ascii_lowercase();
    let network = match transport.as_str() {
        "" | "tcp" | "raw" | "none" | "original" => "tcp",
        "ws" | "websocket" => "ws",
        "grpc" | "gun" => "grpc",
        "http" | "h2" | "h2c" => "h2",
        "httpupgrade" => "httpupgrade",
        "xhttp" | "splithttp" => "xhttp",
        "kcp" | "mkcp" => "kcp",
        other => {
            return Err(format!(
                "Транспорт \"{other}\" не поддерживается Xray-core"
            ))
        }
    };

    let path = {
        let raw = value("path");
        if raw.trim().is_empty() { "/".to_string() } else { raw }
    };
    let host_header = value("host");
    let sni = {
        let raw = value("sni");
        if raw.trim().is_empty() { server.host.clone() } else { raw }
    };
    let fingerprint = {
        let raw = value("fp");
        if raw.trim().is_empty() { "chrome".to_string() } else { raw }
    };
    let public_key = value("pbk");
    let insecure = value("allowInsecure") == "1" || value("insecure") == "1";
    let declared_security = value("security").trim().to_ascii_lowercase();
    let security = if !public_key.trim().is_empty() || declared_security == "reality" {
        "reality"
    } else if declared_security == "none" {
        "none"
    } else {
        "tls"
    };

    let mut settings = json!({"network": network, "security": security});

    if security == "reality" {
        settings["realitySettings"] = json!({
            "serverName": sni,
            "fingerprint": fingerprint,
            "publicKey": public_key,
            "shortId": value("sid"),
            "spiderX": value("spx")
        });
    } else if security == "tls" {
        let mut tls = json!({
            "serverName": sni,
            "fingerprint": fingerprint,
            "allowInsecure": insecure
        });
        let alpn = value("alpn");
        if !alpn.trim().is_empty() {
            tls["alpn"] = json!(alpn
                .split(',')
                .map(|item| item.trim().to_string())
                .filter(|item| !item.is_empty())
                .collect::<Vec<String>>());
        }
        settings["tlsSettings"] = tls;
    }

    match network {
        "ws" => {
            let mut options = json!({"path": path});
            if !host_header.trim().is_empty() {
                options["host"] = json!(host_header.clone());
                options["headers"] = json!({"Host": host_header});
            }
            settings["wsSettings"] = options;
        }
        "grpc" => {
            settings["grpcSettings"] = json!({
                "serviceName": value("serviceName"),
                "multiMode": value("mode") == "multi"
            });
        }
        "h2" => {
            let mut options = json!({"path": path});
            if !host_header.trim().is_empty() {
                options["host"] = json!([host_header]);
            }
            settings["httpSettings"] = options;
        }
        "httpupgrade" => {
            let mut options = json!({"path": path});
            if !host_header.trim().is_empty() {
                options["host"] = json!(host_header);
            }
            settings["httpupgradeSettings"] = options;
        }
        "xhttp" => {
            let mode = {
                let raw = value("mode");
                if raw.trim().is_empty() { "auto".to_string() } else { raw }
            };
            let mut options = json!({"path": path, "mode": mode});
            if !host_header.trim().is_empty() {
                options["host"] = json!(host_header);
            }
            let extra = value("extra");
            if !extra.trim().is_empty() {
                if let Ok(parsed) = serde_json::from_str::<Value>(&extra) {
                    options["extra"] = parsed;
                }
            }
            settings["xhttpSettings"] = options;
        }
        "kcp" => {
            let header = {
                let raw = value("headerType");
                if raw.trim().is_empty() { "none".to_string() } else { raw }
            };
            let mut options = json!({"header": {"type": header}});
            let seed = value("seed");
            if !seed.trim().is_empty() {
                options["seed"] = json!(seed);
            }
            settings["kcpSettings"] = options;
        }
        _ => {}
    }

    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(uri: &str, protocol: &str) -> Server {
        Server {
            id: "id".into(),
            name: "Node".into(),
            protocol: protocol.into(),
            host: "example.com".into(),
            port: 443,
            uri: uri.into(),
            latency_ms: None,
        }
    }

    #[test]
    fn builds_xhttp_outbound() {
        let node = server(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=xhttp&path=%2Fdl&host=cdn.example.com&mode=packet-up&sni=cdn.example.com#Node",
            "vless",
        );
        let config = build(&node, 2081).expect("config");
        let stream = &config["outbounds"][0]["streamSettings"];
        assert_eq!(stream["network"], "xhttp");
        assert_eq!(stream["security"], "tls");
        assert_eq!(stream["xhttpSettings"]["path"], "/dl");
        assert_eq!(stream["xhttpSettings"]["mode"], "packet-up");
        assert_eq!(config["inbounds"][0]["port"], 2081);
        assert_eq!(config["inbounds"][0]["protocol"], "socks");
    }

    #[test]
    fn builds_reality_vision_outbound() {
        let node = server(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&pbk=pub&sid=ab&fp=chrome&flow=xtls-rprx-vision&type=tcp#Node",
            "vless",
        );
        let config = build(&node, 2081).expect("config");
        let outbound = &config["outbounds"][0];
        assert_eq!(outbound["settings"]["vnext"][0]["users"][0]["flow"], "xtls-rprx-vision");
        assert_eq!(outbound["streamSettings"]["security"], "reality");
        assert_eq!(outbound["streamSettings"]["realitySettings"]["publicKey"], "pub");
    }

    #[test]
    fn rejects_hysteria2() {
        let node = server("hysteria2://secret@example.com:443#Node", "hysteria2");
        assert!(build(&node, 2081).is_err());
    }
}

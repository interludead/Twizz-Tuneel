use crate::model::Server;
use serde_json::{json, Value};
use url::Url;

/// Builds a Mihomo (Clash.Meta) configuration with a single proxy and a local
/// mixed inbound. JSON is a valid YAML subset, so the generated document is
/// written as `bridge.yaml` and accepted by Mihomo as-is.
pub fn build(server: &Server, listen_port: u16, ipv6: bool) -> Result<Value, String> {
    let proxy = proxy(server)?;
    Ok(json!({
        "mixed-port": listen_port,
        "bind-address": "127.0.0.1",
        "allow-lan": false,
        "mode": "rule",
        "log-level": "warning",
        "ipv6": ipv6,
        "unified-delay": true,
        "external-controller": "",
        "geo-auto-update": false,
        "profile": {"store-selected": false, "store-fake-ip": false},
        "dns": {"enable": false},
        "proxies": [proxy],
        "rules": ["MATCH,LZT"]
    }))
}

fn proxy(server: &Server) -> Result<Value, String> {
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
    let sni = {
        let raw = value("sni");
        if raw.trim().is_empty() { server.host.clone() } else { raw }
    };
    let insecure = value("insecure") == "1" || value("allowInsecure") == "1";

    match server.protocol.trim().to_ascii_lowercase().as_str() {
        "vless" => {
            let public_key = value("pbk");
            let declared = value("security").trim().to_ascii_lowercase();
            let mut proxy = json!({
                "name": "LZT",
                "type": "vless",
                "server": server.host,
                "port": server.port,
                "uuid": secret,
                "udp": true,
                "tls": declared != "none",
                "servername": sni,
                "skip-cert-verify": insecure
            });
            let flow = value("flow");
            if !flow.trim().is_empty() {
                proxy["flow"] = json!(flow);
            }
            let reality = !public_key.trim().is_empty() || declared == "reality";
            // Mihomo needs a client fingerprint for REALITY; links without `fp`
            // otherwise produce a connection that establishes and carries no data.
            let fingerprint = {
                let raw = value("fp");
                if raw.trim().is_empty() {
                    if reality { "chrome".to_string() } else { String::new() }
                } else {
                    raw
                }
            };
            if !fingerprint.trim().is_empty() {
                proxy["client-fingerprint"] = json!(fingerprint);
            }
            if reality {
                proxy["tls"] = json!(true);
                proxy["reality-opts"] = json!({
                    "public-key": public_key,
                    "short-id": value("sid")
                });
            }
            apply_transport(&mut proxy, &value)?;
            Ok(proxy)
        }
        "trojan" => {
            let mut proxy = json!({
                "name": "LZT",
                "type": "trojan",
                "server": server.host,
                "port": server.port,
                "password": secret,
                "udp": true,
                "sni": sni,
                "skip-cert-verify": insecure
            });
            apply_transport(&mut proxy, &value)?;
            Ok(proxy)
        }
        "hysteria2" => {
            let mut proxy = json!({
                "name": "LZT",
                "type": "hysteria2",
                "server": server.host,
                "port": server.port,
                "password": secret,
                "sni": sni,
                "skip-cert-verify": insecure
            });
            let obfs = value("obfs");
            if !obfs.trim().is_empty() {
                proxy["obfs"] = json!(obfs);
                proxy["obfs-password"] = json!(value("obfs-password"));
            }
            Ok(proxy)
        }
        "vmess" => {
            let public_key = value("pbk");
            let declared = value("security").trim().to_ascii_lowercase();
            let reality = !public_key.trim().is_empty() || declared == "reality";
            let mut proxy = json!({
                "name": "LZT",
                "type": "vmess",
                "server": server.host,
                "port": server.port,
                "uuid": secret,
                "alterId": 0,
                "cipher": "auto",
                "udp": true,
                "tls": declared == "tls" || reality,
                "servername": sni,
                "skip-cert-verify": insecure
            });
            if reality {
                let fingerprint = {
                    let raw = value("fp");
                    if raw.trim().is_empty() { "chrome".to_string() } else { raw }
                };
                proxy["client-fingerprint"] = json!(fingerprint);
                proxy["reality-opts"] = json!({
                    "public-key": public_key,
                    "short-id": value("sid")
                });
            }
            apply_transport(&mut proxy, &value)?;
            Ok(proxy)
        }
        other => Err(format!(
            "Mihomo в LZT Tunnel не обслуживает протокол \"{other}\""
        )),
    }
}

fn apply_transport<F>(proxy: &mut Value, value: &F) -> Result<(), String>
where
    F: Fn(&str) -> String,
{
    let raw_transport = {
        let direct = value("type");
        if direct.trim().is_empty() { value("network") } else { direct }
    };
    let transport = raw_transport.trim().to_ascii_lowercase();
    let path = {
        let raw = value("path");
        if raw.trim().is_empty() { "/".to_string() } else { raw }
    };
    let host_header = value("host");

    match transport.as_str() {
        "" | "tcp" | "raw" | "none" | "original" => {
            proxy["network"] = json!("tcp");
        }
        "ws" | "websocket" => {
            proxy["network"] = json!("ws");
            let mut options = json!({"path": path});
            if !host_header.trim().is_empty() {
                options["headers"] = json!({"Host": host_header});
            }
            proxy["ws-opts"] = options;
        }
        "grpc" | "gun" => {
            proxy["network"] = json!("grpc");
            proxy["grpc-opts"] = json!({"grpc-service-name": value("serviceName")});
        }
        "http" | "h2" | "h2c" => {
            proxy["network"] = json!("h2");
            let mut options = json!({"path": path});
            if !host_header.trim().is_empty() {
                options["host"] = json!([host_header]);
            }
            proxy["h2-opts"] = options;
        }
        other => {
            return Err(format!(
                "Транспорт \"{other}\" не поддерживается Mihomo"
            ))
        }
    }
    Ok(())
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
    fn builds_vless_ws_proxy() {
        let node = server(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=ws&path=%2Fws&host=cdn.example.com&sni=cdn.example.com#Node",
            "vless",
        );
        let config = build(&node, 2081, false).expect("config");
        assert_eq!(config["mixed-port"], 2081);
        let proxy = &config["proxies"][0];
        assert_eq!(proxy["type"], "vless");
        assert_eq!(proxy["network"], "ws");
        assert_eq!(proxy["ws-opts"]["path"], "/ws");
        assert_eq!(proxy["ws-opts"]["headers"]["Host"], "cdn.example.com");
        assert_eq!(config["rules"][0], "MATCH,LZT");
    }

    #[test]
    fn builds_hysteria2_proxy() {
        let node = server(
            "hysteria2://secret@example.com:443?sni=example.com&obfs=salamander&obfs-password=pw#Node",
            "hysteria2",
        );
        let config = build(&node, 2081, true).expect("config");
        let proxy = &config["proxies"][0];
        assert_eq!(proxy["type"], "hysteria2");
        assert_eq!(proxy["obfs"], "salamander");
        assert_eq!(proxy["obfs-password"], "pw");
        assert_eq!(config["ipv6"], true);
    }

    #[test]
    fn rejects_xhttp() {
        let node = server(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=xhttp#Node",
            "vless",
        );
        assert!(build(&node, 2081, false).is_err());
    }
}

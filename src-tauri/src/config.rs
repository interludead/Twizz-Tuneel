use crate::model::{ConnectRequest, Server};
use serde_json::{json, Value};
use url::Url;

fn query(url: &Url, key: &str) -> Option<String> {
    url.query_pairs().find(|(k, _)| k == key).map(|(_, v)| v.into_owned())
}

/// sing-box supports only these stream transports: ws, grpc, http (h2), httpupgrade, quic.
/// Xray-only transports (xhttp/splithttp, mKCP, ...) must be rejected with a readable
/// message instead of being passed through, otherwise sing-box dies with
/// `unknown transport type: xhttp` while decoding active.json.
fn transport_object(url: &Url, kind: &str) -> Result<Value, String> {
    let path = query(url, "path").unwrap_or_else(|| "/".into());
    let host = query(url, "host").unwrap_or_default();
    match kind {
        "ws" => {
            let mut value = json!({"type":"ws","path":path});
            if !host.is_empty() {
                value["headers"] = json!({"Host":host});
            }
            if let Some(early) = query(url, "ed").and_then(|v| v.parse::<u32>().ok()) {
                value["max_early_data"] = json!(early);
                value["early_data_header_name"] = json!(query(url, "eh")
                    .unwrap_or_else(|| "Sec-WebSocket-Protocol".into()));
            }
            Ok(value)
        }
        "grpc" => Ok(json!({
            "type":"grpc",
            "service_name":query(url, "serviceName").unwrap_or_default()
        })),
        "httpupgrade" => {
            let mut value = json!({"type":"httpupgrade","path":path});
            if !host.is_empty() {
                value["host"] = json!(host);
            }
            Ok(value)
        }
        "http" | "h2" | "h2c" => {
            let mut value = json!({"type":"http","path":path});
            if !host.is_empty() {
                value["host"] = json!([host]);
            }
            Ok(value)
        }
        "quic" => Ok(json!({"type":"quic"})),
        "xhttp" | "splithttp" => Err("Сервер использует транспорт XHTTP (SplitHTTP), который поддерживает только Xray-core. sing-box с ним работать не может — выберите другой сервер из подписки.".into()),
        "kcp" | "mkcp" => Err("Сервер использует транспорт mKCP, не поддерживаемый sing-box. Выберите другой сервер из подписки.".into()),
        other => Err(format!(
            "Транспорт \"{other}\" не поддерживается sing-box. Выберите другой сервер из подписки."
        )),
    }
}

fn is_plain_transport(kind: &str) -> bool {
    matches!(kind, "" | "tcp" | "raw" | "none" | "original")
}

fn outbound(server: &Server) -> Result<Value, String> {
    let url = Url::parse(&server.uri).map_err(|e| e.to_string())?;
    let password = percent_encoding::percent_decode_str(url.username()).decode_utf8_lossy().into_owned();
    match server.protocol.as_str() {
        "vless" => {
            // Many subscriptions ship REALITY links without `security=reality`:
            // the presence of a public key is the reliable signal. Treating such
            // a node as plain TLS makes the handshake succeed while the server
            // silently drops the session ("connected, but no internet").
            let public_key = query(&url, "pbk").unwrap_or_default();
            let declared = query(&url, "security").unwrap_or_default().trim().to_ascii_lowercase();
            let security = if !public_key.trim().is_empty() || declared == "reality" {
                "reality".to_string()
            } else if declared == "none" {
                "none".to_string()
            } else {
                "tls".to_string()
            };
            let transport = query(&url, "type").unwrap_or_else(|| "tcp".into());
            let mut tls = json!({
                "enabled": security != "none",
                "server_name": query(&url, "sni").unwrap_or_else(|| server.host.clone()),
                "insecure": query(&url, "allowInsecure").as_deref() == Some("1")
                    || query(&url, "insecure").as_deref() == Some("1")
            });
            // REALITY requires uTLS; a link without `fp` must still get a
            // fingerprint, otherwise sing-box negotiates a handshake the server
            // refuses to serve.
            let fingerprint = query(&url, "fp")
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "chrome".into());
            tls["utls"] = json!({"enabled": true, "fingerprint": fingerprint});
            if let Some(alpn) = query(&url, "alpn").filter(|value| !value.trim().is_empty()) {
                let list: Vec<String> = alpn
                    .split(',')
                    .map(|item| item.trim().to_string())
                    .filter(|item| !item.is_empty())
                    .collect();
                if !list.is_empty() && security != "reality" {
                    tls["alpn"] = json!(list);
                }
            }
            if security == "reality" {
                tls["reality"] = json!({
                    "enabled": true,
                    "public_key": public_key,
                    "short_id": query(&url, "sid").unwrap_or_default()
                });
            }
            let mut result = json!({
                "type": "vless", "tag": "proxy", "server": server.host,
                "server_port": server.port, "uuid": password,
                "tls": tls,
                "domain_resolver": "bootstrap"
            });
            if let Some(flow) = query(&url, "flow").filter(|value| !value.trim().is_empty()) {
                result["flow"] = json!(flow);
            }
            if security == "none" {
                result["tls"] = json!({"enabled": false});
            }
            if !is_plain_transport(transport.as_str()) {
                result["transport"] = transport_object(&url, transport.as_str())?;
            }
            Ok(result)
        }
        "trojan" => {
            let transport=query(&url,"type").unwrap_or_else(||"tcp".into());
            let mut value=json!({"type":"trojan","tag":"proxy","server":server.host,"server_port":server.port,"password":password,"domain_resolver":"bootstrap","tls":{"enabled":true,"server_name":query(&url,"sni").unwrap_or_else(||server.host.clone()),"insecure":query(&url,"insecure").as_deref()==Some("1")||query(&url,"allowInsecure").as_deref()==Some("1")}});
            if let Some(fp) = query(&url, "fp") {
                value["tls"]["utls"] = json!({"enabled": true, "fingerprint": fp});
            }
            if let Some(alpn) = query(&url, "alpn") {
                let list: Vec<String> = alpn.split(',').map(|item| item.trim().to_string()).filter(|item| !item.is_empty()).collect();
                if !list.is_empty() { value["tls"]["alpn"] = json!(list); }
            }
            if !is_plain_transport(transport.as_str()) {
                value["transport"] = transport_object(&url, transport.as_str())?;
            }
            Ok(value)
        }
        "hysteria2" => {
            let mut value = json!({
                "type":"hysteria2", "tag":"proxy", "server":server.host,
                "server_port":server.port, "password":password,
                "domain_resolver":"bootstrap",
                "tls":{"enabled":true,"server_name":query(&url,"sni").unwrap_or_else(||server.host.clone()),"insecure":query(&url,"insecure").as_deref()==Some("1")||query(&url,"allowInsecure").as_deref()==Some("1")}
            });
            if let Some(alpn) = query(&url, "alpn") {
                let list: Vec<String> = alpn.split(',').map(|item| item.trim().to_string()).filter(|item| !item.is_empty()).collect();
                if !list.is_empty() { value["tls"]["alpn"] = json!(list); }
            }
            // `obfs` must be omitted entirely when the node does not use Salamander;
            // a null object makes sing-box reject the whole outbound.
            if let Some(kind) = query(&url, "obfs").filter(|value| !value.trim().is_empty()) {
                value["obfs"] = json!({"type":kind,"password":query(&url,"obfs-password").unwrap_or_default()});
            }
            Ok(value)
        }
        "vmess" => { let transport=query(&url,"type").unwrap_or_else(||"tcp".into());let mut v=json!({"type":"vmess","tag":"proxy","server":server.host,"server_port":server.port,"uuid":password,"alter_id":query(&url,"aid").and_then(|x|x.parse::<u32>().ok()).unwrap_or(0),"security":"auto","domain_resolver":"bootstrap"});if query(&url,"security").as_deref()!=Some("none"){v["tls"]=json!({"enabled":true,"server_name":query(&url,"sni").unwrap_or_else(||server.host.clone())});}if !is_plain_transport(&transport){v["transport"]=transport_object(&url,&transport)?;}Ok(v) },
        "shadowsocks" => Ok(json!({"type":"shadowsocks","tag":"proxy","server":server.host,"server_port":server.port,"method":query(&url,"method").unwrap_or_else(||"aes-128-gcm".into()),"password":password,"domain_resolver":"bootstrap"})),
        "tuic" => Ok(json!({"type":"tuic","tag":"proxy","server":server.host,"server_port":server.port,"uuid":password,"password":url.password().map(|v|percent_encoding::percent_decode_str(v).decode_utf8_lossy().into_owned()).unwrap_or_default(),"congestion_control":query(&url,"congestion_control").unwrap_or_else(||"bbr".into()),"udp_relay_mode":query(&url,"udp_relay_mode").unwrap_or_else(||"native".into()),"domain_resolver":"bootstrap","tls":{"enabled":true,"server_name":query(&url,"sni").unwrap_or_else(||server.host.clone())}})),
        "anytls" => Ok(json!({"type":"anytls","tag":"proxy","server":server.host,"server_port":server.port,"password":password,"domain_resolver":"bootstrap","tls":{"enabled":true,"server_name":query(&url,"sni").unwrap_or_else(||server.host.clone())}})),
        _ => Err(format!("Неподдерживаемый протокол: {}",server.protocol)),
    }
}

/// Returns either the native sing-box outbound or a SOCKS5 outbound pointing at
/// the local Xray-core / Mihomo bridge.
fn proxy_outbound(server: &Server, bridge: Option<(u16, &str)>) -> Result<Value, String> {
    match bridge {
        Some((port, _)) => Ok(json!({
            "type":"socks",
            "tag":"proxy",
            "server":"127.0.0.1",
            "server_port":port,
            "version":"5",
            "domain_resolver":"bootstrap"
        })),
        None => outbound(server),
    }
}

fn is_ip_literal(host: &str) -> bool {
    let trimmed = host.trim().trim_start_matches('[').trim_end_matches(']');
    trimmed.parse::<std::net::IpAddr>().is_ok()
}

/// Builds a sing-box 1.12+ DNS server object (new format, no `address` field).
fn dns_server(tag: &str, address: &str, detour: &str) -> Value {
    let raw = address.trim();
    let lower = raw.to_ascii_lowercase();
    if raw.is_empty() || lower == "local" || lower == "system" || lower == "dhcp" || lower.starts_with("local://") || lower.starts_with("dhcp://") || lower == "fakeip" {
        return json!({"type":"local","tag":tag});
    }
    if raw.contains("://") {
        if let Ok(url) = Url::parse(raw) {
            let scheme = url.scheme().to_ascii_lowercase();
            let host = url.host_str().unwrap_or("1.1.1.1").to_string();
            let kind = match scheme.as_str() {
                "https" => "https",
                "h3" => "h3",
                "tls" => "tls",
                "quic" => "quic",
                "tcp" => "tcp",
                _ => "udp",
            };
            let mut value = json!({"type":kind,"tag":tag,"server":host.clone(),"detour":detour});
            // sing-box 1.12+: a DNS server addressed by hostname must declare how that
            // hostname itself is resolved, otherwise startup fails with
            // `missing route.default_domain_resolver or domain_resolver in dial fields`.
            if !is_ip_literal(&host) {
                value["domain_resolver"] = json!("bootstrap");
            }
            if let Some(port) = url.port() {
                value["server_port"] = json!(port);
            }
            if kind == "https" || kind == "h3" {
                let path = url.path();
                if !path.is_empty() && path != "/" {
                    value["path"] = json!(path);
                }
            }
            return value;
        }
    }
    let (host, port) = match raw.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => (h.to_string(), p.parse::<u16>().ok()),
        _ => (raw.to_string(), None),
    };
    let mut value = json!({"type":"udp","tag":tag,"server":host.clone(),"detour":detour});
    if !is_ip_literal(&host) {
        value["domain_resolver"] = json!("bootstrap");
    }
    if let Some(port) = port {
        value["server_port"] = json!(port);
    }
    value
}

/// sing-box still ships the legacy Clash API in 1.11–1.13 and drops it in
/// 1.14; unknown top-level fields make `check` fail hard, so the block is only
/// emitted for versions known to accept it. Unknown versions default to on:
/// the builder currently fetches 1.12.x, where the API works.
pub fn supports_clash_api(version_text: &str) -> bool {
    let token = version_text
        .split_whitespace()
        .find(|part| part.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false));
    let Some(token) = token else { return true };
    let mut parts = token.trim_start_matches('v').split('.');
    let major: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(1);
    let minor: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    major < 1 || (major == 1 && minor < 14)
}

/// Builds the sing-box configuration.
///
/// `bridge` is `Some((port, process_name))` when a specialised protocol core
/// (Xray-core or Mihomo) owns the outbound. In that case sing-box keeps TUN,
/// DNS, sniffing and routing and forwards traffic into the local SOCKS5 bridge,
/// while the upstream core process itself is routed directly so its own
/// connection to the server cannot loop back into the tunnel.
pub fn build(request:&ConnectRequest,bridge:Option<(u16,&str)>,stats_port:Option<u16>,bypass_ips:&[String],probe_port:u16,profile_sets:&[(String, std::path::PathBuf)])->Result<Value,String>{
    // The loopback mixed inbound exists in both modes: the UI measures the
    // exit IP through it while TUN owns the rest of the traffic.
    let mixed = json!({"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":2080});
    let tun_addresses=if request.ipv6_mode=="tunnel"{vec!["172.19.0.1/30","fdfe:dcba:9876::1/126"]}else{vec!["172.19.0.1/30"]};
    let mut inbounds = if request.mode == "tun" {
        vec![
            json!({"type":"tun","tag":"tun-in","interface_name":"lzt-tun","address":tun_addresses,"mtu":1420,"auto_route":true,"strict_route":request.strict_route,"stack":"mixed"}),
            mixed,
        ]
    } else {
        vec![mixed]
    };
    inbounds.push(json!({"type":"mixed","tag":"health-in","listen":"127.0.0.1","listen_port":probe_port}));
    let mut route_rules=vec![json!({"inbound":["health-in"],"outbound":"proxy"})];
    if bridge.is_some()&&!bypass_ips.is_empty(){let xs:Vec<String>=bypass_ips.iter().map(|ip|if ip.contains(':'){format!("{ip}/128")}else{format!("{ip}/32")}).collect();route_rules.push(json!({"ip_cidr":xs,"outbound":"direct"}));}
    if let Some((_, process_name)) = bridge {
        route_rules.push(json!({"process_name":[process_name],"outbound":"direct"}));
    }
    // Latency probes and subscription updates are made by the app process and
    // must leave from the original IP even while TUN is up. The rule is scoped
    // to tun-in, so connections entering via the loopback proxy inbound (the
    // exit-IP check) are still routed through the VPN.
    if request.mode == "tun" {
        if let Some(exe) = std::env::current_exe().ok().and_then(|path| path.file_name().map(|name| name.to_string_lossy().into_owned())) {
            route_rules.push(json!({"inbound":["tun-in"],"process_name":[exe],"outbound":"direct"}));
        }
    }
    if request.sniff { route_rules.push(json!({"action":"sniff"})); }
    if request.dns_hijack {
        route_rules.push(json!({"protocol":"dns","action":"hijack-dns"}));
        // Sniffing can miss plain UDP/TCP 53 traffic, so hijack the port as well.
        route_rules.push(json!({"network":"udp","port":[53],"action":"hijack-dns"}));
    }
    if request.ipv6_mode=="block" || (request.ipv6_mode.is_empty()&&!request.ipv6) { route_rules.push(json!({"ip_version":6,"action":"reject"})); }
    if request.block_quic { route_rules.push(json!({"network":"udp","port":[443],"action":"reject"})); }
    if request.allow_lan || request.routing_profile == crate::model::RoutingProfile::BypassRussia {
        route_rules.push(json!({"ip_is_private":true,"outbound":"direct"}));
    }
    let compiled=crate::route_compiler::compile(&request.rules);
    route_rules.extend(compiled.route_rules.clone());
    let mut rule_sets=compiled.rule_sets.clone();
    let mut final_outbound=compiled.final_outbound.clone();
    let profile_routes = request.routing_profile.routes();
    if let Some((outbound, fallback)) = profile_routes {
        final_outbound = fallback.into();
        let tags: Vec<&str> = profile_sets.iter().map(|(tag, _)| tag.as_str()).collect();
        for (tag, path) in profile_sets {
            rule_sets.push(json!({"type":"local","tag":tag,"format":"binary","path":path}));
        }
        route_rules.push(json!({"rule_set":tags,"outbound":outbound}));
    }
    if final_outbound == "block" {
        // sing-box 1.12 dropped the `block` outbound: express it as a catch-all reject.
        route_rules.push(json!({"network":["tcp","udp"],"action":"reject"}));
        final_outbound = "direct".to_string();
    }
    // Loopback-only Clash API exposes /connections with cumulative session
    // traffic, which the dashboard polls while connected.
    let mut experimental = json!({"cache_file":{"enabled":request.cache_enabled}});
    if let Some(port)=stats_port{experimental["clash_api"]=json!({"external_controller":format!("127.0.0.1:{port}")});}
    let requested=request.dns.trim();
    let secure_address=if requested.is_empty()||matches!(requested.to_ascii_lowercase().as_str(),"local"|"system"|"dhcp"|"fakeip"){"https://1.1.1.1/dns-query"}else{requested};
    let dns_strategy=if request.ipv6_mode=="block"{"ipv4_only"}else{"prefer_ipv4"};
    let proxy_dns_detour=if request.secure_dns{"proxy"}else{"direct"};
    let mut dns_servers=vec![json!({"type":"local","tag":"bootstrap"}),dns_server("direct",secure_address,"direct"),dns_server("proxy-dns",secure_address,proxy_dns_detour)];
    if request.dns_mode=="fakeip"{dns_servers.push(json!({"type":"fakeip","tag":"fakeip","inet4_range":"198.18.0.0/15","inet6_range":"fc00::/18"}));experimental["cache_file"]["store_fakeip"]=json!(true);}
    let mut dns_rules=vec![json!({"domain":[request.server.host.clone()],"server":"bootstrap"})];
    if request.dns_mode=="fakeip"{dns_rules.push(json!({"domain_suffix":["local","lan","home.arpa","in-addr.arpa","ip6.arpa"],"server":"direct"}));dns_rules.push(json!({"domain":["localhost","localhost.localdomain","connectivitycheck.gstatic.com","www.msftconnecttest.com","dns.msftncsi.com"],"server":"direct"}));}
    if !compiled.direct_domains.is_empty(){dns_rules.push(json!({"domain_suffix":compiled.direct_domains,"server":"direct"}));}
    if !compiled.proxy_domains.is_empty(){dns_rules.push(json!({"domain_suffix":compiled.proxy_domains,"server":"proxy-dns"}));}
    if let (Some((outbound, _)), Some((domain_tag, _))) = (profile_routes, profile_sets.first()) {
        if request.dns_mode == "split" {
            let server = if outbound == "proxy" { "proxy-dns" } else { "direct" };
            dns_rules.push(json!({"rule_set":[domain_tag],"server":server}));
        }
    }
    let dns_final=match request.dns_mode.as_str(){"system"=>"bootstrap","fakeip"=>"fakeip","direct"=>"direct",_ if final_outbound == "direct" && profile_routes.is_some()=>"direct",_=>"proxy-dns"};
    Ok(json!({
        "log":{"level":"info","timestamp":true},
        "dns":{
            "servers":dns_servers,
            "rules": dns_rules,
            "final":dns_final,
            "strategy": dns_strategy
        },
        "inbounds":inbounds,
        "outbounds":[proxy_outbound(&request.server, bridge)?,{"type":"direct","tag":"direct","domain_resolver":"bootstrap"}],
        "route":{
            "auto_detect_interface":true,
            // Required since sing-box 1.12: every outbound that dials a domain needs a
            // resolver. Without this the core aborts with a FATAL deprecation error.
            "default_domain_resolver":{"server":"bootstrap","strategy":dns_strategy},
            "rules":route_rules,
            "rule_set":rule_sets,
            "final":final_outbound
        },
        "experimental":experimental
    }))
}

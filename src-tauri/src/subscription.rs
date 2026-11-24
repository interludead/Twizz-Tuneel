use crate::model::{RouteRule, Server};
use base64::{engine::general_purpose, Engine};
use serde_yaml::{Mapping, Value as Yaml};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use url::{form_urlencoded, Url};

#[derive(Clone, Debug)]
pub struct RemoteRuleProvider {
    pub url: String,
    pub behavior: String,
    pub route: String,
}

#[derive(Default)]
pub struct ParsedSubscription {
    pub servers: Vec<Server>,
    pub rules: Vec<RouteRule>,
    pub remote_providers: Vec<RemoteRuleProvider>,
}

fn id(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))[..16].to_string()
}

fn yaml_string(value: Option<&Yaml>) -> Option<String> {
    match value? {
        Yaml::String(v) => Some(v.clone()),
        Yaml::Number(v) => Some(v.to_string()),
        Yaml::Bool(v) => Some(v.to_string()),
        _ => None,
    }
}

fn yaml_bool(value: Option<&Yaml>) -> bool {
    matches!(value, Some(Yaml::Bool(true)))
        || yaml_string(value).as_deref() == Some("true")
}

fn get<'a>(map: &'a Mapping, key: &str) -> Option<&'a Yaml> {
    map.get(Yaml::String(key.to_string()))
}

fn host_for_uri(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn make_query(pairs: Vec<(&str, String)>) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        if !value.is_empty() {
            serializer.append_pair(key, &value);
        }
    }
    serializer.finish()
}


fn decode_b64(value: &str) -> Option<String> {
    for engine in [&general_purpose::STANDARD,&general_purpose::URL_SAFE,&general_purpose::STANDARD_NO_PAD,&general_purpose::URL_SAFE_NO_PAD] {
        if let Ok(bytes)=engine.decode(value.trim().as_bytes()) { if let Ok(text)=String::from_utf8(bytes){return Some(text)} }
    }
    None
}
fn parse_vmess(raw:&str)->Option<Server>{
    let v:serde_json::Value=serde_json::from_str(&decode_b64(raw.strip_prefix("vmess://")?)?).ok()?;
    let host=v.get("add")?.as_str()?.to_string();
    let port_text=match v.get("port")? { serde_json::Value::String(value)=>value.clone(), serde_json::Value::Number(value)=>value.to_string(), _=>return None };
    let port=port_text.parse::<u16>().ok()?;
    let uuid=v.get("id")?.as_str()?;let name=v.get("ps").and_then(|x|x.as_str()).unwrap_or(&host).to_string();let net=v.get("net").and_then(|x|x.as_str()).unwrap_or("tcp");
    let q=make_query(vec![("type",net.into()),("security",if v.get("tls").and_then(|x|x.as_str()).unwrap_or("").is_empty(){"none".into()}else{"tls".into()}),("sni",v.get("sni").and_then(|x|x.as_str()).unwrap_or("").into()),("host",v.get("host").and_then(|x|x.as_str()).unwrap_or("").into()),("path",v.get("path").and_then(|x|x.as_str()).unwrap_or("").into()),("aid",v.get("aid").and_then(|x|x.as_u64()).unwrap_or(0).to_string())]);
    let u:String=form_urlencoded::byte_serialize(uuid.as_bytes()).collect();let n:String=form_urlencoded::byte_serialize(name.as_bytes()).collect();let uri=format!("vmess://{u}@{}:{port}?{q}#{n}",host_for_uri(&host));Some(Server{id:id(raw),name,protocol:"vmess".into(),host,port,uri,latency_ms:None})
}
fn parse_ss(raw:&str)->Option<Server>{
    let body=raw.strip_prefix("ss://")?.split('#').next()?;let decoded=decode_b64(body);let canonical=decoded.as_deref().unwrap_or(body);let (cred,endpoint)=canonical.rsplit_once('@')?;let cred=decode_b64(cred).unwrap_or_else(||cred.into());let (method,password)=cred.split_once(':')?;let u=Url::parse(&format!("ss://x@{endpoint}")).ok()?;let host=u.host_str()?.to_string();let port=u.port()?;let name=raw.split_once('#').map(|(_,v)|percent_encoding::percent_decode_str(v).decode_utf8_lossy().replace('+'," ")).unwrap_or_else(||host.clone());let pw:String=form_urlencoded::byte_serialize(password.as_bytes()).collect();let n:String=form_urlencoded::byte_serialize(name.as_bytes()).collect();let q=make_query(vec![("method",method.into())]);let uri=format!("shadowsocks://{pw}@{}:{port}?{q}#{n}",host_for_uri(&host));Some(Server{id:id(raw),name,protocol:"shadowsocks".into(),host,port,uri,latency_ms:None})
}

fn parse_uri(raw: &str) -> Option<Server> {
    let raw=raw.trim();
    if raw.starts_with("vmess://"){return parse_vmess(raw)}
    if raw.starts_with("ss://"){return parse_ss(raw)}
    let url=Url::parse(raw).ok()?;
    let protocol = match url.scheme().to_lowercase().as_str() {
        "vless" => "vless",
        "hysteria2" | "hy2" => "hysteria2",
        "trojan" => "trojan",
        "tuic" => "tuic",
        "anytls" => "anytls",
        "shadowsocks" => "shadowsocks",
        _ => return None,
    };
    let host = url.host_str()?.to_string();
    let port = url.port().unwrap_or(443);
    let name = url
        .fragment()
        .filter(|v| !v.is_empty())
        .unwrap_or(&host);
    let name = percent_encoding::percent_decode_str(name)
        .decode_utf8_lossy()
        .replace('+', " ");
    Some(Server {
        id: id(raw),
        name,
        protocol: protocol.to_string(),
        host,
        port,
        uri: raw.to_string(),
        latency_ms: None,
    })
}

fn clash_proxy(map: &Mapping) -> Option<Server> {
    let raw_protocol=yaml_string(get(map,"type"))?.to_lowercase();
    let protocol=match raw_protocol.as_str(){"hy2"=>"hysteria2","ss"=>"shadowsocks",other=>other};
    if !matches!(protocol,"vless"|"hysteria2"|"trojan"|"vmess"|"shadowsocks"|"tuic"|"anytls"){return None}
    let name=yaml_string(get(map,"name")).unwrap_or_else(||"Server".into());let host=yaml_string(get(map,"server"))?;let port=yaml_string(get(map,"port"))?.parse::<u16>().ok()?;
    if protocol=="shadowsocks"{let password=yaml_string(get(map,"password"))?;let method=yaml_string(get(map,"cipher")).or_else(||yaml_string(get(map,"method")))?;let pw:String=form_urlencoded::byte_serialize(password.as_bytes()).collect();let n:String=form_urlencoded::byte_serialize(name.as_bytes()).collect();let uri=format!("shadowsocks://{pw}@{}:{port}?{}#{n}",host_for_uri(&host),make_query(vec![("method",method)]));return Some(Server{id:id(&uri),name,protocol:protocol.into(),host,port,uri,latency_ms:None})}
    if protocol=="tuic"{let uuid=yaml_string(get(map,"uuid"))?;let password=yaml_string(get(map,"password"))?;let u:String=form_urlencoded::byte_serialize(uuid.as_bytes()).collect();let pw:String=form_urlencoded::byte_serialize(password.as_bytes()).collect();let n:String=form_urlencoded::byte_serialize(name.as_bytes()).collect();let q=make_query(vec![("sni",yaml_string(get(map,"sni")).unwrap_or_else(||host.clone())),("congestion_control",yaml_string(get(map,"congestion-controller")).unwrap_or_else(||"bbr".into())),("udp_relay_mode",yaml_string(get(map,"udp-relay-mode")).unwrap_or_else(||"native".into()))]);let uri=format!("tuic://{u}:{pw}@{}:{port}?{q}#{n}",host_for_uri(&host));return Some(Server{id:id(&uri),name,protocol:protocol.into(),host,port,uri,latency_ms:None})}
    if protocol=="anytls"{let password=yaml_string(get(map,"password"))?;let pw:String=form_urlencoded::byte_serialize(password.as_bytes()).collect();let n:String=form_urlencoded::byte_serialize(name.as_bytes()).collect();let uri=format!("anytls://{pw}@{}:{port}?{}#{n}",host_for_uri(&host),make_query(vec![("sni",yaml_string(get(map,"sni")).unwrap_or_else(||host.clone()))]));return Some(Server{id:id(&uri),name,protocol:protocol.into(),host,port,uri,latency_ms:None})}
    let user=if matches!(protocol,"vless"|"vmess"){yaml_string(get(map,"uuid"))?}else{yaml_string(get(map,"password")).or_else(||yaml_string(get(map,"auth")))?};
    let mut pairs:Vec<(&str,String)>=Vec::new();
    if protocol=="vless"||protocol=="vmess" {
        let reality = get(map, "reality-opts").and_then(Yaml::as_mapping);
        let security = if reality.is_some() {
            "reality"
        } else if yaml_bool(get(map, "tls")) {
            "tls"
        } else {
            "none"
        };
        pairs.push(("security", security.into()));
        pairs.push((
            "sni",
            yaml_string(get(map, "servername"))
                .or_else(|| yaml_string(get(map, "sni")))
                .unwrap_or_default(),
        ));
        pairs.push((
            "fp",
            yaml_string(get(map, "client-fingerprint")).unwrap_or_default(),
        ));
        pairs.push((
            "flow",
            yaml_string(get(map, "flow")).unwrap_or_default(),
        ));
        if let Some(reality) = reality {
            pairs.push((
                "pbk",
                yaml_string(get(reality, "public-key")).unwrap_or_default(),
            ));
            pairs.push((
                "sid",
                yaml_string(get(reality, "short-id")).unwrap_or_default(),
            ));
        }
        let network = yaml_string(get(map, "network")).unwrap_or_else(|| "tcp".into());
        pairs.push(("type", network.clone()));
        if network == "ws" {
            if let Some(options) = get(map, "ws-opts").and_then(Yaml::as_mapping) {
                pairs.push((
                    "path",
                    yaml_string(get(options, "path")).unwrap_or_else(|| "/".into()),
                ));
                let host_header = get(options, "headers")
                    .and_then(Yaml::as_mapping)
                    .and_then(|headers| yaml_string(get(headers, "Host")))
                    .unwrap_or_default();
                pairs.push(("host", host_header));
            }
        } else if network == "grpc" {
            if let Some(options) = get(map, "grpc-opts").and_then(Yaml::as_mapping) {
                pairs.push((
                    "serviceName",
                    yaml_string(get(options, "grpc-service-name")).unwrap_or_default(),
                ));
            }
        }
    } else if protocol == "trojan" {
        pairs.push(("sni", yaml_string(get(map, "sni")).or_else(|| yaml_string(get(map, "servername"))).unwrap_or_else(|| host.clone())));
        if yaml_bool(get(map, "skip-cert-verify")) { pairs.push(("insecure", "1".into())); }
        let network = yaml_string(get(map, "network")).unwrap_or_else(|| "tcp".into());
        pairs.push(("type", network.clone()));
        if network == "ws" {
            if let Some(options) = get(map, "ws-opts").and_then(Yaml::as_mapping) {
                pairs.push(("path", yaml_string(get(options, "path")).unwrap_or_else(|| "/".into())));
                let host_header = get(options, "headers").and_then(Yaml::as_mapping).and_then(|headers| yaml_string(get(headers, "Host")).or_else(|| yaml_string(get(headers, "host")))).unwrap_or_default();
                pairs.push(("host", host_header));
            }
        } else if network == "grpc" {
            if let Some(options) = get(map, "grpc-opts").and_then(Yaml::as_mapping) {
                pairs.push(("serviceName", yaml_string(get(options, "grpc-service-name")).unwrap_or_default()));
            }
        }
    } else {
        pairs.push(("sni", yaml_string(get(map, "sni")).or_else(|| yaml_string(get(map, "servername"))).unwrap_or_default()));
        if yaml_bool(get(map, "skip-cert-verify")) { pairs.push(("insecure", "1".into())); }
        let nested_obfs = get(map, "obfs-opts").and_then(Yaml::as_mapping);
        pairs.push(("obfs", yaml_string(get(map, "obfs")).or_else(|| nested_obfs.and_then(|options| yaml_string(get(options, "type")))).unwrap_or_default()));
        pairs.push(("obfs-password", yaml_string(get(map, "obfs-password")).or_else(|| nested_obfs.and_then(|options| yaml_string(get(options, "password")))).unwrap_or_default()));
    }

    let query = make_query(pairs);
    let encoded_user: String = form_urlencoded::byte_serialize(user.as_bytes()).collect();
    let encoded_name: String = form_urlencoded::byte_serialize(name.as_bytes()).collect();
    let uri = format!(
        "{protocol}://{encoded_user}@{}:{port}?{query}#{encoded_name}",
        host_for_uri(&host)
    );
    Some(Server {
        id: id(&uri),
        name,
        protocol: protocol.to_string(),
        host,
        port,
        uri,
        latency_ms: None,
    })
}

fn route_for_policy(policy: &str) -> String {
    match policy.trim().to_ascii_uppercase().as_str() {
        "DIRECT" => "direct".into(),
        "REJECT" | "REJECT-DROP" | "BLOCK" => "block".into(),
        _ => "proxy".into(),
    }
}

fn parse_clash_rule(line: &str, forced_route: Option<&str>) -> Option<RouteRule> {
    let parts: Vec<&str> = line.split(',').map(str::trim).collect();
    if parts.len() < 2 {
        return None;
    }
    let rule_type = parts[0].to_ascii_uppercase();
    let (kind, value, policy_index) = match rule_type.as_str() {
        "DOMAIN" => ("Точный домен", parts[1].to_string(), 2),
        "DOMAIN-SUFFIX" => ("Домен", parts[1].trim_start_matches("+.").to_string(), 2),
        "DOMAIN-KEYWORD" => ("Ключ домена", parts[1].to_string(), 2),
        "IP-CIDR" | "IP-CIDR6" => ("IP / CIDR", parts[1].to_string(), 2),
        "SRC-IP-CIDR" => ("IP источника / CIDR", parts[1].to_string(), 2),
        "PROCESS-NAME" => ("Приложение", parts[1].to_string(), 2),
        "PROCESS-PATH" => ("Путь приложения", parts[1].to_string(), 2),
        "NETWORK" => ("Сеть", parts[1].to_ascii_lowercase(), 2),
        "DST-PORT" => ("Порт назначения", parts[1].to_string(), 2),
        "SRC-PORT" => ("Порт источника", parts[1].to_string(), 2),
        "GEOIP" => ("GEOIP", parts[1].to_ascii_lowercase(), 2),
        "GEOSITE" => ("GEOSITE", parts[1].to_ascii_lowercase(), 2),
        "AND" | "OR" | "NOT" => ("Логическое", line.to_string(), parts.len().saturating_sub(1)),
        "MATCH" | "FINAL" => ("Финальное", "*".to_string(), 1),
        _ => return None,
    };
    let route = forced_route
        .map(ToString::to_string)
        .unwrap_or_else(|| route_for_policy(parts.get(policy_index).copied().unwrap_or("PROXY")));
    Some(RouteRule { kind: kind.into(), value, route })
}

fn parse_clash(text: &str, base_url: Option<&str>) -> Option<ParsedSubscription> {
    let document: Yaml = serde_yaml::from_str(text).ok()?;
    let root = document.as_mapping()?;
    let mut parsed = ParsedSubscription::default();

    if let Some(proxies) = get(root, "proxies").and_then(Yaml::as_sequence) {
        parsed.servers = proxies
            .iter()
            .filter_map(Yaml::as_mapping)
            .filter_map(clash_proxy)
            .collect();
    }

    let mut providers: HashMap<String, (String, String)> = HashMap::new();
    if let Some(provider_map) = get(root, "rule-providers").and_then(Yaml::as_mapping) {
        for (name, value) in provider_map {
            let Some(name) = yaml_string(Some(name)) else { continue };
            let Some(provider) = value.as_mapping() else { continue };
            let Some(raw_url) = yaml_string(get(provider, "url")) else { continue };
            let resolved = base_url
                .and_then(|base| Url::parse(base).ok())
                .and_then(|base| base.join(&raw_url).ok())
                .map(|url| url.to_string())
                .unwrap_or(raw_url);
            let behavior = yaml_string(get(provider, "behavior")).unwrap_or_else(|| "classical".into());
            providers.insert(name, (resolved, behavior));
        }
    }

    if let Some(rules) = get(root, "rules").and_then(Yaml::as_sequence) {
        for value in rules {
            let Some(line) = yaml_string(Some(value)) else { continue };
            let parts: Vec<&str> = line.split(',').map(str::trim).collect();
            if parts.first().map(|v| v.eq_ignore_ascii_case("RULE-SET")) == Some(true) && parts.len() >= 3 {
                if let Some((url, behavior)) = providers.get(parts[1]) {
                    parsed.remote_providers.push(RemoteRuleProvider {
                        url: url.clone(),
                        behavior: behavior.clone(),
                        route: route_for_policy(parts[2]),
                    });
                }
            } else if let Some(rule) = parse_clash_rule(&line, None) {
                parsed.rules.push(rule);
            }
        }
    }
    Some(parsed)
}

pub fn parse_rule_provider(text: &str, behavior: &str, route: &str) -> Vec<RouteRule> {
    let document: Yaml = match serde_yaml::from_str(text) {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };
    let payload = document
        .as_mapping()
        .and_then(|root| get(root, "payload"))
        .and_then(Yaml::as_sequence);
    let Some(payload) = payload else { return Vec::new() };
    payload
        .iter()
        .filter_map(|value| yaml_string(Some(value)))
        .filter_map(|value| {
            if behavior.eq_ignore_ascii_case("domain") {
                Some(RouteRule { kind: "Домен".into(), value: value.trim_start_matches("+.").to_string(), route: route.into() })
            } else if behavior.eq_ignore_ascii_case("ipcidr") {
                Some(RouteRule { kind: "IP / CIDR".into(), value, route: route.into() })
            } else {
                parse_clash_rule(&value, Some(route))
            }
        })
        .collect()
}

pub fn compact_rules(rules: Vec<RouteRule>) -> Vec<RouteRule> {
    let mut compacted: Vec<RouteRule> = Vec::new();
    let mut current_count = 0usize;
    for rule in rules {
        let can_merge = !matches!(rule.kind.as_str(), "Логическое" | "Финальное")
            && compacted
                .last()
                .map(|last| last.kind == rule.kind && last.route == rule.route && current_count < 5_000)
                .unwrap_or(false);
        if can_merge {
            let last = compacted.last_mut().expect("last rule exists");
            last.value.push(',');
            last.value.push_str(&rule.value);
            current_count += 1;
        } else {
            compacted.push(rule);
            current_count = 1;
        }
    }
    compacted
}

pub fn parse_flexible(text: &str, source_url: Option<&str>) -> ParsedSubscription {
    let text=text.trim_start_matches('\u{feff}').trim();
    let direct:Vec<Server>=text.lines().filter_map(parse_uri).collect();
    if !direct.is_empty(){return ParsedSubscription{servers:direct,..Default::default()}}
    let compact:String=text.chars().filter(|c|!c.is_whitespace()).collect();
    for engine in [&general_purpose::STANDARD,&general_purpose::URL_SAFE,&general_purpose::STANDARD_NO_PAD,&general_purpose::URL_SAFE_NO_PAD]{
        if let Ok(bytes)=engine.decode(compact.as_bytes()){if let Ok(decoded)=String::from_utf8(bytes){let parsed=parse_flexible(&decoded,source_url);if !parsed.servers.is_empty(){return parsed}}}
    }
    if let Some(parsed)=parse_clash(text,source_url){if !parsed.servers.is_empty(){return parsed}}
    let decoded=percent_encoding::percent_decode_str(text).decode_utf8_lossy();
    if decoded.as_ref()!=text{let parsed=parse_flexible(decoded.as_ref(),source_url);if !parsed.servers.is_empty(){return parsed}}
    ParsedSubscription::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_clash_servers_rules_and_provider() {
        let yaml = r#"
proxies:
  - name: NL Reality
    type: vless
    server: nl.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    tls: true
    network: tcp
    reality-opts:
      public-key: key
      short-id: abcd
  - name: DE Hysteria
    type: hysteria2
    server: de.example.com
    port: 443
    password: secret
    sni: de.example.com
rule-providers:
  private:
    type: http
    behavior: domain
    url: https://rules.example/private.yaml
rules:
  - DOMAIN-SUFFIX,example.org,DIRECT
  - IP-CIDR,10.0.0.0/8,DIRECT
  - RULE-SET,private,DIRECT
  - MATCH,Proxy
"#;
        let parsed = parse_flexible(yaml, Some("https://provider.example/sub"));
        assert_eq!(parsed.servers.len(), 2);
        assert_eq!(parsed.rules.len(), 3);
        assert_eq!(parsed.remote_providers.len(), 1);
        assert_eq!(parsed.servers[0].protocol, "vless");
        assert_eq!(parsed.servers[1].protocol, "hysteria2");
    }

    #[test]
    fn preserves_source_ip_and_process_path_rules() {
        let source = "SRC-IP-CIDR,10.0.0.0/8,DIRECT\nPROCESS-PATH,C:/Apps/client.exe,DIRECT";
        let rules: Vec<RouteRule> = source.lines().filter_map(|line| parse_clash_rule(line, None)).collect();
        assert_eq!(rules[0].kind, "IP источника / CIDR");
        assert_eq!(rules[1].kind, "Путь приложения");
    }

    #[test]
    fn does_not_merge_logical_or_final_rules() {
        let rules = vec![
            RouteRule { kind: "Логическое".into(), value: "AND,((NETWORK,TCP),(DST-PORT,443))".into(), route: "proxy".into() },
            RouteRule { kind: "Логическое".into(), value: "OR,((NETWORK,UDP),(DST-PORT,53))".into(), route: "proxy".into() },
            RouteRule { kind: "Финальное".into(), value: "*".into(), route: "proxy".into() },
            RouteRule { kind: "Финальное".into(), value: "*".into(), route: "proxy".into() },
        ];
        assert_eq!(compact_rules(rules).len(), 4);
    }
}

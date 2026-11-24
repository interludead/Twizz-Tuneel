use crate::model::RouteRule;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Default)]
pub struct CompiledRules {
    pub route_rules: Vec<Value>,
    pub rule_sets: Vec<Value>,
    pub final_outbound: String,
    pub direct_domains: Vec<String>,
    pub proxy_domains: Vec<String>,
}

fn values(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .map(|value| value.trim_start_matches("*.").trim_start_matches("+.").to_string())
        .filter(|value| !value.is_empty())
        .collect()
}

fn action(mut value: Value, target: &str) -> Value {
    if target == "block" {
        if let Some(object) = value.as_object_mut() {
            object.remove("outbound");
            object.insert("action".into(), json!("reject"));
        }
    }
    value
}

fn add_outbound(mut value: Value, target: &str) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.insert("outbound".into(), json!(target));
    }
    value
}

fn normalize_cidr(raw: &str) -> Option<String> {
    let value = raw.trim();
    if let Some((address, prefix)) = value.split_once('/') {
        let ip = address.trim().parse::<IpAddr>().ok()?;
        let prefix = prefix.trim().parse::<u16>().ok()?;
        let valid = match ip { IpAddr::V4(_) => prefix <= 32, IpAddr::V6(_) => prefix <= 128 };
        valid.then(|| format!("{ip}/{prefix}"))
    } else {
        let ip = value.parse::<IpAddr>().ok()?;
        Some(match ip { IpAddr::V4(_) => format!("{ip}/32"), IpAddr::V6(_) => format!("{ip}/128") })
    }
}

fn port_fields(items: &[String], source: bool) -> Option<Value> {
    let mut ports = Vec::<u16>::new();
    let mut ranges = Vec::<String>::new();
    for raw in items {
        let value = raw.trim().trim_end_matches('+').trim();
        if let Some((start, end)) = value.split_once('-').or_else(|| value.split_once(':')) {
            if let (Ok(start), Ok(end)) = (start.trim().parse::<u16>(), end.trim().parse::<u16>()) {
                if start > 0 && start <= end { ranges.push(format!("{start}:{end}")); }
            }
        } else if let Ok(port) = value.parse::<u16>() {
            if port > 0 { ports.push(port); }
        }
    }
    ports.sort_unstable();
    ports.dedup();
    ranges.sort();
    ranges.dedup();
    if ports.is_empty() && ranges.is_empty() { return None; }
    let mut object = Map::new();
    if source {
        if !ports.is_empty() { object.insert("source_port".into(), json!(ports)); }
        if !ranges.is_empty() { object.insert("source_port_range".into(), json!(ranges)); }
    } else {
        if !ports.is_empty() { object.insert("port".into(), json!(ports)); }
        if !ranges.is_empty() { object.insert("port_range".into(), json!(ranges)); }
    }
    Some(Value::Object(object))
}

fn condition(kind: &str, items: &[String]) -> Option<Value> {
    if items.is_empty() { return None; }
    match kind.trim().to_ascii_uppercase().as_str() {
        "DOMAIN" | "Точный домен" => Some(json!({"domain":items})),
        "DOMAIN-SUFFIX" | "Домен" => Some(json!({"domain_suffix":items})),
        "DOMAIN-KEYWORD" | "Ключ домена" => Some(json!({"domain_keyword":items})),
        "IP-CIDR" | "IP-CIDR6" | "IP / CIDR" => {
            let cidrs: Vec<String> = items.iter().filter_map(|value| normalize_cidr(value)).collect();
            (!cidrs.is_empty()).then(|| json!({"ip_cidr":cidrs}))
        }
        "SRC-IP-CIDR" | "IP источника / CIDR" => {
            let cidrs: Vec<String> = items.iter().filter_map(|value| normalize_cidr(value)).collect();
            (!cidrs.is_empty()).then(|| json!({"source_ip_cidr":cidrs}))
        }
        "PROCESS-NAME" | "Приложение" => Some(json!({"process_name":items})),
        "PROCESS-PATH" | "Путь приложения" => Some(json!({"process_path":items})),
        "NETWORK" | "Сеть" => {
            let networks: Vec<&str> = items.iter().filter_map(|value| match value.trim().to_ascii_lowercase().as_str() {
                "tcp" => Some("tcp"), "udp" => Some("udp"), _ => None,
            }).collect();
            (!networks.is_empty()).then(|| json!({"network":networks}))
        }
        "DST-PORT" | "Порт назначения" => port_fields(items, false),
        "SRC-PORT" | "Порт источника" => port_fields(items, true),
        _ => None,
    }
}

fn logical(raw: &str, target: &str) -> Option<Value> {
    let operation = raw.split(',').next()?.trim().to_ascii_lowercase();
    let mode = if operation == "or" { "or" } else { "and" };
    let invert = operation == "not";
    let start = raw.find('(')?;
    let end = raw.rfind(')')?;
    let inner = raw.get(start..=end)?.trim_matches(|c| c == '(' || c == ')');
    let rules: Vec<Value> = inner
        .split("),(")
        .filter_map(|part| {
            let clean = part.trim().trim_matches(|c| c == '(' || c == ')');
            let (kind, value) = clean.split_once(',')?;
            condition(kind, &values(value))
        })
        .collect();
    if rules.is_empty() { return None; }
    Some(json!({"type":"logical","mode":mode,"invert":invert,"rules":rules,"outbound":target}))
}

fn valid_geo_name(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    (!value.is_empty() && value.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))).then_some(value)
}

pub fn compile(rules: &[RouteRule]) -> CompiledRules {
    let mut output = CompiledRules { final_outbound: "proxy".into(), ..Default::default() };
    let mut known_sets = HashSet::new();
    for rule in rules {
        let items = values(&rule.value);
        if items.is_empty() { continue; }
        let target = match rule.route.as_str() { "direct" => "direct", "block" => "block", _ => "proxy" };
        if rule.kind == "Финальное" {
            output.final_outbound = target.into();
            continue;
        }
        if matches!(rule.kind.as_str(), "Точный домен" | "Домен") {
            if target == "direct" { output.direct_domains.extend(items.clone()); }
            if target == "proxy" { output.proxy_domains.extend(items.clone()); }
        }
        let item = match rule.kind.as_str() {
            "GEOIP" | "GEOSITE" => {
                let prefix = if rule.kind == "GEOIP" { "geoip" } else { "geosite" };
                let names: Vec<String> = items.iter().filter_map(|value| valid_geo_name(value)).collect();
                if names.is_empty() { continue; }
                let tags: Vec<String> = names.iter().map(|value| format!("{prefix}-{value}")).collect();
                for (name, tag) in names.iter().zip(tags.iter()) {
                    if known_sets.insert(tag.clone()) {
                        let base = if prefix == "geoip" { "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-" } else { "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-" };
                        output.rule_sets.push(json!({"type":"remote","tag":tag,"format":"binary","url":format!("{base}{name}.srs"),"download_detour":"direct","update_interval":"1d"}));
                    }
                }
                json!({"rule_set":tags,"outbound":target})
            }
            "Логическое" => match logical(&rule.value, target) { Some(value) => value, None => continue },
            other => match condition(other, &items) { Some(value) => add_outbound(value, target), None => continue },
        };
        output.route_rules.push(action(item, target));
    }
    output.direct_domains.sort(); output.direct_domains.dedup();
    output.proxy_domains.sort(); output.proxy_domains.dedup();
    output
}

fn v4_match(ip: Ipv4Addr, cidr: &str) -> bool { let Some((network,prefix))=cidr.split_once('/') else{return ip.to_string()==cidr};let(Ok(network),Ok(prefix))=(network.parse::<Ipv4Addr>(),prefix.parse::<u32>())else{return false};if prefix>32{return false}let mask=if prefix==0{0}else{u32::MAX<<(32-prefix)};(u32::from(ip)&mask)==(u32::from(network)&mask) }
fn v6_match(ip: Ipv6Addr, cidr: &str) -> bool { let Some((network,prefix))=cidr.split_once('/') else{return ip.to_string()==cidr};let(Ok(network),Ok(prefix))=(network.parse::<Ipv6Addr>(),prefix.parse::<u32>())else{return false};if prefix>128{return false}let mask=if prefix==0{0}else{u128::MAX<<(128-prefix)};(u128::from(ip)&mask)==(u128::from(network)&mask) }
fn matches_rule(target:&str,rule:&RouteRule)->bool{let target=target.trim().trim_end_matches('.').to_ascii_lowercase();values(&rule.value).iter().any(|value|match rule.kind.as_str(){"Точный домен"=>target==value.to_ascii_lowercase(),"Домен"=>{let value=value.to_ascii_lowercase();target==value||target.ends_with(&format!(".{value}"))},"Ключ домена"=>target.contains(&value.to_ascii_lowercase()),"IP / CIDR"=>match target.parse::<IpAddr>(){Ok(IpAddr::V4(ip))=>v4_match(ip,value),Ok(IpAddr::V6(ip))=>v6_match(ip,value),_=>false},"Финальное"=>true,_=>false})}
pub fn analyze(target:&str,rules:&[RouteRule])->Value{for(index,rule)in rules.iter().enumerate(){if matches_rule(target,rule){return json!({"matched":true,"index":index,"kind":rule.kind,"value":rule.value,"route":rule.route,"explanation":format!("{} {} → {}",rule.kind,rule.value,rule.route)})}}json!({"matched":false,"route":"proxy","explanation":"Совпадений нет — используется финальный маршрут через VPN"})}
pub fn conflicts(rules:&[RouteRule])->Value{let mut entries:BTreeMap<(String,String),BTreeSet<String>>=BTreeMap::new();for rule in rules{for value in values(&rule.value){entries.entry((rule.kind.clone(),value.to_ascii_lowercase())).or_default().insert(rule.route.clone());}}let conflicts:Vec<Value>=entries.into_iter().filter(|(_,routes)|routes.len()>1).map(|((kind,value),routes)|json!({"kind":kind,"value":value,"routes":routes.into_iter().collect::<Vec<_>>()})).collect();json!({"count":conflicts.len(),"conflicts":conflicts})}

#[cfg(test)]
mod tests {
    use super::*;
    fn rule(kind:&str,value:&str,target:&str)->RouteRule{RouteRule{kind:kind.into(),value:value.into(),route:target.into()}}
    #[test] fn final_and_domain(){let rules=vec![rule("Домен","example.com","direct"),rule("Финальное","*","block")];let compiled=compile(&rules);assert_eq!(compiled.final_outbound,"block");assert_eq!(analyze("api.example.com",&rules)["route"],"direct");}
    #[test] fn ipv6_cidr(){let rules=vec![rule("IP / CIDR","2001:db8::/32","direct")];assert_eq!(analyze("2001:db8::1",&rules)["route"],"direct");}
    #[test] fn duplicate_conflict(){let rules=vec![rule("Домен","a.test","direct"),rule("Домен","a.test","proxy")];assert_eq!(conflicts(&rules)["count"],1);}
    #[test] fn single_port_uses_port(){let compiled=compile(&[rule("Порт назначения","5223 +","direct")]);assert_eq!(compiled.route_rules[0]["port"],json!([5223]));assert!(compiled.route_rules[0].get("port_range").is_none());}
    #[test] fn range_uses_port_range(){let compiled=compile(&[rule("Порт назначения","1000-2000","direct")]);assert_eq!(compiled.route_rules[0]["port_range"],json!(["1000:2000"]));}
    #[test] fn invalid_conditions_are_dropped(){let compiled=compile(&[rule("Порт назначения","garbage","direct"),rule("Сеть","wat","direct"),rule("IP / CIDR","999.1.1.1/99","direct"),rule("Неизвестно","x","direct")]);assert!(compiled.route_rules.is_empty());}
    #[test] fn source_conditions_are_preserved(){let compiled=compile(&[rule("IP источника / CIDR","10.0.0.1","direct"),rule("Путь приложения","C:/app.exe","direct")]);assert_eq!(compiled.route_rules[0]["source_ip_cidr"],json!(["10.0.0.1/32"]));assert!(compiled.route_rules[1].get("process_path").is_some());}
}

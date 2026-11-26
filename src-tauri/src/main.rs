#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod config;
mod cores;
mod job;
mod mihomo_config;
mod model;
mod rules_engine;
mod route_compiler;
mod subscription;
mod windows;
mod xray_config;

use cores::CoreKind;
use model::{ConnectRequest, RouteRule, RoutingProfile, Server, Subscription};
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    process::Stdio,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Emitter, Manager, State};
use url::Url;
use tokio::{
    net::TcpStream,
    process::{Child, Command},
    sync::Mutex,
    time::timeout,
};

struct Runtime {
    /// Upstream protocol core first (if used), sing-box last.
    children: Mutex<Vec<Child>>,
    mode: Mutex<String>,
    core: Mutex<String>,
    stats_endpoint: Mutex<Option<(u16, String)>>,
    probe_port: std::sync::atomic::AtomicU16,
    profile_download: Mutex<()>,
    connection_operation: Mutex<()>,
    connection_state: Mutex<String>,
    last_error: Mutex<Option<String>>,
    exit_ip: Mutex<Option<String>>,
    kill_switch_mode: Mutex<String>,
    network_signature: Mutex<String>,
    health_failures: Mutex<u32>,
    last_health_check: Mutex<std::time::Instant>,
    trace: Mutex<Vec<serde_json::Value>>,
    job: job::ProcessJob,
}

static SING_BOX_BYTES: &[u8] = include_bytes!("../bin/sing-box.exe");
static XRAY_BYTES: &[u8] = include_bytes!("../bin/xray.exe");
static MIHOMO_BYTES: &[u8] = include_bytes!("../bin/mihomo.exe");

fn core_bytes(core: CoreKind) -> &'static [u8] {
    match core {
        CoreKind::SingBox => SING_BOX_BYTES,
        CoreKind::Xray => XRAY_BYTES,
        CoreKind::Mihomo => MIHOMO_BYTES,
    }
}

/// Hides the console window of a child process on Windows (CREATE_NO_WINDOW),
/// so PowerShell, sing-box, Xray and Mihomo never flash a cmd window at the
/// user when the VPN starts or stops.
#[cfg(windows)]
fn hide_window(command: &mut std::process::Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    command.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(windows))]
fn hide_window(_command: &mut std::process::Command) {}

/// Same for the long-running async child processes (the VPN cores).
#[cfg(windows)]
fn hide_window_async(command: &mut Command) {
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    command.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(windows))]
fn hide_window_async(_command: &mut Command) {}

/// Extracts a bundled core next to the app data directory and returns its path.
fn embedded_core(app: &AppHandle, core: CoreKind) -> Result<PathBuf, String> {
    let core_dir = data_dir(app)?.join("core");
    std::fs::create_dir_all(&core_dir).map_err(|e| e.to_string())?;
    let bytes = core_bytes(core);
    let binary = core_dir.join(core.binary());
    let needs_write = std::fs::read(&binary).map(|existing| existing != bytes).unwrap_or(true);
    if needs_write {
        let temporary = core_dir.join(format!("{}.tmp", core.binary()));
        std::fs::write(&temporary, bytes).map_err(|e| e.to_string())?;
        if binary.exists() { std::fs::remove_file(&binary).map_err(|e| e.to_string())?; }
        std::fs::rename(&temporary, &binary).map_err(|e| e.to_string())?;
    }
    Ok(binary)
}

fn embedded_sing_box(app: &AppHandle) -> Result<PathBuf, String> {
    embedded_core(app, CoreKind::SingBox)
}

/// Returns the last meaningful lines of a core log so failures are explained
/// to the user instead of being silently swallowed.
fn tail_log(path: &std::path::Path) -> String {
    let text = match std::fs::read_to_string(path) {
        Ok(value) => value,
        Err(_) => return String::new(),
    };
    let lines: Vec<&str> = text
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect();
    let start = lines.len().saturating_sub(6);
    lines[start..].join("\n")
}

fn core_version(app: &AppHandle, core: CoreKind) -> Result<String, String> {
    let binary = embedded_core(app, core)?;
    let args: Vec<&str> = match core {
        CoreKind::SingBox => vec!["version"],
        CoreKind::Xray => vec!["version"],
        CoreKind::Mihomo => vec!["-v"],
    };
    let mut command = std::process::Command::new(binary);
    command.args(&args);
    hide_window(&mut command);
    let output = command.output().map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let text = if stdout.is_empty() { stderr } else { stdout };
    let first = text.lines().next().unwrap_or_default().trim().to_string();
    if first.is_empty() {
        return Err(format!("{} не сообщило версию", core.title()));
    }
    Ok(first)
}

fn data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    app.path().app_data_dir().map_err(|e| e.to_string())
}

fn device_id(app: &AppHandle) -> Result<String, String> {
    let dir = data_dir(app)?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join("device-id");
    if let Ok(value) = std::fs::read_to_string(&path) {
        let value = value.trim();
        if (10..=64).contains(&value.len()) && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '=' || c == '-') {
            return Ok(value.to_string());
        }
    }
    let seed = format!("{}:{}:{}", std::env::var("COMPUTERNAME").unwrap_or_default(), std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos());
    let value = hex::encode(Sha256::digest(seed.as_bytes()))[..32].to_ascii_uppercase();
    std::fs::write(&path, &value).map_err(|e| e.to_string())?;
    Ok(value)
}

async fn record_trace(runtime:&Arc<Runtime>,stage:&str,detail:serde_json::Value){let mut trace=runtime.trace.lock().await;trace.push(serde_json::json!({"at":SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),"stage":stage,"detail":detail}));if trace.len()>200{let drain=trace.len()-200;trace.drain(0..drain);}}

async fn disconnect_runtime(runtime: &Arc<Runtime>) -> Result<(), String> {
    let mut errors = Vec::new();
    let mode = std::mem::take(&mut *runtime.mode.lock().await);
    let kill_switch = runtime.kill_switch_mode.lock().await.clone();
    if mode == "proxy" {
        let path = std::env::temp_dir().join("lzt-tunnel-proxy-state.json");
        if let Err(error) = windows::recover_proxy(&path) { errors.push(error); }
    }
    let mut children = std::mem::take(&mut *runtime.children.lock().await);
    for child in children.iter_mut().rev() {
        if let Err(error) = child.start_kill() {
            if !matches!(child.try_wait(), Ok(Some(_))) { errors.push(error.to_string()); }
        }
    }
    for child in children.iter_mut().rev() {
        if let Err(error) = child.wait().await { errors.push(error.to_string()); }
    }
    if kill_switch == "session" {
        let path = std::env::temp_dir().join("lzt-tunnel-firewall-state.json");
        if let Err(error) = windows::recover_kill_switch(&path) { errors.push(error); }
    }
    runtime.probe_port.store(2080, std::sync::atomic::Ordering::Relaxed);
    runtime.core.lock().await.clear();
    *runtime.stats_endpoint.lock().await = None;
    *runtime.exit_ip.lock().await = None;
    if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
}

fn parse_subscription_info(value: Option<&str>) -> (Option<u64>, Option<u64>, Option<u64>, Option<u64>) {
    let mut upload = None;
    let mut download = None;
    let mut total = None;
    let mut expire = None;
    if let Some(value) = value {
        for item in value.split(';') {
            let mut pair = item.trim().splitn(2, '=');
            let key = pair.next().unwrap_or_default().trim();
            let number = pair.next().and_then(|v| v.trim().parse::<u64>().ok());
            match key {
                "upload" => upload = number,
                "download" => download = number,
                "total" => total = number,
                "expire" => expire = number,
                _ => {}
            }
        }
    }
    (upload, download, total, expire)
}



/// Reads a FlClash/FlClashX custom-protocol argument and extracts the HTTP(S)
/// subscription URL. Supports common url/config/subscription parameter names.
#[tauri::command]
fn startup_subscription_url()->Option<String>{
 for argument in std::env::args().skip(1){
  let raw=argument.trim().trim_matches(char::from(34));
  if raw.starts_with("https://")||raw.starts_with("http://"){return Some(raw.to_string())}
  let Ok(parsed)=Url::parse(raw) else {continue};
  if !matches!(parsed.scheme(),"flclash"|"flclashx"|"clash"|"lzt-tunnel"){continue}
  for (key,value) in parsed.query_pairs(){
   if matches!(key.as_ref(),"url"|"config"|"subscription"|"subscribe"|"link")&&(value.starts_with("https://")||value.starts_with("http://")){return Some(value.into_owned())}
  }
  let decoded=percent_encoding::percent_decode_str(parsed.path().trim_start_matches('/')).decode_utf8_lossy();
  if decoded.starts_with("https://")||decoded.starts_with("http://"){return Some(decoded.into_owned())}
 }
 None
}

#[tauri::command]
async fn import_subscription(app: AppHandle, url: String, name: String) -> Result<Subscription, String> {
    if !url.starts_with("https://") && !url.starts_with("http://") {
        return Err("Поддерживаются только HTTP(S)-подписки".into());
    }
    let hwid = device_id(&app)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("FlClash/v0.8.91")
        .build()
        .map_err(|e| e.to_string())?;
    let response = client
        .get(&url)
        .header("Accept", "text/yaml, application/yaml, application/json, text/plain, */*")
        .header("x-hwid", &hwid)
        .header("x-device-os", "Windows")
        .header("x-ver-os", "10+")
        .header("x-device-model", std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Windows PC".into()))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?;
    let hwid_limit_reached = response.headers().get("x-hwid-max-devices-reached").and_then(|v| v.to_str().ok()).map(|v| v.eq_ignore_ascii_case("true")).unwrap_or(false);
    let announce = response.headers().get("announce").and_then(|v| v.to_str().ok()).map(ToString::to_string);
    if hwid_limit_reached { return Err(announce.unwrap_or_else(|| "Достигнут лимит устройств подписки".into())); }
    let content_type = response.headers().get("content-type").and_then(|v|v.to_str().ok()).unwrap_or("unknown").to_string();
    let subscription_info = response
        .headers()
        .get("subscription-userinfo")
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    let (upload_bytes, download_bytes, total_bytes, expires_at) =
        parse_subscription_info(subscription_info.as_deref());
    let body = response.text().await.map_err(|e| e.to_string())?;
    let decoded_body = percent_encoding::percent_decode_str(body.trim()).decode_utf8_lossy();
    if decoded_body.contains("Требуется идентификатор устройства") || decoded_body.contains("device identifier") {
        return Err(decoded_body.into_owned());
    }

    let mut parsed = subscription::parse_flexible(&body, Some(&url));
    if let Some(error_server) = parsed.servers.iter().find(|server| {
        let decoded = percent_encoding::percent_decode_str(&server.name).decode_utf8_lossy();
        server.host.eq_ignore_ascii_case("error.cdn-global.pro") || decoded.contains("Требуется идентификатор устройства") || decoded.contains("HWID")
    }) {
        let message = percent_encoding::percent_decode_str(&error_server.name).decode_utf8_lossy().into_owned();
        return Err(message);
    }
    let mut remote_rules = Vec::new();
    let cache_dir = data_dir(&app)?.join("rule-provider-cache");
    std::fs::create_dir_all(&cache_dir).map_err(|e| e.to_string())?;
    for provider in parsed.remote_providers.clone().into_iter().take(64) {
        let cache_name = format!("{}.yaml", hex::encode(Sha256::digest(provider.url.as_bytes())));
        let cache_path = cache_dir.join(cache_name);
        let provider_body = match client.get(&provider.url).send().await {
            Ok(response) => match response.error_for_status() {
                Ok(response) => match response.text().await {
                    Ok(body) => {
                        std::fs::write(&cache_path, &body).ok();
                        Some(body)
                    }
                    Err(_) => std::fs::read_to_string(&cache_path).ok(),
                },
                Err(_) => std::fs::read_to_string(&cache_path).ok(),
            },
            Err(_) => std::fs::read_to_string(&cache_path).ok(),
        };
        if let Some(provider_body) = provider_body {
            remote_rules.extend(subscription::parse_rule_provider(
                &provider_body,
                &provider.behavior,
                &provider.route,
            ));
        }
        if parsed.rules.len() + remote_rules.len() > 100_000 {
            remote_rules.truncate(100_000usize.saturating_sub(parsed.rules.len()));
            break;
        }
    }
    let final_position = parsed
        .rules
        .iter()
        .position(|rule| rule.kind == "Финальное")
        .unwrap_or(parsed.rules.len());
    parsed.rules.splice(final_position..final_position, remote_rules);

    if parsed.servers.is_empty() {
        let preview:String=body.chars().take(240).collect::<String>().replace('\r'," ").replace('\n'," ");
        return Err(format!("Не удалось распознать подписку (Content-Type: {content_type}). Начало ответа: {preview}"));
    }
    let rule_count = parsed.rules.len();
    parsed.rules = subscription::compact_rules(std::mem::take(&mut parsed.rules));
    Ok(Subscription {
        id: parsed.servers[0].id.clone(),
        name,
        url,
        servers: parsed.servers,
        rules: parsed.rules,
        rule_count,
        updated_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        enabled: true,
        priority: 0,
        update_interval_minutes: 60,
        update_on_start: true,
        upload_bytes,
        download_bytes,
        total_bytes,
        expires_at,
    })
}


#[tauri::command]
async fn core_status(app:AppHandle)->Result<String,String>{let report=tauri::async_runtime::spawn_blocking(move || core_report(app)).await.map_err(|error|error.to_string())?;let ready=report["cores"].as_array().map(|xs|xs.iter().filter(|x|x["error"].is_null()).count()).unwrap_or(0);Ok(format!("Сделано для twizz.geek · ядра {ready}/3"))}

/// Per-core report for the UI: version, availability and supported features.
#[tauri::command]
fn core_report(app: AppHandle) -> serde_json::Value {
    let list: Vec<serde_json::Value> = cores::ALL_CORES
        .iter()
        .map(|core| {
            let (version, error) = match core_version(&app, *core) {
                Ok(version) => (Some(version), None),
                Err(error) => (None, Some(error)),
            };
            serde_json::json!({
                "id": core.id(),
                "title": core.title(),
                "version": version,
                "error": error
            })
        })
        .collect();
    serde_json::json!({"cores": list, "bridge_port": cores::BRIDGE_PORT})
}

/// Resolves which core will serve each server, so the UI can show a badge and
/// hide nodes that no bundled core can handle.
#[tauri::command]
fn plan_cores(servers: Vec<Server>, preference: Option<String>) -> serde_json::Value {
    let preference = preference.unwrap_or_else(|| "auto".to_string());
    let list: Vec<serde_json::Value> = servers
        .iter()
        .map(|server| cores::describe(server, &preference))
        .collect();
    serde_json::json!({"plans": list})
}

#[tauri::command]
async fn run_diagnostics(state:State<'_,Arc<Runtime>>)->Result<serde_json::Value,String>{
 let connected=!state.inner().mode.lock().await.is_empty();let mut builder=reqwest::Client::builder().timeout(Duration::from_secs(8));if connected{builder=builder.proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{}", state.inner().probe_port.load(std::sync::atomic::Ordering::Relaxed))).map_err(|e|e.to_string())?);}let client=builder.build().map_err(|e|e.to_string())?;
 let started=std::time::Instant::now();let response=client.get("https://api.ipify.org?format=json").send().await.map_err(|e|e.to_string())?.error_for_status().map_err(|e|e.to_string())?;let latency=started.elapsed().as_millis();let body:serde_json::Value=response.json().await.map_err(|e|e.to_string())?;
 let dns=timeout(Duration::from_secs(4),tokio::net::lookup_host(("example.com",443))).await.map(|r|r.is_ok()).unwrap_or(false);let tcp=timeout(Duration::from_secs(4),TcpStream::connect(("1.1.1.1",443))).await.map(|r|r.is_ok()).unwrap_or(false);
 Ok(serde_json::json!({"ip":body.get("ip").and_then(|v|v.as_str()).unwrap_or("—"),"tcp":tcp,"dns":dns,"via_tunnel":connected,"latency_ms":latency,"health_failures":*state.inner().health_failures.lock().await}))
}

#[tauri::command]
async fn export_diagnostics(app:AppHandle,state:State<'_,Arc<Runtime>>)->Result<String,String>{
 let stamp=SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();let work=std::env::temp_dir().join(format!("lzt-diagnostics-{stamp}"));std::fs::create_dir_all(&work).map_err(|e|e.to_string())?;
 let report=serde_json::json!({"generated_at":stamp,"app_version":"1.12.0","runtime":{"state":state.inner().connection_state.lock().await.clone(),"core":state.inner().core.lock().await.clone(),"connected":!state.inner().mode.lock().await.is_empty(),"health_failures":*state.inner().health_failures.lock().await,"exit_ip_present":state.inner().exit_ip.lock().await.is_some()},"cores":core_report(app),"network":windows::network_report().unwrap_or_else(|e|serde_json::json!({"error":e})),"trace":state.inner().trace.lock().await.clone()});
 std::fs::write(work.join("report.json"),serde_json::to_vec_pretty(&report).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
 let downloads=std::env::var_os("USERPROFILE").map(PathBuf::from).unwrap_or_else(std::env::temp_dir).join("Downloads");std::fs::create_dir_all(&downloads).map_err(|e|e.to_string())?;let zip=downloads.join(format!("LZT-Tunnel-diagnostics-{stamp}.zip"));
 let mut cmd=std::process::Command::new("powershell.exe");hide_window(&mut cmd);let script=format!("Compress-Archive -Path '{}' -DestinationPath '{}' -Force",work.join("*").to_string_lossy().replace('\'',"''"),zip.to_string_lossy().replace('\'',"''"));let out=cmd.args(["-NoProfile","-NonInteractive","-Command",&script]).output().map_err(|e|e.to_string())?;if !out.status.success(){return Err(String::from_utf8_lossy(&out.stderr).into_owned())}Ok(zip.to_string_lossy().into_owned())
}



fn usable_probe_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets=v4.octets();
            !(octets[0]==198 && (octets[1]==18 || octets[1]==19)) && !v4.is_loopback() && !v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unspecified(),
    }
}

async fn resolve_probe_addr(host:&str,port:u16)->Result<std::net::SocketAddr,String>{
    if let Ok(ip)=host.parse::<std::net::IpAddr>() {
        if usable_probe_ip(ip){return Ok(std::net::SocketAddr::new(ip,port))}
    }
    // Resolve through an external DoH service so a running TUN/fake-IP DNS
    // cannot turn every server probe into a 0-2 ms connection to localhost.
    let encoded:String=url::form_urlencoded::byte_serialize(host.as_bytes()).collect();
    let endpoint=format!("https://cloudflare-dns.com/dns-query?name={encoded}&type=A");
    if let Ok(client)=reqwest::Client::builder().timeout(Duration::from_secs(4)).no_proxy().build(){
        if let Ok(response)=client.get(endpoint).header("Accept","application/dns-json").send().await{
            if let Ok(value)=response.json::<serde_json::Value>().await{
                if let Some(answers)=value.get("Answer").and_then(|v|v.as_array()){
                    for answer in answers{
                        if let Some(raw)=answer.get("data").and_then(|v|v.as_str()){
                            if let Ok(ip)=raw.parse::<std::net::IpAddr>(){if usable_probe_ip(ip){return Ok(std::net::SocketAddr::new(ip,port))}}
                        }
                    }
                }
            }
        }
    }
    let addresses=tokio::net::lookup_host((host,port)).await.map_err(|e|e.to_string())?;
    addresses.into_iter().find(|address|usable_probe_ip(address.ip())).ok_or_else(||"DNS вернул только локальный/fake-IP адрес".into())
}

fn elapsed_ms(started:std::time::Instant)->u128{
    let micros=started.elapsed().as_micros();
    (micros.saturating_add(999)/1000).max(1)
}

async fn active_probe_interfaces(runtime: &Runtime) -> Result<Option<windows::ProbeInterfaces>, String> {
    let tun = runtime.mode.lock().await.as_str() == "tun";
    if !tun { return Ok(None); }
    tauri::async_runtime::spawn_blocking(windows::probe_interfaces)
        .await.map_err(|error| error.to_string())?.map(Some)
}

async fn connect_probe(address: std::net::SocketAddr, interfaces: Option<windows::ProbeInterfaces>) -> std::io::Result<TcpStream> {
    let Some(interfaces) = interfaces else { return TcpStream::connect(address).await; };
    let socket = if address.is_ipv4() { tokio::net::TcpSocket::new_v4()? } else { tokio::net::TcpSocket::new_v6()? };
    windows::bind_probe_interface(&socket, address, interfaces)?;
    socket.connect(address).await
}

#[tauri::command]
async fn ping_server(state: State<'_, Arc<Runtime>>, server: Server) -> Result<u128, String> {
    let interfaces = active_probe_interfaces(state.inner()).await?;
    let address=resolve_probe_addr(&server.host,server.port).await?;
    let started = std::time::Instant::now();
    timeout(
        Duration::from_millis(1500),
        connect_probe(address, interfaces),
    )
    .await
    .map_err(|_| "timeout".to_string())?
    .map_err(|e| e.to_string())?;
    Ok(elapsed_ms(started))
}

/// Probes up to 24 endpoints at once. In TUN mode all sockets in the batch
/// use the same snapshot of the default interfaces outside Twizz's tunnel.
#[tauri::command]
async fn ping_servers(app: AppHandle, state: State<'_, Arc<Runtime>>, servers: Vec<Server>) -> Result<Vec<serde_json::Value>, String> {
    let interfaces = active_probe_interfaces(state.inner()).await?;
    let total = servers.len();
    let semaphore = Arc::new(tokio::sync::Semaphore::new(24));
    let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut set = tokio::task::JoinSet::new();
    for (index, server) in servers.into_iter().enumerate() {
        let semaphore = semaphore.clone();
        let done = done.clone();
        let app = app.clone();
        set.spawn(async move {
            let _permit = semaphore.acquire_owned().await.ok();
            let address=resolve_probe_addr(&server.host,server.port).await.ok();
            let mut hits = 0usize;
            let mut samples:Vec<u128> = Vec::new();
            for attempt in 0..3 {
                let wait = if attempt == 0 { 1200 } else { 1600 };
                let started = std::time::Instant::now();
                let probe = timeout(
                    Duration::from_millis(wait),
                    async { match address { Some(value)=>connect_probe(value, interfaces).await, None=>Err(std::io::Error::new(std::io::ErrorKind::AddrNotAvailable,"DNS")) } },
                )
                .await;
                if matches!(probe, Ok(Ok(_))) {
                    hits += 1;
                    samples.push(elapsed_ms(started));
                }
                if attempt == 0 {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                }
            }
            let finished = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            app.emit("ping-progress", serde_json::json!({"done": finished, "total": total})).ok();
            samples.sort_unstable();
            let latency = if hits > 0 { Some(samples[samples.len()/2]) } else { None };
            (index, latency, (3usize.saturating_sub(hits)) * 100 / 3)
        });
    }
    let mut results = vec![serde_json::json!({"latency":null,"loss":100}); total];
    while let Some(joined) = set.join_next().await {
        if let Ok((index, latency, loss)) = joined {
            results[index] = serde_json::json!({"latency": latency, "loss": loss});
        }
    }
    Ok(results)
}

/// Lightweight external IP lookup for the dashboard pill and metric.
/// In TUN mode the request itself rides through the tunnel, so the user sees
/// the exit-node IP; in system-proxy mode it is routed through the local
/// mixed inbound so it still shows the VPN address.
#[tauri::command]
async fn external_ip(state: State<'_, Arc<Runtime>>) -> Result<String, String> {
    let mode = state.inner().mode.lock().await.clone();
    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(5));
    // The loopback mixed inbound listens in both modes, so the exit IP is
    // always measured through the tunnel even though ordinary app traffic
    // (latency probes, subscription updates) bypasses TUN.
    if mode == "proxy" || mode == "tun" {
        builder = builder
            .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{}", state.inner().probe_port.load(std::sync::atomic::Ordering::Relaxed))).map_err(|e| e.to_string())?);
    }
    let client = builder.build().map_err(|e| e.to_string())?;
    let mut last_error = String::new();
    // Right after TUN comes up the first packets can still fail, so the probe
    // retries once instead of reporting a false "no internet".
    for attempt in 0..2 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(700)).await;
        }
        match client.get("https://api.ipify.org?format=json").send().await {
            Ok(response) => match response.json::<serde_json::Value>().await {
                Ok(body) => {
                    if let Some(ip) = body.get("ip").and_then(|value| value.as_str()) {
                        return Ok(ip.to_string());
                    }
                    last_error = "Сервис не вернул IP".to_string();
                }
                Err(error) => last_error = error.to_string(),
            },
            Err(error) => last_error = error.to_string(),
        }
    }
    Err(if last_error.is_empty() { "Сервис не вернул IP".to_string() } else { last_error })
}

/// Live session traffic counters from the sing-box Clash API (loopback only,
/// enabled by config::build when the sing-box version still supports it).
#[tauri::command]
async fn traffic_stats(state: State<'_, Arc<Runtime>>) -> Result<serde_json::Value, String> {
    let (port, secret) = state.inner().stats_endpoint.lock().await.clone()
        .ok_or_else(|| "Статистика недоступна".to_owned())?;
    let client = reqwest::Client::builder().no_proxy().timeout(Duration::from_millis(1500))
        .build().map_err(|error| error.to_string())?;
    let data: serde_json::Value = client.get(format!("http://127.0.0.1:{port}/connections"))
        .bearer_auth(secret).send().await.and_then(reqwest::Response::error_for_status)
        .map_err(|error| error.to_string())?.json().await.map_err(|error| error.to_string())?;
    let counter = |key: &str| data[key].as_u64().ok_or_else(|| format!("Нет счётчика {key}"));
    Ok(serde_json::json!({"upload": counter("uploadTotal")?, "download": counter("downloadTotal")?}))
}

#[tauri::command]
async fn vpn_notice(lost: bool, server: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || windows::vpn_notice(lost, &server))
        .await.map_err(|error| error.to_string())?
}

async fn load_profile_sets(app: &AppHandle, runtime: &Runtime, profile: RoutingProfile) -> Result<Vec<(String, PathBuf)>, String> {
    if profile.sets().is_empty() {
        return Ok(Vec::new());
    }
    let _download = runtime.profile_download.lock().await;
    let folder = data_dir(app)?.join("routing-profiles");
    std::fs::create_dir_all(&folder).map_err(|error| error.to_string())?;
    let client = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(8))
        .build().map_err(|error| error.to_string())?;
    let binary = embedded_sing_box(app)?;
    let mut files = Vec::new();
    for &(tag, url) in profile.sets() {
        let path = folder.join(format!("{tag}.srs"));
        let fresh = std::fs::metadata(&path).and_then(|meta| meta.modified())
            .ok().and_then(|time| time.elapsed().ok()).is_some_and(|age| age < Duration::from_secs(86400));
        if !fresh {
            let staged = folder.join(format!("{tag}.download"));
            let result: Result<(), String> = async {
                const MAX_BYTES: usize = 16 * 1024 * 1024;
                let mut response = client.get(url).send().await.and_then(reqwest::Response::error_for_status)
                    .map_err(|error| error.to_string())?;
                let mut bytes = Vec::new();
                while let Some(chunk) = response.chunk().await.map_err(|error| error.to_string())? {
                    if bytes.len() + chunk.len() > MAX_BYTES {
                        return Err("Список правил слишком большой".into());
                    }
                    bytes.extend_from_slice(&chunk);
                }
                std::fs::write(&staged, bytes).map_err(|error| error.to_string())?;
                matches_profile_set(&binary, &staged, "example.com").await?;
                std::fs::rename(&staged, &path).map_err(|error| error.to_string())
            }.await;
            if let Err(error) = result {
                let _ = std::fs::remove_file(&staged);
                if !path.is_file() {
                    return Err(format!("Не удалось загрузить список {tag}: {error}"));
                }
            }
        }
        files.push((tag.into(), path));
    }
    Ok(files)
}

async fn matches_profile_set(binary: &std::path::Path, path: &std::path::Path, target: &str) -> Result<bool, String> {
    let mut command = std::process::Command::new(binary);
    hide_window(&mut command);
    command.args(["rule-set", "match", "--format", "binary", "--"]).arg(path).arg(target);
    let output = Command::from(command).output().await.map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    Ok([output.stdout, output.stderr].into_iter().any(|stream| 
        String::from_utf8_lossy(&stream).lines().any(|line| line.starts_with("match rules."))))
}

#[tauri::command]
async fn analyze_route(
    app: AppHandle, state: State<'_, Arc<Runtime>>, target: String, mut rules: Vec<RouteRule>,
    profile: Option<RoutingProfile>, allow_lan: Option<bool>,
) -> Result<serde_json::Value, String> {
    let profile = profile.unwrap_or_default();
    let Some((outbound, fallback)) = profile.routes() else {
        return Ok(rules_engine::analyze(&target, &rules));
    };
    let target = target.trim().trim_end_matches('.');
    if target.is_empty() || target.chars().any(char::is_whitespace) || target.contains('/') {
        return Err("Введите домен или IP без протокола и пути".into());
    }
    let ip = target.parse::<std::net::IpAddr>().ok();
    let private = match ip {
        Some(std::net::IpAddr::V4(ip)) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        Some(std::net::IpAddr::V6(ip)) => ip.is_unique_local() || ip.is_loopback() || ip.is_unicast_link_local(),
        None => false,
    };
    if private && (allow_lan.unwrap_or(false) || profile == RoutingProfile::BypassRussia) {
        return Ok(serde_json::json!({"route":"direct","explanation":"Локальная сеть"}));
    }
    rules.retain(|rule| rule.kind != "Финальное");
    let manual = rules_engine::analyze(target, &rules);
    if manual["matched"] == true {
        return Ok(manual);
    }
    let files = load_profile_sets(&app, state.inner(), profile).await?;
    let (tag, path) = &files[usize::from(ip.is_some())];
    let binary = embedded_sing_box(&app)?;
    let matched = matches_profile_set(&binary, path, target).await?;
    Ok(serde_json::json!({
        "route": if matched { outbound } else { fallback },
        "explanation": if matched { tag.as_str() } else { "Маршрут по умолчанию для профиля" }
    }))
}

#[tauri::command]
fn find_rule_conflicts(rules: Vec<RouteRule>) -> serde_json::Value {
    rules_engine::conflicts(&rules)
}

#[tauri::command]
async fn test_server(state: State<'_, Arc<Runtime>>, server: Server) -> Result<serde_json::Value, String> {
    let interfaces = active_probe_interfaces(state.inner()).await?;
    let address=match resolve_probe_addr(&server.host,server.port).await{Ok(value)=>value,Err(_)=>return Ok(serde_json::json!({"latency":null,"jitter":null,"loss":100,"stability":0}))};
    let mut samples: Vec<u128> = Vec::new();
    for _ in 0..3 {
        let started = std::time::Instant::now();
        let result = timeout(
            Duration::from_millis(1200),
            connect_probe(address, interfaces),
        )
        .await;
        if matches!(result, Ok(Ok(_))) {
            samples.push(elapsed_ms(started));
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    let failures = 3usize.saturating_sub(samples.len());
    let loss = failures * 100 / 3;
    if samples.is_empty() {
        return Ok(serde_json::json!({"latency":null,"jitter":null,"loss":100,"stability":0}));
    }
    let latency = samples.iter().sum::<u128>() / samples.len() as u128;
    let jitter = if samples.len() > 1 {
        samples.windows(2).map(|pair| pair[0].abs_diff(pair[1])).sum::<u128>()
            / (samples.len() - 1) as u128
    } else { 0 };
    let stability = 100usize.saturating_sub(loss + usize::try_from(jitter.min(30)).unwrap_or(30));
    Ok(serde_json::json!({"latency":latency,"jitter":jitter,"loss":loss,"stability":stability}))
}

#[tauri::command]
async fn connect(
    app: AppHandle,
    state: State<'_, Arc<Runtime>>,
    request: ConnectRequest,
) -> Result<(), String> {
    let runtime = state.inner().clone();
    let _operation = runtime.connection_operation.lock().await;
    disconnect_runtime(&runtime).await?;
    *runtime.connection_state.lock().await="connecting".into();*runtime.last_error.lock().await=None;record_trace(&runtime,"connecting",serde_json::json!({"server":request.server.name.clone(),"protocol":request.server.protocol.clone(),"mode":request.mode.clone(),"dns_mode":request.dns_mode.clone(),"ipv6_mode":request.ipv6_mode.clone()})).await;
    app.emit("connect-stage", "prepare").ok();
    if request.mode=="tun" && !windows::is_elevated().unwrap_or(false){return Err("TUN требует запуска от имени администратора".into());}

    let plan = cores::plan(&request.server, &request.core_preference)?;
    let dir = data_dir(&app)?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    let mut started: Vec<Child> = Vec::new();
    let bridge = match plan.bridge_port {
        Some(_) => {
            let port=reserve_local_port()?;
            app.emit("connect-stage", "bridge").ok();
            let mut upstream=start_upstream_core(&app,&dir,&plan,&request,port).await?;
            if let Some(pid)=upstream.id(){if let Err(e)=runtime.job.assign_pid(pid){upstream.kill().await.ok();return Err(format!("Job Object: {e}"));}}
            started.push(upstream);
            Some((port, plan.core.binary()))
        }
        None => None,
    };

    let mut stats_key = [0u8; 24];
    let stats = reserve_local_port().ok().and_then(|port| {
        getrandom::fill(&mut stats_key).ok().map(|()| (port, hex::encode(stats_key)))
    });
    let mut bypass_ips=Vec::new();if let Ok(xs)=tokio::net::lookup_host((request.server.host.as_str(),request.server.port)).await{for a in xs{let ip=a.ip().to_string();if !bypass_ips.contains(&ip){bypass_ips.push(ip)}}}
    app.emit("connect-stage", "config").ok();
    let probe_port = match reserve_local_port() {
        Ok(port) => port,
        Err(error) => { kill_all(started).await; return Err(error); }
    };
    let profile_sets = match load_profile_sets(&app, &runtime, request.routing_profile).await {
        Ok(sets) => sets,
        Err(error) => { kill_all(started).await; return Err(error); }
    };
    let cfg=match config::build(&request,bridge,stats.as_ref().map(|(port, secret)| (*port, secret.as_str())),&bypass_ips,probe_port,&profile_sets){
        Ok(value)=>value,
        Err(error)=>{kill_all(started).await;return Err(error)}
    };
    let config_path = dir.join("active.json");
    if let Err(error) = std::fs::write(
        &config_path,
        serde_json::to_vec_pretty(&cfg).map_err(|e| e.to_string())?,
    ) {
        kill_all(started).await;
        return Err(error.to_string());
    }

    let binary = match embedded_sing_box(&app){
        Ok(value)=>value,
        Err(error)=>{kill_all(started).await;return Err(error)}
    };
    let config_arg = match config_path.to_str(){
        Some(value)=>value,
        None=>{kill_all(started).await;return Err("Некорректный путь конфигурации".into())}
    };

    app.emit("connect-stage", "check").ok();
    let mut check_command = std::process::Command::new(&binary);
    check_command.args(["check", "-c", config_arg]);
    hide_window(&mut check_command);
    let check = check_command.output();
    let check = match check {
        Ok(value) => value,
        Err(error) => {
            kill_all(started).await;
            return Err(format!("sing-box не найден: {error}"));
        }
    };
    if !check.status.success() {
        kill_all(started).await;
        let details = String::from_utf8_lossy(&check.stderr).trim().to_string();
        return Err(if details.is_empty() { "sing-box отклонил конфигурацию".into() } else { format!("Ошибка конфигурации sing-box: {details}") });
    }

    let log_path = dir.join("sing-box.log");
    let log_file = std::fs::File::create(&log_path).ok();
    let mut command = Command::new(binary);
    command.args(["run", "-c", config_arg]);
    hide_window_async(&mut command);
    match log_file {
        Some(file) => {
            let clone = file.try_clone().ok();
            command.stdout(Stdio::from(file));
            match clone {
                Some(handle) => command.stderr(Stdio::from(handle)),
                None => command.stderr(Stdio::null()),
            };
        }
        None => {
            command.stdout(Stdio::null()).stderr(Stdio::null());
        }
    }
    app.emit("connect-stage", "start").ok();
    let spawned = command.spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            kill_all(started).await;
            return Err(error.to_string());
        }
    };
    if let Some(pid)=child.id(){if let Err(e)=runtime.job.assign_pid(pid){child.kill().await.ok();kill_all(started).await;return Err(format!("Job Object: {e}"));}}
    if request.mode=="tun"{app.emit("connect-stage","tun").ok();}
    if let Err(error) = wait_for_core(&mut child, probe_port, request.mode == "tun", Duration::from_secs(8)).await {
        child.kill().await.ok();
        kill_all(started).await;
        let details = tail_log(&log_path);
        return Err(if details.is_empty() { error } else { format!("{error}\n{details}") });
    }
    app.emit("connect-stage", "verify").ok();
    let exit_ip=match verify_proxy_path(probe_port).await{Ok(v)=>v,Err(e)=>{child.kill().await.ok();kill_all(started).await;return Err(format!("End-to-end проверка: {e}"));}};
    started.push(child);
    if request.kill_switch_mode!="off"{
        app.emit("connect-stage", "protect").ok();
        let f=std::env::temp_dir().join("lzt-tunnel-firewall-state.json");
        let mut programs=Vec::new();
        if let Ok(p)=std::env::current_exe(){programs.push(p.to_string_lossy().into_owned())}
        for c in cores::ALL_CORES{if let Ok(p)=embedded_core(&app,c){programs.push(p.to_string_lossy().into_owned())}}
        if let Err(error)=windows::set_kill_switch(true,&f,&programs,request.allow_lan){
            kill_all(started).await;
            let _=windows::set_kill_switch(false,&f,&[],false);
            return Err(format!("Kill Switch: {error}"));
        }
    }
    runtime.probe_port.store(probe_port, std::sync::atomic::Ordering::Relaxed);
    *runtime.mode.lock().await=request.mode.clone();*runtime.core.lock().await=plan.core.id().into();*runtime.stats_endpoint.lock().await=stats;*runtime.kill_switch_mode.lock().await=request.kill_switch_mode.clone();*runtime.exit_ip.lock().await=Some(exit_ip.clone());*runtime.connection_state.lock().await="connected".into();runtime.network_signature.lock().await.clear();*runtime.health_failures.lock().await=0;*runtime.last_health_check.lock().await=std::time::Instant::now();*runtime.children.lock().await=started;record_trace(&runtime,"connected",serde_json::json!({"core":plan.core.id(),"exit_ip":exit_ip.clone()})).await;
    if request.mode=="proxy"{let p=std::env::temp_dir().join("lzt-tunnel-proxy-state.json");if let Err(e)=windows::set_proxy(true,&p){disconnect_runtime(&runtime).await.ok();return Err(e)}}
    app.emit("connect-stage",serde_json::json!({"stage":"ready","exit_ip":exit_ip})).ok();Ok(())
}

async fn kill_all(children: Vec<Child>) {
    let mut children = children;
    while let Some(mut child) = children.pop() {
        child.kill().await.ok();
        child.wait().await.ok();
    }
}

/// Starts Xray-core or Mihomo as the local SOCKS5 bridge used by sing-box.
async fn start_upstream_core(
    app: &AppHandle,
    dir: &std::path::Path,
    plan: &cores::CorePlan,
    request: &ConnectRequest,
    port: u16,
) -> Result<Child, String> {
    let binary = embedded_core(app, plan.core)?;
    let (config_path, config_bytes, test_args, run_args) = match plan.core {
        CoreKind::Xray => {
            let value = xray_config::build(&request.server, port)?;
            let path = dir.join("bridge-xray.json");
            (
                path,
                serde_json::to_vec_pretty(&value).map_err(|e| e.to_string())?,
                vec!["-test".to_string(), "-c".to_string()],
                vec!["run".to_string(), "-c".to_string()],
            )
        }
        CoreKind::Mihomo => {
            let value = mihomo_config::build(&request.server, port, request.ipv6)?;
            let path = dir.join("bridge-mihomo.yaml");
            (
                path,
                serde_json::to_vec_pretty(&value).map_err(|e| e.to_string())?,
                vec!["-t".to_string(), "-f".to_string()],
                vec!["-f".to_string()],
            )
        }
        CoreKind::SingBox => return Err("sing-box не используется как промежуточное ядро".into()),
    };
    std::fs::write(&config_path, config_bytes).map_err(|e| e.to_string())?;
    let config_arg = config_path
        .to_str()
        .ok_or_else(|| "Некорректный путь конфигурации".to_string())?
        .to_string();

    let mut test_command = std::process::Command::new(&binary);
    for argument in &test_args {
        test_command.arg(argument);
    }
    hide_window(&mut test_command);
    let test = test_command
        .arg(&config_arg)
        .output()
        .map_err(|error| format!("{} не запустилось: {error}", plan.core.title()))?;
    if !test.status.success() {
        let stderr = String::from_utf8_lossy(&test.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&test.stdout).trim().to_string();
        let details = if stderr.is_empty() { stdout } else { stderr };
        return Err(format!(
            "{} отклонило конфигурацию: {}",
            plan.core.title(),
            if details.is_empty() { "причина не указана".to_string() } else { details }
        ));
    }

    let mut command = Command::new(&binary);
    for argument in &run_args {
        command.arg(argument);
    }
    hide_window_async(&mut command);
    command.arg(&config_arg);
    if plan.core == CoreKind::Mihomo {
        let mihomo_dir = dir.join("mihomo");
        std::fs::create_dir_all(&mihomo_dir).map_err(|e| e.to_string())?;
        command.arg("-d").arg(mihomo_dir);
    }
    let bridge_log = dir.join("bridge.log");
    match std::fs::File::create(&bridge_log).ok() {
        Some(file) => {
            let clone = file.try_clone().ok();
            command.stdout(Stdio::from(file));
            match clone {
                Some(handle) => command.stderr(Stdio::from(handle)),
                None => command.stderr(Stdio::null()),
            };
        }
        None => {
            command.stdout(Stdio::null()).stderr(Stdio::null());
        }
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("{} не запустилось: {error}", plan.core.title()))?;

    if let Err(error) = wait_for_core(&mut child, port, false, Duration::from_secs(5)).await {
        child.kill().await.ok();
        let details = tail_log(&bridge_log);
        return Err(format!("{}: {error}\n{details}", plan.core.title()));
    }
    Ok(child)
}

async fn wait_for_core(child: &mut Child, port: u16, tun: bool, limit: Duration) -> Result<(), String> {
    let until = tokio::time::Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            return Err(format!("VPN-ядро завершилось: {status}"));
        }
        if (!tun || windows::tun_ready()) && matches!(
            timeout(Duration::from_millis(75), TcpStream::connect(("127.0.0.1", port))).await,
            Ok(Ok(_))
        ) {
            return Ok(());
        }
        if tokio::time::Instant::now() >= until {
            return Err(if tun { "Интерфейс TUN или локальный порт не готовы".into() } else { format!("Локальный порт {port} не открылся") });
        }
        tokio::time::sleep(Duration::from_millis(75)).await;
    }
}

fn reserve_local_port()->Result<u16,String>{let l=std::net::TcpListener::bind(("127.0.0.1",0)).map_err(|e|e.to_string())?;l.local_addr().map(|a|a.port()).map_err(|e|e.to_string())}
async fn verify_proxy_path(port: u16) -> Result<String, String> {
    let proxy = reqwest::Proxy::all(format!("http://127.0.0.1:{port}")).map_err(|error| error.to_string())?;
    let client = reqwest::Client::builder().proxy(proxy).timeout(Duration::from_secs(5))
        .user_agent("LZT-Tunnel/1.12.0").build().map_err(|error| error.to_string())?;
    let probes = [
        ("https://api.ipify.org?format=json", "json"),
        ("https://api64.ipify.org?format=json", "json"),
        ("https://www.cloudflare.com/cdn-cgi/trace", "cloudflare"),
        ("https://icanhazip.com/", "text"),
    ];
    let mut tasks = tokio::task::JoinSet::new();
    for (index, (url, kind)) in probes.into_iter().enumerate() {
        let client = client.clone();
        tasks.spawn(async move {
            if index != 0 { tokio::time::sleep(Duration::from_millis(250 * index as u64)).await; }
            let response = client.get(url).send().await.and_then(reqwest::Response::error_for_status)
                .map_err(|error| format!("{url}: {error}"))?;
            let body = response.text().await.map_err(|error| format!("{url}: {error}"))?;
            let candidate = match kind {
                "json" => serde_json::from_str::<serde_json::Value>(&body).ok()
                    .and_then(|value| value.get("ip").and_then(|ip| ip.as_str()).map(str::to_owned)),
                "cloudflare" => body.lines().find_map(|line| line.strip_prefix("ip=").map(str::to_owned)),
                _ => Some(body.trim().to_owned()),
            };
            candidate.filter(|ip| ip.parse::<std::net::IpAddr>().is_ok())
                .ok_or_else(|| format!("{url}: ответ без IP"))
        });
    }
    let mut errors = Vec::new();
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(ip)) => return Ok(ip),
            Ok(Err(error)) => errors.push(error),
            Err(error) => errors.push(error.to_string()),
        }
    }
    Err(format!("Не удалось проверить туннель: {}", errors.join(" | ")))
}

#[tauri::command]
async fn connection_status(state: State<'_, Arc<Runtime>>) -> Result<serde_json::Value, String> {
    let runtime = state.inner();
    let connected = !runtime.mode.lock().await.is_empty();
    let port = runtime.probe_port.load(std::sync::atomic::Ordering::Relaxed);
    let mut failure = None;
    if connected {
        for child in runtime.children.lock().await.iter_mut() {
            match child.try_wait() {
                Ok(None) => continue,
                Ok(Some(status)) => failure = Some(format!("Ядро завершилось: {status}")),
                Err(error) => failure = Some(error.to_string()),
            }
            break;
        }
    }
    let due = if connected && failure.is_none() {
        let mut last = runtime.last_health_check.lock().await;
        if last.elapsed() >= Duration::from_secs(10) {
            *last = std::time::Instant::now();
            true
        } else { false }
    } else { false };
    if due {
        let network_task = tauri::async_runtime::spawn_blocking(windows::network_signature);
        let health = verify_proxy_path(port).await;
        let network = network_task.await;
        let _operation = runtime.connection_operation.lock().await;
        if runtime.probe_port.load(std::sync::atomic::Ordering::Relaxed) == port {
            if let Ok(Ok(signature)) = network {
                let mut old = runtime.network_signature.lock().await;
                if !signature.is_empty() {
                    if !old.is_empty() && *old != signature { failure = Some("Изменилась сеть или основной шлюз".into()); }
                    *old = signature;
                }
            }
            match health {
                Ok(ip) => {
                    *runtime.exit_ip.lock().await = Some(ip);
                    *runtime.health_failures.lock().await = 0;
                }
                Err(error) => {
                    let mut count = runtime.health_failures.lock().await;
                    *count += 1;
                    if *count >= 2 && failure.is_none() { failure = Some(error); }
                }
            }
        }
    }
    if let Some(error) = failure {
        let _operation = runtime.connection_operation.lock().await;
        if runtime.probe_port.load(std::sync::atomic::Ordering::Relaxed) == port {
            *runtime.connection_state.lock().await = "failed".into();
            *runtime.last_error.lock().await = Some(error.clone());
            record_trace(runtime, "failed", serde_json::json!({"error":error.clone()})).await;
            let _ = disconnect_runtime(runtime).await;
            return Ok(serde_json::json!({"state":"failed","connected":false,"error":error}));
        }
    }
    Ok(serde_json::json!({
        "state": runtime.connection_state.lock().await.clone(),
        "connected": !runtime.mode.lock().await.is_empty(),
        "core": runtime.core.lock().await.clone(),
        "exit_ip": runtime.exit_ip.lock().await.clone(),
        "health_failures": *runtime.health_failures.lock().await
    }))
}
#[tauri::command] fn windows_network_report()->Result<serde_json::Value,String>{windows::network_report()}
#[tauri::command]
async fn disconnect(state: State<'_, Arc<Runtime>>) -> Result<(), String> {
    let runtime = state.inner();
    let _operation = runtime.connection_operation.lock().await;
    let result = disconnect_runtime(runtime).await;
    *runtime.connection_state.lock().await = "idle".into();
    result
}

#[tauri::command]
fn always_admin() -> Result<bool, String> { windows::always_admin() }

#[tauri::command]
fn set_always_admin(enabled: bool) -> Result<(), String> { windows::set_always_admin(enabled) }

fn main() {
    if windows::always_admin().unwrap_or(false) && matches!(windows::is_elevated(), Ok(false)) {
        match windows::relaunch_as_admin() {
            Ok(()) => return,
            Err(error) => eprintln!("{error}"),
        }
    }
    let runtime = Arc::new(Runtime {
        children: Mutex::new(Vec::new()),
        mode: Mutex::new(String::new()),
        core: Mutex::new(String::new()),
        probe_port: std::sync::atomic::AtomicU16::new(2080),
        profile_download: Mutex::new(()),
        connection_operation: Mutex::new(()),
        stats_endpoint: Mutex::new(None),connection_state:Mutex::new("idle".into()),last_error:Mutex::new(None),exit_ip:Mutex::new(None),kill_switch_mode:Mutex::new("off".into()),network_signature:Mutex::new(String::new()),health_failures:Mutex::new(0),last_health_check:Mutex::new(std::time::Instant::now()),trace:Mutex::new(Vec::new()),
        job: job::ProcessJob::new().expect("Windows Job Object"),
    });
    let app = tauri::Builder::default()
        .setup(|_|{if let Err(error) = windows::register_subscription_protocols() { eprintln!("Subscription URL registration: {error}"); }let p=std::env::temp_dir().join("lzt-tunnel-proxy-state.json");windows::recover_proxy(&p).map_err(std::io::Error::other)?;let f=std::env::temp_dir().join("lzt-tunnel-firewall-state.json");windows::recover_kill_switch(&f).map_err(std::io::Error::other)?;Ok(())})
        .manage(runtime)
        .invoke_handler(tauri::generate_handler![
            startup_subscription_url,
            import_subscription,
            core_status,
            core_report,
            plan_cores,
            run_diagnostics,
            export_diagnostics,
            external_ip,
            traffic_stats,
            vpn_notice,
            ping_server,
            ping_servers,
            test_server,
            analyze_route,
            find_rule_conflicts,
            windows_network_report,
            always_admin,
            set_always_admin,
            connection_status,
            connect,
            disconnect
        ])
        .build(tauri::generate_context!())
        .expect("LZT Tunnel failed");

    app.run(|app_handle, event| {
        if matches!(event, tauri::RunEvent::ExitRequested { .. }) {
            let runtime = app_handle.state::<Arc<Runtime>>().inner().clone();
            tauri::async_runtime::block_on(async move {
                let _operation = runtime.connection_operation.lock().await;
                disconnect_runtime(&runtime).await.ok();
            });
        }
    });
}

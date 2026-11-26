use std::path::Path;
use std::process::{Command,Output};
fn quote(v:&str)->String{format!("'{}'",v.replace('\'',"''"))}
#[cfg(windows)] fn powershell(script:&str)->std::io::Result<Output>{use std::os::windows::process::CommandExt;let mut c=Command::new("powershell.exe");c.args(["-NoProfile","-NonInteractive","-WindowStyle","Hidden","-Command",script]).creation_flags(0x08000000);c.output()}
#[cfg(not(windows))] fn powershell(_: &str)->std::io::Result<Output>{Err(std::io::Error::new(std::io::ErrorKind::Unsupported,"Windows only"))}
fn run(script:&str)->Result<String,String>{let o=powershell(script).map_err(|e|e.to_string())?;if !o.status.success(){let e=String::from_utf8_lossy(&o.stderr).trim().to_string();return Err(if e.is_empty(){"Команда Windows завершилась с ошибкой".into()}else{e})}Ok(String::from_utf8_lossy(&o.stdout).trim().into())}
#[derive(Clone, Copy, Debug)]
pub struct ProbeInterfaces {
    ipv4: Option<u32>,
    ipv6: Option<u32>,
}

#[cfg(windows)]
pub fn probe_interfaces() -> Result<ProbeInterfaces, String> {
    use std::{mem::zeroed, ptr::{addr_of, null_mut}, slice};
    use windows_sys::Win32::{
        NetworkManagement::IpHelper::{
            ConvertInterfaceAliasToLuid, FreeMibTable, GetIpForwardTable2, GetIpInterfaceEntry,
            InitializeIpInterfaceEntry, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
        },
        Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC},
    };

    let alias: Vec<u16> = "lzt-tun\0".encode_utf16().collect();
    let mut tunnel = unsafe { zeroed() };
    let status = unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut tunnel) };
    if status != 0 {
        return Err(format!("Не найден интерфейс TUN: {}", std::io::Error::from_raw_os_error(status as i32)));
    }
    let mut table: *mut MIB_IPFORWARD_TABLE2 = null_mut();
    let status = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) };
    if status != 0 {
        return Err(format!("Не удалось прочитать маршруты Windows: {}", std::io::Error::from_raw_os_error(status as i32)));
    }
    if table.is_null() { return Err("Windows вернула пустую таблицу маршрутов".into()); }

    let mut ipv4 = None;
    let mut ipv6 = None;
    // Windows owns this flexible array until FreeMibTable. NumEntries is its length.
    let rows = unsafe { slice::from_raw_parts(addr_of!((*table).Table).cast::<MIB_IPFORWARD_ROW2>(), (*table).NumEntries as usize) };
    for row in rows {
        if row.DestinationPrefix.PrefixLength != 0 || row.Loopback != 0 || unsafe { row.InterfaceLuid.Value == tunnel.Value } {
            continue;
        }
        let family = unsafe { row.DestinationPrefix.Prefix.si_family };
        let best = match family { AF_INET => &mut ipv4, AF_INET6 => &mut ipv6, _ => continue };
        let mut interface = unsafe { zeroed() };
        unsafe { InitializeIpInterfaceEntry(&mut interface) };
        interface.Family = family;
        interface.InterfaceLuid = row.InterfaceLuid;
        if unsafe { GetIpInterfaceEntry(&mut interface) } != 0 || interface.Connected == 0 {
            continue;
        }
        let candidate = (row.Metric.saturating_add(interface.Metric), row.InterfaceIndex);
        if best.is_none_or(|current| candidate < current) { *best = Some(candidate); }
    }
    unsafe { FreeMibTable(table.cast()) };
    if ipv4.is_none() && ipv6.is_none() {
        return Err("Не найдена сеть для проверки задержки вне TUN".into());
    }
    Ok(ProbeInterfaces { ipv4: ipv4.map(|(_, index)| index), ipv6: ipv6.map(|(_, index)| index) })
}

#[cfg(not(windows))]
pub fn probe_interfaces() -> Result<ProbeInterfaces, String> { Err("Windows only".into()) }

#[cfg(windows)]
pub fn bind_probe_interface(socket: &tokio::net::TcpSocket, address: std::net::SocketAddr, interfaces: ProbeInterfaces) -> std::io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        setsockopt, WSAGetLastError, IPPROTO_IP, IPPROTO_IPV6, IP_UNICAST_IF, IPV6_UNICAST_IF,
    };
    let (level, option, index) = if address.is_ipv4() {
        // Winsock expects the IPv4 interface index in network byte order.
        (IPPROTO_IP, IP_UNICAST_IF, interfaces.ipv4.map(u32::to_be))
    } else {
        (IPPROTO_IPV6, IPV6_UNICAST_IF, interfaces.ipv6)
    };
    let index = index.ok_or_else(|| std::io::Error::new(
        std::io::ErrorKind::AddrNotAvailable, "Нет маршрута вне TUN для семейства адреса",
    ))?;
    let result = unsafe {
        setsockopt(socket.as_raw_socket() as usize, level, option, (&index as *const u32).cast(), 4)
    };
    if result == 0 { Ok(()) } else { Err(std::io::Error::from_raw_os_error(unsafe { WSAGetLastError() })) }
}

#[cfg(not(windows))]
pub fn bind_probe_interface(_: &tokio::net::TcpSocket, _: std::net::SocketAddr, _: ProbeInterfaces) -> std::io::Result<()> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "Windows only"))
}

fn notify()->&'static str{r#"Add-Type -Namespace WinInet -Name NativeMethods -MemberDefinition '[DllImport("wininet.dll")] public static extern bool InternetSetOption(IntPtr h,int o,IntPtr b,int l);';[WinInet.NativeMethods]::InternetSetOption(0,39,0,0)|Out-Null;[WinInet.NativeMethods]::InternetSetOption(0,37,0,0)|Out-Null"#}
pub fn set_proxy(on:bool,state_file:&Path)->Result<(),String>{let f=quote(&state_file.to_string_lossy());let p="$ErrorActionPreference='Stop';$p='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';";let s=if on{format!("{p}$f={f};if(!(Test-Path $f)){{$r=Get-ItemProperty $p;$s=@{{}};foreach($n in @('ProxyEnable','ProxyServer','ProxyOverride','AutoConfigURL')){{$x=$r.PSObject.Properties.Name -contains $n;$s[$n]=@{{present=$x;value=if($x){{$r.$n}}else{{$null}}}}}};$s|ConvertTo-Json -Depth 4|Set-Content $f -Encoding UTF8}};Set-ItemProperty $p ProxyEnable 1;Set-ItemProperty $p ProxyServer 'socks=127.0.0.1:2080;http=127.0.0.1:2080;https=127.0.0.1:2080';Set-ItemProperty $p ProxyOverride '<local>';{}",notify())}else{format!("{p}$f={f};if(Test-Path $f){{$s=Get-Content $f -Raw|ConvertFrom-Json;foreach($n in @('ProxyEnable','ProxyServer','ProxyOverride','AutoConfigURL')){{$e=$s.$n;if($e.present){{Set-ItemProperty $p $n $e.value}}else{{Remove-ItemProperty $p $n -ErrorAction SilentlyContinue}}}};Remove-Item $f -Force}}else{{Set-ItemProperty $p ProxyEnable 0}};{}",notify())};run(&s).map(|_|())}
pub fn recover_proxy(p:&Path)->Result<(),String>{if p.exists(){set_proxy(false,p)}else{Ok(())}}

#[cfg(windows)]
pub fn is_elevated() -> Result<bool, String> {
    use std::{mem::size_of, ptr::null_mut};
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned = 0;
    let ok = unsafe { GetTokenInformation(token, TokenElevation, (&mut elevation as *mut TOKEN_ELEVATION).cast(), size_of::<TOKEN_ELEVATION>() as u32, &mut returned) };
    let error = std::io::Error::last_os_error();
    unsafe { CloseHandle(token) };
    if ok == 0 { Err(error.to_string()) } else { Ok(elevation.TokenIsElevated != 0) }
}

#[cfg(not(windows))]
pub fn is_elevated() -> Result<bool, String> { Ok(false) }

fn admin_preference() -> Result<std::path::PathBuf, String> {
    std::env::var_os("APPDATA")
        .map(|root| std::path::PathBuf::from(root).join("team.lolz.tunnel").join("always-admin"))
        .ok_or_else(|| "Не найдена папка настроек Windows".into())
}

pub fn always_admin() -> Result<bool, String> {
    admin_preference()?.try_exists().map_err(|error| error.to_string())
}

pub fn set_always_admin(enabled: bool) -> Result<(), String> {
    let path = admin_preference()?;
    if enabled {
        std::fs::create_dir_all(path.parent().expect("preference parent"))
            .and_then(|()| std::fs::File::create(&path).map(|_| ()))
            .map_err(|error| error.to_string())
    } else {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    }
}

#[cfg(windows)]
pub fn relaunch_as_admin() -> Result<(), String> {
    use std::{os::windows::ffi::OsStrExt, ptr::null};
    use windows_sys::Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL};
    let file = std::env::current_exe().map_err(|error| error.to_string())?;
    let file: Vec<u16> = file.as_os_str().encode_wide().chain([0]).collect();
    let mut args = Vec::new();
    for arg in std::env::args_os().skip(1) {
        if !args.is_empty() { args.push(b' ' as u16); }
        args.push(0x22);
        let mut slashes = 0;
        for unit in arg.encode_wide() {
            if unit == b'\\' as u16 { slashes += 1; continue; }
            let count = if unit == 0x22 { slashes * 2 + 1 } else { slashes };
            args.extend(std::iter::repeat_n(b'\\' as u16, count));
            args.push(unit);
            slashes = 0;
        }
        args.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
        args.push(0x22);
    }
    args.push(0);
    let verb: Vec<u16> = "runas\0".encode_utf16().collect();
    let result = unsafe { ShellExecuteW(std::ptr::null_mut(), verb.as_ptr(), file.as_ptr(), args.as_ptr(), null(), SW_SHOWNORMAL) };
    if result as isize > 32 { Ok(()) } else { Err(format!("Повышение прав не выполнено ({})", result as isize)) }
}

#[cfg(not(windows))]
pub fn relaunch_as_admin() -> Result<(), String> { Err("Windows only".into()) }

#[cfg(windows)]
pub fn tun_ready() -> bool {
    use windows_sys::Win32::NetworkManagement::{
        IpHelper::{ConvertInterfaceAliasToLuid, GetIfEntry2},
        Ndis::IfOperStatusUp,
    };
    let alias: Vec<u16> = "lzt-tun\0".encode_utf16().collect();
    let mut row: windows_sys::Win32::NetworkManagement::IpHelper::MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
    let status = unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut row.InterfaceLuid) };
    status == 0 && unsafe { GetIfEntry2(&mut row) } == 0 && row.OperStatus == IfOperStatusUp
}

#[cfg(not(windows))]
pub fn tun_ready() -> bool { false }

const FIREWALL_GROUP:&str="LZT Tunnel Kill Switch";
pub fn set_kill_switch(on:bool,state_file:&Path,programs:&[String],allow_lan:bool)->Result<(),String>{
 let f=quote(&state_file.to_string_lossy());let g=quote(FIREWALL_GROUP);
 let script=if on{let rules=programs.iter().enumerate().map(|(i,p)|format!("New-NetFirewallRule -DisplayName 'LZT Core {i}' -Group {g} -Direction Outbound -Action Allow -Program {} -Profile Any|Out-Null;",quote(p))).collect::<String>();let lan=if allow_lan{format!("New-NetFirewallRule -DisplayName 'LZT LAN' -Group {g} -Direction Outbound -Action Allow -RemoteAddress LocalSubnet -Profile Any|Out-Null;")}else{String::new()};format!("$ErrorActionPreference='Stop';$f={f};if(!(Test-Path $f)){{Get-NetFirewallProfile|Select Name,DefaultOutboundAction|ConvertTo-Json|Set-Content $f -Encoding UTF8}};Get-NetFirewallRule -Group {g} -ErrorAction SilentlyContinue|Remove-NetFirewallRule;{rules}New-NetFirewallRule -DisplayName 'LZT TUN' -Group {g} -Direction Outbound -Action Allow -InterfaceAlias 'lzt-tun' -Profile Any|Out-Null;New-NetFirewallRule -DisplayName 'LZT DHCP' -Group {g} -Direction Outbound -Action Allow -Protocol UDP -RemotePort 67,68 -Profile Any|Out-Null;{lan}Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block")}else{format!("$ErrorActionPreference='Stop';Get-NetFirewallRule -Group {g} -ErrorAction SilentlyContinue|Remove-NetFirewallRule;$f={f};if(Test-Path $f){{$s=Get-Content $f -Raw|ConvertFrom-Json;foreach($q in @($s | Group-Object DefaultOutboundAction)){{Set-NetFirewallProfile -Name @($q.Group.Name) -DefaultOutboundAction $q.Name}};Remove-Item $f -Force}}")};run(&script).map(|_|())
}
pub fn recover_kill_switch(p:&Path)->Result<(),String>{if p.exists(){set_kill_switch(false,p,&[],false)}else{Ok(())}}
pub fn network_signature()->Result<String,String>{run("$x=Get-NetIPConfiguration|Where-Object{$_.IPv4DefaultGateway}|%{[string]$_.InterfaceIndex+'|'+[string]$_.IPv4DefaultGateway.NextHop+'|'+[string]$_.NetAdapter.Status};$x -join ';'")}
pub fn network_report()->Result<serde_json::Value,String>{let t=run(r#"$x=[ordered]@{adapters=@(Get-NetAdapter|Select Name,Status,LinkSpeed);routes=@(Get-NetRoute -AddressFamily IPv4|? DestinationPrefix -in @('0.0.0.0/0','0.0.0.0/1','128.0.0.0/1')|Select DestinationPrefix,InterfaceAlias,NextHop,RouteMetric);dns=@(Get-DnsClientServerAddress|?{$_.ServerAddresses.Count}|Select InterfaceAlias,AddressFamily,ServerAddresses);proxy=(Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'|Select ProxyEnable,ProxyServer,ProxyOverride,AutoConfigURL)};$x|ConvertTo-Json -Depth 6 -Compress"#)?;serde_json::from_str(&t).map_err(|e|e.to_string())}


/// Makes this portable executable the per-user handler for subscription links
/// generated by FlClash/FlClashX pages. HKCU does not require administrator rights.
#[cfg(windows)]
pub fn register_subscription_protocols()->Result<(),String>{
 use std::os::windows::process::CommandExt;
 let exe=std::env::current_exe().map_err(|e|e.to_string())?;
 let command_value=format!("\"{}\" \"%1\"",exe.to_string_lossy());
 for scheme in ["flclash","flclashx","clash","lzt-tunnel"]{
  let base=format!(r"HKCU\Software\Classes\{scheme}");
  let command_key=format!(r"{base}\shell\open\command");
  let commands=[
   vec!["add".into(),base.clone(),"/ve".into(),"/d".into(),"URL:LZT Tunnel subscription".into(),"/f".into()],
   vec!["add".into(),base.clone(),"/v".into(),"URL Protocol".into(),"/d".into(),String::new(),"/f".into()],
   vec!["add".into(),command_key,"/ve".into(),"/d".into(),command_value.clone(),"/f".into()],
  ];
  for args in commands{
   let mut command=Command::new("reg.exe");command.args(args).creation_flags(0x08000000);
   let output=command.output().map_err(|e|e.to_string())?;
   if !output.status.success(){return Err(String::from_utf8_lossy(&output.stderr).into_owned())}
  }
 }
 Ok(())
}
#[cfg(not(windows))]
pub fn register_subscription_protocols()->Result<(),String>{Ok(())}

pub fn vpn_notice(lost: bool, server: &str) -> Result<(), String> {
    let title = if lost { "Соединение потеряно" } else { "VPN отключён" };
    let name: String = server.chars().filter(|ch| !ch.is_control()).take(120).collect();
    let title = quote(title);
    let name = quote(&name);
    run(&format!(r#"
        $ErrorActionPreference='Stop'
        $id='Twizz.Tuneel'
        $key='HKCU:\Software\Classes\AppUserModelId\'+$id
        if (!(Test-Path $key)) {{
            New-Item -Path $key -Force | Out-Null
            New-ItemProperty -Path $key -Name DisplayName -Value 'Twizz Tuneel' -PropertyType String -Force | Out-Null
        }}
        $null=[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
        $null=[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
        $heading=[Security.SecurityElement]::Escape({title})
        $message=[Security.SecurityElement]::Escape({name})
        $doc=[Windows.Data.Xml.Dom.XmlDocument]::new()
        $doc.LoadXml('<toast><visual><binding template="ToastGeneric"><text>'+$heading+'</text><text>'+$message+'</text></binding></visual><audio silent="true"/></toast>')
        $toast=[Windows.UI.Notifications.ToastNotification]::new($doc)
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($id).Show($toast)
    "#)).map(|_| ())
}

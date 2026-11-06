//! Native WSL networking adapter. No agent, no WSL sing-box, no permanent service.
use std::net::Ipv4Addr;
#[cfg(any(windows, test))]
use std::time::Duration;

#[cfg(any(windows, test))]
const DIAGNOSTIC_READBACK_TIMEOUT: Duration = Duration::from_millis(2200);
/// One deadline for both native WSL guest discovery and Windows NIC ownership.
/// A cold Ubuntu startup may take longer than a warm per-process probe.
#[cfg(windows)]
const WSL_DIAGNOSE_DISCOVERY_BUDGET: Duration = Duration::from_millis(6500);
#[cfg(any(windows, test))]
const WSL_SYNC_READBACK_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Network {
    pub guest: Ipv4Addr,
    pub gateway: Ipv4Addr,
}

pub fn validate_ips(guest: &str, gateway: &str) -> Result<Network, &'static str> {
    let guest: Ipv4Addr = guest.parse().map_err(|_| "WSL_IP_INVALID")?;
    let gateway: Ipv4Addr = gateway.parse().map_err(|_| "WSL_GATEWAY_INVALID")?;
    if !guest.is_private()
        || !gateway.is_private()
        || guest == gateway
        || guest.is_loopback()
        || gateway.is_loopback()
    {
        return Err("WSL_NETWORK_SCOPE_INVALID");
    }
    Ok(Network { guest, gateway })
}
#[cfg(windows)]
fn read_only_command(command: std::process::Command) -> Result<std::process::Output, &'static str> {
    read_only_command_with_timeout(command, DIAGNOSTIC_READBACK_TIMEOUT)
}

#[cfg(any(windows, test))]
fn read_only_command_with_timeout(
    mut command: std::process::Command,
    timeout: Duration,
) -> Result<std::process::Output, &'static str> {
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().map_err(|_| "WSL_READBACK_UNAVAILABLE")?;
    let until = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                // Process already exited; collect exit status and bounded output.
                return child.wait_with_output().map_err(|_| "WSL_READBACK_FAILED");
            }
            Ok(None) if Instant::now() < until => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("WSL_READBACK_TIMEOUT");
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("WSL_READBACK_FAILED");
            }
        }
    }
}

/// Native Windows bind is the source of local address ownership. No WSL process
/// is spawned. The optional WSL inbound cannot prevent Desktop/TUN startup.
#[cfg(windows)]
pub fn windows_start_config(
    current: &serde_json::Value,
) -> Result<serde_json::Value, &'static str> {
    use std::io::ErrorKind;
    let address: Ipv4Addr = current
        .pointer("/inbounds/1/listen")
        .and_then(|v| v.as_str())
        .ok_or("WSL_LISTENER_INVALID")?
        .parse()
        .map_err(|_| "WSL_LISTENER_INVALID")?;
    if address.is_loopback() {
        return Ok(current.clone());
    }
    match std::net::TcpListener::bind((address, 0)) {
        Ok(socket) => {
            drop(socket);
            Ok(current.clone())
        }
        Err(e) if e.kind() == ErrorKind::AddrNotAvailable => {
            crate::config::with_wsl_loopback(current)
        }
        Err(_) => Err("WSL_LISTENER_NATIVE_CHECK_FAILED"),
    }
}
#[cfg(windows)]
pub fn discover() -> Result<Option<Network>, &'static str> {
    // A bounded diagnostic readback is independent of Windows start.
    // Share the budget between the WSL guest and Windows ownership probe;
    // two separate full timeouts would multiply the worst-case duration.
    discover_with_deadline(Some(
        std::time::Instant::now() + WSL_DIAGNOSE_DISCOVERY_BUDGET,
    ))
}

/// Only an explicit WSL sync starts Ubuntu; Windows startup never calls it.
/// Share one bounded budget across guest discovery and gateway ownership.
#[cfg(windows)]
pub fn discover_for_start() -> Result<Option<Network>, &'static str> {
    discover_with_deadline(Some(std::time::Instant::now() + WSL_SYNC_READBACK_TIMEOUT))
}

#[cfg(windows)]
fn discover_with_deadline(
    startup_deadline: Option<std::time::Instant>,
) -> Result<Option<Network>, &'static str> {
    use std::process::Command;
    let readback = |command| {
        let timeout = startup_deadline
            .map(|deadline| deadline.saturating_duration_since(std::time::Instant::now()))
            .unwrap_or(DIAGNOSTIC_READBACK_TIMEOUT);
        read_only_command_with_timeout(command, timeout)
    };
    // Read only: two IPv4 observations from the existing Ubuntu instance.
    let script = "import subprocess,socket; r=subprocess.check_output(['ip','-4','route','show','default'],text=True).split(); g=r[r.index('via')+1]; a=subprocess.check_output(['hostname','-I'],text=True).split(); print(a[0]+' '+g)";
    let mut command = Command::new("wsl.exe");
    command.args(["-d", "Ubuntu", "--", "/usr/bin/python3", "-c", script]);
    let output = readback(command)?;
    if !output.status.success() {
        return Ok(None);
    }
    let text = std::str::from_utf8(&output.stdout).map_err(|_| "WSL_NETWORK_READBACK_INVALID")?;
    let parts: Vec<_> = text.split_whitespace().collect();
    if parts.len() != 2 {
        return Err("WSL_NETWORK_READBACK_INVALID");
    }
    let network = validate_ips(parts[0], parts[1])?;
    // A valid gateway must belong to an actual native Windows local interface.
    let command = format!(
        "if (-not (Get-NetIPAddress -AddressFamily IPv4 -IPAddress '{}' -ErrorAction SilentlyContinue)) {{ exit 4 }}",
        network.gateway
    );
    let mut native = Command::new("powershell.exe");
    native.args(["-NoProfile", "-NonInteractive", "-Command", &command]);
    let check = readback(native)?;
    if !check.status.success() {
        return Err("WSL_GATEWAY_NOT_OWNED");
    }
    Ok(Some(network))
}
#[cfg(not(windows))]
pub fn discover_for_start() -> Result<Option<Network>, &'static str> {
    Ok(None)
}

#[cfg(not(windows))]
pub fn discover() -> Result<Option<Network>, &'static str> {
    Ok(None)
}

#[cfg(windows)]
pub fn firewall_allow(network: &Network) -> Result<(), &'static str> {
    use std::process::Command;
    // Exactly one named application-owned firewall rule, one TCP port, one guest and one host IP.
    let script = format!(
        r#"
$ErrorActionPreference='Stop'
$name='INTERNET-WSL-INBOUND-2081'
$local='{gateway}'
$remote='{guest}'
$r=Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
if($r){{
  $p=$r | Get-NetFirewallPortFilter
  $a=$r | Get-NetFirewallAddressFilter
  if($r.DisplayName -cne $name -or $r.Direction -ne 'Inbound' -or
     $r.Action -ne 'Allow' -or [string]$p.Protocol -ne 'TCP' -or
     [string]$p.LocalPort -ne '2081' -or $p.RemotePort -ne 'Any'){{
      throw 'FIREWALL_RULE_OWNER_CONFLICT'
  }}
  $a | Set-NetFirewallAddressFilter -LocalAddress $local -RemoteAddress $remote | Out-Null
}}else{{
  New-NetFirewallRule -Name $name -DisplayName $name -Direction Inbound -Action Allow -Protocol TCP -LocalPort 2081 -LocalAddress $local -RemoteAddress $remote -Profile Any | Out-Null
}}
$r=Get-NetFirewallRule -Name $name -ErrorAction Stop
$p=$r | Get-NetFirewallPortFilter
$a=$r | Get-NetFirewallAddressFilter
if([string]$p.LocalPort -ne '2081' -or [string]$a.RemoteAddress -ne $remote -or
   [string]$a.LocalAddress -ne $local) {{ throw 'FIREWALL_RULE_READBACK_FAILED' }}
"#,
        gateway = network.gateway,
        guest = network.guest
    );
    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|_| "FIREWALL_RULE_EXEC_FAILED")?;
    if !out.status.success() {
        return Err("FIREWALL_RULE_APPLY_UNCONFIRMED");
    }
    Ok(())
}
#[cfg(not(windows))]
pub fn firewall_allow(_: &Network) -> Result<(), &'static str> {
    Err("WINDOWS_ONLY")
}

// Scoped rollback data is intentionally transient in the same Rust invocation.
// Only addresses are captured; no firewall export or second state store.
#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireGuardFirewallBefore(pub Option<(Ipv4Addr, Ipv4Addr)>);

#[cfg(windows)]
fn valid_wg_interface(interface: &str) -> bool {
    interface.starts_with("vEthernet (WSL")
        && interface.ends_with(')')
        && interface.len() <= 128
        && interface
            .bytes()
            .all(|c| (c.is_ascii_graphic() || c == b' ') && c != b'\'')
}

#[cfg(windows)]
pub fn wireguard_firewall_snapshot(
    _network: &Network,
    interface: &str,
) -> Result<WireGuardFirewallBefore, &'static str> {
    use std::process::Command;
    if !valid_wg_interface(interface) {
        return Err("WSL_WG_INTERFACE_INVALID");
    }
    let script = format!(
        r#"
$ErrorActionPreference='Stop'
$name='INTERNET-WSL-WG-43913'
$r=Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
if (!$r) {{ 'ABSENT'; exit 0 }}
$p=$r | Get-NetFirewallPortFilter
$app=$r | Get-NetFirewallApplicationFilter
$f=$r | Get-NetFirewallInterfaceFilter
if ($r.DisplayName -cne $name -or $r.Direction -ne 'Inbound' -or
    $r.Action -ne 'Allow' -or $r.Enabled -ne 'True' -or
    [string]$p.Protocol -ne 'UDP' -or [string]$p.LocalPort -ne '43913' -or
    [string]$p.RemotePort -ne 'Any' -or
    $app.Program -cne 'C:\internet\sing-box.exe' -or
    [string]$f.InterfaceAlias -cne '{interface}') {{ throw 'OWNER_CONFLICT' }}
$a=$r | Get-NetFirewallAddressFilter
'{{0}} {{1}}' -f [string]$a.LocalAddress,[string]$a.RemoteAddress
"#,
        interface = interface
    );
    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|_| "WSL_WG_FIREWALL_SNAPSHOT_FAILED")?;
    if !out.status.success() {
        return Err("WSL_WG_FIREWALL_OWNER_CONFLICT");
    }
    let text = std::str::from_utf8(&out.stdout).map_err(|_| "WSL_WG_FIREWALL_SNAPSHOT_FAILED")?;
    let parts: Vec<_> = text.split_whitespace().collect();
    if parts == ["ABSENT"] {
        return Ok(WireGuardFirewallBefore(None));
    }
    if parts.len() != 2 {
        return Err("WSL_WG_FIREWALL_SNAPSHOT_FAILED");
    }
    let local = parts[0]
        .parse::<Ipv4Addr>()
        .map_err(|_| "WSL_WG_FIREWALL_SNAPSHOT_FAILED")?;
    let remote = parts[1]
        .parse::<Ipv4Addr>()
        .map_err(|_| "WSL_WG_FIREWALL_SNAPSHOT_FAILED")?;
    if !local.is_private() || !remote.is_private() {
        return Err("WSL_WG_FIREWALL_SNAPSHOT_FAILED");
    }
    Ok(WireGuardFirewallBefore(Some((local, remote))))
}

#[cfg(windows)]
pub fn wireguard_firewall_restore(
    network: &Network,
    interface: &str,
    before: &WireGuardFirewallBefore,
) -> Result<(), &'static str> {
    use std::process::Command;
    // Never overwrite a rule changed by another actor since this invocation.
    let current = wireguard_firewall_snapshot(network, interface)?;
    let intended = WireGuardFirewallBefore(Some((network.gateway, network.guest)));
    if current == *before {
        return Ok(());
    }
    if current != intended {
        return Err("WSL_WG_FIREWALL_CONCURRENT_CHANGE");
    }
    let action = match before.0 {
        None => "Remove-NetFirewallRule -Name $name -ErrorAction Stop".to_string(),
        Some((local, remote)) => format!(
            "$r | Get-NetFirewallAddressFilter | Set-NetFirewallAddressFilter -LocalAddress '{local}' -RemoteAddress '{remote}' -ErrorAction Stop | Out-Null"
        ),
    };
    let script = format!(
        r#"
$ErrorActionPreference='Stop'
$name='INTERNET-WSL-WG-43913'
$r=Get-NetFirewallRule -Name $name -ErrorAction Stop
{action}
"#
    );
    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|_| "WSL_WG_FIREWALL_ROLLBACK_FAILED")?;
    if !out.status.success() || wireguard_firewall_snapshot(network, interface)? != *before {
        return Err("WSL_WG_FIREWALL_ROLLBACK_UNCONFIRMED");
    }
    Ok(())
}

#[cfg(windows)]
pub fn wireguard_firewall_allow(network: &Network, interface: &str) -> Result<(), &'static str> {
    use std::process::Command;
    // This is an endpoint-specific Windows Defender rule, not a controller.
    // One exact guest /32 and one native WSL host adapter; never open the VM,
    // Ethernet or global UDP scope. The existing Rust CLI is its only writer.
    if !valid_wg_interface(interface) {
        return Err("WSL_WG_INTERFACE_INVALID");
    }
    let script = format!(
        r#"
$ErrorActionPreference='Stop'
$name='INTERNET-WSL-WG-43913'
$remote='{guest}'
$local='{gateway}'
$iface='{interface}'
$exe='C:\internet\sing-box.exe'
$r=Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
if($r){{
  $p=$r | Get-NetFirewallPortFilter
  $app=$r | Get-NetFirewallApplicationFilter
  $f=$r | Get-NetFirewallInterfaceFilter
  if($r.DisplayName -cne $name -or $r.Direction -ne 'Inbound' -or
     $r.Action -ne 'Allow' -or $r.Enabled -ne 'True' -or
     [string]$p.Protocol -ne 'UDP' -or [string]$p.LocalPort -ne '43913' -or
     [string]$p.RemotePort -ne 'Any' -or $app.Program -cne $exe -or
     [string]$f.InterfaceAlias -cne $iface){{
     throw 'WSL_WG_FIREWALL_OWNER_CONFLICT'
  }}
  $a=$r | Get-NetFirewallAddressFilter
  $a | Set-NetFirewallAddressFilter -LocalAddress $local -RemoteAddress $remote | Out-Null
}}else{{
  New-NetFirewallRule -Name $name -DisplayName $name -Direction Inbound -Action Allow -Enabled True -Program $exe -Protocol UDP -LocalPort 43913 -LocalAddress $local -RemoteAddress $remote -InterfaceAlias $iface -Profile Any | Out-Null
}}
$r=Get-NetFirewallRule -Name $name -ErrorAction Stop
$a=$r | Get-NetFirewallAddressFilter
$p=$r | Get-NetFirewallPortFilter
if([string]$a.RemoteAddress -cne $remote -or [string]$a.LocalAddress -cne $local -or
   [string]$p.LocalPort -cne '43913'){{ throw 'WSL_WG_FIREWALL_READBACK_FAILED' }}
"#,
        guest = network.guest,
        gateway = network.gateway,
        interface = interface,
    );
    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|_| "WSL_WG_FIREWALL_EXEC_UNAVAILABLE")?;
    if !out.status.success() {
        return Err("WSL_WG_FIREWALL_APPLY_UNCONFIRMED");
    }
    Ok(())
}
#[cfg(not(windows))]
pub fn wireguard_firewall_allow(_: &Network, _: &str) -> Result<(), &'static str> {
    Err("WINDOWS_ONLY")
}

/// The only accepted positive readback is an HTTP 407 challenge from inside WSL.
/// A bare listening socket or unknown protocol reply is not a proof.
pub fn classify_auth_reply(raw: &str) -> Result<(), &'static str> {
    match raw.trim() {
        "AUTH_REQUIRED" => Ok(()),
        "AUTH_BYPASS" => Err("WSL_PROXY_AUTH_BYPASS"),
        "SOCKET_FAILED" => Err("WSL_TO_WINDOWS_PROXY_UNREACHABLE"),
        _ => Err("WSL_PROXY_AUTH_UNVERIFIED"),
    }
}

#[cfg(windows)]
pub fn probe(network: &Network) -> Result<(), &'static str> {
    use std::process::Command;
    // Test the real HTTP proxy boundary from the WSL guest, not just an open
    // TCP socket. No credentials or egress configuration are read or changed.
    let source = format!(
        r#"import socket
try:
 s=socket.create_connection(('{}',2081),timeout=1.5)
 s.settimeout(1.5)
 s.sendall(b'CONNECT api.ipify.org:443 HTTP/1.1\r\nHost: api.ipify.org:443\r\n\r\n')
 response=s.recv(256).split(b'\r\n',1)[0]
 print('AUTH_REQUIRED' if response.startswith(b'HTTP/1.1 407 ') else ('AUTH_BYPASS' if response.startswith(b'HTTP/1.1 200 ') else 'AUTH_UNKNOWN'))
 s.close()
except (OSError,TimeoutError):
 print('SOCKET_FAILED')
"#,
        network.gateway
    );
    let mut native = Command::new("wsl.exe");
    native.args(["-d", "Ubuntu", "--", "/usr/bin/python3", "-c", &source]);
    let out = read_only_command(native)?;
    if !out.status.success() {
        return Err("WSL_TO_WINDOWS_PROXY_UNREACHABLE");
    }
    let reply = std::str::from_utf8(&out.stdout).map_err(|_| "WSL_AUTH_REPLY_INVALID")?;
    classify_auth_reply(reply)
}
#[cfg(not(windows))]
pub fn probe(_: &Network) -> Result<(), &'static str> {
    Err("WINDOWS_ONLY")
}

#[cfg(test)]
mod tests {
    use super::*;

    // A disposable test subprocess stands in for a slow native WSL readback.
    // It never starts WSL or touches the installed application/network.
    fn slow_readback() -> std::process::Command {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args([
            "--exact",
            "wsl::tests::readback_delay_fixture",
            "--nocapture",
        ]);
        command.env("INTERNET_WSL_DELAY_FIXTURE", "1");
        command
    }
    #[test]
    fn readback_delay_fixture() {
        if std::env::var_os("INTERNET_WSL_DELAY_FIXTURE").is_some() {
            std::thread::sleep(DIAGNOSTIC_READBACK_TIMEOUT + Duration::from_millis(300));
        }
    }
    #[test]
    fn explicit_sync_accepts_readback_slower_than_diagnostic_budget() {
        let output = read_only_command_with_timeout(slow_readback(), WSL_SYNC_READBACK_TIMEOUT)
            .expect("slow but successful readback must be accepted during start");
        assert!(output.status.success());
    }
    #[test]
    fn diagnostics_still_reject_slow_readback() {
        let error = read_only_command_with_timeout(slow_readback(), DIAGNOSTIC_READBACK_TIMEOUT)
            .unwrap_err();
        assert_eq!(error, "WSL_READBACK_TIMEOUT");
    }

    #[test]
    fn wsl_http_auth_challenge_is_required() {
        assert!(classify_auth_reply("AUTH_REQUIRED\n").is_ok());
        assert_eq!(
            classify_auth_reply("AUTH_BYPASS"),
            Err("WSL_PROXY_AUTH_BYPASS")
        );
        assert_eq!(
            classify_auth_reply("SOCKET_FAILED"),
            Err("WSL_TO_WINDOWS_PROXY_UNREACHABLE")
        );
        for response in ["", "AUTH_UNKNOWN", "200", "AUTH_REQUIRED\nINJECTED"] {
            assert_eq!(
                classify_auth_reply(response),
                Err("WSL_PROXY_AUTH_UNVERIFIED")
            );
        }
    }
    #[test]
    fn exact_private_wsl_scope() {
        assert_eq!(
            validate_ips("172.26.23.199", "172.26.16.1")
                .unwrap()
                .gateway
                .to_string(),
            "172.26.16.1"
        );
        for (guest, gw) in [
            ("8.8.8.8", "172.26.16.1"),
            ("172.26.23.199", "0.0.0.0"),
            ("127.0.0.1", "172.26.16.1"),
            ("172.26.23.199", "172.26.23.199"),
        ] {
            assert!(validate_ips(guest, gw).is_err());
        }
    }
}

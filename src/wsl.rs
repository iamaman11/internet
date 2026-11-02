//! Native WSL networking adapter. No agent, no WSL sing-box, no permanent service.
use std::net::Ipv4Addr;

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
fn read_only_command(
    mut command: std::process::Command,
) -> Result<std::process::Output, &'static str> {
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().map_err(|_| "WSL_READBACK_UNAVAILABLE")?;
    let until = Instant::now() + Duration::from_millis(2200);
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

#[cfg(windows)]
pub fn discover() -> Result<Option<Network>, &'static str> {
    use std::process::Command;
    // Read only: two IPv4 observations from the existing Ubuntu instance.
    let script = "import subprocess,socket; r=subprocess.check_output(['ip','-4','route','show','default'],text=True).split(); g=r[r.index('via')+1]; a=subprocess.check_output(['hostname','-I'],text=True).split(); print(a[0]+' '+g)";
    let mut command = Command::new("wsl.exe");
    command.args(["-d", "Ubuntu", "--", "/usr/bin/python3", "-c", script]);
    let output = read_only_command(command)?;
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
    let check = read_only_command(native)?;
    if !check.status.success() {
        return Err("WSL_GATEWAY_NOT_OWNED");
    }
    Ok(Some(network))
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

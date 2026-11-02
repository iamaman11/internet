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
pub fn discover() -> Result<Option<Network>, &'static str> {
    use std::process::Command;
    // Read only: two IPv4 observations from the existing Ubuntu instance.
    let script = "import subprocess,socket; r=subprocess.check_output(['ip','-4','route','show','default'],text=True).split(); g=r[r.index('via')+1]; a=subprocess.check_output(['hostname','-I'],text=True).split(); print(a[0]+' '+g)";
    let output = Command::new("wsl.exe")
        .args(["-d", "Ubuntu", "--", "/usr/bin/python3", "-c", script])
        .output()
        .map_err(|_| "WSL_UNAVAILABLE")?;
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
    let check = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &command])
        .output()
        .map_err(|_| "WSL_GATEWAY_NOT_OWNED")?;
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

#[cfg(windows)]
pub fn probe(network: &Network) -> Result<(), &'static str> {
    use std::process::Command;
    let source = format!(
        r#"import socket; s=socket.socket(); s.settimeout(1.5); s.connect(('{}',2081)); s.close()"#,
        network.gateway
    );
    let out = Command::new("wsl.exe")
        .args(["-d", "Ubuntu", "--", "/usr/bin/python3", "-c", &source])
        .output()
        .map_err(|_| "WSL_SOCKET_TEST_UNAVAILABLE")?;
    if out.status.success() {
        Ok(())
    } else {
        Err("WSL_TO_WINDOWS_PROXY_UNREACHABLE")
    }
}
#[cfg(not(windows))]
pub fn probe(_: &Network) -> Result<(), &'static str> {
    Err("WINDOWS_ONLY")
}

#[cfg(test)]
mod tests {
    use super::*;
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

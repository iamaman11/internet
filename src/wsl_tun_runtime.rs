//! U7 native WSL TUN operations. Rust CLI is the only lifecycle owner.
//! Ubuntu executes one-shot native ip/wg/resolvectl commands, never a daemon.
use serde_json::Value;
#[cfg(windows)]
use serde_json::json;

// Read-only validation for the already-installed Windows endpoint.
// WSL ON/OFF never reconfigure or restart the native Windows sing-box task.
#[cfg(any(windows, test))]
fn endpoint_needs_update(
    configured: bool,
    endpoint: &Value,
    guest_ip: &str,
    guest_public_key: &str,
    windows_private_key: &str,
) -> bool {
    !configured
        || endpoint["listen_port"].as_u64()
            != Some(u64::from(crate::wsl_tun::WINDOWS_WG_LISTEN_PORT))
        || endpoint["peers"][0]["address"].as_str() != Some(guest_ip)
        || endpoint["peers"][0]["public_key"].as_str() != Some(guest_public_key)
        || endpoint["private_key"].as_str() != Some(windows_private_key)
        || endpoint.get("detour").is_some()
}

#[cfg(windows)]
mod native {
    use super::*;
    use crate::{config, lifecycle, model::Target, wsl, wsl_tun};
    use std::{
        fs,
        net::Ipv4Addr,
        path::Path,
        process::{Command, Output, Stdio},
        time::{Duration, Instant},
    };

    const GUEST_CODE: &str = include_str!("wsl_tun_guest.py");
    // These are native executor working credentials, provisioned once on the
    // local machine. Vault and GitHub never participate in runtime operations.
    const WIN_KEY_FILE: &str = r"C:\internet\config\wsl-wireguard.key";

    fn valid_key(k: &str) -> bool {
        k.len() == 44
            && k.ends_with('=')
            && k.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=')
    }
    fn windows_private() -> Result<String, &'static str> {
        let path = Path::new(WIN_KEY_FILE);
        let meta = fs::symlink_metadata(path).map_err(|_| "WSL_WINDOWS_KEY_NOT_PROVISIONED")?;
        if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 80 {
            return Err("WSL_WINDOWS_KEY_UNOWNED");
        }
        let k = fs::read_to_string(path).map_err(|_| "WSL_WINDOWS_KEY_UNREADABLE")?;
        let key = k.trim().to_owned();
        if !valid_key(&key) {
            return Err("WSL_WINDOWS_KEY_INVALID");
        }
        Ok(key)
    }
    fn windows_public(private: &str) -> Result<String, &'static str> {
        use std::io::Write;
        let mut c = Command::new("wsl.exe");
        c.args(["-d", "Ubuntu", "--", "/usr/bin/wg", "pubkey"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = c.spawn().map_err(|_| "WSL_PUBKEY_TOOL_UNAVAILABLE")?;
        let result = (|| -> Result<(), &'static str> {
            let stdin = child.stdin.as_mut().ok_or("WSL_PUBKEY_PIPE_FAILED")?;
            stdin
                .write_all(private.as_bytes())
                .map_err(|_| "WSL_PUBKEY_PIPE_FAILED")?;
            stdin
                .write_all(b"\n")
                .map_err(|_| "WSL_PUBKEY_PIPE_FAILED")?;
            Ok(())
        })();
        drop(child.stdin.take());
        if let Err(code) = result {
            let _ = child.kill();
            let _ = child.wait();
            return Err(code);
        }
        let out = child
            .wait_with_output()
            .map_err(|_| "WSL_PUBKEY_READBACK_FAILED")?;
        if !out.status.success() {
            return Err("WSL_PUBKEY_INVALID");
        }
        let value = String::from_utf8(out.stdout).map_err(|_| "WSL_PUBKEY_INVALID")?;
        let public = value.trim().to_owned();
        if !valid_key(&public) {
            return Err("WSL_PUBKEY_INVALID");
        }
        Ok(public)
    }

    fn output(mut command: Command) -> Result<Output, &'static str> {
        // A safety ceiling prevents an unresponsive WSL child from holding CLI forever.
        // It is never treated as a readiness/success signal.
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn().map_err(|_| "WSL_EXEC_UNAVAILABLE")?;
        let deadline = Instant::now() + Duration::from_secs(40);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => {
                    return child
                        .wait_with_output()
                        .map_err(|_| "WSL_EXEC_READBACK_FAILED");
                }
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(30))
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("WSL_EXEC_UNRESPONSIVE");
                }
            }
        }
    }
    fn guest(action: &str, public: Option<&str>) -> Result<Value, &'static str> {
        let mut c = Command::new("wsl.exe");
        c.args([
            "-d",
            "Ubuntu",
            "--",
            "/usr/bin/python3",
            "-c",
            GUEST_CODE,
            action,
        ]);
        if let Some(p) = public {
            c.arg(p);
        }
        let out = output(c)?;
        let value: Value =
            serde_json::from_slice(&out.stdout).map_err(|_| "WSL_NATIVE_OUTPUT_INVALID")?;
        if !out.status.success() || value["ok"] != true {
            return Err(match value["reason_code"].as_str() {
                Some("WSL_GUEST_KEY_NOT_PROVISIONED") => "WSL_GUEST_KEY_NOT_PROVISIONED",
                Some("WSL_NATIVE_DNS_SETUP_REQUIRED") => "WSL_NATIVE_DNS_SETUP_REQUIRED",
                Some("WSL_DNS_SETUP_OWNER_CONFLICT") => "WSL_DNS_SETUP_OWNER_CONFLICT",
                Some("WSL_DNS_SETUP_TUN_OWNED") => "WSL_DNS_SETUP_TUN_OWNED",
                Some("WSL_DNS_SETUP_FAILED") => "WSL_DNS_SETUP_FAILED",
                Some("WSL_WG_ORPHAN_RULE") => "WSL_WG_ORPHAN_RULE",
                Some("WSL_NATIVE_GATEWAY_INVALID") => "WSL_NATIVE_GATEWAY_INVALID",
                Some("WSL_WG_ALREADY_PRESENT") => "WSL_WG_ALREADY_PRESENT",
                Some("WSL_WG_INTERFACE_UNOWNED") => "WSL_WG_INTERFACE_UNOWNED",
                Some("WSL_WG_KEY_UNOWNED") => "WSL_WG_KEY_UNOWNED",
                Some("WSL_WG_LISTEN_UNOWNED") => "WSL_WG_LISTEN_UNOWNED",
                Some("WSL_WG_UNOWNED_ROUTE_REFUSE") => "WSL_WG_UNOWNED_ROUTE_REFUSE",
                Some("WSL_WG_PARTIAL_STATE_REFUSE") => "WSL_WG_PARTIAL_STATE_REFUSE",
                Some("WSL_RESOLV_OWNER_CONFLICT") => "WSL_RESOLV_OWNER_CONFLICT",
                Some("WSL_RESOLVED_NOT_ACTIVE") => "WSL_RESOLVED_NOT_ACTIVE",
                Some("WSL_RESOLVED_STUB_MISSING") => "WSL_RESOLVED_STUB_MISSING",
                Some("WSL_IPV6_DEFAULT_CONFLICT") => "WSL_IPV6_DEFAULT_CONFLICT",
                Some("WSL_WG_APPLY_READBACK_FAILED") => "WSL_WG_APPLY_READBACK_FAILED",
                Some("WSL_WG_ORPHAN_STATE") => "WSL_WG_ORPHAN_STATE",
                _ => "WSL_NATIVE_ACTION_REJECTED",
            });
        }
        Ok(value)
    }
    // Read actual Windows UDP ownership: RUNNING Task Scheduler and valid
    // config do not prove that the optional WG listener is active.
    fn windows_wg_listener_ready() -> Result<bool, &'static str> {
        let script = format!(
            "$p=@(Get-CimInstance Win32_Process -Filter \"Name='sing-box.exe'\" | Where-Object {{ $_.ExecutablePath -eq 'C:\\internet\\sing-box.exe' }}); if($p.Count -ne 1){{exit 4}}; $u=@(Get-NetUDPEndpoint -LocalPort {} -ErrorAction SilentlyContinue | Where-Object {{ $_.OwningProcess -eq $p[0].ProcessId }}); if($u.Count -gt 0){{'READY'}}else{{'MISSING'}}",
            wsl_tun::WINDOWS_WG_LISTEN_PORT
        );
        let mut c = Command::new("powershell.exe");
        c.args(["-NoProfile", "-NonInteractive", "-Command", &script]);
        let out = output(c).map_err(|_| "WSL_WG_WINDOWS_LISTENER_READBACK_FAILED")?;
        if !out.status.success() {
            return Err("WSL_WG_WINDOWS_LISTENER_READBACK_FAILED");
        }
        match std::str::from_utf8(&out.stdout)
            .map_err(|_| "WSL_WG_WINDOWS_LISTENER_READBACK_FAILED")?
            .trim()
        {
            "READY" => Ok(true),
            "MISSING" => Ok(false),
            _ => Err("WSL_WG_WINDOWS_LISTENER_READBACK_FAILED"),
        }
    }
    fn guest_state() -> Result<Value, &'static str> {
        guest("status", None)
    }
    fn guest_public() -> Result<String, &'static str> {
        let response = guest("pubkey", None)?;
        let key = response["public_key"]
            .as_str()
            .ok_or("WSL_GUEST_PUBLIC_INVALID")?;
        if !valid_key(key) {
            return Err("WSL_GUEST_PUBLIC_INVALID");
        }
        Ok(key.to_owned())
    }
    fn windows_binding(gateway: Ipv4Addr) -> Result<String, &'static str> {
        let script = format!(
            "$a=Get-NetIPAddress -AddressFamily IPv4 -IPAddress '{}' -ErrorAction Stop; (Get-NetAdapter -InterfaceIndex $a.InterfaceIndex -ErrorAction Stop).Name",
            gateway
        );
        let mut c = Command::new("powershell.exe");
        c.args(["-NoProfile", "-NonInteractive", "-Command", &script]);
        let out = output(c)?;
        if !out.status.success() {
            return Err("WSL_NATIVE_ADAPTER_NOT_OWNED");
        }
        let name = std::str::from_utf8(&out.stdout)
            .map_err(|_| "WSL_NATIVE_ADAPTER_INVALID")?
            .trim()
            .to_owned();
        if !name.starts_with("vEthernet (WSL") || !name.ends_with(')') || name.len() > 128 {
            return Err("WSL_NATIVE_ADAPTER_INVALID");
        }
        Ok(name)
    }
    fn check_egress() -> Result<String, &'static str> {
        // Use ordinary guest networking; explicitly remove proxy variables.
        let mut c = Command::new("wsl.exe");
        c.args([
            "-d",
            "Ubuntu",
            "--",
            "/usr/bin/env",
            "-u",
            "HTTP_PROXY",
            "-u",
            "HTTPS_PROXY",
            "-u",
            "ALL_PROXY",
            "-u",
            "http_proxy",
            "-u",
            "https_proxy",
            "-u",
            "all_proxy",
            "/usr/bin/curl",
            "-4",
            "-fsS",
            "--max-time",
            "15",
            "https://api.ipify.org",
        ]);
        let res = output(c)?;
        if !res.status.success() {
            return Err("WSL_NATIVE_EGRESS_UNREACHABLE");
        }
        let ip = std::str::from_utf8(&res.stdout)
            .map_err(|_| "WSL_NATIVE_EGRESS_INVALID")?
            .trim();
        let parsed: Ipv4Addr = ip.parse().map_err(|_| "WSL_NATIVE_EGRESS_INVALID")?;
        if parsed.is_private() || parsed.is_loopback() {
            return Err("WSL_NATIVE_EGRESS_INVALID");
        }
        Ok(ip.to_owned())
    }
    fn expected_vm_ipv4(config: &Value) -> Result<Ipv4Addr, &'static str> {
        let server = config["outbounds"][0]["server"]
            .as_str()
            .ok_or("WSL_VM_TARGET_UNKNOWN")?;
        let target: Ipv4Addr = server.parse().map_err(|_| "WSL_VM_TARGET_INVALID")?;
        if target.is_private()
            || target.is_loopback()
            || target.is_link_local()
            || target.is_unspecified()
        {
            return Err("WSL_VM_TARGET_INVALID");
        }
        Ok(target)
    }
    #[cfg(test)]
    #[test]
    fn vm_egress_expectation_uses_configured_endpoint_not_hardcoded_vm() {
        for target in ["64.176.74.102", "203.0.113.9"] {
            let c = json!({"outbounds":[{"server":target}]});
            assert_eq!(expected_vm_ipv4(&c).unwrap().to_string(), target);
        }
        for invalid in ["127.0.0.1", "10.1.2.3", "not-an-ip"] {
            let c = json!({"outbounds":[{"server":invalid}]});
            assert!(expected_vm_ipv4(&c).is_err());
        }
    }
    fn active(s: &Value) -> bool {
        s["kernel_interface"] == true
            && s["route_active"] == true
            && s["dns_redirected"] == true
            && s["ipv6_guard"] == true
    }
    /// One-time native Ubuntu DNS setup. No additional runtime service or secret store.
    pub fn dns_setup() -> Result<Value, &'static str> {
        let s = guest_state()?;
        if s["kernel_interface"] != false
            || s["owned_route_rules"] != false
            || s["ipv6_guard"] != false
        {
            return Err("WSL_DNS_SETUP_TUN_OWNED");
        }
        guest("dns-setup", None)
    }

    pub fn status() -> Result<Value, &'static str> {
        let current = config::read(&config::installed())?;
        let configured = wsl_tun::split(&current)?.1.is_some();
        let guest = guest_state()?;
        let is_active = active(&guest);
        let handshake = guest["handshake_observed"] == true;
        let peer_current =
            !configured || current["endpoints"][0]["peers"][0]["address"] == guest["guest_ipv4"];
        let state = if is_active && configured && handshake && peer_current {
            "ON"
        } else if guest["kernel_interface"] == false
            && guest["owned_route_rules"] == false
            && guest["dns_redirected"] == false
            && guest["ipv6_guard"] == false
        {
            "OFF"
        } else {
            "UNKNOWN"
        };
        Ok(json!({"ok":true,"owner":"INTERNET Rust / kernel WireGuard",
        "network":"WSL2 NAT","state":state,"windows_endpoint_configured":configured,
        "handshake_observed":handshake,"guest_peer_matches_native":peer_current,
        "guest":guest,"route":config::selected(&current,Target::Wsl)?.tag(),
        "next_action":match state {
            "ON"=>"internet wsl tun diagnose",
            "OFF"=>"internet wsl tun on",
            _=>"internet wsl tun diagnose; do not change foreign resources"
        }}))
    }
    pub fn diagnose() -> Result<Value, &'static str> {
        let state = status()?;
        if state["state"] != "ON" {
            return Ok(json!({"ok":false,"reason_code":"WSL_TUN_NOT_ACTIVE",
                "observed":state,"next_action":"Check WSL WireGuard status and route ownership"}));
        }
        let ip = check_egress()?;
        let route = state["route"].as_str().unwrap_or("UNKNOWN");
        let expect_vm = route.starts_with("direct-");
        let target = expected_vm_ipv4(&config::read(&config::installed())?)?;
        let pass = !expect_vm || ip == target.to_string();
        Ok(json!({"ok":pass,"state":"ON","ip4":ip,
            "expected":if expect_vm {target.to_string()} else {"WARP_EGRESS_UNSPECIFIED".into()},
            "reason_code":if pass {"WSL_NATIVE_IPV4_EGRESS_CONFIRMED"} else {"WSL_NATIVE_IP_MISMATCH"},
            "other_protocols":"NOT_TESTED",
            "next_action":"Verify DNS UDP IPv6 and independent Windows paths"}))
    }
    /// Idempotent guest-only ON. Windows sing-box, its configuration, native
    /// task, TUN, firewall and MCP are never modified by this operation.
    /// Initial endpoint provisioning is a separate explicit Windows action.
    pub fn on() -> Result<Value, &'static str> {
        let current = config::read(&config::installed())?;
        let configured = wsl_tun::split(&current)?.1.is_some();
        let before = guest_state()?;
        if configured && active(&before) && before["handshake_observed"] == true {
            let test = diagnose()?;
            if test["ok"] == true {
                return Ok(json!({"ok":true,"changed":false,"observed":test}));
            }
            return Err("WSL_TUN_EXISTING_STATE_UNVERIFIED");
        }
        if before["kernel_interface"] != false
            || before["owned_route_rules"] != false
            || before["unexpected_route"] != false
            || before["dns_redirected"] != false
            || before["ipv6_guard"] != false
        {
            return Err("WSL_TUN_GUEST_OWNER_CONFLICT");
        }
        // All Windows prerequisites are read before changing anything in Ubuntu.
        if !configured {
            return Err("WSL_WG_ENDPOINT_NOT_CONFIGURED");
        }
        if !lifecycle::is_running()? {
            return Err("WSL_TUN_WINDOWS_NOT_RUNNING");
        }
        let network = wsl::discover_for_start()?.ok_or("WSL_GUEST_UNAVAILABLE")?;
        let interface = windows_binding(network.gateway)?;
        let guest_pub = guest_public()?;
        let windows_private = windows_private()?;
        let windows_pub = windows_public(&windows_private)?;
        if super::endpoint_needs_update(
            configured,
            &current["endpoints"][0],
            &network.guest.to_string(),
            &guest_pub,
            &windows_private,
        ) {
            return Err("WSL_TUN_ENDPOINT_RECONFIGURATION_REQUIRED");
        }
        if !windows_wg_listener_ready()? {
            return Err("WSL_WG_WINDOWS_LISTENER_NOT_READY");
        }
        // No automatic Windows firewall edits in WSL ON. An absent or stale
        // owned rule is a setup fault, not permission to mutate Windows.
        wsl::wireguard_firewall_verify(&network, &interface)?;
        let result = (|| -> Result<Value, &'static str> {
            // Prepare keeps Ubuntu's NAT default until a real handshake.
            guest("prepare", Some(&windows_pub))?;
            guest("probe", None)?;
            let deadline = Instant::now() + Duration::from_secs(25);
            let mut handshake = false;
            while Instant::now() < deadline {
                if let Ok(s) = guest_state() {
                    if s["handshake_observed"] == true {
                        handshake = true;
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(400));
            }
            if !handshake {
                return Err("WSL_WG_HANDSHAKE_UNVERIFIED");
            }
            guest("activate", Some(&guest_pub))?;
            let ip = check_egress()?;
            let chosen = config::selected(&current, Target::Wsl)?;
            if chosen.tag().starts_with("direct-") && ip != expected_vm_ipv4(&current)?.to_string()
            {
                return Err("WSL_TUN_EGRESS_NOT_VM");
            }
            let after = guest_state()?;
            if !active(&after) {
                return Err("WSL_TUN_GUEST_READBACK_FAILED");
            }
            Ok(json!({"ok":true,"changed":true,"state":"ON",
                "handshake":"PASS","public_ip4":ip,"route":chosen.tag(),
                "dns_ipv6_route_readback":"PASS",
                "windows_process_unchanged":true,
                "udp_dns_independent_apps":"NOT_TESTED"}))
        })();
        match result {
            Ok(v) => Ok(v),
            Err(code) => {
                if guest("off", Some(&guest_pub)).is_err() {
                    return Err("WSL_TUN_ROLLBACK_UNCONFIRMED");
                }
                Err(code)
            }
        }
    }

    /// OFF changes only Ubuntu; the idle owned Windows endpoint is retained.
    /// This avoids interrupting Windows TUN/MCP on ordinary WSL ON/OFF.
    pub fn off() -> Result<Value, &'static str> {
        let current = config::read(&config::installed())?;
        let configured = wsl_tun::split(&current)?.1.is_some();
        let before = guest_state()?;
        let clean = before["kernel_interface"] == false
            && before["owned_route_rules"] == false
            && before["dns_redirected"] == false
            && before["ipv6_guard"] == false;
        if clean {
            return Ok(json!({"ok":true,"state":"OFF","changed":false,
                "windows_endpoint_configured":configured}));
        }
        if !configured {
            return Err("WSL_TUN_CONFIG_GUEST_DRIFT");
        }
        let guest_pub = guest_public()?;
        guest("off", Some(&guest_pub))?;
        let after = guest_state()?;
        if after["kernel_interface"] != false
            || after["owned_route_rules"] != false
            || after["dns_redirected"] != false
            || after["ipv6_guard"] != false
        {
            return Err("WSL_TUN_OFF_READBACK_FAILED");
        }
        Ok(json!({"ok":true,"state":"OFF","changed":true,
            "nat_restored":true,"windows_endpoint_configured":true,
            "windows_process_unchanged":true}))
    }
}

#[cfg(windows)]
pub use native::{diagnose, dns_setup, off, on, status};

#[cfg(not(windows))]
pub fn dns_setup() -> Result<Value, &'static str> {
    Err("WINDOWS_ONLY")
}
#[cfg(not(windows))]
pub fn status() -> Result<Value, &'static str> {
    Err("WINDOWS_ONLY")
}
#[cfg(not(windows))]
pub fn diagnose() -> Result<Value, &'static str> {
    Err("WINDOWS_ONLY")
}
#[cfg(not(windows))]
pub fn on() -> Result<Value, &'static str> {
    Err("WINDOWS_ONLY")
}
#[cfg(not(windows))]
pub fn off() -> Result<Value, &'static str> {
    Err("WINDOWS_ONLY")
}

#[cfg(test)]
mod endpoint_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn live_legacy_binding_alone_never_forces_windows_restart() {
        let endpoint = json!({
            "listen_port": crate::wsl_tun::WINDOWS_WG_LISTEN_PORT,
            "bind_interface": "vEthernet (WSL (Hyper-V firewall))",
            "private_key": "windows-test-key",
            "peers": [{"address": "172.26.23.199", "public_key": "guest-test-key"}]
        });
        assert!(!endpoint_needs_update(
            true,
            &endpoint,
            "172.26.23.199",
            "guest-test-key",
            "windows-test-key"
        ));
        assert!(endpoint_needs_update(
            true,
            &endpoint,
            "172.26.23.200",
            "guest-test-key",
            "windows-test-key"
        ));
        assert!(endpoint_needs_update(
            true,
            &endpoint,
            "172.26.23.199",
            "other-key",
            "windows-test-key"
        ));
        assert!(endpoint_needs_update(
            false,
            &endpoint,
            "172.26.23.199",
            "guest-test-key",
            "windows-test-key"
        ));
        let mut old_detour = endpoint.clone();
        old_detour.as_object_mut().unwrap().remove("listen_port");
        old_detour["detour"] = json!("wsl-transport-direct");
        assert!(endpoint_needs_update(
            true,
            &old_detour,
            "172.26.23.199",
            "guest-test-key",
            "windows-test-key"
        ));
    }
}

#[cfg(test)]
mod no_windows_mutation_tests {
    #[test]
    fn wsl_on_off_cannot_restart_or_reconfigure_windows() {
        let source = include_str!("wsl_tun_runtime.rs");
        let start = source.find("    pub fn on() -> Result<Value").unwrap();
        let end = source[start..]
            .find("    /// OFF changes only Ubuntu;")
            .unwrap()
            + start;
        let on_body = &source[start..end];
        for forbidden in [
            "lifecycle::restart(",
            "lifecycle::start(",
            "lifecycle::stop(",
            "config::write_checked(",
            "wireguard_firewall_allow(",
            "wireguard_firewall_restore(",
            "allow_mcp_reconnect",
        ] {
            assert!(
                !on_body.contains(forbidden),
                "WSL ON must never alter Windows: {forbidden}"
            );
        }
        let off_body = &source[end..source.find("#[cfg(windows)]\npub use native::").unwrap()];
        for forbidden in [
            "lifecycle::",
            "config::write_checked(",
            "wireguard_firewall_allow(",
        ] {
            assert!(
                !off_body.contains(forbidden),
                "WSL OFF must never alter Windows: {forbidden}"
            );
        }
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    #[test]
    fn no_linux_controller_activates_network() {
        assert_eq!(status(), Err("WINDOWS_ONLY"));
        assert_eq!(dns_setup(), Err("WINDOWS_ONLY"));
        assert_eq!(on(), Err("WINDOWS_ONLY"));
        assert_eq!(off(), Err("WINDOWS_ONLY"));
    }
}

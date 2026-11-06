//! U7 native WSL TUN operations. Rust CLI is the only lifecycle owner.
//! Ubuntu executes one-shot native ip/wg/resolvectl commands, never a daemon.
use serde_json::Value;
#[cfg(windows)]
use serde_json::json;

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
    fn native_check(c: &Value) -> Result<(), &'static str> {
        let dir = config::installed()
            .parent()
            .ok_or("CONFIG_PATH_INVALID")?
            .to_path_buf();
        config::protect_private_directory(&dir)?;
        let check = dir.join("sing-box.u7-check.json");
        let f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&check)
            .map_err(|_| "CONFIG_CHECK_CONFLICT")?;
        serde_json::to_writer(f, c).map_err(|_| "CONFIG_CHECK_WRITE_FAILED")?;
        let r = lifecycle::native_check(&check);
        let cleanup = fs::remove_file(&check);
        if cleanup.is_err() {
            return Err("WSL_SECRET_CHECK_CLEANUP_FAILED");
        }
        r
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
    fn active(s: &Value) -> bool {
        s["kernel_interface"] == true
            && s["route_active"] == true
            && s["dns_redirected"] == true
            && s["ipv6_guard"] == true
    }
    fn cleanup_previous() -> Result<(), &'static str> {
        let backup = Path::new(crate::ROOT)
            .join("config")
            .join("sing-box.previous.json");
        if backup.exists() {
            // Only remove a file which carries our validated transient layer.
            let raw = fs::read(&backup).map_err(|_| "WSL_SECRET_BACKUP_READ_FAILED")?;
            let c: Value = serde_json::from_slice(&raw).map_err(|_| "WSL_SECRET_BACKUP_UNOWNED")?;
            if wsl_tun::split(&c)?.1.is_some() {
                fs::remove_file(&backup).map_err(|_| "WSL_SECRET_BACKUP_CLEANUP_FAILED")?;
            }
        }
        Ok(())
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
        let pass = !expect_vm || ip == "64.176.74.102";
        Ok(json!({"ok":pass,"state":"ON","ip4":ip,
            "expected":if expect_vm {"64.176.74.102"}else{"WARP_EGRESS_UNSPECIFIED"},
            "reason_code":if pass {"WSL_NATIVE_IPV4_EGRESS_CONFIRMED"} else {"WSL_NATIVE_IP_MISMATCH"},
            "other_protocols":"NOT_TESTED",
            "next_action":"Verify DNS UDP IPv6 and independent Windows paths"}))
    }
    /// ON is idempotent. With an installed Windows endpoint, only Ubuntu
    /// kernel routes and DNS change. Initial Windows attachment is guarded.
    pub fn on() -> Result<Value, &'static str> {
        on_inner(false)
    }
    /// Explicit operator-approved reconnect of the existing MCP-over-TUN link.
    /// This must run in a detached instance of the same Rust CLI so that
    /// the operation and its rollback outlive a temporary MCP disconnect.
    pub fn on_allow_mcp_reconnect() -> Result<Value, &'static str> {
        on_inner(true)
    }
    fn on_inner(allow_mcp_reconnect: bool) -> Result<Value, &'static str> {
        let path = config::installed();
        let old = config::read(&path)?;
        let configured = wsl_tun::split(&old)?.1.is_some();
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
        let running = lifecycle::is_running()?;
        let network = wsl::discover_for_start()?.ok_or("WSL_GUEST_UNAVAILABLE")?;
        let interface = windows_binding(network.gateway)?;
        let guest_pub = guest_public()?;
        let windows_private = windows_private()?;
        let windows_pub = windows_public(&windows_private)?;
        let ip = network.guest.to_string();
        let peer = &old["endpoints"][0]["peers"][0];
        let native_if = if old["endpoints"][0]["listen_port"].is_number() {
            old["endpoints"][0]["bind_interface"].as_str()
        } else {
            old["outbounds"]
                .as_array()
                .and_then(|a| a.last())
                .and_then(|v| v["bind_interface"].as_str())
        };
        let needs_update = !configured
            || old["endpoints"][0]["listen_port"].as_u64()
                != Some(u64::from(wsl_tun::WINDOWS_WG_LISTEN_PORT))
            || peer["address"].as_str() != Some(ip.as_str())
            || peer["public_key"].as_str() != Some(guest_pub.as_str())
            || old["endpoints"][0]["private_key"].as_str() != Some(windows_private.as_str())
            || native_if != Some(interface.as_str());
        if !running && !needs_update {
            return Err("WSL_TUN_WINDOWS_NOT_RUNNING");
        }
        // Never silently restart a managed Windows TUN/control connection.
        if needs_update
            && running
            && crate::tun::status()?["managed_tun"] == true
            && !allow_mcp_reconnect
        {
            return Err("WSL_TUN_RESTART_CONTROL_NOT_VERIFIED");
        }
        let candidate = if needs_update {
            let base = if configured {
                wsl_tun::remove(&old)?
            } else {
                old.clone()
            };
            let next = wsl_tun::render(
                &base,
                &wsl_tun::Options {
                    guest_ip: network.guest,
                    wsl_interface: &interface,
                    windows_private_key: &windows_private,
                    guest_public_key: &guest_pub,
                },
            )?;
            native_check(&next)?;
            next
        } else {
            old.clone()
        };
        // Snapshot only the exact Rust-owned firewall rule, in memory.
        // A failed guest prepare must never leave a new Windows allowance.
        let firewall_before = wsl::wireguard_firewall_snapshot(&network, &interface)?;
        let mut modified_windows = false;
        let result = (|| -> Result<Value, &'static str> {
            // Prepare retains the native NAT default until handshake.
            // Both prepare and firewall application belong to this rollback.
            guest("prepare", Some(&windows_pub))?;
            wsl::wireguard_firewall_allow(&network, &interface)?;
            if needs_update {
                if running {
                    lifecycle::stop()?;
                }
                config::write_checked(&path, &candidate)?;
                modified_windows = true;
                lifecycle::start()?;
            }
            // Send an isolated peer packet before changing Ubuntu's default
            // route; a fresh kernel WG interface must initiate a handshake
            // even when Windows sing-box was already running for hours.
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
            let chosen = config::selected(&candidate, Target::Wsl)?;
            if chosen.tag().starts_with("direct-") && ip != "64.176.74.102" {
                return Err("WSL_TUN_EGRESS_NOT_VM");
            }
            let after = guest_state()?;
            if !active(&after) {
                return Err("WSL_TUN_GUEST_READBACK_FAILED");
            }
            Ok(json!({"ok":true,"changed":true,"state":"ON",
                "handshake":"PASS","public_ip4":ip,"route":chosen.tag(),
                "dns_ipv6_route_readback":"PASS",
                "udp_dns_independent_apps":"NOT_TESTED"}))
        })();
        match result {
            Ok(v) => Ok(v),
            Err(code) => {
                let guest_clean = guest("off", Some(&guest_pub)).is_ok();
                let firewall_restored =
                    wsl::wireguard_firewall_restore(&network, &interface, &firewall_before).is_ok();
                let windows_restored = if modified_windows {
                    lifecycle::stop().is_ok()
                        && config::write_checked(&path, &old).is_ok()
                        && (!running || lifecycle::start().is_ok())
                        && cleanup_previous().is_ok()
                } else if needs_update && running {
                    lifecycle::is_running().unwrap_or(false) || lifecycle::start().is_ok()
                } else {
                    true
                };
                if !guest_clean || !windows_restored || !firewall_restored {
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
pub use native::{diagnose, dns_setup, off, on, on_allow_mcp_reconnect, status};

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
#[cfg(not(windows))]
pub fn on_allow_mcp_reconnect() -> Result<Value, &'static str> {
    Err("WINDOWS_ONLY")
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

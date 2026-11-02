//! S4: Rust owns only desired toggle state. Native sing-box owns actual routes.
//! No TUN activation until Windows control independence and routing semantics are proven.
use crate::{
    config,
    model::{Diagnostic, Health},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

const SCHEMA: &str = "internet-tun-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    schema: String,
    pub managed_tun: bool,
    pub selected_apps: bool,
    pub applications: Vec<String>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            schema: SCHEMA.into(),
            managed_tun: false,
            selected_apps: false,
            applications: vec![],
        }
    }
}

pub fn path() -> PathBuf {
    Path::new(crate::ROOT).join("config").join("tun.json")
}

fn application(value: &str) -> Result<String, &'static str> {
    if value.is_empty()
        || value.len() > 260
        || value.trim() != value
        || value
            .chars()
            .any(|c| c.is_control() || "<>\"|?*".contains(c))
        || value.contains('/')
        || value.contains("..")
    {
        return Err("APPLICATION_PATH_INVALID");
    }
    let normalized = value.to_lowercase();
    let leaf = if normalized.contains('\\') {
        let b = normalized.as_bytes();
        if b.len() < 6
            || !b[0].is_ascii_alphabetic()
            || b[1] != b':'
            || b[2] != b'\\'
            || normalized.split('\\').skip(1).any(str::is_empty)
        {
            return Err("APPLICATION_PATH_INVALID");
        }
        normalized.rsplit('\\').next().unwrap_or("")
    } else {
        if !normalized
            .chars()
            .all(|c| c.is_alphanumeric() || "._-".contains(c))
        {
            return Err("APPLICATION_NAME_INVALID");
        }
        normalized.as_str()
    };
    if leaf.len() < 5 || !leaf.ends_with(".exe") || leaf.starts_with('.') {
        return Err("APPLICATION_NAME_INVALID");
    }
    if [
        "internet.exe",
        "sing-box.exe",
        "tunnel-client-runtime.exe",
        "cloudflared.exe",
        "pwsh.exe",
        "powershell.exe",
        "ssh.exe",
        "wsl.exe",
    ]
    .contains(&leaf)
    {
        return Err("APPLICATION_CONTROL_PROCESS_FORBIDDEN");
    }
    Ok(normalized)
}

fn validate(s: &Settings) -> Result<(), &'static str> {
    if s.schema != SCHEMA {
        return Err("TUN_STATE_SCHEMA_INVALID");
    }
    if s.applications.len() > 32 {
        return Err("APPLICATION_LIST_TOO_LARGE");
    }
    let mut unique = std::collections::HashSet::new();
    for item in &s.applications {
        let canonical = application(item)?;
        if canonical != *item || !unique.insert(canonical) {
            return Err("APPLICATION_LIST_INVALID");
        }
    }
    if s.selected_apps && s.applications.is_empty() {
        return Err("SELECTED_APPS_EMPTY");
    }
    Ok(())
}

pub fn read_at(path: &Path) -> Result<Settings, &'static str> {
    let previous = path.with_extension("previous.json");
    let incoming = path.with_extension("incoming.json");
    if previous.exists() || incoming.exists() {
        return Err("TUN_STATE_INTERRUPTED");
    }
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Settings::default()),
        Err(_) => return Err("TUN_STATE_READ_FAILED"),
        Ok(meta) if !meta.is_file() || meta.file_type().is_symlink() => {
            return Err("TUN_STATE_NOT_REGULAR_FILE");
        }
        Ok(_) => {}
    }
    let bytes = fs::read(path).map_err(|_| "TUN_STATE_READ_FAILED")?;
    let settings: Settings =
        serde_json::from_slice(&bytes).map_err(|_| "TUN_STATE_JSON_INVALID")?;
    validate(&settings)?;
    Ok(settings)
}

fn write_at(path: &Path, state: &Settings) -> Result<(), &'static str> {
    validate(state)?;
    let dir = path.parent().ok_or("TUN_STATE_PATH_INVALID")?;
    let incoming = path.with_extension("incoming.json");
    let previous = path.with_extension("previous.json");
    if incoming.exists() || previous.exists() {
        return Err("TUN_STATE_INTERRUPTED");
    }
    let bytes = serde_json::to_vec_pretty(state).map_err(|_| "TUN_STATE_SERIALIZE_FAILED")?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&incoming)
        .map_err(|_| "TUN_STATE_WRITE_CONFLICT")?;
    if file
        .write_all(&bytes)
        .and_then(|_| file.sync_all())
        .is_err()
    {
        return Err("TUN_STATE_WRITE_FAILED");
    }
    drop(file);
    let had_previous = path.exists();
    if had_previous {
        fs::rename(path, &previous).map_err(|_| "TUN_STATE_BACKUP_FAILED")?;
    }
    if fs::rename(&incoming, path).is_err() {
        if had_previous {
            let _ = fs::rename(&previous, path);
        }
        return Err("TUN_STATE_REPLACE_FAILED");
    }
    if had_previous {
        fs::remove_file(&previous).map_err(|_| "TUN_STATE_CLEANUP_REQUIRED")?;
    }
    if read_at(path)? != *state {
        return Err("TUN_STATE_READBACK_MISMATCH");
    }
    // Reusing the managed config directory is intentional: no second owner or secret vault.
    let _ = dir;
    Ok(())
}

/// Validate a transported settings snapshot but never activate TUN during restore.
/// The original desired TUN state remains in the exported backup for the operator.
pub fn validate_backup(saved: &Settings) -> Result<(), &'static str> {
    validate(saved)
}

pub fn restore_inactive_at(path: &Path, saved: &Settings) -> Result<Settings, &'static str> {
    validate(saved)?;
    let mut safe = saved.clone();
    safe.managed_tun = false;
    write_at(path, &safe)?;
    if read_at(path)? != safe {
        return Err("RESTORE_TUN_READBACK_FAILED");
    }
    Ok(safe)
}

#[derive(Clone, Copy)]
pub enum Switch {
    ManagedTun,
    SelectedApps,
}

pub fn validate_native(c: &Value, on: bool) -> Result<(), &'static str> {
    let inb = c["inbounds"].as_array().ok_or("TUN_INBOUND_INVALID")?;
    let out = c["outbounds"].as_array().ok_or("TUN_OUTBOUND_INVALID")?;
    let rules = c
        .pointer("/route/rules")
        .and_then(Value::as_array)
        .ok_or("TUN_RULE_INVALID")?;
    if !on {
        if c.pointer("/route/auto_detect_interface").is_some()
            || inb.iter().any(|x| x["type"] == "tun")
            || out.iter().any(|x| x["tag"] == "s4-native-direct")
        {
            return Err("TUN_UNOWNED_NATIVE_OBJECT");
        }
        return Ok(());
    }
    let t = &inb[2];
    let mut shape = t.as_object().ok_or("TUN_INBOUND_UNSAFE")?.clone();
    let addresses = shape
        .remove("route_exclude_address")
        .ok_or("TUN_CONTROL_EXCLUSION_MISSING")?;
    if Value::Object(shape)
        != json!({"type":"tun","tag":"windows-tun",
        "interface_name":"internet-tun","address":["172.29.241.1/30"],
        "mtu":1500,"dns_mode":"disabled","auto_route":true})
    {
        return Err("TUN_INBOUND_UNSAFE");
    }
    let addresses = addresses
        .as_array()
        .ok_or("TUN_CONTROL_EXCLUSION_INVALID")?;
    if addresses.len() < 2 || addresses.len() > 9 {
        return Err("TUN_CONTROL_EXCLUSION_INVALID");
    }
    let vm = c["outbounds"][0]["server"]
        .as_str()
        .ok_or("TUN_VM_UNAVAILABLE")?;
    if !addresses.contains(&json!(format!("{vm}/32"))) {
        return Err("TUN_VM_EXCLUSION_MISSING");
    }
    let mut uniq = std::collections::HashSet::new();
    for value in addresses {
        let ip: Ipv4Addr = value
            .as_str()
            .and_then(|s| s.strip_suffix("/32"))
            .ok_or("TUN_CONTROL_EXCLUSION_INVALID")?
            .parse()
            .map_err(|_| "TUN_CONTROL_EXCLUSION_INVALID")?;
        if ip.is_private()
            || ip.is_loopback()
            || ip.is_unspecified()
            || ip.is_link_local()
            || !uniq.insert(ip)
        {
            return Err("TUN_CONTROL_EXCLUSION_INVALID");
        }
    }
    if c.pointer("/route/auto_detect_interface") != Some(&Value::Bool(true))
        || out[8] != json!({"type":"direct","tag":"s4-native-direct"})
    {
        return Err("TUN_ROUTE_UNSAFE");
    }
    if rules.len() == 3 {
        if rules[2] != json!({"inbound":["windows-tun"],"outbound":"desktop-selector"}) {
            return Err("TUN_ROUTE_UNSAFE");
        }
    } else {
        if rules[3] != json!({"inbound":["windows-tun"],"outbound":"s4-native-direct"})
            || rules[2]["inbound"] != json!(["windows-tun"])
            || rules[2]["outbound"] != "desktop-selector"
            || rules[2].as_object().is_none_or(|o| o.len() != 3)
        {
            return Err("TUN_ROUTE_UNSAFE");
        }
        let names = rules[2]["process_name"]
            .as_array()
            .ok_or("TUN_PROCESS_RULE_INVALID")?;
        if names.is_empty() || names.len() > 32 {
            return Err("TUN_PROCESS_RULE_INVALID");
        }
        for v in names {
            let name = v.as_str().ok_or("TUN_PROCESS_RULE_INVALID")?;
            if application(name)? != name {
                return Err("TUN_PROCESS_RULE_INVALID");
            }
        }
    }
    Ok(())
}

pub fn render_native(
    original: &Value,
    selected: &Settings,
    control: &[Ipv4Addr],
) -> Result<Value, &'static str> {
    validate(selected)?;
    config::validate(original)?;
    let mut c = original.clone();
    if c["inbounds"].as_array().is_some_and(|a| a.len() == 3) {
        c["inbounds"].as_array_mut().unwrap().pop();
        c["outbounds"].as_array_mut().unwrap().pop();
        c.pointer_mut("/route/rules")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .truncate(2);
        c["route"]
            .as_object_mut()
            .unwrap()
            .remove("auto_detect_interface");
    }
    if !selected.managed_tun {
        config::validate(&c)?;
        return Ok(c);
    }
    if selected.selected_apps && selected.applications.iter().any(|v| v.contains('\\')) {
        return Err("TUN_PROCESS_PATH_UNSUPPORTED");
    }
    if control.is_empty() || control.len() > 8 {
        return Err("TUN_CONTROL_NOT_CONNECTED");
    }
    let vm: Ipv4Addr = c["outbounds"][0]["server"]
        .as_str()
        .ok_or("TUN_VM_UNAVAILABLE")?
        .parse()
        .map_err(|_| "TUN_VM_UNAVAILABLE")?;
    let mut exclusions = vec![vm];
    for ip in control {
        if ip.is_private() || ip.is_loopback() || ip.is_unspecified() || ip.is_link_local() {
            return Err("TUN_CONTROL_IP_UNSAFE");
        }
        if !exclusions.contains(ip) {
            exclusions.push(*ip)
        }
    }
    if exclusions.len() < 2 {
        return Err("TUN_CONTROL_NOT_INDEPENDENT");
    }
    let cidrs: Vec<String> = exclusions.iter().map(|ip| format!("{ip}/32")).collect();
    c["inbounds"].as_array_mut().unwrap().push(json!({
        "type":"tun","tag":"windows-tun","interface_name":"internet-tun",
        "address":["172.29.241.1/30"],"mtu":1500,
        "dns_mode":"disabled","auto_route":true,"route_exclude_address":cidrs}));
    c["outbounds"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type":"direct","tag":"s4-native-direct"}));
    c["route"]["auto_detect_interface"] = Value::Bool(true);
    let rules = c
        .pointer_mut("/route/rules")
        .unwrap()
        .as_array_mut()
        .unwrap();
    if selected.selected_apps {
        rules.push(json!({"inbound":["windows-tun"],
            "process_name":selected.applications,"outbound":"desktop-selector"}));
        rules.push(json!({"inbound":["windows-tun"],"outbound":"s4-native-direct"}));
    } else {
        rules.push(json!({"inbound":["windows-tun"],"outbound":"desktop-selector"}));
    }
    config::validate(&c)?;
    Ok(c)
}

pub fn toggle_state(
    current: &Settings,
    switch: Switch,
    enable: bool,
) -> Result<Settings, &'static str> {
    validate(current)?;
    let mut next = current.clone();
    match switch {
        Switch::ManagedTun => next.managed_tun = enable,
        Switch::SelectedApps => next.selected_apps = enable,
    }
    validate(&next)?;
    Ok(next)
}

pub fn list_change(current: &Settings, add: bool, name: &str) -> Result<Settings, &'static str> {
    validate(current)?;
    let name = application(name)?;
    let mut next = current.clone();
    if add {
        if next.applications.contains(&name) {
            return Ok(next);
        }
        if next.applications.len() >= 32 {
            return Err("APPLICATION_LIST_TOO_LARGE");
        }
        next.applications.push(name);
        next.applications.sort();
    } else {
        next.applications.retain(|a| a != &name);
        if next.selected_apps && next.applications.is_empty() {
            return Err("SELECTED_APPS_EMPTY");
        }
    }
    validate(&next)?;
    Ok(next)
}

#[cfg(windows)]
fn control_endpoints() -> Result<Vec<Ipv4Addr>, &'static str> {
    let script = r#"$p=@(Get-CimInstance Win32_Process -Filter "Name='tunnel-client-runtime.exe'" | Where-Object {$_.ExecutablePath -like '*\WindowsAdminMCP\client\tunnel-client-runtime.exe'}); if($p.Count -ne 1){exit 5}; @(Get-NetTCPConnection -State Established -ErrorAction Stop | Where-Object {$_.OwningProcess -eq $p[0].ProcessId} | Select-Object -ExpandProperty RemoteAddress -Unique)"#;
    let out = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|_| "TUN_CONTROL_QUERY_FAILED")?;
    if !out.status.success() {
        return Err("TUN_CONTROL_NOT_CONNECTED");
    }
    let text = String::from_utf8(out.stdout).map_err(|_| "TUN_CONTROL_QUERY_FAILED")?;
    let mut ips = Vec::new();
    for line in text.lines() {
        let ip: Ipv4Addr = line.trim().parse().map_err(|_| "TUN_CONTROL_IP_UNSAFE")?;
        if ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() {
            return Err("TUN_CONTROL_IP_UNSAFE");
        }
        if !ips.contains(&ip) {
            ips.push(ip)
        }
    }
    if ips.is_empty() || ips.len() > 8 {
        return Err("TUN_CONTROL_NOT_CONNECTED");
    }
    Ok(ips)
}
#[cfg(not(windows))]
fn control_endpoints() -> Result<Vec<Ipv4Addr>, &'static str> {
    Err("WINDOWS_ONLY")
}

#[cfg(windows)]
fn adapter_up() -> Result<bool, &'static str> {
    let cmd = "(@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {$_.Name -eq 'internet-tun' -and $_.Status -eq 'Up'}).Count)";
    let out = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", cmd])
        .output()
        .map_err(|_| "TUN_ADAPTER_READBACK_UNKNOWN")?;
    if !out.status.success() {
        return Err("TUN_ADAPTER_READBACK_UNKNOWN");
    }
    match String::from_utf8_lossy(&out.stdout).trim() {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err("TUN_ADAPTER_READBACK_UNKNOWN"),
    }
}
#[cfg(not(windows))]
fn adapter_up() -> Result<bool, &'static str> {
    Err("WINDOWS_ONLY")
}

fn candidate_check(c: &Value) -> Result<(), &'static str> {
    let file = config::installed().with_file_name("s4-native.check.json");
    if file.exists() {
        return Err("TUN_CHECK_CONFLICT");
    }
    let bytes = serde_json::to_vec(c).map_err(|_| "TUN_SERIALIZE_FAILED")?;
    let outcome = (|| {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&file)
            .map_err(|_| "TUN_CHECK_CONFLICT")?;
        f.write_all(&bytes)
            .and_then(|_| f.sync_all())
            .map_err(|_| "TUN_CHECK_WRITE_FAILED")?;
        drop(f);
        crate::lifecycle::native_check(&file)
    })();
    let _ = fs::remove_file(file);
    outcome
}
fn verify_native(enabled: bool) -> Result<(), &'static str> {
    if !crate::lifecycle::is_running()? {
        return Err("TUN_TASK_NOT_RUNNING");
    }
    crate::selector::runtime_selected(crate::model::Target::Desktop)?;
    crate::selector::runtime_selected(crate::model::Target::Wsl)?;
    if adapter_up()? != enabled {
        return Err("TUN_ADAPTER_READBACK_MISMATCH");
    }
    Ok(())
}
pub fn command(switch: Switch, enable: bool) -> Result<Value, &'static str> {
    if !cfg!(windows) {
        return Err("WINDOWS_ONLY");
    }
    let current = read_at(&path())?;
    let next = toggle_state(&current, switch, enable)?;
    persist(&path(), &current, &next)
}
pub fn change_application(add: bool, name: &str) -> Result<Value, &'static str> {
    if !cfg!(windows) {
        return Err("WINDOWS_ONLY");
    }
    let current = read_at(&path())?;
    let next = list_change(&current, add, name)?;
    persist(&path(), &current, &next)
}
fn persist(path: &Path, old: &Settings, next: &Settings) -> Result<Value, &'static str> {
    let current = config::read(&config::installed())?;
    let configured = current["inbounds"].as_array().is_some_and(|v| v.len() == 3);
    // A crash after native apply but before state persistence must not trap
    // Windows in a TUN that "tun off" refuses to remove.
    let recovering = configured != old.managed_tun;
    if recovering && next.managed_tun {
        return Err("TUN_DESIRED_NATIVE_DRIFT");
    }
    if old == next && !recovering {
        return Ok(
            json!({"ok":true,"changed":false,"managed_tun":old.managed_tun,
            "selected_apps":old.selected_apps,"applications":old.applications,
            "native_adapter_up":adapter_up()?,
            "next_action":"internet tun status"}),
        );
    }
    let needs_restart = configured || old.managed_tun || next.managed_tun;
    if !needs_restart {
        config::protect_private_directory(path.parent().ok_or("TUN_STATE_PATH_INVALID")?)?;
        write_at(path, next)?;
    } else {
        if !crate::lifecycle::is_running()? {
            return Err("TUN_TASK_NOT_RUNNING");
        }
        let ips = if next.managed_tun {
            control_endpoints()?
        } else {
            vec![]
        };
        let updated = render_native(&current, next, &ips)?;
        candidate_check(&updated)?;
        if updated != current {
            if crate::lifecycle::stop().is_err() {
                let _ = crate::lifecycle::start();
                return Err("TUN_STOP_UNCONFIRMED");
            }
            let outcome = (|| {
                config::write_checked(&config::installed(), &updated)?;
                crate::lifecycle::start()?;
                verify_native(next.managed_tun)
            })();
            if outcome.is_err() {
                let rollback = config::write_checked(&config::installed(), &current)
                    .and_then(|_| crate::lifecycle::restart())
                    .and_then(|_| verify_native(configured));
                return Err(if rollback.is_ok() {
                    "TUN_APPLY_ROLLED_BACK"
                } else {
                    "TUN_ROLLBACK_UNCONFIRMED"
                });
            }
        } else {
            verify_native(next.managed_tun)?;
        }
        if write_at(path, next).is_err() {
            let rollback = config::write_checked(&config::installed(), &current)
                .and_then(|_| crate::lifecycle::restart())
                .and_then(|_| verify_native(configured));
            return Err(if rollback.is_ok() {
                "TUN_STATE_WRITE_ROLLED_BACK"
            } else {
                "TUN_ROLLBACK_UNCONFIRMED"
            });
        }
    }
    Ok(
        json!({"ok":true,"changed":true,"managed_tun":next.managed_tun,
        "selected_apps":next.selected_apps,"applications":next.applications,
        "runtime_confirmed":needs_restart,
        "recovered_from_interrupted_apply":recovering,
        "unselected_egress":"native_direct_not_kernel_bypass",
        "next_action":"internet diagnose windows/tun"}),
    )
}

pub fn status() -> Result<Value, &'static str> {
    if !cfg!(windows) {
        return Err("WINDOWS_ONLY");
    }
    let s = read_at(&path())?;
    let native = config::read(&config::installed())?;
    let configured = native["inbounds"].as_array().is_some_and(|a| a.len() == 3);
    let up = adapter_up()?;
    Ok(
        json!({"managed_tun":s.managed_tun,"selected_apps":s.selected_apps,
        "applications":s.applications,"native_tun_configured":configured,
        "native_tun_up":up,"desired_native_match":s.managed_tun==configured,
        "kernel_bypass_for_unselected":"UNSUPPORTED",
        "unselected_egress":"native DIRECT when selected-apps on",
        "physical_egress":"NOT_TESTED_BY_STATUS"}),
    )
}

pub fn inspect(id: &str) -> Diagnostic {
    let mut d = Diagnostic::unknown(
        id,
        "switch",
        "Rust INTERNET / sing-box",
        "internet tun status",
    );
    d.parent = Some("windows/sing-box");
    d.dependencies = vec!["windows/sing-box"];
    d.source = "config/tun.json, native sing-box.json, Windows adapter readback";
    d.scope = "desired_and_native_state_only";
    if !cfg!(windows) {
        return d;
    }
    match status() {
        Ok(v) => {
            d.observed_at = Some(chrono::Utc::now().to_rfc3339());
            d.expected = Some("desired/native config and actual adapter agree".into());
            d.actual = Some(format!(
                "tun={};configured={};up={};selected_apps={};count={}",
                v["managed_tun"],
                v["native_tun_configured"],
                v["native_tun_up"],
                v["selected_apps"],
                v["applications"].as_array().map_or(0, Vec::len)
            ));
            let good = v["desired_native_match"] == true && v["managed_tun"] == v["native_tun_up"];
            d.health = if good {
                Health::Healthy
            } else {
                Health::Failed
            };
            d.reason_code = if good {
                "TUN_NATIVE_STATE_CONFIRMED"
            } else {
                "TUN_NATIVE_STATE_MISMATCH"
            };
            d.next_action = if good {
                "internet tun status"
            } else {
                "internet diagnose windows/tun"
            };
        }
        Err(code) => {
            d.health = Health::Unknown;
            d.reason_code = match code {
                "TUN_STATE_INTERRUPTED" => "TUN_STATE_INTERRUPTED",
                "TUN_STATE_JSON_INVALID" | "TUN_STATE_SCHEMA_INVALID" => "TUN_STATE_INVALID",
                _ => "TUN_READBACK_UNKNOWN",
            };
            d.next_action = "internet tun status";
        }
    }
    d
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn two_switches_are_independent_and_inert_list_does_not_start_tun() {
        let s = Settings::default();
        let s = list_change(&s, true, "Firefox.EXE").unwrap();
        let s = toggle_state(&s, Switch::SelectedApps, true).unwrap();
        assert!(s.selected_apps);
        assert!(!s.managed_tun);
        assert_eq!(s.applications, ["firefox.exe"]);
        assert!(
            toggle_state(&s, Switch::ManagedTun, true)
                .unwrap()
                .managed_tun
        );
        let s = toggle_state(&s, Switch::SelectedApps, false).unwrap();
        assert!(!s.selected_apps);
        assert_eq!(s.applications, ["firefox.exe"]);
    }
    #[test]
    fn toggles_only_change_desired_state_without_native_mutation() {
        let s = Settings::default();
        assert!(
            toggle_state(&s, Switch::ManagedTun, true)
                .unwrap()
                .managed_tun
        );
        assert_eq!(toggle_state(&s, Switch::ManagedTun, false).unwrap(), s);
    }
    #[test]
    fn app_names_paths_protected_processes_and_empty_list() {
        let s = Settings::default();
        assert_eq!(
            toggle_state(&s, Switch::SelectedApps, true).unwrap_err(),
            "SELECTED_APPS_EMPTY"
        );
        for v in [
            "",
            "foo",
            "../firefox.exe",
            "foo/bar.exe",
            r"C:\a\..\x.exe",
            "a*.exe",
        ] {
            assert!(list_change(&s, true, v).is_err(), "{v}");
        }
        for v in [
            "internet.exe",
            "tunnel-client-runtime.exe",
            r"C:\bin\sing-box.exe",
        ] {
            assert_eq!(
                list_change(&s, true, v).unwrap_err(),
                "APPLICATION_CONTROL_PROCESS_FORBIDDEN"
            );
        }
        let s = list_change(&s, true, r"C:\Program Files\Mozilla Firefox\firefox.exe").unwrap();
        assert_eq!(
            s.applications,
            [r"c:\program files\mozilla firefox\firefox.exe"]
        );
        let s2 = list_change(&s, true, r"C:\Program Files\Mozilla Firefox\firefox.exe").unwrap();
        assert_eq!(s, s2);
    }

    #[test]
    fn saved_state_is_atomic_and_invalid_or_interrupted_data_is_not_assumed_off() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("internet-s4-{}-{suffix}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("tun.json");
        assert_eq!(read_at(&file).unwrap(), Settings::default());
        let s = list_change(&Settings::default(), true, "firefox.exe").unwrap();
        write_at(&file, &s).unwrap();
        assert_eq!(read_at(&file).unwrap(), s);
        let mut changed = s.clone();
        changed.selected_apps = true;
        write_at(&file, &changed).unwrap();
        assert_eq!(read_at(&file).unwrap(), changed);
        std::fs::write(&file, b"{bad json").unwrap();
        assert_eq!(read_at(&file).unwrap_err(), "TUN_STATE_JSON_INVALID");
        let marker = file.with_extension("incoming.json");
        std::fs::write(&marker, b"partial").unwrap();
        assert_eq!(read_at(&file).unwrap_err(), "TUN_STATE_INTERRUPTED");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn empty_last_entry_and_interrupted_state_fail_closed() {
        let s = list_change(&Settings::default(), true, "firefox.exe").unwrap();
        let s = toggle_state(&s, Switch::SelectedApps, true).unwrap();
        assert_eq!(
            list_change(&s, false, "firefox.exe").unwrap_err(),
            "SELECTED_APPS_EMPTY"
        );
        let mut wrong = s;
        wrong.schema = "v2".into();
        assert_eq!(validate(&wrong), Err("TUN_STATE_SCHEMA_INVALID"));
    }
}

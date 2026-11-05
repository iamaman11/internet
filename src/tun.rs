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
const HOT_TAG: &str = "internet-selected-apps";
const HOT_PATH: &str = r"C:\internet\config\selected-apps.rules.json";

fn rules_path() -> PathBuf {
    Path::new(crate::ROOT)
        .join("config")
        .join("selected-apps.rules.json")
}
// Windows process lookup preserves the casing of QueryFullProcessImageNameW.
// Application identity is case-folded for stable Windows comparisons, so the
// native process_path rule (case-sensitive) cannot match the stored string.
// Use an anchored Go/RE2 path regexp with the native case-insensitive modifier.
fn native_path_pattern(path: &str) -> String {
    let mut result = String::from("(?i)^");
    for ch in path.chars() {
        if r"\\.+*?()[]{}^$|".contains(ch) {
            result.push('\\');
        }
        result.push(ch);
    }
    result.push('$');
    result
}
fn rules_source(state: &Settings) -> Value {
    let mut names = Vec::new();
    let mut paths = Vec::new();
    for app in &state.applications {
        if app.contains('\\') {
            paths.push(native_path_pattern(app));
        } else {
            names.push(app.as_str());
        }
    }
    let mut rules = Vec::new();
    if !names.is_empty() {
        rules.push(json!({"process_name":names}));
    }
    if !paths.is_empty() {
        rules.push(json!({"process_path_regex":paths}));
    }
    json!({"version":3,"rules":rules})
}
fn hot_native(c: &Value) -> bool {
    c.pointer("/route/rules/2/rule_set") == Some(&json!([HOT_TAG]))
}
fn hot_readback(state: &Settings) -> Result<(), &'static str> {
    let raw = fs::read(rules_path()).map_err(|_| "HOT_RULESET_NOT_FOUND")?;
    let disk: Value = serde_json::from_slice(&raw).map_err(|_| "HOT_RULESET_INVALID")?;
    if disk != rules_source(state) {
        return Err("HOT_RULESET_DRIFT");
    }
    Ok(())
}
fn write_hot_rules(state: &Settings) -> Result<(), &'static str> {
    validate(state)?;
    let path = rules_path();
    let dir = path.parent().ok_or("HOT_RULESET_PATH_INVALID")?;
    config::protect_private_directory(dir)?;
    if fs::symlink_metadata(&path).is_ok_and(|x| !x.is_file() || x.file_type().is_symlink()) {
        return Err("HOT_RULESET_UNOWNED_FILE");
    }
    let pending = path.with_extension("incoming.json");
    if pending.exists() {
        return Err("HOT_RULESET_INTERRUPTED");
    }
    let bytes = serde_json::to_vec_pretty(&rules_source(state))
        .map_err(|_| "HOT_RULESET_SERIALIZE_FAILED")?;
    let result = (|| -> Result<(), &'static str> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pending)
            .map_err(|_| "HOT_RULESET_CONFLICT")?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| "HOT_RULESET_WRITE_FAILED")?;
        drop(file);
        fs::rename(&pending, &path).map_err(|_| "HOT_RULESET_REPLACE_FAILED")?;
        hot_readback(state)
    })();
    let _ = fs::remove_file(pending);
    result
}

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

/// Operator profiles are projections of the two existing saved switches.
/// No additional mode state is stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowsMode {
    Normal,
    Selected,
    All,
}
impl WindowsMode {
    pub fn parse(raw: &str) -> Result<Self, &'static str> {
        match raw {
            "normal" => Ok(Self::Normal),
            "selected" => Ok(Self::Selected),
            "all" => Ok(Self::All),
            _ => Err("WINDOWS_MODE_INVALID"),
        }
    }
}
pub fn mode_transition(old: &Settings, mode: WindowsMode) -> Result<Settings, &'static str> {
    validate(old)?;
    let mut next = old.clone();
    match mode {
        WindowsMode::Normal => next.managed_tun = false,
        WindowsMode::Selected => {
            next.managed_tun = true;
            next.selected_apps = true;
        }
        WindowsMode::All => {
            next.managed_tun = true;
            next.selected_apps = false;
        }
    }
    validate(&next)?;
    Ok(next)
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
            || c.pointer("/route/rule_set").is_some()
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
    if addresses.is_empty() || addresses.len() > 9 {
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
        if c.pointer("/route/rule_set").is_some()
            || rules[2] != json!({"inbound":["windows-tun"],"outbound":"desktop-selector"})
        {
            return Err("TUN_ROUTE_UNSAFE");
        }
    } else {
        if hot_native(c) {
            if c["route"]["rule_set"]
                != json!([{"type":"local","tag":HOT_TAG,
                "format":"source","path":HOT_PATH}])
                || rules[2]
                    != json!({"inbound":["windows-tun"],
                    "rule_set":[HOT_TAG],"outbound":"desktop-selector"})
                || rules[3] != json!({"inbound":["windows-tun"],"outbound":"s4-native-direct"})
            {
                return Err("TUN_HOT_RULESET_INVALID");
            }
            return Ok(());
        }
        if c.pointer("/route/rule_set").is_some() {
            return Err("TUN_HOT_RULESET_UNOWNED");
        }
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
    // A native Windows TUN mode change must preserve the independent WSL WG ingress.
    let (base, wsl_layer) = crate::wsl_tun::split(original)?;
    let mut c = base;
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
        c["route"].as_object_mut().unwrap().remove("rule_set");
    }
    if !selected.managed_tun {
        let merged = crate::wsl_tun::attach(&c, wsl_layer.as_ref())?;
        config::validate(&merged)?;
        return Ok(merged);
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
            "rule_set":[HOT_TAG],"outbound":"desktop-selector"}));
        rules.push(json!({"inbound":["windows-tun"],"outbound":"s4-native-direct"}));
        c["route"]["rule_set"] = json!([{"type":"local","tag":HOT_TAG,
            "format":"source","path":HOT_PATH}]);
    } else {
        rules.push(json!({"inbound":["windows-tun"],"outbound":"desktop-selector"}));
    }
    let merged = crate::wsl_tun::attach(&c, wsl_layer.as_ref())?;
    config::validate(&merged)?;
    Ok(merged)
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
    }
    validate(&next)?;
    Ok(next)
}

/// No per-application registry: full paths are exact; short EXE names
/// resolve only against the Windows process table. Never guess a path.
fn executable_leaf(value: &str) -> &str {
    value.rsplit('\\').next().unwrap_or(value)
}
fn running_paths(name: &str) -> Result<Vec<String>, &'static str> {
    if !cfg!(windows) {
        return Err("WINDOWS_ONLY");
    }
    let validated = application(name)?;
    if validated.contains('\\') {
        return Err("APP_NAME_EXPECTED");
    }
    let script = format!(
        r#"[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $ErrorActionPreference='Stop'; @(Get-CimInstance Win32_Process -Filter "Name='{validated}'" | Where-Object {{ $_.ExecutablePath }} | Select-Object -ExpandProperty ExecutablePath -Unique) | ForEach-Object {{ [Console]::WriteLine($_) }}"#
    );
    let result = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|_| "APP_PROCESS_QUERY_FAILED")?;
    if !result.status.success() {
        return Err("APP_PROCESS_QUERY_FAILED");
    }
    let text = String::from_utf8(result.stdout).map_err(|_| "APP_PROCESS_QUERY_FAILED")?;
    let mut paths = Vec::new();
    for line in text.lines().map(str::trim).filter(|s| !s.is_empty()) {
        let path = application(line)?;
        if !path.contains('\\') || executable_leaf(&path) != validated {
            return Err("APP_PROCESS_PATH_UNTRUSTED");
        }
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}
/// Native Windows process inventory on demand, without scanning installed
/// software or maintaining a second application registry.
pub fn running_apps() -> Result<Value, &'static str> {
    if !cfg!(windows) {
        return Err("WINDOWS_ONLY");
    }
    let script = r#"[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $ErrorActionPreference='Stop'; Get-CimInstance Win32_Process | Where-Object {$_.ExecutablePath} | Select-Object -ExpandProperty ExecutablePath -Unique | ForEach-Object {[Console]::WriteLine($_)}"#;
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|_| "APP_PROCESS_QUERY_FAILED")?;
    if !output.status.success() || output.stdout.len() > 512 * 1024 {
        return Err("APP_PROCESS_QUERY_FAILED");
    }
    let raw = String::from_utf8(output.stdout).map_err(|_| "APP_PROCESS_QUERY_FAILED")?;
    let mut paths = Vec::new();
    for raw_path in raw.lines().map(str::trim).filter(|s| !s.is_empty()) {
        if let Ok(path) = application(raw_path)
            && path.contains('\\')
            && !paths.contains(&path)
        {
            paths.push(path);
        }
    }
    paths.sort();
    let truncated = paths.len() > 128;
    paths.truncate(128);
    Ok(json!({"ok":true,"source":"windows_process_executable_path",
        "paths":paths,"truncated":truncated,
        "next_action":"internet app <exact-path> vm|direct"}))
}
fn resolve_application(
    raw: &str,
    old: &Settings,
    for_vm: bool,
    observed: Option<&[String]>,
) -> Result<(String, &'static str), &'static str> {
    let name = application(raw)?;
    if name.contains('\\') {
        if for_vm && !Path::new(raw).is_file() {
            return Err("APP_EXECUTABLE_NOT_FOUND");
        }
        return Ok((name, "EXPLICIT_EXACT_PATH"));
    }
    let running = match observed {
        Some(paths) => paths.to_vec(),
        None => running_paths(&name)?,
    };
    let mut unique = Vec::new();
    for candidate in running {
        let path = application(&candidate)?;
        if !path.contains('\\') || executable_leaf(&path) != name {
            return Err("APP_PROCESS_PATH_UNTRUSTED");
        }
        if !unique.contains(&path) {
            unique.push(path);
        }
    }
    if unique.len() > 1 {
        return Err("APP_EXECUTABLE_AMBIGUOUS_USE_PATH");
    }
    if let Some(path) = unique.pop() {
        if for_vm && observed.is_none() && !Path::new(&path).is_file() {
            return Err("APP_EXECUTABLE_NOT_FOUND");
        }
        return Ok((path, "RUNNING_PROCESS_EXACT_PATH"));
    }
    if for_vm {
        return Err("APP_NOT_RUNNING_USE_FULL_PATH");
    }
    let stored: Vec<_> = old
        .applications
        .iter()
        .filter(|s| executable_leaf(s) == name)
        .cloned()
        .collect();
    if stored.len() > 1 {
        return Err("APP_EXECUTABLE_AMBIGUOUS_USE_PATH");
    }
    match stored.into_iter().next() {
        Some(value) => Ok((value, "SAVED_STATE_NOT_RUNNING")),
        None => Err("APP_NOT_RUNNING_USE_FULL_PATH"),
    }
}
fn app_transition(old: &Settings, vm: bool, target: &str) -> Result<Settings, &'static str> {
    validate(old)?;
    if old.managed_tun && !old.selected_apps && !vm {
        return Err("APP_DIRECT_REQUIRES_SELECTED_APPS");
    }
    let mut next = old.clone();
    let leaf = executable_leaf(target);
    next.applications.retain(|a| a != target && a != leaf);
    if vm {
        if next.applications.len() >= 32 {
            return Err("APPLICATION_LIST_TOO_LARGE");
        }
        next.applications.push(target.to_owned());
        next.applications.sort();
    }
    validate(&next)?;
    Ok(next)
}
pub fn app_set(raw: &str, vm: bool) -> Result<Value, &'static str> {
    if !cfg!(windows) {
        return Err("WINDOWS_ONLY");
    }
    let old = read_at(&path())?;
    if old.managed_tun && !old.selected_apps && !vm {
        return Err("APP_DIRECT_REQUIRES_SELECTED_APPS");
    }
    let (exact, source) = resolve_application(raw, &old, vm, None)?;
    let next = app_transition(&old, vm, &exact)?;
    let mut result = persist(&path(), &old, &next, None)?;
    result["application"] = json!(exact);
    result["identity_source"] = json!(source);
    result["desired_route"] = json!(if vm { "VM" } else { "DIRECT" });
    result["scope"] = json!(if !next.managed_tun {
        "SAVED_INACTIVE"
    } else if !next.selected_apps {
        "ALL_APPLICATIONS_SAVED_LIST_INACTIVE"
    } else {
        "SELECTED_APPLICATIONS"
    });
    Ok(result)
}
pub fn app_list() -> Result<Value, &'static str> {
    let mut value = status()?;
    value["ok"] = json!(true);
    value["source"] = json!("native sing-box + config/tun.json");
    value["egress"] = json!("NOT_TESTED_BY_STATUS");
    Ok(value)
}
pub fn app_diagnose(raw: &str) -> Result<Value, &'static str> {
    if !cfg!(windows) {
        return Err("WINDOWS_ONLY");
    }
    let state = read_at(&path())?;
    let (exact, source) = resolve_application(raw, &state, false, None)?;
    let native = config::read(&config::installed())?;
    let configured = native["inbounds"].as_array().is_some_and(|a| a.len() == 3);
    if state.managed_tun != configured {
        return Err("TUN_DESIRED_NATIVE_DRIFT");
    }
    if adapter_up()? != state.managed_tun {
        return Err("TUN_NATIVE_STATE_MISMATCH");
    }
    if state.managed_tun && state.selected_apps && hot_native(&native) {
        hot_readback(&state)?;
    }
    let selected = state
        .applications
        .iter()
        .any(|a| a == &exact || a == executable_leaf(&exact));
    Ok(
        json!({"ok":true,"application":exact,"identity_source":source,
        "desired_route":if state.managed_tun && !state.selected_apps {"VM_ALL_APPLICATIONS"}
            else if state.managed_tun && selected {"VM"} else {"DIRECT"},
        "managed_tun":state.managed_tun,"selected_apps":state.selected_apps,
        "rule_format":if configured && hot_native(&native) {"native_hot_rule_set"}
            else if configured && state.selected_apps {"legacy_process_name"} else {"inactive"},
        "native_state":"CONFIG_AND_FILE_READBACK_ONLY",
        "physical_egress":"NOT_TESTED_BY_STATUS",
        "next_action":"Independently verify real application HTTPS egress"}),
    )
}

#[cfg(windows)]
fn control_endpoints() -> Result<Vec<Ipv4Addr>, &'static str> {
    // Distinct IP addresses do not prove independent routing: the Windows
    // Admin MCP control endpoint may legitimately be the same Vultr VM as
    // the data plane. Verify the established control socket uses the native
    // physical interface and source address before preparing TUN exclusions.
    let script = r#"
$ErrorActionPreference = 'Stop'
$p = @(Get-CimInstance Win32_Process -Filter "Name='tunnel-client-runtime.exe'" |
    Where-Object {$_.ExecutablePath -like '*\WindowsAdminMCP\client\tunnel-client-runtime.exe'})
if ($p.Count -ne 1) { exit 5 }
$sockets = @(Get-NetTCPConnection -State Established -ErrorAction Stop |
    Where-Object {$_.OwningProcess -eq $p[0].ProcessId})
if ($sockets.Count -eq 0) { exit 6 }
foreach ($socket in $sockets) {
    $route = @(Find-NetRoute -RemoteIPAddress $socket.RemoteAddress -ErrorAction Stop)
    $source = @($route | Where-Object {$null -ne $_.PSObject.Properties['IPAddress']})
    $next = @($route | Where-Object {$null -ne $_.PSObject.Properties['DestinationPrefix']})
    if ($source.Count -ne 1 -or $next.Count -lt 1) { exit 9 }
    if ($source[0].IPAddress -ne $socket.LocalAddress -or
        $source[0].InterfaceAlias -eq 'internet-tun' -or
        $next[0].InterfaceAlias -ne $source[0].InterfaceAlias) { exit 9 }
    $socket.RemoteAddress
}
"#;
    let out = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|_| "TUN_CONTROL_QUERY_FAILED")?;
    if !out.status.success() {
        return Err(if out.status.code() == Some(9) {
            "TUN_CONTROL_ROUTE_NOT_DIRECT"
        } else {
            "TUN_CONTROL_NOT_CONNECTED"
        });
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
    use windows::Win32::NetworkManagement::{
        IpHelper::{FreeMibTable, GetIfTable2, MIB_IF_TABLE2},
        Ndis::IfOperStatusUp,
    };

    // Native OS-owned interface inventory, including hidden TUN adapters.
    // No PowerShell process per status read; never infer "down" on API failure.
    struct Table(*mut MIB_IF_TABLE2);
    impl Drop for Table {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: GetIfTable2 owns this allocation until FreeMibTable.
                unsafe { FreeMibTable(self.0.cast()) };
            }
        }
    }
    let mut raw = std::ptr::null_mut();
    // SAFETY: the API fills an owned pointer; Table frees it on every path.
    let result = unsafe { GetIfTable2(&mut raw) };
    let table = Table(raw);
    if result.0 != 0 || table.0.is_null() {
        return Err("TUN_ADAPTER_READBACK_UNKNOWN");
    }
    // SAFETY: GetIfTable2 returns a valid MIB_IF_TABLE2 with NumEntries rows.
    let count = unsafe { (*table.0).NumEntries as usize };
    if count > 16384 {
        return Err("TUN_ADAPTER_READBACK_UNKNOWN");
    }
    // SAFETY: Table is the first element of a contiguous, API-allocated array.
    let rows = unsafe { std::slice::from_raw_parts((*table.0).Table.as_ptr(), count) };
    for row in rows {
        let len = row
            .Alias
            .iter()
            .position(|ch| *ch == 0)
            .unwrap_or(row.Alias.len());
        if String::from_utf16_lossy(&row.Alias[..len]).eq_ignore_ascii_case("internet-tun") {
            return Ok(row.OperStatus == IfOperStatusUp);
        }
    }
    Ok(false)
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
    persist(&path(), &current, &next, None)
}
/// One operator action changes the target TUN mode using the existing native
/// apply/rollback path. The ALL profile also selects the VM DIRECT route in the
/// same prepared sing-box configuration, avoiding an intermediate selector PUT.
pub fn windows_mode(mode: WindowsMode) -> Result<Value, &'static str> {
    if !cfg!(windows) {
        return Err("WINDOWS_ONLY");
    }
    let old = read_at(&path())?;
    let next = mode_transition(&old, mode)?;
    let desktop = if mode == WindowsMode::All {
        Some(crate::model::Route::DirectAuto)
    } else {
        None
    };
    let mut output = persist(&path(), &old, &next, desktop)?;
    output["mode"] = json!(match mode {
        WindowsMode::Normal => "normal",
        WindowsMode::Selected => "selected",
        WindowsMode::All => "all",
    });
    output["egress"] = json!("NOT_TESTED_BY_APPLY");
    output["next_action"] = json!("internet diagnose windows/tun");
    Ok(output)
}
pub fn change_application(add: bool, name: &str) -> Result<Value, &'static str> {
    if !cfg!(windows) {
        return Err("WINDOWS_ONLY");
    }
    let current = read_at(&path())?;
    let next = list_change(&current, add, name)?;
    persist(&path(), &current, &next, None)
}
fn persist(
    path: &Path,
    old: &Settings,
    next: &Settings,
    desktop_route: Option<crate::model::Route>,
) -> Result<Value, &'static str> {
    let current = config::read(&config::installed())?;
    let planned = if let Some(route) = desktop_route {
        config::with_selected(&current, crate::model::Target::Desktop, route)?
    } else {
        current.clone()
    };
    let route_changed = planned != current;
    let configured = current["inbounds"].as_array().is_some_and(|v| v.len() == 3);
    let confirm_native = || -> Result<(), &'static str> {
        verify_native(next.managed_tun)?;
        if let Some(expected) = desktop_route
            && crate::selector::runtime_selected(crate::model::Target::Desktop)? != expected
        {
            return Err("WINDOWS_MODE_ROUTE_UNCONFIRMED");
        }
        Ok(())
    };
    // A crash after native apply but before state persistence must not trap
    // Windows in a TUN that "tun off" refuses to remove.
    let recovering = configured != old.managed_tun;
    if recovering && next.managed_tun {
        return Err("TUN_DESIRED_NATIVE_DRIFT");
    }
    if old == next && !recovering && !route_changed {
        if desktop_route.is_some() {
            confirm_native()?;
        }
        return Ok(
            json!({"ok":true,"changed":false,"managed_tun":old.managed_tun,
            "selected_apps":old.selected_apps,"applications":old.applications,
            "native_adapter_up":adapter_up()?,
            "next_action":"internet tun status"}),
        );
    }
    // Native sing-box watches this source rule-set itself; no lifecycle mutation.
    // The file is a derived projection of tun.json, never a second state owner.
    if configured
        && old.managed_tun
        && next.managed_tun
        && old.selected_apps
        && next.selected_apps
        && hot_native(&current)
        && !route_changed
    {
        if !crate::lifecycle::is_running()? {
            return Err("TUN_TASK_NOT_RUNNING");
        }
        hot_readback(old)?;
        write_hot_rules(next)?;
        if write_at(path, next).is_err() {
            let rollback = write_hot_rules(old).and_then(|_| hot_readback(old));
            return Err(if rollback.is_ok() {
                "HOT_STATE_WRITE_ROLLED_BACK"
            } else {
                "HOT_RULESET_ROLLBACK_UNKNOWN"
            });
        }
        hot_readback(next)?;
        return Ok(
            json!({"ok":true,"changed":true,"managed_tun":next.managed_tun,
            "selected_apps":next.selected_apps,"applications":next.applications,
            "singbox_restarted":false,"hot_reload":"NATIVE_FILE_WATCHER",
            "runtime_confirmed":false,"egress":"NOT_TESTED_BY_APPLY",
            "next_action":"internet app diagnose <EXE>"}),
        );
    }
    let needs_restart = configured || old.managed_tun || next.managed_tun || route_changed;
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
        let updated = render_native(&planned, next, &ips)?;
        if next.managed_tun && next.selected_apps {
            write_hot_rules(next)?;
        }
        candidate_check(&updated)?;
        if updated != current {
            if crate::lifecycle::stop().is_err() {
                let _ = crate::lifecycle::start();
                return Err("TUN_STOP_UNCONFIRMED");
            }
            let outcome = (|| {
                config::write_checked(&config::installed(), &updated)?;
                crate::lifecycle::start()?;
                confirm_native()
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
            confirm_native()?;
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
    if configured && hot_native(&native) {
        hot_readback(&s)?;
    }
    Ok(
        json!({"managed_tun":s.managed_tun,"selected_apps":s.selected_apps,
        "applications":s.applications,"native_tun_configured":configured,
        "native_tun_up":up,"desired_native_match":s.managed_tun==configured,
        "kernel_bypass_for_unselected":"UNSUPPORTED",
        "unselected_egress":"native DIRECT when selected-apps on",
        "physical_egress":"NOT_TESTED_BY_STATUS",
        "application_rule_mode":if configured && hot_native(&native) {"native_hot_rule_set"}
            else if configured && s.selected_apps {"legacy_restart_required"} else {"inactive"}}),
    )
}

/// An intentionally stopped Task is not a native configuration mismatch.
fn classify_tun_status(
    desired_matches_config: bool,
    desired: bool,
    adapter_up: bool,
    task: Result<bool, &'static str>,
) -> (Health, &'static str) {
    if !desired_matches_config || (matches!(task, Ok(false)) && adapter_up) {
        return (Health::Failed, "TUN_NATIVE_STATE_MISMATCH");
    }
    match task {
        Err(_) => (Health::Unknown, "TASK_READBACK_UNKNOWN"),
        Ok(false) if desired => (Health::Degraded, "SING_BOX_STOPPED_TUN_INACTIVE"),
        Ok(_) if desired == adapter_up => (Health::Healthy, "TUN_NATIVE_STATE_CONFIRMED"),
        _ => (Health::Failed, "TUN_NATIVE_STATE_MISMATCH"),
    }
}

pub fn inspect(id: &str) -> Diagnostic {
    inspect_with_snapshot(id, &status(), None)
}

/// Reuse the same native readback for both independent switch diagnostics.
/// The observation is scoped to one CLI invocation, not a persistent cache.
pub(crate) fn inspect_with_snapshot(
    id: &str,
    observed: &Result<Value, &'static str>,
    task: Option<&Result<bool, &'static str>>,
) -> Diagnostic {
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
    match observed {
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
            let (health, reason) = classify_tun_status(
                v["desired_native_match"] == true,
                v["managed_tun"] == true,
                v["native_tun_up"] == true,
                task.copied().unwrap_or_else(crate::lifecycle::is_running),
            );
            d.health = health;
            d.reason_code = reason;
            d.next_action = match reason {
                "SING_BOX_STOPPED_TUN_INACTIVE" => "internet start",
                "TUN_NATIVE_STATE_CONFIRMED" => "internet tun status",
                _ => "internet diagnose windows/tun",
            };
        }
        Err(code) => {
            d.health = Health::Unknown;
            d.reason_code = match *code {
                "TUN_STATE_INTERRUPTED" => "TUN_STATE_INTERRUPTED",
                "TUN_STATE_JSON_INVALID" | "TUN_STATE_SCHEMA_INVALID" => "TUN_STATE_INVALID",
                "HOT_RULESET_DRIFT" | "HOT_RULESET_NOT_FOUND" | "HOT_RULESET_INVALID" => {
                    "HOT_RULESET_DRIFT"
                }
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
    fn stopped_task_is_degraded_not_a_false_tun_failure() {
        assert_eq!(
            classify_tun_status(true, true, false, Ok(false)),
            (Health::Degraded, "SING_BOX_STOPPED_TUN_INACTIVE")
        );
        assert_eq!(
            classify_tun_status(true, false, false, Ok(false)),
            (Health::Healthy, "TUN_NATIVE_STATE_CONFIRMED")
        );
        assert_eq!(
            classify_tun_status(true, true, true, Ok(false)),
            (Health::Failed, "TUN_NATIVE_STATE_MISMATCH")
        );
        assert_eq!(
            classify_tun_status(true, true, false, Ok(true)),
            (Health::Failed, "TUN_NATIVE_STATE_MISMATCH")
        );
        assert_eq!(
            classify_tun_status(true, true, true, Err("TASK_READBACK_FAILED")),
            (Health::Unknown, "TASK_READBACK_UNKNOWN")
        );
        assert_eq!(
            classify_tun_status(false, false, false, Ok(true)),
            (Health::Failed, "TUN_NATIVE_STATE_MISMATCH")
        );
    }
    #[test]
    fn operator_modes_preserve_selected_application_inventory() {
        let initial = list_change(&Settings::default(), true, "firefox.exe").unwrap();
        let selected = mode_transition(&initial, WindowsMode::Selected).unwrap();
        assert!(selected.managed_tun && selected.selected_apps);
        let all = mode_transition(&selected, WindowsMode::All).unwrap();
        assert!(all.managed_tun && !all.selected_apps);
        let normal = mode_transition(&all, WindowsMode::Normal).unwrap();
        assert!(!normal.managed_tun && !normal.selected_apps);
        assert_eq!(normal.applications, ["firefox.exe"]);
        let selected_again = mode_transition(&normal, WindowsMode::Selected).unwrap();
        assert_eq!(selected_again.applications, ["firefox.exe"]);
        assert_eq!(WindowsMode::parse("all"), Ok(WindowsMode::All));
        assert_eq!(WindowsMode::parse("ALL"), Err("WINDOWS_MODE_INVALID"));
        assert_eq!(WindowsMode::parse("vpn"), Err("WINDOWS_MODE_INVALID"));
    }
    #[test]
    fn offline_application_selection_is_saved_not_activated() {
        let initial = Settings::default();
        let saved = app_transition(&initial, true, r"c:\apps\example\demo.exe").unwrap();
        assert!(!saved.managed_tun);
        assert_eq!(saved.applications, [r"c:\apps\example\demo.exe"]);
        let all = mode_transition(&saved, WindowsMode::All).unwrap();
        assert_eq!(
            app_transition(&all, false, r"c:\apps\example\demo.exe"),
            Err("APP_DIRECT_REQUIRES_SELECTED_APPS")
        );
    }
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
    fn app_names_paths_allow_all_executables_and_empty_list() {
        let s = Settings::default();
        assert!(
            toggle_state(&s, Switch::SelectedApps, true)
                .unwrap()
                .applications
                .is_empty()
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
            "sing-box.exe",
            "tunnel-client-runtime.exe",
            "cloudflared.exe",
            "pwsh.exe",
            "powershell.exe",
            "ssh.exe",
            "wsl.exe",
            r"C:\bin\sing-box.exe",
        ] {
            let added = list_change(&s, true, v).unwrap();
            assert_eq!(added.applications, [v.to_lowercase()]);
            assert_eq!(list_change(&added, false, v).unwrap(), s);
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
    fn hot_native_rule_set_matches_exact_paths_and_process_names() {
        let s = list_change(&Settings::default(), true, "msedge.exe").unwrap();
        let s = list_change(
            &s,
            true,
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        )
        .unwrap();
        let rule = rules_source(&s);
        assert_eq!(rule["version"], 3);
        assert_eq!(rule["rules"].as_array().unwrap().len(), 2);
        assert_eq!(rule["rules"][0]["process_name"], json!(["msedge.exe"]));
        assert_eq!(
            rule["rules"][1]["process_path_regex"],
            json!([r"(?i)^c:\\program files \(x86\)\\microsoft\\edge\\application\\msedge\.exe$"])
        );
        let mut other = s.clone();
        other.applications.clear();
        assert_eq!(rules_source(&other)["rules"], json!([]));
    }
    #[test]
    fn process_path_pattern_is_anchored_escaped_and_case_insensitive() {
        assert_eq!(
            native_path_pattern(r"C:\Temp\A+[B](c)\my app.exe"),
            r"(?i)^C:\\Temp\\A\+\[B\]\(c\)\\my app\.exe$"
        );
        assert_eq!(native_path_pattern(r"c:\a\b.exe"), r"(?i)^c:\\a\\b\.exe$");
    }
    #[test]
    fn hot_rule_set_alias_never_confuses_arbitrary_references() {
        let c = json!({"route":{"rules":[{}, {}, {"rule_set":[HOT_TAG]}]}});
        assert!(hot_native(&c));
        let mut other = c;
        other["route"]["rules"][2]["rule_set"] = json!(["foreign"]);
        assert!(!hot_native(&other));
    }
    #[test]
    fn generic_apps_do_not_change_global_tun_or_other_applications() {
        let browser = r"c:\program files\browser\browser.exe";
        let editor = r"c:\tools\editor.exe";
        let inactive = list_change(&Settings::default(), true, "another.exe").unwrap();
        let saved_off = app_transition(&inactive, true, browser).unwrap();
        assert!(!saved_off.managed_tun);
        assert!(saved_off.applications.contains(&browser.to_owned()));
        let all = toggle_state(&inactive, Switch::ManagedTun, true).unwrap();
        let staged_all = app_transition(&all, true, browser).unwrap();
        assert!(staged_all.applications.contains(&browser.to_owned()));
        assert_eq!(
            app_transition(&all, false, browser),
            Err("APP_DIRECT_REQUIRES_SELECTED_APPS")
        );
        let selected = toggle_state(&all, Switch::SelectedApps, true).unwrap();
        let added = app_transition(&selected, true, browser).unwrap();
        let added = app_transition(&added, true, editor).unwrap();
        assert_eq!(added.applications, ["another.exe", browser, editor]);
        let removed = app_transition(&added, false, editor).unwrap();
        assert_eq!(removed.applications, ["another.exe", browser]);
        let last = list_change(&Settings::default(), true, "browser.exe").unwrap();
        let last = toggle_state(&last, Switch::SelectedApps, true).unwrap();
        let last = toggle_state(&last, Switch::ManagedTun, true).unwrap();
        let cleared = app_transition(&last, false, browser).unwrap();
        assert!(cleared.applications.is_empty());
        assert!(cleared.managed_tun && cleared.selected_apps);
    }
    #[test]
    fn generic_name_resolution_refuses_ambiguous_or_unverifiable_identity() {
        let saved = list_change(&Settings::default(), true, "browser.exe").unwrap();
        let browser = r"c:\program files\browser\browser.exe".to_owned();
        let portable = r"d:\portable\browser.exe".to_owned();
        assert_eq!(
            resolve_application(
                "browser.exe",
                &saved,
                true,
                Some(std::slice::from_ref(&browser))
            ),
            Ok((browser.clone(), "RUNNING_PROCESS_EXACT_PATH"))
        );
        assert_eq!(
            resolve_application("browser.exe", &saved, true, Some(&[])),
            Err("APP_NOT_RUNNING_USE_FULL_PATH")
        );
        assert_eq!(
            resolve_application("browser.exe", &saved, false, Some(&[])),
            Ok(("browser.exe".to_owned(), "SAVED_STATE_NOT_RUNNING"))
        );
        assert_eq!(
            resolve_application(
                "browser.exe",
                &saved,
                false,
                Some(&[browser.clone(), portable.clone()])
            ),
            Err("APP_EXECUTABLE_AMBIGUOUS_USE_PATH")
        );
        assert_eq!(
            resolve_application(
                "browser.exe",
                &saved,
                true,
                Some(&[r"c:\evil\ssh.exe".to_owned()])
            ),
            Err("APP_PROCESS_PATH_UNTRUSTED")
        );
        assert_eq!(
            resolve_application(
                "browser.exe",
                &saved,
                false,
                Some(&["browser.exe".to_owned()])
            ),
            Err("APP_PROCESS_PATH_UNTRUSTED")
        );
        let mut two = saved;
        two.applications = vec![browser, portable];
        assert_eq!(
            resolve_application("browser.exe", &two, false, Some(&[])),
            Err("APP_EXECUTABLE_AMBIGUOUS_USE_PATH")
        );
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
        assert!(
            list_change(&s, false, "firefox.exe")
                .unwrap()
                .applications
                .is_empty()
        );
        let mut wrong = s;
        wrong.schema = "v2".into();
        assert_eq!(validate(&wrong), Err("TUN_STATE_SCHEMA_INVALID"));
    }
}

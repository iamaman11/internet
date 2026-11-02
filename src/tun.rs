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

#[derive(Clone, Copy)]
pub enum Switch {
    ManagedTun,
    SelectedApps,
}

pub fn toggle_state(
    current: &Settings,
    switch: Switch,
    enable: bool,
) -> Result<Settings, &'static str> {
    validate(current)?;
    let mut next = current.clone();
    match switch {
        Switch::ManagedTun if enable && current.selected_apps => {
            return Err("S4_WINDOWS_KERNEL_BYPASS_UNSUPPORTED");
        }
        Switch::ManagedTun if enable => return Err("S4_INDEPENDENT_CONTROL_NOT_VERIFIED"),
        Switch::ManagedTun if current.managed_tun => {
            return Err("S4_ACTIVE_TUN_REQUIRES_NATIVE_RECOVERY");
        }
        Switch::ManagedTun => next.managed_tun = false,
        Switch::SelectedApps if current.managed_tun => {
            return Err("S4_ACTIVE_TUN_REQUIRES_NATIVE_RECOVERY");
        }
        Switch::SelectedApps => next.selected_apps = enable,
    }
    validate(&next)?;
    Ok(next)
}

pub fn list_change(current: &Settings, add: bool, name: &str) -> Result<Settings, &'static str> {
    validate(current)?;
    if current.managed_tun {
        return Err("S4_ACTIVE_TUN_REQUIRES_NATIVE_RECOVERY");
    }
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

pub fn command(switch: Switch, enable: bool) -> Result<Value, &'static str> {
    if !cfg!(windows) {
        return Err("WINDOWS_ONLY");
    }
    let path = path();
    let current = read_at(&path)?;
    let next = toggle_state(&current, switch, enable)?;
    persist(&path, &current, &next)
}

pub fn change_application(add: bool, name: &str) -> Result<Value, &'static str> {
    if !cfg!(windows) {
        return Err("WINDOWS_ONLY");
    }
    let path = path();
    let current = read_at(&path)?;
    let next = list_change(&current, add, name)?;
    persist(&path, &current, &next)
}

fn persist(path: &Path, old: &Settings, next: &Settings) -> Result<Value, &'static str> {
    // Even NOOP must prove the native configuration has no TUN.
    // This never mutates a live route, Task or proxy selector.
    config::read(&config::installed())?;
    if old != next {
        config::protect_private_directory(path.parent().ok_or("TUN_STATE_PATH_INVALID")?)?;
        write_at(path, next)?;
    }
    Ok(
        json!({"ok":true,"changed":old != next,"managed_tun":next.managed_tun,
        "selected_apps":next.selected_apps,"applications":next.applications,
        "native_config":"TUN_NOT_CONFIGURED","runtime_proof":"NOT_TESTED","scope":"desired_settings_only",
        "next_action":"internet inspect windows/tun"}),
    )
}

pub fn status() -> Result<Value, &'static str> {
    if !cfg!(windows) {
        return Err("WINDOWS_ONLY");
    }
    let s = read_at(&path())?;
    let c = config::read(&config::installed())?;
    let native_tun = c["inbounds"]
        .as_array()
        .is_some_and(|a| a.iter().any(|i| i["type"] == "tun"));
    Ok(
        json!({"managed_tun":s.managed_tun,"selected_apps":s.selected_apps,
        "applications":s.applications,"native_tun_configured":native_tun,
        "runtime_proof":"NOT_TESTED","windows_kernel_bypass":"UNSUPPORTED",
        "control_independent":"NOT_TESTED"}),
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
    d.source = "config/tun.json and native sing-box.json";
    d.scope = "configured_state_only_no_live_tun_proof";
    if !cfg!(windows) {
        return d;
    }
    match status() {
        Ok(s) => {
            d.observed_at = Some(chrono::Utc::now().to_rfc3339());
            d.expected = Some("No managed TUN while control independence is unverified".into());
            d.actual = Some(if id == "windows/tun" {
                format!(
                    "desired={};native_configured={}",
                    s["managed_tun"], s["native_tun_configured"]
                )
            } else {
                format!(
                    "selected_apps={};count={};tun={}",
                    s["selected_apps"],
                    s["applications"].as_array().map_or(0, Vec::len),
                    s["managed_tun"]
                )
            });
            if s["managed_tun"] == true || s["native_tun_configured"] == true {
                d.health = Health::Unsupported;
                d.reason_code = "S4_NATIVE_TUN_UNVERIFIED";
            } else {
                d.health = Health::Healthy;
                d.reason_code = if id == "windows/tun" {
                    "TUN_OFF_NATIVE_CONFIG_CONFIRMED"
                } else if s["selected_apps"] == true {
                    "SELECTED_APPS_SAVED_INERT"
                } else {
                    "SELECTED_APPS_OFF"
                };
            }
            d.next_action = if id == "windows/tun" {
                "internet tun status"
            } else {
                "internet selected-apps status"
            };
        }
        Err(code) => {
            d.health = Health::Unknown;
            d.reason_code = match code {
                "TUN_STATE_INTERRUPTED" => "TUN_STATE_INTERRUPTED",
                "TUN_STATE_JSON_INVALID" | "TUN_STATE_SCHEMA_INVALID" => "TUN_STATE_INVALID",
                _ => "TUN_NATIVE_READBACK_UNKNOWN",
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
        assert_eq!(
            toggle_state(&s, Switch::ManagedTun, true).unwrap_err(),
            "S4_WINDOWS_KERNEL_BYPASS_UNSUPPORTED"
        );
        let s = toggle_state(&s, Switch::SelectedApps, false).unwrap();
        assert!(!s.selected_apps);
        assert_eq!(s.applications, ["firefox.exe"]);
    }
    #[test]
    fn tun_never_activates_without_verified_independent_control() {
        let s = Settings::default();
        assert_eq!(
            toggle_state(&s, Switch::ManagedTun, true).unwrap_err(),
            "S4_INDEPENDENT_CONTROL_NOT_VERIFIED"
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

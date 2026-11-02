//! One native sing-box JSON is the configuration owner. No second selector DB.
use crate::model::{ROUTES, Route, Target};
use serde_json::Value;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

pub fn installed() -> PathBuf {
    Path::new(crate::ROOT).join("config").join("sing-box.json")
}
pub fn binary() -> PathBuf {
    Path::new(crate::ROOT).join("sing-box.exe")
}

fn array<'a>(config: &'a Value, key: &str) -> Result<&'a Vec<Value>, &'static str> {
    config
        .get(key)
        .and_then(Value::as_array)
        .ok_or("CONFIG_SECTION_MISSING")
}
fn by_tag<'a>(items: &'a [Value], tag: &str) -> Result<&'a Value, &'static str> {
    let mut matches = items.iter().filter(|v| v["tag"].as_str() == Some(tag));
    let first = matches.next().ok_or("CONFIG_TAG_MISSING")?;
    if matches.next().is_some() {
        return Err("CONFIG_TAG_DUPLICATE");
    }
    Ok(first)
}
pub fn validate(c: &Value) -> Result<(), &'static str> {
    let inbounds = array(c, "inbounds")?;
    let outbounds = array(c, "outbounds")?;
    let rules = c
        .pointer("/route/rules")
        .and_then(Value::as_array)
        .ok_or("CONFIG_ROUTE_RULES_MISSING")?;
    if inbounds.len() != 2 || outbounds.len() != 8 || rules.len() != 2 {
        return Err("CONFIG_SCOPE_MISMATCH");
    }
    for (target, port) in [(Target::Desktop, 2080), (Target::Wsl, 2081)] {
        let inbound = by_tag(inbounds, target.listener())?;
        let addr = inbound["listen"].as_str().ok_or("CONFIG_INBOUND_UNSAFE")?;
        let bind_ok = if target == Target::Desktop {
            addr == "127.0.0.1"
        } else {
            addr == "127.0.0.1"
                || addr
                    .parse::<std::net::Ipv4Addr>()
                    .is_ok_and(|ip| ip.is_private() && !ip.is_unspecified() && !ip.is_loopback())
        };
        if inbound["type"] != "mixed" || !bind_ok || inbound["listen_port"].as_u64() != Some(port) {
            return Err("CONFIG_INBOUND_UNSAFE");
        }
        if target == Target::Wsl {
            let users = inbound["users"]
                .as_array()
                .ok_or("CONFIG_WSL_AUTH_REQUIRED")?;
            if users.len() != 1
                || users[0]["username"].as_str().is_none_or(str::is_empty)
                || users[0]["password"].as_str().is_none_or(str::is_empty)
            {
                return Err("CONFIG_WSL_AUTH_REQUIRED");
            }
        }
        let count = rules
            .iter()
            .filter(|r| {
                r["outbound"] == target.selector()
                    && r["inbound"]
                        .as_array()
                        .is_some_and(|a| a.len() == 1 && a[0] == target.listener())
            })
            .count();
        if count != 1 {
            return Err("CONFIG_ROUTE_OWNER_MISMATCH");
        }
        let sel = by_tag(outbounds, target.selector())?;
        if sel["type"] != "selector" {
            return Err("CONFIG_SELECTOR_MISSING");
        }
        let options = sel["outbounds"]
            .as_array()
            .ok_or("CONFIG_SELECTOR_OPTIONS_MISSING")?;
        if options.len() != 6
            || ROUTES
                .iter()
                .any(|tag| options.iter().filter(|v| v.as_str() == Some(*tag)).count() != 1)
        {
            return Err("CONFIG_SELECTOR_OPTIONS_INVALID");
        }
        let def = sel["default"].as_str().ok_or("CONFIG_DEFAULT_MISSING")?;
        if !ROUTES.contains(&def) {
            return Err("CONFIG_DEFAULT_INVALID");
        }
    }
    for (mode, choices) in [
        ("direct-auto", ["direct-hysteria2", "direct-vless"]),
        ("warp-auto", ["warp-hysteria2", "warp-vless"]),
    ] {
        let v = by_tag(outbounds, mode)?;
        if v["type"] != "urltest" {
            return Err("CONFIG_AUTO_TYPE_INVALID");
        }
        let a = v["outbounds"]
            .as_array()
            .ok_or("CONFIG_AUTO_OPTIONS_MISSING")?;
        if a.len() != 2
            || choices
                .iter()
                .any(|tag| a.iter().filter(|v| v.as_str() == Some(*tag)).count() != 1)
        {
            return Err("CONFIG_AUTO_FALLBACK_FORBIDDEN");
        }
    }
    for (tag, kind, port) in [
        ("direct-vless", "vless", 443),
        ("warp-vless", "vless", 5443),
        ("direct-hysteria2", "hysteria2", 8443),
        ("warp-hysteria2", "hysteria2", 9444),
    ] {
        let v = by_tag(outbounds, tag)?;
        if v["type"] != kind
            || v["server"] != "64.176.74.102"
            || v["server_port"].as_u64() != Some(port)
            || v["tls"]["enabled"] != true
        {
            return Err("CONFIG_ENDPOINT_MISMATCH");
        }
        let auth = if kind == "vless" { "uuid" } else { "password" };
        if v[auth].as_str().is_none_or(str::is_empty) {
            return Err("CONFIG_AUTH_MISSING");
        }
        if v["tls"]["insecure"] == true {
            return Err("CONFIG_TLS_INSECURE");
        }
    }
    if c.pointer("/experimental/clash_api/external_controller")
        .and_then(Value::as_str)
        != Some("127.0.0.1:9090")
    {
        return Err("CONFIG_CLASH_API_NOT_LOOPBACK");
    }
    if c.pointer("/route/final").and_then(Value::as_str) != Some(Target::Desktop.selector()) {
        return Err("CONFIG_DEFAULT_ROUTE_UNSAFE");
    }
    if c.pointer("/route/rule_set").is_some()
        || c.pointer("/inbounds/0/auto_route").is_some()
        || c.pointer("/inbounds/1/auto_route").is_some()
    {
        return Err("CONFIG_SCOPE_EXCEEDED");
    }
    Ok(())
}
pub fn selected(c: &Value, target: Target) -> Result<Route, &'static str> {
    let sel = by_tag(array(c, "outbounds")?, target.selector())?;
    sel["default"]
        .as_str()
        .ok_or("CONFIG_DEFAULT_MISSING")?
        .parse()
        .map_err(|_| "CONFIG_DEFAULT_INVALID")
}
pub fn with_selected(
    original: &Value,
    target: Target,
    route: Route,
) -> Result<Value, &'static str> {
    validate(original)?;
    let mut next = original.clone();
    let outbounds = next
        .get_mut("outbounds")
        .and_then(Value::as_array_mut)
        .ok_or("CONFIG_OUTBOUNDS_MISSING")?;
    let item = outbounds
        .iter_mut()
        .find(|v| v["tag"] == target.selector())
        .ok_or("CONFIG_SELECTOR_MISSING")?;
    item["default"] = Value::String(route.to_string());
    validate(&next)?;
    Ok(next)
}
pub fn with_wsl_gateway(
    original: &Value,
    gateway: std::net::Ipv4Addr,
) -> Result<Value, &'static str> {
    validate(original)?;
    if !gateway.is_private() || gateway.is_loopback() {
        return Err("WSL_GATEWAY_INVALID");
    }
    let mut next = original.clone();
    let inbound = next
        .get_mut("inbounds")
        .and_then(Value::as_array_mut)
        .ok_or("CONFIG_INBOUND_UNSAFE")?
        .iter_mut()
        .find(|v| v["tag"] == "wsl-in")
        .ok_or("CONFIG_INBOUND_UNSAFE")?;
    inbound["listen"] = Value::String(gateway.to_string());
    validate(&next)?;
    Ok(next)
}
pub fn read(path: &Path) -> Result<Value, &'static str> {
    let raw = fs::read(path).map_err(|_| "CONFIG_NOT_CONFIGURED")?;
    let parsed: Value = serde_json::from_slice(&raw).map_err(|_| "CONFIG_JSON_INVALID")?;
    validate(&parsed)?;
    Ok(parsed)
}
pub fn protect_private_directory(path: &Path) -> Result<(), &'static str> {
    #[cfg(windows)]
    {
        let marker = Path::new(crate::ROOT).join(".internet-owned");
        if std::fs::read_to_string(&marker)
            .map(|s| s.trim().to_owned())
            .ok()
            .as_deref()
            != Some("iamaman11/internet:s2-windows-x64")
        {
            return Err("INSTALL_OWNER_UNCONFIRMED");
        }
        let root = Path::new(crate::ROOT);
        if std::fs::symlink_metadata(root).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err("INSTALL_ROOT_REPARSE_FORBIDDEN");
        }
    }
    std::fs::create_dir_all(path).map_err(|_| "CONFIG_DIRECTORY_CREATE_FAILED")?;
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err("CONFIG_SYMLINK_FORBIDDEN");
    }
    #[cfg(windows)]
    {
        let output = std::process::Command::new("icacls.exe")
            .arg(path)
            .args([
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-32-544:(OI)(CI)F",
            ])
            .output()
            .map_err(|_| "CONFIG_ACL_APPLY_FAILED")?;
        if !output.status.success() {
            return Err("CONFIG_ACL_APPLY_FAILED");
        }
    }
    Ok(())
}
pub fn write_checked(path: &Path, c: &Value) -> Result<(), &'static str> {
    validate(c)?;
    let dir = path.parent().ok_or("CONFIG_PATH_INVALID")?;
    if fs::symlink_metadata(dir).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err("CONFIG_SYMLINK_FORBIDDEN");
    }
    protect_private_directory(dir)?;
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err("CONFIG_SYMLINK_FORBIDDEN");
    }
    let temporary = dir.join("sing-box.incoming.json");
    let previous = dir.join("sing-box.previous.json");
    let bytes = serde_json::to_vec_pretty(c).map_err(|_| "CONFIG_SERIALIZE_FAILED")?;
    let result = (|| -> Result<(), &'static str> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| "CONFIG_TEMP_CONFLICT")?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| "CONFIG_TEMP_WRITE_FAILED")?;
        drop(file);
        let had_old = path.exists();
        if had_old {
            fs::copy(path, &previous).map_err(|_| "CONFIG_BACKUP_FAILED")?;
        }
        if fs::rename(&temporary, path).is_err() {
            if had_old {
                let _ = fs::copy(&previous, path);
            }
            return Err("CONFIG_REPLACE_FAILED");
        }
        Ok(())
    })();
    if temporary.exists() {
        let _ = fs::remove_file(temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Value {
        let mut out = vec![];
        for (tag, typ, port) in [
            ("direct-vless", "vless", 443),
            ("warp-vless", "vless", 5443),
            ("direct-hysteria2", "hysteria2", 8443),
            ("warp-hysteria2", "hysteria2", 9444),
        ] {
            let mut o = serde_json::json!({"tag":tag,"type":typ,"server":"64.176.74.102","server_port":port,
                       "tls":{"enabled":true},"password":"testing"});
            if typ == "vless" {
                o["uuid"] = Value::String("12345678-1234-1234-1234-123456789012".into());
            }
            out.push(o);
        }
        for mode in ["direct", "warp"] {
            out.push(
                serde_json::json!({"type":"urltest","tag":format!("{mode}-auto"),
                "outbounds":[format!("{mode}-hysteria2"),format!("{mode}-vless")]}),
            );
        }
        for target in [Target::Desktop, Target::Wsl] {
            out.push(
                serde_json::json!({"type":"selector","tag":target.selector(),
                "outbounds":ROUTES,"default":"direct-auto"}),
            );
        }
        serde_json::json!({"inbounds":[
            {"type":"mixed","tag":"desktop-in","listen":"127.0.0.1","listen_port":2080},
            {"type":"mixed","tag":"wsl-in","listen":"127.0.0.1","listen_port":2081,"users":[{"username":"test","password":"test-password"}]}],
            "outbounds":out,
            "route":{"rules":[{"inbound":["desktop-in"],"outbound":"desktop-selector"},
                              {"inbound":["wsl-in"],"outbound":"wsl-selector"}],"final":"desktop-selector"},
            "experimental":{"clash_api":{"external_controller":"127.0.0.1:9090"}}})
    }
    #[test]
    fn scoped_gateway_binding_and_wsl_auth() {
        let original = fixture();
        let gateway: std::net::Ipv4Addr = "172.26.16.
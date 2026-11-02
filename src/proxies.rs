//! Proxy read-only view and scoped Local Secret Vault operations.
//! No credentials in Rust, argv, CLI JSON, logs or the repository.
use crate::config;
use serde_json::{Value, json};
use std::{
    io::{self, IsTerminal, Write},
    net::Ipv4Addr,
    process::{Command, Stdio},
};

const LINES: [(&str, &str, u16, &str); 6] = [
    ("DIRECT", "HTTP", 4128, "http"),
    ("DIRECT", "SOCKS5", 4080, "socks5h"),
    ("DIRECT", "HTTPS", 4443, "https"),
    ("WARP", "HTTP", 3128, "http"),
    ("WARP", "SOCKS5", 1080, "socks5h"),
    ("WARP", "HTTPS", 9443, "https"),
];
const VAULT: &str = "/home/bose/projects/secret-vault/bin/secret-vault";
const SCRIPT: &str = "/mnt/c/internet/windows/proxies.py";

pub fn endpoint() -> Result<(String, String), &'static str> {
    let c = config::read(&config::installed())?;
    let ip = c["outbounds"][0]["server"]
        .as_str()
        .ok_or("PROXY_VM_IP_MISSING")?;
    let addr: Ipv4Addr = ip.parse().map_err(|_| "PROXY_VM_IP_INVALID")?;
    if addr.is_private() || addr.is_loopback() || addr.is_unspecified() || addr.is_link_local() {
        return Err("PROXY_VM_IP_UNSAFE");
    }
    let domain = c["outbounds"][2]["tls"]["server_name"]
        .as_str()
        .ok_or("PROXY_TLS_DOMAIN_MISSING")?;
    if domain.len() > 253
        || domain.len() < 4
        || !domain.contains('.')
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err("PROXY_TLS_DOMAIN_INVALID");
    }
    Ok((ip.to_owned(), domain.to_owned()))
}

pub fn list() -> Result<Value, &'static str> {
    let (ip, domain) = endpoint()?;
    let lines = LINES
        .iter()
        .map(|(mode, protocol, port, scheme)| {
            let hostname = if *scheme == "https" { &domain } else { &ip };
            json!({"mode":mode,"protocol":protocol,"address":hostname,"port":port,
               "url":format!("{scheme}://{hostname}:{port}"),"authentication":"Local Secret Vault"})
        })
        .collect::<Vec<_>>();
    Ok(
        json!({"ok":true,"owner":"native sing-box config + fixed Line2 topology",
              "credentials":"Local Secret Vault / internet.vm.dataplane-auth",
              "lines":lines}),
    )
}

fn vault_child(action: &str) -> Result<Command, &'static str> {
    if !cfg!(windows) {
        return Err("WINDOWS_ONLY");
    }
    let (ip, domain) = endpoint()?;
    let mut command = Command::new("wsl.exe");
    command.args([
        "-d",
        "Ubuntu",
        "--",
        VAULT,
        "run-file",
        "--require-complete",
        "--suffix",
        ".json",
        "internet.vm.dataplane-auth",
        "INTERNET_VM_AUTH_FILE",
        "--",
        "/usr/bin/python3",
        SCRIPT,
        action,
        &ip,
        &domain,
    ]);
    Ok(command)
}

pub fn test() -> Result<Value, &'static str> {
    let out = vault_child("test")?
        .stdin(Stdio::null())
        .output()
        .map_err(|_| "VAULT_WSL_UNREACHABLE")?;
    // The child emits ONLY a sanitized JSON result, never credentials or raw curl stderr.
    let result: Value =
        serde_json::from_slice(&out.stdout).map_err(|_| "PROXY_TEST_RESULT_UNAVAILABLE")?;
    if result["total"] != 6
        || !result["results"].is_array()
        || (result["ok"] == true && !out.status.success())
    {
        return Err("PROXY_TEST_RESULT_INVALID");
    }
    Ok(result)
}

pub fn reveal() -> Result<Value, &'static str> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("PROXY_CREDENTIALS_LOCAL_TERMINAL_ONLY");
    }
    print!("Show the shared proxy login and password on this local screen? Type SHOW: ");
    io::stdout().flush().map_err(|_| "CONSOLE_WRITE_FAILED")?;
    let mut yes = String::new();
    io::stdin()
        .read_line(&mut yes)
        .map_err(|_| "CONSOLE_READ_FAILED")?;
    if yes.trim() != "SHOW" {
        return Err("PROXY_CREDENTIALS_CANCELLED");
    }
    let status = vault_child("show")?
        .status()
        .map_err(|_| "VAULT_WSL_UNREACHABLE")?;
    if !status.success() {
        return Err("VAULT_PROXY_CREDENTIALS_UNAVAILABLE");
    }
    Ok(json!({"ok":true,"displayed":"local_terminal_only","no_secret_copy":true}))
}

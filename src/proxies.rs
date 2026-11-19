//! Native Windows Line2 proxy diagnostics and explicitly local credential reveal.
//! Protected sing-box runtime configuration is the one existing credential owner.
//! Credentials never enter argv, diagnostic results, CLI JSON or logs.
use crate::config;
use serde_json::{Value, json};
use std::{
    io::{self, IsTerminal, Write},
    net::Ipv4Addr,
};

pub(crate) const LINES: [(&str, &str, u16, &str); 6] = [
    ("DIRECT", "HTTP", 4128, "http"),
    ("DIRECT", "SOCKS5", 4080, "socks5h"),
    ("DIRECT", "HTTPS", 4443, "https"),
    ("WARP", "HTTP", 3128, "http"),
    ("WARP", "SOCKS5", 1080, "socks5h"),
    ("WARP", "HTTPS", 9443, "https"),
];

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
               "url":format!("{scheme}://{hostname}:{port}"),"authentication":"protected native runtime config"})
        })
        .collect::<Vec<_>>();
    Ok(
        json!({"ok":true,"owner":"native sing-box config + fixed Line2 topology",
              "credentials":"native sing-box runtime config / wsl-in shared Line2 auth",
              "lines":lines}),
    )
}

pub fn test() -> Result<Value, &'static str> {
    crate::diagnostic::line2_proxy_tests()
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
    // The same native account is consumed by the six Line2 probes. Reveal
    // ONLY after local terminal confirmation; no WSL/Vault binary is needed.
    // A normal non-elevated user cannot bypass the native protected config ACL.
    if !cfg!(windows) {
        return Err("WINDOWS_ONLY");
    }
    let config = config::read(&config::installed())?;
    let (user, pass) = crate::diagnostic::line2_auth(&config)?;
    crate::egress::credential_line(user, pass)?;
    println!("Line2 login: {user}");
    println!("Line2 password: {pass}");
    io::stdout().flush().map_err(|_| "CONSOLE_WRITE_FAILED")?;
    Ok(json!({"ok":true,"displayed":"local_terminal_only","no_secret_copy":true}))
}

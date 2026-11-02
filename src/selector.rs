//! Native sing-box Clash selector API. Persist only in native JSON (no selector DB).
use crate::{
    config,
    model::{Route, Target},
};
use serde_json::Value;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::Path,
    time::Duration,
};

fn native_request(method: &str, target: Target, body: Option<&str>) -> Result<Value, &'static str> {
    let address: SocketAddr = "127.0.0.1:9090".parse().expect("fixed loopback");
    let mut sock = TcpStream::connect_timeout(&address, Duration::from_millis(400))
        .map_err(|_| "SING_BOX_API_UNREACHABLE")?;
    sock.set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| "SING_BOX_API_IO")?;
    sock.set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| "SING_BOX_API_IO")?;
    let data = body.unwrap_or("");
    let request = format!(
        "{method} /proxies/{} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{data}",
        target.selector(),
        data.len()
    );
    sock.write_all(request.as_bytes())
        .map_err(|_| "SING_BOX_API_IO")?;
    let mut response = Vec::new();
    sock.take(128 * 1024)
        .read_to_end(&mut response)
        .map_err(|_| "SING_BOX_API_IO")?;
    let pos = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("SING_BOX_API_REPLY_INVALID")?;
    let header = std::str::from_utf8(&response[..pos]).map_err(|_| "SING_BOX_API_REPLY_INVALID")?;
    if !header.starts_with("HTTP/1.1 200 ") && !header.starts_with("HTTP/1.1 204 ") {
        return Err("SING_BOX_API_REJECTED");
    }
    if method == "PUT" {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&response[pos + 4..]).map_err(|_| "SING_BOX_API_REPLY_INVALID")
}
pub fn runtime_selected(target: Target) -> Result<Route, &'static str> {
    let response = native_request("GET", target, None)?;
    response["now"]
        .as_str()
        .ok_or("SING_BOX_SELECTOR_READBACK_INVALID")?
        .parse()
        .map_err(|_| "SING_BOX_SELECTOR_READBACK_INVALID")
}
pub fn select(
    config_path: &Path,
    target: Target,
    route: Route,
    running: bool,
) -> Result<(), &'static str> {
    let original = config::read(config_path)?;
    let old = config::selected(&original, target)?;
    if old == route && (!running || runtime_selected(target)? == route) {
        return Ok(());
    }
    let updated = config::with_selected(&original, target, route)?;
    if running {
        if runtime_selected(target)? != old {
            return Err("SING_BOX_SELECTOR_DRIFT");
        }
        let payload = serde_json::json!({"name":route.tag()}).to_string();
        native_request("PUT", target, Some(&payload))?;
        if runtime_selected(target)? != route {
            return Err("SING_BOX_SELECTOR_APPLY_UNCONFIRMED");
        }
    }
    if let Err(e) = config::write_checked(config_path, &updated) {
        if running {
            let payload = serde_json::json!({"name":old.tag()}).to_string();
            let _ = native_request("PUT", target, Some(&payload));
        }
        return Err(e);
    }
    if config::selected(&config::read(config_path)?, target)? != route {
        return Err("SELECTOR_PERSISTENCE_UNCONFIRMED");
    }
    Ok(())
}

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
    time::{Duration, Instant},
};

fn native_request(method: &str, target: Target, body: Option<&str>) -> Result<Value, &'static str> {
    native_request_path(
        method,
        &format!("/proxies/{}", target.selector()),
        body,
        Duration::from_secs(2),
    )
}

/// A single native Clash API adapter serves selector GET/PUT and outbound
/// latency GET. No second control plane or change of selected routes.
fn native_request_path(
    method: &str,
    path: &str,
    body: Option<&str>,
    read_timeout: Duration,
) -> Result<Value, &'static str> {
    let address: SocketAddr = "127.0.0.1:9090".parse().expect("fixed loopback");
    let mut sock = TcpStream::connect_timeout(&address, Duration::from_millis(400))
        .map_err(|_| "SING_BOX_API_UNREACHABLE")?;
    sock.set_read_timeout(Some(read_timeout))
        .map_err(|_| "SING_BOX_API_IO")?;
    sock.set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| "SING_BOX_API_IO")?;
    let data = body.unwrap_or("");
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{data}",
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
/// Read-only CONNECT/TLS reachability through one native outbound. The native
/// Clash API reports elapsed milliseconds, NOT its external IP/WARP identity.
/// Exact allowlist avoids using this internal API as a generic request proxy.
pub fn outbound_delay_ms(tag: &str, deadline: Instant) -> Result<u64, &'static str> {
    if !matches!(
        tag,
        "direct-hysteria2" | "direct-vless" | "warp-hysteria2" | "warp-vless"
    ) {
        return Err("LINE1_OUTBOUND_NOT_OWNED");
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining < Duration::from_millis(500) {
        return Err("DEEP_DEADLINE_EXCEEDED");
    }
    let path = format!(
        "/proxies/{tag}/delay?url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=3500"
    );
    // One bounded read; all four independent outbounds are probed in parallel.
    let value = native_request_path(
        "GET",
        &path,
        None,
        remaining.min(Duration::from_millis(4200)),
    )?;
    parse_delay(&value)
}

fn parse_delay(value: &Value) -> Result<u64, &'static str> {
    match value["delay"].as_u64() {
        Some(ms) if (1..=3500).contains(&ms) => Ok(ms),
        _ => Err("LINE1_DELAY_REPLY_INVALID"),
    }
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

#[cfg(test)]
mod latency_tests {
    use super::*;

    #[test]
    fn latency_response_must_be_numeric_positive_and_bounded() {
        assert_eq!(parse_delay(&serde_json::json!({"delay": 53})), Ok(53));
        for body in [
            serde_json::json!({"delay": 0}),
            serde_json::json!({"delay": 3501}),
            serde_json::json!({"delay": "53"}),
            serde_json::json!({"delay": -1}),
            serde_json::json!({"message": "proxy unavailable"}),
            serde_json::json!(null),
        ] {
            assert_eq!(parse_delay(&body), Err("LINE1_DELAY_REPLY_INVALID"));
        }
    }

    #[test]
    fn unowned_tag_and_expired_deadline_rejected_before_network() {
        let future = Instant::now() + Duration::from_secs(4);
        assert_eq!(
            outbound_delay_ms("desktop-selector", future),
            Err("LINE1_OUTBOUND_NOT_OWNED")
        );
        assert_eq!(
            outbound_delay_ms("direct-hysteria2", Instant::now()),
            Err("DEEP_DEADLINE_EXCEEDED")
        );
    }
}

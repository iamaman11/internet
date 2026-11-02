//! Read-only, scope-limited HTTPS egress proof using Windows' native curl.
//! Secrets (Line2 proxy authentication) are supplied only through child stdin.
#[cfg(windows)]
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    thread,
    time::Duration,
};
use std::{net::Ipv4Addr, time::Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Failed,
    Unknown,
}
#[derive(Debug, Clone)]
pub struct Proof {
    pub verdict: Verdict,
    pub reason: &'static str,
}
impl Proof {
    fn new(verdict: Verdict, reason: &'static str) -> Self {
        Self { verdict, reason }
    }
}

pub fn credential_line(user: &str, password: &str) -> Result<String, &'static str> {
    // curl config quoting is intentionally narrow: reject ambiguous values.
    if user.is_empty()
        || password.is_empty()
        || [user, password].iter().any(|s| {
            s.chars()
                .any(|c| c == '\r' || c == '\n' || c == '"' || c == '\\' || c.is_control())
        })
    {
        return Err("PROXY_AUTH_CONFIG_UNSAFE");
    }
    Ok(format!("proxy-user = \"{user}:{password}\"\n"))
}

pub fn verify_body(body: &str, vm: Ipv4Addr, warp: bool) -> Proof {
    if !warp {
        return match body.trim().parse::<Ipv4Addr>() {
            Ok(ip) if ip == vm => Proof::new(Verdict::Pass, "DIRECT_PUBLIC_IP_CONFIRMED"),
            Ok(_) => Proof::new(Verdict::Failed, "DIRECT_IP_MISMATCH"),
            Err(_) => Proof::new(Verdict::Unknown, "PUBLIC_IP_RESPONSE_INVALID"),
        };
    }
    let warp_on = body.lines().any(|l| l.trim() == "warp=on");
    let observed = body.lines().find_map(|l| l.trim().strip_prefix("ip="));
    if !warp_on {
        return Proof::new(Verdict::Failed, "WARP_TRACE_NOT_ON");
    }
    match observed.and_then(|s| s.parse::<std::net::IpAddr>().ok()) {
        Some(ip) if ip != std::net::IpAddr::V4(vm) => {
            Proof::new(Verdict::Pass, "WARP_TRACE_AND_EGRESS_CONFIRMED")
        }
        Some(_) => Proof::new(Verdict::Failed, "WARP_DIRECT_EGRESS_LEAK"),
        None => Proof::new(Verdict::Unknown, "WARP_IP_NOT_VERIFIED"),
    }
}

#[cfg(any(windows, test))]
fn curl_failure(code: Option<i32>) -> Proof {
    match code {
        Some(28) => Proof::new(Verdict::Unknown, "HTTPS_DEADLINE_OR_TIMEOUT"),
        Some(60) => Proof::new(Verdict::Failed, "TLS_CERTIFICATE_REJECTED"),
        Some(35) => Proof::new(Verdict::Failed, "TLS_HANDSHAKE_FAILED"),
        Some(67) => Proof::new(Verdict::Failed, "PROXY_AUTH_REJECTED"),
        Some(22) => Proof::new(Verdict::Failed, "HTTPS_STATUS_NOT_SUCCESS"),
        _ => Proof::new(Verdict::Failed, "HTTPS_PROXY_REQUEST_FAILED"),
    }
}

#[cfg(windows)]
pub fn https(
    proxy: &str,
    auth: Option<(&str, &str)>,
    vm: Ipv4Addr,
    warp: bool,
    deadline: Instant,
    resolve: Option<&str>,
) -> Proof {
    let mut command = Command::new("curl.exe");
    command.arg("-q");
    https_child(&mut command, proxy, auth, vm, warp, deadline, resolve)
}

/// Read-only HTTPS egress originating from Ubuntu, with proxy credentials sent
/// only over stdin to curl; no user/pass appears in child process arguments.
#[cfg(windows)]
pub fn https_wsl(
    gateway: Ipv4Addr,
    auth: (&str, &str),
    vm: Ipv4Addr,
    warp: bool,
    deadline: Instant,
) -> Proof {
    let mut command = Command::new("wsl.exe");
    command.args(["-d", "Ubuntu", "--", "/usr/bin/curl", "-q"]);
    https_child(
        &mut command,
        &format!("http://{gateway}:2081"),
        Some(auth),
        vm,
        warp,
        deadline,
        None,
    )
}
#[cfg(windows)]
fn https_child(
    command: &mut Command,
    proxy: &str,
    auth: Option<(&str, &str)>,
    vm: Ipv4Addr,
    warp: bool,
    deadline: Instant,
    resolve: Option<&str>,
) -> Proof {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining < Duration::from_millis(400) {
        return Proof::new(Verdict::Unknown, "DEEP_DEADLINE_EXCEEDED");
    }
    let url = if warp {
        "https://www.cloudflare.com/cdn-cgi/trace"
    } else {
        "https://api.ipify.org"
    };

    command
        .args([
            "--silent",
            "--fail",
            "--show-error",
            "--ipv4",
            "--noproxy",
            "",
            "--proxy",
            proxy,
            "--config",
            "-",
            "--max-filesize",
            "4096",
            "--connect-timeout",
            "3",
            "--max-time",
            "6",
            url,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::piped());
    if let Some(pin) = resolve {
        command.args(["--resolve", pin]);
    }
    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(_) => return Proof::new(Verdict::Unknown, "CURL_NATIVE_UNAVAILABLE"),
    };
    if let Some((user, password)) = auth {
        let line = match credential_line(user, password) {
            Ok(s) => s,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Proof::new(Verdict::Unknown, e);
            }
        };
        if child
            .stdin
            .take()
            .is_none_or(|mut input| input.write_all(line.as_bytes()).is_err())
        {
            let _ = child.kill();
            let _ = child.wait();
            return Proof::new(Verdict::Unknown, "CURL_STDIN_FAILED");
        }
    } else {
        drop(child.stdin.take());
    }
    // A single absolute deadline bounds all concurrently executing probes.
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut output = Vec::new();
                if child
                    .stdout
                    .take()
                    .is_none_or(|o| o.take(4097).read_to_end(&mut output).is_err())
                {
                    return Proof::new(Verdict::Unknown, "HTTPS_RESPONSE_UNAVAILABLE");
                }
                if !status.success() {
                    return curl_failure(status.code());
                }
                if output.len() > 4096 {
                    return Proof::new(Verdict::Unknown, "HTTPS_RESPONSE_TOO_LARGE");
                }
                return match std::str::from_utf8(&output) {
                    Ok(body) => verify_body(body, vm, warp),
                    Err(_) => Proof::new(Verdict::Unknown, "HTTPS_RESPONSE_INVALID"),
                };
            }
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(15));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Proof::new(Verdict::Unknown, "DEEP_DEADLINE_EXCEEDED");
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Proof::new(Verdict::Unknown, "CURL_WAIT_FAILED");
            }
        }
    }
}
#[cfg(not(windows))]
pub fn https(
    _: &str,
    _: Option<(&str, &str)>,
    _: Ipv4Addr,
    _: bool,
    _: Instant,
    _: Option<&str>,
) -> Proof {
    Proof::new(Verdict::Unknown, "WINDOWS_ONLY")
}

#[cfg(not(windows))]
pub fn https_wsl(_: Ipv4Addr, _: (&str, &str), _: Ipv4Addr, _: bool, _: Instant) -> Proof {
    Proof::new(Verdict::Unknown, "WINDOWS_ONLY")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn vm() -> Ipv4Addr {
        "64.176.74.102".parse().unwrap()
    }
    #[test]
    fn direct_requires_exact_public_ip() {
        assert_eq!(
            verify_body("64.176.74.102\n", vm(), false).verdict,
            Verdict::Pass
        );
        assert_eq!(
            verify_body("1.1.1.1", vm(), false).reason,
            "DIRECT_IP_MISMATCH"
        );
        assert_eq!(verify_body("bad", vm(), false).verdict, Verdict::Unknown);
    }
    #[test]
    fn warp_cannot_fallback_to_direct() {
        assert_eq!(
            verify_body("ip=104.28.1.10\nwarp=on\n", vm(), true).verdict,
            Verdict::Pass
        );
        assert_eq!(
            verify_body("ip=64.176.74.102\nwarp=on\n", vm(), true).reason,
            "WARP_DIRECT_EGRESS_LEAK"
        );
        assert_eq!(
            verify_body("ip=104.28.1.10\nwarp=off\n", vm(), true).reason,
            "WARP_TRACE_NOT_ON"
        );
        assert_eq!(
            verify_body("ip=2a09:bac1:5b80:40::49:134\nwarp=on\n", vm(), true).verdict,
            Verdict::Pass
        );
        assert_eq!(
            verify_body("warp=on\n", vm(), true).verdict,
            Verdict::Unknown
        );
    }
    #[test]
    fn distinct_failures_are_not_silent_fallback() {
        assert_eq!(curl_failure(Some(60)).reason, "TLS_CERTIFICATE_REJECTED");
        assert_eq!(curl_failure(Some(67)).reason, "PROXY_AUTH_REJECTED");
        assert_eq!(curl_failure(Some(28)).verdict, Verdict::Unknown);
    }
    #[test]
    fn auth_never_escapes_stdin_config() {
        assert!(credential_line("username", "some-password").is_ok());
        for bad in ["bad\ninjection", "bad\" quote", "bad\\escape", ""] {
            assert!(credential_line("username", bad).is_err());
        }
    }
}

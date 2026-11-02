//! Read-only diagnostics; remote facts are never fabricated.
use crate::{
    config, egress, lifecycle,
    model::{Diagnostic, Health, Target},
    selector,
};
use chrono::Utc;
use std::{
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};
pub const IDS: [&str; 10] = [
    "internet",
    "windows",
    "windows/network",
    "windows/sing-box",
    "windows/desktop-selector",
    "windows/wsl-selector",
    "vultr",
    "vultr/vm",
    "vultr/line1",
    "vultr/line2",
];
fn now() -> Option<String> {
    Some(Utc::now().to_rfc3339())
}
/// One local task readback for a whole CLI request, never a cached process or DB.
pub fn batch(ids: &[&str], deep: bool) -> Vec<Diagnostic> {
    let needs_task = ids.iter().any(|id| {
        matches!(
            *id,
            "windows/sing-box" | "windows/desktop-selector" | "windows/wsl-selector"
        )
    });
    let task = if needs_task && cfg!(windows) {
        Some(lifecycle::is_running())
    } else {
        None
    };
    if !deep || !cfg!(windows) {
        return ids
            .iter()
            .map(|id| inspect_with_task(id, deep, task.as_ref()))
            .collect();
    }
    // Run independent real HTTPS probes at the same time as native local readback.
    // A probe never changes a selector, firewall, task, or remote process.
    let deadline = Instant::now() + Duration::from_millis(9300);
    let need_desktop = ids
        .iter()
        .any(|id| *id == "windows/desktop-selector" || *id == "vultr/line1");
    let need_line2 = ids.contains(&"vultr/line2");
    let config = config::read(&config::installed()).ok();
    let running = task.as_ref().is_some_and(|v| matches!(v, Ok(true)));
    let desktop = if need_desktop && running {
        config
            .clone()
            .map(|c| std::thread::spawn(move || selected_desktop_egress(c, deadline)))
    } else {
        None
    };
    let line2 = if need_line2 {
        config
            .clone()
            .map(|c| std::thread::spawn(move || line2_egress(c, deadline)))
    } else {
        None
    };
    let mut results: Vec<_> = ids
        .iter()
        .map(|id| inspect_with_task(id, deep, task.as_ref()))
        .collect();
    // Guest-originating authenticated HTTPS is only attempted after the
    // existing WSL boundary check proved selector ownership, binding and 407.
    // No secrets in argv, logs or stored state; read runtime sing-box JSON.
    if let Some(d) = results
        .iter_mut()
        .find(|d| d.resource_id == "windows/wsl-selector")
        && d.reason_code == "WSL_AUTH_CHALLENGE_PASS_EGRESS_NOT_CHECKED"
        && let Some(c) = &config
    {
        let proof = selected_wsl_egress(c, deadline);
        d.health = proof_health(proof.verdict);
        d.reason_code = if proof.verdict == egress::Verdict::Pass {
            "WSL_AUTHENTICATED_HTTPS_EGRESS_CONFIRMED"
        } else {
            proof.reason
        };
        d.source = "wsl-ubuntu-curl-https-via-sing-box";
        d.scope = "selected_wsl_authenticated_https_egress";
        d.observed_at = now();
        d.next_action = "internet diagnose windows/wsl-selector";
    }
    let desktop_proof = desktop.map(|h| {
        h.join().unwrap_or(egress::Proof {
            verdict: egress::Verdict::Unknown,
            reason: "EGRESS_PROBE_PANIC",
        })
    });
    let line2_proof = line2.map(|h| {
        h.join().unwrap_or(Line2Result {
            verdict: egress::Verdict::Unknown,
            reason: "EGRESS_PROBE_PANIC",
            actual: "line2 probe thread unavailable".into(),
        })
    });
    for d in &mut results {
        match d.resource_id.as_str() {
            "windows/desktop-selector" if d.health == Health::Healthy => {
                if let Some(proof) = &desktop_proof {
                    d.health = proof_health(proof.verdict);
                    d.reason_code = proof.reason;
                    d.scope = "selected_https_egress";
                    d.source = "native-curl-https-via-sing-box";
                    d.observed_at = now();
                    d.next_action = "internet diagnose vultr/line1";
                }
            }
            "vultr/line1" if desktop_proof.is_some() => {
                let proof = desktop_proof.as_ref().expect("checked");
                // One selected path cannot prove the other VLESS/Hy2 paths.
                d.health = if proof.verdict == egress::Verdict::Failed {
                    Health::Failed
                } else {
                    Health::Unknown
                };
                d.reason_code = if proof.verdict == egress::Verdict::Pass {
                    "SELECTED_LINE1_EGRESS_PASS_OTHERS_NOT_CHECKED"
                } else {
                    proof.reason
                };
                d.scope = "selected_desktop_line1_only";
                d.source = "native-curl-https-via-sing-box";
                d.observed_at = now();
                d.actual = Some(format!("selected_desktop_egress={:?}", proof.verdict));
            }
            "vultr/line2" if line2_proof.is_some() => {
                let proof = line2_proof.as_ref().expect("checked");
                // The HTTP direct/WARP pair alone does not prove all 6 Line2 inbounds.
                d.health = proof_health(proof.verdict);
                d.reason_code = proof.reason;
                d.scope = "six_line2_http_socks_https_ipv4_https_egress";
                d.source = "native-curl-https-via-line2";
                d.observed_at = now();
                d.actual = Some(proof.actual.clone());
            }
            _ => {}
        }
    }
    results
}
fn proof_health(verdict: egress::Verdict) -> Health {
    match verdict {
        egress::Verdict::Pass => Health::Healthy,
        egress::Verdict::Failed => Health::Failed,
        egress::Verdict::Unknown => Health::Unknown,
    }
}

fn native_vm(config: &serde_json::Value) -> Option<std::net::Ipv4Addr> {
    config
        .pointer("/outbounds/0/server")?
        .as_str()?
        .parse()
        .ok()
}
fn selected_desktop_egress(config: serde_json::Value, deadline: Instant) -> egress::Proof {
    let Some(vm) = native_vm(&config) else {
        return egress::Proof {
            verdict: egress::Verdict::Unknown,
            reason: "REMOTE_ENDPOINT_UNKNOWN",
        };
    };
    let Ok(selected) = config::selected(&config, Target::Desktop) else {
        return egress::Proof {
            verdict: egress::Verdict::Unknown,
            reason: "SELECTOR_CONFIG_INVALID",
        };
    };
    egress::https(
        "http://127.0.0.1:2080",
        None,
        vm,
        selected.tag().starts_with("warp-"),
        deadline,
        None,
    )
}
/// The native installed sing-box config is already the runtime auth owner.
/// Caller only executes after the independent WSL 407 challenge and host
/// gateway binding check succeed; no duplicate credential store or Vault read.
fn wsl_egress_input(
    c: &serde_json::Value,
) -> Result<(std::net::Ipv4Addr, std::net::Ipv4Addr, bool, &str, &str), &'static str> {
    let vm = native_vm(c).ok_or("REMOTE_ENDPOINT_UNKNOWN")?;
    let inbound = &c["inbounds"][1];
    if inbound["tag"] != "wsl-in"
        || inbound["type"] != "mixed"
        || inbound["listen_port"].as_u64() != Some(2081)
    {
        return Err("WSL_NATIVE_INBOUND_INVALID");
    }
    let gateway: std::net::Ipv4Addr = inbound["listen"]
        .as_str()
        .ok_or("WSL_NATIVE_BINDING_MISSING")?
        .parse()
        .map_err(|_| "WSL_NATIVE_BINDING_INVALID")?;
    if !gateway.is_private() || gateway.is_loopback() || gateway.is_unspecified() {
        return Err("WSL_NATIVE_BINDING_INVALID");
    }
    let user = inbound["users"][0]["username"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("WSL_RUNTIME_AUTH_UNAVAILABLE")?;
    let password = inbound["users"][0]["password"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("WSL_RUNTIME_AUTH_UNAVAILABLE")?;
    let route = config::selected(c, Target::Wsl).map_err(|_| "WSL_ROUTE_UNKNOWN")?;
    Ok((
        gateway,
        vm,
        route.tag().starts_with("warp-"),
        user,
        password,
    ))
}
fn selected_wsl_egress(c: &serde_json::Value, deadline: Instant) -> egress::Proof {
    match wsl_egress_input(c) {
        Ok((gateway, vm, warp, user, password)) => {
            egress::https_wsl(gateway, (user, password), vm, warp, deadline)
        }
        Err(reason) => egress::Proof {
            verdict: egress::Verdict::Unknown,
            reason,
        },
    }
}

#[derive(Debug)]
struct Line2Result {
    verdict: egress::Verdict,
    reason: &'static str,
    actual: String,
}

fn line2_egress(config: serde_json::Value, deadline: Instant) -> Line2Result {
    use egress::Verdict;
    let unknown = |reason: &'static str| Line2Result {
        verdict: Verdict::Unknown,
        reason,
        actual: "line2 endpoints not verified".into(),
    };
    let Some(vm) = native_vm(&config) else {
        return unknown("REMOTE_ENDPOINT_UNKNOWN");
    };
    let Some(user) = config
        .pointer("/inbounds/1/users/0/username")
        .and_then(|v| v.as_str())
    else {
        return unknown("LINE2_CREDENTIAL_NOT_CONFIGURED");
    };
    let Some(pass) = config
        .pointer("/inbounds/1/users/0/password")
        .and_then(|v| v.as_str())
    else {
        return unknown("LINE2_CREDENTIAL_NOT_CONFIGURED");
    };
    let domain_for = |tag: &str| {
        config["outbounds"]
            .as_array()?
            .iter()
            .find(|v| v["tag"] == tag)?["tls"]["server_name"]
            .as_str()
    };
    let Some(domain) = domain_for("direct-hysteria2") else {
        return unknown("LINE2_TLS_DOMAIN_UNKNOWN");
    };
    if domain_for("warp-hysteria2") != Some(domain)
        || domain.is_empty()
        || domain.len() > 253
        || !domain.contains('.')
        || !domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return unknown("LINE2_TLS_DOMAIN_INVALID");
    }
    // Six native Line2 inbounds; only confirmed HTTPS egress is claimed.
    // Remote TLS proxies are pinned to the VM IP but verified by the DNS/SAN name.
    let routes = [
        ("warp_http", "http", 3128u16, true),
        ("warp_socks", "socks5h", 1080, true),
        ("warp_https", "https", 9443, true),
        ("direct_http", "http", 4128, false),
        ("direct_socks", "socks5h", 4080, false),
        ("direct_https", "https", 4443, false),
    ];
    let proofs: Vec<(&str, egress::Proof)> = std::thread::scope(|scope| {
        let jobs: Vec<_> = routes
            .iter()
            .map(|(label, scheme, port, warp)| {
                let proxy = if *scheme == "https" {
                    format!("https://{domain}:{port}")
                } else {
                    format!("{scheme}://{vm}:{port}")
                };
                let pinned = if *scheme == "https" {
                    Some(format!("{domain}:{port}:{vm}"))
                } else {
                    None
                };
                (
                    *label,
                    scope.spawn(move || {
                        egress::https(
                            &proxy,
                            Some((user, pass)),
                            vm,
                            *warp,
                            deadline,
                            pinned.as_deref(),
                        )
                    }),
                )
            })
            .collect();
        jobs.into_iter()
            .map(|(label, job)| {
                (
                    label,
                    job.join().unwrap_or(egress::Proof {
                        verdict: Verdict::Unknown,
                        reason: "EGRESS_PROBE_PANIC",
                    }),
                )
            })
            .collect()
    });
    let actual = proofs
        .iter()
        .map(|(name, p)| format!("{name}={:?}/{}", p.verdict, p.reason))
        .collect::<Vec<_>>()
        .join("; ");
    if let Some((_, fail)) = proofs.iter().find(|(_, p)| p.verdict == Verdict::Failed) {
        return Line2Result {
            verdict: Verdict::Failed,
            reason: fail.reason,
            actual,
        };
    }
    if proofs.iter().all(|(_, p)| p.verdict == Verdict::Pass) {
        Line2Result {
            verdict: Verdict::Pass,
            reason: "LINE2_SIX_HTTPS_EGRESS_PATHS_CONFIRMED",
            actual,
        }
    } else {
        Line2Result {
            verdict: Verdict::Unknown,
            reason: "LINE2_EGRESS_INCOMPLETE",
            actual,
        }
    }
}

pub fn inspect(id: &str, deep: bool) -> Diagnostic {
    inspect_with_task(id, deep, None)
}
fn task_running(task: Option<&Result<bool, &'static str>>) -> Result<bool, &'static str> {
    match task {
        Some(observed) => *observed,
        None => lifecycle::is_running(),
    }
}
fn node(
    id: &str,
    kind: &'static str,
    owner: &'static str,
    parent: Option<&'static str>,
    next: &'static str,
) -> Diagnostic {
    let mut d = Diagnostic::unknown(id, kind, owner, next);
    d.parent = parent;
    d
}
fn inspect_with_task(
    id: &str,
    deep: bool,
    task: Option<&Result<bool, &'static str>>,
) -> Diagnostic {
    match id {
        "internet" => node(id, "application", "Rust INTERNET", None, "internet status"),
        "windows" => node(id, "host", "Windows", Some("internet"), "internet status"),
        "windows/network" => node(
            id,
            "network",
            "Windows",
            Some("windows"),
            "Check Windows network separately; never mutate routes",
        ),
        "vultr" => node(
            id,
            "provider",
            "Vultr",
            Some("internet"),
            "internet status --deep",
        ),
        "vultr/vm" | "vultr/line1" | "vultr/line2" => {
            remote_transport(id, deep && id == "vultr/vm")
        }
        "windows/sing-box" => local_binary(task),
        "windows/desktop-selector" => local_selector(id, Target::Desktop, deep, task),
        "windows/wsl-selector" => local_selector(id, Target::Wsl, deep, task),
        _ => node(
            id,
            "unknown",
            "none",
            None,
            "Use internet tree for known resource IDs",
        ),
    }
}
/// Public port reachability is only a transport observation. It never proves VM
/// identity, TLS, authentication, UDP, Docker health or actual egress.
fn remote_transport(id: &str, deep: bool) -> Diagnostic {
    use std::net::{IpAddr, Ipv4Addr};
    let parent = if id == "vultr/vm" {
        "vultr"
    } else {
        "vultr/vm"
    };
    let mut d = node(
        id,
        "remote",
        "Vultr/Docker",
        Some(parent),
        "Use Vault SSH and native Docker/protocol probes for actual service health",
    );
    if !deep {
        return d;
    }
    let Ok(config) = config::read(&config::installed()) else {
        d.reason_code = "LOCAL_CONFIG_UNAVAILABLE_FOR_REMOTE_PROBE";
        return d;
    };
    let Some(host) = config
        .pointer("/outbounds/0/server")
        .and_then(|v| v.as_str())
        .and_then(|v| v.parse::<Ipv4Addr>().ok())
    else {
        d.reason_code = "REMOTE_ENDPOINT_UNKNOWN";
        return d;
    };
    let ports: &[u16] = match id {
        "vultr/line1" => &[443, 5443],
        "vultr/line2" => &[3128, 4080],
        _ => &[443],
    };
    let mut available = 0;
    for port in ports {
        if TcpStream::connect_timeout(
            &SocketAddr::new(IpAddr::V4(host), *port),
            Duration::from_millis(450),
        )
        .is_ok()
        {
            available += 1;
        }
    }
    d.source = "native-tcp-connect";
    d.observed_at = now();
    d.scope = "tcp_transport_only";
    d.actual = Some(format!(
        "{} of {} TCP ports reachable",
        available,
        ports.len()
    ));
    d.reason_code = if available == ports.len() {
        "TCP_REACHABLE_PROTOCOL_EGRESS_NOT_CHECKED"
    } else {
        "TCP_REACHABILITY_INCOMPLETE"
    };
    // Even TCP success cannot identify the remote VM or prove end-to-end health.
    d
}
fn local_binary(task: Option<&Result<bool, &'static str>>) -> Diagnostic {
    let id = "windows/sing-box";
    let mut d = Diagnostic::unknown(
        id,
        "process",
        "Windows Task Scheduler",
        "Install signed release and configure sing-box",
    );
    d.parent = Some("windows");
    d.source = "local-filesystem/task-scheduler";
    if !cfg!(windows) {
        d.next_action = "Install on Windows";
        return d;
    }
    d.observed_at = now();
    d.scope = "local";
    if !config::binary().is_file() {
        d.health = Health::Failed;
        d.reason_code = "BINARY_MISSING";
        return d;
    }
    if config::read(&config::installed()).is_err() {
        d.health = Health::Degraded;
        d.reason_code = "NOT_CONFIGURED";
        return d;
    }
    match task_running(task) {
        Ok(true) => {
            d.health = Health::Healthy;
            d.reason_code = "TASK_RUNNING";
            d.next_action = "internet diagnose windows/desktop-selector";
        }
        Ok(false) => {
            d.health = Health::Degraded;
            d.reason_code = "TASK_STOPPED";
            d.next_action = "internet start";
        }
        Err(_) => {
            d.health = Health::Unknown;
            d.reason_code = "TASK_READBACK_UNKNOWN";
            d.next_action = "internet diagnose windows/sing-box";
        }
    }
    d
}
fn local_selector(
    id: &str,
    target: Target,
    deep: bool,
    task: Option<&Result<bool, &'static str>>,
) -> Diagnostic {
    let mut d = Diagnostic::unknown(
        id,
        "selector",
        "sing-box",
        "Configure from Local Secret Vault",
    );
    d.parent = Some("windows/sing-box");
    d.dependencies.push("windows/sing-box");
    d.scope = "local";
    if !cfg!(windows) {
        d.next_action = "Install on Windows";
        return d;
    }
    match config::read(&config::installed()) {
        Ok(c) => {
            d.source = "local-native-config";
            d.observed_at = now();
            d.actual = Some(
                config::selected(&c, target)
                    .map(|r| r.to_string())
                    .unwrap_or_else(|_| "invalid".into()),
            );
            match task_running(task) {
                Ok(true) => match selector::runtime_selected(target) {
                    Ok(r) if Some(r.to_string()) == d.actual => {
                        d.health = Health::Healthy;
                        d.reason_code = "SELECTOR_CONFIRMED";
                        d.source = "sing-box-clash-api";
                        d.next_action = "internet diagnose";
                    }
                    Ok(_) => {
                        d.health = Health::Failed;
                        d.reason_code = "SELECTOR_DRIFT";
                        d.next_action = "internet restart";
                    }
                    Err(_) => {
                        d.health = Health::Unknown;
                        d.reason_code = "SELECTOR_READBACK_FAILED";
                        d.next_action = "internet diagnose";
                    }
                },
                Ok(false) => {
                    d.health = Health::Degraded;
                    d.reason_code = "SING_BOX_STOPPED";
                    d.next_action = "internet start";
                }
                Err(_) => {
                    d.health = Health::Unknown;
                    d.reason_code = "TASK_STATE_UNKNOWN";
                    d.next_action = "internet diagnose";
                }
            }
            if target == Target::Wsl && d.health == Health::Healthy {
                // A selector readback from Windows is NOT a WSL connectivity proof.
                d.health = Health::Unknown;
                d.reason_code = "WSL_CHANNEL_NOT_TESTED";
                d.next_action = "internet diagnose windows/wsl-selector";
                if deep {
                    match crate::wsl::discover() {
                        Ok(Some(n)) => {
                            let actual = c["inbounds"][1]["listen"].as_str().unwrap_or("");
                            if actual != n.gateway.to_string() {
                                d.health = Health::Failed;
                                d.reason_code = "WSL_BINDING_STALE";
                                d.next_action = "internet restart";
                            } else {
                                match crate::wsl::probe(&n) {
                                    Ok(()) => {
                                        // HTTP 407 from inside the guest proves
                                        // protocol reachability and auth enforcement,
                                        // NOT an authenticated external egress.
                                        d.health = Health::Unknown;
                                        d.reason_code =
                                            "WSL_AUTH_CHALLENGE_PASS_EGRESS_NOT_CHECKED";
                                        d.source = "wsl-http-connect-negative";
                                        d.scope = "wsl_authenticated_egress_not_checked";
                                    }
                                    Err("WSL_PROXY_AUTH_BYPASS") => {
                                        d.health = Health::Failed;
                                        d.reason_code = "WSL_PROXY_AUTH_BYPASS";
                                    }
                                    Err("WSL_PROXY_AUTH_UNVERIFIED" | "WSL_AUTH_REPLY_INVALID") => {
                                        d.health = Health::Unknown;
                                        d.reason_code = "WSL_AUTH_CHALLENGE_UNVERIFIED";
                                    }
                                    Err(_) => {
                                        d.health = Health::Failed;
                                        d.reason_code = "WSL_PROXY_UNREACHABLE";
                                        d.next_action = "internet inspect windows/wsl-selector";
                                    }
                                }
                            }
                        }
                        Ok(None) => {
                            d.reason_code = "WSL_NOT_INSTALLED";
                        }
                        Err(_) => {
                            d.reason_code = "WSL_NETWORK_READBACK_UNKNOWN";
                        }
                    }
                }
            } else if deep && d.health == Health::Healthy {
                let addr: SocketAddr = "127.0.0.1:2080".parse().expect("fixed loopback");
                if TcpStream::connect_timeout(&addr, Duration::from_millis(700)).is_err() {
                    d.health = Health::Failed;
                    d.reason_code = "PROXY_LISTENER_UNREACHABLE";
                    d.next_action = "internet inspect windows/sing-box";
                }
            }
            // Even a TCP listener is not authenticated external egress proof.
        }
        Err(_) => {
            d.source = "local-filesystem";
            d.observed_at = now();
            d.health = Health::Degraded;
            d.reason_code = "NOT_CONFIGURED";
        }
    }
    d
}
pub fn all(deep: bool) -> Vec<Diagnostic> {
    batch(&IDS, deep)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wsl_egress_input_enforces_binding_auth_and_route_without_secrets_in_output() {
        let mut c = serde_json::json!({
            "outbounds":[{"server":"64.176.74.102"},{"tag":"wsl-selector","default":"warp-auto"}],
            "inbounds":[{},{"tag":"wsl-in","type":"mixed","listen":"172.26.16.1",
                           "listen_port":2081,"users":[{"username":"demo","password":"test-only"}]}]
        });
        let p = wsl_egress_input(&c).unwrap();
        assert_eq!(p.0.to_string(), "172.26.16.1");
        assert_eq!(p.1.to_string(), "64.176.74.102");
        assert!(p.2);
        c["inbounds"][1]["listen"] = serde_json::json!("127.0.0.1");
        assert_eq!(
            wsl_egress_input(&c).unwrap_err(),
            "WSL_NATIVE_BINDING_INVALID"
        );
        c["inbounds"][1]["listen"] = serde_json::json!("172.26.16.1");
        c["inbounds"][1]["users"][0]["password"] = serde_json::json!("");
        assert_eq!(
            wsl_egress_input(&c).unwrap_err(),
            "WSL_RUNTIME_AUTH_UNAVAILABLE"
        );
        c["inbounds"][1]["users"][0]["password"] = serde_json::json!("test-only");
        c["outbounds"][1]["default"] = serde_json::json!("not-a-route");
        assert_eq!(wsl_egress_input(&c).unwrap_err(), "WSL_ROUTE_UNKNOWN");
    }
    #[test]
    fn read_only_unknown_remote() {
        let d = inspect("vultr/vm", true);
        assert_eq!(d.health, Health::Unknown);
        assert!(d.observed_at.is_none());
    }
    #[test]
    fn tree_is_closed_and_acyclic() {
        let mut ids = std::collections::HashSet::new();
        for id in IDS {
            assert!(ids.insert(id), "duplicate resource id: {id}");
        }
        for id in IDS {
            let node = inspect(id, false);
            if let Some(parent) = node.parent {
                assert!(ids.contains(parent), "orphan: {id} -> {parent}");
                assert_ne!(id, parent, "self-parent");
                let mut ancestor = parent;
                let mut visited = std::collections::HashSet::new();
                while let Some(next) = inspect(ancestor, false).parent {
                    assert!(visited.insert(ancestor), "parent cycle at {ancestor}");
                    ancestor = next;
                }
            } else {
                assert_eq!(id, "internet", "unexpected root: {id}");
            }
            for dep in node.dependencies {
                assert!(ids.contains(dep), "unknown dependency {dep} of {id}");
            }
        }
    }
    #[test]
    fn remote_not_checked_is_not_fabricated() {
        let d = inspect("vultr/line2", false);
        assert_eq!(d.health, Health::Unknown);
        assert_eq!(d.reason_code, "NOT_CHECKED");
        assert!(d.observed_at.is_none());
    }
}

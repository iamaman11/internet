//! Read-only diagnostics; remote facts are never fabricated.
use crate::{
    config, lifecycle,
    model::{Diagnostic, Health, Target},
    selector,
};
use chrono::Utc;
use std::{
    net::{SocketAddr, TcpStream},
    time::Duration,
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
    ids.iter()
        .map(|id| inspect_with_task(id, deep, task.as_ref()))
        .collect()
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
        "vultr/vm" | "vultr/line1" | "vultr/line2" => remote_transport(id, deep),
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
                            } else if crate::wsl::probe(&n).is_err() {
                                d.health = Health::Failed;
                                d.reason_code = "WSL_PROXY_UNREACHABLE";
                                d.next_action = "internet inspect windows/wsl-selector";
                            } else {
                                d.health = Health::Degraded;
                                d.reason_code = "WSL_TRANSPORT_PASS_EGRESS_NOT_CHECKED";
                                d.source = "wsl-tcp-connect";
                                d.scope = "wsl_transport_only";
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

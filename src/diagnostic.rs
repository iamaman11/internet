//! Read-only diagnostics; remote facts are never fabricated.
use crate::{
    config, lifecycle,
    model::{Diagnostic, Health, Target},
    selector,
};
use chrono::Utc;
use std::{
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};
pub const IDS: [&str; 7] = [
    "windows/network",
    "windows/sing-box",
    "windows/desktop-selector",
    "windows/wsl-selector",
    "vultr/vm",
    "vultr/line1",
    "vultr/line2",
];
fn now() -> Option<String> {
    Some(Utc::now().to_rfc3339())
}
pub fn inspect(id: &str, deep: bool) -> Diagnostic {
    match id {
        "windows/network" => Diagnostic::unknown(
            id,
            "network",
            "Windows",
            "Check Windows network separately; never mutate routes",
        ),
        "vultr/vm" | "vultr/line1" | "vultr/line2" => Diagnostic::unknown(
            id,
            "remote",
            "Vultr/Docker",
            "Use verified Vault SSH and external network probes; remote not checked by local CLI",
        ),
        "windows/sing-box" => local_binary(),
        "windows/desktop-selector" => local_selector(id, Target::Desktop, deep),
        "windows/wsl-selector" => local_selector(id, Target::Wsl, deep),
        _ => Diagnostic::unknown(
            id,
            "unknown",
            "none",
            "Use internet tree for known resource IDs",
        ),
    }
}
fn local_binary() -> Diagnostic {
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
    match lifecycle::is_running() {
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
fn local_selector(id: &str, target: Target, deep: bool) -> Diagnostic {
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
            match lifecycle::is_running() {
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
                d.health=Health::Unknown;
                d.reason_code="WSL_CHANNEL_NOT_TESTED";
                d.next_action="internet diagnose windows/wsl-selector";
                if deep {
                    match crate::wsl::discover() {
                        Ok(Some(n)) => {
                            let actual=c["inbounds"][1]["listen"].as_str().unwrap_or("");
                            if actual!=n.gateway.to_string() {
                                d.health=Health::Failed;
                                d.reason_code="WSL_BINDING_STALE";
                                d.next_action="internet restart";
                            } else if crate::wsl::probe(&n).is_err() {
                                d.health=Health::Failed;
                                d.reason_code="WSL_PROXY_UNREACHABLE";
                                d.next_action="internet inspect windows/wsl-selector";
                            } else {
                                d.health=Health::Degraded;
                                d.reason_code="WSL_TRANSPORT_PASS_EGRESS_NOT_CHECKED";
                                d.source="wsl-tcp-connect";
                                d.scope="wsl_transport_only";
                            }
                        },
                        Ok(None) => { d.reason_code="WSL_NOT_INSTALLED"; },
                        Err(_) => { d.reason_code="WSL_NETWORK_READBACK_UNKNOWN"; }
                    }
                }
            } else if deep && d.health == Health::Healthy {
                let addr: SocketAddr = "127.0.0.1:2080".parse().expect("fixed loopback");
                if TcpStream::connect_timeout(&addr, Duration::from_millis(700)).is_err() {
                    d.health=Health::Failed;
                    d.reason_code="PROXY_LISTENER_UNREACHABLE";
                    d.next_action="internet inspect windows/sing-box";
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
    let begin = Instant::now();
    IDS.iter()
        .map(|id| {
            if begin.elapsed() > Duration::from_secs(10) {
                Diagnostic::unknown(id, "timeout", "none", "Retry specific resource inspect")
            } else {
                inspect(id, deep)
            }
        })
        .collect()
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
    fn no_duplicate_resource_ids() {
        let mut s = std::collections::HashSet::new();
        for id in IDS {
            assert!(s.insert(id));
        }
    }
}

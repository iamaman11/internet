//! Read-only operator presentation and ephemeral evidence for one menu session.
//! This is not a status cache: every line carrying previous proof is labelled
//! as a snapshot, and normal CLI status still uses current native readback.
use serde_json::Value;
use std::time::Instant;

#[derive(Clone, Copy)]
enum ResultKind { Pass, Failed, Unknown }

#[derive(Default)]
pub struct Session {
    wsl_state: Option<(String, Instant)>,
    wsl_egress: Option<(ResultKind, Instant)>,
    windows_egress: Option<(ResultKind, Instant)>,
}
fn ago(time: Instant) -> String {
    format!("{}s ago (session snapshot)", time.elapsed().as_secs())
}
fn outcome(code: i32) -> ResultKind {
    match code { 0 => ResultKind::Pass, 2 => ResultKind::Failed, _ => ResultKind::Unknown }
}
fn outcome_label(check: ResultKind) -> &'static str {
    match check { ResultKind::Pass => "PASS", ResultKind::Failed => "FAILED", ResultKind::Unknown => "UNKNOWN" }
}
impl Session {
    pub fn observe_wsl(&mut self, value: &Result<Value, &'static str>) {
        let state = value.as_ref().ok().and_then(|v| v["state"].as_str())
            .filter(|s| matches!(*s, "ON" | "OFF"))
            .unwrap_or("UNKNOWN").to_owned();
        if state != "ON" {
            self.wsl_egress = None;
        }
        self.wsl_state = Some((state, Instant::now()));
    }
    pub fn wsl_state(&self) -> String {
        match &self.wsl_state {
            Some((state, time)) => format!("{state} (last checked {}; not live-rechecked)", ago(*time)),
            None => "NOT CHECKED (4 -> 5: Ubuntu readback)".to_owned(),
        }
    }
    pub fn wsl_egress(&self) -> String {
        match self.wsl_egress {
            Some((result, time)) => format!("{} (WSL IPv4 HTTPS, last checked {}; not live-rechecked)", outcome_label(result), ago(time)),
            None => "NOT TESTED (8 -> 2: real WSL IPv4 HTTPS)".to_owned(),
        }
    }
    pub fn windows_egress(&self) -> String {
        match self.windows_egress {
            Some((result, time)) => format!("{} (desktop selector, last checked {}; not per-app proof)", outcome_label(result), ago(time)),
            None => "NOT TESTED (8 -> 1: desktop HTTPS; not each app)".to_owned(),
        }
    }
    pub fn command_finished(&mut self, args: &[String], code: i32) {
        let parts = args.iter().map(String::as_str).collect::<Vec<_>>();
        match parts.as_slice() {
            ["diagnose", "windows/wsl-tun"] | ["wsl", "tun", "diagnose"] =>
                self.wsl_egress = Some((outcome(code), Instant::now())),
            ["diagnose", "windows/desktop-selector"] =>
                self.windows_egress = Some((outcome(code), Instant::now())),
            ["wsl", "route", _] | ["wsl", "tun", "on"] | ["wsl", "tun", "off"] | ["wsl", "sync"] => {
                self.wsl_egress = None;
                self.wsl_state = None;
            },
            ["route", _] => self.windows_egress = None,
            ["windows-mode", _] | ["start"] | ["stop"] | ["restart"] => {
                self.windows_egress = None;
                self.wsl_egress = None;
                self.wsl_state = None;
            },
            _ => {}
        }
    }
}
fn yes(v: &Value, key: &str) -> &'static str {
    match v[key].as_bool() { Some(true) => "YES", Some(false) => "NO", None => "UNKNOWN" }
}
pub fn wsl_state_lines(v: &Value) -> Vec<String> {
    let guest = &v["guest"];
    let val = |key: &str| v[key].as_str().unwrap_or("UNKNOWN");
    let gval = |key: &str| guest[key].as_str().unwrap_or("UNKNOWN");
    let mut lines = vec![
        format!("WSL network:      {}", val("network")),
        format!("WireGuard:        {}", val("state")),
        format!("Route selected:   {}", val("route")),
        format!("Guest IPv4:       {}", gval("guest_ipv4")),
        format!("Handshake:        {}", yes(v,"handshake_observed")),
        format!("Kernel interface: {}", yes(guest,"kernel_interface")),
        format!("Packet route:     {}", yes(guest,"route_active")),
        format!("DNS redirected:   {}", yes(guest,"dns_redirected")),
        format!("IPv6 guard:       {} (not external IPv6 proof)", yes(guest,"ipv6_guard")),
        "Public IPv4:      NOT TESTED by status (run WSL Diagnose)".to_owned(),
    ];
    if val("state") != "ON" {
        lines.push(format!("Next: {}", val("next_action")));
    }
    lines
}
pub fn wsl_egress_lines(v: &Value) -> Vec<String> {
    let value = |key: &str| v[key].as_str().unwrap_or("UNKNOWN");
    vec![
        format!("WSL IPv4 HTTPS: {}", if v["ok"] == true {"PASS"} else {"FAILED"}),
        format!("Observed IPv4:  {}", value("ip4")),
        format!("Expected:       {}", value("expected")),
        format!("Reason:         {}", value("reason_code")),
        "Scope:          ordinary Ubuntu HTTPS through native WireGuard".to_owned(),
        "Not proved:     independent UDP, DNS and IPv6 egress".to_owned(),
        format!("Next:           {}", value("next_action")),
    ]
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn no_unsampled_egress_claim_and_explicit_snapshot_age() {
        let mut s = Session::default();
        assert!(s.wsl_state().contains("NOT CHECKED"));
        assert!(s.wsl_egress().contains("NOT TESTED"));
        s.observe_wsl(&Ok(json!({"state":"ON"})));
        assert!(s.wsl_state().contains("session snapshot"));
        assert!(s.wsl_egress().contains("NOT TESTED"));
        s.command_finished(&["diagnose".into(),"windows/wsl-tun".into()],0);
        assert!(s.wsl_egress().contains("PASS"));
        s.command_finished(&["wsl".into(),"route".into(),"warp-auto".into()],0);
        assert!(s.wsl_egress().contains("NOT TESTED"));
        assert!(s.wsl_state().contains("NOT CHECKED"));
    }
    #[test]
    fn stale_or_failed_wsl_never_preserves_prior_success() {
        let mut s = Session::default();
        s.observe_wsl(&Ok(json!({"state":"ON"})));
        s.command_finished(&["wsl".into(),"tun".into(),"diagnose".into()],0);
        s.observe_wsl(&Err("WSL_EXEC_UNRESPONSIVE"));
        assert!(s.wsl_state().starts_with("UNKNOWN"));
        assert!(s.wsl_egress().contains("NOT TESTED"));
    }
    #[test]
    fn wsl_proof_formats_without_claiming_ipv6_or_leaking_secrets() {
        let status=json!({"state":"ON","network":"WSL2 NAT","route":"direct-auto","guest":{
            "guest_ipv4":"172.26.23.199","kernel_interface":true,"route_active":true,
            "dns_redirected":true,"ipv6_guard":true},"handshake_observed":true});
        let text=wsl_state_lines(&status).join("\n");
        assert!(text.contains("WireGuard:        ON"));
        assert!(text.contains("not external IPv6 proof"));
        assert!(text.contains("NOT TESTED by status"));
        let diagnosis=json!({"ok":false,"ip4":"203.0.113.8","expected":"203.0.113.10",
            "reason_code":"WSL_NATIVE_IP_MISMATCH"});
        let text=wsl_egress_lines(&diagnosis).join("\n");
        assert!(text.contains("FAILED"));
        assert!(text.contains("203.0.113.8"));
    }
}

//! Task Scheduler is the single native lifecycle owner. No daemon/supervisor.
#[cfg(any(windows, test))]
use crate::model::NativeReadFailure;
#[cfg(windows)]
use crate::{TASK, config};
use std::path::Path;

// Win32 and Task Scheduler use invariant numeric HRESULTs; never parse
// localized schtasks/PowerShell error text to infer that a task is absent.
#[cfg(any(windows, test))]
fn scheduler_error(code: i32) -> &'static str {
    let category = match code as u32 {
        0x80070002 | 0x8004130f => NativeReadFailure::NotFound,
        0x80070005 => NativeReadFailure::AccessDenied,
        _ => NativeReadFailure::Failed,
    };
    category.task_code()
}

#[cfg(any(windows, test))]
fn task_state_running(state: i32) -> Result<bool, &'static str> {
    match state {
        4 => Ok(true),
        1..=3 => Ok(false),
        _ => Err("TASK_STATE_UNKNOWN"),
    }
}

/// Windows startup requires only the native managed task and the Desktop
/// selector. WSL selector health is diagnosed independently, never a
/// prerequisite for a usable Windows TUN or MCP connection.
#[cfg(any(windows, test))]
fn windows_start_gate(
    task_running: bool,
    desktop_selector: Result<(), &'static str>,
) -> Result<(), &'static str> {
    if !task_running {
        return Err("TASK_PROCESS_NOT_RUNNING");
    }
    desktop_selector
}

/// Read-only evidence permits at most one explicitly requested recovery.
/// TLS, HTTP, IP mismatch, and unobserved failures are not local-restart proof.
#[cfg(any(windows, test))]
fn recovery_eligible(
    proof: &crate::egress::Proof,
    repeated_timeout: bool,
) -> Result<bool, &'static str> {
    use crate::egress::Verdict;
    match (proof.verdict, proof.reason) {
        (Verdict::Pass, "DIRECT_PUBLIC_IP_CONFIRMED") => Ok(false),
        (
            Verdict::Failed,
            "CURL_SOURCE_ADDRESS_UNAVAILABLE_OBSERVED"
            | "HTTPS_CONNECT_FAILED"
            | "HTTPS_TRANSPORT_INTERRUPTED",
        ) => Ok(true),
        (Verdict::Unknown, "HTTPS_DEADLINE_OR_TIMEOUT") if repeated_timeout => Ok(true),
        _ => Err("RECOVERY_CAUSE_UNVERIFIED_NO_MUTATION"),
    }
}

/// Recovery is a task-only restart: it must not quietly migrate or rewrite
/// the optional WSL listener as part of the ordinary startup path.
#[cfg(any(windows, test))]
fn recovery_restart_config_stable(
    installed: &serde_json::Value,
    startup: &serde_json::Value,
) -> Result<(), &'static str> {
    if installed == startup {
        Ok(())
    } else {
        Err("RECOVERY_START_WOULD_REWRITE_CONFIG")
    }
}

pub fn task_owned(receipt: &str) -> bool {
    receipt.contains(&format!("<Command>{}\\sing-box.exe</Command>", crate::ROOT))
        && (receipt.contains(&format!(
            "run -c &quot;{}\\config\\sing-box.json&quot;",
            crate::ROOT
        )) || receipt.contains(&format!(r#"run -c "{}\config\sing-box.json""#, crate::ROOT)))
        && receipt.contains("<UserId>S-1-5-18</UserId>")
        && receipt.matches("<Exec>").count() == 1
}
#[cfg(windows)]
mod native {
    use super::*;
    use crate::{diagnostic, egress, model::Target, selector, tun};
    use serde_json::{Value, json};
    use std::{
        fs,
        io::Write,
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    struct RecoveryLease(std::path::PathBuf);
    impl Drop for RecoveryLease {
        fn drop(&mut self) {
            // Only this invocation's create_new sentinel can be removed.
            let _ = fs::remove_file(&self.0);
        }
    }
    fn recovery_lease() -> Result<RecoveryLease, &'static str> {
        let path = config::installed().with_file_name("recovery.inprogress");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|_| "RECOVERY_ALREADY_RUNNING_OR_INTERRUPTED")?;
        // Own the sentinel before any fallible write; a failed sync must not
        // strand the file and block every later deliberate recovery.
        let lease = RecoveryLease(path);
        file.write_all(b"one-shot owned recovery\n")
            .and_then(|_| file.sync_all())
            .map_err(|_| "RECOVERY_LOCK_WRITE_FAILED")?;
        Ok(lease)
    }

    /// Native read-only process inventory; bounded independently of status.
    fn owned_process_unique() -> Result<(), &'static str> {
        let script = r#"
$ErrorActionPreference = 'Stop'
try {
  $p = @(Get-CimInstance Win32_Process -Filter "Name='sing-box.exe'" -ErrorAction Stop)
  if ($p.Count -ne 1) { exit 7 }
  if (-not $p[0].ExecutablePath -or $p[0].ExecutablePath -ine $env:INTERNET_RECOVERY_EXE) { exit 8 }
  if (-not $p[0].CommandLine -or
    $p[0].CommandLine.IndexOf($env:INTERNET_RECOVERY_CONFIG, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { exit 9 }
  exit 0
} catch [System.UnauthorizedAccessException] { exit 5 }
catch { exit 6 }
"#;
        let mut child = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .env("INTERNET_RECOVERY_EXE", config::binary())
            .env("INTERNET_RECOVERY_CONFIG", config::installed())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "RECOVERY_PROCESS_READBACK_UNAVAILABLE")?;
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    return match status.code() {
                        Some(0) => Ok(()),
                        Some(5) => Err("RECOVERY_PROCESS_ACCESS_DENIED"),
                        Some(7) | Some(8) | Some(9) => Err("RECOVERY_PROCESS_OWNER_UNCONFIRMED"),
                        _ => Err("RECOVERY_PROCESS_READBACK_FAILED"),
                    };
                }
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("RECOVERY_PROCESS_READBACK_TIMEOUT");
                }
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("RECOVERY_PROCESS_READBACK_FAILED");
                }
            }
        }
    }

    fn recovery_native_gate(config: &Value) -> Result<(), &'static str> {
        if !is_running()? {
            return Err("RECOVERY_MANUAL_STOP_HONORED");
        }
        // Never take a Task/process from another owner or a saved-but-down TUN.
        owned_process_unique()?;
        native_check(&crate::config::installed())?;
        let state = tun::status()?;
        if state["managed_tun"] != true
            || state["native_tun_up"] != true
            || state["desired_native_match"] != true
            || state["native_tun_configured"] != true
        {
            return Err("RECOVERY_TUN_NATIVE_DRIFT");
        }
        let configured = crate::config::selected(config, Target::Desktop)?;
        if !configured.tag().starts_with("direct-") {
            return Err("RECOVERY_DIRECT_VM_IPV4_REQUIRED");
        }
        // A regular Windows start may normalize an obsolete WSL interface
        // binding. That is not authorized by a guarded network restart.
        // Check the exact startup candidate before ending the live Task.
        let startup = crate::wsl::windows_start_config(config)?;
        super::recovery_restart_config_stable(config, &startup)?;
        if selector::runtime_selected(Target::Desktop)? != configured {
            return Err("RECOVERY_DESKTOP_SELECTOR_DRIFT");
        }
        // Do not mutate while remote control is using the same TUN; a shared
        // destination IP does not prove control path independence.
        tun::recovery_control_independent()
            .map_err(|_| "RECOVERY_CONTROL_INDEPENDENCE_UNPROVEN")?;
        tun::recovery_selected_apps_quiescent()
    }

    /// Explicitly called by one CLI/menu operation; never from status/diagnose,
    /// Task Scheduler restart-on-failure or an unvalidated network event.
    pub fn recover(check_only: bool) -> Result<Value, &'static str> {
        let original = config::read(&config::installed())?;
        recovery_native_gate(&original)?;
        let first = diagnostic::selected_desktop_egress(
            original.clone(),
            Instant::now() + Duration::from_secs(8),
        );
        let repeated_timeout = first.verdict == egress::Verdict::Unknown
            && first.reason == "HTTPS_DEADLINE_OR_TIMEOUT";
        let proof = if repeated_timeout {
            diagnostic::selected_desktop_egress(
                original.clone(),
                Instant::now() + Duration::from_secs(8),
            )
        } else {
            first.clone()
        };
        let eligible = recovery_eligible(
            &proof,
            repeated_timeout && proof.reason == "HTTPS_DEADLINE_OR_TIMEOUT",
        )?;
        if check_only || !eligible {
            return Ok(
                json!({"ok":true,"changed":false,"eligible_for_one_recovery":eligible,
                "pre_https_reason":proof.reason,"pre_https_verdict":format!("{:?}",proof.verdict).to_uppercase(),
                "control":"INDEPENDENT_PHYSICAL_ROUTE_READBACK",
                "task":"OWNED_RUNNING","tun":"CONFIGURED_UP",
                "autonomous_interface_event":"UNSUPPORTED_NOT_PROVEN",
                "next_action":if eligible {"internet recover (explicit one-shot restart, may interrupt TUN traffic)"}
                    else {"No restart needed; native VM HTTPS already confirmed"}}),
            );
        }
        let _lease = recovery_lease()?;
        // Preflight again under the single-flight guard to reject concurrent
        // configuration/Task changes. No additional network probe is needed.
        if config::read(&config::installed())? != original {
            return Err("RECOVERY_CONFIG_CHANGED_BEFORE_ACTION");
        }
        recovery_native_gate(&original)?;
        if let Err(_) = stop() {
            // Restore task enablement only if the owned process is still live;
            // do not start an unknown or deliberately stopped process.
            if is_running() == Ok(true) {
                let _ = enable_task();
            }
            return Err("RECOVERY_STOP_UNCONFIRMED");
        }
        start().map_err(|_| "RECOVERY_START_UNCONFIRMED")?;
        let actual = config::read(&config::installed())?;
        if actual != original {
            return Err("RECOVERY_CONFIG_CHANGED_POST_ACTION");
        }
        recovery_native_gate(&actual).map_err(|_| "RECOVERY_NATIVE_POSTCHECK_FAILED")?;
        let post =
            diagnostic::selected_desktop_egress(actual, Instant::now() + Duration::from_secs(9));
        if post.verdict != egress::Verdict::Pass || post.reason != "DIRECT_PUBLIC_IP_CONFIRMED" {
            return Err("RECOVERY_POST_HTTPS_VM_IPV4_UNCONFIRMED");
        }
        Ok(json!({"ok":true,"changed":true,"restart_attempts":1,
            "pre_https_reason":proof.reason,"post_https_reason":post.reason,
            "http":"HTTPS_200","egress":"EXPECTED_VM_IPV4_CONFIRMED",
            "tun":"CONFIGURED_UP","control":"INDEPENDENT_PHYSICAL_ROUTE_READBACK",
            "autonomous_interface_event":"UNSUPPORTED_NOT_PROVEN",
            "scope":"native_desktop_proxy_ipv4_https_only_not_per_app_dns_udp_ipv6",
            "next_action":"Run independent Chrome/other-app physical HTTPS tests; record acceptance in #8"}))
    }
    fn command(bin: &str, args: &[&str]) -> Result<std::process::Output, &'static str> {
        Command::new(bin)
            .args(args)
            .output()
            .map_err(|_| "WINDOWS_NATIVE_COMMAND_UNAVAILABLE")
    }
    fn task_receipt() -> Result<Option<String>, &'static str> {
        let o = command("schtasks.exe", &["/Query", "/TN", TASK, "/XML"])?;
        if !o.status.success() {
            // A failed /Query is NOT proof that a task is missing. Ask native
            // COM for the invariant missing/denied error; do not guess from
            // exit code 1 or translated stderr.
            return match task_com_state() {
                Ok(None) => Ok(None),
                Ok(Some(_)) => Err("TASK_XML_READBACK_FAILED"),
                Err(reason) => Err(reason),
            };
        }
        let text = String::from_utf8_lossy(&o.stdout).into_owned();
        if !task_owned(&text) {
            return Err("TASK_OWNER_CONFLICT");
        }
        Ok(Some(text))
    }
    fn task_com_state() -> Result<Option<i32>, &'static str> {
        // The scheduler's COM State is an invariant integer enum, not
        // localized PowerShell output. The existing XML receipt verifies owner.
        use windows::{
            Win32::System::{
                Com::{
                    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
                    CoUninitialize,
                },
                TaskScheduler::ITaskService,
                Variant::VARIANT,
            },
            core::{BSTR, GUID},
        };
        struct ComSession;
        impl Drop for ComSession {
            fn drop(&mut self) {
                unsafe { CoUninitialize() };
            }
        }
        let _session = {
            // SAFETY: this CLI initializes COM on the calling thread and
            // balances each successful initialization on that same thread.
            unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
                .ok()
                .map_err(|_| "TASK_COM_INITIALIZE_FAILED")?;
            ComSession
        };
        // CLSID of the native Windows Task Scheduler service.
        let clsid = GUID::from_u128(0x0f87369f_a4e5_4cfc_bd3e_73e6154572dd);
        let service: ITaskService = unsafe { CoCreateInstance(&clsid, None, CLSCTX_INPROC_SERVER) }
            .map_err(|_| "TASK_COM_CONNECT_FAILED")?;
        let empty = VARIANT::default();
        let task = unsafe {
            service
                .Connect(&empty, &empty, &empty, &empty)
                .and_then(|_| service.GetFolder(&BSTR::from("\\")))
                .and_then(|folder| folder.GetTask(&BSTR::from(TASK)))
        }
        .map(Some)
        .or_else(|err| {
            if scheduler_error(err.code().0) == "TASK_NOT_INSTALLED" {
                Ok(None)
            } else {
                Err(scheduler_error(err.code().0))
            }
        })?;
        match task {
            Some(task) => unsafe { task.State() }
                .map(|state| Some(state.0))
                .map_err(|err| scheduler_error(err.code().0)),
            None => Ok(None),
        }
    }
    pub fn is_running() -> Result<bool, &'static str> {
        if task_receipt()?.is_none() {
            return Err("TASK_NOT_INSTALLED");
        }
        let state = task_com_state()?.ok_or("TASK_NOT_INSTALLED")?;
        super::task_state_running(state)
    }
    pub fn native_check(path: &Path) -> Result<(), &'static str> {
        let o = Command::new(config::binary())
            .arg("check")
            .arg("-c")
            .arg(path)
            .output()
            .map_err(|_| "SING_BOX_BINARY_MISSING")?;
        if !o.status.success() {
            return Err("SING_BOX_NATIVE_CHECK_FAILED");
        }
        Ok(())
    }
    fn other_processes() -> Result<bool, &'static str> {
        let o = command(
            "powershell.exe",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "@(Get-CimInstance Win32_Process -Filter \"Name='sing-box.exe'\").Count",
            ],
        )?;
        if !o.status.success() {
            return Err("PROCESS_INVENTORY_FAILED");
        }
        let n: String = String::from_utf8_lossy(&o.stdout).trim().into();
        n.parse::<u32>()
            .map(|n| n > 0)
            .map_err(|_| "PROCESS_INVENTORY_FAILED")
    }
    // Native sing-box validates the candidate before any firewall/config
    // mutation. An existing candidate file is never overwritten.
    fn validate_candidate(path: &Path, updated: &serde_json::Value) -> Result<(), &'static str> {
        let check_path = path
            .parent()
            .ok_or("CONFIG_PATH_INVALID")?
            .join("sing-box.wsl-check.json");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&check_path)
            .map_err(|_| "CONFIG_CHECK_CONFLICT")?;
        let write = serde_json::to_vec(updated)
            .map_err(|_| "CONFIG_SERIALIZE_FAILED")
            .and_then(|bytes| {
                file.write_all(&bytes)
                    .and_then(|_| file.sync_all())
                    .map_err(|_| "CONFIG_CHECK_WRITE_FAILED")
            });
        drop(file);
        if let Err(reason) = write {
            let _ = fs::remove_file(&check_path);
            return Err(reason);
        }
        let test = native_check(&check_path);
        let _ = fs::remove_file(&check_path);
        test
    }
    fn checked_replace(
        path: &Path,
        current: &serde_json::Value,
        updated: &serde_json::Value,
    ) -> Result<(), &'static str> {
        if current == updated {
            return Ok(());
        }
        validate_candidate(path, updated)?;
        config::write_checked(path, updated)
    }
    fn ensure_task() -> Result<(), &'static str> {
        if task_receipt()?.is_some() {
            Ok(())
        } else {
            Err("TASK_NOT_INSTALLED")
        }
    }
    fn enable_task() -> Result<(), &'static str> {
        ensure_task()?;
        let out = command("schtasks.exe", &["/Change", "/TN", TASK, "/Enable"])?;
        if !out.status.success() {
            return Err("TASK_ENABLE_REJECTED");
        }
        Ok(())
    }
    fn disable_task() -> Result<(), &'static str> {
        if task_receipt()?.is_none() {
            return Ok(());
        }
        let out = command("schtasks.exe", &["/Change", "/TN", TASK, "/Disable"])?;
        if !out.status.success() {
            return Err("TASK_DISABLE_REJECTED");
        }
        Ok(())
    }
    pub fn start() -> Result<(), &'static str> {
        let path = config::installed();
        let current = config::read(&path)?;
        if is_running()? {
            super::windows_start_gate(
                true,
                crate::selector::runtime_selected(crate::model::Target::Desktop).map(|_| ()),
            )?;
            // The existing native task owns lifecycle and recovery.
            // Do not require Ubuntu or the WSL selector for Windows startup.
            enable_task()?;
            return Ok(());
        }
        if other_processes()? {
            return Err("FOREIGN_SING_BOX_PROCESS");
        }
        // Windows starts without WSL. Preserve a live, native-owned WSL listener;
        // if its NAT gateway disappeared, restrict the optional inbound to loopback.
        let updated = crate::wsl::windows_start_config(&current)?;
        checked_replace(&path, &current, &updated)?;
        native_check(&path)?;
        enable_task()?;
        let o = command("schtasks.exe", &["/Run", "/TN", TASK])?;
        if !o.status.success() {
            return Err("TASK_START_REJECTED");
        }
        // A bounded safety ceiling, not a success timer. Return the exact
        // failing readiness condition; the WSL selector is not a Windows gate.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let running = is_running()?;
            let desktop = if running {
                crate::selector::runtime_selected(crate::model::Target::Desktop).map(|_| ())
            } else {
                Err("TASK_PROCESS_NOT_RUNNING")
            };
            let state = super::windows_start_gate(running, desktop);
            if state.is_ok() || Instant::now() >= deadline {
                return state;
            }
            thread::sleep(Duration::from_millis(200));
        }
    }
    /// Operator-requested WSL attach; never part of Windows startup.
    pub fn sync_wsl() -> Result<(), &'static str> {
        if is_running()? {
            return Err("WSL_SYNC_REQUIRES_STOP");
        }
        let network = crate::wsl::discover_for_start()?.ok_or("WSL_GUEST_UNAVAILABLE")?;
        let path = config::installed();
        let current = config::read(&path)?;
        let changed_gateway = config::with_wsl_gateway(&current, network.gateway)?;
        // WSL's authenticated TCP proxy predates the optional WireGuard TUN.
        // A machine without the U7 layer must retain the original sync path.
        let has_wg = crate::wsl_tun::split(&current)?.1.is_some();
        let interface = if has_wg {
            let (guest_public, windows_private, interface) =
                crate::wsl_tun_runtime::offline_rebind_material(&network)?;
            Some((guest_public, windows_private, interface))
        } else {
            None
        };
        let updated = if let Some((guest_public, windows_private, _)) = &interface {
            crate::wsl_tun::rebind_guest(
                &changed_gateway,
                network.guest,
                guest_public,
                windows_private,
            )?
        } else {
            changed_gateway
        };
        // All ownership/key/native-config checks happen BEFORE mutation.
        // A stale old interface GUID is accepted only if it is no longer
        // attached to any live adapter; foreign firewall rules are refused.
        validate_candidate(&path, &updated)?;
        let tcp_before = crate::wsl::firewall_snapshot()?;
        let wg_before = interface
            .as_ref()
            .map(|(_, _, name)| crate::wsl::wireguard_firewall_snapshot(&network, name))
            .transpose()?;
        if is_running()? {
            return Err("WSL_SYNC_TASK_STARTED_CONCURRENTLY");
        }
        let apply = (|| -> Result<(), &'static str> {
            crate::wsl::firewall_allow(&network)?;
            if let Some((_, _, name)) = &interface {
                crate::wsl::wireguard_firewall_allow(&network, name)?;
            }
            if is_running()? {
                return Err("WSL_SYNC_TASK_STARTED_CONCURRENTLY");
            }
            checked_replace(&path, &current, &updated)?;
            if config::read(&path)? != updated {
                return Err("WSL_SYNC_CONFIG_READBACK_MISMATCH");
            }
            Ok(())
        })();
        if let Err(original) = apply {
            let config_restored = match config::read(&path) {
                Ok(ref actual) if *actual == current => true,
                Ok(ref actual) if *actual == updated => {
                    checked_replace(&path, &updated, &current).is_ok()
                }
                _ => false,
            };
            let wg_restored = match (&interface, &wg_before) {
                (Some((_, _, name)), Some(before)) => {
                    crate::wsl::wireguard_firewall_restore(&network, name, before).is_ok()
                }
                (None, None) => true,
                _ => false,
            };
            let tcp_restored = crate::wsl::firewall_restore(&network, &tcp_before).is_ok();
            if !config_restored || !wg_restored || !tcp_restored {
                return Err("WSL_SYNC_ROLLBACK_UNCONFIRMED");
            }
            return Err(original);
        }
        Ok(())
    }
    pub fn stop() -> Result<(), &'static str> {
        let running = is_running()?;
        // Disable scheduled recovery BEFORE ending the task. Otherwise the
        // next native trigger would undo an explicit operator Stop.
        disable_task()?;
        if !running {
            return Ok(());
        }
        let o = command("schtasks.exe", &["/End", "/TN", TASK])?;
        if !o.status.success() {
            return Err("TASK_STOP_REJECTED");
        }
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if !is_running()? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("TASK_STOP_UNVERIFIED");
            }
            thread::sleep(Duration::from_millis(200));
        }
    }
    pub fn restart() -> Result<(), &'static str> {
        let path = config::installed();
        let original = config::read(&path)?;
        // Do not interrupt working Windows networking for a config that cannot
        // even pass the native sing-box parser. No WSL process is involved.
        native_check(&path)?;
        let was_running = is_running()?;
        if !was_running {
            return start();
        }
        stop()?;
        if start().is_ok() {
            return Ok(());
        }
        // Native start is allowed to normalize only its own legacy WSL
        // endpoint binding and optional local listener. This is not a
        // concurrent foreign config change; never roll it back to a broken
        // NIC-bound cold-boot configuration.
        let current = config::read(&path).map_err(|_| "TASK_RESTART_RECOVERY_UNCONFIRMED")?;
        let normalized = crate::wsl_tun::prepare_at_windows_start(&original)
            .map_err(|_| "TASK_RESTART_RECOVERY_UNCONFIRMED")?;
        if current != original
            && current != normalized
            && config::with_wsl_loopback(&normalized).as_ref().ok() != Some(&current)
        {
            return Err("TASK_RESTART_CONFIG_OWNER_CONFLICT");
        }
        // One bounded recovery through the same owned Task, with validated
        // current config. It never reinstates the obsolete WSL NIC binding.
        stop().map_err(|_| "TASK_RESTART_RECOVERY_UNCONFIRMED")?;
        if start().is_err() {
            return Err("TASK_RESTART_RECOVERY_UNCONFIRMED");
        }
        // Runtime is healthy again, but the initial restart did fail.
        Err("TASK_RESTART_RECOVERED")
    }
}
#[cfg(windows)]
pub use native::{is_running, native_check, recover, restart, start, stop, sync_wsl};

#[cfg(not(windows))]
pub fn recover(_: bool) -> Result<serde_json::Value, &'static str> {
    Err("WINDOWS_ONLY")
}

#[cfg(not(windows))]
pub fn is_running() -> Result<bool, &'static str> {
    Err("WINDOWS_ONLY")
}
#[cfg(not(windows))]
pub fn native_check(_: &Path) -> Result<(), &'static str> {
    Err("WINDOWS_ONLY")
}
#[cfg(not(windows))]
pub fn start() -> Result<(), &'static str> {
    Err("WINDOWS_ONLY")
}
#[cfg(not(windows))]
pub fn sync_wsl() -> Result<(), &'static str> {
    Err("WINDOWS_ONLY")
}
#[cfg(not(windows))]
pub fn stop() -> Result<(), &'static str> {
    Err("WINDOWS_ONLY")
}
#[cfg(not(windows))]
pub fn restart() -> Result<(), &'static str> {
    Err("WINDOWS_ONLY")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn owned() -> String {
        format!(
            r#"<Task><Principals><Principal><UserId>S-1-5-18</UserId></Principal></Principals><Actions><Exec><Command>{}\sing-box.exe</Command><Arguments>run -c &quot;{}\config\sing-box.json&quot;</Arguments></Exec></Actions></Task>"#,
            crate::ROOT,
            crate::ROOT
        )
    }
    #[test]
    fn only_exact_system_task_is_owned() {
        let receipt = owned();
        assert!(task_owned(&receipt));
        assert!(!task_owned(
            &receipt.replace("C:\\internet", "C:\\sing-box")
        ));
        assert!(!task_owned(&receipt.replace("S-1-5-18", "S-1-5-21")));
        assert!(!task_owned(&(receipt.clone() + "<Exec>foreign</Exec>")));
    }
    #[test]
    fn no_fallback_to_unowned_scheduler() {
        assert!(!task_owned(""));
        assert!(!task_owned("<Task><Actions><Exec /></Actions></Task>"));
    }
    #[test]
    fn windows_start_does_not_depend_on_wsl_selector() {
        assert_eq!(windows_start_gate(true, Ok(())), Ok(()));
        assert_eq!(
            windows_start_gate(false, Ok(())),
            Err("TASK_PROCESS_NOT_RUNNING")
        );
        assert_eq!(
            windows_start_gate(true, Err("SING_BOX_API_UNREACHABLE")),
            Err("SING_BOX_API_UNREACHABLE")
        );
    }
    #[test]
    fn task_state_is_numeric_and_fail_closed() {
        assert_eq!(task_state_running(4), Ok(true));
        for v in [1, 2, 3] {
            assert_eq!(task_state_running(v), Ok(false));
        }
        for v in [-1, 0, 5] {
            assert_eq!(task_state_running(v), Err("TASK_STATE_UNKNOWN"));
        }
    }
    #[test]
    fn scheduler_native_error_categories_are_not_localized() {
        assert_eq!(scheduler_error(0x8004130f_u32 as i32), "TASK_NOT_INSTALLED");
        assert_eq!(scheduler_error(0x80070002_u32 as i32), "TASK_NOT_INSTALLED");
        assert_eq!(scheduler_error(0x80070005_u32 as i32), "TASK_ACCESS_DENIED");
        assert_eq!(
            scheduler_error(0x8004131f_u32 as i32),
            "TASK_READBACK_FAILED"
        );
    }
    #[test]
    fn recovery_decision_is_fail_closed_and_never_uses_tls_or_unknown_as_permission() {
        use crate::egress::{Proof, Verdict};
        let probe = |verdict, reason| Proof { verdict, reason };
        assert_eq!(
            recovery_eligible(&probe(Verdict::Pass, "DIRECT_PUBLIC_IP_CONFIRMED"), false),
            Ok(false)
        );
        assert_eq!(
            recovery_eligible(&probe(Verdict::Failed, "HTTPS_CONNECT_FAILED"), false),
            Ok(true)
        );
        assert_eq!(
            recovery_eligible(
                &probe(Verdict::Failed, "CURL_SOURCE_ADDRESS_UNAVAILABLE_OBSERVED"),
                false
            ),
            Ok(true)
        );
        assert_eq!(
            recovery_eligible(&probe(Verdict::Unknown, "HTTPS_DEADLINE_OR_TIMEOUT"), false),
            Err("RECOVERY_CAUSE_UNVERIFIED_NO_MUTATION")
        );
        assert_eq!(
            recovery_eligible(&probe(Verdict::Unknown, "HTTPS_DEADLINE_OR_TIMEOUT"), true),
            Ok(true)
        );
        for reason in [
            "TLS_CERTIFICATE_REJECTED",
            "HTTPS_STATUS_NOT_SUCCESS",
            "DIRECT_IP_MISMATCH",
            "PROXY_AUTH_REJECTED",
        ] {
            assert_eq!(
                recovery_eligible(&probe(Verdict::Failed, reason), true),
                Err("RECOVERY_CAUSE_UNVERIFIED_NO_MUTATION")
            );
        }
    }

    #[test]
    fn recovery_refuses_startup_config_migration_before_stopping_task() {
        let installed =
            serde_json::json!({"inbounds": [], "endpoints": [{"bind_interface":"old-wsl"}]});
        assert_eq!(
            recovery_restart_config_stable(&installed, &installed),
            Ok(())
        );
        let normalized = serde_json::json!({"inbounds": [], "endpoints": [{}]});
        assert_eq!(
            recovery_restart_config_stable(&installed, &normalized),
            Err("RECOVERY_START_WOULD_REWRITE_CONFIG")
        );
    }
}

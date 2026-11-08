//! Task Scheduler is the single native lifecycle owner. No daemon/supervisor.
#[cfg(windows)]
use crate::{TASK, config};
use std::path::Path;

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
    use std::{
        fs,
        process::Command,
        thread,
        time::{Duration, Instant},
    };
    fn command(bin: &str, args: &[&str]) -> Result<std::process::Output, &'static str> {
        Command::new(bin)
            .args(args)
            .output()
            .map_err(|_| "WINDOWS_NATIVE_COMMAND_UNAVAILABLE")
    }
    fn task_receipt() -> Result<Option<String>, &'static str> {
        let o = command("schtasks.exe", &["/Query", "/TN", TASK, "/XML"])?;
        if !o.status.success() {
            return Ok(None);
        }
        let text = String::from_utf8_lossy(&o.stdout).into_owned();
        if !task_owned(&text) {
            return Err("TASK_OWNER_CONFLICT");
        }
        Ok(Some(text))
    }
    pub fn is_running() -> Result<bool, &'static str> {
        if task_receipt()?.is_none() {
            return Ok(false);
        }
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
        .map_err(|_| "TASK_READBACK_FAILED")?;
        let state = unsafe { task.State() }.map_err(|_| "TASK_READBACK_FAILED")?;
        super::task_state_running(state.0)
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
    // Native sing-box validates the candidate before the single config is written.
    fn checked_replace(
        path: &Path,
        current: &serde_json::Value,
        updated: &serde_json::Value,
    ) -> Result<(), &'static str> {
        if current == updated {
            return Ok(());
        }
        let check_path = path
            .parent()
            .ok_or("CONFIG_PATH_INVALID")?
            .join("sing-box.wsl-check.json");
        if check_path.exists() {
            return Err("CONFIG_CHECK_CONFLICT");
        }
        fs::write(
            &check_path,
            serde_json::to_vec(updated).map_err(|_| "CONFIG_SERIALIZE_FAILED")?,
        )
        .map_err(|_| "CONFIG_CHECK_WRITE_FAILED")?;
        let test = native_check(&check_path);
        let _ = fs::remove_file(&check_path);
        test?;
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
        let updated = config::with_wsl_gateway(&current, network.gateway)?;
        crate::wsl::firewall_allow(&network)?;
        checked_replace(&path, &current, &updated)
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
        let normalized = crate::wsl_tun::unbind_at_windows_start(&original)
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
pub use native::{is_running, native_check, restart, start, stop, sync_wsl};

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
}

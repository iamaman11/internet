//! Task Scheduler is the single native lifecycle owner. No daemon/supervisor.
#[cfg(windows)]
use crate::{TASK, config};
use std::path::Path;

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
        let o = command(
            "powershell.exe",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$t=Get-ScheduledTask -TaskName 'INTERNET-SingBox' -ErrorAction Stop; [string]$t.State",
            ],
        )?;
        if !o.status.success() {
            return Err("TASK_READBACK_FAILED");
        }
        match String::from_utf8_lossy(&o.stdout).trim() {
            "Running" => Ok(true),
            "Ready" | "Disabled" | "Queued" => Ok(false),
            _ => Err("TASK_STATE_UNKNOWN"),
        }
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
    fn ensure_task() -> Result<(), &'static str> {
        if task_receipt()?.is_some() {
            Ok(())
        } else {
            Err("TASK_NOT_INSTALLED")
        }
    }
    pub fn start() -> Result<(), &'static str> {
        let path = config::installed();
        let current = config::read(&path)?;
        if is_running()? {
            if crate::selector::runtime_selected(crate::model::Target::Desktop).is_ok()
                && crate::selector::runtime_selected(crate::model::Target::Wsl).is_ok()
            {
                return Ok(());
            }
            return Err("RUNNING_SING_BOX_UNHEALTHY");
        }
        if other_processes()? {
            return Err("FOREIGN_SING_BOX_PROCESS");
        }
        let network = crate::wsl::discover()?;
        if let Some(ref net) = network {
            let updated = config::with_wsl_gateway(&current, net.gateway)?;
            if updated != current {
                let check_path = path
                    .parent()
                    .ok_or("CONFIG_PATH_INVALID")?
                    .join("sing-box.wsl-check.json");
                if check_path.exists() {
                    return Err("CONFIG_CHECK_CONFLICT");
                }
                fs::write(
                    &check_path,
                    serde_json::to_vec(&updated).map_err(|_| "CONFIG_SERIALIZE_FAILED")?,
                )
                .map_err(|_| "CONFIG_CHECK_WRITE_FAILED")?;
                let test = native_check(&check_path);
                let _ = fs::remove_file(&check_path);
                test?;
                config::write_checked(&path, &updated)?;
            }
        }
        native_check(&path)?;
        ensure_task()?;
        if let Some(ref net) = network {
            crate::wsl::firewall_allow(net)?;
        }
        let o = command("schtasks.exe", &["/Run", "/TN", TASK])?;
        if !o.status.success() {
            return Err("TASK_START_REJECTED");
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if is_running()?
                && crate::selector::runtime_selected(crate::model::Target::Desktop).is_ok()
                && crate::selector::runtime_selected(crate::model::Target::Wsl).is_ok()
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("TASK_START_UNVERIFIED");
            }
            thread::sleep(Duration::from_millis(200));
        }
    }
    pub fn stop() -> Result<(), &'static str> {
        if !is_running()? {
            return Ok(());
        }
        let o = command("schtasks.exe", &["/End", "/TN", TASK])?;
        if !o.status.success() {
            return Err("TASK_STOP_REJECTED");
        }
        let deadline = Instant::now() + Duration::from_secs(5);
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
        stop()?;
        start()
    }
}
#[cfg(windows)]
pub use native::{is_running, native_check, restart, start, stop};

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
}

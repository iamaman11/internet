//! Task Scheduler is the single native lifecycle owner. No daemon/supervisor.
#[cfg(windows)]
use crate::{config, TASK};
use std::path::Path;

pub fn xml() -> String {
    // Fixed, canonical paths only: never install into legacy sing-box directories.
    format!(r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>INTERNET owned sing-box (manual start)</Description></RegistrationInfo>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><LogonType>ServiceAccount</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>false</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>
  <Actions Context="Author"><Exec><Command>{root}\sing-box.exe</Command><Arguments>run -c "{root}\config\sing-box.json"</Arguments><WorkingDirectory>{root}</WorkingDirectory></Exec></Actions>
</Task>"#, root = crate::ROOT)
}
pub fn task_owned(receipt: &str) -> bool {
    receipt.contains(&format!("<Command>{}\\sing-box.exe</Command>",crate::ROOT))
        && (receipt.contains(&format!("run -c &quot;{}\\config\\sing-box.json&quot;",crate::ROOT))
            || receipt.contains(&format!(r#"run -c "{}\config\sing-box.json""#,crate::ROOT)))
        && receipt.contains("<UserId>S-1-5-18</UserId>")
        && receipt.matches("<Exec>").count() == 1
}
#[cfg(windows)]
mod native {
    use super::*;
    use std::{fs, process::Command, thread, time::{Duration,Instant}};
    fn command(bin: &str, args: &[&str]) -> Result<std::process::Output,&'static str> {
        Command::new(bin).args(args).output().map_err(|_| "WINDOWS_NATIVE_COMMAND_UNAVAILABLE")
    }
    fn task_receipt() -> Result<Option<String>, &'static str> {
        let o=command("schtasks.exe",&["/Query","/TN",TASK,"/XML"])?;
        if !o.status.success() { return Ok(None); }
        let text = String::from_utf8_lossy(&o.stdout).into_owned();
        if !task_owned(&text) { return Err("TASK_OWNER_CONFLICT"); }
        Ok(Some(text))
    }
    pub fn is_running() -> Result<bool,&'static str> {
        if task_receipt()?.is_none() { return Ok(false); }
        let o=command("powershell.exe",&["-NoProfile","-NonInteractive","-Command",
            "$t=Get-ScheduledTask -TaskName 'INTERNET-SingBox' -ErrorAction Stop; [string]$t.State"])?;
        if !o.status.success() { return Err("TASK_READBACK_FAILED"); }
        match String::from_utf8_lossy(&o.stdout).trim() {
            "Running" => Ok(true),
            "Ready" | "Disabled" | "Queued" => Ok(false),
            _ => Err("TASK_STATE_UNKNOWN"),
        }
    }
    pub fn native_check(path: &Path) -> Result<(), &'static str> {
        let o=Command::new(config::binary()).arg("check").arg("-c").arg(path)
            .output().map_err(|_| "SING_BOX_BINARY_MISSING")?;
        if !o.status.success() { return Err("SING_BOX_NATIVE_CHECK_FAILED"); }
        Ok(())
    }
    fn other_processes() -> Result<bool,&'static str> {
        let o=command("powershell.exe",&["-NoProfile","-NonInteractive","-Command",
            "@(Get-CimInstance Win32_Process -Filter \"Name='sing-box.exe'\").Count"])?;
        if !o.status.success() { return Err("PROCESS_INVENTORY_FAILED"); }
        let n:String=String::from_utf8_lossy(&o.stdout).trim().into();
        n.parse::<u32>().map(|n| n>0).map_err(|_| "PROCESS_INVENTORY_FAILED")
    }
    fn ensure_task() -> Result<(), &'static str> {
        if task_receipt()?.is_some() { return Ok(()); }
        let task_file=Path::new(crate::ROOT).join("state").join("task.xml");
        fs::create_dir_all(task_file.parent().ok_or("TASK_PATH_INVALID")?)
            .map_err(|_| "TASK_XML_WRITE_FAILED")?;
        // Task Scheduler's XML import accepts UTF-16 LE with BOM.
        let mut bytes=vec![0xff,0xfe];
        for unit in xml().encode_utf16() { bytes.extend_from_slice(&unit.to_le_bytes()); }
        fs::write(&task_file,bytes).map_err(|_| "TASK_XML_WRITE_FAILED")?;
        let file=task_file.to_str().ok_or("TASK_PATH_INVALID")?;
        let o=command("schtasks.exe",&["/Create","/TN",TASK,"/XML",file])?;
        if !o.status.success() { return Err("TASK_CREATE_FAILED"); }
        if task_receipt()?.is_none() { return Err("TASK_CREATE_UNVERIFIED"); }
        Ok(())
    }
    pub fn start() -> Result<(), &'static str> {
        let path=config::installed();
        let _=config::read(&path)?;
        native_check(&path)?;
        if is_running()? {
            if crate::selector::runtime_selected(crate::model::Target::Desktop).is_ok()
                && crate::selector::runtime_selected(crate::model::Target::Wsl).is_ok() {
                return Ok(());
            }
            return Err("RUNNING_SING_BOX_UNHEALTHY");
        }
        if other_processes()? { return Err("FOREIGN_SING_BOX_PROCESS"); }
        ensure_task()?;
        let o=command("schtasks.exe",&["/Run","/TN",TASK])?;
        if !o.status.success() { return Err("TASK_START_REJECTED"); }
        let deadline=Instant::now()+Duration::from_secs(5);
        loop {
            if is_running()? && crate::selector::runtime_selected(crate::model::Target::Desktop).is_ok()
                && crate::selector::runtime_selected(crate::model::Target::Wsl).is_ok() { return Ok(()); }
            if Instant::now() >= deadline { return Err("TASK_START_UNVERIFIED"); }
            thread::sleep(Duration::from_millis(200));
        }
    }
    pub fn stop() -> Result<(), &'static str> {
        if !is_running()? { return Ok(()); }
        let o=command("schtasks.exe",&["/End","/TN",TASK])?;
        if !o.status.success() { return Err("TASK_STOP_REJECTED"); }
        let deadline=Instant::now()+Duration::from_secs(5);
        loop {
            if !is_running()? { return Ok(()); }
            if Instant::now()>=deadline { return Err("TASK_STOP_UNVERIFIED"); }
            thread::sleep(Duration::from_millis(200));
        }
    }
    pub fn restart() -> Result<(), &'static str> { stop()?;start() }
}
#[cfg(windows)]
pub use native::{is_running,native_check,start,stop,restart};

#[cfg(not(windows))]
pub fn is_running() -> Result<bool,&'static str> { Err("WINDOWS_ONLY") }
#[cfg(not(windows))]
pub fn native_check(_: &Path) -> Result<(),&'static str> { Err("WINDOWS_ONLY") }
#[cfg(not(windows))]
pub fn start() -> Result<(),&'static str> { Err("WINDOWS_ONLY") }
#[cfg(not(windows))]
pub fn stop() -> Result<(),&'static str> { Err("WINDOWS_ONLY") }
#[cfg(not(windows))]
pub fn restart() -> Result<(),&'static str> { Err("WINDOWS_ONLY") }

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn owns_only_one_exact_native_task() {
        let receipt=xml().replace('"', "&quot;");
        assert!(task_owned(&receipt));
        assert!(!task_owned(&receipt.replace("C:\\internet", "C:\\sing-box")));
        assert!(!task_owned(&receipt.replace("S-1-5-18","S-1-5-21")));
        assert!(!task_owned(&(receipt.clone()+"<Exec>foreign</Exec>")));
    }
    #[test] fn manual_only_no_startup_trigger() {
        let task=xml();
        assert!(!task.contains("<Triggers>"));
        assert!(task.contains("<AllowStartOnDemand>true</AllowStartOnDemand>"));
        assert!(task.contains("<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"));
    }
}

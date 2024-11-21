use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::Duration,
};

use anyhow::{Context, Result};
use chrono::Local;
use log::{error, info, warn};
use winreg::{
    enums::{HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS},
    RegKey,
};

#[derive(Debug)]
struct HardeningConfig {
    log_path: PathBuf,
    base_dir: PathBuf,
    backup_dir: PathBuf,
    logs_dir: PathBuf,
    current_date: String,
}

impl HardeningConfig {
    fn new() -> Self {
        let base_dir = PathBuf::from(r"C:\ProgramData\Infopercept\Hardening");
        Self {
            log_path: PathBuf::from(r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"),
            base_dir: base_dir.clone(),
            backup_dir: base_dir.join("Windows_Backup"),
            logs_dir: base_dir.join("Logs"),
            current_date: Local::now().format("%Y/%m/%d").to_string(),
        }
    }

    fn ensure_directories(&self) -> io::Result<()> {
        fs::create_dir_all(&self.base_dir)?;
        fs::create_dir_all(&self.backup_dir)?;
        fs::create_dir_all(&self.logs_dir)?;
        Ok(())
    }
}

struct SystemHardening {
    config: HardeningConfig,
}

impl SystemHardening {
    fn new() -> Self {
        Self {
            config: HardeningConfig::new(),
        }
    }

    fn init(&self) -> Result<()> {
        env_logger::init();
        self.config.ensure_directories()?;
        self.write_log("Starting")?;
        self.start_transcript()?;
        Ok(())
    }

    fn write_log(&self, message: &str) -> Result<()> {
        let timestamp = Local::now().format("%Y/%m/%d %H:%M:%S");
        let log_entry = format!(
            "{} active-response/bin/hardening-apply.exe: {}\n",
            timestamp, message
        );

        // Implement retry mechanism
        let max_retries = 5;
        let retry_wait = Duration::from_secs(1);
        
        for attempt in 0..max_retries {
            match OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.config.log_path)
            {
                Ok(mut file) => {
                    match file.write_all(log_entry.as_bytes()) {
                        Ok(_) => return Ok(()),
                        Err(e) => {
                            if attempt == max_retries - 1 {
                                return Err(e.into());
                            }
                        }
                    }
                }
                Err(e) => {
                    if attempt == max_retries - 1 {
                        return Err(e.into());
                    }
                }
            }
            thread::sleep(retry_wait);
        }
        
        Err(anyhow::anyhow!("Failed to write to log after maximum retries"))
    }

    fn start_transcript(&self) -> Result<()> {
        let transcript_path = self.config.logs_dir
            .join(format!("Hardening-Apply-Process-{}.log", self.config.current_date));
        
        Command::new("powershell")
            .args(&[
                "-Command",
                &format!("Start-Transcript -Path '{}'", transcript_path.display()),
            ])
            .output()
            .context("Failed to start transcript")?;
        
        Ok(())
    }

    fn stop_transcript(&self) -> Result<()> {
        Command::new("powershell")
            .args(&["-Command", "Stop-Transcript"])
            .output()
            .context("Failed to stop transcript")?;
        
        Ok(())
    }

    fn create_restore_point(&self) -> Result<()> {
        info!("Creating system restore point");
        
        let ps_script = r#"
            # Enable System Restore if it's not already enabled
            Enable-ComputerRestore -Drive "C:\"
            
            # Set restore point creation frequency to 0
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore" `
                -Name "SystemRestorePointCreationFrequency" -Value 0 -Type DWord
            
            # Check for existing restore points
            $existing = Get-ComputerRestorePoint | Where-Object { $_.Description -eq "Pre-Hardening Backup" }
            
            if (-not $existing) {
                Checkpoint-Computer -Description "Pre-Hardening Backup" -RestorePointType "MODIFY_SETTINGS"
            }
        "#;

        let script_path = self.config.base_dir.join("create_restore_point.ps1");
        fs::write(&script_path, ps_script)?;

        let output = Command::new("powershell")
            .args(&[
                "-ExecutionPolicy", "Bypass",
                "-NoProfile",
                "-File", script_path.to_str().unwrap(),
            ])
            .output()
            .context("Failed to execute PowerShell script")?;

        fs::remove_file(script_path)?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            warn!("Failed to create restore point: {}", error);
            return Err(anyhow::anyhow!("Failed to create restore point"));
        }

        Ok(())
    }

    fn apply_registry_settings(&self) -> Result<()> {
        info!("Applying registry hardening settings");

        // Define all registry settings
        let registry_settings = [
            // Windows Defender settings
            (r"Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", "26190899-1602-49E8-8B27-eB1D0A1CE869", 1u32),
            (r"Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", "3B576869-A4EC-4529-8536-B80A7769E899", 1u32),
            // Screen saver settings
            (r"Software\Policies\Microsoft\Windows\Control Panel\Desktop", "ScreenSaverIsSecure", 1u32),
            (r"Software\Policies\Microsoft\Windows\Control Panel\Desktop", "ScreenSaveActive", 1u32),
            // Network settings
            (r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "DisableIPSourceRouting", 2u32),
            // ... Add all other registry settings from the PowerShell script
        ];

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

        for (path, name, value) in registry_settings.iter() {
            match hklm.create_subkey_with_flags(path, KEY_ALL_ACCESS) {
                Ok((key, _)) => {
                    if let Err(e) = key.set_value(name, value) {
                        warn!("Failed to set registry value {}/{}: {}", path, name, e);
                    }
                }
                Err(e) => warn!("Failed to open/create registry key {}: {}", path, e),
            }
        }

        Ok(())
    }

    fn backup_registry(&self) -> Result<()> {
        info!("Backing up registry keys");
        
        let backup_paths = [
            (r"SOFTWARE\Policies", "Policies_Backup.reg"),
            (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "Winlogon_Backup.reg"),
        ];

        for (path, filename) in backup_paths.iter() {
            let output = Command::new("reg")
                .args(&[
                    "export",
                    path,
                    &self.config.backup_dir.join(filename).to_string_lossy(),
                    "/y",
                ])
                .output()
                .with_context(|| format!("Failed to backup registry key: {}", path))?;

            if !output.status.success() {
                warn!("Failed to backup registry key: {}", path);
            }
        }

        // Export Group Policy
        Command::new("gpresult")
            .args(&["/h", &self.config.backup_dir.join("GroupPolicyBackup.html").to_string_lossy()])
            .output()
            .context("Failed to export Group Policy")?;

        Ok(())
    }

    fn download_hardening_tools(&self) -> Result<()> {
        info!("Downloading hardening tools");

        // Download and extract hardening tools
        let download_url = "https://github.com/bhaveshpa-icpl/Hardening-windows/archive/refs/heads/main.zip";
        let zip_path = self.config.base_dir.join("main.zip");
        
        Command::new("powershell")
            .args(&[
                "-Command",
                &format!(
                    "Invoke-WebRequest -Uri '{}' -OutFile '{}'",
                    download_url,
                    zip_path.display()
                ),
            ])
            .output()
            .context("Failed to download hardening tools")?;

        // Extract zip file
        Command::new("powershell")
            .args(&[
                "-Command",
                &format!(
                    "Expand-Archive -Path '{}' -DestinationPath '{}'",
                    zip_path.display(),
                    self.config.base_dir.join("main").display()
                ),
            ])
            .output()
            .context("Failed to extract hardening tools")?;

        Ok(())
    }

    fn manage_services(&self) -> Result<()> {
        info!("Managing Wazuh service");

        // Stop Wazuh service
        Command::new("net")
            .args(&["stop", "WazuhSvc"])
            .output()
            .context("Failed to stop Wazuh service")?;

        thread::sleep(Duration::from_secs(5));

        // Start Wazuh service
        Command::new("net")
            .args(&["start", "WazuhSvc"])
            .output()
            .context("Failed to start Wazuh service")?;

        // Verify service status
        let status = Command::new("powershell")
            .args(&[
                "-Command",
                "(Get-Service -Name 'WazuhSvc').Status",
            ])
            .output()
            .context("Failed to get service status")?;

        let status_str = String::from_utf8_lossy(&status.stdout).trim().to_string();
        if status_str != "Running" {
            warn!("Wazuh service is not running. Current status: {}", status_str);
        }

        Ok(())
    }

    fn cleanup(&self) -> Result<()> {
        info!("Cleaning up temporary files");

        // Remove temporary files
        if let Ok(_) = fs::remove_file(self.config.base_dir.join("main.zip")) {
            info!("Removed main.zip");
        }
        
        if let Ok(_) = fs::remove_dir_all(self.config.base_dir.join("main")) {
            info!("Removed main directory");
        }

        // Move log files
        let log_pattern = "hardeningkitty_*";
        for entry in fs::read_dir(".")? {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with(log_pattern))
                    .unwrap_or(false)
                {
                    if let Err(e) = fs::rename(&path, self.config.logs_dir.join(path.file_name().unwrap())) {
                        warn!("Failed to move log file: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    fn run(&self) -> Result<()> {
        self.init()?;
        
        info!("Starting system hardening process");
        
        // Create restore point
        if let Err(e) = self.create_restore_point() {
            warn!("Failed to create restore point: {}", e);
        }

        // Backup registry
        if let Err(e) = self.backup_registry() {
            warn!("Failed to backup registry: {}", e);
        }

        // Download and extract hardening tools
        if let Err(e) = self.download_hardening_tools() {
            error!("Failed to download hardening tools: {}", e);
        }

        // Apply registry settings
        if let Err(e) = self.apply_registry_settings() {
            error!("Failed to apply registry settings: {}", e);
        }

        // Cleanup
        if let Err(e) = self.cleanup() {
            warn!("Failed to cleanup: {}", e);
        }

        // Manage services
        if let Err(e) = self.manage_services() {
            warn!("Failed to manage services: {}", e);
        }

        self.stop_transcript()?;
        self.write_log("Ended")?;
        info!("System hardening completed successfully");

        Ok(())
    }
}

fn main() -> Result<()> {
    let hardening = SystemHardening::new();
    hardening.run()?;
    Ok(())
}
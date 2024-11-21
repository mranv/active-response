

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
}

impl HardeningConfig {
    fn new() -> Self {
        let base_dir = PathBuf::from(r"C:\ProgramData\Infopercept\Hardening");
        Self {
            log_path: PathBuf::from(r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"),
            base_dir: base_dir.clone(),
            backup_dir: base_dir.join("Windows_Backup"),
            logs_dir: base_dir.join("Logs"),
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
        self.write_log("Starting hardening process")?;
        Ok(())
    }

    fn write_log(&self, message: &str) -> Result<()> {
        let timestamp = Local::now().format("%Y/%m/%d %H:%M:%S");
        let log_entry = format!(
            "{} active-response/bin/hardening-apply.exe: {}\n",
            timestamp, message
        );

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.config.log_path)
            .context("Failed to open log file")?;

        file.write_all(log_entry.as_bytes())
            .context("Failed to write to log file")?;

        Ok(())
    }

    fn create_restore_point(&self) -> Result<()> {
        info!("Creating system restore point");
        
        // PowerShell script content for creating restore point
        let ps_script = r#"
            # Enable System Restore if it's not already enabled
            Enable-ComputerRestore -Drive "C:\"
            
            # Set the restore point creation frequency to 0 (no minimum interval)
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Value 0 -Type DWord
            
            # Check for existing restore points with our description
            $existing = Get-ComputerRestorePoint | Where-Object { $_.Description -eq "Pre-Hardening Backup" }
            
            if (-not $existing) {
                # Create the restore point
                Checkpoint-Computer -Description "Pre-Hardening Backup" -RestorePointType "MODIFY_SETTINGS"
                Write-Output "Restore point created successfully"
            } else {
                Write-Output "Restore point already exists"
            }
        "#;

        // Create a temporary PowerShell script file
        let script_path = self.config.base_dir.join("create_restore_point.ps1");
        fs::write(&script_path, ps_script)?;

        // Execute PowerShell script with elevated privileges
        let output = Command::new("powershell")
            .args(&[
                "-ExecutionPolicy",
                "Bypass",
                "-NoProfile",
                "-File",
                script_path.to_str().unwrap(),
            ])
            .output()
            .context("Failed to execute PowerShell script")?;

        // Clean up the temporary script
        fs::remove_file(script_path)?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            warn!("Failed to create restore point: {}", error);
            return Err(anyhow::anyhow!("Failed to create restore point"));
        }

        info!("Restore point operation completed");
        Ok(())
    }

    fn apply_registry_settings(&self) -> Result<()> {
        info!("Applying registry hardening settings");

        let registry_settings = [
            (
                r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
                "EnableScriptBlockLogging",
                1u32,
            ),
            (
                r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
                "DoHPolicy",
                2u32,
            ),
            // Add your registry settings here
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

        Ok(())
    }

    fn manage_services(&self) -> Result<()> {
        info!("Managing services");

        // Using Command to manage services
        let services = ["WazuhSvc"]; // Add more services as needed

        for service in services.iter() {
            // Stop service
            let stop_output = Command::new("net")
                .args(&["stop", service])
                .output()
                .with_context(|| format!("Failed to stop service: {}", service))?;

            if !stop_output.status.success() {
                warn!("Failed to stop service: {}", service);
            }

            thread::sleep(Duration::from_secs(5));

            // Start service
            let start_output = Command::new("net")
                .args(&["start", service])
                .output()
                .with_context(|| format!("Failed to start service: {}", service))?;

            if !start_output.status.success() {
                warn!("Failed to start service: {}", service);
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

        // Apply registry settings
        if let Err(e) = self.apply_registry_settings() {
            error!("Failed to apply registry settings: {}", e);
        }

        // Manage services
        if let Err(e) = self.manage_services() {
            warn!("Failed to manage services: {}", e);
        }

        self.write_log("Hardening process completed")?;
        info!("System hardening completed successfully");

        Ok(())
    }
}

fn main() -> Result<()> {
    let hardening = SystemHardening::new();
    hardening.run()?;
    Ok(())
}
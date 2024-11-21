use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::PathBuf,
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
enum RegistryValueType {
    DWord(u32),
    String(String),
}


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

    // Define registry settings with proper value types
    let registry_settings: Vec<(&str, &str, RegistryValueType)> = vec![
        // Windows Defender ASR Rules
        (r"Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", "26190899-1602-49E8-8B27-eB1D0A1CE869", RegistryValueType::DWord(1)),
        (r"Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", "3B576869-A4EC-4529-8536-B80A7769E899", RegistryValueType::DWord(1)),
        (r"Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", RegistryValueType::DWord(1)),
        (r"Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84", RegistryValueType::DWord(1)),
        (r"Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C", RegistryValueType::DWord(1)),
        (r"Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B", RegistryValueType::DWord(1)),
        (r"Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", "9E6C4E1F-7D60-472F-bA1A-A39EF669E4B2", RegistryValueType::DWord(1)),
        (r"Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4", RegistryValueType::DWord(1)),
        (r"Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", RegistryValueType::DWord(1)),
        (r"Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", "D3E037E1-3EB8-44C8-A917-57927947596D", RegistryValueType::DWord(1)),
        (r"Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", RegistryValueType::DWord(1)),

        // Screen Saver Settings
        (r"Software\Policies\Microsoft\Windows\Control Panel\Desktop", "ScreenSaverIsSecure", RegistryValueType::DWord(1)),
        (r"Software\Policies\Microsoft\Windows\Control Panel\Desktop", "ScreenSaveActive", RegistryValueType::DWord(1)),
        
        // Network Settings
        (r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "DisableIPSourceRouting", RegistryValueType::DWord(2)),
        (r"SYSTEM\CurrentControlSet\Services\SharedAccess", "Start", RegistryValueType::DWord(4)),
        
        // Network Provider Settings
        (r"SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths", r"\\*\NETLOGON", 
            RegistryValueType::String("RequireMutualAuthentication=1, RequireIntegrity=1".to_string())),
        (r"SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths", r"\\*\SYSVOL", 
            RegistryValueType::String("RequireMutualAuthentication=1, RequireIntegrity=1".to_string())),

        // WCN Registrars
        (r"SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars", "DisableFlashConfigRegistrar", RegistryValueType::DWord(0)),
        (r"SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars", "DisableInBand802DOT11Registrar", RegistryValueType::DWord(0)),
        (r"SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars", "DisableUPnPRegistrar", RegistryValueType::DWord(0)),
        (r"SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars", "DisableWPDRegistrar", RegistryValueType::DWord(0)),
        (r"SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars", "EnableRegistrars", RegistryValueType::DWord(0)),

        // System Policies
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "DisableBkGndGroupPolicy", RegistryValueType::DWord(0)),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ProcessCreationIncludeCmdLine_Enabled", RegistryValueType::DWord(1)),

        // Windows Error Reporting
        (r"SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting", "Disabled", RegistryValueType::DWord(1)),

        // PowerShell Settings
        (r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging", RegistryValueType::DWord(1)),

        // DNS Client Settings
        (r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "DoHPolicy", RegistryValueType::DWord(2)),

        // Printer Settings
        (r"SOFTWARE\Policies\Microsoft\Windows NT\Printers", "RegisterSpoolerRemoteRpcEndPoint", RegistryValueType::DWord(2)),
        (r"SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint", "NoWarningNoElevationOnInstall", RegistryValueType::DWord(0)),
        (r"SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint", "RestrictDriverInstallationToAdministrators", RegistryValueType::DWord(1)),

        // Device Metadata
        (r"SOFTWARE\Policies\Microsoft\Windows\Device Metadata", "PreventDeviceMetadataFromNetwork", RegistryValueType::DWord(1)),

        // Windows Update Settings
        (r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "ManagePreviewBuilds", RegistryValueType::DWord(0)),

        // Sandbox Settings
        (r"SOFTWARE\Policies\Microsoft\Windows\Sandbox", "AllowClipboardRedirection", RegistryValueType::DWord(0)),
        (r"SOFTWARE\Policies\Microsoft\Windows\Sandbox", "AllowNetworking", RegistryValueType::DWord(0)),

        // Windows Defender Real-time Protection
        (r"Software\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableScriptScanning", RegistryValueType::DWord(0)),

        // Winlogon Settings
        (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "ScreenSaverGracePeriod", RegistryValueType::DWord(0)),
        (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AllocateDASD", RegistryValueType::String("0".to_string())),
        (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "SCRemoveOption", RegistryValueType::String("1".to_string())),
        (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon", RegistryValueType::String("0".to_string())),

        // Additional Settings
        (r"Software\Policies\Microsoft\Windows\CloudContent", "DisableConsumerAccountStateContent", RegistryValueType::DWord(1)),
        (r"Software\Policies\Microsoft\Windows\CloudContent", "DisableThirdPartySuggestions", RegistryValueType::DWord(1)),
        (r"Software\Policies\Microsoft\Windows\DataCollection", "DisableOneSettingsDownloads", RegistryValueType::DWord(1)),
        (r"Software\Policies\Microsoft\Windows\DataCollection", "EnableOneSettingsAuditing", RegistryValueType::DWord(1)),
        (r"Software\Policies\Microsoft\Windows\DataCollection", "LimitDiagnosticLogCollection", RegistryValueType::DWord(1)),
        (r"Software\Policies\Microsoft\Windows\DataCollection", "LimitDumpCollection", RegistryValueType::DWord(1)),
        (r"SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config", "AutoConnectAllowedOEM", RegistryValueType::DWord(0)),
        (r"Software\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated", RegistryValueType::DWord(0)),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoInPlaceSharing", RegistryValueType::DWord(1)),
        (r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "NullSessionPipes", 
            RegistryValueType::String("netlogon,samr,lsarpc".to_string())),
    ];

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    for (path, name, value) in registry_settings.iter() {
        info!("Setting registry key: {}\\{}", path, name);
        match hklm.create_subkey_with_flags(path, KEY_ALL_ACCESS) {
            Ok((key, _)) => {
                let result = match value {
                    RegistryValueType::DWord(dword_value) => {
                        key.set_value(name, dword_value)
                    },
                    RegistryValueType::String(string_value) => {
                        key.set_value(name, string_value)
                    }
                };

                if let Err(e) = result {
                    warn!("Failed to set registry value {}/{}: {}", path, name, e);
                }
            }
            Err(e) => warn!("Failed to open/create registry key {}: {}", path, e),
        }
    }

    info!("Registry settings applied successfully");
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
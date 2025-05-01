use std::error::Error;
use std::fs;
use std::io::Write;
use std::process::Command;
use crate::explorer::get_executable_path;

pub fn install_integration() -> Result<(), Box<dyn Error>> {
    let exe_path = get_executable_path()?;
    let exe_path_str = exe_path.to_string_lossy().to_string();
    
    // Get user's Services directory
    let home_dir = dirs::home_dir().ok_or("Failed to get home directory")?;
    let services_dir = home_dir.join("Library/Services");
    
    // Create directory if it doesn't exist
    fs::create_dir_all(&services_dir)?;
    
    // Create "Encrypt with ZeroVault.workflow" directory
    let encrypt_workflow_dir = services_dir.join("Encrypt with ZeroVault.workflow");
    let encrypt_contents_dir = encrypt_workflow_dir.join("Contents");
    let encrypt_macos_dir = encrypt_contents_dir.join("MacOS");
    
    fs::create_dir_all(&encrypt_macos_dir)?;
    
    // Create Info.plist for encryption workflow
    let encrypt_info_plist = encrypt_contents_dir.join("Info.plist");
    let encrypt_info_content = format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.zerovault.encrypt</string>
    <key>CFBundleName</key>
    <string>Encrypt with ZeroVault</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>NSServices</key>
    <array>
        <dict>
            <key>NSMenuItem</key>
            <dict>
                <key>default</key>
                <string>Encrypt with ZeroVault</string>
            </dict>
            <key>NSMessage</key>
            <string>runWorkflowAsService</string>
            <key>NSRequiredContext</key>
            <dict>
                <key>NSApplicationIdentifier</key>
                <string>com.apple.finder</string>
            </dict>
            <key>NSSendFileTypes</key>
            <array>
                <string>public.item</string>
            </array>
        </dict>
    </array>
</dict>
</plist>"#);
    
    fs::write(&encrypt_info_plist, encrypt_info_content)?;
    
    // Create executable script for encryption
    let encrypt_exec = encrypt_macos_dir.join("encrypt");
    let encrypt_script = format!(r#"#!/bin/bash
# Get selected files from macOS Services
for f in "$@"; do
  "{}" encrypt "$f"
done
"#, exe_path_str);
    
    let mut encrypt_file = fs::File::create(&encrypt_exec)?;
    encrypt_file.write_all(encrypt_script.as_bytes())?;
    
    // Make script executable
    let _ = Command::new("chmod")
        .arg("+x")
        .arg(&encrypt_exec)
        .output()?;
    
    // Create "Decrypt with ZeroVault.workflow"
    let decrypt_workflow_dir = services_dir.join("Decrypt with ZeroVault.workflow");
    let decrypt_contents_dir = decrypt_workflow_dir.join("Contents");
    let decrypt_macos_dir = decrypt_contents_dir.join("MacOS");
    
    fs::create_dir_all(&decrypt_macos_dir)?;
    
    // Create Info.plist for decryption workflow
    let decrypt_info_plist = decrypt_contents_dir.join("Info.plist");
    let decrypt_info_content = format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.zerovault.decrypt</string>
    <key>CFBundleName</key>
    <string>Decrypt with ZeroVault</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>NSServices</key>
    <array>
        <dict>
            <key>NSMenuItem</key>
            <dict>
                <key>default</key>
                <string>Decrypt with ZeroVault</string>
            </dict>
            <key>NSMessage</key>
            <string>runWorkflowAsService</string>
            <key>NSRequiredContext</key>
            <dict>
                <key>NSApplicationIdentifier</key>
                <string>com.apple.finder</string>
            </dict>
            <key>NSSendFileTypes</key>
            <array>
                <string>public.data</string>
            </array>
        </dict>
    </array>
</dict>
</plist>"#);
    
    fs::write(&decrypt_info_plist, decrypt_info_content)?;
    
    // Create executable script for decryption
    let decrypt_exec = decrypt_macos_dir.join("decrypt");
    let decrypt_script = format!(r#"#!/bin/bash
# Get selected files from macOS Services
for f in "$@"; do
  # Only process .vault files
  if [[ "$f" == *.vault ]]; then
    "{}" decrypt "$f"
  fi
done
"#, exe_path_str);
    
    let mut decrypt_file = fs::File::create(&decrypt_exec)?;
    decrypt_file.write_all(decrypt_script.as_bytes())?;
    
    // Make script executable
    let _ = Command::new("chmod")
        .arg("+x")
        .arg(&decrypt_exec)
        .output()?;
    
    // Restart Finder to apply changes
    let _ = Command::new("killall")
        .arg("Finder")
        .output();
    
    Ok(())
}

pub fn uninstall_integration() -> Result<(), Box<dyn Error>> {
    // Get user's Services directory
    let home_dir = dirs::home_dir().ok_or("Failed to get home directory")?;
    let services_dir = home_dir.join("Library/Services");
    
    // Remove workflow directories
    let encrypt_workflow = services_dir.join("Encrypt with ZeroVault.workflow");
    let decrypt_workflow = services_dir.join("Decrypt with ZeroVault.workflow");
    
    if encrypt_workflow.exists() {
        fs::remove_dir_all(&encrypt_workflow)?;
    }
    
    if decrypt_workflow.exists() {
        fs::remove_dir_all(&decrypt_workflow)?;
    }
    
    // Restart Finder to apply changes
    let _ = Command::new("killall")
        .arg("Finder")
        .output();
    
    Ok(())
}
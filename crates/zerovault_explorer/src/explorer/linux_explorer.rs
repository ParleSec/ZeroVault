use std::error::Error;
use std::fs;
use std::io::Write;
use std::process::Command;
use std::path::Path;
use crate::explorer::get_executable_path;

pub fn install_integration() -> Result<(), Box<dyn Error>> {
    let exe_path = get_executable_path()?;
    let exe_path_str = exe_path.to_string_lossy().to_string();
    
    // Get user's local share directory (per XDG spec)
    let data_dir = dirs::data_local_dir().ok_or("Could not determine local data directory")?;
    
    // Paths for Nautilus scripts
    let nautilus_scripts_dir = data_dir.join("nautilus/scripts");
    fs::create_dir_all(&nautilus_scripts_dir)?;
    
    // Create "Encrypt with ZeroVault" script
    let encrypt_script_path = nautilus_scripts_dir.join("Encrypt with ZeroVault");
    let encrypt_script = format!(r#"#!/bin/bash
# Nautilus script for ZeroVault encryption
if [ $# -eq 0 ]; then
  # Use NAUTILUS_SCRIPT_SELECTED_FILE_PATHS if no args
  while read file; do
    "{}" encrypt "$file"
  done < <(echo "$NAUTILUS_SCRIPT_SELECTED_FILE_PATHS" | tr '\n' '\0' | xargs -0 -n1 echo)
else
  # Use arguments directly
  for file in "$@"; do
    "{}" encrypt "$file"
  done
fi
"#, exe_path_str, exe_path_str);
    
    let mut encrypt_file = fs::File::create(&encrypt_script_path)?;
    encrypt_file.write_all(encrypt_script.as_bytes())?;
    
    // Create "Decrypt with ZeroVault" script
    let decrypt_script_path = nautilus_scripts_dir.join("Decrypt with ZeroVault");
    let decrypt_script = format!(r#"#!/bin/bash
# Nautilus script for ZeroVault decryption
if [ $# -eq 0 ]; then
  # Use NAUTILUS_SCRIPT_SELECTED_FILE_PATHS if no args
  while read file; do
    # Only process .vault files
    if [[ "$file" == *.vault ]]; then
      "{}" decrypt "$file"
    fi
  done < <(echo "$NAUTILUS_SCRIPT_SELECTED_FILE_PATHS" | tr '\n' '\0' | xargs -0 -n1 echo)
else
  # Use arguments directly
  for file in "$@"; do
    # Only process .vault files
    if [[ "$file" == *.vault ]]; then
      "{}" decrypt "$file"
    fi
  done
fi
"#, exe_path_str, exe_path_str);
    
    let mut decrypt_file = fs::File::create(&decrypt_script_path)?;
    decrypt_file.write_all(decrypt_script.as_bytes())?;
    
    // Make scripts executable
    let _ = Command::new("chmod")
        .arg("+x")
        .arg(&encrypt_script_path)
        .output()?;
    
    let _ = Command::new("chmod")
        .arg("+x")
        .arg(&decrypt_script_path)
        .output()?;
    
    // Create similar scripts for Dolphin (KDE file manager)
    install_dolphin_integration(&exe_path_str, &data_dir)?;
    
    // Create .desktop file for .vault mime type
    install_mime_integration(&exe_path_str, &data_dir)?;
    
    Ok(())
}

fn install_dolphin_integration(exe_path: &str, data_dir: &Path) -> Result<(), Box<dyn Error>> {
    let dolphin_service_dir = data_dir.join("kservices5/ServiceMenus");
    fs::create_dir_all(&dolphin_service_dir)?;
    
    // Create .desktop file for Dolphin service menu
    let desktop_file_path = dolphin_service_dir.join("zerovault.desktop");
    let desktop_file_content = format!(r#"[Desktop Entry]
Type=Service
X-KDE-ServiceTypes=KonqPopupMenu/Plugin
MimeType=application/octet-stream;
Actions=encryptFile;decryptFile;

[Desktop Action encryptFile]
Name=Encrypt with ZeroVault
Icon=document-encrypt
Exec="{}" encrypt %f

[Desktop Action decryptFile]
Name=Decrypt with ZeroVault
Icon=document-decrypt
Exec="{}" decrypt %f
"#, exe_path, exe_path);
    
    fs::write(&desktop_file_path, desktop_file_content)?;
    
    Ok(())
}

fn install_mime_integration(exe_path: &str, data_dir: &Path) -> Result<(), Box<dyn Error>> {
    // Create mime directory
    let mime_dir = data_dir.join("mime/packages");
    fs::create_dir_all(&mime_dir)?;
    
    // Create .xml file for .vault mime type
    let mime_file_path = mime_dir.join("application-x-zerovault.xml");
    let mime_file_content = r#"<?xml version="1.0" encoding="UTF-8"?>
<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
  <mime-type type="application/x-zerovault">
    <comment>ZeroVault encrypted file</comment>
    <glob pattern="*.vault"/>
    <icon name="application-x-zerovault"/>
  </mime-type>
</mime-info>
"#;
    
    fs::write(&mime_file_path, mime_file_content)?;
    
    // Create .desktop file for .vault file type
    let applications_dir = data_dir.join("applications");
    fs::create_dir_all(&applications_dir)?;
    
    let app_file_path = applications_dir.join("zerovault.desktop");
    let app_file_content = format!(r#"[Desktop Entry]
Type=Application
Name=ZeroVault
Comment=ZeroVault Secure Encryption Utility
Exec="{}" decrypt %f
Terminal=false
NoDisplay=true
MimeType=application/x-zerovault;
"#, exe_path);
    
    fs::write(&app_file_path, app_file_content)?;
    
    // Update mime database
    let _ = Command::new("update-mime-database")
        .arg(data_dir.join("mime").to_string_lossy().as_ref())
        .output();
    
    Ok(())
}

pub fn uninstall_integration() -> Result<(), Box<dyn Error>> {
    // Get user's local share directory
    let data_dir = dirs::data_local_dir().ok_or("Could not determine local data directory")?;
    
    // Remove Nautilus scripts
    let nautilus_scripts_dir = data_dir.join("nautilus/scripts");
    let encrypt_script_path = nautilus_scripts_dir.join("Encrypt with ZeroVault");
    let decrypt_script_path = nautilus_scripts_dir.join("Decrypt with ZeroVault");
    
    if encrypt_script_path.exists() {
        fs::remove_file(&encrypt_script_path)?;
    }
    
    if decrypt_script_path.exists() {
        fs::remove_file(&decrypt_script_path)?;
    }
    
    // Remove Dolphin service menu
    let dolphin_service_file = data_dir.join("kservices5/ServiceMenus/zerovault.desktop");
    if dolphin_service_file.exists() {
        fs::remove_file(&dolphin_service_file)?;
    }
    
    // Remove mime type
    let mime_file = data_dir.join("mime/packages/application-x-zerovault.xml");
    if mime_file.exists() {
        fs::remove_file(&mime_file)?;
        
        // Update mime database
        let _ = Command::new("update-mime-database")
            .arg(data_dir.join("mime").to_string_lossy().as_ref())
            .output();
    }
    
    // Remove .desktop file
    let app_file = data_dir.join("applications/zerovault.desktop");
    if app_file.exists() {
        fs::remove_file(&app_file)?;
    }
    
    Ok(())
}
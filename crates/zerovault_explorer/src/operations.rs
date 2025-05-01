use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use zero_vault_core::{encrypt_data, decrypt_data};
use crate::dialogs;

/// Structure representing a vault file
#[derive(serde::Serialize, serde::Deserialize)]
struct VaultFile {
    data: zero_vault_core::VaultEncryptedData,
    #[serde(default)]
    metadata: Metadata,
}

/// Metadata for the vault file
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct Metadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    modified_at: Option<u64>,
    version: String,
}

impl VaultFile {
    /// Create a new vault file with encrypted data
    fn new(encrypted_data: zero_vault_core::VaultEncryptedData, comment: Option<String>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        let metadata = Metadata {
            comment,
            created_at: now,
            modified_at: None,
            version: env!("CARGO_PKG_VERSION").to_string(),
        };
        
        Self {
            data: encrypted_data,
            metadata,
        }
    }
}

/// Get the default output path for encryption
fn get_encryption_output_path(input_path: &Path) -> PathBuf {
    let mut output_path = input_path.to_path_buf();
    output_path.set_extension(format!(
        "{}.vault", 
        input_path.extension().unwrap_or_default().to_string_lossy()
    ));
    output_path
}

/// Get the default output path for decryption
fn get_decryption_output_path(input_path: &Path) -> PathBuf {
    // If it's a .vault file, remove that extension
    if input_path.extension().map_or(false, |ext| ext == "vault") {
        let file_stem = input_path.file_stem().unwrap_or_default();
        let parent = input_path.parent().unwrap_or_else(|| Path::new(""));
        
        // Get the original extension
        let original_name = file_stem.to_string_lossy();
        if let Some(dot_pos) = original_name.rfind('.') {
            let new_stem = &original_name[..dot_pos];
            let new_ext = &original_name[dot_pos+1..];
            
            let mut new_path = parent.join(new_stem);
            new_path.set_extension(new_ext);
            return new_path;
        }
        
        // No dot found, just return the file stem
        return parent.join(file_stem);
    }
    
    // Otherwise add .decrypted extension
    let mut output_path = input_path.to_path_buf();
    output_path.set_extension(format!(
        "{}.decrypted", 
        input_path.extension().unwrap_or_default().to_string_lossy()
    ));
    output_path
}

/// Check if the output file exists and prompt for overwrite if needed
fn check_output_file(output_path: &Path) -> Result<bool, Box<dyn Error>> {
    if output_path.exists() {
        // Ask for confirmation
        let message = format!("File '{}' already exists. Do you want to overwrite it?", 
                             output_path.display());
        let confirmed = dialogs::show_confirmation("File Exists", &message);
        
        Ok(confirmed)
    } else {
        Ok(true)
    }
}

/// Encrypt a file using ZeroVault core
pub fn encrypt_file(file_path: &Path, password: &str) -> Result<PathBuf, Box<dyn Error>> {
    // Determine output path
    let output_path = get_encryption_output_path(file_path);
    
    // Check if output file exists
    if !check_output_file(&output_path)? {
        return Err("Operation cancelled by user".into());
    }
    
    // Read the input file
    let data = fs::read(file_path)?;
    
    // Encrypt the data
    let encrypted = encrypt_data(&data, password).map_err(|e| format!("Encryption failed: {:?}", e))?;
    
    // Create a vault file with metadata
    let vault_file = VaultFile::new(encrypted, None);
    
    // Serialize to JSON
    let json = serde_json::to_string_pretty(&vault_file)?;
    
    // Write to output file
    fs::write(&output_path, json)?;
    
    Ok(output_path)
}

/// Parse a vault file
fn parse_vault_file(json: &str) -> Result<zero_vault_core::VaultEncryptedData, Box<dyn Error>> {
    // Try parsing as a VaultFile
    if let Ok(vault_file) = serde_json::from_str::<VaultFile>(json) {
        return Ok(vault_file.data);
    }
    
    // Try parsing directly as VaultEncryptedData
    let data = serde_json::from_str(json)?;
    Ok(data)
}

/// Decrypt a file using ZeroVault core
pub fn decrypt_file(file_path: &Path, password: &str) -> Result<PathBuf, Box<dyn Error>> {
    // Determine output path
    let output_path = get_decryption_output_path(file_path);
    
    // Check if output file exists
    if !check_output_file(&output_path)? {
        return Err("Operation cancelled by user".into());
    }
    
    // Read the vault file
    let json = fs::read_to_string(file_path)?;
    
    // Parse the vault file
    let encrypted_data = parse_vault_file(&json)?;
    
    // Decrypt the data
    let decrypted = decrypt_data(&encrypted_data, password)
        .map_err(|e| format!("Decryption failed: {:?}", e))?;
    
    // Write to output file
    fs::write(&output_path, decrypted)?;
    
    Ok(output_path)
}
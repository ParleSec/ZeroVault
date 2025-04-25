use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use zero_vault_core::{
    encrypt_data, decrypt_data, VaultEncryptedData, VaultError, 
    memory::{SecureString, SecureBytes}
};
use serde::{Serialize, Deserialize};
use thiserror::Error;

/// Error type for CLI operations
#[derive(Error, Debug)]
pub enum CliError {
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),
    
    #[error("Encryption error: {0:?}")]
    EncryptionError(#[from] VaultError),
    
    #[error("JSON serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("File already exists: {0}")]
    FileExists(PathBuf),
    
    #[error("Password error: {0}")]
    PasswordError(String),
    
    #[error("Operation cancelled by user")]
    UserCancelled,
    
    #[error("Invalid format")]
    InvalidFormat,
}

/// Metadata for the vault file
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaultMetadata {
    /// Optional comment about the encrypted content
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    
    /// Unix timestamp of when the vault file was created
    pub created_at: u64,
    
    /// Unix timestamp of when the vault file was last modified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_at: Option<u64>,
    
    /// Version of the vault file format
    pub version: String,
    
    /// Security level used for encryption
    pub security_level: String,
}

/// Complete vault file structure
#[derive(Serialize, Deserialize)]
pub struct VaultFile {
    /// The encrypted data
    pub data: VaultEncryptedData,
    
    /// Metadata about the vault file
    pub metadata: VaultMetadata,
}

/// Encrypt a file using secure password handling
pub fn encrypt_file(
    input_path: &Path,
    output_path: &Path,
    password: Option<String>,
    comment: Option<String>,
    force: bool,
    interactive: bool,
) -> Result<(), CliError> {
    // Check if output file exists
    if output_path.exists() && !force {
        if interactive {
            // Ask for confirmation
            print!("File '{}' already exists. Overwrite? (y/n): ", output_path.display());
            io::stdout().flush()?;
            
            let mut response = String::new();
            io::stdin().read_line(&mut response)?;
            
            if response.trim().to_lowercase() != "y" {
                return Err(CliError::UserCancelled);
            }
        } else {
            return Err(CliError::FileExists(output_path.to_path_buf()));
        }
    }
    
    // Get password
    let password = match password {
        Some(pass) => pass,
        None => {
            if !interactive {
                return Err(CliError::PasswordError("Password required in non-interactive mode".to_string()));
            }
            
            // Prompt for password
            let password = prompt_password("Enter encryption password")?;
            
            // Confirm password
            let confirm = prompt_password("Confirm password")?;
            
            if password != confirm {
                return Err(CliError::PasswordError("Passwords do not match".to_string()));
            }
            
            password
        }
    };
    
    // Read input file
    let data = fs::read(input_path)?;
    
    // Securely store the data and password
    let secure_data = SecureBytes::new(data)?;
    let secure_password = SecureString::new(password)?;
    
    // Encrypt data with maximum security
    let encrypted = encrypt_data(
        secure_data.as_slice(),
        secure_password.as_str()
    )?;
    
    // Create metadata
    let metadata = VaultMetadata {
        comment,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        modified_at: None,
        version: env!("CARGO_PKG_VERSION").to_string(),
        security_level: "Fort-Knox".to_string(),
    };
    
    // Create vault file
    let vault_file = VaultFile {
        data: encrypted,
        metadata,
    };
    
    // Serialize to JSON
    let json = serde_json::to_string_pretty(&vault_file)?;
    
    // Write output file
    fs::write(output_path, json)?;
    
    Ok(())
}

/// Decrypt a file using secure password handling
pub fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    password: Option<String>,
    force: bool,
    interactive: bool,
) -> Result<(), CliError> {
    // Check if output file exists
    if output_path.exists() && !force {
        if interactive {
            // Ask for confirmation
            print!("File '{}' already exists. Overwrite? (y/n): ", output_path.display());
            io::stdout().flush()?;
            
            let mut response = String::new();
            io::stdin().read_line(&mut response)?;
            
            if response.trim().to_lowercase() != "y" {
                return Err(CliError::UserCancelled);
            }
        } else {
            return Err(CliError::FileExists(output_path.to_path_buf()));
        }
    }
    
    // Read vault file
    let json = fs::read_to_string(input_path)?;
    
    // Parse JSON
    let vault_file: VaultFile = serde_json::from_str(&json)?;
    
    // Get password
    let password = match password {
        Some(pass) => pass,
        None => {
            if !interactive {
                return Err(CliError::PasswordError("Password required in non-interactive mode".to_string()));
            }
            
            // Prompt for password
            prompt_password("Enter decryption password")?
        }
    };
    
    // Securely store the password
    let secure_password = SecureString::new(password)?;
    
    // Decrypt data
    let decrypted = decrypt_data(&vault_file.data, secure_password.as_str())?;
    
    // Write output file
    fs::write(output_path, decrypted)?;
    
    Ok(())
}

/// Show information about a vault file
pub fn show_vault_info(input_path: &Path) -> Result<VaultMetadata, CliError> {
    // Read vault file
    let json = fs::read_to_string(input_path)?;
    
    // Parse JSON
    let vault_file: VaultFile = serde_json::from_str(&json)?;
    
    Ok(vault_file.metadata)
}

/// Validate a vault file structure without decrypting
pub fn validate_vault(input_path: &Path) -> Result<bool, CliError> {
    // Read vault file
    let json = fs::read_to_string(input_path)?;
    
    // Try to parse the JSON structure
    let result: Result<VaultFile, _> = serde_json::from_str(&json);
    
    match result {
        Ok(_) => Ok(true), // File structure is valid
        Err(_) => Err(CliError::InvalidFormat),
    }
}

/// Prompt for password securely (no echo)
fn prompt_password(prompt: &str) -> Result<String, CliError> {
    print!("{}: ", prompt);
    io::stdout().flush()?;
    
    let password = rpassword::read_password()
        .map_err(|e| CliError::IoError(e))?;
    
    if password.is_empty() {
        return Err(CliError::PasswordError("Password cannot be empty".to_string()));
    }
    
    Ok(password)
}

/// Encrypt data from stdin to stdout
pub fn encrypt_stream(password: Option<String>) -> Result<(), CliError> {
    // Get password
    let password = match password {
        Some(pass) => pass,
        None => prompt_password("Enter encryption password")?,
    };
    
    // Read from stdin
    let mut data = Vec::new();
    io::stdin().read_to_end(&mut data)?;
    
    // Securely store data and password
    let secure_data = SecureBytes::new(data)?;
    let secure_password = SecureString::new(password)?;
    
    // Encrypt
    let encrypted = encrypt_data(
        secure_data.as_slice(),
        secure_password.as_str()
    )?;
    
    // Create metadata
    let metadata = VaultMetadata {
        comment: None,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        modified_at: None,
        version: env!("CARGO_PKG_VERSION").to_string(),
        security_level: "Fort-Knox".to_string(),
    };
    
    // Create vault file
    let vault_file = VaultFile {
        data: encrypted,
        metadata,
    };
    
    // Serialize to JSON
    let json = serde_json::to_string(&vault_file)?;
    
    // Write to stdout
    println!("{}", json);
    
    Ok(())
}

/// Decrypt data from stdin to stdout
pub fn decrypt_stream(password: Option<String>) -> Result<(), CliError> {
    // Get password
    let password = match password {
        Some(pass) => pass,
        None => prompt_password("Enter decryption password")?,
    };
    
    // Read from stdin
    let mut json = String::new();
    io::stdin().read_to_string(&mut json)?;
    
    // Parse JSON
    let vault_file: VaultFile = serde_json::from_str(&json)?;
    
    // Securely store password
    let secure_password = SecureString::new(password)?;
    
    // Decrypt
    let decrypted = decrypt_data(&vault_file.data, secure_password.as_str())?;
    
    // Write to stdout as raw bytes
    io::stdout().write_all(&decrypted)?;
    
    Ok(())
}

/// Run self-tests to verify the encryption/decryption functionality
pub fn run_self_tests() -> Result<(), CliError> {
    // Test 1: Basic encryption/decryption
    let test_data = b"Test data for self-test verification";
    let password = "test_password_123!@#";
    
    // Encrypt
    let encrypted = encrypt_data(test_data, password)?;
    
    // Decrypt
    let decrypted = decrypt_data(&encrypted, password)?;
    
    // Verify
    if decrypted != test_data {
        return Err(CliError::EncryptionError(VaultError::VerificationFailed));
    }
    
    // Test 2: Wrong password
    let result = decrypt_data(&encrypted, "wrong_password");
    if result.is_ok() {
        return Err(CliError::EncryptionError(VaultError::SecurityViolation));
    }
    
    // Test 3: Test with empty data
    let empty_data = b"";
    
    let encrypted_empty = encrypt_data(empty_data, password)?;
    let decrypted_empty = decrypt_data(&encrypted_empty, password)?;
    
    if decrypted_empty != empty_data {
        return Err(CliError::EncryptionError(VaultError::VerificationFailed));
    }
    
    Ok(())
}
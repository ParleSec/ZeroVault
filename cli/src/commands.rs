use std::fs;
use std::io::{self, Write, Read};
use std::path::PathBuf;
use zero_vault_core::crypto::{encrypt_data, decrypt_data};
use crate::types::{VaultFile, CommandOutput};
use crate::utils;
use base64::Engine;

/// Encrypt a file with the given arguments
pub fn encrypt_file(
    input: Option<PathBuf>,
    output: Option<PathBuf>,
    password: Option<String>,
    comment: Option<String>,
    security_level: zero_vault_core::types::SecurityLevel,
    force: bool,
    non_interactive: bool,
    verbose: u8,
    json_format: bool,
) -> Result<(), String> {
    let interactive = !non_interactive;
    
    // Get input file path
    let input_path = match input {
        Some(path) => path,
        None => {
            if !interactive {
                return Err("Input file path is required in non-interactive mode".to_string());
            }
            utils::prompt_file_path("Enter input file path", true)?
        }
    };
    
    // Get output file path
    let output_path = match output {
        Some(path) => path,
        None => {
            let default_path = utils::get_default_output_path(&input_path, true);
            if interactive {
                // Suggest default path but allow changing it
                print!("Enter output file path [{}]: ", default_path.display());
                io::stdout().flush().map_err(|e| format!("Failed to flush stdout: {}", e))?;
                
                let mut input = String::new();
                io::stdin()
                    .read_line(&mut input)
                    .map_err(|e| format!("Failed to read input: {}", e))?;
                
                if input.trim().is_empty() {
                    default_path
                } else {
                    PathBuf::from(input.trim())
                }
            } else {
                default_path
            }
        }
    };
    
    // Get password
    let password = match password {
        Some(pass) => {
            if verbose > 0 && interactive {
                eprintln!("Warning: Using password from command line is less secure");
            }
            pass
        },
        None => {
            if !interactive {
                return Err("Password is required in non-interactive mode".to_string());
            }
            
            let password = utils::prompt_password("Enter encryption password")
                .map_err(|e| format!("Failed to read password: {}", e))?;
            
            // Confirm password
            let confirm = utils::prompt_password("Confirm password")
                .map_err(|e| format!("Failed to read password confirmation: {}", e))?;
            
            if password != confirm {
                return Err("Passwords do not match".to_string());
            }
            
            if password.len() < 8 && verbose > 0 {
                eprintln!("Warning: Password is less than 8 characters. This may be insecure.");
            }
            
            password
        }
    };
    
    // Get comment if needed
    let comment = match comment {
        Some(comment) => Some(comment),
        None => {
            if interactive {
                print!("Enter comment (optional): ");
                io::stdout().flush().map_err(|e| format!("Failed to flush stdout: {}", e))?;
                
                let mut input = String::new();
                io::stdin()
                    .read_line(&mut input)
                    .map_err(|e| format!("Failed to read input: {}", e))?;
                
                let comment = input.trim();
                if comment.is_empty() {
                    None
                } else {
                    Some(comment.to_string())
                }
            } else {
                None
            }
        }
    };
    
    // Check if output file exists
    utils::check_output_file(&output_path, force, interactive)?;
    
    // Read input file
    let data = fs::read(&input_path)
        .map_err(|e| format!("Failed to read input file '{}': {}", input_path.display(), e))?;
    
    if verbose > 0 {
        eprintln!("Encrypting {} bytes from '{}'", data.len(), input_path.display());
    }
    
    // Encrypt data
    let enc = encrypt_data(&data, &password)
        .map_err(|e| format!("Encryption failed: {}", e))?;
    
    // Create vault file with metadata
    let vault_file = VaultFile::new(enc, comment.clone());
    
    // Write output file
    let json = serde_json::to_string_pretty(&vault_file)
        .map_err(|e| format!("Failed to serialize encrypted data: {}", e))?;
    
    fs::write(&output_path, json)
        .map_err(|e| format!("Failed to write output file '{}': {}", output_path.display(), e))?;
    
    let output = CommandOutput {
        success: true,
        message: "File encrypted successfully".to_string(),
        input_path: Some(input_path.display().to_string()),
        output_path: Some(output_path.display().to_string()),
        file_size: Some(data.len() as u64),
        metadata: if comment.is_some() { Some(vault_file.metadata) } else { None },
        error: None,
    };
    
    utils::output_result(output, json_format);
    
    Ok(())
}

/// Decrypt a file with the given arguments
pub fn decrypt_file(
    input: Option<PathBuf>,
    output: Option<PathBuf>, 
    password: Option<String>,
    force: bool,
    non_interactive: bool,
    verbose: u8, 
    json_format: bool
) -> Result<(), String> {
    let interactive = !non_interactive;
    
    // Get input file path
    let input_path = match input {
        Some(path) => path,
        None => {
            if !interactive {
                return Err("Input file path is required in non-interactive mode".to_string());
            }
            utils::prompt_file_path("Enter vault file path", true)?
        }
    };
    
    // Read encrypted file
    let json = fs::read_to_string(&input_path)
        .map_err(|e| format!("Failed to read vault file '{}': {}", input_path.display(), e))?;
    
    // Parse JSON - try new format first, then legacy
    let (enc, _) = utils::parse_vault_file(&json)?;
    
    // Get output file path
    let output_path = match output {
        Some(path) => path,
        None => {
            let default_path = utils::get_default_output_path(&input_path, false);
            if interactive {
                // Suggest default path but allow changing it
                print!("Enter output file path [{}]: ", default_path.display());
                io::stdout().flush().map_err(|e| format!("Failed to flush stdout: {}", e))?;
                
                let mut input = String::new();
                io::stdin()
                    .read_line(&mut input)
                    .map_err(|e| format!("Failed to read input: {}", e))?;
                
                if input.trim().is_empty() {
                    default_path
                } else {
                    PathBuf::from(input.trim())
                }
            } else {
                default_path
            }
        }
    };
    
    // Get password
    let password = match password {
        Some(pass) => {
            if verbose > 0 && interactive {
                eprintln!("Warning: Using password from command line is less secure");
            }
            pass
        },
        None => {
            if !interactive {
                return Err("Password is required in non-interactive mode".to_string());
            }
            
            utils::prompt_password("Enter decryption password")
                .map_err(|e| format!("Failed to read password: {}", e))?
        }
    };
    
    // Check if output file exists
    utils::check_output_file(&output_path, force, interactive)?;
    
    if verbose > 0 {
        eprintln!("Decrypting data from vault file '{}'", input_path.display());
    }
    
    // Decrypt data
    let data = decrypt_data(&enc, &password)
        .map_err(|e| format!("Decryption failed: {}", e))?;
    
    // Write output file
    fs::write(&output_path, data.clone())
        .map_err(|e| format!("Failed to write output file '{}': {}", output_path.display(), e))?;
    
    let output = CommandOutput {
        success: true,
        message: "File decrypted successfully".to_string(),
        input_path: Some(input_path.display().to_string()),
        output_path: Some(output_path.display().to_string()),
        file_size: Some(data.len() as u64),
        metadata: None,
        error: None,
    };
    
    utils::output_result(output, json_format);
    
    Ok(())
}

/// Validate a vault file structure
pub fn validate_vault(
    input: Option<PathBuf>,
    verbose: u8, 
    json_format: bool
) -> Result<(), String> {
    // Get input file path
    let input_path = match input {
        Some(path) => path,
        None => utils::prompt_file_path("Enter vault file path to validate", true)?
    };
    
    if verbose > 0 {
        eprintln!("Validating vault file: {}", input_path.display());
    }
    
    // Read vault file
    let json = fs::read_to_string(&input_path)
        .map_err(|e| format!("Failed to read vault file '{}': {}", input_path.display(), e))?;
    
    // Parse JSON - try new format first, then legacy
    let (enc, _) = utils::parse_vault_file(&json)?;
    
    // Validate base64 fields
    let validate_base64 = |field: &str, value: &str| -> Result<Vec<u8>, String> {
        base64::engine::general_purpose::STANDARD.decode(value)
            .map_err(|_| format!("Invalid base64 in {} field", field))
    };
    
    validate_base64("primary_nonce", &enc.primary_nonce)?;
    validate_base64("primary_ciphertext", &enc.primary_ciphertext)?;
    validate_base64("data_signature", &enc.data_signature)?;
    validate_base64("public_key", &enc.public_key)?;
    
    // Validate salt
    validate_base64("master_salt", &enc.master_salt)?;
    
    let output = CommandOutput {
        success: true,
        message: "Vault file is valid".to_string(),
        input_path: Some(input_path.display().to_string()),
        output_path: None,
        file_size: fs::metadata(&input_path).ok().map(|m| m.len()),
        metadata: None,
        error: None,
    };
    
    utils::output_result(output, json_format);
    
    Ok(())
}

/// Show information about a vault file
pub fn show_vault_info(
    input: Option<PathBuf>,
    verbose: u8, 
    json_format: bool
) -> Result<(), String> {
    // Get input file path
    let input_path = match input {
        Some(path) => path,
        None => utils::prompt_file_path("Enter vault file path to inspect", true)?
    };
    
    if verbose > 0 {
        eprintln!("Reading vault info: {}", input_path.display());
    }
    
    // Read vault file
    let json = fs::read_to_string(&input_path)
        .map_err(|e| format!("Failed to read vault file '{}': {}", input_path.display(), e))?;
    
    // Try parsing as new VaultFile or legacy format
    let (enc, vault_metadata) = utils::parse_vault_file(&json)?;
    
    // Get file info
    let file_metadata = fs::metadata(&input_path)
        .map_err(|e| format!("Failed to get metadata for file: {}", e))?;
    
    if json_format {
        // Create a structured output for JSON mode - update field names
        let mut output = serde_json::json!({
            "success": true,
            "file_path": input_path.display().to_string(),
            "file_size": file_metadata.len(),
            "public_key": enc.public_key,
            "encrypted_data_size": base64::engine::general_purpose::STANDARD.decode(&enc.primary_ciphertext) // Changed from ciphertext to primary_ciphertext
                .map(|v| v.len())
                .unwrap_or(0),
        });
        
        // Add metadata if available
        if let Some(metadata) = vault_metadata {
            let metadata_json = serde_json::to_value(metadata).unwrap();
            if let serde_json::Value::Object(mut map) = output {
                map.insert("metadata".to_string(), metadata_json);
                output = serde_json::Value::Object(map);
            }
        }
        
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        // Display information in text mode
        println!("Vault File: {}", input_path.display());
        println!("File Size: {} bytes", file_metadata.len());
        
        // Changed field access
        if let Ok(ciphertext) = base64::engine::general_purpose::STANDARD.decode(&enc.primary_ciphertext) {
            println!("Encrypted Data Size: {} bytes", ciphertext.len());
        }
        
        println!("Public Key: {}", enc.public_key);
        
        // Display metadata if available
        if let Some(metadata) = vault_metadata {
            println!("\nMetadata:");
            
            // Format creation time
            let created_at = utils::format_timestamp(metadata.created_at);
            println!("  Created: {}", created_at);
            
            // Format modification time if available
            if let Some(modified_at) = metadata.modified_at {
                let modified_time = utils::format_timestamp(modified_at);
                println!("  Modified: {}", modified_time);
            }
            
            // Display version
            println!("  Version: {}", metadata.version);
            
            // Display comment if available
            if let Some(comment) = metadata.comment {
                println!("  Comment: {}", comment);
            }
        }
        
        println!("\nNote: Use the decrypt command with the correct password to access the contents.");
    }
    
    Ok(())
}

/// Encrypt data from stdin to stdout
pub fn encrypt_stream(
    password: Option<String>,
    verbose: u8, 
    _json_format: bool
) -> Result<(), String> {
    // Get password
    let password = match password {
        Some(pass) => {
            if verbose > 0 {
                eprintln!("Warning: Using password from command line is less secure");
            }
            pass
        },
        None => utils::prompt_password("Enter encryption password")
            .map_err(|e| format!("Failed to read password: {}", e))?
    };
    
    // Read from stdin
    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf)
        .map_err(|e| format!("Failed to read from stdin: {}", e))?;
    
    if verbose > 0 {
        eprintln!("Encrypting {} bytes from stdin", buf.len());
    }
    
    // Encrypt data - now properly handling the Result
    let enc = encrypt_data(&buf, &password)
        .map_err(|e| format!("Encryption failed: {}", e))?;
    
    // Create vault file with metadata (no comment for stream mode)
    let vault_file = VaultFile::new(enc, None);
    
    // Write to stdout
    let json = serde_json::to_string(&vault_file)
        .map_err(|e| format!("Failed to serialize encrypted data: {}", e))?;
    
    println!("{}", json);
    
    Ok(())
}

/// Decrypt data from stdin to stdout
pub fn decrypt_stream(
    password: Option<String>,
    verbose: u8, 
    _json_format: bool
) -> Result<(), String> {
    // Get password
    let password = match password {
        Some(pass) => {
            if verbose > 0 {
                eprintln!("Warning: Using password from command line is less secure");
            }
            pass
        },
        None => utils::prompt_password("Enter decryption password")
            .map_err(|e| format!("Failed to read password: {}", e))?
    };
    
    // Read from stdin
    let mut buf = String::new();
    io::stdin().read_to_string(&mut buf)
        .map_err(|e| format!("Failed to read from stdin: {}", e))?;
    
    // Parse JSON - try new format first, then legacy
    let (enc, _) = utils::parse_vault_file(&buf)?;
    
    if verbose > 0 {
        eprintln!("Decrypting data from stdin");
    }
    
    // Decrypt data
    let data = decrypt_data(&enc, &password)
        .map_err(|e| format!("Decryption failed: {}", e))?;
    
    // Write to stdout as raw bytes
    io::stdout().write_all(&data)
        .map_err(|e| format!("Failed to write to stdout: {}", e))?;
    
    Ok(())
}

/// Run self-tests
pub fn run_tests(verbose: u8, json_format: bool) -> Result<(), String> {
    if verbose > 0 {
        eprintln!("Running self-tests...");
    }
    
    // Test 1: Basic encryption/decryption
    let test_data = b"Test data for encryption";
    let password = "test_password";
    
    if verbose > 1 {
        eprintln!("Test 1: Basic encryption/decryption");
    }
    
    // Handle Result from encrypt_data
    let encrypted = encrypt_data(test_data, password)
        .map_err(|e| format!("Test 1 failed: {}", e))?;
        
    let decrypted = decrypt_data(&encrypted, password)
        .map_err(|e| format!("Test 1 failed: {}", e))?;
    
    if decrypted != test_data {
        return Err("Test 1 failed: Decrypted data does not match original".to_string());
    }
    
    // Test 2: Wrong password
    if verbose > 1 {
        eprintln!("Test 2: Wrong password");
    }
    
    let wrong_result = decrypt_data(&encrypted, "wrong_password");
    if wrong_result.is_ok() {
        return Err("Test 2 failed: Decryption succeeded with wrong password".to_string());
    }
    
    // Test 3: VaultFile serialization/deserialization
    if verbose > 1 {
        eprintln!("Test 3: VaultFile serialization/deserialization");
    }
    
    let vault_file = VaultFile::new(encrypted, Some("Test comment".to_string()));
    let serialized = serde_json::to_string(&vault_file)
        .map_err(|e| format!("Test 3 failed (serialization): {}", e))?;
    
    let deserialized: VaultFile = serde_json::from_str(&serialized)
        .map_err(|e| format!("Test 3 failed (deserialization): {}", e))?;
    
    let redecrypted = decrypt_data(&deserialized.data, password)
        .map_err(|e| format!("Test 3 failed (redecryption): {}", e))?;
    
    if redecrypted != test_data {
        return Err("Test 3 failed: VaultFile roundtrip failed".to_string());
    }
    
    if deserialized.metadata.comment != Some("Test comment".to_string()) {
        return Err("Test 3 failed: Metadata comment not preserved".to_string());
    }
    
    // Success
    let output = CommandOutput {
        success: true,
        message: "All tests passed successfully".to_string(),
        input_path: None,
        output_path: None,
        file_size: None,
        metadata: None,
        error: None,
    };
    
    utils::output_result(output, json_format);
    
    Ok(())
}
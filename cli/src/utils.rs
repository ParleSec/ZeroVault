use std::io::{self, Write};
use std::path::{Path, PathBuf};
use crate::types::{VaultFile, CommandOutput};
use zero_vault_core::types::VaultEncryptedData;

/// Prompt for password securely (no echo)
pub fn prompt_password(prompt: &str) -> Result<String, io::Error> {
    print!("{}: ", prompt);
    io::stdout().flush()?;
    
    let password = rpassword::read_password()?;
    
    // Check for empty password
    if password.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Password cannot be empty"));
    }
    
    Ok(password)
}

/// Prompt for a file path
pub fn prompt_file_path(prompt: &str, must_exist: bool) -> Result<PathBuf, String> {
    print!("{}: ", prompt);
    io::stdout().flush().map_err(|e| format!("Failed to flush stdout: {}", e))?;
    
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| format!("Failed to read input: {}", e))?;
    
    let path = PathBuf::from(input.trim());
    
    if must_exist && !path.exists() {
        return Err(format!("File '{}' does not exist", path.display()));
    }
    
    Ok(path)
}

/// Confirm a file overwrite
pub fn confirm_overwrite(path: &Path) -> Result<bool, io::Error> {
    print!("File '{}' already exists. Overwrite? (y/n): ", path.display());
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    Ok(input.trim().to_lowercase() == "y")
}

/// Get default output path based on input path
pub fn get_default_output_path(input: &Path, is_encrypt: bool) -> PathBuf {
    if is_encrypt {
        // For encryption: input.txt -> input.txt.vault
        let mut output = input.to_path_buf();
        output.set_extension(format!("{}.vault", 
            input.extension().unwrap_or_default().to_string_lossy()));
        output
    } else {
        // For decryption: try to remove .vault extension
        let file_stem = input.file_stem().unwrap_or_default();
        let parent = input.parent().unwrap_or_else(|| Path::new(""));
        
        if input.extension().unwrap_or_default() == "vault" {
            // If it ends with .vault, remove that extension
            parent.join(file_stem)
        } else {
            // Otherwise add .decrypted extension
            let mut output = parent.join(file_stem);
            output.set_extension(format!("{}.decrypted", 
                input.extension().unwrap_or_default().to_string_lossy()));
            output
        }
    }
}

/// Check if output file exists and handle accordingly
pub fn check_output_file(path: &Path, force: bool, interactive: bool) -> Result<(), String> {
    if path.exists() {
        if force {
            // Force overwrite, no confirmation needed
            return Ok(());
        } else if interactive {
            // Interactive mode, ask for confirmation
            match confirm_overwrite(path) {
                Ok(true) => return Ok(()),
                Ok(false) => return Err(format!("Operation cancelled by user")),
                Err(e) => return Err(format!("Failed to get confirmation: {}", e)),
            }
        } else {
            // Non-interactive mode, no force flag
            return Err(format!(
                "Output file '{}' already exists. Use --force to overwrite.", 
                path.display()
            ));
        }
    }
    
    Ok(())
}

/// Output result in JSON or text format
pub fn output_result(result: CommandOutput, json_format: bool) {
    if json_format {
        if let Ok(json) = serde_json::to_string_pretty(&result) {
            println!("{}", json);
        } else {
            eprintln!("Error serializing JSON output");
        }
    } else {
        if result.success {
            println!("✓ {}", result.message);
            
            if let Some(input) = result.input_path {
                println!("  Input: {}", input);
            }
            
            if let Some(output) = result.output_path {
                println!("  Output: {}", output);
            }
            
            if let Some(size) = result.file_size {
                println!("  Size: {} bytes", size);
            }
            
            if let Some(metadata) = result.metadata {
                if let Some(comment) = metadata.comment {
                    println!("  Comment: {}", comment);
                }
            }
        } else {
            eprintln!("✗ Error: {}", result.message);
            
            if let Some(details) = result.error {
                eprintln!("  Details: {}", details);
            }
        }
    }
}

/// Try to parse a file as VaultFile
pub fn parse_vault_file(json: &str) -> Result<(VaultEncryptedData, Option<crate::types::Metadata>), String> {
    let vault_file: VaultFile = serde_json::from_str(json)
        .map_err(|e| format!("Failed to parse vault file: {}", e))?;
    
    Ok((vault_file.data, Some(vault_file.metadata)))
}
/// Format a Unix timestamp using chrono
pub fn format_timestamp(timestamp: u64) -> String {
    use chrono::{DateTime, Utc};
    
    DateTime::<Utc>::from_timestamp(timestamp as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| timestamp.to_string())
}
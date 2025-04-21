// cli/src/main.rs
use clap::{Parser, Subcommand, Args, ArgAction, ValueHint};
use std::fs;
use std::io::{self, Write, Read};
use std::path::{Path, PathBuf};
use vault_core::crypto::{encrypt_data, decrypt_data};
use vault_core::types::EncryptedData;
use std::process;
use base64::Engine;

/// ZeroVault - Secure Document Encryption CLI
#[derive(Parser)]
#[command(name = "zerovault")]
#[command(version)]
#[command(author = "Mason Parle")]
#[command(about = "Zero-trust document encryption vault")]
#[command(long_about = "A lightweight encryption vault for secure document storage using AES-256-GCM and Ed25519 signatures")]
#[command(propagate_version = true)]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, action = ArgAction::Count, global = true)]
    verbose: u8,

    /// Enable JSON output for programmatic usage
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file using a password
    Encrypt(EncryptArgs),
    
    /// Decrypt a vault file using a password
    Decrypt(DecryptArgs),
    
    /// Validate a vault file structure without decrypting
    Validate {
        /// Input vault file to validate
        #[arg(short, long, value_hint = ValueHint::FilePath)]
        input: Option<PathBuf>,
    },
    
    /// Show information about a vault file
    Info {
        /// Input vault file to inspect
        #[arg(short, long, value_hint = ValueHint::FilePath)]
        input: Option<PathBuf>,
    },

    /// Encrypt data from stdin and output to stdout
    EncryptStream {
        /// Password for encryption
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Decrypt data from stdin and output to stdout
    DecryptStream {
        /// Password for decryption
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Run self-tests to verify encryption/decryption works correctly
    Test,
}

#[derive(Args, Clone)]
struct EncryptArgs {
    /// Input file to encrypt
    #[arg(short, long, value_hint = ValueHint::FilePath)]
    input: Option<PathBuf>,
    
    /// Output vault file (defaults to input.vault)
    #[arg(short, long, value_hint = ValueHint::FilePath)]
    output: Option<PathBuf>,
    
    /// Force overwrite if output file exists
    #[arg(short, long)]
    force: bool,
    
    /// Non-interactive mode (don't prompt for missing values)
    #[arg(short, long)]
    non_interactive: bool,
    
    /// Password for encryption
    #[arg(short, long)]
    password: Option<String>,

    /// Add a comment to the vault file
    #[arg(short, long)]
    comment: Option<String>,
}

#[derive(Args, Clone)]
struct DecryptArgs {
    /// Input vault file to decrypt
    #[arg(short, long, value_hint = ValueHint::FilePath)]
    input: Option<PathBuf>,
    
    /// Output decrypted file
    #[arg(short, long, value_hint = ValueHint::FilePath)]
    output: Option<PathBuf>,
    
    /// Force overwrite if output file exists
    #[arg(short, long)]
    force: bool,
    
    /// Non-interactive mode (don't prompt for missing values)
    #[arg(short, long)]
    non_interactive: bool,
    
    /// Password for decryption
    #[arg(short, long)]
    password: Option<String>,
}

/// Structured output for JSON mode
#[derive(serde::Serialize)]
struct CommandOutput {
    success: bool,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    input_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Prompt for password securely (no echo)
fn prompt_password(prompt: &str) -> Result<String, io::Error> {
    print!("{}: ", prompt);
    io::stdout().flush()?;
    
    // In a real implementation, use rpassword crate for this
    let password = rpassword::read_password()?;
    
    // Check for empty password
    if password.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Password cannot be empty"));
    }
    
    Ok(password)
}

/// Prompt for a file path
fn prompt_file_path(prompt: &str, must_exist: bool) -> Result<PathBuf, String> {
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
fn confirm_overwrite(path: &Path) -> Result<bool, io::Error> {
    print!("File '{}' already exists. Overwrite? (y/n): ", path.display());
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    Ok(input.trim().to_lowercase() == "y")
}

/// Get default output path based on input path
fn get_default_output_path(input: &Path, is_encrypt: bool) -> PathBuf {
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
fn check_output_file(path: &Path, force: bool, interactive: bool) -> Result<(), String> {
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
fn output_result(result: CommandOutput, json_format: bool) {
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
        } else {
            eprintln!("✗ Error: {}", result.message);
            
            if let Some(details) = result.error {
                eprintln!("  Details: {}", details);
            }
        }
    }
}

/// Encrypt a file with the given arguments
fn encrypt_file(args: EncryptArgs, verbose: u8, json_format: bool) -> Result<(), String> {
    let interactive = !args.non_interactive;
    
    // Get input file path
    let input_path = match args.input {
        Some(path) => path,
        None => {
            if !interactive {
                return Err("Input file path is required in non-interactive mode".to_string());
            }
            prompt_file_path("Enter input file path", true)?
        }
    };
    
    // Get output file path
    let output_path = match args.output {
        Some(path) => path,
        None => {
            let default_path = get_default_output_path(&input_path, true);
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
    let password = match args.password {
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
            
            let password = prompt_password("Enter encryption password")
                .map_err(|e| format!("Failed to read password: {}", e))?;
            
            // Confirm password
            let confirm = prompt_password("Confirm password")
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
    let _comment = match args.comment {
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
    check_output_file(&output_path, args.force, interactive)?;
    
    // Read input file
    let data = fs::read(&input_path)
        .map_err(|e| format!("Failed to read input file '{}': {}", input_path.display(), e))?;
    
    if verbose > 0 {
        eprintln!("Encrypting {} bytes from '{}'", data.len(), input_path.display());
    }
    
    // Encrypt data
    let enc = encrypt_data(&data, &password);
    
    // TODO: Add comment to metadata if provided
    
    // Write output file
    let json = serde_json::to_string_pretty(&enc)
        .map_err(|e| format!("Failed to serialize encrypted data: {}", e))?;
    
    fs::write(&output_path, json)
        .map_err(|e| format!("Failed to write output file '{}': {}", output_path.display(), e))?;
    
    let output = CommandOutput {
        success: true,
        message: "File encrypted successfully".to_string(),
        input_path: Some(input_path.display().to_string()),
        output_path: Some(output_path.display().to_string()),
        file_size: Some(data.len() as u64),
        error: None,
    };
    
    output_result(output, json_format);
    
    Ok(())
}

/// Decrypt a file with the given arguments
fn decrypt_file(args: DecryptArgs, verbose: u8, json_format: bool) -> Result<(), String> {
    let interactive = !args.non_interactive;
    
    // Get input file path
    let input_path = match args.input {
        Some(path) => path,
        None => {
            if !interactive {
                return Err("Input file path is required in non-interactive mode".to_string());
            }
            prompt_file_path("Enter vault file path", true)?
        }
    };
    
    // Read encrypted file
    let json = fs::read_to_string(&input_path)
        .map_err(|e| format!("Failed to read vault file '{}': {}", input_path.display(), e))?;
    
    // Parse JSON
    let enc: EncryptedData = serde_json::from_str(&json)
        .map_err(|e| format!("Failed to parse vault file - invalid format: {}", e))?;
    
    // Get output file path
    let output_path = match args.output {
        Some(path) => path,
        None => {
            let default_path = get_default_output_path(&input_path, false);
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
    let password = match args.password {
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
            
            prompt_password("Enter decryption password")
                .map_err(|e| format!("Failed to read password: {}", e))?
        }
    };
    
    // Check if output file exists
    check_output_file(&output_path, args.force, interactive)?;
    
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
        error: None,
    };
    
    output_result(output, json_format);
    
    Ok(())
}

/// Validate a vault file structure
fn validate_vault(input: Option<PathBuf>, verbose: u8, json_format: bool) -> Result<(), String> {
    // Get input file path
    let input_path = match input {
        Some(path) => path,
        None => prompt_file_path("Enter vault file path to validate", true)?
    };
    
    if verbose > 0 {
        eprintln!("Validating vault file: {}", input_path.display());
    }
    
    // Read vault file
    let json = fs::read_to_string(&input_path)
        .map_err(|e| format!("Failed to read vault file '{}': {}", input_path.display(), e))?;
    
    // Parse JSON
    let enc: EncryptedData = serde_json::from_str(&json)
        .map_err(|e| format!("Failed to parse vault file - invalid format: {}", e))?;
    
    // Validate base64 fields
    let validate_base64 = |field: &str, value: &str| -> Result<Vec<u8>, String> {
        base64::engine::general_purpose::STANDARD.decode(value)
            .map_err(|_| format!("Invalid base64 in {} field", field))
    };
    
    validate_base64("nonce", &enc.nonce)?;
    validate_base64("ciphertext", &enc.ciphertext)?;
    validate_base64("signature", &enc.signature)?;
    validate_base64("public_key", &enc.public_key)?;
    
    // Validate salt
    argon2::password_hash::SaltString::from_b64(&enc.salt)
        .map_err(|_| "Invalid salt format".to_string())?;
    
    let output = CommandOutput {
        success: true,
        message: "Vault file is valid".to_string(),
        input_path: Some(input_path.display().to_string()),
        output_path: None,
        file_size: fs::metadata(&input_path).ok().map(|m| m.len()),
        error: None,
    };
    
    output_result(output, json_format);
    
    Ok(())
}

/// Show information about a vault file
fn show_vault_info(input: Option<PathBuf>, verbose: u8, json_format: bool) -> Result<(), String> {
    // Get input file path
    let input_path = match input {
        Some(path) => path,
        None => prompt_file_path("Enter vault file path to inspect", true)?
    };
    
    if verbose > 0 {
        eprintln!("Reading vault info: {}", input_path.display());
    }
    
    // Read vault file
    let json = fs::read_to_string(&input_path)
        .map_err(|e| format!("Failed to read vault file '{}': {}", input_path.display(), e))?;
    
    // Parse JSON
    let enc: EncryptedData = serde_json::from_str(&json)
        .map_err(|e| format!("Failed to parse vault file - invalid format: {}", e))?;
    
    // Get file info
    let metadata = fs::metadata(&input_path)
        .map_err(|e| format!("Failed to get metadata for file: {}", e))?;
    
    if json_format {
        // Create a structured output for JSON mode
        let output = serde_json::json!({
            "success": true,
            "file_path": input_path.display().to_string(),
            "file_size": metadata.len(),
            "public_key": enc.public_key,
            "encrypted_data_size": base64::engine::general_purpose::STANDARD.decode(&enc.ciphertext)
                .map(|v| v.len())
                .unwrap_or(0),
        });
        
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        // Display information in text mode
        println!("Vault File: {}", input_path.display());
        println!("File Size: {} bytes", metadata.len());
        
        if let Ok(ciphertext) = base64::engine::general_purpose::STANDARD.decode(&enc.ciphertext) {
            println!("Encrypted Data Size: {} bytes", ciphertext.len());
        }
        
        println!("Public Key: {}", enc.public_key);
        
        println!("\nNote: Use the decrypt command with the correct password to access the contents.");
    }
    
    Ok(())
}

/// Encrypt data from stdin to stdout
fn encrypt_stream(password: Option<String>, verbose: u8, _json_format: bool) -> Result<(), String> {
    // Get password
    let password = match password {
        Some(pass) => {
            if verbose > 0 {
                eprintln!("Warning: Using password from command line is less secure");
            }
            pass
        },
        None => prompt_password("Enter encryption password")
            .map_err(|e| format!("Failed to read password: {}", e))?
    };
    
    // Read from stdin
    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf)
        .map_err(|e| format!("Failed to read from stdin: {}", e))?;
    
    if verbose > 0 {
        eprintln!("Encrypting {} bytes from stdin", buf.len());
    }
    
    // Encrypt data
    let enc = encrypt_data(&buf, &password);
    
    // Write to stdout
    let json = serde_json::to_string(&enc)
        .map_err(|e| format!("Failed to serialize encrypted data: {}", e))?;
    
    println!("{}", json);
    
    Ok(())
}

/// Decrypt data from stdin to stdout
fn decrypt_stream(password: Option<String>, verbose: u8, _json_format: bool) -> Result<(), String> {
    // Get password
    let password = match password {
        Some(pass) => {
            if verbose > 0 {
                eprintln!("Warning: Using password from command line is less secure");
            }
            pass
        },
        None => prompt_password("Enter decryption password")
            .map_err(|e| format!("Failed to read password: {}", e))?
    };
    
    // Read from stdin
    let mut buf = String::new();
    io::stdin().read_to_string(&mut buf)
        .map_err(|e| format!("Failed to read from stdin: {}", e))?;
    
    // Parse JSON
    let enc: EncryptedData = serde_json::from_str(&buf)
        .map_err(|e| format!("Failed to parse input - invalid format: {}", e))?;
    
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
fn run_tests(verbose: u8, json_format: bool) -> Result<(), String> {
    if verbose > 0 {
        eprintln!("Running self-tests...");
    }
    
    // Test 1: Basic encryption/decryption
    let test_data = b"Test data for encryption";
    let password = "test_password";
    
    if verbose > 1 {
        eprintln!("Test 1: Basic encryption/decryption");
    }
    
    let encrypted = encrypt_data(test_data, password);
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
    
    // Success
    let output = CommandOutput {
        success: true,
        message: "All tests passed successfully".to_string(),
        input_path: None,
        output_path: None,
        file_size: None,
        error: None,
    };
    
    output_result(output, json_format);
    
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    
    let result = match &cli.command {
        Commands::Encrypt(args) => encrypt_file(args.clone(), cli.verbose, cli.json),
        Commands::Decrypt(args) => decrypt_file(args.clone(), cli.verbose, cli.json),
        Commands::Validate { input } => validate_vault(input.clone(), cli.verbose, cli.json),
        Commands::Info { input } => show_vault_info(input.clone(), cli.verbose, cli.json),
        Commands::EncryptStream { password } => 
            encrypt_stream(password.clone(), cli.verbose, cli.json),
        Commands::DecryptStream { password } => 
            decrypt_stream(password.clone(), cli.verbose, cli.json),
        Commands::Test => run_tests(cli.verbose, cli.json),
    };
    
    if let Err(e) = result {
        if cli.json {
            let output = CommandOutput {
                success: false,
                message: e.clone(),
                input_path: None,
                output_path: None,
                file_size: None,
                error: Some(e),
            };
            
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        } else {
            eprintln!("Error: {}", e);
        }
        
        process::exit(1);
    }
}
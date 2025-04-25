mod types;
mod utils;
mod commands;
mod self_install;

use clap::{Parser, Subcommand, Args, ArgAction, ValueHint};
use std::path::PathBuf;
use std::process;
use types::CommandOutput;

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

    /// !!WIP!! Security profile: 
    #[arg(
        value_parser = ["interactive", "balanced", "paranoid"],
        long, default_value = "paranoid"
        )]
    security: String,
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

fn main() {
    self_install::ensure_installed();
    let cli = Cli::parse();

    
    let result = match &cli.command {
        Commands::Encrypt(args) => {
            use vault_core::types::SecurityLevel;
            let level = match args.security.as_str() {
                "interactive" => SecurityLevel::Interactive,
                "balanced"    => SecurityLevel::Balanced,
                "paranoid"    => SecurityLevel::Paranoid,
                _             => SecurityLevel::Paranoid,
            };
        
            commands::encrypt_file(
                args.input.clone(),
                args.output.clone(),
                args.password.clone(),
                args.comment.clone(),
                level,
                args.force,
                args.non_interactive,
                cli.verbose,
                cli.json,
            )
        },
        Commands::Decrypt(args) => commands::decrypt_file(
            args.input.clone(),
            args.output.clone(),
            args.password.clone(),
            args.force,
            args.non_interactive,
            cli.verbose, 
            cli.json
        ),
        Commands::Validate { input } => commands::validate_vault(
            input.clone(),
            cli.verbose, 
            cli.json
        ),
        Commands::Info { input } => commands::show_vault_info(
            input.clone(),
            cli.verbose, 
            cli.json
        ),
        Commands::EncryptStream { password } => commands::encrypt_stream(
            password.clone(),
            cli.verbose, 
            cli.json
        ),
        Commands::DecryptStream { password } => commands::decrypt_stream(
            password.clone(),
            cli.verbose, 
            cli.json
        ),
        Commands::Test => commands::run_tests(cli.verbose, cli.json),
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
                metadata: None,
            };
            
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        } else {
            eprintln!("Error: {}", e);
        }
        
        process::exit(1);
    }
}
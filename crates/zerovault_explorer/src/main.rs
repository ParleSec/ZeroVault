mod dialogs;
mod explorer;
mod operations;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::info;

/// ZeroVault Explorer Integration - Encrypt and decrypt files from file explorer
#[derive(Parser)]
#[command(name = "zerovault_explorer")]
#[command(version)]
#[command(about = "File explorer integration for ZeroVault encryption")]
#[command(author = "Mason Parle")]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Enable JSON output for programmatic usage
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file using a password
    Encrypt {
        /// File to encrypt
        file_path: PathBuf,
        
        /// Run in background mode (no console window)
        #[arg(short, long)]
        background: bool,
    },
    
    /// Decrypt a vault file using a password
    Decrypt {
        /// Vault file to decrypt
        file_path: PathBuf,
        
        /// Run in background mode (no console window)
        #[arg(short, long)]
        background: bool,
    },
    
    /// Install context menu integration for the current user
    Install {
        /// Skip confirmation dialog
        #[arg(long)]
        no_confirm: bool,
    },
    
    /// Remove context menu integration for the current user
    Uninstall {
        /// Skip confirmation dialog
        #[arg(long)]
        no_confirm: bool,
    },
}

#[cfg(windows)]
fn hide_console_window() {
    use windows_sys::Win32::System::Console::GetConsoleWindow;
    use windows_sys::Win32::UI::WindowsAndMessaging::{ShowWindow, SW_HIDE};
    
    unsafe {
        let console_window = GetConsoleWindow();
        if console_window != 0 {
            ShowWindow(console_window, SW_HIDE);
        }
    }
}

#[cfg(not(windows))]
fn hide_console_window() {
    // No-op on non-Windows platforms
}

fn main() {
    // Parse command line arguments
    let cli = Cli::parse();
    
    // Initialize logging based on verbosity
    if cli.verbose {
        tracing_subscriber::fmt::init();
        info!("ZeroVault Explorer starting up");
    }
    
    // Determine if we should run in background mode
    let background_mode = match &cli.command {
        Commands::Encrypt { background, .. } => *background,
        Commands::Decrypt { background, .. } => *background,
        _ => false,
    };
    
    // Hide console window if in background mode
    if background_mode {
        hide_console_window();
    }
    
    match cli.command {
        Commands::Encrypt { file_path, .. } => {
            if cli.verbose {
                info!("Encrypting file: {}", file_path.display());
            }
            
            // Show password input dialog
            let password = match dialogs::get_new_password() {
                Ok(pwd) => pwd,
                Err(e) => {
                    dialogs::show_error("Error", &format!("Failed to get password: {}", e));
                    return;
                }
            };
            
            if password.is_empty() {
                dialogs::show_error("Encryption canceled", "Operation was canceled by the user");
                return;
            }
            
            // Perform encryption
            match operations::encrypt_file(&file_path, &password) {
                Ok(output_path) => {
                    dialogs::show_success(
                        "Encryption successful",
                        &format!("File encrypted to: {}", output_path.display())
                    );
                },
                Err(err) => {
                    dialogs::show_error(
                        "Encryption failed",
                        &format!("Error: {}", err)
                    );
                }
            }
        },
        
        Commands::Decrypt { file_path, .. } => {
            if cli.verbose {
                info!("Decrypting file: {}", file_path.display());
            }
            
            // Show password input dialog
            let password = match dialogs::get_existing_password() {
                Ok(pwd) => pwd,
                Err(e) => {
                    dialogs::show_error("Error", &format!("Failed to get password: {}", e));
                    return;
                }
            };
            
            if password.is_empty() {
                dialogs::show_error("Decryption canceled", "Operation was canceled by the user");
                return;
            }
            
            // Perform decryption
            match operations::decrypt_file(&file_path, &password) {
                Ok(output_path) => {
                    dialogs::show_success(
                        "Decryption successful",
                        &format!("File decrypted to: {}", output_path.display())
                    );
                },
                Err(err) => {
                    dialogs::show_error(
                        "Decryption failed",
                        &format!("Error: {}", err)
                    );
                }
            }
        },
        
        Commands::Install { no_confirm } => {
            if !no_confirm {
                let confirmed = dialogs::show_confirmation(
                    "Install ZeroVault Integration",
                    "This will add ZeroVault to your file explorer context menu. Continue?"
                );
                
                if !confirmed {
                    return;
                }
            }
            
            match explorer::install_integration() {
                Ok(_) => {
                    dialogs::show_success(
                        "Installation successful",
                        "ZeroVault has been added to your file explorer context menu."
                    );
                },
                Err(err) => {
                    dialogs::show_error(
                        "Installation failed",
                        &format!("Error: {}", err)
                    );
                }
            }
        },
        
        Commands::Uninstall { no_confirm } => {
            if !no_confirm {
                let confirmed = dialogs::show_confirmation(
                    "Uninstall ZeroVault Integration",
                    "This will remove ZeroVault from your file explorer context menu. Continue?"
                );
                
                if !confirmed {
                    return;
                }
            }
            
            match explorer::uninstall_integration() {
                Ok(_) => {
                    dialogs::show_success(
                        "Uninstallation successful",
                        "ZeroVault has been removed from your file explorer context menu."
                    );
                },
                Err(err) => {
                    dialogs::show_error(
                        "Uninstallation failed",
                        &format!("Error: {}", err)
                    );
                }
            }
        },
    }
}
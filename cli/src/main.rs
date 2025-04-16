use clap::{Parser, Subcommand};
use std::fs;
use vault_core::crypto::{encrypt_data, decrypt_data};
use vault_core::types::EncryptedData;

/// CertusVault - Secure Credential Encryption CLI
#[derive(Parser)]
#[command(name = "certusvault")]
#[command(about = "Zero-trust identity vault", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        password: String,
    },
    Decrypt {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        password: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Encrypt { input, password } => {
            let data = fs::read(input).expect("Failed to read input file");
            let enc = encrypt_data(&data, password);
            let json = serde_json::to_string_pretty(&enc).unwrap();
            fs::write(format!("{}.vault", input), json).expect("Failed to write .vault file");
            println!("Encrypted and signed successfully.");
        }
        Commands::Decrypt { input, password } => {
            let json = fs::read_to_string(input).expect("Failed to read .vault file");
            let enc: EncryptedData = serde_json::from_str(&json).unwrap();
            let data = decrypt_data(&enc, password).expect("Decryption or signature check failed");
            fs::write(format!("{}.decrypted", input), data).expect("Failed to write decrypted file");
            println!("Decrypted and verified successfully.");
        }
    }
}

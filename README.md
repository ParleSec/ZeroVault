# ZeroVault

[![Rust Version](https://img.shields.io/badge/Rust-1.70%2B-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org/) [![Crypto](https://img.shields.io/badge/Encryption-AES--GCM%20%7C%20Ed25519-blue?style=for-the-badge&logo=lock)](https://docs.rs/aes-gcm) [![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

## Project Overview

**ZeroVault** is a lightweight cryptographic vault designed for encrypting and verifying sensitive documents using modern, secure encryption primitives. The vault uses AES-256-GCM for symmetric encryption and Ed25519 for digital signatures. It is written in Rust and offers cryptographic integrity, password-based key derivation (via Argon2), and support for secure serialization of encrypted artifacts.

## Purpose & Motivation

### Why ZeroVault Exists

Digital file protection requires a blend of confidentiality, integrity, and ease of use. ZeroVault aims to:

- Provide strong encryption using modern ciphers and key derivation
- Offer digital signature verification to detect tampering
- Simplify encryption/decryption processes via a CLI-based toolchain
- Be usable for SPII and document workflows

ZeroVault is particularly useful for developers and professionals seeking a verifiable and deterministic mechanism for protecting sensitive files during transmission or at rest.

## Architecture

### System Structure

- `vault_core`: Core cryptographic logic
- `cli`: Command-line interface for using the vault
- `types.rs`: Custom serializable types including encryption metadata
- `main.rs`: Entrypoint for CLI application

### Cryptographic Components

- **AES-GCM (256-bit)**: Symmetric encryption algorithm for confidentiality & integrity
- **Argon2id**: Password-based key derivation function with salt for secure key material
- **Ed25519**: Signature scheme to provide authenticity and non-repudiation

## Key Features

### 🔐 Secure Encryption

- Random nonces and salts per encryption
- Key derived from password using Argon2id
- Ciphertext authenticated with AES-GCM

### 🧾 Digital Signatures

- Signing of ciphertext with Ed25519 private key
- Signature verification using embedded public key

### 🔁 Serialization

- Metadata (nonce, salt, signature, pubkey, ciphertext) encoded to Base64
- Encrypted data structure: `EncryptedData`

### 🖥️ Interactive CLI

- User-friendly interface with interactive prompts
- Smart defaults for file paths and options
- Secure password entry with confirmation
- Optional comments for encrypted files

## Example Code

```rust
let keypair = SigningKey::generate(&mut OsRng);
let enc = encrypt_data(b"my secret data", "mypassword");
let result = decrypt_data(&enc, "mypassword").unwrap();
```

## Crates & Dependencies

- `aes-gcm` – AES-256-GCM authenticated encryption
- `argon2` – Secure key derivation (Argon2id)
- `base64` – Encoding for serialized outputs
- `ed25519-dalek` – Key generation & signature scheme
- `rand` – CSPRNG (OsRng)
- `serde` / `serde_json` – Serialization
- `clap` – Command line argument parsing
- `rpassword` – Secure password input

## Usage & CLI

ZeroVault CLI provides both interactive and non-interactive modes for encrypting and decrypting files.

### Interactive Mode (Default)

Simply run commands without all required arguments, and ZeroVault will prompt for the missing information:

```bash
# Interactive encryption (will prompt for input file, password, etc.)
zerovault encrypt

# Interactive decryption (will prompt for vault file, password, etc.)
zerovault decrypt
```

Example interactive session:
```
$ zerovault encrypt
Enter input file path: document.txt
Enter output file path [document.txt.vault]: 
Enter encryption password: ********
Confirm password: ********
Enter comment (optional): My secure document
✓ File encrypted successfully
  Input: document.txt
  Output: document.txt.vault
  Size: 1024 bytes
```

### Command-Line Arguments

For scripting or automation, you can provide all arguments directly:

```bash
# Encrypt a file
zerovault encrypt --input file.pdf --output file.vault --password mypassword --non-interactive

# Decrypt a file
zerovault decrypt --input file.vault --output file.pdf --password mypassword --non-interactive

# Force overwrite existing files
zerovault encrypt --input file.pdf --output file.vault --force
```

### Additional Commands

```bash
# Validate a vault file without decrypting
zerovault validate --input file.vault

# Display information about a vault file
zerovault info --input file.vault

# Stream encryption/decryption (pipe data through stdin/stdout)
cat file.txt | zerovault encrypt-stream --password mypassword > file.vault
cat file.vault | zerovault decrypt-stream --password mypassword > file_decrypted.txt

# Run self-tests
zerovault test
```

### Verbose Mode

Add `-v` or `--verbose` for more detailed output:

```bash
zerovault encrypt --input file.pdf --verbose
```

### JSON Output

For programmatic usage, add `--json` to get structured JSON output:

```bash
zerovault info --input file.vault --json
```


## Future Plans

- 🔒 CLI file encryption with vault format
- 📜 Public key export/import support
- 📤 Secure upload & retrieval workflows (REST API?)
- 💼 Integration into secure document management systems (SecureVault?)

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for more details.

---
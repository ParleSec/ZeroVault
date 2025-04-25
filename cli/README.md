# ZeroVault

[![Rust Version](https://img.shields.io/badge/Rust-1.70%2B-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org/) [![Crypto](https://img.shields.io/badge/Encryption-AES--GCM%20%7C%20Ed25519-blue?style=for-the-badge&logo=lock)](https://docs.rs/aes-gcm) [![Security](https://img.shields.io/badge/Security-Argon2%20%7C%20CSPRNG-red?style=for-the-badge&logo=shield)](https://en.wikipedia.org/wiki/Argon2) [![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

A Fort-Knox level document encryption command-line tool with defense-in-depth security.

## Installation

```bash
cargo install zerovault
```

## Features

- **Triple-layer encryption** using AES-256-GCM, ChaCha20-Poly1305, and AES-256-CBC
- **Digital signatures** for tamper detection using Ed25519
- **Maximum-security key derivation** with Argon2id (1GB memory cost)
- **Interactive and non-interactive modes** for ease of use and scripting
- **File and stream processing** for versatile encryption workflows
- **Metadata support** including comments, timestamps, and versioning
- **Validation and information commands** to examine vault files without decryption

## Quick Start

### Interactive Mode (Default)
```bash
# Basic encryption (will prompt for inputs)
zerovault encrypt

# Basic decryption (will prompt for inputs)
zerovault decrypt
```

### Non-Interactive Mode
```bash
# Encrypt a file with a password
zerovault encrypt --input document.pdf --output document.vault --password mypassword --non-interactive

# Decrypt a vault file
zerovault decrypt --input document.vault --output document.pdf --password mypassword --non-interactive
```

## Command Reference

### Encryption
```bash
# Add a comment to describe the encrypted content
zerovault encrypt --input file.txt --comment "Confidential data" 

# Force overwrite of existing files
zerovault encrypt --input file.txt --output encrypted.vault --force
```

### Decryption
```bash
# Basic decryption with output file specification
zerovault decrypt --input file.vault --output recovered.txt

# Force overwrite of existing files
zerovault decrypt --input file.vault --output recovered.txt --force
```

### Validation and Information
```bash
# Validate a vault file structure without decrypting
zerovault validate --input file.vault

# Show information about a vault file
zerovault info --input file.vault

# Output information in JSON format
zerovault info --input file.vault --json
```

### Stream Processing
```bash
# Encrypt data from stdin to stdout
cat file.txt | zerovault encrypt-stream --password mypassword > file.vault

# Decrypt data from stdin to stdout
cat file.vault | zerovault decrypt-stream --password mypassword > file_decrypted.txt
```

### Testing
```bash
# Run self-tests to verify encryption/decryption
zerovault test
```

## Security Features

- **Paranoid Security Level**: All operations use maximum security parameters (1GB memory cost, 12 Argon2id iterations)
- **Memory protection**: Secure memory with guard pages and canaries
- **Zero-knowledge architecture**: Data never leaves your device
- **Tamper-resistant**: Cryptographic signatures detect any modification
- **Defense-in-depth**: Multiple security layers with independent algorithms
- **Side-channel protection**: Memory zeroing and timing attack mitigations

## Batch Processing

Process multiple files easily with scripts:

```bash
# Encrypt all text files in directory
for file in *.txt; do
  zerovault encrypt --input "$file" --password batch_password --non-interactive
done

# Validate all vault files
for vault in *.vault; do
  zerovault validate --input "$vault"
done
```

## JSON Output

For integration with other tools:

```bash
zerovault info --input file.vault --json
zerovault encrypt --input file.txt --json
```

## Example Interactive Session

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
  Comment: My secure document
```

## Advanced Use Cases

### Nested Encryption

You can encrypt already encrypted files for layered security:

```bash
# First layer of encryption
zerovault encrypt --input secret.txt --output layer1.vault --password inner_password

# Second layer of encryption
zerovault encrypt --input layer1.vault --output layer2.vault --password outer_password
```

### Secure Workflows

For secure document sharing:

```bash
# 1. Sender encrypts file with comment
zerovault encrypt --input presentation.pptx --comment "For review - Confidential" 

# 2. Share the vault file and password securely with recipient

# 3. Recipient verifies file metadata before decryption
zerovault info --input presentation.pptx.vault

# 4. Recipient decrypts file
zerovault decrypt --input presentation.pptx.vault
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Core Library

ZeroVault is built on the `zero_vault_core` library, which is also available on crates.io for use in other Rust projects.
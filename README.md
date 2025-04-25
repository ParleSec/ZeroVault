# ZeroVault

[![Rust Version](https://img.shields.io/badge/Rust-1.70%2B-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org/) [![Crypto](https://img.shields.io/badge/Encryption-AES--GCM%20%7C%20ChaCha20%20%7C%20Ed25519-blue?style=for-the-badge&logo=lock)](https://docs.rs/aes-gcm) [![Security](https://img.shields.io/badge/Security-Argon2id%20%7C%20CSPRNG-red?style=for-the-badge&logo=shield)](https://en.wikipedia.org/wiki/Argon2) [![CLI](https://img.shields.io/badge/Interface-CLI-purple?style=for-the-badge&logo=powershell)](https://github.com/clap-rs/clap) [![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE) 

**ZeroVault** is a lightweight cryptographic vault designed for encrypting and verifying sensitive documents using modern, secure encryption primitives. With a simple command like `zerovault encrypt`, your data is protected by multiple layers of strong encryption.

ZeroVault automatically installs itself to `~/.zerovault/bin/` (or Windows equivalent) and adds this location to your PATH.

For detailed installation instructions, see [INSTALL.md](INSTALL.md).

## Purpose & Motivation

Digital file protection requires a blend of confidentiality, integrity, and ease of use. ZeroVault aims to:

- Provide strong encryption using modern ciphers and key derivation
- Offer digital signature verification to detect tampering
- Simplify encryption/decryption processes via a CLI-based toolchain
- Be usable for SPII and document workflows

ZeroVault is particularly useful for developers and professionals seeking a verifiable and deterministic mechanism for protecting sensitive files during transmission or at rest.

## Quick Installation

ZeroVault features automatic self-installation:

```bash
# Windows
curl.exe -L -o zerovault.exe https://github.com/ParleSec/zerovault/releases/latest/download/zerovault-windows-amd64.exe
.\zerovault.exe --version

# Linux
curl -L -o zerovault https://github.com/ParleSec/zerovault/releases/latest/download/zerovault-linux-amd64
chmod +x zerovault
./zerovault --version
```

## Key Features

### 🔐 Secure Encryption

- **Triple-layer protection**: Uses AES-256-GCM, ChaCha20-Poly1305, and AES-256-CBC
- Random nonces and salts per encryption
- Key derived from password using Argon2id with configurable memory cost (256MB-1GB)
- Multiple security levels from interactive (faster) to paranoid (maximum security)

### 🧾 Digital Signatures

- Signing of ciphertext with Ed25519 private key
- Signature verification using embedded public key
- Cryptographic proof of file integrity

### 🛡️ Memory Protection

- Memory locking to prevent sensitive data from being swapped to disk
- Guard pages for buffer overflow detection
- Canary values for memory tampering detection
- Multi-pass secure memory zeroization

### 📋 Metadata Support

- File comments for describing encrypted content
- Creation and modification timestamps
- Version tracking for backward compatibility
- Full JSON serialization of all metadata

### 🔁 Serialization

- All binary data (nonce, salt, signature, pubkey, ciphertext) encoded to Base64
- Structured vault format with separate data and metadata sections
- Backward compatibility with legacy vault formats

### 🖥️ Interactive CLI

- User-friendly interface with interactive prompts
- Smart defaults for file paths and options
- Secure password entry with confirmation
- Optional comments for encrypted files

## Security Architecture

### Triple-Layer Encryption

ZeroVault employs three independent encryption layers:

1. **AES-256-GCM**: Authenticated encryption providing confidentiality and integrity
2. **ChaCha20-Poly1305**: Stream cipher with integrated authentication
3. **AES-256-CBC with HMAC-SHA512**: Block cipher with separate message authentication

Each layer uses independent keys, nonces, and authentication mechanisms to ensure that a vulnerability in one algorithm doesn't compromise your data.

### Key Derivation

- **Argon2id**: Memory-hard algorithm resistant to specialized hardware attacks
- **Tunable Parameters**:
  - Memory usage: 1GB 
  - Iteration count: 12 passes for maximum security level
  - Parallelism: Automatically utilizes available CPU cores

### Implementation Details

- **Memory Safety**: Built in Rust to eliminate common vulnerability classes
- **Modular Design**: Core cryptography isolated from interface code
- **Comprehensive Testing**: Unit tests, integration tests, property-based testing
- **Self-Installing**: Automatically configures itself on first run

## Command Reference

| Command | Description | Example |
|---------|-------------|---------|
| `encrypt` | Encrypt a file | `zerovault encrypt --input file.pdf` |
| `decrypt` | Decrypt a vault file | `zerovault decrypt --input file.vault` |
| `info` | Display vault metadata | `zerovault info --input file.vault` |
| `validate` | Verify vault integrity | `zerovault validate --input file.vault` |
| `encrypt-stream` | Encrypt from stdin to stdout | `cat file.txt \| zerovault encrypt-stream` |
| `decrypt-stream` | Decrypt from stdin to stdout | `cat file.vault \| zerovault decrypt-stream` |
| `test` | Run self-tests | `zerovault test` |

For complete options, run `zerovault --help` or `zerovault <command> --help`.

## Security Considerations

### Strengths

- Multiple independent encryption layers
- Memory-hard key derivation resistant to brute-force attacks
- Written in Rust for memory safety
- Constant-time operations for cryptographic functions
- Unique cryptographic material for each file

### Limitations

- Security depends significantly on password strength
- Higher security levels require substantial RAM (up to 1GB)
- Stronger security comes with performance trade-offs
- No current support for public key encryption
- Side-channel protection depends on hardware/OS capabilities

### Best Practices

- Use strong, unique passwords
- Select appropriate security level for your needs
- Verify metadata before decryption
- Keep secure backups of encrypted files
- Consider offline storage for the most sensitive vault files

## Comparison with Alternatives

| Feature | ZeroVault | GPG | VeraCrypt | Age |
|---------|-----------|-----|-----------|-----|
| **Multiple Encryption Layers** | ✅ (3 layers) | ❌ | ✅ (2 layers) | ❌ |
| **Memory-Hard KDF** | ✅ (Argon2id) | ❌ | ✅ (PBKDF2) | ✅ (scrypt) |
| **Digital Signatures** | ✅ | ✅ | ❌ | ❌ |
| **Memory Safety** | ✅ (Rust) | ❌ (C) | ❌ (C/C++) | ✅ (Go) |
| **Self-Installing** | ✅ | ❌ | ❌ | ❌ |
| **Stream Processing** | ✅ | ✅ | ❌ | ✅ |
| **File Comments** | ✅ | ✅ | ❌ | ❌ |
| **Volume Encryption** | ❌ | ❌ | ✅ | ❌ |

## Getting Started

### Basic Usage

```bash
# Encrypt a file (interactive mode)
zerovault encrypt

# Decrypt a file (interactive mode)
zerovault decrypt

# View information about an encrypted file
zerovault info --input document.txt.vault
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
  Comment: My secure document
```

### Security Profiles

Choose between different security levels:

```bash
# Fast with 256MB memory (suitable for most uses)
zerovault encrypt --input document.pdf --security interactive

# Balanced with 512MB memory
zerovault encrypt --input document.pdf --security balanced

# Maximum with 1GB memory (default)
zerovault encrypt --input document.pdf --security paranoid
```

### Command-Line Arguments

For scripting or automation:

```bash
# Encrypt a file
zerovault encrypt --input file.pdf --output file.vault --password mypassword --non-interactive

# Decrypt a file
zerovault decrypt --input file.vault --output file.pdf --password mypassword --non-interactive

# Force overwrite existing files
zerovault encrypt --input file.pdf --output file.vault --force
```

### Stream Processing

Work with standard input/output:

```bash
# Encrypt from stdin to a file
cat document.txt | zerovault encrypt-stream --password "your-password" > document.vault

# Decrypt from a file to stdout
cat document.vault | zerovault decrypt-stream --password "your-password" > document.txt
```

### Batch Processing

Process multiple files:

```bash
# Batch encrypt all text files in a directory
for file in *.txt; do
  zerovault encrypt --input "$file" --password batch_password --non-interactive
done

# Batch validate all vault files
for vault in *.vault; do
  zerovault validate --input "$vault"
done
```

### Additional Options

```bash
# Verbose output
zerovault encrypt --input file.pdf --verbose

# JSON output for programmatic usage
zerovault info --input file.vault --json
```

Example JSON output:
```json
{
  "encrypted_data_size": 423,
  "file_path": "file.vault",
  "file_size": 974,
  "metadata": {
    "comment": "Confidential document",
    "created_at": 1745333818,
    "version": "2.0.0"
  },
  "public_key": "YiN4WYqupD3vyefIFh0ESlRRRX2yvOMWGkXQZKW3HH0=",
  "success": true
}
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



## Architecture

### System Structure

- `vault_core`: Core cryptographic logic
- `cli`: Command-line interface for using the vault
  - `types.rs`: Custom serializable types including encryption metadata
  - `utils.rs`: Utility functions for CLI operations
  - `commands.rs`: Command implementations
  - `main.rs`: Entrypoint for CLI application
  - `self_install.rs`: Automatic installation logic

The modular design ensures separation of concerns, with the core cryptographic functionality isolated from the command-line interface. This makes the code more maintainable and allows for easy extension of features.

## Crates & Dependencies

- `aes-gcm` - AES-256-GCM authenticated encryption
- `chacha20poly1305` - ChaCha20-Poly1305 authenticated encryption
- `aes` / `cbc` - AES-256-CBC block cipher
- `argon2` - Secure key derivation (Argon2id)
- `ed25519-dalek` - Key generation & signature scheme
- `rand` / `getrandom` - CSPRNG (OsRng)
- `blake3` / `sha2` / `sha3` - Cryptographic hash functions
- `hmac` / `hkdf` - HMAC and key derivation
- `zeroize` / `secrecy` - Secure memory handling
- `serde` / `serde_json` / `bincode` - Serialization
- `base64` - Encoding for serialized outputs
- `clap` - Command line argument parsing
- `rpassword` - Secure password input
- `chrono` - Date and time formatting

## Future Plans

- 📜 Public key export/import support
- 🏷️ Tagging and categorization for vault files
- 🔍 Search functionality for vault metadata
- 📤 Secure upload & retrieval workflows (REST API)
- 🗄️ Multi-file archive support
- 💼 Integration into secure document management systems

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for more details.

---

<div align="center">
<i>ZeroVault: Defense-in-depth file encryption, simplified.</i>
</div>
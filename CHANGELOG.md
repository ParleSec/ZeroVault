# Changelog

All notable features and changes to ZeroVault will be documented in this file.

## [1.0.0] - 2025-04-25 - "Knox" Release

This is the first major public release of ZeroVault, featuring a comprehensive encryption and file security system designed to provide Fort-Knox level protection for sensitive documents.

### Core Security Features

- **Triple-Layer Encryption Architecture**
  - Primary Layer: AES-256-GCM authenticated encryption
  - Secondary Layer: ChaCha20-Poly1305 authenticated encryption 
  - Tertiary Layer: AES-256-CBC with independent HMAC-SHA512
  - Complete defense-in-depth design requiring all layers to be compromised

- **Advanced Key Management**
  - Password-based key derivation using memory-hard Argon2id
  - Shamir's Secret Sharing for master key splitting (threshold scheme)
  - Sophisticated key hierarchy with domain separation
  - Multiple independent key derivation functions (Argon2id, PBKDF2, HKDF)
  - Ed25519 digital signatures for authentication and integrity

- **Customizable Security Levels**
  - Interactive Mode: Balanced for everyday use while maintaining strong security
  - Balanced Mode: Enhanced parameters for sensitive documents
  - Paranoid Mode: Maximum security with 1GB memory cost and 16-pass key derivation

- **Memory Protection**
  - Guard pages to detect buffer overflows and exploits
  - Memory locking to prevent sensitive data from being swapped to disk
  - Canary values for detecting memory tampering attempts
  - Multi-pass secure memory zeroization for data remnant prevention
  - Protected memory allocation with side-channel mitigation

- **Anti-Forensic and Side-Channel Protection**
  - Constant-time operations for cryptographically sensitive functions
  - Variable-length padding to prevent size correlation
  - Decoy data to frustrate forensic analysis
  - Randomized timestamps to prevent correlation attacks
  - Integrity verification through multiple independent mechanisms

### Usability Features

- **Interactive Command-Line Interface**
  - User-friendly design with smart defaults
  - Secure password entry with confirmation
  - Interactive prompts for missing parameters
  - Command completion and input validation
  - Clear error messages and security warnings

- **File Management**
  - Single file encryption and decryption
  - Optional file comments and metadata
  - Creation and modification timestamps
  - Version tracking for backward compatibility
  - Non-destructive operations with confirmation prompts

- **Operational Modes**
  - Standard file-to-file encryption
  - Stream processing for stdin/stdout operations
  - Batch processing for multiple files
  - Validation mode to verify vault files without decryption
  - Information display for examining vault metadata

- **Format and Compatibility**
  - JSON serialization with Base64 encoding of binary data
  - Structured vault format with separate data and metadata sections
  - Full compatibility across operating systems
  - Complete separation of cryptographic core from interface

- **Output Options**
  - Standard human-readable output
  - JSON output mode for programmatic usage
  - Verbose mode for detailed operation information
  - Non-interactive mode for scripting and automation

### Technical Implementations

- **Cryptographic Primitives**
  - AES-256-GCM for authenticated encryption
  - ChaCha20-Poly1305 for secondary authenticated encryption
  - AES-256-CBC with HMAC-SHA512 for tertiary protection
  - Ed25519 for digital signatures
  - SHA-512 and BLAKE3 for integrity verification
  - HMAC for authenticated hashing
  - Secure random number generation via OS entropy

- **Key Derivation**
  - Argon2id with high memory cost (configurable up to 1GB)
  - Configurable parameters for time cost, memory, and parallelism
  - Salt generation with entropy verification
  - Secondary derivation with PBKDF2-HMAC-SHA512
  - Independent keys for each cryptographic operation
  
- **Memory Security**
  - Custom allocator with guard page protection
  - Memory locking via mlock/VirtualLock
  - Canary-based tamper detection
  - Statistical entropy verification
  - Multi-level zeroization for sensitive data
  - Constant-time comparison functions

- **Integrity Protection**
  - Ed25519 signatures over all ciphertext layers
  - SHA-512 integrity hash for primary verification
  - BLAKE3 hash for secondary verification
  - HMAC verification of parameters
  - Structure validation for complete vault files

### Platforms and Support

- **Cross-Platform Support**
  - Linux (various distributions)
  - macOS (Intel and Apple Silicon)
  - Windows
  - BSD variants

- **Command-Line Tools**
  - `encrypt` - Secure file encryption
  - `decrypt` - Authenticated file decryption
  - `validate` - Verify vault file integrity without decryption
  - `info` - Display vault file metadata
  - `encrypt-stream` - Process data from stdin/stdout
  - `decrypt-stream` - Decrypt data from stdin/stdout
  - `test` - Run self-tests for verification

- **Documentation**
  - Comprehensive README with usage examples
  - Security design documentation
  - CLI command reference
  - Batch processing examples
  - Advanced use cases

---
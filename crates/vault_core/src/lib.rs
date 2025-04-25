//! # ZeroVault Core - Fort-Knox Level Cryptographic Security
//!
//! This crate provides enterprise-grade, maximum security cryptographic operations
//! for the ZeroVault secure document encryption system. It implements a comprehensive
//! defense-in-depth approach with:
//!
//! - Triple-layer encryption using multiple algorithms
//! - Advanced key derivation with Argon2id (1GB memory cost)
//! - Key splitting using Shamir's Secret Sharing
//! - Secure memory management with guard pages and canaries
//! - Side-channel attack resistance
//! - Comprehensive integrity verification
//!
//! ## Security Design
//!
//! ZeroVault Core implements a true "defense-in-depth" approach where multiple
//! independent security layers must be breached to compromise the data:
//!
//! 1. **Outer Layer**: AES-256-GCM authenticated encryption
//! 2. **Middle Layer**: ChaCha20-Poly1305 authenticated encryption
//! 3. **Inner Layer**: AES-256-CBC with independent HMAC-SHA512
//!
//! ## Memory Security
//!
//! All sensitive data is protected in memory using:
//!
//! - Memory locking to prevent swapping to disk
//! - Guard pages to detect buffer overflows
//! - Memory canaries for tampering detection
//! - Secure multi-pass memory zeroization
//!
//! ## Usage Example
//!
//! ```no_run
//! use zero_vault_core::{encrypt_data, decrypt_data};
//!
//! // Encrypt data with maximum security
//! let data = b"Sensitive information";
//! let password = "complex-password-example";
//!
//! let encrypted = encrypt_data(data, password).unwrap();
//!
//! // Decrypt data with all security verifications
//! let decrypted = decrypt_data(&encrypted, password).unwrap();
//! assert_eq!(data.to_vec(), decrypted);
//! ```

// Changed from #![forbid(unsafe_code)] to #![deny(unsafe_code)]
// This allows us to use #[allow(unsafe_code)] in specific modules
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![doc(html_logo_url = "https://example.com/logo.png")]
#![doc(html_favicon_url = "https://example.com/favicon.ico")]

/// Cryptographic operations module providing encryption, decryption, and key management
///
/// This module implements the core cryptographic functionality:
/// - Triple-layer encryption using AES-GCM, ChaCha20-Poly1305, and AES-CBC
/// - Key derivation with Argon2id and PBKDF2
/// - Digital signatures with Ed25519
/// - Secure random number generation and entropy verification
pub mod crypto;

/// Core data structures and types used throughout the library
///
/// This module defines:
/// - Encrypted data container (`VaultEncryptedData`)
/// - Security parameters for encryption operations
/// - Error types with safe information disclosure
/// - Secure key containers with automatic zeroization
pub mod types;

/// Secure memory management with protection against various attacks
///
/// This module implements:
/// - Guard pages to detect buffer overflows
/// - Memory locking to prevent swapping to disk
/// - Canary values to detect memory tampering
/// - Multi-pass secure memory zeroization
/// - Secure memory containers for sensitive data
pub mod memory;

// Initialize secure memory on crate load
#[allow(unused_imports)]
use std::sync::Once;

static INIT: Once = Once::new();

// Initialize secure memory management when the library is loaded
fn initialize() {
    INIT.call_once(|| {
        let _ = memory::init_secure_memory();
    });
}

// Re-export commonly used types and functions
pub use types::{
    SecureKey, VaultEncryptedData, VaultEncryptionParams, VaultError, VaultKeyHierarchy,
};

pub use crypto::{decrypt_data, encrypt_data};

pub use memory::{SecureBytes, SecureMemory, SecureString};

// Execute initialization when the crate is loaded
#[doc(hidden)]
pub fn _internal_initialize() {
    initialize();
}

// Ensure initialization happens
#[ctor::ctor]
fn init_on_load() {
    _internal_initialize();
}

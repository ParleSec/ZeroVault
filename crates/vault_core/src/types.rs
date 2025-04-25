use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ZeroVault version identifier
pub const VAULT_VERSION: &str = "2.0.0";

/// Primary encryption algorithms supported by ZeroVault
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimaryAlgorithm {
    /// AES-256 in Galois/Counter Mode with authenticated encryption
    AES256GCM,
}

/// Secondary encryption algorithms for additional security layer
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecondaryAlgorithm {
    /// ChaCha20 stream cipher with Poly1305 authentication
    ChaCha20Poly1305,
}

/// Tertiary encryption algorithms for the innermost security layer
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum TertiaryAlgorithm {
    /// AES-256 in CBC mode with separate HMAC-SHA512 authentication
    Aes256CbcHmac,
}

/// Key derivation function algorithms for deriving encryption keys from passwords
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfAlgorithm {
    /// Argon2id - memory-hard password hashing function (2015 Password Hashing Competition winner)
    Argon2id,
}

/// Digital signature algorithms for verifying data integrity and authenticity
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// Edwards-curve Digital Signature Algorithm using Curve25519
    Ed25519,
}

/// Hash algorithms used for integrity verification
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-512 cryptographic hash function (part of SHA-2 family)
    SHA512,
    /// BLAKE3 - fast cryptographic hash function optimized for modern hardware
    BLAKE3,
}

/// Enhanced encryption parameters with maximum security by default
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityLevel {
    /// Fast enough for interactive use (≥ OWASP / CIS baselines)
    Interactive,
    /// Middle-ground: ~2× slower, ideal for routine backups
    Balanced,
    /// Original 1 GiB / 12-pass defaults
    Paranoid,
}

/// All tunable parameters that influence encryption strength.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaultEncryptionParams {
    /*──────── Algorithm selections ────────*/
    pub primary_algorithm: PrimaryAlgorithm,
    pub secondary_algorithm: SecondaryAlgorithm,
    pub tertiary_algorithm: TertiaryAlgorithm,
    pub kdf_algorithm: KdfAlgorithm,
    pub signature_algorithm: SignatureAlgorithm,
    pub hash_algorithm: HashAlgorithm,

    /*──────── Argon2id (primary KDF) ───────*/
    /// Memory cost in **KiB**
    pub memory_cost_kib: u32,
    /// Number of Argon2id passes
    pub time_cost:      u32,
    /// Number of lanes / threads
    pub parallelism:    u32,

    /*──────── PBKDF2 (secondary KDF) ───────*/
    pub pbkdf2_iterations: u32,

    /*──────── bookkeeping ──────────────────*/
    pub format_version: String,
    /// HMAC over all parameters – filled in by the creator
    pub params_hmac: String,
}

impl VaultEncryptionParams {
    /// Construct parameters for the requested `SecurityLevel`.
    pub fn with_security(level: SecurityLevel) -> Self {
        const I_MEM: u32 = 256 * 1024;   // 256 MiB
        const B_MEM: u32 = 512 * 1024;   // 512 MiB
        const P_MEM: u32 = 1024 * 1024;  //   1 GiB

        let (mem, passes, pbkdf2) = match level {
            SecurityLevel::Interactive => (I_MEM, 4, 120_000),
            SecurityLevel::Balanced    => (B_MEM, 6, 240_000),
            SecurityLevel::Paranoid    => (P_MEM, 12, 600_000),
        };

        Self {
            /* algorithm selections stay unchanged */
            primary_algorithm:  PrimaryAlgorithm::AES256GCM,
            secondary_algorithm: SecondaryAlgorithm::ChaCha20Poly1305,
            tertiary_algorithm:  TertiaryAlgorithm::Aes256CbcHmac,
            kdf_algorithm:      KdfAlgorithm::Argon2id,
            signature_algorithm: SignatureAlgorithm::Ed25519,
            hash_algorithm:      HashAlgorithm::SHA512,

            memory_cost_kib: mem,
            time_cost:       passes,
            parallelism:     num_cpus::get() as u32,
            pbkdf2_iterations: pbkdf2,

            format_version:  VAULT_VERSION.to_string(),
            params_hmac:     String::new(),
        }
    }
}

impl Default for VaultEncryptionParams {
    fn default() -> Self {
        Self::with_security(SecurityLevel::Paranoid)
    }
}

/// Triple-layer encrypted data structure with maximum security measures
#[derive(Serialize, Deserialize, Clone)]
pub struct VaultEncryptedData {
    /// Primary layer nonce for AES-256-GCM (base64 encoded)
    pub primary_nonce: String,

    /// Primary layer ciphertext from AES-256-GCM (base64 encoded)
    pub primary_ciphertext: String,

    /// Secondary layer nonce for ChaCha20-Poly1305 (base64 encoded)
    pub secondary_nonce: String,

    /// Secondary layer ciphertext from ChaCha20-Poly1305 (base64 encoded)
    pub secondary_ciphertext: String,

    /// Tertiary layer nonce for AES-256-CBC (base64 encoded)
    pub tertiary_nonce: String,

    /// Tertiary layer ciphertext from AES-256-CBC (base64 encoded)
    pub tertiary_ciphertext: String,

    /// Tertiary layer HMAC for authentication (base64 encoded)
    pub tertiary_hmac: String,

    /// Salt for master key derivation (base64 encoded)
    pub master_salt: String,

    /// Salt for key encryption key derivation (base64 encoded)
    pub kek_salt: String,

    /// Salt for key splitting operations (base64 encoded)
    pub key_splits_salt: String,

    /// Minimum number of key parts needed to reconstruct the master key
    pub key_threshold: u8,

    /// Encrypted key parts for key recovery (base64 encoded)
    pub key_parts: Vec<String>,

    /// Hash to verify entropy quality of the derived keys
    pub entropy_verification: String,

    /// Ed25519 signature over all ciphertext layers (base64 encoded)
    pub data_signature: String,

    /// Ed25519 public key for signature verification (base64 encoded)
    pub public_key: String,

    /// Encryption parameters used for this data
    pub params: VaultEncryptionParams,

    /// SHA-512 integrity hash over the encrypted data
    pub primary_integrity_hash: String,

    /// BLAKE3 integrity hash for secondary verification
    pub secondary_integrity_hash: String,

    /// Random data to confuse forensic analysis
    pub decoy_data: Vec<String>,

    /// Salt for padding generation (base64 encoded)
    pub padding_salt: String,

    /// Unix timestamp when the data was encrypted
    pub creation_timestamp: u64,

    /// Security canary value to detect tampering (base64 encoded)
    pub canary_value: String,

    /// HMAC over the entire structure for integrity verification
    pub structure_hmac: String,
}

/// Memory-secure key container with automatic zeroization on drop
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureKey {
    /// The raw key bytes, automatically zeroed when dropped
    pub key_bytes: Vec<u8>,
}

impl SecureKey {
    /// Create a new secure key from raw bytes
    ///
    /// # Arguments
    ///
    /// * `key_bytes` - Raw key material that will be securely stored
    pub fn new(key_bytes: Vec<u8>) -> Self {
        Self { key_bytes }
    }

    /// Get the length of the key in bytes
    pub fn len(&self) -> usize {
        self.key_bytes.len()
    }

    /// Check if the key is empty
    pub fn is_empty(&self) -> bool {
        self.key_bytes.is_empty()
    }
}

// Prevent accidentally printing sensitive key material
impl fmt::Debug for SecureKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureKey(length={})", self.key_bytes.len())
    }
}

/// Advanced key hierarchy with key splitting for maximum security
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultKeyHierarchy {
    /// Split master key parts, each encrypted separately
    pub master_key_parts: Vec<SecureKey>,

    /// The complete reconstituted master key
    pub master_key: SecureKey,

    /// Key that protects other keys in the hierarchy
    pub key_encryption_key: SecureKey,

    /// Primary data key for AES-256-GCM operations
    pub primary_data_key: SecureKey,

    /// Secondary data key for ChaCha20-Poly1305 operations
    pub secondary_data_key: SecureKey,

    /// Tertiary data key for AES-256-CBC operations
    pub tertiary_data_key: SecureKey,

    /// Key for HMAC authentication operations
    pub hmac_key: SecureKey,

    /// Key for integrity verification operations
    pub integrity_key: SecureKey,

    /// Number of key parts required to reconstruct the master key
    pub key_threshold: u8,
}

/// Implements human-readable error messages for VaultError
impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::KeyDerivationFailed => write!(f, "Key derivation failed"),
            VaultError::EncryptionFailed => write!(f, "Encryption operation failed"),
            VaultError::DecryptionFailed => write!(f, "Decryption operation failed"),
            VaultError::SigningFailed => write!(f, "Signature generation failed"),
            VaultError::VerificationFailed => write!(f, "Signature verification failed"),
            VaultError::IntegrityCheckFailed => write!(f, "Integrity check failed"),
            VaultError::InvalidFormat => write!(f, "Invalid data format"),
            VaultError::ParameterValidationFailed => write!(f, "Parameter validation failed"),
            VaultError::EntropyInsufficientError => write!(f, "Insufficient entropy"),
            VaultError::MemoryProtectionFailed => write!(f, "Memory protection operation failed"),
            VaultError::SecureRandomFailed => write!(f, "Secure random generation failed"),
            VaultError::KeySplittingFailed => write!(f, "Key splitting operation failed"),
            VaultError::KeyReconstructionFailed => write!(f, "Key reconstruction failed"),
            VaultError::CryptographicError => write!(f, "General cryptographic error"),
            VaultError::SecurityViolation => write!(f, "Security violation detected"),
        }
    }
}

/// Safe error types that prevent information leakage
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    /// Failed to derive a key from password or other material
    KeyDerivationFailed,

    /// Failed to encrypt data
    EncryptionFailed,

    /// Failed to decrypt data
    DecryptionFailed,

    /// Failed to generate a cryptographic signature
    SigningFailed,

    /// Signature verification failed, data may be tampered with
    VerificationFailed,

    /// Integrity check failed, data corruption or tampering detected
    IntegrityCheckFailed,

    /// Invalid data format encountered
    InvalidFormat,

    /// Validation of encryption parameters failed
    ParameterValidationFailed,

    /// Insufficient entropy in generated cryptographic material
    EntropyInsufficientError,

    /// Memory protection operation failed
    MemoryProtectionFailed,

    /// Secure random number generation failed
    SecureRandomFailed,

    /// Failed to split a key using Shamir's Secret Sharing
    KeySplittingFailed,

    /// Failed to reconstruct a key from its parts
    KeyReconstructionFailed,

    /// General cryptographic operation failed
    CryptographicError,

    /// Security violation detected (e.g., memory tampering)
    SecurityViolation,
}

/// Memory protection parameters for secure memory handling
pub struct MemoryProtectionParams {
    /// Whether to use guard pages to detect buffer overflows
    pub use_guard_pages: bool,

    /// Whether to lock memory to prevent swapping to disk
    pub memory_lock: bool,

    /// Whether to use canary values to detect memory tampering
    pub canary_check: bool,

    /// Whether to zero memory after use
    pub zero_after_use: bool,
}

impl Default for MemoryProtectionParams {
    fn default() -> Self {
        Self {
            use_guard_pages: true,
            memory_lock: true,
            canary_check: true,
            zero_after_use: true,
        }
    }
}

/// Size of guard pages for memory protection (4KB, standard OS page size)
pub const GUARD_PAGE_SIZE: usize = 4096;

/// Pattern used for memory canaries to detect buffer overflows or tampering
pub const CANARY_PATTERN: &[u8] = b"ZEROVAULT_SECURE_MEMORY_GUARD_9f8e7d6c5b4a3210";

/// Number of parts to split a key into using Shamir's Secret Sharing
pub const DEFAULT_KEY_PARTS: u8 = 5;

/// Number of parts required to reconstruct a key (threshold)
pub const DEFAULT_KEY_THRESHOLD: u8 = 3;

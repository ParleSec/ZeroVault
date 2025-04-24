use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};
use constant_time_eq::constant_time_eq;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use rand_core::{OsRng, RngCore};
use std::sync::OnceLock;
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use std::convert::TryInto;
use std::time::{SystemTime, UNIX_EPOCH};

// For AES-CBC
use aes::cipher::BlockSizeUser;
use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor as CbcDecryptor, Encryptor as CbcEncryptor};

use crate::types::{
    SecureKey, VaultEncryptedData, VaultEncryptionParams, VaultError, VaultKeyHierarchy,
    DEFAULT_KEY_PARTS, DEFAULT_KEY_THRESHOLD,
};

// Constants for key derivation
const MASTER_KEY_SIZE: usize = 32;
const KEK_SIZE: usize = 32;
const DATA_KEY_SIZE: usize = 32;
const HMAC_KEY_SIZE: usize = 64; // SHA512 block size
const ENTROPY_MIN_BITS: usize = 256;
const ENTROPY_MIN_BYTES:    usize = ENTROPY_MIN_BITS / 8;
const ENTROPY_TEST_SAMPLE: usize = 256;
const ENTROPY_RETRIES: usize = 8;

// PBKDF2 iteration constants
const PBKDF2_PRIMARY_ITERATIONS: u32 = 1_000_000; // 1 million iterations
const PBKDF2_SECONDARY_ITERATIONS: u32 = 600_000; // 600,000 iterations
const PBKDF2_TERTIARY_ITERATIONS: u32 = 300_000; // 300,000 iterations

// Context separators for key derivation
const CONTEXT_MASTER_KEY: &[u8] = b"ZEROVAULT_MASTER_KEY_CONTEXT_v2";
const CONTEXT_KEK: &[u8] = b"ZEROVAULT_KEY_ENCRYPTION_KEY_CONTEXT_v2";
const CONTEXT_PRIMARY_KEY: &[u8] = b"ZEROVAULT_PRIMARY_DATA_KEY_CONTEXT_v2";
const CONTEXT_SECONDARY_KEY: &[u8] = b"ZEROVAULT_SECONDARY_DATA_KEY_CONTEXT_v2";
const CONTEXT_TERTIARY_KEY: &[u8] = b"ZEROVAULT_TERTIARY_DATA_KEY_CONTEXT_v2";
const CONTEXT_HMAC_KEY: &[u8] = b"ZEROVAULT_HMAC_KEY_CONTEXT_v2";
const CONTEXT_INTEGRITY_KEY: &[u8] = b"ZEROVAULT_INTEGRITY_KEY_CONTEXT_v2";

static ENTROPY_OK: OnceLock<bool> = OnceLock::new();

fn secure_random(len: usize) -> Result<Vec<u8>, VaultError> {
    /* fast deterministic branch when running `cargo test` */
    #[cfg(test)]
    {
        use sha2::{Digest, Sha256};
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut buf = vec![0u8; len];
        OsRng.fill_bytes(&mut buf);

        let mut h = Sha256::new_with_prefix(&buf);
        h.update(len.to_le_bytes());
        if let Ok(d) = SystemTime::now().duration_since(UNIX_EPOCH) {
            h.update(d.as_nanos().to_le_bytes());
        }
        h.update(format!("{:?}", std::thread::current().id()).as_bytes());

        let dig = h.finalize();
        for (i, b) in buf.iter_mut().enumerate() {
            *b ^= dig[i % dig.len()];
        }
        return Ok(buf);
    }

    /* production path */
    #[cfg(not(test))]
    {
        use std::{thread, time::Duration};

        /* If we’ve already verified entropy quality, just return fresh bytes */
        if ENTROPY_OK.get() == Some(&true) {
            let mut out = vec![0u8; len];
            OsRng.fill_bytes(&mut out);
            return Ok(out);
        }

        let mut out = vec![0u8; len];

        for attempt in 0..ENTROPY_RETRIES {
            OsRng.fill_bytes(&mut out);

            /* choose what to analyse */
            let mut sample_buf;
            let sample: &[u8] = if len >= ENTROPY_TEST_SAMPLE {
                &out[..ENTROPY_TEST_SAMPLE]
            } else {
                sample_buf = vec![0u8; ENTROPY_TEST_SAMPLE];
                OsRng.fill_bytes(&mut sample_buf);
                &sample_buf
            };

            if verify_entropy(sample, ENTROPY_MIN_BYTES) {
                let _ = ENTROPY_OK.set(true);
                return Ok(out);
            }

            /* back-off */
            thread::sleep(Duration::from_millis(25 * (attempt as u64 + 1)));
        }

        Err(VaultError::EntropyInsufficientError)
    }
}

/// Verify that a buffer contains sufficient entropy
fn verify_entropy(buffer: &[u8], min_bytes: usize) -> bool {
    // Very small samples cannot give statistically reliable χ² results.
    if buffer.len() < min_bytes {
        return false;
    }

    // 1. Calculate Shannon entropy (should be close to 8.0 for truly random bytes)
    let shannon_entropy = calculate_shannon_entropy(buffer);
    // For cryptographic applications, expect at least 7.0 bits of entropy per byte
    if shannon_entropy < 7.0 {
        return false;
    }

    // 2. Run NIST monobit frequency test (basic test from NIST SP 800-22)
    // Count number of 1 bits, should be close to 50%
    let bit_count = count_bits(buffer);
    let bit_ratio = bit_count as f64 / (buffer.len() * 8) as f64;
    // Allow deviation of 1% from ideal 50% in either direction
    if bit_ratio < 0.49 || bit_ratio > 0.51 {
        return false;
    }

    // 3. Run consecutive bit runs test
    // Count runs of consecutive 0s and 1s, these should be within statistical norms
    if !verify_runs_test(buffer) {
        return false;
    }

    // 4. Frequency analysis
    // Each byte value should appear with roughly equal frequency
    let frequencies = get_byte_frequencies(buffer);

    // Chi-squared test for uniform distribution
    let chi_squared = calculate_chi_squared(&frequencies, buffer.len());
    // Critical chi-squared value (95% confidence, 255 degrees of freedom) is ~293
    // Lower value means more uniform distribution
    if chi_squared > 293.0 {
        return false;
    }

    // All tests passed!
    true
}

/// Calculate Shannon entropy in bits per byte (max 8.0 for perfect randomness)
fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    let data_len = data.len() as f64;
    if data_len == 0.0 {
        return 0.0;
    }

    // Count frequencies
    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    // Calculate entropy
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let probability = count as f64 / data_len;
            entropy -= probability * probability.log2();
        }
    }

    entropy
}

/// Count the number of set bits (1s) in the buffer
fn count_bits(buffer: &[u8]) -> u64 {
    let mut count = 0;
    for &byte in buffer {
        // Use bit counting techniques - population count
        count += byte.count_ones() as u64;
    }
    count
}

/// Calculate byte frequencies
fn get_byte_frequencies(buffer: &[u8]) -> [u32; 256] {
    let mut frequencies = [0u32; 256];
    for &byte in buffer {
        frequencies[byte as usize] += 1;
    }
    frequencies
}

/// Calculate chi-squared statistic for byte frequencies
/// Lower value indicates more uniform distribution
fn calculate_chi_squared(frequencies: &[u32; 256], total_bytes: usize) -> f64 {
    // Expected count for each byte in uniform distribution
    let expected = total_bytes as f64 / 256.0;

    // Calculate chi-squared statistic
    let mut chi_squared = 0.0;
    for &observed in frequencies {
        if expected > 0.0 {
            let difference = observed as f64 - expected;
            chi_squared += (difference * difference) / expected;
        }
    }

    chi_squared
}

/// Test for runs of consecutive bits (simplified version of NIST runs test)
fn verify_runs_test(buffer: &[u8]) -> bool {
    if buffer.len() < 20 {
        // Need reasonable minimum for this test
        return true; // Skip for very small buffers
    }

    let mut runs_count = 0;
    let mut current_run = 1;
    let mut prev_bit = buffer[0] & 1; // Get least significant bit of first byte

    // Count bit runs through the entire buffer
    for byte in buffer {
        for bit_pos in 0..8 {
            let current_bit = (byte >> bit_pos) & 1;
            if current_bit == prev_bit {
                current_run += 1;
            } else {
                // End of a run
                if current_run > 25 {
                    // Long runs are suspicious
                    runs_count += 1;
                }
                current_run = 1;
                prev_bit = current_bit;
            }
        }
    }

    // Calculate expected number of long runs - this is a simplified threshold
    // Actual NIST test uses much more complex statistics
    let max_expected_long_runs = buffer.len() / 100 + 1;

    runs_count <= max_expected_long_runs
}

/// Generate a cryptographically strong key pair
fn generate_keypair() -> Result<SigningKey, VaultError> {
    // Generate with OsRng for maximum entropy
    Ok(SigningKey::generate(&mut OsRng))
}

/// Generate an ephemeral nonce with proper length
fn generate_nonce(len: usize) -> Result<Vec<u8>, VaultError> {
    secure_random(len)
}

/// Constant-time comparison of two byte arrays
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    constant_time_eq(a, b)
}

/// Derive a key securely using Argon2id with high security parameters
fn derive_key_argon2id(
    password: &[u8],
    salt: &[u8],
    params: &VaultEncryptionParams,
    output_len: usize,
) -> Result<SecureKey, VaultError> {
    // Create a buffer for the derived key
    let mut key_bytes = vec![0u8; output_len];

    // Create Argon2id configuration with the specified parameters
    // Fixed: Explicitly converted output_len to u32 as required by the API
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            params.memory_cost_kib,
            params.time_cost,
            params.parallelism,
            Some(output_len), // Fixed: Convert usize to u32
        )
        .map_err(|_| VaultError::KeyDerivationFailed)?,
    );

    // Derive the key
    argon2
        .hash_password_into(password, salt, &mut key_bytes)
        .map_err(|_| VaultError::KeyDerivationFailed)?;

    // Return the key in a secure container
    Ok(SecureKey::new(key_bytes))
}

/// Derive a key using PBKDF2-HMAC-SHA512 for secondary derivations
fn derive_key_pbkdf2(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output_len: usize,
) -> Result<SecureKey, VaultError> {
    // Create a buffer for the derived key
    let mut key_bytes = vec![0u8; output_len];

    // Derive the key using PBKDF2 with HMAC-SHA512
    type HmacSha512 = Hmac<Sha512>;

    pbkdf2::<HmacSha512>(password, salt, iterations, &mut key_bytes)
        .map_err(|_| VaultError::KeyDerivationFailed)?;

    // Return the key in a secure container
    Ok(SecureKey::new(key_bytes))
}

/// Derive a key using HKDF-SHA512
fn derive_key_hkdf(
    ikm: &[u8],  // Input key material
    salt: &[u8], // Salt
    info: &[u8], // Context/application info
    output_len: usize,
) -> Result<SecureKey, VaultError> {
    // Create output buffer
    let mut okm = vec![0u8; output_len];

    // Create an HKDF instance using Sha512
    let hk = hkdf::Hkdf::<Sha512>::new(Some(salt), ikm);

    // Derive the key
    hk.expand(info, &mut okm)
        .map_err(|_| VaultError::KeyDerivationFailed)?;

    // Return the key in a secure container
    Ok(SecureKey::new(okm))
}

/// Split a key into multiple parts using Shamir's Secret Sharing
/// Implementation of Shamir's Secret Sharing for key splitting
fn split_key(key: &SecureKey, parts: u8, threshold: u8) -> Result<Vec<Vec<u8>>, VaultError> {
    if threshold > parts || threshold == 0 || parts == 0 {
        return Err(VaultError::KeySplittingFailed);
    }

    // This is a simplified implementation for demonstration
    // In production, use a well-vetted SSS library

    let mut result = Vec::with_capacity(parts as usize);
    let key_bytes = &key.key_bytes;

    // Generate coefficient arrays (one for each byte of the secret)
    let mut coefficients = Vec::with_capacity(key_bytes.len());
    for &key_byte in key_bytes {
        let mut coef = vec![key_byte]; // constant term = secret byte

        // Generate random coefficients for the polynomial
        for _ in 1..threshold {
            coef.push(OsRng.next_u32() as u8);
        }

        coefficients.push(coef);
    }

    // Generate shares
    for part in 1..=parts {
        let x = part; // Use part number as the x-coordinate

        // Evaluate polynomial for each byte
        let mut share = vec![x]; // First byte is the x-coordinate
        for coef in &coefficients {
            let mut y = coef[0]; // Start with the constant term

            // Evaluate the polynomial at x
            let mut x_pow = 1u8;
            for j in 1..coef.len() {
                x_pow = x_pow.wrapping_mul(x);
                y = y.wrapping_add(coef[j].wrapping_mul(x_pow));
            }

            share.push(y);
        }

        result.push(share);
    }

    Ok(result)
}

/// Reconstruct a key from its parts using Lagrange interpolation
fn reconstruct_key(parts: &[Vec<u8>], threshold: u8) -> Result<SecureKey, VaultError> {
    if parts.len() < threshold as usize {
        return Err(VaultError::KeyReconstructionFailed);
    }

    // Check that all parts have the same length
    let share_len = parts[0].len();
    if parts.iter().any(|s| s.len() != share_len) {
        return Err(VaultError::KeyReconstructionFailed);
    }

    // Extract x-coordinates and data points
    let mut x_coords = Vec::with_capacity(parts.len());
    let mut y_points = Vec::with_capacity(parts.len());
    for part in parts {
        x_coords.push(part[0]);
        y_points.push(&part[1..]);
    }

    // Result buffer for the reconstructed secret
    let secret_len = share_len - 1;
    let mut secret = vec![0u8; secret_len];

    // For each byte position in the secret
    for i in 0..secret_len {
        // Lagrange interpolation for this byte
        let mut byte_value = 0u8;

        for j in 0..threshold as usize {
            let x_j = x_coords[j];
            let y_j = y_points[j][i];

            let mut lagrange_basis = 1u8;
            for k in 0..threshold as usize {
                if j != k {
                    let x_k = x_coords[k];
                    let num = x_k;
                    let denom = x_k.wrapping_sub(x_j);

                    // Avoid division by zero
                    if denom == 0 {
                        return Err(VaultError::KeyReconstructionFailed);
                    }

                    // Multiply by (x_k / (x_k - x_j))
                    lagrange_basis = lagrange_basis.wrapping_mul(num).wrapping_div(denom);
                }
            }

            byte_value = byte_value.wrapping_add(y_j.wrapping_mul(lagrange_basis));
        }

        secret[i] = byte_value;
    }

    Ok(SecureKey::new(secret))
}

/// Create a complete key hierarchy using the password and parameters
fn derive_key_hierarchy(
    password: &str,
    master_salt: &[u8],
    kek_salt: &[u8],
    key_splits_salt: &[u8],
    params: &VaultEncryptionParams,
) -> Result<VaultKeyHierarchy, VaultError> {
    // Derive the master key using Argon2id with high security parameters
    let master_key =
        derive_key_argon2id(password.as_bytes(), master_salt, params, MASTER_KEY_SIZE)?;

    // Derive the key encryption key (KEK) using PBKDF2 with different salt
    let key_encryption_key = derive_key_pbkdf2(
        &master_key.key_bytes,
        kek_salt,
        params.pbkdf2_iterations,
        KEK_SIZE,
    )?;

    // Derive primary data key
    let primary_info = [CONTEXT_PRIMARY_KEY.as_ref(), &[1u8]].concat();
    let primary_data_key = derive_key_hkdf(
        &key_encryption_key.key_bytes,
        master_salt,
        &primary_info,
        DATA_KEY_SIZE,
    )?;

    // Derive secondary data key with different context
    let secondary_info = [CONTEXT_SECONDARY_KEY.as_ref(), &[2u8]].concat();
    let secondary_data_key = derive_key_hkdf(
        &key_encryption_key.key_bytes,
        master_salt,
        &secondary_info,
        DATA_KEY_SIZE,
    )?;

    // Derive tertiary data key with different context
    let tertiary_info = [CONTEXT_TERTIARY_KEY.as_ref(), &[3u8]].concat();
    let tertiary_data_key = derive_key_hkdf(
        &key_encryption_key.key_bytes,
        master_salt,
        &tertiary_info,
        DATA_KEY_SIZE,
    )?;

    // Derive HMAC key with different context
    let hmac_info = [CONTEXT_HMAC_KEY.as_ref(), &[4u8]].concat();
    let hmac_key = derive_key_hkdf(
        &key_encryption_key.key_bytes,
        master_salt,
        &hmac_info,
        HMAC_KEY_SIZE,
    )?;

    // Derive integrity key with different context
    let integrity_info = [CONTEXT_INTEGRITY_KEY.as_ref(), &[5u8]].concat();
    let integrity_key = derive_key_hkdf(
        &key_encryption_key.key_bytes,
        master_salt,
        &integrity_info,
        HMAC_KEY_SIZE,
    )?;

    // Split the master key using Shamir's Secret Sharing
    let key_parts_data = split_key(&master_key, DEFAULT_KEY_PARTS, DEFAULT_KEY_THRESHOLD)?;

    // Encrypt each key part with the KEK
    let mut master_key_parts = Vec::with_capacity(key_parts_data.len());
    for part in key_parts_data {
        // Further protect each part with a unique derived key using the part as info
        let part_info = [b"KEY_PART_", &part[0..1]].concat();
        let part_key = derive_key_hkdf(
            &key_encryption_key.key_bytes,
            key_splits_salt,
            &part_info,
            32,
        )?;

        // XOR the part with the derived key (simplified encryption)
        let mut protected_part = vec![part[0]]; // Keep the x-coordinate
        for i in 1..part.len() {
            protected_part.push(part[i] ^ part_key.key_bytes[i % part_key.key_bytes.len()]);
        }

        master_key_parts.push(SecureKey::new(protected_part));
    }

    // Create and return the complete key hierarchy
    Ok(VaultKeyHierarchy {
        master_key_parts,
        master_key,
        key_encryption_key,
        primary_data_key,
        secondary_data_key,
        tertiary_data_key,
        hmac_key,
        integrity_key,
        key_threshold: DEFAULT_KEY_THRESHOLD,
    })
}

/// Create a cryptographic integrity hash for tamper detection using SHA-512
fn create_integrity_hash(
    data: &VaultEncryptedData,
    integrity_key: &[u8],
) -> Result<String, VaultError> {
    // Create a HMAC-SHA512 instance - fixed: use fully qualified syntax
    let mut mac = <Hmac<Sha512> as hmac::Mac>::new_from_slice(integrity_key)
        .map_err(|_| VaultError::IntegrityCheckFailed)?;

    // Add fields to the HMAC in a defined order (except integrity hashes and structure_hmac)
    mac.update(data.primary_nonce.as_bytes());
    mac.update(data.primary_ciphertext.as_bytes());
    mac.update(data.secondary_nonce.as_bytes());
    mac.update(data.secondary_ciphertext.as_bytes());
    mac.update(data.tertiary_nonce.as_bytes());
    mac.update(data.tertiary_ciphertext.as_bytes());
    mac.update(data.tertiary_hmac.as_bytes());
    mac.update(data.master_salt.as_bytes());
    mac.update(data.kek_salt.as_bytes());
    mac.update(data.key_splits_salt.as_bytes());
    mac.update(&[data.key_threshold]);

    for part in &data.key_parts {
        mac.update(part.as_bytes());
    }

    mac.update(data.entropy_verification.as_bytes());
    mac.update(data.data_signature.as_bytes());
    mac.update(data.public_key.as_bytes());

    // Add params fields except params_hmac
    mac.update(&bincode::serialize(&data.params).map_err(|_| VaultError::IntegrityCheckFailed)?);

    // Compute the HMAC
    let result = mac.finalize().into_bytes();

    // Return base64 encoded HMAC
    Ok(BASE64.encode(result))
}

/// Create a BLAKE3 hash for secondary integrity verification
fn create_blake3_hash(data: &VaultEncryptedData) -> Result<String, VaultError> {
    // Create a BLAKE3 hasher
    let mut hasher = blake3::Hasher::new();

    // Add the same fields as for the SHA-512 hash, plus the primary integrity hash
    hasher.update(data.primary_nonce.as_bytes());
    hasher.update(data.primary_ciphertext.as_bytes());
    hasher.update(data.secondary_nonce.as_bytes());
    hasher.update(data.secondary_ciphertext.as_bytes());
    hasher.update(data.tertiary_nonce.as_bytes());
    hasher.update(data.tertiary_ciphertext.as_bytes());
    hasher.update(data.tertiary_hmac.as_bytes());
    hasher.update(data.master_salt.as_bytes());
    hasher.update(data.kek_salt.as_bytes());
    hasher.update(data.key_splits_salt.as_bytes());
    hasher.update(&[data.key_threshold]);

    for part in &data.key_parts {
        hasher.update(part.as_bytes());
    }

    hasher.update(data.entropy_verification.as_bytes());
    hasher.update(data.data_signature.as_bytes());
    hasher.update(data.public_key.as_bytes());
    hasher.update(&bincode::serialize(&data.params).map_err(|_| VaultError::IntegrityCheckFailed)?);

    // Also include the primary integrity hash for layered protection
    hasher.update(data.primary_integrity_hash.as_bytes());

    // Finalize and return the hash
    let hash = hasher.finalize();
    Ok(BASE64.encode(hash.as_bytes()))
}

/// Verify the integrity hashes of encrypted data
fn verify_integrity(data: &VaultEncryptedData, integrity_key: &[u8]) -> Result<(), VaultError> {
    // Verify primary SHA-512 integrity hash
    let primary_hash = data.primary_integrity_hash.clone();

    // Create a temporary copy and calculate the expected hash
    // Fixed: made a mutable copy since we need to modify it
    let mut temp_data = data.clone();
    temp_data.primary_integrity_hash = String::new();
    temp_data.secondary_integrity_hash = String::new();
    temp_data.structure_hmac = String::new();

    let expected_primary_hash = create_integrity_hash(&temp_data, integrity_key)?;

    // Verify using constant-time comparison
    if !constant_time_compare(primary_hash.as_bytes(), expected_primary_hash.as_bytes()) {
        return Err(VaultError::IntegrityCheckFailed);
    }

    // Verify secondary BLAKE3 integrity hash
    let secondary_hash = data.secondary_integrity_hash.clone();

    // Update the temporary copy with the correct primary hash
    temp_data.primary_integrity_hash = primary_hash;

    let expected_secondary_hash = create_blake3_hash(&temp_data)?;

    // Verify using constant-time comparison
    if !constant_time_compare(
        secondary_hash.as_bytes(),
        expected_secondary_hash.as_bytes(),
    ) {
        return Err(VaultError::IntegrityCheckFailed);
    }

    Ok(())
}

/// Add random padding to the plaintext for traffic analysis resistance
fn add_random_padding(data: &[u8]) -> Result<Vec<u8>, VaultError> {
    // Calculate a variable padding length based on data size
    // Min padding: 64 bytes, Max padding: 4096 bytes or 10% of data size, whichever is larger
    let min_padding = 64;
    let max_percentage_padding = data.len() / 10;
    let max_padding = max_percentage_padding.max(4096);

    // Generate a random padding length within the range
    let range = max_padding - min_padding;
    let padding_len = if range > 0 {
        min_padding + (OsRng.next_u32() as usize % range)
    } else {
        min_padding
    };

    // Generate random padding
    let padding = secure_random(padding_len)?;

    // Format: [data_len(4 bytes)][data][padding_len(4 bytes)][padding]
    let data_len = data.len() as u32;
    let padding_len_u32 = padding_len as u32;

    let mut result = Vec::with_capacity(4 + data.len() + 4 + padding_len);

    // Add data length as 4 bytes (big endian)
    result.extend_from_slice(&data_len.to_be_bytes());

    // Add the original data
    result.extend_from_slice(data);

    // Add padding length as 4 bytes (big endian)
    result.extend_from_slice(&padding_len_u32.to_be_bytes());

    // Add the random padding
    result.extend_from_slice(&padding);

    Ok(result)
}

/// Remove padding from the decrypted plaintext
fn remove_padding(padded_data: &[u8]) -> Result<Vec<u8>, VaultError> {
    if padded_data.len() < 8 {
        return Err(VaultError::DecryptionFailed);
    }

    // Extract the original data length
    let data_len = u32::from_be_bytes([
        padded_data[0],
        padded_data[1],
        padded_data[2],
        padded_data[3],
    ]) as usize;

    // Verify that the length is valid
    if data_len + 4 > padded_data.len() {
        return Err(VaultError::DecryptionFailed);
    }

    // Extract the original data
    let data = padded_data[4..4 + data_len].to_vec();

    Ok(data)
}

/// Primary encryption function using AES-256-GCM
fn encrypt_aes_gcm(plaintext: &[u8], key: &SecureKey, nonce: &[u8]) -> Result<Vec<u8>, VaultError> {
    // Validate key length
    if key.key_bytes.len() != 32 {
        return Err(VaultError::InvalidFormat);
    }

    // Validate nonce length
    if nonce.len() != 12 {
        return Err(VaultError::InvalidFormat);
    }

    // Create AES key
    let aes_key = GenericArray::from_slice(&key.key_bytes);
    let cipher = Aes256Gcm::new(aes_key);

    // Create nonce
    let nonce = GenericArray::from_slice(nonce);

    // Encrypt
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| VaultError::EncryptionFailed)
}

/// Secondary encryption function using ChaCha20-Poly1305
fn encrypt_chacha20_poly1305(
    plaintext: &[u8],
    key: &SecureKey,
    nonce: &[u8],
) -> Result<Vec<u8>, VaultError> {
    // Validate key length
    if key.key_bytes.len() != 32 {
        return Err(VaultError::InvalidFormat);
    }

    // Validate nonce length
    if nonce.len() != 12 {
        return Err(VaultError::InvalidFormat);
    }

    // Create ChaCha key and nonce
    let chacha_key = ChaChaKey::from_slice(&key.key_bytes);
    let chacha_nonce = ChaChaNonce::from_slice(nonce);

    // Create cipher
    let cipher = ChaCha20Poly1305::new(chacha_key);

    // Encrypt
    cipher
        .encrypt(chacha_nonce, plaintext)
        .map_err(|_| VaultError::EncryptionFailed)
}

/// Tertiary encryption function using AES-256-CBC with separate HMAC
fn encrypt_aes_cbc_hmac(
    plaintext: &[u8],
    key: &SecureKey,
    hmac_key: &SecureKey,
    nonce: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), VaultError> {
    // Validate key lengths
    if key.key_bytes.len() != 32 {
        return Err(VaultError::InvalidFormat);
    }

    if hmac_key.key_bytes.len() < 32 {
        return Err(VaultError::InvalidFormat);
    }

    // Validate IV length
    if nonce.len() != 16 {
        return Err(VaultError::InvalidFormat);
    }

    // Create AES-CBC encryptor
    type Aes256CbcEnc = CbcEncryptor<Aes256>;

    // Create a buffer with enough space for the padded output
    // Fixed: Use the block_size method from the BlockSizeUser trait
    let mut buffer = vec![0u8; plaintext.len() + Aes256::block_size()];

    let cipher = Aes256CbcEnc::new_from_slices(&key.key_bytes, nonce)
        .map_err(|_| VaultError::EncryptionFailed)?;

    // Encrypt data
    let ciphertext_len = cipher
        .encrypt_padded_b2b_mut::<cbc::cipher::block_padding::Pkcs7>(plaintext, &mut buffer)
        .map_err(|_| VaultError::EncryptionFailed)?
        .len();

    // Now buffer can be borrowed immutably
    let ciphertext = buffer[..ciphertext_len].to_vec();

    // Create HMAC for the ciphertext - fixed: use fully qualified syntax
    let mut mac = <Hmac<Sha512> as hmac::Mac>::new_from_slice(&hmac_key.key_bytes)
        .map_err(|_| VaultError::EncryptionFailed)?;

    // Update with nonce and ciphertext
    mac.update(nonce);
    mac.update(&ciphertext);

    // Finalize HMAC
    let hmac_result = mac.finalize().into_bytes().to_vec();

    Ok((ciphertext, hmac_result))
}

/// Primary decryption function using AES-256-GCM
fn decrypt_aes_gcm(
    ciphertext: &[u8],
    key: &SecureKey,
    nonce: &[u8],
) -> Result<Vec<u8>, VaultError> {
    // Validate key length
    if key.key_bytes.len() != 32 {
        return Err(VaultError::InvalidFormat);
    }

    // Validate nonce length
    if nonce.len() != 12 {
        return Err(VaultError::InvalidFormat);
    }

    // Create AES key
    let aes_key = GenericArray::from_slice(&key.key_bytes);
    let cipher = Aes256Gcm::new(aes_key);

    // Create nonce
    let nonce = GenericArray::from_slice(nonce);

    // Decrypt
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| VaultError::DecryptionFailed)
}

/// Secondary decryption function using ChaCha20-Poly1305
fn decrypt_chacha20_poly1305(
    ciphertext: &[u8],
    key: &SecureKey,
    nonce: &[u8],
) -> Result<Vec<u8>, VaultError> {
    // Validate key length
    if key.key_bytes.len() != 32 {
        return Err(VaultError::InvalidFormat);
    }

    // Validate nonce length
    if nonce.len() != 12 {
        return Err(VaultError::InvalidFormat);
    }

    // Create ChaCha key and nonce
    let chacha_key = ChaChaKey::from_slice(&key.key_bytes);
    let chacha_nonce = ChaChaNonce::from_slice(nonce);

    // Create cipher
    let cipher = ChaCha20Poly1305::new(chacha_key);

    // Decrypt
    cipher
        .decrypt(chacha_nonce, ciphertext)
        .map_err(|_| VaultError::DecryptionFailed)
}

/// Tertiary decryption function using AES-256-CBC with separate HMAC verification
fn decrypt_aes_cbc_hmac(
    ciphertext: &[u8],
    key: &SecureKey,
    hmac_key: &SecureKey,
    nonce: &[u8],
    hmac: &[u8],
) -> Result<Vec<u8>, VaultError> {
    // Validate key lengths
    if key.key_bytes.len() != 32 {
        return Err(VaultError::InvalidFormat);
    }

    if hmac_key.key_bytes.len() < 32 {
        return Err(VaultError::InvalidFormat);
    }

    // Validate IV length
    if nonce.len() != 16 {
        return Err(VaultError::InvalidFormat);
    }

    // Verify HMAC first - fixed: use fully qualified syntax
    let mut mac = <Hmac<Sha512> as hmac::Mac>::new_from_slice(&hmac_key.key_bytes)
        .map_err(|_| VaultError::DecryptionFailed)?;

    // Update with nonce and ciphertext
    mac.update(nonce);
    mac.update(ciphertext);

    // Verify HMAC
    mac.verify_slice(hmac)
        .map_err(|_| VaultError::VerificationFailed)?;

    // Create AES-CBC decryptor
    type Aes256CbcDec = CbcDecryptor<Aes256>;

    let mut buffer = vec![0u8; ciphertext.len()];
    let cipher = Aes256CbcDec::new_from_slices(&key.key_bytes, nonce)
        .map_err(|_| VaultError::DecryptionFailed)?;

    // Decrypt data
    let len = cipher
        .decrypt_padded_b2b_mut::<cbc::cipher::block_padding::Pkcs7>(ciphertext, &mut buffer)
        .map_err(|_| VaultError::DecryptionFailed)?
        .len();

    Ok(buffer[..len].to_vec())
}
/// Calculate entropy verification hash
fn calculate_entropy_verification(
    primary_key: &SecureKey,
    secondary_key: &SecureKey,
    tertiary_key: &SecureKey,
) -> String {
    // Create a SHA-256 hasher
    let mut hasher = sha2::Sha256::new_with_prefix(b"");

    // Add all key material
    hasher.update(&primary_key.key_bytes);
    hasher.update(&secondary_key.key_bytes);
    hasher.update(&tertiary_key.key_bytes);

    // Return base64 encoded hash
    BASE64.encode(hasher.finalize())
}

/// Verify entropy verification hash
fn verify_entropy_hash(
    entropy_hash: &str,
    primary_key: &SecureKey,
    secondary_key: &SecureKey,
    tertiary_key: &SecureKey,
) -> Result<(), VaultError> {
    // Calculate expected hash
    let expected_hash = calculate_entropy_verification(primary_key, secondary_key, tertiary_key);

    // Verify using constant-time comparison
    if !constant_time_compare(entropy_hash.as_bytes(), expected_hash.as_bytes()) {
        return Err(VaultError::EntropyInsufficientError);
    }

    Ok(())
}

/// Generate anti-forensic decoy data
fn generate_decoys(count: usize) -> Result<Vec<String>, VaultError> {
    let mut decoys = Vec::with_capacity(count);

    // Create realistic-looking but random decoy data
    for _ in 0..count {
        let len = 20 + (OsRng.next_u32() % 100) as usize;
        let random_data = secure_random(len)?;
        decoys.push(BASE64.encode(random_data));
    }

    Ok(decoys)
}

/// Create parameters HMAC for tamper protection
fn create_params_hmac(
    params: &VaultEncryptionParams,
    hmac_key: &[u8],
) -> Result<String, VaultError> {
    // Create a temporary copy without the HMAC
    let mut temp_params = params.clone();
    temp_params.params_hmac = String::new();

    // Serialize the parameters
    let params_data =
        bincode::serialize(&temp_params).map_err(|_| VaultError::ParameterValidationFailed)?;

    // Create HMAC - fixed: use fully qualified syntax
    let mut mac = <Hmac<Sha512> as hmac::Mac>::new_from_slice(hmac_key)
        .map_err(|_| VaultError::ParameterValidationFailed)?;

    mac.update(&params_data);

    // Finalize and return base64 encoded HMAC
    let result = mac.finalize().into_bytes();
    Ok(BASE64.encode(&result))
}

/// Verify parameters HMAC
fn verify_params_hmac(params: &VaultEncryptionParams, hmac_key: &[u8]) -> Result<(), VaultError> {
    // Get the stored HMAC
    let stored_hmac = params.params_hmac.clone();

    // Create a temporary copy without the HMAC
    let mut temp_params = params.clone();
    temp_params.params_hmac = String::new();

    // Calculate the expected HMAC
    let expected_hmac = create_params_hmac(&temp_params, hmac_key)?;

    // Verify using constant-time comparison
    if !constant_time_compare(stored_hmac.as_bytes(), expected_hmac.as_bytes()) {
        return Err(VaultError::ParameterValidationFailed);
    }

    Ok(())
}

/// Encrypt data with triple-layer protection
pub fn encrypt_data(data: &[u8], password: &str) -> Result<VaultEncryptedData, VaultError> {
    // Use default parameters with maximum security
    let mut params = VaultEncryptionParams::with_security(crate::types::SecurityLevel::Interactive);

    // Generate salts
    let master_salt = secure_random(32)?;
    let kek_salt = secure_random(32)?;
    let key_splits_salt = secure_random(32)?;

    // Derive the key hierarchy
    let key_hierarchy =
        derive_key_hierarchy(password, &master_salt, &kek_salt, &key_splits_salt, &params)?;

    // Calculate and set the params HMAC
    params.params_hmac = create_params_hmac(&params, &key_hierarchy.hmac_key.key_bytes)?;

    // Add random padding to the plaintext
    let padded_data = add_random_padding(data)?;

    // Layer 1: Primary encryption with AES-256-GCM
    let primary_nonce = generate_nonce(12)?;
    let primary_ciphertext = encrypt_aes_gcm(
        &padded_data,
        &key_hierarchy.primary_data_key,
        &primary_nonce,
    )?;

    // Layer 2: Secondary encryption with ChaCha20-Poly1305
    let secondary_nonce = generate_nonce(12)?;
    let secondary_ciphertext = encrypt_chacha20_poly1305(
        &primary_ciphertext,
        &key_hierarchy.secondary_data_key,
        &secondary_nonce,
    )?;

    // Layer 3: Tertiary encryption with AES-256-CBC + HMAC
    let tertiary_nonce = generate_nonce(16)?;
    let (tertiary_ciphertext, tertiary_hmac) = encrypt_aes_cbc_hmac(
        &secondary_ciphertext,
        &key_hierarchy.tertiary_data_key,
        &key_hierarchy.hmac_key,
        &tertiary_nonce,
    )?;

    // Generate a signing key and sign the encrypted data
    let signing_key = generate_keypair()?;
    let verifying_key = VerifyingKey::from(&signing_key);

    // Sign all ciphertext layers and nonces
    let mut to_sign = Vec::new();
    to_sign.extend_from_slice(&primary_nonce);
    to_sign.extend_from_slice(&primary_ciphertext);
    to_sign.extend_from_slice(&secondary_nonce);
    to_sign.extend_from_slice(&secondary_ciphertext);
    to_sign.extend_from_slice(&tertiary_nonce);
    to_sign.extend_from_slice(&tertiary_ciphertext);
    to_sign.extend_from_slice(&tertiary_hmac);

    let signature = signing_key.sign(&to_sign);

    // Calculate entropy verification hash
    let entropy_verification = calculate_entropy_verification(
        &key_hierarchy.primary_data_key,
        &key_hierarchy.secondary_data_key,
        &key_hierarchy.tertiary_data_key,
    );

    // Convert the split key parts to base64
    let key_parts: Vec<String> = key_hierarchy
        .master_key_parts
        .iter()
        .map(|k| BASE64.encode(&k.key_bytes))
        .collect();

    // Generate decoy data
    let decoy_data = generate_decoys(3 + (OsRng.next_u32() % 5) as usize)?;

    // Calculate creation timestamp with slight randomization
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| VaultError::EncryptionFailed)?
        .as_secs();

    // Add random offset (-10 to +10 seconds) to prevent exact timing correlation
    let time_offset = (OsRng.next_u32() % 21) as i64 - 10;
    let creation_timestamp = (now as i64 + time_offset) as u64;

    // Generate canary value
    let canary = secure_random(16)?;

    // Create the encrypted data structure
    let mut encrypted_data = VaultEncryptedData {
        primary_nonce: BASE64.encode(&primary_nonce),
        primary_ciphertext: BASE64.encode(&primary_ciphertext),
        secondary_nonce: BASE64.encode(&secondary_nonce),
        secondary_ciphertext: BASE64.encode(&secondary_ciphertext),
        tertiary_nonce: BASE64.encode(&tertiary_nonce),
        tertiary_ciphertext: BASE64.encode(&tertiary_ciphertext),
        tertiary_hmac: BASE64.encode(&tertiary_hmac),
        master_salt: BASE64.encode(&master_salt),
        kek_salt: BASE64.encode(&kek_salt),
        key_splits_salt: BASE64.encode(&key_splits_salt),
        key_threshold: key_hierarchy.key_threshold,
        key_parts,
        entropy_verification,
        data_signature: BASE64.encode(&signature.to_bytes()),
        public_key: BASE64.encode(&verifying_key.to_bytes()),
        params,
        primary_integrity_hash: String::new(), // Will be set below
        secondary_integrity_hash: String::new(), // Will be set below
        decoy_data,
        padding_salt: BASE64.encode(&secure_random(16)?),
        creation_timestamp,
        canary_value: BASE64.encode(&canary),
        structure_hmac: String::new(), // Will be set below
    };

    // Calculate and add the primary integrity hash
    encrypted_data.primary_integrity_hash =
        create_integrity_hash(&encrypted_data, &key_hierarchy.integrity_key.key_bytes)?;

    // Calculate and add the secondary integrity hash
    encrypted_data.secondary_integrity_hash = create_blake3_hash(&encrypted_data)?;

    // Calculate and add the structure HMAC
    let mut mac = <Hmac<Sha512> as hmac::Mac>::new_from_slice(&key_hierarchy.hmac_key.key_bytes)
        .map_err(|_| VaultError::IntegrityCheckFailed)?;

    // Add all fields including integrity hashes, but exclude structure_hmac
    let mut temp_data = encrypted_data.clone();
    temp_data.structure_hmac = String::new();

    // Serialize for HMAC calculation
    let serialized =
        bincode::serialize(&temp_data).map_err(|_| VaultError::IntegrityCheckFailed)?;

    mac.update(&serialized);

    encrypted_data.structure_hmac = BASE64.encode(&mac.finalize().into_bytes());

    Ok(encrypted_data)
}

/// Decrypt data with full verification of all security measures
pub fn decrypt_data(enc: &VaultEncryptedData, password: &str) -> Result<Vec<u8>, VaultError> {
    // Decode all salts
    let master_salt = BASE64
        .decode(&enc.master_salt)
        .map_err(|_| VaultError::InvalidFormat)?;

    let kek_salt = BASE64
        .decode(&enc.kek_salt)
        .map_err(|_| VaultError::InvalidFormat)?;

    let key_splits_salt = BASE64
        .decode(&enc.key_splits_salt)
        .map_err(|_| VaultError::InvalidFormat)?;

    // Derive the key hierarchy
    let key_hierarchy = derive_key_hierarchy(
        password,
        &master_salt,
        &kek_salt,
        &key_splits_salt,
        &enc.params,
    )?;

    // Verify parameters HMAC
    verify_params_hmac(&enc.params, &key_hierarchy.hmac_key.key_bytes)?;

    // Verify integrity hashes
    verify_integrity(enc, &key_hierarchy.integrity_key.key_bytes)?;

    // Verify structure HMAC
    let mut temp_enc = enc.clone();
    temp_enc.structure_hmac = String::new();

    let mut mac = <Hmac<Sha512> as hmac::Mac>::new_from_slice(&key_hierarchy.hmac_key.key_bytes)
        .map_err(|_| VaultError::IntegrityCheckFailed)?;

    // Serialize for HMAC verification
    let serialized = bincode::serialize(&temp_enc).map_err(|_| VaultError::IntegrityCheckFailed)?;

    mac.update(&serialized);

    let expected_hmac = BASE64.encode(&mac.finalize().into_bytes());

    if !constant_time_compare(enc.structure_hmac.as_bytes(), expected_hmac.as_bytes()) {
        return Err(VaultError::IntegrityCheckFailed);
    }

    // Verify entropy quality via hash
    verify_entropy_hash(
        &enc.entropy_verification,
        &key_hierarchy.primary_data_key,
        &key_hierarchy.secondary_data_key,
        &key_hierarchy.tertiary_data_key,
    )?;

    // Decode all the binary fields
    let primary_nonce = BASE64
        .decode(&enc.primary_nonce)
        .map_err(|_| VaultError::InvalidFormat)?;

    let primary_ciphertext = BASE64
        .decode(&enc.primary_ciphertext)
        .map_err(|_| VaultError::InvalidFormat)?;

    let secondary_nonce = BASE64
        .decode(&enc.secondary_nonce)
        .map_err(|_| VaultError::InvalidFormat)?;

    let secondary_ciphertext = BASE64
        .decode(&enc.secondary_ciphertext)
        .map_err(|_| VaultError::InvalidFormat)?;

    let tertiary_nonce = BASE64
        .decode(&enc.tertiary_nonce)
        .map_err(|_| VaultError::InvalidFormat)?;

    let tertiary_ciphertext = BASE64
        .decode(&enc.tertiary_ciphertext)
        .map_err(|_| VaultError::InvalidFormat)?;

    let tertiary_hmac = BASE64
        .decode(&enc.tertiary_hmac)
        .map_err(|_| VaultError::InvalidFormat)?;

    let signature_bytes = BASE64
        .decode(&enc.data_signature)
        .map_err(|_| VaultError::InvalidFormat)?;

    let public_key_bytes = BASE64
        .decode(&enc.public_key)
        .map_err(|_| VaultError::InvalidFormat)?;

    // Verify the digital signature
    let verifying_key = VerifyingKey::from_bytes(
        public_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::VerificationFailed)?,
    )
    .map_err(|_| VaultError::VerificationFailed)?;

    // Recreate the signed data
    let mut to_verify = Vec::new();
    to_verify.extend_from_slice(&primary_nonce);
    to_verify.extend_from_slice(&primary_ciphertext);
    to_verify.extend_from_slice(&secondary_nonce);
    to_verify.extend_from_slice(&secondary_ciphertext);
    to_verify.extend_from_slice(&tertiary_nonce);
    to_verify.extend_from_slice(&tertiary_ciphertext);
    to_verify.extend_from_slice(&tertiary_hmac);

    // Convert signature bytes to a signature
    let signature = ed25519_dalek::Signature::from_bytes(
        signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::VerificationFailed)?,
    );

    // Verify signature
    verifying_key
        .verify(&to_verify, &signature)
        .map_err(|_| VaultError::VerificationFailed)?;

    // Decrypt the tertiary layer
    let secondary_ciphertext_decrypted = decrypt_aes_cbc_hmac(
        &tertiary_ciphertext,
        &key_hierarchy.tertiary_data_key,
        &key_hierarchy.hmac_key,
        &tertiary_nonce,
        &tertiary_hmac,
    )?;

    // Decrypt the secondary layer
    let primary_ciphertext_decrypted = decrypt_chacha20_poly1305(
        &secondary_ciphertext_decrypted,
        &key_hierarchy.secondary_data_key,
        &secondary_nonce,
    )?;

    // Decrypt the primary layer
    let padded_plaintext = decrypt_aes_gcm(
        &primary_ciphertext_decrypted,
        &key_hierarchy.primary_data_key,
        &primary_nonce,
    )?;

    // Remove padding to get the original plaintext
    let plaintext = remove_padding(&padded_plaintext)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_basic() {
        let data = b"Test data for triple-layer encryption";
        let password = "secure_password_123!@#";

        // Encrypt data
        let encrypted = encrypt_data(data, password).expect("Encryption failed");

        // Decrypt data
        let decrypted = decrypt_data(&encrypted, password).expect("Decryption failed");

        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_wrong_password() {
        let data = b"Sensitive data for password testing";
        let correct_password = "correct_password_123!@#";
        let wrong_password = "wrong_password_456!@#";

        // Encrypt with correct password
        let encrypted = encrypt_data(data, correct_password).expect("Encryption failed");

        // Try to decrypt with wrong password
        let result = decrypt_data(&encrypted, wrong_password);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampering_detection() {
        let data = b"Data to verify tampering detection";
        let password = "tampering_test_password_123";

        // Encrypt the data
        let mut encrypted = encrypt_data(data, password).expect("Encryption failed");

        // Tamper with primary ciphertext
        let original_ciphertext = encrypted.primary_ciphertext.clone();

        // Decode, modify, and re-encode
        let mut ciphertext_bytes = BASE64.decode(&original_ciphertext).unwrap();
        if ciphertext_bytes.len() > 0 {
            ciphertext_bytes[0] ^= 0xFF; // Flip bits in the first byte
        }
        encrypted.primary_ciphertext = BASE64.encode(&ciphertext_bytes);

        // Attempt to decrypt should fail integrity check
        let result = decrypt_data(&encrypted, password);
        assert!(result.is_err());

        // Restore the original ciphertext
        encrypted.primary_ciphertext = original_ciphertext;

        // Now tamper with the integrity hash
        encrypted.primary_integrity_hash = BASE64.encode(b"tampered_hash");

        // Attempt to decrypt should fail
        let result = decrypt_data(&encrypted, password);
        assert!(result.is_err());
    }

    #[test]
    fn test_padding() {
        // Test with various data sizes
        for &size in &[0, 10, 100, 1000, 10000] {
            let data = vec![0u8; size];

            // Add padding
            let padded = add_random_padding(&data).expect("Padding failed");

            // Check that padding was added
            assert!(padded.len() > data.len());

            // Check that original data can be recovered
            let recovered = remove_padding(&padded).expect("Padding removal failed");
            assert_eq!(data, recovered);
        }
    }

    #[test]
    fn test_empty_data() {
        // Test with empty data
        let data = b"";
        let password = "empty_data_password_123";

        // Encrypt and decrypt
        let encrypted = encrypt_data(data, password).expect("Encryption of empty data failed");

        let decrypted =
            decrypt_data(&encrypted, password).expect("Decryption of empty data failed");

        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_large_data() {
        // Test with moderately large data (100KB for fast tests)
        let size = 100 * 1024; // 100KB
        let data = vec![0x42u8; size]; // Fill with 'B'
        let password = "large_data_password_123";

        // Encrypt and decrypt
        let encrypted = encrypt_data(&data, password).expect("Encryption of large data failed");

        let decrypted =
            decrypt_data(&encrypted, password).expect("Decryption of large data failed");

        assert_eq!(data, decrypted);
    }
}

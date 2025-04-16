use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{SigningKey, VerifyingKey, Signer};
use rand_core::{OsRng, RngCore};
use crate::types::EncryptedData;
use std::convert::TryInto;

pub fn generate_keypair() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Encrypts the provided data with a key derived from `password` and returns an `EncryptedData`
/// structure that holds the base64-encoded nonce, salt, ciphertext, signature, and public key.
pub fn encrypt_data(data: &[u8], password: &str) -> EncryptedData {
    // Generate a random salt.
    let salt = SaltString::generate(&mut OsRng);

    // Derive a 32-byte key using Argon2 by filling a buffer.
    let mut key_bytes = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt.as_str().as_bytes(), &mut key_bytes)
        .expect("Key derivation failed");

    // Create the AES-256 key from the derived key bytes.
    let key = aes_gcm::Key::<aes_gcm::aes::Aes256>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Generate a 12-byte nonce.
    let mut nonce_bytes_12 = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes_12);
    let nonce = Nonce::from_slice(&nonce_bytes_12);

    // Encrypt the data.
    let ciphertext = cipher.encrypt(nonce, data).unwrap();

    // Generate a signing key and sign the ciphertext.
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);
    let signature = signing_key.sign(&ciphertext);

    EncryptedData {
        nonce: BASE64.encode(nonce_bytes_12),
        salt: salt.to_string(), // Save the salt as a string.
        ciphertext: BASE64.encode(ciphertext),
        signature: BASE64.encode(signature.to_bytes()),
        public_key: BASE64.encode(verifying_key.to_bytes()),
    }
}

/// Decrypts the data contained in `enc` using a key derived from the given `password`.
/// Returns either the plaintext or an error message.
pub fn decrypt_data(enc: &EncryptedData, password: &str) -> Result<Vec<u8>, &'static str> {
    // Re-create the salt from its stored string representation.
    let salt = SaltString::from_b64(&enc.salt).map_err(|_| "Invalid salt")?;

    // Re-derive the 32-byte key.
    let mut key_bytes = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt.as_str().as_bytes(), &mut key_bytes)
        .map_err(|_| "Key derivation failed")?;

    let key = aes_gcm::Key::<aes_gcm::aes::Aes256>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Decode the stored nonce (base64) and create a Nonce.
    let nonce_decoded = BASE64.decode(&enc.nonce).map_err(|_| "Invalid nonce")?;
    let nonce = Nonce::from_slice(&nonce_decoded);

    // Decode the ciphertext (base64).
    let ciphertext = BASE64.decode(&enc.ciphertext).map_err(|_| "Invalid ciphertext")?;

    // Decrypt the data.
    cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| "Decryption failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

    #[test]
    fn test_encrypt_decrypt() {
        let data = b"Test data for encryption";
        let password = "super_secret_password";

        // Encrypt the data.
        let encrypted = encrypt_data(data, password);
        // Decrypt the data back.
        let decrypted = decrypt_data(&encrypted, password).expect("Decryption failed");
        // Verify that the original and decrypted data match.
        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_decrypt_wrong_password() {
        // Ensure that using a wrong password results in a decryption error.
        let data = b"Sensitive data";
        let correct_password = "correct_password";
        let wrong_password = "wrong_password";

        let encrypted = encrypt_data(data, correct_password);
        let result = decrypt_data(&encrypted, wrong_password);
        assert!(result.is_err(), "Decryption should fail with an incorrect password");
    }

    #[test]
    fn test_decrypt_corrupted_ciphertext() {
        // Tamper with the encrypted ciphertext and ensure decryption fails.
        let data = b"Data to encrypt";
        let password = "password123";

        let mut encrypted = encrypt_data(data, password);
        // Decode the ciphertext, modify a byte, then re-encode.
        let mut ciphertext = BASE64.decode(&encrypted.ciphertext).expect("Ciphertext decode failed");
        ciphertext[0] ^= 0xFF;  // Flip one bit in the first byte.
        encrypted.ciphertext = BASE64.encode(&ciphertext);

        let result = decrypt_data(&encrypted, password);
        assert!(result.is_err(), "Decryption should fail when ciphertext is corrupted");
    }

    #[test]
    fn test_encrypt_decrypt_empty_data() {
        // Test encrypting and decrypting an empty byte slice.
        let data = b"";
        let password = "empty_password_test";

        let encrypted = encrypt_data(data, password);
        let decrypted = decrypt_data(&encrypted, password)
            .expect("Decryption failed for empty data");

        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_encrypted_data_format() {
        // Check that the output fields are valid base64 and have the expected byte lengths.
        let data = b"Some data";
        let password = "format_password";

        let encrypted = encrypt_data(data, password);

        // Verify nonce decodes to 12 bytes.
        let nonce_bytes = BASE64.decode(&encrypted.nonce).expect("Nonce base64 decode failed");
        assert_eq!(nonce_bytes.len(), 12, "Nonce should be 12 bytes long");

        // Verify signature decodes to 64 bytes (ed25519 signatures are 64 bytes).
        let sig_bytes = BASE64.decode(&encrypted.signature).expect("Signature base64 decode failed");
        assert_eq!(sig_bytes.len(), 64, "Signature should be 64 bytes long");

        // Verify public key decodes to 32 bytes (ed25519 public keys are 32 bytes).
        let pubkey_bytes = BASE64.decode(&encrypted.public_key).expect("Public key base64 decode failed");
        assert_eq!(pubkey_bytes.len(), 32, "Public key should be 32 bytes long");
    }
}

use base64::Engine;
use rand::{thread_rng, RngCore};
use std::time::Instant;
use test_case::test_case;
use zero_vault_core::{
    decrypt_data, encrypt_data,
    memory::{is_secure_memory_available, SecureBytes, SecureString},
    VaultError,
};

fn generate_random_data(size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];
    thread_rng().fill_bytes(&mut data);
    data
}

#[test]
fn test_memory_security_available() {
    // Check if secure memory is available on this platform
    let available = is_secure_memory_available();
    println!("Secure memory available: {}", available);
}

#[test]
fn test_encryption_decryption_cycle() {
    let data = b"Critical test data that must remain confidential";
    let password = "Test-Password-123!@#";

    // Encrypt data
    let start = Instant::now();
    let encrypted = encrypt_data(data, password).expect("Encryption failed");
    let encryption_time = start.elapsed();

    println!("Encryption time: {:?}", encryption_time);

    // Decrypt data
    let start = Instant::now();
    let decrypted = decrypt_data(&encrypted, password).expect("Decryption failed");
    let decryption_time = start.elapsed();

    println!("Decryption time: {:?}", decryption_time);

    // Verify data integrity
    assert_eq!(data.to_vec(), decrypted);
}

#[test_case(10; "tiny_10_bytes")]
#[test_case(1024; "small_1kb")]
#[test_case(1024 * 10; "medium_10kb")]
#[test_case(1024 * 100; "large_100kb")]
fn test_variable_data_sizes(size: usize) {
    let data = generate_random_data(size);
    let password = "Size-Test-Password-123!@#";

    // Encrypt and decrypt
    let encrypted = encrypt_data(&data, password).expect("Encryption failed");
    let decrypted = decrypt_data(&encrypted, password).expect("Decryption failed");

    // Verify
    assert_eq!(data, decrypted);
}

#[test]
fn test_password_security() {
    let data = b"Password security test data";

    // Test correct password
    let correct_password = "Correct-Password-123!@#";
    let encrypted = encrypt_data(data, correct_password).expect("Encryption failed");

    // Test wrong password
    let wrong_password = "Wrong-Password-456!@#";
    let result = decrypt_data(&encrypted, wrong_password);
    assert!(result.is_err());

    // Test different password lengths
    let long_password =
        "This-Is-A-Very-Long-Password-With-Special-Characters-!@#$%^&*()_+-=[]{}|;:,.<>?/~`";
    let encrypted_long =
        encrypt_data(data, long_password).expect("Encryption with long password failed");
    let decrypted_long =
        decrypt_data(&encrypted_long, long_password).expect("Decryption with long password failed");
    assert_eq!(data.to_vec(), decrypted_long);
}

#[test]
fn test_tamper_resistance() {
    let data = b"Tamper test data";
    let password = "Tamper-Test-Password-123!@#";

    // Encrypt data
    let mut encrypted = encrypt_data(data, password).expect("Encryption failed");

    // Test various tampering scenarios

    // 1. Tamper with primary ciphertext
    let original_primary = encrypted.primary_ciphertext.clone();
    encrypted.primary_ciphertext =
        base64::engine::general_purpose::STANDARD.encode(b"tampered_data");
    assert!(decrypt_data(&encrypted, password).is_err());
    encrypted.primary_ciphertext = original_primary;

    // 2. Tamper with secondary ciphertext
    let original_secondary = encrypted.secondary_ciphertext.clone();
    encrypted.secondary_ciphertext =
        base64::engine::general_purpose::STANDARD.encode(b"tampered_data");
    assert!(decrypt_data(&encrypted, password).is_err());
    encrypted.secondary_ciphertext = original_secondary;

    // 3. Tamper with tertiary ciphertext
    let original_tertiary = encrypted.tertiary_ciphertext.clone();
    encrypted.tertiary_ciphertext =
        base64::engine::general_purpose::STANDARD.encode(b"tampered_data");
    assert!(decrypt_data(&encrypted, password).is_err());
    encrypted.tertiary_ciphertext = original_tertiary;

    // 4. Tamper with integrity hash
    let original_hash = encrypted.primary_integrity_hash.clone();
    encrypted.primary_integrity_hash =
        base64::engine::general_purpose::STANDARD.encode(b"tampered_hash");
    assert!(decrypt_data(&encrypted, password).is_err());
    encrypted.primary_integrity_hash = original_hash;

    // 5. Tamper with parameters
    let original_params_hmac = encrypted.params.params_hmac.clone();
    encrypted.params.params_hmac =
        base64::engine::general_purpose::STANDARD.encode(b"tampered_hmac");
    assert!(decrypt_data(&encrypted, password).is_err());
    encrypted.params.params_hmac = original_params_hmac;

    // Verify original data still works
    let restored = encrypt_data(data, password).expect("Encryption failed");
    let decrypted = decrypt_data(&restored, password).expect("Decryption failed");
    assert_eq!(data.to_vec(), decrypted);
}

#[test]
fn test_secure_memory_containers() {
    // Test SecureBytes
    let sensitive_data = vec![1, 2, 3, 4, 5];
    let secure_bytes =
        SecureBytes::new(sensitive_data.clone()).expect("Failed to create SecureBytes");

    // Verify data access
    assert_eq!(secure_bytes.as_slice(), &[1, 2, 3, 4, 5]);

    // Test SecureString
    let sensitive_string = "password123".to_string();
    let secure_string =
        SecureString::new(sensitive_string.clone()).expect("Failed to create SecureString");

    // Verify data access
    assert_eq!(secure_string.as_str(), "password123");

    // Test memory integrity
    secure_bytes
        .verify_integrity()
        .expect("SecureBytes integrity check failed");
    secure_string
        .verify_integrity()
        .expect("SecureString integrity check failed");
}

#[test]
fn test_empty_data() {
    // Test with empty data
    let data = b"";
    let password = "Empty-Data-Password-123!@#";

    // Encrypt and decrypt
    let encrypted = encrypt_data(data, password).expect("Encryption of empty data failed");
    let decrypted = decrypt_data(&encrypted, password).expect("Decryption of empty data failed");

    // Verify
    assert_eq!(data.to_vec(), decrypted);
}

#[test]
fn test_unicode_passwords() {
    let data = b"Unicode password test data";

    // Test with various Unicode passwords
    let passwords = [
        "Password-πάσσωορδ-123",    // Greek
        "Password-パスワード-123",  // Japanese
        "Password-пароль-123",      // Russian
        "Password-密码-123",        // Chinese
        "Password-كلمة المرور-123", // Arabic
        "Password-🔒🔑💻-123",      // Emoji
    ];

    for password in &passwords {
        let encrypted =
            encrypt_data(data, password).expect("Encryption with Unicode password failed");
        let decrypted =
            decrypt_data(&encrypted, password).expect("Decryption with Unicode password failed");
        assert_eq!(data.to_vec(), decrypted);
    }
}

#[test]
fn test_multiple_encryption_uniqueness() {
    // Verify that encrypting the same data twice produces different results
    let data = b"Multiple encryption test data";
    let password = "Multiple-Test-Password-123!@#";

    let encrypted1 = encrypt_data(data, password).expect("First encryption failed");
    let encrypted2 = encrypt_data(data, password).expect("Second encryption failed");

    // Ciphertexts should be different due to random salt and nonces
    assert_ne!(encrypted1.primary_ciphertext, encrypted2.primary_ciphertext);
    assert_ne!(
        encrypted1.secondary_ciphertext,
        encrypted2.secondary_ciphertext
    );
    assert_ne!(
        encrypted1.tertiary_ciphertext,
        encrypted2.tertiary_ciphertext
    );

    // But both should decrypt to the same plaintext
    let decrypted1 = decrypt_data(&encrypted1, password).expect("First decryption failed");
    let decrypted2 = decrypt_data(&encrypted2, password).expect("Second decryption failed");

    assert_eq!(data.to_vec(), decrypted1);
    assert_eq!(data.to_vec(), decrypted2);
}

#[test]
fn test_stress_large_data() {
    // Only run this test when explicitly enabled
    if option_env!("RUN_LARGE_DATA_TEST").is_none() {
        println!("Skipping large data test (set RUN_LARGE_DATA_TEST=1 to enable)");
        return;
    }

    // Test with very large data (10MB)
    let size = 10 * 1024 * 1024; // 10MB
    let data = generate_random_data(size);
    let password = "Large-Data-Test-Password-123!@#";

    println!("Testing with {}MB of data", size / (1024 * 1024));

    // Encrypt and decrypt
    let start = Instant::now();
    let encrypted = encrypt_data(&data, password).expect("Encryption of large data failed");
    let encryption_time = start.elapsed();
    println!(
        "Encryption time for {}MB: {:?}",
        size / (1024 * 1024),
        encryption_time
    );

    let start = Instant::now();
    let decrypted = decrypt_data(&encrypted, password).expect("Decryption of large data failed");
    let decryption_time = start.elapsed();
    println!(
        "Decryption time for {}MB: {:?}",
        size / (1024 * 1024),
        decryption_time
    );

    // Verify
    assert_eq!(data, decrypted);
}

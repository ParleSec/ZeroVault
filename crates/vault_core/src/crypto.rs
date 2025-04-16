use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES-GCM
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use ed25519_dalek::{Keypair, Signature, Signer, PublicKey, Verifier};
use rand::rngs::OsRng as DalekRng;
use sha2::Sha512;
use base64::{encode, decode};
use crate::types::EncryptedData;

pub fn generate_keypair() -> Keypair {
    Keypair::generate(&mut DalekRng)
}

pub fn encrypt_data(data: &[u8], password: &str) -> EncryptedData {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let key = argon2
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .hash
        .unwrap();

    let key_bytes = hex::decode(key.as_str()).unwrap();
    let key = Key::from_slice(&key_bytes[..32]);
    let cipher = Aes256Gcm::new(key);
    let nonce_bytes = rand::random::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, data).unwrap();

    let keypair = generate_keypair();
    let signature: Signature = keypair.sign(&ciphertext);

    EncryptedData {
        nonce: encode(nonce_bytes),
        salt: encode(salt.as_bytes()),
        ciphertext: encode(ciphertext),
        signature: encode(signature.to_bytes()),
        public_key: encode(keypair.public.to_bytes()),
    }
}

pub fn decrypt_data(enc: &EncryptedData, password: &str) -> Result<Vec<u8>, &'static str> {
    let salt = decode(&enc.salt).unwrap();
    let nonce = decode(&enc.nonce).unwrap();
    let ciphertext = decode(&enc.ciphertext).unwrap();
    let signature = decode(&enc.signature).unwrap();
    let public_key_bytes = decode(&enc.public_key).unwrap();

    let public_key = PublicKey::from_bytes(&public_key_bytes).unwrap();
    let sig = Signature::from_bytes(&signature).unwrap();
    public_key.verify(&ciphertext, &sig).map_err(|_| "Invalid signature")?;

    let salt_str = SaltString::b64_encode(&salt).unwrap();
    let argon2 = Argon2::default();
    let key = argon2
        .hash_password(password.as_bytes(), &salt_str)
        .unwrap()
        .hash
        .unwrap();

    let key_bytes = hex::decode(key.as_str()).unwrap();
    let key = Key::from_slice(&key_bytes[..32]);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce);
    cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| "Decryption failed")
}

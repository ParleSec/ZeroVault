use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct EncryptedData {
    pub nonce: String,
    pub salt: String,
    pub ciphertext: String,
    pub signature: String,
    pub public_key: String,
}

# zero_vault_core

A lightweight cryptographic library providing Fort-Knox level security for document encryption.

## Security Features

- **Triple-layer encryption**: AES-256-GCM + ChaCha20-Poly1305 + AES-256-CBC
- **Advanced key derivation**: Argon2id with configurable memory cost
- **Digital signatures**: Ed25519 for data integrity and authenticity
- **Memory protection**: Guard pages, canaries, and secure memory handling
- **Defense-in-depth approach**: Multiple independent security layers

## Usage Example

```rust
use zero_vault_core::{encrypt_data, decrypt_data};

// Encrypt sensitive data
let data = b"Confidential information";
let password = "secure-password-example";

let encrypted = encrypt_data(data, password).unwrap();

// Decrypt with verification
let decrypted = decrypt_data(&encrypted, password).unwrap();
assert_eq!(data.to_vec(), decrypted);
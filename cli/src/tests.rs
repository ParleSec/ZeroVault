#[cfg(test)]
mod tests {
    use crate::types::{VaultFile, Metadata};
    use zero_vault_core::crypto::{encrypt_data, decrypt_data};
    use zero_vault_core::VaultEncryptedData;
    use std::time::{SystemTime, UNIX_EPOCH};
    
    #[test]
    fn test_metadata_default() {
        let metadata = Metadata::default();
        
        assert!(metadata.comment.is_none());
        assert!(metadata.created_at > 0);
        assert!(metadata.modified_at.is_none());
        assert!(!metadata.version.is_empty());
    }
    
    #[test]
    fn test_vault_file_new() {
        let test_data = b"Test data for encryption";
        let password = "test_password";
        let encrypted = encrypt_data(test_data, password);
        
        // Test with comment
        let vault_file = VaultFile::new(encrypted.clone(), Some("Test comment".to_string()));
        assert_eq!(vault_file.metadata.comment, Some("Test comment".to_string()));
        assert!(vault_file.metadata.created_at > 0);
        assert!(vault_file.metadata.modified_at.is_none());
        
        // Test without comment
        let vault_file = VaultFile::new(encrypted, None);
        assert_eq!(vault_file.metadata.comment, None);
    }
    
    #[test]
    fn test_vault_file_update() {
        let test_data = b"Test data for encryption";
        let password = "test_password";
        let encrypted = encrypt_data(test_data, password);
        
        let mut vault_file = VaultFile::new(encrypted.clone(), Some("Test comment".to_string()));
        let created_at = vault_file.metadata.created_at;
        
        // Wait a moment to ensure modified time is different
        std::thread::sleep(std::time::Duration::from_millis(10));
        
        // Update with new data
        let new_data = b"Updated test data";
        let new_encrypted = encrypt_data(new_data, password);
        vault_file.update(new_encrypted);
        
        // Check that modified time was set
        assert!(vault_file.metadata.modified_at.is_some());
        assert!(vault_file.metadata.modified_at.unwrap() > created_at);
        
        // Check that comment was preserved
        assert_eq!(vault_file.metadata.comment, Some("Test comment".to_string()));
    }
    
    #[test]
    fn test_vault_file_serialization() {
        let test_data = b"Test data for encryption";
        let password = "test_password";
        let encrypted = encrypt_data(test_data, password);
        
        let vault_file = VaultFile::new(encrypted, Some("Test comment".to_string()));
        
        // Serialize to JSON
        let json = serde_json::to_string(&vault_file).unwrap();
        
        // Deserialize from JSON
        let deserialized: VaultFile = serde_json::from_str(&json).unwrap();
        
        // Check metadata
        assert_eq!(deserialized.metadata.comment, Some("Test comment".to_string()));
        assert_eq!(deserialized.metadata.created_at, vault_file.metadata.created_at);
        assert_eq!(deserialized.metadata.modified_at, None);
        
        // Check encrypted data
        let decrypted = decrypt_data(&deserialized.data, password).unwrap();
        assert_eq!(decrypted, test_data);
    }
    
    #[test]
    fn test_parse_vault_file() {
        use crate::utils::parse_vault_file;
        
        // Test parsing a VaultFile
        let test_data = b"Test data for encryption";
        let password = "test_password";
        let encrypted = encrypt_data(test_data, password);
        let vault_file = VaultFile::new(encrypted.clone(), Some("Test comment".to_string()));
        let json = serde_json::to_string(&vault_file).unwrap();
        
        let (parsed_enc, parsed_metadata) = parse_vault_file(&json).unwrap();
        assert!(parsed_metadata.is_some());
        let metadata = parsed_metadata.unwrap();
        assert_eq!(metadata.comment, Some("Test comment".to_string()));
        
        // Test parsing a legacy EncryptedData
        let legacy_json = serde_json::to_string(&encrypted).unwrap();
        let (parsed_enc, parsed_metadata) = parse_vault_file(&legacy_json).unwrap();
        assert!(parsed_metadata.is_none());
    }
    
    #[test]
    fn test_format_timestamp() {
        use crate::utils::format_timestamp;
        
        // Test formatting a known timestamp
        let timestamp = 1609459200; // 2021-01-01 00:00:00 UTC
        let formatted = format_timestamp(timestamp);
        assert_eq!(formatted, "2021-01-01 00:00:00 UTC");
        
        // Test formatting current time
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let formatted = format_timestamp(now);
        assert!(!formatted.is_empty());
    }
}
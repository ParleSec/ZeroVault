use serde::{Serialize, Deserialize};
use zero_vault_core::VaultEncryptedData; // Update to use the new type directly
use std::time::{SystemTime, UNIX_EPOCH};

/// Metadata for the vault file
#[derive(Serialize, Deserialize, Debug)]
pub struct Metadata {
    /// Optional comment about the encrypted content
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    
    /// Unix timestamp of when the vault file was created
    pub created_at: u64,
    
    /// Unix timestamp of when the vault file was last modified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_at: Option<u64>,
    
    /// Version of the vault file format
    pub version: String,
}

impl Default for Metadata {
    fn default() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
            
        Self {
            comment: None,
            created_at: now,
            modified_at: None,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// Complete vault file structure including encrypted data and metadata
#[derive(Serialize, Deserialize)]
pub struct VaultFile {
    /// The encrypted data
    pub data: VaultEncryptedData,
    
    /// Metadata about the vault file
    #[serde(default)]
    pub metadata: Metadata,
}

impl VaultFile {
    /// Create a new vault file with the given encrypted data and optional comment
    pub fn new(data: VaultEncryptedData, comment: Option<String>) -> Self {
        let mut metadata = Metadata::default();
        metadata.comment = comment;
        
        Self {
            data,
            metadata,
        }
    }
    
    /// Update the vault file with new encrypted data
    pub fn update(&mut self, data: VaultEncryptedData) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
            
        self.data = data;
        self.metadata.modified_at = Some(now);
    }
}

/// Structured output for JSON mode
#[derive(Serialize)]
pub struct CommandOutput {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
}
use serde::{Deserialize, Serialize};

use crate::errors::RvError;

pub mod barrier;
pub mod barrier_aes_gcm;
pub mod barrier_view;
pub mod physical;
#[cfg(feature = "storage_mysql")]
pub mod mysql;

pub trait Storage {
    fn list(&self, prefix: &str) -> Result<Vec<String>, RvError>;
    fn get(&self, key: &str) -> Result<Option<StorageEntry>, RvError>;
    fn put(&self, entry: &StorageEntry) -> Result<(), RvError>;
    fn delete(&self, key: &str) -> Result<(), RvError>;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageEntry {
    pub key: String,
    pub value: Vec<u8>,
}

impl Default for StorageEntry {
    fn default() -> Self {
        Self { key: String::new(), value: Vec::new() }
    }
}

impl StorageEntry {
    pub fn new(k: &str, v: &impl Serialize) -> Result<StorageEntry, RvError> {
        let data = serde_json::to_string(v)?;

        Ok(StorageEntry { key: k.to_string(), value: data.into_bytes() })
    }
}

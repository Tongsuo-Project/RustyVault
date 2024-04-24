//! This module manages all storage related code by defining a 'barrier' concept and a 'backend'
//! concept.
//!
//! Each different storage type needs to implement the `backend` trait to complete the support.
//!
//! Each barrier represents a specific cryptography method for ecrypting or decrypting data before
//! the data connects to a specific backend. A barrier is defined by implementing the `SecurityBarrier`
//! trait.
//!
//! So one example of a whole data path could be something like this:
//!
//! HTTP API -> some module (e.g. KV) -> barrier -> backend -> real storage (file, MySQL...)
//!
//! Typical storage types may be direct file, databases, remote network filesystem and etc.
//! Different strage types are all as sub-module of this module.

use serde::{Deserialize, Serialize};

use crate::errors::RvError;

pub mod barrier;
pub mod barrier_aes_gcm;
pub mod barrier_view;
pub mod physical;
#[cfg(feature = "storage_mysql")]
pub mod mysql;

/// A trait that abstracts core methods for all storage barrier types.
pub trait Storage {
    fn list(&self, prefix: &str) -> Result<Vec<String>, RvError>;
    fn get(&self, key: &str) -> Result<Option<StorageEntry>, RvError>;
    fn put(&self, entry: &StorageEntry) -> Result<(), RvError>;
    fn delete(&self, key: &str) -> Result<(), RvError>;
}

/// This struct is used to describe a specific storage entry
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

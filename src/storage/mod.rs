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

use std::{collections::HashMap, sync::Arc};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::errors::RvError;

pub mod barrier;
pub mod barrier_aes_gcm;
pub mod barrier_view;
#[cfg(feature = "storage_mysql")]
pub mod mysql;
pub mod physical;

/// A trait that abstracts core methods for all storage barrier types.
pub trait Storage: Send + Sync {
    fn list(&self, prefix: &str) -> Result<Vec<String>, RvError>;
    fn get(&self, key: &str) -> Result<Option<StorageEntry>, RvError>;
    fn put(&self, entry: &StorageEntry) -> Result<(), RvError>;
    fn delete(&self, key: &str) -> Result<(), RvError>;
}

/// This struct is used to describe a specific storage entry
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageEntry {
    pub key: String,
    pub value: Vec<u8>,
}

impl StorageEntry {
    pub fn new(k: &str, v: &impl Serialize) -> Result<StorageEntry, RvError> {
        let data = serde_json::to_string(v)?;

        Ok(StorageEntry { key: k.to_string(), value: data.into_bytes() })
    }
}

pub trait Backend: Send + Sync {
    //! This trait decsribes the generic methods that a storage backend needs to implement.
    fn list(&self, prefix: &str) -> Result<Vec<String>, RvError>;
    fn get(&self, key: &str) -> Result<Option<BackendEntry>, RvError>;
    fn put(&self, entry: &BackendEntry) -> Result<(), RvError>;
    fn delete(&self, key: &str) -> Result<(), RvError>;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendEntry {
    pub key: String,
    pub value: Vec<u8>,
}

/// this is a generic function that instantiates different storage backends.
pub fn new_backend(t: &str, conf: &HashMap<String, Value>) -> Result<Arc<dyn Backend>, RvError> {
    match t {
        "file" => {
            let backend = physical::file::FileBackend::new(conf)?;
            Ok(Arc::new(backend))
        }
        #[cfg(feature = "storage_mysql")]
        "mysql" => {
            let backend = mysql::mysql_backend::MysqlBackend::new(conf)?;
            Ok(Arc::new(backend))
        }
        "mock" => Ok(Arc::new(physical::mock::MockBackend::new())),
        _ => Err(RvError::ErrPhysicalTypeInvalid),
    }
}

#[cfg(test)]
pub mod test {
    use std::{collections::HashMap, env, fs};

    use serde_json::Value;

    use crate::{
        storage::{new_backend, Backend, BackendEntry},
        test_utils::TEST_DIR,
    };

    #[test]
    fn test_new_backend() {
        let dir = env::temp_dir().join(*TEST_DIR).join("new_backend");
        assert!(fs::create_dir(&dir).is_ok());

        let mut conf: HashMap<String, Value> = HashMap::new();
        conf.insert("path".to_string(), Value::String(dir.to_string_lossy().into_owned()));

        let backend = new_backend("file", &conf);
        assert!(backend.is_ok());

        let backend = new_backend("foo", &conf);
        assert!(!backend.is_ok());
    }

    pub fn test_backend_curd(backend: &dyn Backend) {
        // Should be empty
        let keys = backend.list("");
        assert!(keys.is_ok());
        assert_eq!(keys.unwrap().len(), 0);

        let keys = backend.list("bar");
        assert!(keys.is_ok());
        assert_eq!(keys.unwrap().len(), 0);

        // Delete should work if it does not exist
        let res = backend.delete("bar");
        assert!(res.is_ok());

        // Get should work, but result is None
        let res = backend.get("bar");
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), None);

        // Make an Entry
        let entry = BackendEntry { key: "bar".to_string(), value: "test".as_bytes().to_vec() };

        let res = backend.put(&entry);
        assert!(res.is_ok());

        // Get should ok
        let res = backend.get("bar");
        assert!(res.is_ok());
        match res.unwrap() {
            Some(e) => {
                assert_eq!(e, entry);
            }
            None => panic!("Get should ok!"),
        }

        // List should not be empty
        let keys = backend.list("");
        assert!(keys.is_ok());
        let keys = keys.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], "bar".to_string());

        // Delete should ok
        let res = backend.delete("bar");
        assert!(res.is_ok());

        // List should be empty
        let keys = backend.list("");
        assert!(keys.is_ok());
        let keys = keys.unwrap();
        assert_eq!(keys.len(), 0);

        // Get should work, but result is None
        let res = backend.get("bar");
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), None);
    }

    pub fn test_backend_list_prefix(backend: &dyn Backend) {
        let entry1 = BackendEntry { key: "bar".to_string(), value: "test".as_bytes().to_vec() };
        let entry2 = BackendEntry { key: "bar/foo".to_string(), value: "test".as_bytes().to_vec() };
        let entry3 = BackendEntry { key: "bar/foo/goo".to_string(), value: "test".as_bytes().to_vec() };

        let res = backend.put(&entry1);
        assert!(res.is_ok());

        let res = backend.put(&entry2);
        assert!(res.is_ok());

        let res = backend.put(&entry3);
        assert!(res.is_ok());

        // Scan the root
        let keys = backend.list("");
        assert!(keys.is_ok());
        let keys = keys.unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.join("") == "barbar/" || keys.join("") == "bar/bar");

        // Scan bar/
        let keys = backend.list("bar/");
        assert!(keys.is_ok());
        let keys = keys.unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.join("") == "foofoo/" || keys.join("") == "foo/foo");

        // Scan bar/foo/
        let keys = backend.list("bar/foo/");
        assert!(keys.is_ok());
        let keys = keys.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], "goo".to_string());
    }
}

//! The `rusty_vault::storage::physical` module supports to physical file storage.

use std::{collections::HashMap, sync::Arc};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::errors::RvError;

#[cfg(feature = "storage_mysql")]
use super::mysql::mysql_backend::MysqlBackend;

pub mod etcd;
pub mod file;
pub mod mock;
pub mod error;

// TODO: this trait definition should be moved to an upper layer, e.g., in the storage/mod.rs
pub trait Backend: Send + Sync {
    //! This trait decsribes the general methods that a storage backend needs to implement.
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

// TODO: this is a common function needed by all storage backend. Should be moved out of this file.
pub fn new_backend(t: &str, conf: &HashMap<String, Value>) -> Result<Arc<dyn Backend>, RvError> {
    match t {
        "file" => {
            let backend = file::FileBackend::new(conf)?;
            Ok(Arc::new(backend))
        }
        #[cfg(feature = "storage_mysql")]
        "mysql" => {
            let backend = MysqlBackend::new(conf)?;
            Ok(Arc::new(backend))
        }
        "etcd" => {
            let backend = etcd::EtcdBackend::new(conf)?;
            Ok(Arc::new(backend))
        }
        "mock" => Ok(Arc::new(mock::MockBackend::new())),
        _ => Err(RvError::ErrPhysicalTypeInvalid),
    }
}

#[cfg(test)]
pub mod test {
    use std::{collections::HashMap, env, fs};

    use go_defer::defer;

    use super::*;

    #[test]
    fn test_new_backend() {
        let dir = env::temp_dir().join("rusty_vault_test_new_backend");
        assert!(fs::create_dir(&dir).is_ok());
        defer! (
            assert!(fs::remove_dir_all(&dir).is_ok());
        );

        let mut conf: HashMap<String, Value> = HashMap::new();
        conf.insert("path".to_string(), Value::String(dir.to_string_lossy().into_owned()));

        let backend = new_backend("file", &conf);
        assert!(backend.is_ok());

        let backend = new_backend("foo", &conf);
        assert!(!backend.is_ok());
    }

    pub fn test_backend(backend: &dyn Backend) {
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

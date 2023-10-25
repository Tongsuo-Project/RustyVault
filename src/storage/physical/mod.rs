use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::errors::RvError;

mod file;

pub trait Backend {
    fn list(&self, prefix: &str) -> Result<Vec<String>, RvError>;
    fn get(&self, key: &str) -> Result<Option<BackendEntry>, RvError>;
    fn put(&self, entry: &BackendEntry) -> Result<(), RvError>;
    fn delete(&self, key: &str) -> Result<(), RvError>;
}

pub trait Lock {
    fn lock(&self) -> Result<(), RvError>;
    fn unlock(&self) -> Result<(), RvError>;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendEntry {
    pub key: String,
    pub value: Vec<u8>,
}

pub fn new_backend(t: &str, conf: &HashMap<String, String>) -> Result<Box<dyn Backend>, RvError> {
    match t {
        "file" => {
            let backend = file::FileBackend::new(conf)?;
            Ok(Box::new(backend))
        }
        _ => {
            Err(RvError::ErrPhysicalTypeInvalid)
        }
    }
}

#[cfg(test)]
mod test {
    use std::env;
    use std::fs;
    use std::collections::HashMap;
    use go_defer::defer;
    use super::*;

    #[test]
    fn test_new_backend() {
        let dir = env::temp_dir().join("rusty_vault_test_new_backend");
        assert!(fs::create_dir(&dir).is_ok());
        defer! (
            assert!(fs::remove_dir_all(&dir).is_ok());
        );

        let mut conf: HashMap<String, String> = HashMap::new();
        conf.insert("path".to_string(), dir.to_string_lossy().into_owned());

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
        let entry = BackendEntry {
            key: "bar".to_string(),
            value: "test".as_bytes().to_vec(),
        };

        let res = backend.put(&entry);
        assert!(res.is_ok());

        // Get should ok
        let res = backend.get("bar");
        assert!(res.is_ok());
        match res.unwrap() {
            Some(e) => {
                assert_eq!(e, entry);
            }
            None => panic!("Get should ok!")
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
        let entry1 = BackendEntry {
            key: "bar".to_string(),
            value: "test".as_bytes().to_vec(),
        };
        let entry2 = BackendEntry {
            key: "bar/foo".to_string(),
            value: "test".as_bytes().to_vec(),
        };
        let entry3 = BackendEntry {
            key: "bar/foo/goo".to_string(),
            value: "test".as_bytes().to_vec(),
        };

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
        assert_eq!(keys[0], "bar".to_string());
        assert_eq!(keys[1], "bar/".to_string());

        // Scan bar/
        let keys = backend.list("bar/");
        assert!(keys.is_ok());
        let keys = keys.unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], "foo".to_string());
        assert_eq!(keys[1], "foo/".to_string());

        // Scan bar/foo/
        let keys = backend.list("bar/foo/");
        assert!(keys.is_ok());
        let keys = keys.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], "goo".to_string());
    }
}

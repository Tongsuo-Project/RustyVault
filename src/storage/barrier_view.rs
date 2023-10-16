use std::sync::Arc;
use crate::errors::RvError;
use super::{Storage, StorageEntry, barrier::SecurityBarrier};

pub struct BarrierView {
    barrier: Arc<dyn SecurityBarrier>,
    prefix: String,
}

impl Storage for BarrierView {
    fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
        self.sanity_check(prefix)?;
        self.barrier.list(self.expand_key(prefix).as_str())
    }

    fn get(&self, key: &str) -> Result<Option<StorageEntry>, RvError> {
        self.sanity_check(key)?;
        let storage_entry = self.barrier.get(self.expand_key(key).as_str())?;
        if let Some(entry) = storage_entry {
            Ok(Some(StorageEntry {
                key: self.truncate_key(entry.key.as_str()),
                value: entry.value,
            }))
        } else {
            Ok(None)
        }
    }

    fn put(&self, entry: &StorageEntry) -> Result<(), RvError> {
        self.sanity_check(entry.key.as_str())?;
        let nested = StorageEntry {
            key: self.expand_key(entry.key.as_str()),
            value: entry.value.clone(),
        };
        self.barrier.put(&nested)
    }

    fn delete(&self, key: &str) -> Result<(), RvError> {
        self.sanity_check(key)?;
        self.barrier.delete(self.expand_key(key).as_str())
    }
}

impl BarrierView {
    pub fn new(barrier: Arc<dyn SecurityBarrier>, prefix: &str) -> Self {
        Self {
            barrier: barrier,
            prefix: prefix.to_string(),
        }
    }

    pub fn get_keys(&self) -> Result<Vec<String>, RvError> {
        let mut paths = vec!["".to_string()];
        let mut keys = Vec::new();
        while !paths.is_empty() {
            let n = paths.len();
            let curr = paths[n - 1].to_owned();
            paths.pop();

            let items = self.list(curr.as_str())?;
            for p in items {
                let path = format!("{}{}", curr, p);
                if p.ends_with("/") {
                    paths.push(path);
                } else {
                    keys.push(path.to_owned());
                }
            }
        }
        Ok(keys)
    }

    pub fn clear(&self) -> Result<(), RvError> {
        let keys = self.get_keys()?;
        for key in keys {
            self.delete(key.as_str())?
        }
        Ok(())
    }

    pub fn as_storage(&self) -> &dyn Storage {
        self
    }

    fn sanity_check(&self, key: &str) -> Result<(), RvError> {
        if key.contains("..") || key.starts_with("/") {
            Err(RvError::ErrBarrierKeySanityCheckFailed)
        } else {
            Ok(())
        }
    }

    fn expand_key(&self, suffix: &str) -> String {
        format!("{}{}", self.prefix, suffix)
    }

    fn truncate_key(&self, full: &str) -> String {
        if let Some(result) = full.strip_prefix(self.prefix.as_str()) {
            return result.to_string();
        } else {
            return full.to_string();
        }
    }
}

#[cfg(test)]
mod test {
    use std::env;
    use std::fs;
    use std::sync::Arc;
    use std::collections::HashMap;
    use rand::{Rng, thread_rng};
    use go_defer::defer;
    use super::*;
    use super::super::*;

    #[test]
    fn test_new_barrier_view() {
        let dir = env::temp_dir().join("rusty_vault_test_new_barrier_view");
        assert!(fs::create_dir(&dir).is_ok());
        defer! (
            assert!(fs::remove_dir_all(&dir).is_ok());
        );

        let mut conf: HashMap<String, String> = HashMap::new();
        conf.insert("path".to_string(), dir.to_string_lossy().into_owned());

        let mut key = vec![0u8; 32];
        thread_rng().fill(key.as_mut_slice());

        let backend = physical::new_backend("file", &conf);
        assert!(backend.is_ok());
        let backend = backend.unwrap();
        let aes_gcm_view = barrier_aes_gcm::AESGCMBarrier::new(Arc::clone(&backend));

        let init = aes_gcm_view.init(key.as_slice());
        assert!(init.is_ok());

        let view = barrier_view::BarrierView::new(Arc::new(aes_gcm_view), "test");
        assert_eq!(view.expand_key("foo"), "testfoo");
        assert!(view.sanity_check("foo").is_ok());
        assert!(view.sanity_check("../foo").is_err());
        assert!(view.sanity_check("foo/../").is_err());
    }
}

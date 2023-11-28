use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, Read, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use serde_json::Value;

use super::{Backend, BackendEntry};
use crate::errors::RvError;

#[derive(Debug)]
pub struct FileBackend {
    path: PathBuf,
    lock: Arc<Mutex<i32>>,
}

impl Backend for FileBackend {
    fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
        if prefix.starts_with("/") {
            return Err(RvError::ErrPhysicalBackendPrefixInvalid);
        }

        let mut path = self.path.clone();
        if !prefix.is_empty() {
            path.push(prefix);
        }

        let _lock = self.lock.lock().unwrap();

        if !path.exists() {
            return Ok(Vec::new());
        }

        let mut names: Vec<String> = vec![];
        let entries = fs::read_dir(path)?;
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('_') {
                names.push(name[1..].to_owned());
            } else {
                names.push(name + "/");
            }
        }
        Ok(names)
    }

    fn get(&self, k: &str) -> Result<Option<BackendEntry>, RvError> {
        if k.starts_with("/") {
            return Err(RvError::ErrPhysicalBackendKeyInvalid);
        }

        let (path, key) = self.path_key(k);
        let path = path.join(key);

        let _lock = self.lock.lock().unwrap();

        match File::open(&path) {
            Ok(mut file) => {
                let mut buffer = String::new();
                file.read_to_string(&mut buffer)?;
                let entry: BackendEntry = serde_json::from_str(&buffer)?;
                Ok(Some(entry))
            }
            Err(err) => {
                if err.kind() == io::ErrorKind::NotFound {
                    Ok(None)
                } else {
                    Err(RvError::from(err))
                }
            }
        }
    }

    fn put(&self, entry: &BackendEntry) -> Result<(), RvError> {
        let k = entry.key.as_str();
        if k.starts_with("/") {
            return Err(RvError::ErrPhysicalBackendKeyInvalid);
        }

        let _lock = self.lock.lock().unwrap();
        let (path, key) = self.path_key(k);
        fs::create_dir_all(&path)?;
        let file_path = path.join(&key);
        let mut file = File::create(&file_path)?;
        let serialized_entry = serde_json::to_string(entry)?;
        file.write_all(serialized_entry.as_bytes())?;
        Ok(())
    }

    fn delete(&self, k: &str) -> Result<(), RvError> {
        if k.starts_with("/") {
            return Err(RvError::ErrPhysicalBackendKeyInvalid);
        }

        let _lock = self.lock.lock().unwrap();
        let (path, key) = self.path_key(k);
        let file_path = path.join(key);
        if let Err(err) = fs::remove_file(&file_path) {
            if err.kind() == io::ErrorKind::NotFound {
                return Ok(());
            } else {
                return Err(RvError::from(err));
            }
        }
        Ok(())
    }
}

impl FileBackend {
    pub fn new(conf: &HashMap<String, Value>) -> Result<Self, RvError> {
        match conf.get("path") {
            Some(path) => {
                let path = path.as_str();
                if path.is_none() {
                    return Err(RvError::ErrPhysicalConfigItemMissing);
                }

                Ok(FileBackend { path: PathBuf::from(path.unwrap()), lock: Arc::new(Mutex::new(0)) })
            }
            None => Err(RvError::ErrPhysicalConfigItemMissing),
        }
    }

    fn path_key(&self, k: &str) -> (PathBuf, String) {
        let path = self.path.join(k);
        let parent = path.parent().unwrap().to_owned();
        let key = format!("_{}", path.file_name().unwrap().to_string_lossy());
        (parent, key)
    }
}

#[cfg(test)]
mod test {
    use std::{collections::HashMap, env, fs};

    use go_defer::defer;

    use super::{
        super::test::{test_backend, test_backend_list_prefix},
        *,
    };

    #[test]
    fn test_file_backend() {
        let dir = env::temp_dir().join("rusty_vault");
        assert!(fs::create_dir(&dir).is_ok());
        defer! (
            assert!(fs::remove_dir_all(&dir).is_ok());
        );

        let mut conf: HashMap<String, Value> = HashMap::new();
        conf.insert("path".to_string(), Value::String(dir.to_string_lossy().into_owned()));

        let backend = FileBackend::new(&conf);

        assert!(backend.is_ok());

        let backend = backend.unwrap();

        test_backend(&backend);
        test_backend_list_prefix(&backend);
    }
}

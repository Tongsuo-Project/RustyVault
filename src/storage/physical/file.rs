use std::{
    any::Any,
    collections::HashMap,
    fs::{self, File},
    io::{self, Read, Write},
    path::PathBuf,
    thread::sleep,
    time::Duration,
};

use lockfile::Lockfile;
use serde_json::Value;

use crate::{
    errors::RvError,
    storage::{Backend, BackendEntry},
};

#[derive(Debug)]
pub struct FileBackend {
    path: PathBuf,
}

impl Backend for FileBackend {
    fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
        if prefix.starts_with('/') {
            return Err(RvError::ErrPhysicalBackendPrefixInvalid);
        }

        let mut path = self.path.clone();
        if !prefix.is_empty() {
            path.push(prefix);
        }

        if !path.exists() {
            return Ok(Vec::new());
        }

        let mut names: Vec<String> = vec![];
        let entries = fs::read_dir(path)?;
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(stripped) = name.strip_prefix('_') {
                names.push(stripped.to_owned());
            } else {
                names.push(name + "/");
            }
        }
        Ok(names)
    }

    fn get(&self, k: &str) -> Result<Option<BackendEntry>, RvError> {
        if k.starts_with('/') {
            return Err(RvError::ErrPhysicalBackendKeyInvalid);
        }

        let (path, key) = self.path_key(k);
        let path = path.join(key);

        match File::open(path) {
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
        if k.starts_with('/') {
            return Err(RvError::ErrPhysicalBackendKeyInvalid);
        }

        let serialized_entry = serde_json::to_string(entry)?;
        let (path, key) = self.path_key(k);
        fs::create_dir_all(&path)?;

        let _lock = self.lock(k)?;

        let file_path = path.join(key);
        let mut file = File::create(file_path)?;
        file.write_all(serialized_entry.as_bytes())?;
        Ok(())
    }

    fn delete(&self, k: &str) -> Result<(), RvError> {
        if k.starts_with('/') {
            return Err(RvError::ErrPhysicalBackendKeyInvalid);
        }

        let _lock = self.lock(k)?;

        let (path, key) = self.path_key(k);
        let file_path = path.join(key);
        if let Err(err) = fs::remove_file(file_path) {
            if err.kind() == io::ErrorKind::NotFound {
                return Ok(());
            } else {
                return Err(RvError::from(err));
            }
        }
        Ok(())
    }

    fn lock(&self, lock_name: &str) -> Result<Box<dyn Any>, RvError> {
        let (path, key) = self.path_key(lock_name);
        let file_path = path.join(format!("{}.lock", key));
        loop {
            if let Ok(lock) = Lockfile::create_with_parents(&file_path) {
                return Ok(Box::new(lock));
            } else {
                sleep(Duration::from_millis(100));
            }
        }
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

                let fb = FileBackend { path: PathBuf::from(path.unwrap()) };
                fs::create_dir_all(&fb.path)?;
                Ok(fb)
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
    use super::super::super::test::{test_backend_curd, test_backend_list_prefix};
    use crate::test_utils::{new_test_backend, new_test_file_backend, new_test_temp_dir, test_multi_routine};

    #[test]
    fn test_file_backend() {
        let backend = new_test_backend("test_file_backend");

        test_backend_curd(backend.as_ref());
        test_backend_list_prefix(backend.as_ref());
    }

    #[test]
    fn test_file_backend_multi_routine() {
        let dir = new_test_temp_dir("test_file_backend_multi_routine");
        let backend = new_test_file_backend(&dir);
        test_multi_routine(backend);
    }
}

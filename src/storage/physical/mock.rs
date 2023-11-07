use std::default::Default;
use crate::errors::RvError;
use super::{Backend, BackendEntry};

#[derive(Default)]
pub struct MockBackend(u32);

impl Backend for MockBackend {
    fn list(&self, _prefix: &str) -> Result<Vec<String>, RvError> {
        Ok(Vec::new())
    }

    fn get(&self, _k: &str) -> Result<Option<BackendEntry>, RvError> {
        Ok(None)
    }

    fn put(&self, _entry: &BackendEntry) -> Result<(), RvError> {
        Ok(())
    }

    fn delete(&self, _k: &str) -> Result<(), RvError> {
        Ok(())
    }
}

impl MockBackend {
    pub fn new() -> Self {
        MockBackend(0)
    }
}

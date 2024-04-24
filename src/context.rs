//! The `rusty_vault::context` module is intent to provide a generic key value storage.
//! This module is currently not used by any other part of `crate::rusty_vault`.

use std::{
    any::Any,
    cell::RefCell,
    collections::HashMap,
    sync::{Arc, Mutex},
};

pub struct Context {
    data_map: Mutex<HashMap<String, Arc<RefCell<dyn Any>>>>,
}

impl Context {
    pub fn new() -> Self {
        Self { data_map: Mutex::new(HashMap::new()) }
    }

    pub fn set(&self, key: &str, data: Arc<RefCell<dyn Any>>) {
        let mut data_map = self.data_map.lock().unwrap();
        data_map.insert(key.to_string(), data);
    }

    pub fn get(&self, key: &str) -> Option<Arc<RefCell<dyn Any>>> {
        let data_map = self.data_map.lock().unwrap();
        data_map.get(key).cloned()
    }
}

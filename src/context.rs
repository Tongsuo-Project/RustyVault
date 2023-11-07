use std::any::Any;
use std::cell::RefCell;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

pub struct Context {
    data_map: Mutex<HashMap<String, Arc<RefCell<dyn Any>>>>,
}

impl Context {
    pub fn new() -> Self {
        Self {
            data_map: Mutex::new(HashMap::new()),
        }
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

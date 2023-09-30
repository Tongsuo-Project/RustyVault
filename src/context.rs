use std::any::Any;
use std::rc::Rc;
use std::cell::RefCell;
use std::sync::{Mutex};
use std::collections::HashMap;

pub struct Context {
    data_map: Mutex<HashMap<String, Rc<RefCell<dyn Any>>>>,
}

impl Context {
    pub fn new() -> Self {
        Self {
            data_map: Mutex::new(HashMap::new()),
        }
    }

    pub fn set(&self, key: &str, data: Rc<RefCell<dyn Any>>) {
        let mut data_map = self.data_map.lock().unwrap();
        data_map.insert(key.to_string(), data);
    }

    pub fn get(&self, key: &str) -> Option<Rc<RefCell<dyn Any>>> {
        let data_map = self.data_map.lock().unwrap();
        data_map.get(key).cloned()
    }
}

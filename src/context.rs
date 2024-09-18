//! The `rusty_vault::context` module is intent to provide a generic key value storage.
//! This module is currently not used by any other part of `crate::rusty_vault`.

use std::{
    any::Any,
    sync::{Arc, RwLock},
};

use dashmap::DashMap;

#[derive(Debug)]
pub struct Context {
    data_map: DashMap<String, Arc<dyn Any + Send + Sync>>,
    data_map_mut: DashMap<String, Arc<RwLock<dyn Any + Send + Sync>>>,
}

impl Context {
    pub fn new() -> Self {
        Self { data_map: DashMap::new(), data_map_mut: DashMap::new() }
    }

    pub fn set_mut(&self, key: &str, data: Arc<RwLock<dyn Any + Send + Sync>>) {
        self.data_map_mut.insert(key.to_string(), data);
    }

    pub fn get_mut(&self, key: &str) -> Option<Arc<RwLock<dyn Any + Send + Sync>>> {
        self.data_map_mut.get(key).map(|r| Arc::clone(&r.value()))
    }

    pub fn set(&self, key: &str, data: Arc<dyn Any + Send + Sync>) {
        self.data_map.insert(key.to_string(), data);
    }

    pub fn get(&self, key: &str) -> Option<Arc<dyn Any + Send + Sync>> {
        self.data_map.get(key).map(|r| Arc::clone(&*r))
    }
}

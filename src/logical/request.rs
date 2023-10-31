use std::collections::HashMap;
use std::sync::Arc;
use serde_json::{Value, Map};
use crate::logical::connection::Connection;
use crate::logical::secret::Secret;
use crate::storage::{Storage, StorageEntry};
use super::{Path, Operation};
use crate::errors::RvError;

pub struct Request {
    pub id: String,
    pub name: String,
    pub operation: Operation,
    pub path: String,
    pub match_path: Option<Arc<Path>>,
    pub headers: Option<HashMap<String, String>>,
    pub body: Option<Map<String, Value>>,
    pub data: Option<Map<String, Value>>,
    pub client_token: String,
    pub storage: Option<Arc<dyn Storage>>,
    pub connection: Option<Connection>,
    pub secret: Option<Secret>,
}

impl Request {
    pub fn new(path: &str) -> Self {
        Self {
            id: "".to_string(),
            name: "".to_string(),
            operation: Operation::Read,
            path: path.to_string(),
            match_path: None,
            headers: None,
            body: None,
            data: None,
            client_token: "".to_string(),
            storage: None,
            connection: None,
            secret: None,
        }
    }

    pub fn get_data(&self, key: &str) -> Result<Value, RvError> {
        if self.storage.is_none() || self.match_path.is_none() {
            return Err(RvError::ErrRequestNotReady);
        }

        if self.data.is_none() && self.body.is_none() {
            return Err(RvError::ErrRequestNoData);
        }

        let field = self.match_path.as_ref().unwrap().get_field(key);
        if field.is_none() {
            return Err(RvError::ErrRequestNoDataField);
        }

        if self.data.is_some() {
            if let Some(data) = self.data.as_ref().unwrap().get(key) {
                return Ok(data.clone())
            }
        }

        if self.body.is_some() {
            if let Some(data) = self.body.as_ref().unwrap().get(key) {
                return Ok(data.clone())
            }
        }

        return field.unwrap().get_default();
    }

    pub fn storage_list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
        if self.storage.is_none() {
            return Err(RvError::ErrRequestNotReady);
        }

        self.storage.as_ref().unwrap().list(prefix)
    }

    pub fn storage_get(&self, key: &str) -> Result<Option<StorageEntry>, RvError> {
        if self.storage.is_none() {
            return Err(RvError::ErrRequestNotReady);
        }

        self.storage.as_ref().unwrap().get(key)
    }

    pub fn storage_put(&self, entry: &StorageEntry) -> Result<(), RvError> {
        if self.storage.is_none() {
            return Err(RvError::ErrRequestNotReady);
        }

        self.storage.as_ref().unwrap().put(entry)
    }

    pub fn storage_delete(&self, key: &str) -> Result<(), RvError> {
        if self.storage.is_none() {
            return Err(RvError::ErrRequestNotReady);
        }

        self.storage.as_ref().unwrap().delete(key)
    }
}

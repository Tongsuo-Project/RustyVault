use std::{collections::HashMap, sync::Arc};

use serde_json::{Map, Value};

use super::{Operation, Path};
use crate::{
    errors::RvError,
    logical::{auth::Auth, connection::Connection, secret::SecretData},
    storage::{Storage, StorageEntry},
};

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
    pub secret: Option<SecretData>,
    pub auth: Option<Auth>,
}

impl Default for Request {
    fn default() -> Self {
        Request {
            id: String::new(),
            name: String::new(),
            operation: Operation::Read,
            path: String::new(),
            match_path: None,
            headers: None,
            body: None,
            data: None,
            client_token: String::new(),
            storage: None,
            connection: None,
            secret: None,
            auth: None,
        }
    }
}

impl Request {
    pub fn new(path: &str) -> Self {
        Self { path: path.to_string(), ..Default::default() }
    }

    pub fn new_revoke_request(path: &str, secret: Option<SecretData>, data: Option<Map<String, Value>>) -> Self {
        Self { operation: Operation::Revoke, path: path.to_string(), secret, data, ..Default::default() }
    }

    pub fn new_renew_request(path: &str, secret: Option<SecretData>, data: Option<Map<String, Value>>) -> Self {
        Self { operation: Operation::Renew, path: path.to_string(), secret, data, ..Default::default() }
    }

    pub fn new_renew_auth_request(path: &str, auth: Option<Auth>, data: Option<Map<String, Value>>) -> Self {
        Self { operation: Operation::Renew, path: path.to_string(), auth, data, ..Default::default() }
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
                return Ok(data.clone());
            }
        }

        if self.body.is_some() {
            if let Some(data) = self.body.as_ref().unwrap().get(key) {
                return Ok(data.clone());
            }
        }

        let field = field.unwrap();

        if field.required {
            return Err(RvError::ErrRequestFieldNotFound);
        }

        return field.get_default();
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

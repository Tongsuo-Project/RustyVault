use std::{collections::HashMap, sync::Arc};

use better_default::Default;
use serde_json::{Map, Value};

use super::{Operation, Path};
use crate::{
    context::Context,
    errors::RvError,
    handler::{HandlePhase, Handler},
    logical::{auth::Auth, connection::Connection, secret::SecretData},
    storage::{Storage, StorageEntry},
};

#[derive(Default, Clone)]
pub struct Request {
    pub id: String,
    pub name: String,
    #[default(Operation::Read)]
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
    pub handler: Option<Arc<dyn Handler>>,
    #[default(HandlePhase::PreRoute)]
    pub handle_phase: HandlePhase,
    #[default(Arc::new(Context::new()))]
    pub ctx: Arc<Context>,
}

impl Request {
    pub fn new<S: Into<String>>(path: S) -> Self {
        Self { path: path.into(), ..Default::default() }
    }

    pub fn new_revoke_request<S: Into<String>>(
        path: S,
        secret: Option<SecretData>,
        data: Option<Map<String, Value>>,
    ) -> Self {
        Self { operation: Operation::Revoke, path: path.into(), secret, data, ..Default::default() }
    }

    pub fn new_renew_request<S: Into<String>>(
        path: S,
        secret: Option<SecretData>,
        data: Option<Map<String, Value>>,
    ) -> Self {
        Self { operation: Operation::Renew, path: path.into(), secret, data, ..Default::default() }
    }

    pub fn new_renew_auth_request<S: Into<String>>(
        path: S,
        auth: Option<Auth>,
        data: Option<Map<String, Value>>,
    ) -> Self {
        Self { operation: Operation::Renew, path: path.into(), auth, data, ..Default::default() }
    }

    pub fn bind_handler(&mut self, handler: Arc<dyn Handler>) {
        self.handler = Some(handler);
    }

    pub fn get_handler(&self) -> Option<Arc<dyn Handler>> {
        self.handler.clone()
    }

    fn get_data_raw(&self, key: &str, default: bool) -> Result<Value, RvError> {
        let field = self.match_path.as_ref().unwrap().get_field(key);
        if field.is_none() {
            return Err(RvError::ErrRequestNoDataField);
        }
        let field = field.unwrap();

        if self.data.is_some() {
            if let Some(data) = self.data.as_ref().unwrap().get(key) {
                if !field.check_data_type(data) {
                    return Err(RvError::ErrRequestFieldInvalid);
                }
                return Ok(data.clone());
            }
        }

        if self.body.is_some() {
            if let Some(data) = self.body.as_ref().unwrap().get(key) {
                if !field.check_data_type(data) {
                    return Err(RvError::ErrRequestFieldInvalid);
                }
                return Ok(data.clone());
            }
        }

        if default {
            if field.required {
                return Err(RvError::ErrRequestFieldNotFound);
            }

            return field.get_default();
        }

        Err(RvError::ErrRequestFieldNotFound)
    }

    pub fn get_data(&self, key: &str) -> Result<Value, RvError> {
        if self.match_path.is_none() {
            return Err(RvError::ErrRequestNotReady);
        }

        if self.data.is_none() && self.body.is_none() {
            return Err(RvError::ErrRequestNoData);
        }

        self.get_data_raw(key, false)
    }

    pub fn get_data_or_default(&self, key: &str) -> Result<Value, RvError> {
        if self.match_path.is_none() {
            return Err(RvError::ErrRequestNotReady);
        }

        if self.data.is_none() && self.body.is_none() {
            return Err(RvError::ErrRequestNoData);
        }

        self.get_data_raw(key, true)
    }

    pub fn get_data_or_next(&self, keys: &[&str]) -> Result<Value, RvError> {
        if self.match_path.is_none() {
            return Err(RvError::ErrRequestNotReady);
        }

        if self.data.is_none() && self.body.is_none() {
            return Err(RvError::ErrRequestNoData);
        }

        for &key in keys.iter() {
            match self.get_data_raw(key, false) {
                Ok(raw) => {
                    return Ok(raw);
                }
                Err(e) => {
                    if e != RvError::ErrRequestFieldNotFound {
                        return Err(e);
                    }
                }
            }
        }

        Err(RvError::ErrRequestFieldNotFound)
    }

    pub fn get_data_as_str(&self, key: &str) -> Result<String, RvError> {
        self.get_data(key)?.as_str().ok_or(RvError::ErrRequestFieldInvalid).and_then(|s| {
            if s.trim().is_empty() {
                Err(RvError::ErrResponse(format!("missing {}", key)))
            } else {
                Ok(s.trim().to_string())
            }
        })
    }

    pub fn get_field_default_or_zero(&self, key: &str) -> Result<Value, RvError> {
        if self.match_path.is_none() {
            return Err(RvError::ErrRequestNotReady);
        }
        let field = self.match_path.as_ref().unwrap().get_field(key).ok_or(RvError::ErrRequestNoDataField)?;
        field.get_default()
    }

    pub fn data_iter(&self) -> impl Iterator<Item = (&String, &Value)> {
        let data_iter = self.data.as_ref().into_iter().flat_map(|m| m.iter());
        let body_iter = self.body.as_ref().into_iter().flat_map(|m| m.iter());
        data_iter.chain(body_iter)
    }

    //TODO: the sensitive data is still in the memory. Need to totally resolve this in `serde_json` someday.
    pub fn clear_data(&mut self, key: &str) {
        if self.data.is_some() {
            if let Some(secret_str) = self.data.as_mut().unwrap().get_mut(key) {
                if let Value::String(ref mut s) = *secret_str {
                    "".clone_into(s);
                }
            }
        }

        if self.body.is_some() {
            if let Some(secret_str) = self.body.as_mut().unwrap().get_mut(key) {
                if let Value::String(ref mut s) = *secret_str {
                    "".clone_into(s);
                }
            }
        }
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

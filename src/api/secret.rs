use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{errors::RvError, rv_error_string};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Secret {
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub lease_id: String,
    #[serde(default)]
    pub lease_duration: u32,
    #[serde(default)]
    pub renewable: bool,
    #[serde(default)]
    pub data: Map<String, Value>,
    #[serde(default)]
    pub auth: Option<SecretAuth>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretAuth {
    #[serde(default)]
    pub client_token: String,
    #[serde(default)]
    pub accessor: String,
    #[serde(default)]
    pub policies: Vec<String>,
    #[serde(default)]
    pub token_policies: Vec<String>,
    #[serde(default)]
    pub identity_policies: Vec<String>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    #[serde(default)]
    pub entity_id: String,
    #[serde(default)]
    pub lease_duration: u64,
    #[serde(default)]
    pub renewable: bool,
}

impl Secret {
    pub fn token_is_renewable(&self) -> Result<bool, RvError> {
        if let Some(auth) = &self.auth {
            return Ok(auth.renewable);
        }

        if let Some(data) = self.data.get("renewable") {
            if let Some(renewable) = data.as_bool() {
                return Ok(renewable);
            } else {
                return Err(rv_error_string!("token id found but in the wrong format"));
            }
        }

        Ok(false)
    }

    pub fn token_id(&self) -> Result<String, RvError> {
        if let Some(auth) = &self.auth {
            if !auth.client_token.is_empty() {
                return Ok(auth.client_token.clone());
            }
        }

        if let Some(data) = self.data.get("id") {
            if let Some(id) = data.as_str() {
                return Ok(id.to_string());
            } else {
                return Err(rv_error_string!("token id found but in the wrong format"));
            }
        }

        Ok("".into())
    }

    pub fn token_accessor(&self) -> Result<String, RvError> {
        if let Some(auth) = &self.auth {
            if !auth.accessor.is_empty() {
                return Ok(auth.accessor.clone());
            }
        }

        if let Some(data) = self.data.get("accessor") {
            if let Some(accessor) = data.as_str() {
                return Ok(accessor.to_string());
            } else {
                return Err(rv_error_string!("token accessor found but in the wrong format"));
            }
        }

        Ok("".into())
    }

    pub fn token_policies(&self) -> Result<Vec<String>, RvError> {
        if let Some(auth) = &self.auth {
            if !auth.policies.is_empty() {
                return Ok(auth.policies.clone());
            }
        }

        if let Some(data) = self.data.get("policies") {
            if let Some(policies) = data.as_array() {
                return Ok(policies.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect());
            } else {
                return Err(rv_error_string!("token policies found but in the wrong format"));
            }
        }

        Ok(vec![])
    }

    pub fn token_ttl(&self) -> Result<u64, RvError> {
        if let Some(auth) = &self.auth {
            return Ok(auth.lease_duration);
        }

        if let Some(data) = self.data.get("ttl") {
            if let Some(ttl) = data.as_u64() {
                return Ok(ttl);
            } else {
                return Err(rv_error_string!("token ttl found but in the wrong format"));
            }
        }

        Ok(0)
    }

    pub fn token_metadata(&self) -> Result<HashMap<String, String>, RvError> {
        if let Some(auth) = &self.auth {
            if !auth.metadata.is_empty() {
                return Ok(auth.metadata.clone());
            }
        }

        if let Some(data) = self.data.get("metadata") {
            if let Some(metadata) = data.as_object() {
                return Ok(metadata.into_iter().map(|(k, v)| (k.to_string(), value_to_string(v))).collect());
            } else {
                return Err(rv_error_string!("token metadata found but in the wrong format"));
            }
        }

        if let Some(data) = self.data.get("meta") {
            if let Some(meta) = data.as_object() {
                return Ok(meta.into_iter().map(|(k, v)| (k.to_string(), value_to_string(v))).collect());
            } else {
                return Err(rv_error_string!("token meta found but in the wrong format"));
            }
        }

        Ok(HashMap::new())
    }
}

fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        _ => "".to_string(),
    }
}

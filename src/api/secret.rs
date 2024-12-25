use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub lease_duration: u32,
    #[serde(default)]
    pub renewable: bool,
}
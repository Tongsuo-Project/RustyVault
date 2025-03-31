use derive_more::Deref;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::{secret::SecretAuth, Client, HttpResponse};
use crate::{errors::RvError, http::sys::InitRequest};

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
pub struct MountOutput {
    #[serde(default)]
    pub uuid: String,
    #[serde(default, rename = "type")]
    pub logical_type: String,
    #[serde(default)]
    pub accessor: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub plugin_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthInput {
    #[serde(default)]
    pub path: String,
    #[serde(default, rename = "type")]
    pub logical_type: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub options: Map<String, Value>,
}

#[derive(Deref)]
pub struct Sys<'a> {
    #[deref]
    pub client: &'a Client,
}

impl Client {
    pub fn sys(&self) -> Sys {
        Sys { client: self }
    }
}

impl Sys<'_> {
    pub fn init(&self, init_req: &InitRequest) -> Result<HttpResponse, RvError> {
        let data = json!({
            "secret_shares": init_req.secret_shares,
            "secret_threshold": init_req.secret_threshold,
        });

        self.request_put("/v1/sys/init", data.as_object().cloned())
    }

    pub fn seal_status(&self) -> Result<HttpResponse, RvError> {
        self.request_read("/v1/sys/seal-status")
    }

    pub fn seal(&self) -> Result<HttpResponse, RvError> {
        self.request_put("/v1/sys/seal", None)
    }

    pub fn unseal(&self, key: &str) -> Result<HttpResponse, RvError> {
        let data = json!({
            "key": key,
        });

        self.request_put("/v1/sys/unseal", data.as_object().cloned())
    }

    pub fn list_auth(&self) -> Result<HttpResponse, RvError> {
        self.request_read("/v1/sys/auth")
    }

    pub fn enable_auth(&self, input: &AuthInput) -> Result<HttpResponse, RvError> {
        let data = serde_json::to_value(input)?;
        self.request_write(&format!("/v1/sys/auth/{}", &input.path), data.as_object().cloned())
    }

    pub fn disable_auth(&self, path: &str) -> Result<HttpResponse, RvError> {
        self.request_delete(&format!("/v1/sys/auth/{}", path), None)
    }

    pub fn remount(&self, from: &str, to: &str) -> Result<HttpResponse, RvError> {
        let data = json!({
            "from": from,
            "to": to,
        });

        self.request_write("/v1/sys/remount", data.as_object().cloned())
    }

    pub fn list_policy(&self) -> Result<HttpResponse, RvError> {
        self.request_read("/v1/sys/policies/acl")
    }

    pub fn read_policy(&self, name: &str) -> Result<HttpResponse, RvError> {
        self.request_read(&format!("/v1/sys/policies/acl/{}", name))
    }

    pub fn write_policy(&self, name: &str, policy: &str) -> Result<HttpResponse, RvError> {
        let data = json!({
            "policy": policy,
        });

        self.request_write(&format!("/v1/sys/policies/acl/{}", name), data.as_object().cloned())
    }

    pub fn delete_policy(&self, name: &str) -> Result<HttpResponse, RvError> {
        self.request_delete(&format!("/v1/sys/policies/acl/{}", name), None)
    }
}

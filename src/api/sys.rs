use derive_more::Deref;
use serde_json::json;

use super::{Client, HttpResponse};

use crate::{
    errors::RvError,
    http::sys::InitRequest,
};

#[derive(Deref)]
pub struct Sys<'a> {
    #[deref]
    pub client: &'a Client,
}

impl Client {
    pub fn sys(&self) -> Sys {
        Sys {
            client: self
        }
    }
}

impl Sys<'_> {
    pub fn init(&self, init_req: &InitRequest) -> Result<HttpResponse, RvError> {
        let data = json!({
            "secret_shares": init_req.secret_shares,
            "secret_threshold": init_req.secret_threshold,
        })
        .as_object()
        .unwrap()
        .clone();

        self.request_put("/v1/sys/init", Some(data))
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
        })
        .as_object()
        .unwrap()
        .clone();

        self.request_put("/v1/sys/unseal", Some(data))
    }
}

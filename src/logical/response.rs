use std::collections::HashMap;

use serde_json::{json, Map, Value};

use crate::logical::{secret::SecretData, Auth};

#[derive(Debug, Clone)]
pub struct Response {
    pub headers: Option<HashMap<String, String>>,
    pub data: Option<Map<String, Value>>,
    pub auth: Option<Auth>,
    pub secret: Option<SecretData>,
    pub redirect: String,
}

impl Default for Response {
    fn default() -> Self {
        Response { headers: None, data: None, auth: None, secret: None, redirect: String::new() }
    }
}

impl Response {
    pub fn new() -> Self {
        Self { ..Default::default() }
    }

    pub fn data_response(data: Option<Map<String, Value>>) -> Self {
        let mut resp = Response::new();
        resp.data = data;
        resp
    }

    pub fn list_response(keys: &[String]) -> Self {
        let value = serde_json::to_value(keys);
        let mut resp = Response::new();
        if value.is_ok() {
            resp.data = Some(
                json!({
                    "keys": value.unwrap(),
                })
                .as_object()
                .unwrap()
                .clone(),
            );
        }
        resp
    }

    pub fn help_response(text: &str, see_also: &[String]) -> Self {
        let value = serde_json::to_value(see_also);
        let mut resp = Response::new();
        if value.is_ok() {
            resp.data = Some(
                json!({
                    "help": text.to_string(),
                    "sea_also": value.unwrap(),
                })
                .as_object()
                .unwrap()
                .clone(),
            );
        }
        resp
    }

    pub fn error_response(text: &str) -> Self {
        let mut resp = Response::new();
        resp.data = Some(
            json!({
                "error": text.to_string(),
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        resp
    }
}

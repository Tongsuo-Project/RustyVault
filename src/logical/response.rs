use std::collections::HashMap;
use serde_json::{json, Value, Map};
use crate::logical::{secret::Secret};

pub struct Response {
    pub headers: Option<HashMap<String, String>>,
    pub data: Option<Map<String, Value>>,
    pub secret: Option<Secret>,
    pub redirect: String
}

impl Response {
    pub fn new() -> Self {
        Self {
            headers: None,
            data: None,
            secret: None,
            redirect: "".to_string(),
        }
    }

    pub fn list_response(keys: &[String]) -> Self {
        let value = serde_json::to_value(keys);
        let mut resp = Response::new();
        if value.is_ok() {
            resp.data = Some(json!({
                "keys": value.unwrap(),
            }).as_object().unwrap().clone());
            /*
            let mut data: Map<String, Value> = Map::new();
            data.insert("keys".to_string(), value.unwrap());
            resp.data = Some(data);
            */
        }
        resp
    }

    pub fn help_response(text: &str, see_also: &[String]) -> Self {
        let value = serde_json::to_value(see_also);
        let mut resp = Response::new();
        if value.is_ok() {
            resp.data = Some(json!({
                "help": text.to_string(),
                "sea_also": value.unwrap(),
            }).as_object().unwrap().clone());
            /*
            let mut data: HashMap<String, Value> = HashMap::new();
            data.insert("help".to_string(), Value::String(text.to_string()));
            data.insert("see_also".to_string(), value.unwrap());
            resp.data = Some(data);
            */
        }
        resp
    }

    pub fn error_response(text: &str) -> Self {
        let mut resp = Response::new();
        resp.data = Some(json!({
            "error": text.to_string(),
        }).as_object().unwrap().clone());
        /*
        let mut data = HashMap::new();
        data.insert("error".to_string(), Value::String(text.to_string()));
        resp.data = Some(data);
        */
        resp
    }
}


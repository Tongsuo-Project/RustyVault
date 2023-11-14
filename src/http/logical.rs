use std::{
    sync::{Arc, RwLock},
    collections::HashMap,
};
use actix_web::{
    http::{
        Method, StatusCode
    },
    web, HttpRequest, HttpResponse
};
use serde::{Serialize, Deserialize};
use serde_json::{Value};
use crate::{
    core::{Core},
    logical::{Operation, Request, Response},
    http::{
        Connection,
        response_error,
        response_ok,
        response_json_ok,
    },
    errors::RvError,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Auth {
    client_token: String,
    policies: Vec<String>,
    metadata: HashMap<String, String>,
    lease_duration: u64,
    renewable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LogicalResponse {
    renewable: bool,
    lease_id: String,
    lease_duration: u64,
    auth: Option<Auth>,
    data: HashMap<String, Value>,
}

impl Default for LogicalResponse {
    fn default() -> Self {
        Self {
            renewable: false,
            lease_id: String::new(),
            lease_duration: 0,
            auth: None,
            data: HashMap::new(),
        }
    }
}

async fn logical_request_handler(
    req: HttpRequest,
    body: web::Bytes,
    method: Method,
    path: web::Path<String>,
    core: web::Data<Arc<RwLock<Core>>>
) -> Result<HttpResponse, RvError> {
    let conn = req.conn_data::<Connection>().unwrap();
    log::debug!("logical request, connection info: {:?}, method: {:?}, path: {:?}", conn, method, path);

    let mut r = Request::default();
    r.path = path.into_inner();

    match method {
        Method::GET => {
            r.operation = Operation::Read;
        },
        Method::POST | Method::PUT => {
            r.operation = Operation::Write;
            if body.len() > 0 {
                let payload = serde_json::from_slice(&body)?;
                r.body = Some(payload);
            }
        },
        Method::DELETE => {
            r.operation = Operation::Delete;
        },
        other => {
            if other.as_str() != "LIST" {
                return Ok(response_error(StatusCode::METHOD_NOT_ALLOWED, ""));
            }
            r.operation = Operation::List;
        }
    }

    let core = core.read()?;
    let resp = core.handle_request(&mut r)?;

    println!("resp: {:?}", resp);
    if r.operation == Operation::Read && resp.is_none() {
        return Ok(response_error(StatusCode::NOT_FOUND, ""));
    }

    response_logical(&resp.unwrap())
}

fn response_logical(resp: &Response) -> Result<HttpResponse, RvError> {
    let mut logical_resp = LogicalResponse::default();

    if let Some(ref secret) = &resp.secret {
        logical_resp.lease_id = secret.lease_id.clone();
        logical_resp.renewable = secret.lease.renewable ;
        logical_resp.lease_duration = secret.lease.ttl.as_secs();
    }

    if let Some(ref data) = &resp.data {
        logical_resp.data = data
                            .iter()
                            .map(|(key, value)| (key.clone(), value.clone()))
                            .collect();

        return Ok(response_json_ok(logical_resp));
    }

    return Ok(response_ok(None));
}

pub fn init_logical_service(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/v1")
            .route("/{path:.*}", web::route().to(logical_request_handler))
    );
}

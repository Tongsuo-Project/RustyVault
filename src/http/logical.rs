use std::{
    sync::{Arc, RwLock},
    collections::HashMap,
    time::Duration,
};
use actix_web::{
    http::{
        Method, StatusCode
    },
    cookie::{
        Cookie,
        time::{OffsetDateTime}
    },
    web, HttpRequest, HttpResponse
};
use serde::{Serialize, Deserialize};
use serde_json::{Value};
use humantime::parse_duration;
use crate::{
    core::{Core},
    logical::{Operation, Response},
    http::{
        Connection,
        request_auth,
        response_error,
        response_ok,
        response_json_ok,
    },
    errors::RvError,
};
use super::AUTH_COOKIE_NAME;

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

    let mut r = request_auth(&req);
    r.path = path.into_inner().clone();

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

    if r.operation == Operation::Read && resp.is_none() {
        return Ok(response_error(StatusCode::NOT_FOUND, ""));
    }

    if resp.is_none() {
        return Ok(response_ok(None, None));
    }

    response_logical(&resp.unwrap(), &r.path)
}

fn response_logical(resp: &Response, path: &str) -> Result<HttpResponse, RvError> {
    let mut logical_resp = LogicalResponse::default();
    let mut cookie: Option<Cookie> = None;
    let mut no_content = true;

    if let Some(ref secret) = &resp.secret {
        logical_resp.lease_id = secret.lease_id.clone();
        logical_resp.renewable = secret.lease.renewable ;
        logical_resp.lease_duration = secret.lease.ttl.as_secs();
        no_content = false;
    }

    if let Some(ref auth) = &resp.auth {
        let mut expire_duration = parse_duration("365d")?;
        if logical_resp.lease_duration != 0 {
            expire_duration = Duration::from_secs(logical_resp.lease_duration);
        }

        if !path.starts_with("auth/token/") {
            let expire_time = OffsetDateTime::now_utc() + expire_duration;
            cookie = Some(Cookie::build(AUTH_COOKIE_NAME, &auth.client_token)
                .path("/")
                .expires(expire_time)
                .finish());
        }

        logical_resp.auth = Some(Auth {
            client_token: auth.client_token.clone(),
            policies: auth.policies.clone(),
            metadata: auth.metadata.clone(),
            lease_duration: auth.ttl.as_secs(),
            renewable: auth.renewable(),
        });

        no_content = false;
    }

    if let Some(ref data) = &resp.data {
        logical_resp.data = data
                            .iter()
                            .map(|(key, value)| (key.clone(), value.clone()))
                            .collect();

        no_content = false;
    }

    if no_content {
        return Ok(response_ok(cookie, None));
    } else {
        return Ok(response_json_ok(cookie, logical_resp));
    }
}

pub fn init_logical_service(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/v1")
            .route("/{path:.*}", web::route().to(logical_request_handler))
    );
}

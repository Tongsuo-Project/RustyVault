use std::{
    any::Any,
    net::SocketAddr,
    sync::{Arc, RwLock}
};
use actix_web::{
    dev::Extensions,
    rt::net::TcpStream,
    http::{
        StatusCode
    },
    web, HttpResponse, ResponseError
};
use serde::{Serialize};
use serde_json::{json, Map, Value};
use actix_tls::accept::openssl::TlsStream;
use openssl::{
    x509::{X509, X509Ref, X509VerifyResult},
//    ssl::{SslAcceptor, SslVerifyMode, SslFiletype, SslMethod}
};
use crate::{
    core::Core,
    logical::{Request},
    errors::RvError
};

pub mod sys;
pub mod logical;

#[derive(Debug, Clone)]
pub struct TlsClientInfo {
    pub client_cert_chain: Option<Vec<X509>>,
    pub client_verify_result: X509VerifyResult,
}

impl TlsClientInfo {
    pub fn new() -> Self {
        TlsClientInfo {
            client_cert_chain: None,
            client_verify_result: X509VerifyResult::OK,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Connection {
    pub bind: SocketAddr,
    pub peer: SocketAddr,
    pub ttl: Option<u32>,
    pub tls: Option<TlsClientInfo>,
}

impl Connection {
    pub fn new() -> Self {
        Self {
            bind: SocketAddr::from(([0, 0, 0, 0], 8080)),
            peer: SocketAddr::from(([127, 0, 0, 1], 8888)),
            ttl: None,
            tls: None,
        }
    }
}

pub fn request_on_connect_handler(conn: &dyn Any, ext: &mut Extensions) {
    if let Some(tls_stream) = conn.downcast_ref::<TlsStream<TcpStream>>() {
        let socket = tls_stream.get_ref();
        let mut cert_chain = None;

        if let Some(cert_stack) =  tls_stream.ssl().verified_chain() {
            let certs: Vec<X509> = cert_stack.iter().map(X509Ref::to_owned).collect();
            cert_chain = Some(certs);
        }

        ext.insert(Connection {
            bind: socket.local_addr().unwrap(),
            peer: socket.peer_addr().unwrap(),
            ttl: socket.ttl().ok(),
            tls: Some(TlsClientInfo {
                client_cert_chain: cert_chain,
                client_verify_result: tls_stream.ssl().verify_result(),
            }),
        });
    } else if let Some(socket) = conn.downcast_ref::<TcpStream>() {
        ext.insert(Connection {
            bind: socket.local_addr().unwrap(),
            peer: socket.peer_addr().unwrap(),
            ttl: socket.ttl().ok(),
            tls: None,
        });
    } else {
        unreachable!("socket should be TLS or plaintext");
    }
}

pub fn init_service(cfg: &mut web::ServiceConfig) {
    sys::init_sys_service(cfg);
    logical::init_logical_service(cfg);
}

impl ResponseError for RvError {
    // builds the actual response to send back when an error occurs
    fn error_response(&self) -> HttpResponse {
        let err_json = json!({ "error": self.to_string() });
        HttpResponse::InternalServerError().json(err_json)
    }
}

pub fn response_error(status: StatusCode, msg: &str) -> HttpResponse {
    if msg.len() == 0 {
        HttpResponse::build(status).finish()
    } else {
        let err_json = json!({ "error": msg.to_string() });
        HttpResponse::build(status).json(err_json)
    }
}

pub fn response_ok(body: Option<&Map<String, Value>>) -> HttpResponse {
    if body.is_none() {
        HttpResponse::NoContent().finish()
    } else {
        HttpResponse::Ok().json(body.as_ref().unwrap())
    }
}

pub fn response_json<T: Serialize>(status: StatusCode, body: T) -> HttpResponse {
    HttpResponse::build(status).json(body)
}

pub fn response_json_ok<T: Serialize>(body: T) -> HttpResponse {
    response_json(StatusCode::OK, body)
}

pub fn handle_request(
    core: web::Data<Arc<RwLock<Core>>>,
    req: &mut Request
) -> Result<HttpResponse, RvError> {
    let core = core.read()?;
    let resp = core.handle_request(req)?;
    if resp.is_none() {
        Ok(response_ok(None))
    } else {
        let data = resp.unwrap().data;
        if data.is_none() {
            Ok(response_ok(None))
        } else {
            Ok(response_ok(data.as_ref()))
        }
    }
}

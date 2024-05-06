use std::sync::{Arc, RwLock};

use actix_web::{http::StatusCode, web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    core::{Core, SealConfig},
    errors::RvError,
    http::{
        //Connection,
        handle_request,
        request_auth,
        response_error,
        response_json_ok,
        response_ok,
    },
    logical::Operation,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InitRequest {
    secret_shares: u8,
    secret_threshold: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitResponse {
    pub keys: Vec<String>,
    pub root_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UnsealRequest {
    key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealStatusResponse {
    pub sealed: bool,
    pub t: u8,
    pub n: u8,
    pub progress: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MountRequest {
    #[serde(rename = "type")]
    logical_type: String,
    #[serde(default)]
    description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RemountRequest {
    from: String,
    to: String,
}

fn response_seal_status(core: web::Data<Arc<RwLock<Core>>>) -> Result<HttpResponse, RvError> {
    let core = core.read()?;

    let progress = core.unseal_progress();
    let sealed = core.sealed();
    let seal_config = core.seal_config()?;

    let resp = SealStatusResponse { sealed, t: seal_config.secret_shares, n: seal_config.secret_threshold, progress };

    Ok(response_json_ok(None, resp))
}

async fn sys_init_get_request_handler(
    _req: HttpRequest,
    core: web::Data<Arc<RwLock<Core>>>,
) -> Result<HttpResponse, RvError> {
    //let conn = req.conn_data::<Connection>().unwrap();
    let core = core.read()?;
    let inited = core.inited()?;
    Ok(response_ok(
        None,
        Some(
            json!({
                "initialized": inited
            })
            .as_object()
            .unwrap(),
        ),
    ))
}

async fn sys_init_put_request_handler(
    _req: HttpRequest,
    mut body: web::Bytes,
    core: web::Data<Arc<RwLock<Core>>>,
) -> Result<HttpResponse, RvError> {
    let payload = serde_json::from_slice::<InitRequest>(&body)?;
    body.clear();
    let seal_config = SealConfig { secret_shares: payload.secret_shares, secret_threshold: payload.secret_threshold };

    let mut core = core.write()?;
    let result = core.init(&seal_config)?;

    let resp = InitResponse {
        keys: result.secret_shares.iter().map(|key| hex::encode(key)).collect(),
        root_token: result.root_token,
    };

    Ok(response_json_ok(None, resp))
}

async fn sys_seal_status_request_handler(
    _req: HttpRequest,
    core: web::Data<Arc<RwLock<Core>>>,
) -> Result<HttpResponse, RvError> {
    response_seal_status(core)
}

async fn sys_seal_request_handler(
    _req: HttpRequest,
    core: web::Data<Arc<RwLock<Core>>>,
) -> Result<HttpResponse, RvError> {
    let mut core = core.write()?;
    core.seal("")?;
    Ok(response_ok(None, None))
}

async fn sys_unseal_request_handler(
    _req: HttpRequest,
    mut body: web::Bytes,
    core: web::Data<Arc<RwLock<Core>>>,
) -> Result<HttpResponse, RvError> {
    // TODO
    let payload = serde_json::from_slice::<UnsealRequest>(&body)?;
    body.clear();
    let key = hex::decode(payload.key)?;

    {
        let mut core = core.write()?;
        let _result = core.unseal(&key)?;
    }

    response_seal_status(core)
}

async fn sys_list_mounts_request_handler(
    req: HttpRequest,
    core: web::Data<Arc<RwLock<Core>>>,
) -> Result<HttpResponse, RvError> {
    let mut r = request_auth(&req);
    r.path = "sys/mounts".to_string();
    r.operation = Operation::Read;

    handle_request(core, &mut r)
}

async fn sys_mount_request_handler(
    req: HttpRequest,
    path: web::Path<String>,
    mut body: web::Bytes,
    core: web::Data<Arc<RwLock<Core>>>,
) -> Result<HttpResponse, RvError> {
    let _test = serde_json::from_slice::<MountRequest>(&body)?;
    let payload = serde_json::from_slice(&body)?;
    body.clear();
    let mount_path = path.into_inner();
    if mount_path.len() == 0 {
        return Ok(response_error(StatusCode::NOT_FOUND, ""));
    }

    let mut r = request_auth(&req);
    r.path = "sys/mounts/".to_owned() + mount_path.as_str();
    r.operation = Operation::Write;
    r.body = Some(payload);

    handle_request(core, &mut r)
}

async fn sys_unmount_request_handler(
    req: HttpRequest,
    path: web::Path<String>,
    core: web::Data<Arc<RwLock<Core>>>,
) -> Result<HttpResponse, RvError> {
    let mount_path = path.into_inner();
    if mount_path.len() == 0 {
        return Ok(response_error(StatusCode::NOT_FOUND, ""));
    }

    let mut r = request_auth(&req);
    r.path = "sys/mounts/".to_owned() + mount_path.as_str();
    r.operation = Operation::Delete;

    handle_request(core, &mut r)
}

async fn sys_remount_request_handler(
    req: HttpRequest,
    mut body: web::Bytes,
    core: web::Data<Arc<RwLock<Core>>>,
) -> Result<HttpResponse, RvError> {
    let _test = serde_json::from_slice::<RemountRequest>(&body)?;
    let payload = serde_json::from_slice(&body)?;
    body.clear();

    let mut r = request_auth(&req);
    r.operation = Operation::Write;
    r.body = Some(payload);

    handle_request(core, &mut r)
}

async fn sys_list_auth_mounts_request_handler(
    req: HttpRequest,
    core: web::Data<Arc<RwLock<Core>>>,
) -> Result<HttpResponse, RvError> {
    let mut r = request_auth(&req);
    r.path = "sys/auth".to_string();
    r.operation = Operation::Read;

    handle_request(core, &mut r)
}

async fn sys_auth_enable_request_handler(
    req: HttpRequest,
    path: web::Path<String>,
    mut body: web::Bytes,
    core: web::Data<Arc<RwLock<Core>>>,
) -> Result<HttpResponse, RvError> {
    let _test = serde_json::from_slice::<MountRequest>(&body)?;
    let payload = serde_json::from_slice(&body)?;
    body.clear();
    let mount_path = path.into_inner();
    if mount_path.len() == 0 {
        return Ok(response_error(StatusCode::NOT_FOUND, ""));
    }

    let mut r = request_auth(&req);
    r.path = "sys/auth/".to_owned() + mount_path.as_str();
    r.operation = Operation::Write;
    r.body = Some(payload);

    handle_request(core, &mut r)
}

async fn sys_auth_disable_request_handler(
    req: HttpRequest,
    path: web::Path<String>,
    core: web::Data<Arc<RwLock<Core>>>,
) -> Result<HttpResponse, RvError> {
    let mount_path = path.into_inner();
    if mount_path.len() == 0 {
        return Ok(response_error(StatusCode::NOT_FOUND, ""));
    }

    let mut r = request_auth(&req);
    r.path = "sys/auth/".to_owned() + mount_path.as_str();
    r.operation = Operation::Delete;

    handle_request(core, &mut r)
}

pub fn init_sys_service(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/v1/sys")
            .service(
                web::resource("/init")
                    .route(web::get().to(sys_init_get_request_handler))
                    .route(web::post().to(sys_init_put_request_handler))
                    .route(web::put().to(sys_init_put_request_handler)),
            )
            .service(web::resource("/seal-status").route(web::get().to(sys_seal_status_request_handler)))
            .service(
                web::resource("/seal")
                    .route(web::post().to(sys_seal_request_handler))
                    .route(web::put().to(sys_seal_request_handler)),
            )
            .service(
                web::resource("/unseal")
                    .route(web::post().to(sys_unseal_request_handler))
                    .route(web::put().to(sys_unseal_request_handler)),
            )
            .service(web::resource("/mounts").route(web::get().to(sys_list_mounts_request_handler)))
            .service(
                web::resource("/mounts/{path:.*}")
                    .route(web::get().to(sys_list_mounts_request_handler))
                    .route(web::post().to(sys_mount_request_handler))
                    .route(web::delete().to(sys_unmount_request_handler)),
            )
            .service(
                web::resource("/remount")
                    .route(web::post().to(sys_remount_request_handler))
                    .route(web::put().to(sys_remount_request_handler)),
            )
            .service(web::resource("/auth").route(web::get().to(sys_list_auth_mounts_request_handler)))
            .service(
                web::resource("/auth/{path:.*}")
                    .route(web::get().to(sys_list_auth_mounts_request_handler))
                    .route(web::post().to(sys_auth_enable_request_handler))
                    .route(web::delete().to(sys_auth_disable_request_handler)),
            ),
    );
}

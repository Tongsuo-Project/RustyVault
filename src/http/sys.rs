use std::{
	sync::{Arc, RwLock}
};
use actix_web::{
	web, HttpRequest, HttpResponse
};
use serde::{Serialize, Deserialize};
use serde_json::{json};
use crate::{
	core::Core,
    http::{
        Connection,
        response_ok,
        //response_error,
    },
    errors::RvError,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct InitRequest {
    secret_shares: u32,
    secret_threshold: u32,
}

async fn sys_init_get_request_handler(
    _req: HttpRequest,
    core: web::Data<Arc<RwLock<Core>>>
) -> Result<HttpResponse, RvError> {
    //let conn = req.conn_data::<Connection>().unwrap();
    let core = core.read()?;
    let inited = core.inited()?;
    Ok(response_ok(Some(json!({
        "initialized": inited
    }).as_object().unwrap())))
}

async fn sys_init_put_request_handler(
    _req: HttpRequest,
    body: web::Bytes,
    _core: web::Data<Arc<RwLock<Core>>>
) -> Result<HttpResponse, RvError> {
    // TODO
    let payload = serde_json::from_slice::<InitRequest>(&body)?;
    let resp = Some(json!({
        "secret_shares": payload.secret_shares,
        "secret_threshold": payload.secret_threshold,
    }).as_object().unwrap().clone());

    Ok(response_ok(Some(resp.as_ref().unwrap())))
}

async fn sys_seal_status_request_handler(
    _req: HttpRequest,
    _core: web::Data<Arc<RwLock<Core>>>
) -> Result<HttpResponse, RvError> {
    // TODO
    Ok(HttpResponse::Ok().body("sys seal status\n"))
}

async fn sys_seal_request_handler(
    req: HttpRequest,
    _body: web::Bytes,
    _core: web::Data<Arc<RwLock<Core>>>
) -> Result<HttpResponse, RvError> {
    // TODO
    let _conn = req.conn_data::<Connection>().unwrap();
    Ok(HttpResponse::Ok().body("sys seal\n"))
}

async fn sys_unseal_request_handler(
    _req: HttpRequest,
    _body: web::Bytes,
    _core: web::Data<Arc<RwLock<Core>>>
) -> Result<HttpResponse, RvError> {
    // TODO
    Ok(HttpResponse::Ok().body("sys unseal\n"))
}

async fn sys_list_mounts_request_handler(
    _req: HttpRequest,
    _core: web::Data<Arc<RwLock<Core>>>
) -> Result<HttpResponse, RvError> {
    // TODO
    Ok(HttpResponse::Ok().body("sys list mounts\n"))
}

async fn sys_mount_request_handler(
    _req: HttpRequest,
    _core: web::Data<Arc<RwLock<Core>>>
) -> Result<HttpResponse, RvError> {
    // TODO
    Ok(HttpResponse::Ok().body("sys mount\n"))
}

async fn sys_unmount_request_handler(
    _req: HttpRequest,
    _body: web::Bytes,
    _core: web::Data<Arc<RwLock<Core>>>
) -> Result<HttpResponse, RvError> {
    // TODO
    Ok(HttpResponse::Ok().body("sys unmount\n"))
}

async fn sys_remount_request_handler(
    _req: HttpRequest,
    _body: web::Bytes,
    _core: web::Data<Arc<RwLock<Core>>>
) -> Result<HttpResponse, RvError> {
    // TODO
    Ok(HttpResponse::Ok().body("sys remount\n"))
}

pub fn init_sys_service(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/v1/sys")
            .service(web::resource("/init")
                         .route(web::get().to(sys_init_get_request_handler))
                         .route(web::put().to(sys_init_put_request_handler)))
            .service(web::resource("/seal-status")
                         .route(web::get().to(sys_seal_status_request_handler)))
            .service(web::resource("/seal")
                         .route(web::put().to(sys_seal_request_handler)))
            .service(web::resource("/unseal")
                         .route(web::put().to(sys_unseal_request_handler)))
            .service(web::resource("/mounts")
                         .route(web::get().to(sys_list_mounts_request_handler)))
            .service(web::resource("/mounts/{path:.*}")
                         .route(web::get().to(sys_mount_request_handler))
                         .route(web::post().to(sys_unmount_request_handler))
                         .route(web::delete().to(sys_unmount_request_handler)))
            .service(web::resource("/remount")
                         .route(web::post().to(sys_remount_request_handler))
                         .route(web::put().to(sys_remount_request_handler)))
    );
}

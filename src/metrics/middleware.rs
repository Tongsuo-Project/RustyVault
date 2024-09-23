use std::{sync::{Arc, RwLock}, time::Instant};

use actix_web::{
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    http::Method,
    middleware::Next,
    web::Data,
    Error,
};
use crate::metrics::http_metrics::HttpLabel;

use super::{http_metrics::MetricsMethod, manager::MetricsManager};

pub async fn metrics_midleware(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    let start_time = Instant::now();
    let path = req.path().to_string();
    let method = match *req.method() {
        Method::GET => MetricsMethod::GET,
        _ if req.method().to_string() == "LIST"  => MetricsMethod::LIST,
        Method::POST => MetricsMethod::POST,
        Method::PUT => MetricsMethod::PUT,
        Method::DELETE => MetricsMethod::DELETE,
        _ => MetricsMethod::OTHER,
    };

    let res = next.call(req).await?;

    let status = res.status().as_u16();
    let label = HttpLabel{path, method, status};
    if let Some(m) = res.request().app_data::<Data<Arc<RwLock<MetricsManager>>>>(){
        let metrics_manager = m.read().unwrap();
        metrics_manager.http_metrics.increment_request_count(&label);
        let duration = start_time.elapsed().as_secs_f64();
        metrics_manager.http_metrics.observe_duration(&label, duration);
    }

    Ok(res)
}

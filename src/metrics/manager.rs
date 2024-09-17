use crate::metrics::http_metrics::HttpMetrics;
use crate::metrics::system_metrics::SystemMetrics;
use prometheus_client::registry::Registry;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct MetricsManager {
    pub registry: Arc<Mutex<Registry>>,
    pub system_metrics: Arc<SystemMetrics>,
    pub http_metrics: Arc<HttpMetrics>,
}

impl MetricsManager {
    pub fn new() -> Self {
        let registry = Arc::new(Mutex::new(Registry::default()));
        let system_metrics = Arc::new(SystemMetrics::new(&mut registry.lock().unwrap()));
        let http_metrics = Arc::new(HttpMetrics::new(&mut registry.lock().unwrap()));
        MetricsManager { registry, system_metrics, http_metrics }
    }
}

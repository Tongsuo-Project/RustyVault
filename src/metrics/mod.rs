//! The `rusty_vault::metriccs` is a module that utilize Prometheus to capture system metrics defines 'backend' and relevant data
//! defines 'manager' and relevant data structures such as `SystemMetrics` and `HttpMetrics`
//!
//! The 'manager' holds the Prometheus registry
pub mod middleware;
pub mod manager;
pub mod system_metrics;
pub mod http_metrics;
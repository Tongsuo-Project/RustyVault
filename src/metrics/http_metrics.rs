use std::fmt::Write;

use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue, LabelValueEncoder};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::histogram::{linear_buckets, Histogram};
use prometheus_client::registry::Registry;

const HTTP_REQUEST_COUNT: &str = "http_request_count";
const HTTP_REQUEST_COUNT_HELP: &str = "Number of HTTP requests received, labeled by method and status";
const HTTP_REQUEST_DURATION_SECONDS: &str = "http_request_duration_seconds";
const HTTP_REQUEST_DURATION_SECONDS_HELP: &str = "Duration of HTTP requests, labeled by method and status";
    
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum MetricsMethod {
    GET,
    POST,
    PUT,
    DELETE,
    LIST,
    OTHER,
}

impl EncodeLabelValue for MetricsMethod {
    fn encode(&self, writer: &mut LabelValueEncoder<'_>) -> Result<(), std::fmt::Error> {
        match self {
            MetricsMethod::GET => writer.write_str("get"),
            MetricsMethod::POST => writer.write_str("post"),
            MetricsMethod::PUT => writer.write_str("put"),
            MetricsMethod::DELETE => writer.write_str("delete"),
            MetricsMethod::LIST => writer.write_str("list"),
            MetricsMethod::OTHER => writer.write_str("other"),
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct HttpLabel {
    pub path: String,
    pub method: MetricsMethod,
    pub status: u16,
}

#[derive(Clone)]
pub struct HttpMetrics {
    requests: Family<HttpLabel, Counter>,
    histogram: Family<HttpLabel, Histogram>,
}

impl HttpMetrics {
    pub fn new(registry: &mut Registry) -> Self {
        let requests = Family::<HttpLabel, Counter>::default();
        let histogram =
            Family::<HttpLabel, Histogram>::new_with_constructor(|| Histogram::new(linear_buckets(0.1, 0.1, 10)));

        registry.register(
            HTTP_REQUEST_COUNT,
            HTTP_REQUEST_COUNT_HELP,
            requests.clone(),
        );

        registry.register(
            HTTP_REQUEST_DURATION_SECONDS,
            HTTP_REQUEST_DURATION_SECONDS_HELP,
            histogram.clone(),
        );

        Self { requests, histogram }
    }

    pub fn increment_request_count(&self, label: &HttpLabel) {
        self.requests.get_or_create(label).inc();
    }

    pub fn observe_duration(&self, label: &HttpLabel, duration: f64) {
        self.histogram.get_or_create(label).observe(duration);
    }
}

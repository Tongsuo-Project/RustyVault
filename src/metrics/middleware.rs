use std::{
    sync::{Arc, RwLock},
    time::Instant,
};

use crate::metrics::http_metrics::HttpLabel;
use actix_web::{
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    http::Method,
    middleware::Next,
    web::Data,
    Error,
};

use super::{http_metrics::MetricsMethod, manager::MetricsManager};

pub async fn metrics_midleware(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    let start_time = Instant::now();
    let path = req.path().to_string();
    let method = match *req.method() {
        Method::GET => MetricsMethod::GET,
        _ if req.method().to_string() == "LIST" => MetricsMethod::LIST,
        Method::POST => MetricsMethod::POST,
        Method::PUT => MetricsMethod::PUT,
        Method::DELETE => MetricsMethod::DELETE,
        _ => MetricsMethod::OTHER,
    };

    let res = next.call(req).await?;

    let status = res.status().as_u16();
    let label = HttpLabel { path, method, status };
    if let Some(m) = res.request().app_data::<Data<Arc<RwLock<MetricsManager>>>>() {
        let metrics_manager = m.read().unwrap();
        metrics_manager.http_metrics.increment_request_count(&label);
        let duration = start_time.elapsed().as_secs_f64();
        metrics_manager.http_metrics.observe_duration(&label, duration);
    }

    Ok(res)
}

#[cfg(test)]
mod tests {
    use rand::Rng;
    use regex::Regex;
    use ureq::json;

    use crate::metrics::http_metrics::*;
    use crate::metrics::system_metrics::*;
    use crate::test_utils::TestHttpServer;
    use std::collections::HashMap;
    use std::thread;
    use std::time::Duration;

    const PATH: &str = "path";
    const METHOD: &str = "method";

    const GET: &str = "GET";
    const LIST: &str = "LIST";
    const POST: &str = "POST";
    const PUT: &str = "PUT";
    const DELETE: &str = "DELETE";

    static SYS_METRICS_MAP: &[(&str, &str)] = &[
        (CPU_USAGE_PERCENT, CPU_USAGE_PERCENT_HELP),
        (TOTAL_MEMORY, TOTAL_MEMORY_HELP),
        (USED_MEMORY, USED_MEMORY_HELP),
        (FREE_MEMORY, FREE_MEMORY_HELP),
        (TOTAL_DISK_SPACE, TOTAL_DISK_SPACE_HELP),
        (TOTAL_DISK_AVAILABLE, TOTAL_DISK_AVAILABLE_HELP),
        // (NETWORK_IN, NETWORK_IN_HELP),
        // (NETWORK_OUT, NETWORK_OUT_HELP),
        (LOAD_AVERAGE, LOAD_AVERAGE_HELP),
    ];

    static HTTP_METRICS_MAP: &[(&str, &str)] = &[
        (HTTP_REQUEST_COUNT, HTTP_REQUEST_COUNT_HELP),
        (HTTP_REQUEST_DURATION_SECONDS, HTTP_REQUEST_DURATION_SECONDS_HELP),
    ];

    fn parse_metrics_name_help(raw: &str) -> HashMap<String, String> {
        let mut metrics_map = HashMap::new();
        for line in raw.split('\n') {
            if line.starts_with("# HELP") {
                let line = line.trim_end_matches(".");
                // # PROPERTY METRIC_NAME METRIC_HELP
                // # HELP cpu_usage_percent CPU usage percent.
                let parts: Vec<&str> = line.split(" ").collect();
                let metric_name = parts[2].to_string();
                let metric_help = parts[3..].join(" ");
                metrics_map.insert(metric_name, metric_help);
            }
        }
        metrics_map
    }

    fn parse_gauge(raw: &str) -> HashMap<String, f64> {
        let mut gauge_map = HashMap::new();
        let lines: Vec<&str> = raw.split('\n').collect();
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i];
            if line.ends_with("gauge") {
                let parts: Vec<&str> = lines[i + 1].split(" ").collect();
                // println!("in parse_gauge {}:{}", parts[0], parts[1]);
                let metric_name = parts[0].to_string();
                let value: f64 = parts[1].parse().unwrap();
                gauge_map.insert(metric_name, value);
            }
            i += 1;
        }
        gauge_map
    }

    fn parse_counter(raw: &str) -> HashMap<String, HashMap<String, u32>> {
        let lines: Vec<&str> = raw.split('\n').collect();
        let mut i = 0;
        let mut counter_map: HashMap<String, HashMap<String, u32>> = HashMap::new();
        let name_label_re =
            Regex::new(r#"\bpath="(?P<path>[^"]+)",method="(?P<method>[^"]+)",status="(?P<status>[^"]+)""#).unwrap();

        while i < lines.len() {
            let line = lines[i];
            if line.ends_with("counter") {
                // move to next line, which is counter
                i += 1;
                let parts: Vec<&str> = lines[i].split("{").collect();
                let metric_name = parts[0];

                // capture following counter lines
                while lines[i].starts_with(metric_name) {
                    let parts: Vec<&str> = lines[i].split(" ").collect();
                    let name_label = parts[0];
                    let value: u32 = parts[1].parse().unwrap();

                    if let Some(caps) = name_label_re.captures(name_label) {
                        let path = caps[PATH].to_string();
                        let method = caps[METHOD].to_string().to_uppercase();
                        if let Some(req) = counter_map.get_mut(&path) {
                            req.insert(method, value);
                        } else {
                            let mut req: HashMap<String, u32> = HashMap::new();
                            req.insert(method, value);
                            println!("path:{}", &path);
                            counter_map.insert(path, req);
                        }
                    }

                    i += 1;
                }
            }
            i += 1;
        }
        counter_map
    }

    #[test]
    fn test_metrics_name_and_help_info() {
        let sys_metrics_map: HashMap<&str, &str> = SYS_METRICS_MAP.iter().cloned().collect();
        let http_metrics_map: HashMap<&str, &str> = HTTP_METRICS_MAP.iter().cloned().collect();

        let server = TestHttpServer::new_with_prometheus("test_metrics_name_and_help_info", false);
        let root_token = &server.root_token;
        let (status, resp) = server.request_prometheus("GET", "metrics", None, Some(&root_token), None).unwrap();
        assert_eq!(status, 200);

        let metrics_map = parse_metrics_name_help(resp["metrics"].as_str().unwrap());
        assert_eq!(sys_metrics_map.len() + http_metrics_map.len(), metrics_map.len());

        for (metric_name, metric_help) in &metrics_map {
            let name = metric_name.as_str();
            let help = metric_help.as_str();
            if sys_metrics_map.contains_key(name) {
                assert_eq!(sys_metrics_map.get(name), Some(&help));
            } else if http_metrics_map.contains_key(name) {
                assert_eq!(http_metrics_map.get(name), Some(&help));
            }
        }
    }

    #[test]
    fn test_sys_metrics() {
        let server = TestHttpServer::new_with_prometheus("test_sys_metrics", false);
        let root_token = &server.root_token;
        thread::sleep(Duration::from_secs(20));

        let (status, resp) = server.request_prometheus("GET", "metrics", None, Some(&root_token), None).unwrap();
        assert_eq!(status, 200);

        let gauge_map = parse_gauge(resp["metrics"].as_str().unwrap());
        assert_eq!(SYS_METRICS_MAP.len(), gauge_map.len());

        for (_, value) in gauge_map {
            assert!(value != 0.0);
        }
    }

    #[test]
    fn test_http_request() {
        let server = TestHttpServer::new_with_prometheus("test_http_request", false);
        let root_token = &server.root_token;

        let path = ["v1/secret/password-0", "v1/secret/password-1", "v1/secret/password-2", "v1/secret"];
        let mock = [
            vec![(DELETE, 2)],
            vec![(POST, 3), (GET, 5), (PUT, 7), (DELETE, 9)],
            vec![(POST, 2), (GET, 8), (PUT, 12), (DELETE, 16)],
            vec![(LIST, 1)],
        ];
        let mut mock_map: HashMap<&str, Vec<(&str, u32)>> = HashMap::new();
        for (p, m) in path.iter().zip(mock.iter()) {
            mock_map.insert(p, m.to_vec());
        }

        for (path, mock) in &mock_map {
            for request in mock {
                let method = request.0;
                let count = request.1;
                for _ in 0..count {
                    if method == "POST" || method == "PUT" {
                        let random_number: u32 = rand::thread_rng().gen_range(0..10000);
                        let data = json!({
                            "password": random_number,
                        })
                        .as_object()
                        .unwrap()
                        .clone();
                        let (_, _) = server.request(method, path, Some(data), Some(&root_token), None).unwrap();
                    } else {
                        let (_, _) = server.request(method, path, None, Some(&root_token), None).unwrap();
                    }
                }
            }
        }

        let (status, resp) = server.request_prometheus("GET", "metrics", None, Some(&root_token), None).unwrap();
        assert_eq!(status, 200);

        let counter_map = parse_counter(resp["metrics"].as_str().unwrap());
        println!("counter map len={}", counter_map.len());

        for (path, mock) in &mock_map {
            for mock_req in mock {
                let method = mock_req.0;
                let count = mock_req.1;
                let path = format!("/{}", path);
                assert!(counter_map.contains_key(&path));

                let prom = counter_map.get(&path).unwrap();
                assert!(prom.contains_key(method));

                let value = *prom.get(method).unwrap();
                assert_eq!(count, value);
            }
        }
    }
}

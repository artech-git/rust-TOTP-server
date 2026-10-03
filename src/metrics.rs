use std::sync::OnceLock;
use std::time::Instant;

use axum::{extract::MatchedPath, extract::Request, middleware::Next, response::Response};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Install the global Prometheus recorder once per process and return a
/// (cloneable) handle for rendering `/metrics`.
pub fn prometheus_handle() -> PrometheusHandle {
    HANDLE
        .get_or_init(|| {
            PrometheusBuilder::new()
                .set_buckets(&[
                    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
                ])
                .expect("histogram buckets are non-empty")
                .install_recorder()
                .expect("failed to install prometheus recorder")
        })
        .clone()
}

/// Axum middleware recording request counts and latency histograms, labeled
/// by method, matched route template, and status.
pub async fn track_http(req: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = req.method().to_string();
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| "unmatched".to_owned());

    let response = next.run(req).await;

    let status = response.status().as_u16().to_string();
    metrics::counter!(
        "http_requests_total",
        "method" => method.clone(), "path" => path.clone(), "status" => status.clone()
    )
    .increment(1);
    metrics::histogram!(
        "http_request_duration_seconds",
        "method" => method, "path" => path, "status" => status
    )
    .record(start.elapsed().as_secs_f64());

    response
}

/// Business-event counter (enrollments, logins, failures, lockouts…).
pub fn auth_event(event: &'static str, outcome: &'static str) {
    metrics::counter!("auth_events_total", "event" => event, "outcome" => outcome).increment(1);
}

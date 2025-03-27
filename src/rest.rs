use axum::{http::StatusCode, response::IntoResponse, routing::get, Router};
use prometheus::{Encoder, TextEncoder};
use tracing::error;

pub fn rest_endpoint_router() -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/health", get(health_handler))
}

/// Health check endpoint handler
async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

/// Prometheus metrics endpoint handler
async fn metrics_handler() -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();

    match encoder.encode_to_string(&metric_families) {
        Ok(metrics_text) => (
            StatusCode::OK,
            [("Content-Type", encoder.format_type())],
            metrics_text,
        )
            .into_response(),
        Err(e) => {
            error!("Error encoding metrics: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
        }
    }
}

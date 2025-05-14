// SPDX-License-Identifier: BSD-3-Clause-LBNL
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use axum_extra::extract::Form;
use chrono::{DateTime, Duration, Utc};
use prometheus::{Encoder, TextEncoder}; // For exposing Prometheus metrics
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::sync::Arc;
use tonic::{Request as TonicRequest, Response as TonicResponse, Status};
use tracing::error;

// Application-specific imports
use crate::api::service::LoadBalancerService;
use crate::metrics::INBOUND_REST;
use crate::proto::loadbalancer::v1::{
    AddSendersRequest, CreateTokenRequest, DeregisterRequest, FreeLoadBalancerRequest,
    GetLoadBalancerRequest, ListChildTokensRequest, ListTokenPermissionsRequest,
    LoadBalancerStatusRequest, OverviewRequest, RegisterRequest, RemoveSendersRequest,
    ReserveLoadBalancerRequest, RevokeTokenRequest, SendStateRequest, TimeseriesRequest,
    TokenPermission, TokenSelector, VersionRequest,
};

// Embeds file content directly into the binary at compile time.
const INDEX_HTML: &str = include_str!("../../frontend/index.html");
const STYLE_CSS: &str = include_str!("../../frontend/style.css");
const APP_JS: &str = include_str!("../../frontend/app.js");

type AppState = Arc<LoadBalancerService>;

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    code: u16,
}

/// Extracts the Bearer token from the Authorization header.
fn extract_token(headers: &HeaderMap) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let auth_header = headers.get(header::AUTHORIZATION).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Missing authorization token".to_string(),
                code: StatusCode::UNAUTHORIZED.as_u16(),
            }),
        )
    })?;
    let auth_str = auth_header.to_str().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid authorization token format".to_string(),
                code: StatusCode::BAD_REQUEST.as_u16(),
            }),
        )
    })?;
    match auth_str.strip_prefix("Bearer ") {
        Some(token) => Ok(token.to_owned()),
        None => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid token format: missing Bearer prefix".to_string(),
                code: StatusCode::BAD_REQUEST.as_u16(),
            }),
        )),
    }
}

/// Converts a gRPC `tonic::Status` into an Axum HTTP error response tuple.
fn status_to_response(status: Status) -> (StatusCode, Json<ErrorResponse>) {
    let code = match status.code() {
        tonic::Code::Ok => StatusCode::INTERNAL_SERVER_ERROR,
        tonic::Code::Cancelled => StatusCode::BAD_REQUEST,
        tonic::Code::Unknown => StatusCode::INTERNAL_SERVER_ERROR,
        tonic::Code::InvalidArgument => StatusCode::BAD_REQUEST,
        tonic::Code::DeadlineExceeded => StatusCode::REQUEST_TIMEOUT,
        tonic::Code::NotFound => StatusCode::NOT_FOUND,
        tonic::Code::AlreadyExists => StatusCode::CONFLICT,
        tonic::Code::PermissionDenied => StatusCode::FORBIDDEN,
        tonic::Code::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
        tonic::Code::FailedPrecondition => StatusCode::BAD_REQUEST,
        tonic::Code::Aborted => StatusCode::CONFLICT,
        tonic::Code::OutOfRange => StatusCode::BAD_REQUEST,
        tonic::Code::Unimplemented => StatusCode::NOT_IMPLEMENTED,
        tonic::Code::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        tonic::Code::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        tonic::Code::DataLoss => StatusCode::INTERNAL_SERVER_ERROR,
        tonic::Code::Unauthenticated => StatusCode::UNAUTHORIZED,
    };
    error!("gRPC Error: {} - {}", status.code(), status.message());
    (
        code,
        Json(ErrorResponse {
            error: status.message().to_string(),
            code: code.as_u16(),
        }),
    )
}

/// Creates a `tonic::Request` and injects the authorization token into its metadata.
fn create_request<T>(
    headers: &HeaderMap,
    inner: T,
) -> Result<TonicRequest<T>, (StatusCode, Json<ErrorResponse>)> {
    let token = extract_token(headers)?;
    let mut request = TonicRequest::new(inner);
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token).parse().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to parse token for metadata".to_string(),
                    code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                }),
            )
        })?,
    );
    Ok(request)
}

/// Generic helper function to handle API requests that expect a JSON response body on success.
async fn grpc_to_rest<F, Fut, Req, Rep>(
    headers: HeaderMap,
    service: AppState,
    request_payload: Req,
    handler_fn: F,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)>
where
    F: FnOnce(AppState, TonicRequest<Req>) -> Fut,
    Fut: Future<Output = Result<TonicResponse<Rep>, Status>>,
    Rep: Serialize,
{
    INBOUND_REST.inc();
    let request = create_request(&headers, request_payload)?;
    match handler_fn(service, request).await {
        Ok(response) => {
            let reply = response.into_inner();
            match serde_json::to_value(reply) {
                Ok(json_value) => Ok(Json(json_value)),
                Err(e) => {
                    error!("Failed to serialize response to JSON: {}", e);
                    Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: "Failed to serialize response".to_string(),
                            code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                        }),
                    ))
                }
            }
        }
        Err(status) => Err(status_to_response(status)),
    }
}

/// Generic helper function to handle API requests that return only a status code on success.
async fn grpc_status_only_to_rest<F, Fut, Req, Rep>(
    headers: HeaderMap,
    service: AppState,
    request_payload: Req,
    handler_fn: F,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)>
where
    F: FnOnce(AppState, TonicRequest<Req>) -> Fut,
    Fut: Future<Output = Result<TonicResponse<Rep>, Status>>,
{
    INBOUND_REST.inc();
    let request = create_request(&headers, request_payload)?;
    match handler_fn(service, request).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(status) => Err(status_to_response(status)),
    }
}

// --- Frontend Handlers ---

async fn serve_index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn serve_css() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/css")
        .body(STYLE_CSS.into())
        .unwrap()
}

async fn serve_js() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/javascript")
        .body(APP_JS.into())
        .unwrap()
}

/// Query parameters for the timeseries endpoint
#[derive(Deserialize)]
struct TimeseriesQuery {
    series: Option<Vec<String>>,
    since: Option<String>,
    // format: Option<String>,
    // wide: Option<bool>,
}

pub fn rest_endpoint_router(service: AppState) -> Router {
    let api_router = Router::new()
        .route("/version", get(version_handler))
        .route("/overview", get(overview_handler))
        .route("/lb", post(reserve_load_balancer_handler))
        .route("/lb/{id}", get(get_load_balancer_handler))
        .route("/lb/{id}/status", get(load_balancer_status_handler))
        .route("/lb/{id}", delete(free_load_balancer_handler))
        .route("/lb/{id}/senders", post(add_senders_handler))
        .route("/lb/{id}/senders", delete(remove_senders_handler))
        .route("/lb/{id}/sessions", post(register_handler))
        .route("/sessions/{session_id}", delete(deregister_handler))
        .route("/sessions/{session_id}/state", post(send_state_handler))
        .route("/tokens", post(create_token_handler))
        .route(
            "/tokens/{token_id}/permissions",
            get(list_token_permissions_handler),
        )
        .route(
            "/tokens/{token_id}/children",
            get(list_child_tokens_handler),
        )
        .route("/tokens/{token_id}", delete(revoke_token_handler))
        .route("/timeseries", get(timeseries_handler))
        .route("/timeseries/{*path}", get(timeseries_path_handler));

    Router::new()
        .fallback(serve_index)
        .route("/", get(serve_index))
        .route("/style.css", get(serve_css))
        .route("/app.js", get(serve_js))
        .route("/metrics", get(metrics_handler))
        .nest("/api/v1", api_router)
        .with_state(service)
}

async fn metrics_handler() -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    match encoder.encode_to_string(&metric_families) {
        Ok(metrics_text) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, encoder.format_type())],
            metrics_text,
        )
            .into_response(),
        Err(e) => {
            error!("Error encoding metrics: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
        }
    }
}

async fn version_handler(
    headers: HeaderMap,
    State(service): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    grpc_to_rest(headers, service, VersionRequest {}, |svc, req| async move {
        svc.handle_version(req).await
    })
    .await
}

async fn overview_handler(
    headers: HeaderMap,
    State(service): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    grpc_to_rest(
        headers,
        service,
        OverviewRequest {},
        |svc, req| async move { svc.handle_overview(req).await },
    )
    .await
}

#[derive(Deserialize)]
struct ReserveLoadBalancerBody {
    name: String,
    until: Option<String>,
    sender_addresses: Vec<String>,
}

async fn reserve_load_balancer_handler(
    headers: HeaderMap,
    State(service): State<AppState>,
    Json(body): Json<ReserveLoadBalancerBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let until_timestamp = match body.until {
        Some(ts_str) => match chrono::DateTime::parse_from_rfc3339(&ts_str) {
            Ok(dt) => Some(prost_wkt_types::Timestamp {
                seconds: dt.timestamp(),
                nanos: dt.timestamp_subsec_nanos() as i32,
            }),
            Err(e) => {
                error!("Invalid timestamp format for 'until': {}", e);
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!("Invalid timestamp format for 'until': {}", e),
                        code: StatusCode::BAD_REQUEST.as_u16(),
                    }),
                ));
            }
        },
        None => None,
    };
    let request_payload = ReserveLoadBalancerRequest {
        name: body.name,
        until: until_timestamp,
        sender_addresses: body.sender_addresses,
    };
    grpc_to_rest(headers, service, request_payload, |svc, req| async move {
        svc.handle_reserve_load_balancer(req).await
    })
    .await
}

async fn get_load_balancer_handler(
    headers: HeaderMap,
    Path(id): Path<String>,
    State(service): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    grpc_to_rest(
        headers,
        service,
        GetLoadBalancerRequest { lb_id: id },
        |svc, req| async move { svc.handle_get_load_balancer(req).await },
    )
    .await
}

async fn load_balancer_status_handler(
    headers: HeaderMap,
    Path(id): Path<String>,
    State(service): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    grpc_to_rest(
        headers,
        service,
        LoadBalancerStatusRequest { lb_id: id },
        |svc, req| async move { svc.handle_load_balancer_status(req).await },
    )
    .await
}

async fn free_load_balancer_handler(
    headers: HeaderMap,
    Path(id): Path<String>,
    State(service): State<AppState>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    grpc_status_only_to_rest(
        headers,
        service,
        FreeLoadBalancerRequest { lb_id: id },
        |svc, req| async move { svc.handle_free_load_balancer(req).await },
    )
    .await
}

#[derive(Deserialize)]
struct SenderAddressesBody {
    sender_addresses: Vec<String>,
}

async fn add_senders_handler(
    headers: HeaderMap,
    Path(id): Path<String>,
    State(service): State<AppState>,
    Json(body): Json<SenderAddressesBody>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    grpc_status_only_to_rest(
        headers,
        service,
        AddSendersRequest {
            lb_id: id,
            sender_addresses: body.sender_addresses,
        },
        |svc, req| async move { svc.handle_add_senders(req).await },
    )
    .await
}

async fn remove_senders_handler(
    headers: HeaderMap,
    Path(id): Path<String>,
    State(service): State<AppState>,
    Json(body): Json<SenderAddressesBody>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    grpc_status_only_to_rest(
        headers,
        service,
        RemoveSendersRequest {
            lb_id: id,
            sender_addresses: body.sender_addresses,
        },
        |svc, req| async move { svc.handle_remove_senders(req).await },
    )
    .await
}

#[derive(Deserialize)]
struct RegisterBody {
    name: String,
    weight: f32,
    ip_address: String,
    udp_port: u32,
    port_range: i32,
    min_factor: f32,
    max_factor: f32,
    keep_lb_header: bool,
}

async fn register_handler(
    headers: HeaderMap,
    Path(id): Path<String>,
    State(service): State<AppState>,
    Json(body): Json<RegisterBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    grpc_to_rest(
        headers,
        service,
        RegisterRequest {
            lb_id: id,
            name: body.name,
            weight: body.weight,
            ip_address: body.ip_address,
            udp_port: body.udp_port,
            port_range: body.port_range,
            min_factor: body.min_factor,
            max_factor: body.max_factor,
            keep_lb_header: body.keep_lb_header,
        },
        |svc, req| async move { svc.handle_register(req).await },
    )
    .await
}

async fn deregister_handler(
    headers: HeaderMap,
    Path(session_id): Path<String>,
    State(service): State<AppState>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    grpc_status_only_to_rest(
        headers,
        service,
        DeregisterRequest {
            session_id,
            lb_id: String::new(),
        },
        |svc, req| async move { svc.handle_deregister(req).await },
    )
    .await
}

#[derive(Deserialize)]
struct SendStateBody {
    lb_id: String,
    timestamp: Option<String>,
    fill_percent: f32,
    control_signal: f32,
    is_ready: bool,
    total_events_recv: i64,
    total_events_reassembled: i64,
    total_events_reassembly_err: i64,
    total_events_dequeued: i64,
    total_event_enqueue_err: i64,
    total_bytes_recv: i64,
    total_packets_recv: i64,
}

async fn send_state_handler(
    headers: HeaderMap,
    Path(session_id): Path<String>,
    State(service): State<AppState>,
    Json(body): Json<SendStateBody>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let timestamp = match body.timestamp {
        Some(ts_str) => match chrono::DateTime::parse_from_rfc3339(&ts_str) {
            Ok(dt) => Some(prost_wkt_types::Timestamp {
                seconds: dt.timestamp(),
                nanos: dt.timestamp_subsec_nanos() as i32,
            }),
            Err(e) => {
                error!("Invalid timestamp format for state update: {}", e);
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!("Invalid timestamp format for state update: {}", e),
                        code: StatusCode::BAD_REQUEST.as_u16(),
                    }),
                ));
            }
        },
        None => None,
    };
    grpc_status_only_to_rest(
        headers,
        service,
        SendStateRequest {
            session_id,
            lb_id: body.lb_id,
            timestamp,
            fill_percent: body.fill_percent,
            control_signal: body.control_signal,
            is_ready: body.is_ready,
            total_events_recv: body.total_events_recv,
            total_events_reassembled: body.total_events_reassembled,
            total_events_reassembly_err: body.total_events_reassembly_err,
            total_events_dequeued: body.total_events_dequeued,
            total_event_enqueue_err: body.total_event_enqueue_err,
            total_bytes_recv: body.total_bytes_recv,
            total_packets_recv: body.total_packets_recv,
        },
        |svc, req| async move { svc.handle_send_state(req).await },
    )
    .await
}

#[derive(Deserialize, Serialize, Clone)]
struct TokenPermissionBody {
    resource_type: i32,
    resource_id: String,
    permission: i32,
}

#[derive(Deserialize)]
struct CreateTokenBody {
    name: String,
    permissions: Vec<TokenPermissionBody>,
}

async fn create_token_handler(
    headers: HeaderMap,
    State(service): State<AppState>,
    Json(body): Json<CreateTokenBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let permissions = body
        .permissions
        .into_iter()
        .map(|p| TokenPermission {
            resource_type: p.resource_type,
            resource_id: p.resource_id,
            permission: p.permission,
        })
        .collect();
    let request_payload = CreateTokenRequest {
        name: body.name,
        permissions,
    };
    grpc_to_rest(headers, service, request_payload, |svc, req| async move {
        svc.handle_create_token(req).await
    })
    .await
}

fn parse_token_selector(token_id_param: &str) -> Option<TokenSelector> {
    if token_id_param.eq_ignore_ascii_case("self") {
        None
    } else {
        match token_id_param.parse::<u32>() {
            Ok(numeric_id) => Some(TokenSelector {
                token_selector: Some(
                    crate::proto::loadbalancer::v1::token_selector::TokenSelector::Id(numeric_id),
                ),
            }),
            Err(_) => Some(TokenSelector {
                token_selector: Some(
                    crate::proto::loadbalancer::v1::token_selector::TokenSelector::Token(
                        token_id_param.to_string(),
                    ),
                ),
            }),
        }
    }
}

async fn list_token_permissions_handler(
    headers: HeaderMap,
    Path(token_id): Path<String>,
    State(service): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let selector = parse_token_selector(&token_id);
    grpc_to_rest(
        headers,
        service,
        ListTokenPermissionsRequest { target: selector },
        |svc, req| async move { svc.handle_list_token_permissions(req).await },
    )
    .await
}

async fn list_child_tokens_handler(
    headers: HeaderMap,
    Path(token_id): Path<String>,
    State(service): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let selector = parse_token_selector(&token_id);
    grpc_to_rest(
        headers,
        service,
        ListChildTokensRequest { target: selector },
        |svc, req| async move { svc.handle_list_child_tokens(req).await },
    )
    .await
}

async fn revoke_token_handler(
    headers: HeaderMap,
    Path(token_id): Path<String>,
    State(service): State<AppState>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let selector = parse_token_selector(&token_id);
    grpc_status_only_to_rest(
        headers,
        service,
        RevokeTokenRequest { target: selector },
        |svc, req| async move { svc.handle_revoke_token(req).await },
    )
    .await
}

async fn timeseries_handler(
    headers: HeaderMap,
    State(service): State<AppState>,
    Form(params): Form<TimeseriesQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let series_selector = params.series.unwrap_or_default();
    let since = match params.since {
        Some(ts_str) => match DateTime::parse_from_rfc3339(&ts_str) {
            Ok(dt) => dt.with_timezone(&Utc),
            Err(e) => {
                error!("Invalid timestamp format for 'since': {}", e);
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!("Invalid timestamp format for 'since': {}", e),
                        code: StatusCode::BAD_REQUEST.as_u16(),
                    }),
                ));
            }
        },
        None => Utc::now() - Duration::minutes(1),
    };
    grpc_to_rest(
        headers,
        service,
        TimeseriesRequest {
            series_selector,
            since: Some(prost_wkt_types::Timestamp::from(since)),
        },
        |svc, req| async move { svc.handle_timeseries(req).await },
    )
    .await
}

async fn timeseries_path_handler(
    headers: HeaderMap,
    Path(path): Path<String>,
    State(service): State<AppState>,
    Form(params): Form<TimeseriesQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let normalized_path = if !path.starts_with('/') {
        format!("/{}", path)
    } else {
        path
    };
    let series_selector = vec![normalized_path];
    let since = match params.since {
        Some(ts_str) => match DateTime::parse_from_rfc3339(&ts_str) {
            Ok(dt) => dt.with_timezone(&Utc),
            Err(e) => {
                error!("Invalid timestamp format for 'since': {}", e);
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!("Invalid timestamp format for 'since': {}", e),
                        code: StatusCode::BAD_REQUEST.as_u16(),
                    }),
                ));
            }
        },
        None => Utc::now() - Duration::minutes(1),
    };
    grpc_to_rest(
        headers,
        service,
        TimeseriesRequest {
            series_selector,
            since: Some(prost_wkt_types::Timestamp::from(since)),
        },
        |svc, req| async move { svc.handle_timeseries(req).await },
    )
    .await
}

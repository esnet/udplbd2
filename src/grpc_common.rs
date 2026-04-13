// SPDX-License-Identifier: BSD-3-Clause-LBNL
//! Shared gRPC utilities for SmartNIC clients

use std::future::Future;
use std::path::PathBuf;
use tonic::{
    service::Interceptor,
    transport::{Certificate, Channel, ClientTlsConfig},
    Request, Status, Streaming,
};
use tracing::{debug, info, warn};

/// Bearer token interceptor for gRPC requests
#[derive(Clone)]
pub struct BearerTokenInterceptor {
    token: String,
}

impl BearerTokenInterceptor {
    /// Create a new bearer token interceptor
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }
}

impl Interceptor for BearerTokenInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let token = format!("Bearer {}", self.token);
        request.metadata_mut().insert(
            "authorization",
            token
                .parse()
                .map_err(|_| Status::invalid_argument("Invalid authorization header value"))?,
        );
        Ok(request)
    }
}

/// Create a gRPC channel with optional TLS configuration
///
/// # Arguments
///
/// * `addr` - The server address (e.g., "https://example.com:50051")
/// * `verify` - Whether to verify the TLS certificate
/// * `ca_file` - Optional path to a CA certificate file
/// * `service_name` - Service name for logging (e.g., "sn-p4", "sn-cfg")
///
/// # Returns
///
/// A configured tonic Channel ready for use
///
/// # Errors
///
/// Returns a tonic transport error if channel creation or TLS configuration fails
pub async fn create_grpc_channel(
    addr: &str,
    verify: bool,
    ca_file: Option<PathBuf>,
    service_name: &str,
) -> Result<Channel, tonic::transport::Error> {
    let mut channel = Channel::from_shared(addr.to_string()).unwrap();

    if addr.starts_with("https://") {
        let tls_config: ClientTlsConfig;
        if let Some(ca_file) = ca_file {
            let ca_file_str = ca_file.to_string_lossy();
            info!(
                "{} client for {addr} only trusting configured CA in {ca_file_str}",
                service_name
            );

            let pem = std::fs::read_to_string(&ca_file).expect("Failed to read CA certificate");
            let cert = Certificate::from_pem(pem);
            tls_config = ClientTlsConfig::new().ca_certificate(cert);
        } else {
            debug!(
                "{} client for {addr} has no ca cert provided, trusting system root CAs",
                service_name
            );
            tls_config = ClientTlsConfig::new().with_enabled_roots();
        }

        if !verify {
            warn!(
                "{} client for {addr} has TLS verification disabled (not recommended for production)",
                service_name
            );
        }

        channel = channel.tls_config(tls_config)?;
    }

    channel.connect().await
}

/// Increment the SMARTNIC_GRPC counter, invoke `call`, increment
/// SMARTNIC_GRPC_ERRORS on failure, then collect all streamed responses
/// through the provided `map` closure (returning `None` drops the item).
///
/// This eliminates the ~15-line boilerplate repeated in every streaming
/// gRPC method on `SNP4Client` and `SNCfgClient`.
pub async fn stream_collect<Req, Resp, Item, F, Fut, M>(
    method_name: &str,
    request: Request<Req>,
    call: F,
    mut map: M,
) -> Result<Vec<Item>, Status>
where
    F: FnOnce(Request<Req>) -> Fut,
    Fut: Future<Output = Result<tonic::Response<Streaming<Resp>>, Status>>,
    M: FnMut(Resp) -> Option<Item>,
{
    crate::metrics::SMARTNIC_GRPC
        .with_label_values(&[method_name])
        .inc();

    let mut stream = call(request)
        .await
        .inspect_err(|_| {
            crate::metrics::SMARTNIC_GRPC_ERRORS
                .with_label_values(&[method_name])
                .inc();
        })?
        .into_inner();

    let mut items = Vec::new();
    while let Some(response) = stream.message().await? {
        if let Some(item) = map(response) {
            items.push(item);
        }
    }

    Ok(items)
}

/// Run a set of futures concurrently with `join_all`, then return either
/// `Ok(Vec<T>)` if all succeeded or `Err(Vec<Result<T, Status>>)` preserving
/// per-client results for the caller to inspect.
///
/// Callers collect the futures themselves via `clients.iter_mut().map(...)`:
///
/// ```rust,ignore
/// let futures: Vec<_> = self.clients.iter_mut().map(|c| c.method()).collect();
/// fan_out(futures).await
/// ```
///
/// This eliminates the ~13-line boilerplate repeated in every method on
/// `MultiSNP4Client` and `MultiSNCfgClient`.
pub async fn fan_out<T, Fut>(
    futures: Vec<Fut>,
) -> Result<Vec<T>, Vec<Result<T, Status>>>
where
    Fut: Future<Output = Result<T, Status>>,
{
    let results: Vec<Result<T, Status>> = futures::future::join_all(futures).await;

    if results.iter().all(|r| r.is_ok()) {
        Ok(results.into_iter().map(Result::unwrap).collect())
    } else {
        Err(results)
    }
}

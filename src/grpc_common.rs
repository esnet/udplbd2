// SPDX-License-Identifier: BSD-3-Clause-LBNL
//! Shared gRPC utilities for SmartNIC clients

use std::path::PathBuf;
use tonic::{
    service::Interceptor,
    transport::{Certificate, Channel, ClientTlsConfig},
    Request, Status,
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

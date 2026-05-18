// SPDX-License-Identifier: BSD-3-Clause-LBNL
pub mod api;
pub mod config;
pub mod constants;
pub mod dataplane;
pub mod db;
pub mod errors;
pub mod grpc_common;
pub mod healthcheck;
pub mod macaddr;
pub mod metrics;
pub mod proto;
pub mod reservation;
pub mod sncfg;
pub mod snp4;
pub mod util;

use crate::snp4::metrics_collector::start_metrics_collector;

use api::fix_connect_info;
use chrono::Utc;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{error, info, trace, warn};

use axum::{routing::any_service, Router};
use axum_server::tls_rustls::RustlsConfig;
use futures::future::try_join_all;
use std::net::SocketAddr;

use crate::api::rest::rest_endpoint_router;
use crate::api::service::LoadBalancerService;
use crate::config::{parse_duration, Config};
use crate::dataplane::mock::MockDataplane;
use crate::db::LoadBalancerDB;
use crate::errors::{Error, Result};
use crate::proto::loadbalancer::v1::load_balancer_server::LoadBalancerServer;
use crate::reservation::ReservationManager;
use crate::sncfg::client::{MultiSNCfgClient, SNCfgClient};
use crate::sncfg::setup::smallest_mac_address;
use crate::snp4::client::{MultiSNP4Client, SNP4Client};
use crate::reservation::upstream::start_upstream_send_state;

/// Build SNCfg clients from the configuration
pub async fn build_sncfg_clients(config: &Config) -> Result<MultiSNCfgClient> {
    let mut sncfg_clients = Vec::new();
    for smartnic in &config.smartnic {
        if !smartnic.mock {
            if let Some(cfg_auth_token) = &smartnic.cfg_auth_token {
                let addr = format!(
                    "{}://{}:{}",
                    if smartnic.tls.enable { "https" } else { "http" },
                    if let Some(cfg_host) = &smartnic.cfg_host {
                        cfg_host
                    } else {
                        &smartnic.host
                    },
                    if let Some(cfg_port) = smartnic.cfg_port {
                        cfg_port
                    } else {
                        smartnic.port
                    }
                );
                let client = SNCfgClient::new(
                    &addr,
                    0,
                    smartnic.tls.verify,
                    smartnic.tls.ca_file.clone(),
                    cfg_auth_token.clone(),
                )
                .await?;
                sncfg_clients.push(client);
            }
        }
    }
    Ok(MultiSNCfgClient::new(sncfg_clients))
}

/// Build SNP4 clients from the configuration with optional table index
pub async fn build_snp4_clients(
    config: &Config,
    snp4_client_table_index: i32,
) -> Result<MultiSNP4Client> {
    let mut snp4_clients = Vec::new();
    for smartnic in &config.smartnic {
        if !smartnic.mock {
            let addr = format!(
                "{}://{}:{}",
                if smartnic.tls.enable { "https" } else { "http" },
                smartnic.host,
                smartnic.port
            );
            let mut client = SNP4Client::new(
                &addr,
                0,
                snp4_client_table_index,
                smartnic.tls.verify,
                smartnic.tls.ca_file.clone(),
                smartnic.auth_token.clone(),
            )
            .await?;
            client.clear_table_repeats = smartnic.clear_table_repeats;
            snp4_clients.push(client);
        }
    }
    Ok(MultiSNP4Client::new(snp4_clients))
}

async fn build_smartnic_clients(
    config: &mut Config,
    snp4_client_table_index: i32,
) -> Result<(MultiSNP4Client, MultiSNCfgClient)> {
    let snp4_clients = build_snp4_clients(config, snp4_client_table_index).await?;
    let sncfg_clients = build_sncfg_clients(config).await?;

    Ok((snp4_clients, sncfg_clients))
}

pub async fn apply_static_config(
    config: &mut Config,
    reservation_file: std::path::PathBuf,
    apply: bool,
) -> Result<()> {
    let reservation = crate::reservation::static_reservation::StaticReservation::load_from_file(
        &reservation_file,
    )
    .await?;
    let rules = reservation.generate_rules(config).await?;

    if apply {
        let (mut smartnic_clients, _) = build_smartnic_clients(config, 0).await?;
        reservation
            .apply_rules(&mut smartnic_clients, config)
            .await?;
    } else {
        for rule in rules {
            println!("table_add {rule}");
        }
    }

    Ok(())
}

fn build_server_futures(
    db: Arc<LoadBalancerDB>,
    manager_arc: Arc<Mutex<ReservationManager>>,
    config: &Config,
    mock_mode: bool,
) -> Vec<impl std::future::Future<Output = Result<()>>> {
    let config_arc = Arc::new(config.clone());
    let mut server_futures = Vec::new();
    for addr in config.server.listen.iter() {
        let lb_service = LoadBalancerService::new(
            db.clone(),
            manager_arc.clone(),
            config_arc.clone(),
            mock_mode,
        );
        let http_lb_service = LoadBalancerService::new(
            db.clone(),
            manager_arc.clone(),
            config_arc.clone(),
            mock_mode,
        );
        let svc = LoadBalancerServer::new(lb_service);

        // gRPC route: direct, no custom service
        let grpc_path = format!(
            "/{}/{{*grpc_service}}",
            <LoadBalancerServer<LoadBalancerService> as tonic::server::NamedService>::NAME
        );
        let grpc_router = Router::new().route(&grpc_path, any_service(svc));

        // REST router
        let rest_router = if config.rest.enable {
            rest_endpoint_router(Arc::new(http_lb_service))
        } else {
            Router::new()
        };

        // Compose: gRPC route takes precedence, REST is fallback
        let app = grpc_router
            .fallback_service(rest_router)
            .layer(axum::middleware::from_fn_with_state(*addr, fix_connect_info));

        let tls_config = config.server.tls.clone();
        let server_future = serve_with_optional_tls(*addr, app, tls_config);
        server_futures.push(server_future);
    }
    server_futures
}

pub async fn start_server(config: &mut Config) -> Result<()> {
    metrics::init_metrics();

    let (mut smartnic_clients, mut cfg_clients) = build_smartnic_clients(config, -1).await?;

    if config.lb.mac_unicast.is_none() {
        if let Some(mac_addr) = smallest_mac_address(&mut cfg_clients).await? {
            let mac_addr_str = mac_addr.to_string();
            info!("configured unicast mac addr via sn-cfg: {mac_addr_str}");
            config.lb.mac_unicast = Some(mac_addr_str);
        } else {
            panic!("sn-cfg returned no mac addresses and lb.mac_unicast was not configured");
        }
    }

    let db = Arc::new(LoadBalancerDB::with_config(config).await?);

    let cleanup_interval = parse_duration(&config.database.cleanup_interval)
        .map_err(|e| Error::Config(format!("Invalid cleanup interval: {e}")))?;
    let cleanup_age = parse_duration(&config.database.cleanup_age)
        .map_err(|e| Error::Config(format!("Invalid cleanup age: {e}")))?;
    let db_cleanup = db.clone();
    tokio::spawn(async move {
        loop {
            let cutoff = Utc::now() - chrono::Duration::from_std(cleanup_age).unwrap();
            if let Err(e) = db_cleanup.cleanup_soft_deleted(cutoff).await {
                error!("failed to cleanup soft deleted records: {}", e);
            }
            tokio::time::sleep(cleanup_interval).await;
        }
    });

    // Start SmartNIC P4 pipeline metrics collector if enabled
    let metrics_collector_config = config.get_metrics_collector_config();
    if metrics_collector_config.enabled {
        start_metrics_collector(
            db.clone(),
            smartnic_clients.clone(),
            metrics_collector_config,
        );
    }

    let reservations = db.list_reservations().await?;
    let mut is_empty = false;
    if reservations.is_empty() {
        if smartnic_clients.clear_tables().await.is_err() {
            return Err(Error::NotInitialized("failed to clear tables".into()));
        } else {
            is_empty = true;
            info!("no active reservations - clearing tables")
        }
    }

    // Find first IPv4 and first IPv6 address in config.server.listen
    let sync_addr_v4 = config.server.listen.iter().find(|a| a.is_ipv4()).cloned();
    let sync_addr_v6 = config.server.listen.iter().find(|a| a.is_ipv6()).cloned();

    let mut manager = ReservationManager::new(
        db.clone(),
        smartnic_clients,
        cfg_clients,
        config.get_controller_duration()?,
        config.get_controller_offset()?,
        config
            .lb
            .mac_unicast
            .as_ref()
            .expect("no unicast mac address configured")
            .parse()?,
        sync_addr_v4,
        sync_addr_v6,
    );
    manager.initialize(is_empty).await?;
    let manager_arc = Arc::new(Mutex::new(manager));

    // Start upstream SendState background task
    start_upstream_send_state(db.clone());

    let server_futures = build_server_futures(db.clone(), manager_arc.clone(), config, false);

    try_join_all(server_futures).await?;

    Ok(())
}

/// Spawn a background task that watches TLS certificate and key files for changes,
/// automatically reloading the TLS configuration when files are modified.
///
/// This enables zero-downtime certificate rotation (e.g., from certbot, Kubernetes
/// secrets, or manual renewal). The watcher monitors the parent directories of the
/// cert and key files to handle atomic file replacements (symlink swaps, rename-over).
///
/// A 2-second debounce window is used to coalesce rapid successive writes that
/// commonly occur during certificate renewal (cert + key written separately).
fn spawn_cert_watcher(
    rustls_config: RustlsConfig,
    cert_path: PathBuf,
    key_path: PathBuf,
) {
    use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
    use std::sync::mpsc;

    // Debounce duration: wait for writes to settle before reloading.
    // Certificate renewal tools often write cert and key files separately,
    // so we coalesce events within this window.
    const DEBOUNCE: Duration = Duration::from_secs(2);

    tokio::spawn(async move {
        let (tx, rx) = mpsc::channel();

        let cert_canonical = std::fs::canonicalize(&cert_path).unwrap_or_else(|_| cert_path.clone());
        let key_canonical = std::fs::canonicalize(&key_path).unwrap_or_else(|_| key_path.clone());

        // Watch parent directories so we catch atomic replacements (symlink swaps, rename-over)
        let cert_dir = cert_canonical.parent().unwrap_or(&cert_canonical).to_path_buf();
        let key_dir = key_canonical.parent().unwrap_or(&key_canonical).to_path_buf();

        let mut watcher = match RecommendedWatcher::new(tx, Config::default()) {
            Ok(w) => w,
            Err(e) => {
                error!("failed to create certificate file watcher: {e}");
                return;
            }
        };

        if let Err(e) = watcher.watch(&cert_dir, RecursiveMode::NonRecursive) {
            error!("failed to watch certificate directory {}: {e}", cert_dir.display());
            return;
        }
        // Only watch key_dir separately if it differs from cert_dir
        if key_dir != cert_dir {
            if let Err(e) = watcher.watch(&key_dir, RecursiveMode::NonRecursive) {
                error!("failed to watch key directory {}: {e}", key_dir.display());
                return;
            }
        }

        info!(
            "watching TLS certificate files for changes: cert={}, key={}",
            cert_path.display(),
            key_path.display()
        );

        // Block on a synchronous mpsc receiver in a dedicated blocking thread,
        // forwarding relevant events to the async runtime for reload.
        let cert_path_reload = cert_path.clone();
        let key_path_reload = key_path.clone();
        let cert_canonical_check = cert_canonical.clone();
        let key_canonical_check = key_canonical.clone();

        // Use a blocking task to receive filesystem events from the synchronous channel.
        // This keeps the watcher alive for the lifetime of the server.
        tokio::task::spawn_blocking(move || {
            let mut last_reload = std::time::Instant::now() - DEBOUNCE;

            loop {
                match rx.recv() {
                    Ok(Ok(event)) => {
                        // Only react to create/modify events, which cover:
                        // - Direct file writes (Modify)
                        // - Atomic replacements via rename (Create)
                        // - Symlink target changes (Create)
                        let dominated_by_cert_or_key = event.paths.iter().any(|p| {
                            let canonical = std::fs::canonicalize(p).unwrap_or_else(|_| p.clone());
                            canonical == cert_canonical_check || canonical == key_canonical_check
                        });

                        let is_relevant = matches!(
                            event.kind,
                            EventKind::Create(_) | EventKind::Modify(_)
                        ) && dominated_by_cert_or_key;

                        if is_relevant {
                            let now = std::time::Instant::now();
                            if now.duration_since(last_reload) < DEBOUNCE {
                                continue;
                            }
                            last_reload = now;

                            // Small delay to let both files finish writing
                            std::thread::sleep(Duration::from_millis(500));

                            info!("TLS certificate file change detected, reloading certificates");

                            let config = rustls_config.clone();
                            let cert = cert_path_reload.clone();
                            let key = key_path_reload.clone();

                            // Perform the async reload on the tokio runtime
                            tokio::runtime::Handle::current().spawn(async move {
                                match config.reload_from_pem_file(&cert, &key).await {
                                    Ok(()) => info!(
                                        "TLS certificates reloaded successfully from cert={}, key={}",
                                        cert.display(),
                                        key.display()
                                    ),
                                    Err(e) => error!(
                                        "failed to reload TLS certificates: {e} \
                                         (server continues with previous certificates)"
                                    ),
                                }
                            });
                        }
                    }
                    Ok(Err(e)) => {
                        warn!("certificate file watcher error: {e}");
                    }
                    Err(_) => {
                        // Channel closed — watcher was dropped
                        info!("certificate file watcher stopped");
                        break;
                    }
                }
            }
        });

        // Keep the watcher alive by holding it in this task.
        // The _watcher variable is moved into this future and kept alive.
        // We use a future that never resolves to keep the task (and watcher) alive.
        let _watcher = watcher;
        futures::future::pending::<()>().await;
    });
}

// Helper function to serve with or without TLS, used by both main and mock servers
async fn serve_with_optional_tls(
    addr: SocketAddr,
    app: Router,
    tls_config: crate::config::TlsConfig,
) -> Result<()> {
    if tls_config.enable {
        let cert_path = tls_config
            .cert_file
            .ok_or_else(|| Error::Config("TLS enabled but cert_file missing".to_string()))?;
        let key_path = tls_config
            .key_file
            .ok_or_else(|| Error::Config("TLS enabled but key_file missing".to_string()))?;
        let config = RustlsConfig::from_pem_file(&cert_path, &key_path)
            .await
            .map_err(|e| Error::Config(format!("Failed to load TLS config: {e}")))?;

        // Spawn a background watcher to automatically reload certificates when they change on disk
        spawn_cert_watcher(config.clone(), cert_path, key_path);

        info!("axum server with tls starting: https://{}", addr);
        axum_server::bind_rustls(addr, config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .map_err(|e| Error::Config(format!("axum serve error: {e}")))?;
    } else {
        info!("axum server starting: http://{}", addr);
        axum_server::bind(addr)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?
    }
    Ok(())
}

pub async fn start_mocked_server(
    config: &mut Config,
    db_path: Option<std::path::PathBuf>,
) -> Result<()> {
    metrics::init_metrics();

    let mut sim_config = config.clone();

    if sim_config.lb.mac_unicast.is_none() {
        sim_config.lb.mac_unicast = Some("02:00:DE:CA:FB:AD".to_string())
    }
    sim_config.server.allow_loopback = true;

    if let Some(path) = db_path {
        sim_config.database.file = path;
        sim_config.database.archive_dir = None;
    }
    let db = Arc::new(LoadBalancerDB::with_config(&sim_config).await?);

    let cleanup_interval = parse_duration(&config.database.cleanup_interval)
        .map_err(|e| Error::Config(format!("Invalid cleanup interval: {e}")))?;
    let cleanup_age = parse_duration(&config.database.cleanup_age)
        .map_err(|e| Error::Config(format!("Invalid cleanup age: {e}")))?;
    let db_cleanup = db.clone();
    tokio::spawn(async move {
        loop {
            let cutoff = Utc::now() - chrono::Duration::from_std(cleanup_age).unwrap();
            if let Err(e) = db_cleanup.cleanup_soft_deleted(cutoff).await {
                error!("failed to cleanup soft deleted records: {}", e);
            }
            tokio::time::sleep(cleanup_interval).await;
        }
    });

    let sim_dataplane = if let Some(ref mock_config) = config.mock {
        MockDataplane::with_address_map(mock_config.address_map.clone())
    } else {
        MockDataplane::new()
    };
    let sim_service =
        crate::proto::smartnic::p4_v2::smartnic_p4_server::SmartnicP4Server::new(sim_dataplane);
    tokio::spawn(async move {
        let addr: SocketAddr = "127.0.0.1:50051".parse().unwrap();
        info!("simulated dataplane gRPC server listening on {}", addr);
        tonic::transport::Server::builder()
            .add_service(sim_service)
            .serve(addr)
            .await
            .expect("Failed to start simulated dataplane gRPC server");
    });
    sleep(Duration::from_millis(10)).await;

    let sim_client = SNP4Client::new("http://127.0.0.1:50051", 0, -1, false, None, "").await?;

    trace!("created client");

    // Find first IPv4 and first IPv6 address in config.server.listen
    let sync_addr_v4 = sim_config
        .server
        .listen
        .iter()
        .find(|a| a.is_ipv4())
        .cloned();
    let sync_addr_v6 = sim_config
        .server
        .listen
        .iter()
        .find(|a| a.is_ipv6())
        .cloned();

    let mut manager = ReservationManager::new(
        db.clone(),
        MultiSNP4Client::new(vec![sim_client]),
        MultiSNCfgClient::new(vec![]),
        sim_config.get_controller_duration()?,
        sim_config.get_controller_offset()?,
        sim_config
            .lb
            .mac_unicast
            .as_ref()
            .unwrap_or(&"02:00:DE:CA:FB:AD".to_string())
            .parse()?,
        sync_addr_v4,
        sync_addr_v6,
    );

    trace!("created rules manager");

    manager.initialize(true).await?;
    let manager_arc = Arc::new(Mutex::new(manager));

    trace!("initialized rules manager");

    // Start upstream SendState background task
    start_upstream_send_state(db.clone());

    let server_futures = build_server_futures(db.clone(), manager_arc.clone(), &sim_config, true);

    try_join_all(server_futures).await?;

    Ok(())
}

#[cfg(test)]
mod tls_reload_tests {
    use super::*;
    use crate::api::client::BearerInterceptor;
    use crate::proto::loadbalancer::v1::load_balancer_client::LoadBalancerClient;
    use crate::proto::loadbalancer::v1::VersionRequest;
    use std::process::Command;
    use tonic::transport::{Certificate, Channel, ClientTlsConfig};

    /// Generate a self-signed X.509v3 certificate and private key using `openssl` CLI.
    /// Returns (cert_pem, key_pem) as byte vectors.
    fn generate_self_signed_cert(cn: &str) -> (Vec<u8>, Vec<u8>) {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        let ext_path = dir.path().join("ext.cnf");

        // Write a minimal extensions file to produce X.509v3 certs (required by rustls).
        // LibreSSL/OpenSSL default to v1 without -extensions.
        std::fs::write(
            &ext_path,
            format!(
                "[req]\n\
                 distinguished_name = dn\n\
                 x509_extensions = v3\n\
                 prompt = no\n\
                 [dn]\n\
                 CN = {cn}\n\
                 [v3]\n\
                 subjectAltName = DNS:{cn}\n\
                 basicConstraints = CA:FALSE\n"
            ),
        )
        .expect("failed to write openssl config");

        let status = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key_path.to_str().unwrap(),
                "-out",
                cert_path.to_str().unwrap(),
                "-days",
                "1",
                "-nodes",
                "-config",
                ext_path.to_str().unwrap(),
            ])
            .output()
            .expect("failed to run openssl");
        assert!(
            status.status.success(),
            "openssl failed: {}",
            String::from_utf8_lossy(&status.stderr)
        );

        let cert = std::fs::read(&cert_path).expect("failed to read cert");
        let key = std::fs::read(&key_path).expect("failed to read key");
        (cert, key)
    }

    /// Create a gRPC client channel that trusts the given CA certificate PEM.
    /// Uses `domain_name` for SNI (must match the server cert's SAN).
    async fn make_tls_channel(
        addr: &str,
        ca_pem: &[u8],
        domain_name: &str,
    ) -> std::result::Result<Channel, tonic::transport::Error> {
        let ca = Certificate::from_pem(ca_pem);
        let tls = ClientTlsConfig::new()
            .ca_certificate(ca)
            .domain_name(domain_name);
        Channel::from_shared(addr.to_string())
            .unwrap()
            .tls_config(tls)
            .unwrap()
            .connect()
            .await
    }

    /// Make a Version() gRPC call on a new channel trusting the given CA cert.
    /// Returns Ok(()) on success, Err on connection or RPC failure.
    async fn version_call_with_cert(
        addr: &str,
        ca_pem: &[u8],
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let channel = make_tls_channel(addr, ca_pem, "localhost").await?;
        let interceptor = BearerInterceptor {
            token: "test".to_string(),
        };
        let mut client = LoadBalancerClient::with_interceptor(channel, interceptor);
        let reply = client.version(VersionRequest {}).await?;
        assert!(
            !reply.get_ref().commit.is_empty(),
            "Version reply should contain a commit string"
        );
        Ok(())
    }

    /// End-to-end test for automatic TLS certificate reloading.
    ///
    /// Uses a single mock server instance to verify all behaviors sequentially:
    /// 1. Server starts with cert A — gRPC client trusting A connects successfully.
    /// 2. Invalid cert data is written — server continues serving with cert A.
    /// 3. Cert B is written — server reloads and serves cert B.
    /// 4. Client trusting only cert A can no longer connect (proving B is served).
    #[tokio::test(flavor = "multi_thread")]
    async fn cert_reload_end_to_end() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Generate two distinct certificates (same SAN=localhost, different keys)
        let (cert_a, key_a) = generate_self_signed_cert("localhost");
        let (cert_b, key_b) = generate_self_signed_cert("localhost");
        assert_ne!(cert_a, cert_b, "Generated certificates should differ");

        // Write cert A to the files the server will use
        let tls_dir = tempfile::tempdir().expect("failed to create temp dir");
        let cert_path = tls_dir.path().join("server.crt");
        let key_path = tls_dir.path().join("server.key");
        std::fs::write(&cert_path, &cert_a).unwrap();
        std::fs::write(&key_path, &key_a).unwrap();

        let port = 19621u16;
        let listen_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let db_path = format!("/tmp/udplbd-tls-reload-test-{port}.db");
        let _ = std::fs::remove_file(&db_path);

        // Start the mock server with TLS enabled
        let cert_path_clone = cert_path.clone();
        let key_path_clone = key_path.clone();
        let db_path_clone = db_path.clone();
        tokio::spawn(async move {
            let mut config = config::Config::turmoil();
            config.server.listen = vec![listen_addr];
            config.server.tls = config::TlsConfig {
                enable: true,
                cert_file: Some(cert_path_clone),
                key_file: Some(key_path_clone),
            };
            config.database.file = std::path::PathBuf::from(db_path_clone);
            config.database.archive_dir = None;
            if let Err(e) = start_mocked_server(&mut config, None).await {
                eprintln!("mock server error: {e:?}");
            }
        });

        // Wait for the server to accept connections
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(10);
        let mut ready = false;
        while start.elapsed() < timeout {
            if tokio::net::TcpStream::connect(listen_addr).await.is_ok() {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(ready, "Timed out waiting for TLS server on {listen_addr}");

        let addr = format!("https://127.0.0.1:{port}");

        // --- Phase 1: Verify server works with cert A ---
        version_call_with_cert(&addr, &cert_a)
            .await
            .expect("Version() with cert A should succeed");

        // --- Phase 2: Write invalid certs, verify server keeps cert A ---
        std::fs::write(&cert_path, b"not a valid certificate").unwrap();
        std::fs::write(&key_path, b"not a valid key").unwrap();

        // Wait for the watcher to attempt (and fail) the reload
        tokio::time::sleep(Duration::from_secs(5)).await;

        version_call_with_cert(&addr, &cert_a)
            .await
            .expect("Version() with cert A should still work after invalid cert reload");

        // --- Phase 3: Write cert B, verify server reloads to cert B ---
        std::fs::write(&cert_path, &cert_b).unwrap();
        std::fs::write(&key_path, &key_b).unwrap();

        // Wait for the file watcher to reload (2s debounce + 0.5s settle + margin)
        tokio::time::sleep(Duration::from_secs(5)).await;

        version_call_with_cert(&addr, &cert_b)
            .await
            .expect("Version() with cert B should succeed after reload");

        // --- Phase 4: Verify cert A is no longer served ---
        let stale = make_tls_channel(&addr, &cert_a, "localhost").await;
        assert!(
            stale.is_err(),
            "Connection trusting only cert A should fail after server reloaded to cert B"
        );

        let _ = std::fs::remove_file(&db_path);
    }
}

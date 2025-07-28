// SPDX-License-Identifier: BSD-3-Clause-LBNL
pub mod api;
pub mod config;
pub mod constants;
pub mod dataplane;
pub mod db;
pub mod errors;
pub mod macaddr;
pub mod metrics;
pub mod proto;
pub mod reservation;
pub mod sncfg;
pub mod snp4;
pub mod util;

use api::fix_connect_info;
use chrono::Utc;
use config::LoadBalancerInstanceConfig;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{error, info, trace};

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
use crate::sncfg::setup::auto_configure_smartnics;
use crate::snp4::client::{MultiSNP4Client, SNP4Client};

pub async fn apply_static_config(
    config: &Config,
    reservation_file: std::path::PathBuf,
    apply: bool,
) -> Result<()> {
    let reservation = crate::reservation::static_reservation::StaticReservation::load_from_file(
        &reservation_file,
    )
    .await?;
    let rules = reservation.generate_rules(config).await?;

    if apply {
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
                    0,
                    smartnic.tls.verify,
                    smartnic.auth_token.clone(),
                )
                .await?;
                client.clear_table_repeats = smartnic.clear_table_repeats;
                snp4_clients.push(client);
            }
        }
        let mut smartnic_clients = MultiSNP4Client::new(snp4_clients);

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

pub async fn start_server(config: Config) -> Result<()> {
    metrics::init_metrics();

    let db = Arc::new(LoadBalancerDB::with_config(&config).await?);

    let cleanup_interval = parse_duration(&config.database.cleanup_interval)
        .map_err(|e| Error::Config(format!("Invalid cleanup interval: {}", e)))?;
    let cleanup_age = parse_duration(&config.database.cleanup_age)
        .map_err(|e| Error::Config(format!("Invalid cleanup age: {}", e)))?;
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

    let mut snp4_clients = Vec::new();
    let mut sncfg_clients = Vec::new();
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
                -1,
                smartnic.tls.verify,
                smartnic.auth_token.clone(),
            )
            .await?;
            client.clear_table_repeats = smartnic.clear_table_repeats;
            snp4_clients.push(client);

            if let (Some(cfg_host), Some(cfg_port), Some(cfg_auth_token)) = (
                &smartnic.cfg_host,
                smartnic.cfg_port,
                &smartnic.cfg_auth_token,
            ) {
                let addr = format!(
                    "{}://{}:{}",
                    if smartnic.tls.enable { "https" } else { "http" },
                    cfg_host,
                    cfg_port
                );
                let client =
                    SNCfgClient::new(&addr, 0, smartnic.tls.verify, cfg_auth_token.clone()).await?;
                sncfg_clients.push(client);
            }
        }
    }
    let mut smartnic_clients = MultiSNP4Client::new(snp4_clients);
    let mut cfg_clients = MultiSNCfgClient::new(sncfg_clients);

    auto_configure_smartnics(&mut cfg_clients).await?;

    let reservations = db.list_reservations().await?;
    if reservations.is_empty() {
        if smartnic_clients.clear_tables().await.is_err() {
            return Err(Error::NotInitialized("failed to clear tables".into()));
        } else {
            info!("no active reservations - clearing tables")
        }
    }

    // Find first IPv4 and first IPv6 address in config.server.listen
    let sync_addr_v4 = config.server.listen.iter().find(|a| a.is_ipv4()).cloned();
    let sync_addr_v6 = config.server.listen.iter().find(|a| a.is_ipv6()).cloned();

    let mut manager = ReservationManager::new(
        db.clone(),
        smartnic_clients,
        config.get_controller_duration()?,
        config.get_controller_offset()?,
        config.lb.mac_unicast.parse()?,
        sync_addr_v4,
        sync_addr_v6,
    );
    manager.initialize().await?;
    let manager_arc = Arc::new(Mutex::new(manager));

    let mut server_futures = Vec::new();

    for addr in &config.server.listen {
        let lb_service = LoadBalancerService::new(db.clone(), manager_arc.clone());
        let http_lb_service = LoadBalancerService::new(db.clone(), manager_arc.clone());
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
            .layer(axum::middleware::from_fn(fix_connect_info));

        let addr = *addr;
        let tls_config = config.server.tls.clone();
        let server_future = serve_with_optional_tls(addr, app, tls_config);
        server_futures.push(server_future);
    }

    try_join_all(server_futures).await?;

    Ok(())
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
        let config = RustlsConfig::from_pem_file(cert_path, key_path)
            .await
            .map_err(|e| Error::Config(format!("Failed to load TLS config: {e}")))?;
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
    config: Config,
    db_path: Option<std::path::PathBuf>,
) -> Result<()> {
    metrics::init_metrics();

    let mut sim_config = config.clone();
    sim_config.lb.instances = vec![LoadBalancerInstanceConfig {
        ipv4: Some("127.0.0.1".parse().unwrap()),
        ipv6: Some("::1".parse().unwrap()),
        event_number_port: config.lb.instances[0].event_number_port,
    }];

    if let Some(path) = db_path {
        sim_config.database.file = path;
        sim_config.database.archive_dir = None;
    }
    let db = Arc::new(LoadBalancerDB::with_config(&sim_config).await?);

    let cleanup_interval = parse_duration(&config.database.cleanup_interval)
        .map_err(|e| Error::Config(format!("Invalid cleanup interval: {}", e)))?;
    let cleanup_age = parse_duration(&config.database.cleanup_age)
        .map_err(|e| Error::Config(format!("Invalid cleanup age: {}", e)))?;
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

    let sim_dataplane = MockDataplane::new();
    let sim_addr = format!("http://127.0.0.1:{}", 50051);
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

    let sim_client = SNP4Client::new(&sim_addr, 0, -1, false, "").await?;

    trace!("created client");

    // Find first IPv4 and first IPv6 address in config.server.listen
    let sync_addr_v4 = config.server.listen.iter().find(|a| a.is_ipv4()).cloned();
    let sync_addr_v6 = config.server.listen.iter().find(|a| a.is_ipv6()).cloned();

    let mut manager = ReservationManager::new(
        db.clone(),
        MultiSNP4Client::new(vec![sim_client]),
        config.get_controller_duration()?,
        config.get_controller_offset()?,
        config.lb.mac_unicast.parse()?,
        sync_addr_v4,
        sync_addr_v6,
    );

    trace!("created rules manager");

    manager.initialize().await?;
    let manager_arc = Arc::new(Mutex::new(manager));

    trace!("initialized rules manager");

    let mut server_futures = Vec::new();

    for addr in &config.server.listen {
        let lb_service = LoadBalancerService::new(db.clone(), manager_arc.clone());
        let http_lb_service = LoadBalancerService::new(db.clone(), manager_arc.clone());
        let svc = LoadBalancerServer::new(lb_service);

        let grpc_path = format!(
            "/{}/{{*grpc_service}}",
            <LoadBalancerServer<LoadBalancerService> as tonic::server::NamedService>::NAME
        );
        let grpc_router = Router::new().route(&grpc_path, any_service(svc));

        let rest_router = if config.rest.enable {
            rest_endpoint_router(Arc::new(http_lb_service))
        } else {
            Router::new()
        };

        let app = grpc_router
            .fallback_service(rest_router)
            .layer(axum::middleware::from_fn(fix_connect_info));

        let addr = *addr;
        let tls_config = config.server.tls.clone();
        let server_future = serve_with_optional_tls(addr, app, tls_config);
        server_futures.push(server_future);
    }

    try_join_all(server_futures).await?;

    Ok(())
}

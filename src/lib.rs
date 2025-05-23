// SPDX-License-Identifier: BSD-3-Clause-LBNL
// lib.rs
use chrono::Utc;
use config::LoadBalancerInstanceConfig;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tonic::service::Routes;
use tonic::transport::server::Router;
use tonic::transport::Server;
use tracing::{error, info};

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
pub mod snp4;
pub mod util;

use crate::api::rest::rest_endpoint_router;
use crate::api::service::LoadBalancerService;
use crate::config::{parse_duration, Config};
use crate::dataplane::mock::MockDataplane;
use crate::db::LoadBalancerDB;
use crate::errors::{Error, Result};
use crate::proto::loadbalancer::v1::load_balancer_server::LoadBalancerServer;
use crate::reservation::ReservationManager;
use crate::snp4::client::{MultiSNP4Client, SNP4Client};
use std::net::SocketAddr;
use tonic::transport::Server as TonicServer;

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
        // Initialize SmartNIC clients
        let mut snp4_clients = Vec::new();
        for smartnic in &config.smartnic {
            if !smartnic.mock {
                let addr = format!(
                    "{}://{}:{}",
                    if smartnic.tls.enable { "https" } else { "http" },
                    smartnic.host,
                    smartnic.port
                );
                let client = SNP4Client::new(
                    &addr,
                    0,
                    0,
                    smartnic.tls.verify,
                    smartnic.auth_token.clone(),
                )
                .await?;
                snp4_clients.push(client);
            }
        }
        let mut smartnic_clients = MultiSNP4Client::new(snp4_clients);

        // Apply rules
        reservation
            .apply_rules(&mut smartnic_clients, config)
            .await?;
    } else {
        // Print rules in table_add format
        for rule in rules {
            println!("table_add {rule}");
        }
    }

    Ok(())
}

pub async fn start_server(config: Config) -> Result<()> {
    // Initialize metrics
    metrics::init_metrics();

    // Initialize database
    let db = Arc::new(LoadBalancerDB::new(&config.database.file).await?);
    db.sync_config(&config).await?;

    // Start periodic cleanup task
    let cleanup_interval = parse_duration(&config.database.cleanup_interval)
        .map_err(|e| Error::Config(format!("Invalid cleanup interval: {}", e)))?;
    let cleanup_age = parse_duration(&config.database.cleanup_age)
        .map_err(|e| Error::Config(format!("Invalid cleanup age: {}", e)))?;
    let db_cleanup = db.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(cleanup_interval).await;
            let cutoff = Utc::now() - chrono::Duration::from_std(cleanup_age).unwrap();
            if let Err(e) = db_cleanup.cleanup_soft_deleted(cutoff).await {
                error!("Failed to cleanup soft deleted records: {}", e);
            }
        }
    });

    // Initialize SmartNIC clients
    let mut snp4_clients = Vec::new();
    for smartnic in &config.smartnic {
        if !smartnic.mock {
            let addr = format!(
                "{}://{}:{}",
                if smartnic.tls.enable { "https" } else { "http" },
                smartnic.host,
                smartnic.port
            );
            let client = SNP4Client::new(
                &addr,
                0,
                -1,
                smartnic.tls.verify,
                smartnic.auth_token.clone(),
            )
            .await?;
            snp4_clients.push(client);
        }
    }
    let mut smartnic_clients = MultiSNP4Client::new(snp4_clients);

    let reservations = db.list_reservations().await?;
    if reservations.is_empty() {
        if smartnic_clients.clear_tables().await.is_err() {
            return Err(Error::NotInitialized("failed to clear tables".into()));
        } else {
            info!("no active reservations - clearing tables")
        }
    }

    // Initialize reservation manager and L2 rules
    let mut manager = ReservationManager::new(
        db.clone(),
        smartnic_clients,
        config.get_controller_duration()?,
        config.get_controller_offset()?,
        config.lb.mac_unicast.parse()?,
        config.server.listen[0],
    );
    // manager.dump_rules_dir = Some("./rules".parse().unwrap());
    manager.initialize().await?;
    let manager_arc = Arc::new(Mutex::new(manager));

    // Create server futures for each listen address
    let mut server_futures = Vec::new();

    for addr in &config.server.listen {
        let mut server = Server::builder();

        if config.server.tls.enable {
            let cert = std::fs::read_to_string(config.server.tls.cert_file.as_ref().unwrap())?;
            let key = std::fs::read_to_string(config.server.tls.key_file.as_ref().unwrap())?;

            server = server.tls_config(tonic::transport::ServerTlsConfig::new().identity(
                tonic::transport::Identity::from_pem(cert.as_bytes(), key.as_bytes()),
            ))?;
        }

        let lb_service =
            LoadBalancerService::new(db.clone(), manager_arc.clone(), config.server.listen[0]);
        let http_lb_service =
            LoadBalancerService::new(db.clone(), manager_arc.clone(), config.server.listen[0]);
        let svc = LoadBalancerServer::new(lb_service);
        let mut router: Router;

        // Start REST server if enabled
        if config.rest.enable {
            let mut builder = server.accept_http1(true);
            let rest_routes = rest_endpoint_router(Arc::new(http_lb_service));
            let routes = Routes::from(rest_routes);
            router = builder.add_routes(routes);
            router = router.add_service(svc);
        } else {
            router = server.add_service(svc);
        }

        let server_future = async move {
            info!("gRPC server starting on {}", addr);
            router.serve(*addr).await
        };

        server_futures.push(server_future);
    }

    // Run all gRPC servers concurrently
    futures::future::try_join_all(server_futures).await?;

    Ok(())
}

pub async fn start_mocked_server(
    config: Config,
    db_path: Option<std::path::PathBuf>,
) -> Result<()> {
    // Initialize metrics
    metrics::init_metrics();

    // Initialize in-memory database if no db path is provided
    let db = if let Some(path) = db_path {
        Arc::new(LoadBalancerDB::new(&path).await?)
    } else {
        Arc::new(LoadBalancerDB::new("/tmp/udplbd-sim.db").await?)
    };
    let mut sim_config = config.clone();
    sim_config.lb.instances = vec![LoadBalancerInstanceConfig {
        ipv4: "127.0.0.1".parse().unwrap(),
        ipv6: "::1".parse().unwrap(),
        event_number_port: config.lb.instances[0].event_number_port,
    }];
    db.sync_config(&sim_config).await?;

    // Start periodic cleanup task
    let cleanup_interval = parse_duration(&config.database.cleanup_interval)
        .map_err(|e| Error::Config(format!("Invalid cleanup interval: {}", e)))?;
    let cleanup_age = parse_duration(&config.database.cleanup_age)
        .map_err(|e| Error::Config(format!("Invalid cleanup age: {}", e)))?;
    let db_cleanup = db.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(cleanup_interval).await;
            let cutoff = Utc::now() - chrono::Duration::from_std(cleanup_age).unwrap();
            if let Err(e) = db_cleanup.cleanup_soft_deleted(cutoff).await {
                error!("Failed to cleanup soft deleted records: {}", e);
            }
        }
    });

    // Initialize simulated dataplane
    let sim_dataplane = MockDataplane::new();
    let sim_addr = format!("http://127.0.0.1:{}", 50051); // TODO: Make this configurable
    let sim_service =
        crate::proto::smartnic::p4_v2::smartnic_p4_server::SmartnicP4Server::new(sim_dataplane);
    // Start the SimDataPlane gRPC server
    tokio::spawn(async move {
        let addr: SocketAddr = "127.0.0.1:50051".parse().unwrap();
        info!("simulated dataplane gRPC server listening on {}", addr);
        TonicServer::builder()
            .add_service(sim_service)
            .serve(addr)
            .await
            .expect("Failed to start simulated dataplane gRPC server");
    });
    sleep(Duration::from_millis(10)).await;

    let sim_client = SNP4Client::new(&sim_addr, 0, -1, false, "").await?;

    info!("created client");

    // Initialize reservation manager and L2 rules
    let mut manager = ReservationManager::new(
        db.clone(),
        MultiSNP4Client::new(vec![sim_client]),
        config.get_controller_duration()?,
        config.get_controller_offset()?,
        config.lb.mac_unicast.parse()?,
        config.server.listen[0],
    );
    // manager.dump_rules_dir = Some("./rules".parse().unwrap());

    info!("created rules manager");

    manager.initialize().await?;
    let manager_arc = Arc::new(Mutex::new(manager));

    info!("initialized rules manager");

    // Create server futures for each listen address
    let mut server_futures = Vec::new();

    for addr in &config.server.listen {
        let mut server = Server::builder();

        if config.server.tls.enable {
            let cert = std::fs::read_to_string(config.server.tls.cert_file.as_ref().unwrap())?;
            let key = std::fs::read_to_string(config.server.tls.key_file.as_ref().unwrap())?;

            server = server.tls_config(tonic::transport::ServerTlsConfig::new().identity(
                tonic::transport::Identity::from_pem(cert.as_bytes(), key.as_bytes()),
            ))?;
        }

        let lb_service = LoadBalancerService::new(db.clone(), manager_arc.clone(), *addr);
        let http_lb_service = LoadBalancerService::new(db.clone(), manager_arc.clone(), *addr);
        let svc = LoadBalancerServer::new(lb_service);
        let mut router: Router;

        // Start REST server if enabled
        if config.rest.enable {
            let rest_routes = rest_endpoint_router(Arc::new(http_lb_service));
            let routes = Routes::from(rest_routes);
            server = server.accept_http1(true);
            router = server.add_routes(routes);
            router = router.add_service(svc);
        } else {
            router = server.add_service(svc);
        }

        let server_future = async move {
            if config.rest.enable {
                if config.server.tls.enable {
                    info!("gRPC and REST server starting on https://{}", addr);
                } else {
                    info!("gRPC and REST server starting on http://{}", addr);
                }
            } else if config.server.tls.enable {
                info!("gRPC server starting on https://{}", addr);
            } else {
                info!("gRPC server starting on http://{}", addr);
            }
            router.serve(*addr).await
        };

        server_futures.push(server_future);
    }

    // Run all gRPC servers concurrently
    futures::future::try_join_all(server_futures).await?;

    Ok(())
}

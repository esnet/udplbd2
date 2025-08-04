// SPDX-License-Identifier: BSD-3-Clause-LBNL
use crate::db::LoadBalancerDB;
use crate::errors::{Error, Result};
use crate::macaddr;
use crate::proto::smartnic::p4_v2::TableRule;
use crate::snp4::client::MultiSNP4Client;
use crate::snp4::rules::TableUpdate;
use serde::Deserialize;
use sqlx::sqlite::SqliteConnectOptions;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::str::FromStr;

#[derive(Deserialize)]
pub struct StaticLoadBalancer {
    #[serde(default)]
    unicast_mac_address: Option<String>,
    #[serde(default)]
    unicast_ipv4_address: Option<Ipv4Addr>,
    #[serde(default)]
    unicast_ipv6_address: Option<Ipv6Addr>,
}

#[derive(Deserialize)]
pub struct StaticSession {
    #[serde(default)]
    name: Option<String>,
    #[serde(default = "default_weight")]
    weight: f64,
    ip_address: IpAddr,
    udp_port: u16,
    #[serde(default = "default_port_range")]
    port_range: u16,
    #[serde(default)]
    min_factor: f64,
    #[serde(default)]
    max_factor: f64,
    #[serde(default)]
    keep_lb_header: bool,
}

#[derive(Deserialize)]
pub struct StaticReservation {
    #[serde(default)]
    load_balancer: Option<StaticLoadBalancer>,
    sessions: Vec<StaticSession>,
    #[serde(default)]
    slots: Option<Vec<u16>>,
    #[serde(default)]
    allowed_senders: Vec<String>,
}

fn default_weight() -> f64 {
    1.0
}

fn default_port_range() -> u16 {
    1
}

impl StaticReservation {
    pub async fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        let reservation: StaticReservation = serde_yaml::from_reader(file)?;

        // Validate sessions
        if reservation.sessions.is_empty() {
            return Err(Error::Config(
                "At least one session is required".to_string(),
            ));
        }

        // Validate port ranges are power of 2
        for session in &reservation.sessions {
            if session.port_range != 0 && session.port_range & (session.port_range - 1) != 0 {
                return Err(Error::Config(format!(
                    "Port range {} must be a power of 2",
                    session.port_range
                )));
            }
        }

        Ok(reservation)
    }

    pub async fn generate_rules(&self, config: &crate::config::Config) -> Result<Vec<TableRule>> {
        // Create in-memory database
        let options = SqliteConnectOptions::from_str("sqlite::memory:")?.create_if_missing(true);
        let pool = sqlx::SqlitePool::connect_with(options).await?;
        let pool_clone = pool.clone();

        // Run migrations
        sqlx::migrate!("./migrations").run(&pool).await?;

        let db = LoadBalancerDB {
            write_pool: pool,
            read_pool: pool_clone,
            path: ":memory:".into(),
            archive_manager: None,
        };

        // Use load balancer from config if not explicitly defined
        let lb = if let Some(lb_config) = &self.load_balancer {
            db.create_loadbalancer(
                lb_config
                    .unicast_mac_address
                    .as_ref()
                    .map(|s| s.parse().unwrap())
                    .unwrap_or_else(|| config.lb.mac_unicast.parse().unwrap()),
                lb_config
                    .unicast_ipv4_address
                    .or(config.lb.instances[0].ipv4),
                lb_config
                    .unicast_ipv6_address
                    .or(config.lb.instances[0].ipv6),
                0, // event_number_udp_port not used in static mode
            )
            .await?
        } else {
            // Use first LB instance from config
            db.create_loadbalancer(
                config.lb.mac_unicast.parse().unwrap(),
                config.lb.instances[0].ipv4,
                config.lb.instances[0].ipv6,
                0, // event_number_udp_port not used in static mode
            )
            .await?
        };

        // Create reservation with allowed senders
        let reservation = db
            .create_reservation(lb.id, "static", chrono::Duration::days(1))
            .await?;

        // Add allowed senders
        for sender in &self.allowed_senders {
            db.add_sender(
                reservation.id,
                sender
                    .parse()
                    .map_err(|_| Error::Config(format!("invalid allowed_sender: {sender}")))?,
            )
            .await?;
        }

        // Add sessions
        for (i, session) in self.sessions.iter().enumerate() {
            // Get MAC address for the IP
            let mac_address = macaddr::get_mac_addr(session.ip_address)
                .await
                .map_err(|e| Error::Config(format!("Failed to get MAC address: {e}")))?;

            db.add_session(
                reservation.id,
                &session
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("session-{}", i)),
                session.weight,
                std::net::SocketAddr::new(session.ip_address, session.udp_port),
                session.port_range,
                session.min_factor,
                session.max_factor,
                mac_address,
                session.keep_lb_header,
            )
            .await?;
        }

        // Create initial epoch with slots if provided
        if let Some(slots) = &self.slots {
            db.create_epoch(reservation.id, 0, slots).await?;
        } else {
            db.advance_epoch(reservation.id, chrono::Duration::milliseconds(0), None)
                .await?;
        }

        let active_reservation = ActiveReservation::new(reservation.id, 0);

        active_reservation.generate_all_rules(&db).await
    }

    pub async fn apply_rules(
        &self,
        smartnic_clients: &mut MultiSNP4Client,
        config: &crate::config::Config,
    ) -> Result<()> {
        let rules = self.generate_rules(config).await?;

        let update = TableUpdate {
            description: "Static configuration".into(),
            insertions: rules,
            updates: vec![],
            deletions: vec![],
        };

        if smartnic_clients.bulk_update(&[update]).await.is_ok() {
            Ok(())
        } else {
            Err(Error::NotInitialized(
                "failed to apply static rules".to_string(),
            ))
        }
    }
}

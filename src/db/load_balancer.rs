// src/db/load_balancer.rs

use crate::db::models::LoadBalancer;
use crate::db::{LoadBalancerDB, Result};
use crate::errors::Error;
use chrono::{DateTime, Utc};
use macaddr::MacAddr6;
use std::net::{Ipv4Addr, Ipv6Addr};

impl LoadBalancerDB {
    /// Creates a new loadbalancer.
    pub async fn create_loadbalancer(
        &self,
        name: &str,
        unicast_mac: MacAddr6,
        broadcast_mac: MacAddr6,
        unicast_ipv4: Ipv4Addr,
        unicast_ipv6: Ipv6Addr,
        event_number_port: u16,
    ) -> Result<LoadBalancer> {
        let unicast_mac_string = unicast_mac.to_string();
        let broadcast_mac_string = broadcast_mac.to_string();
        let unicast_ipv4_string = unicast_ipv4.to_string();
        let unicast_ipv6_string = unicast_ipv6.to_string();
        let record = sqlx::query!(
            r#"
            INSERT INTO loadbalancer (
                name,
                unicast_mac_address,
                broadcast_mac_address,
                unicast_ipv4_address,
                unicast_ipv6_address,
                event_number_udp_port
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            RETURNING id, name, unicast_mac_address, broadcast_mac_address,
                      unicast_ipv4_address, unicast_ipv6_address,
                      event_number_udp_port, created_at, deleted_at
            "#,
            name,
            unicast_mac_string,
            broadcast_mac_string,
            unicast_ipv4_string,
            unicast_ipv6_string,
            event_number_port,
        )
        .fetch_one(&self.write_pool)
        .await?;

        Ok(LoadBalancer {
            id: record.id,
            name: record.name,
            unicast_mac_address: record
                .unicast_mac_address
                .parse()
                .map_err(|_| Error::Config("Invalid unicast MAC address".into()))?,
            broadcast_mac_address: record
                .broadcast_mac_address
                .parse()
                .map_err(|_| Error::Config("Invalid broadcast MAC address".into()))?,
            unicast_ipv4_address: record
                .unicast_ipv4_address
                .parse()
                .map_err(|_| Error::Config("Invalid IPv4 address".into()))?,
            unicast_ipv6_address: record
                .unicast_ipv6_address
                .parse()
                .map_err(|_| Error::Config("Invalid IPv6 address".into()))?,
            event_number_udp_port: record.event_number_udp_port as u16,
            created_at: DateTime::<Utc>::from_timestamp_millis(record.created_at)
                .ok_or(Error::Parse("created_at out of range".to_string()))?,
            deleted_at: record.deleted_at.map(|dt| {
                DateTime::<Utc>::from_timestamp_millis(dt)
                    .expect("deleted_at set but out of range!")
            }),
        })
    }

    /// Retrieves a loadbalancer by ID.
    pub async fn get_loadbalancer(&self, id: i64) -> Result<LoadBalancer> {
        let record = sqlx::query!(
            r#"
            SELECT id, name, unicast_mac_address, broadcast_mac_address,
                   unicast_ipv4_address, unicast_ipv6_address,
                   event_number_udp_port, created_at, deleted_at
            FROM loadbalancer
            WHERE id = ?1 AND deleted_at IS NULL
            "#,
            id
        )
        .fetch_optional(&self.read_pool)
        .await?;

        let record =
            record.ok_or_else(|| Error::NotFound(format!("Loadbalancer {id} not found")))?;

        Ok(LoadBalancer {
            id: record.id,
            name: record.name,
            unicast_mac_address: record
                .unicast_mac_address
                .parse()
                .map_err(|_| Error::Config("Invalid unicast MAC address".into()))?,
            broadcast_mac_address: record
                .broadcast_mac_address
                .parse()
                .map_err(|_| Error::Config("Invalid broadcast MAC address".into()))?,
            unicast_ipv4_address: record
                .unicast_ipv4_address
                .parse()
                .map_err(|_| Error::Config("Invalid IPv4 address".into()))?,
            unicast_ipv6_address: record
                .unicast_ipv6_address
                .parse()
                .map_err(|_| Error::Config("Invalid IPv6 address".into()))?,
            event_number_udp_port: record.event_number_udp_port as u16,
            created_at: DateTime::<Utc>::from_timestamp_millis(record.created_at)
                .ok_or(Error::Parse("created_at out of range".to_string()))?,
            deleted_at: record.deleted_at.map(|dt| {
                DateTime::<Utc>::from_timestamp_millis(dt)
                    .expect("deleted_at set but out of range!")
            }),
        })
    }

    /// Retrieves all non-deleted loadbalancers.
    pub async fn list_loadbalancers(&self) -> Result<Vec<LoadBalancer>> {
        let records = sqlx::query!(
            r#"
            SELECT id, name, unicast_mac_address, broadcast_mac_address,
                   unicast_ipv4_address, unicast_ipv6_address,
                   event_number_udp_port, created_at, deleted_at
            FROM loadbalancer
            WHERE deleted_at IS NULL
            ORDER BY name
            "#
        )
        .fetch_all(&self.read_pool)
        .await?;

        let mut loadbalancers = Vec::with_capacity(records.len());
        for record in records {
            loadbalancers.push(LoadBalancer {
                id: record.id,
                name: record.name,
                unicast_mac_address: record
                    .unicast_mac_address
                    .parse()
                    .map_err(|_| Error::Config("Invalid unicast MAC address".into()))?,
                broadcast_mac_address: record
                    .broadcast_mac_address
                    .parse()
                    .map_err(|_| Error::Config("Invalid broadcast MAC address".into()))?,
                unicast_ipv4_address: record
                    .unicast_ipv4_address
                    .parse()
                    .map_err(|_| Error::Config("Invalid IPv4 address".into()))?,
                unicast_ipv6_address: record
                    .unicast_ipv6_address
                    .parse()
                    .map_err(|_| Error::Config("Invalid IPv6 address".into()))?,
                event_number_udp_port: record.event_number_udp_port as u16,
                created_at: DateTime::<Utc>::from_timestamp_millis(record.created_at)
                    .ok_or(Error::Parse("created_at out of range".to_string()))?,
                deleted_at: record.deleted_at.map(|dt| {
                    DateTime::<Utc>::from_timestamp_millis(dt)
                        .expect("deleted_at set but out of range!")
                }),
            });
        }
        Ok(loadbalancers)
    }

    /// Updates a loadbalancer by ID.
    pub async fn update_loadbalancer(&self, lb: &LoadBalancer) -> Result<LoadBalancer> {
        let unicast_mac_string = lb.unicast_mac_address.to_string();
        let broadcast_mac_string = lb.broadcast_mac_address.to_string();
        let unicast_ipv4_string = lb.unicast_ipv4_address.to_string();
        let unicast_ipv6_string = lb.unicast_ipv6_address.to_string();
        let record = sqlx::query!(
            r#"
            UPDATE loadbalancer
            SET name = ?1,
                unicast_mac_address = ?2,
                broadcast_mac_address = ?3,
                unicast_ipv4_address = ?4,
                unicast_ipv6_address = ?5,
                event_number_udp_port = ?6
            WHERE id = ?7 AND deleted_at IS NULL
            RETURNING id, name, unicast_mac_address, broadcast_mac_address,
                      unicast_ipv4_address, unicast_ipv6_address,
                      event_number_udp_port, created_at, deleted_at
            "#,
            lb.name,
            unicast_mac_string,
            broadcast_mac_string,
            unicast_ipv4_string,
            unicast_ipv6_string,
            lb.event_number_udp_port,
            lb.id,
        )
        .fetch_one(&self.write_pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => Error::NotFound("Loadbalancer not found".into()),
            e => Error::Database(e),
        })?;

        Ok(LoadBalancer {
            id: record.id,
            name: record.name,
            unicast_mac_address: record
                .unicast_mac_address
                .parse()
                .map_err(|_| Error::Config("Invalid unicast MAC address".into()))?,
            broadcast_mac_address: record
                .broadcast_mac_address
                .parse()
                .map_err(|_| Error::Config("Invalid broadcast MAC address".into()))?,
            unicast_ipv4_address: record
                .unicast_ipv4_address
                .parse()
                .map_err(|_| Error::Config("Invalid IPv4 address".into()))?,
            unicast_ipv6_address: record
                .unicast_ipv6_address
                .parse()
                .map_err(|_| Error::Config("Invalid IPv6 address".into()))?,
            event_number_udp_port: record.event_number_udp_port as u16,
            created_at: DateTime::<Utc>::from_timestamp_millis(record.created_at)
                .ok_or(Error::Parse("created_at out of range".to_string()))?,
            deleted_at: record.deleted_at.map(|dt| {
                DateTime::<Utc>::from_timestamp_millis(dt)
                    .expect("deleted_at set but out of range!")
            }),
        })
    }

    /// Soft deletes a loadbalancer by ID.
    pub async fn delete_loadbalancer(&self, id: i64) -> Result<()> {
        let result = sqlx::query!(
            r#"
            UPDATE loadbalancer
            SET deleted_at = unixepoch('subsec') * 1000
            WHERE id = ?1 AND deleted_at IS NULL
            "#,
            id
        )
        .execute(&self.write_pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(Error::NotFound("Loadbalancer not found".into()));
        }
        Ok(())
    }
}

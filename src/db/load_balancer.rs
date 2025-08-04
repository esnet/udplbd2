// SPDX-License-Identifier: BSD-3-Clause-LBNL
// src/db/load_balancer.rs

use crate::db::models::LoadBalancer;
use crate::db::{LoadBalancerDB, Result};
use crate::errors::Error;
use chrono::{DateTime, Utc};
use macaddr::MacAddr6;
use std::net::{Ipv4Addr, Ipv6Addr};

impl LoadBalancerDB {
    /// Finds the first available fpga_lb_id (0-7).
    async fn find_available_fpga_lb_id(&self) -> Result<u16> {
        let active_loadbalancers =
            sqlx::query!("SELECT fpga_lb_id FROM loadbalancer WHERE deleted_at IS NULL")
                .fetch_all(&self.read_pool)
                .await?;

        let mut used_ids = std::collections::HashSet::new();
        for lb in active_loadbalancers {
            used_ids.insert(lb.fpga_lb_id as u16);
        }

        for fpga_lb_id in 0..8u16 {
            if !used_ids.contains(&fpga_lb_id) {
                return Ok(fpga_lb_id);
            }
        }

        Err(Error::ResourceExhausted(
            "Max number of load balancers reached (8)".to_string(),
        ))
    }

    /// Creates a new loadbalancer.
    pub async fn create_loadbalancer(
        &self,
        unicast_mac: MacAddr6,
        unicast_ipv4: Option<Ipv4Addr>,
        unicast_ipv6: Option<Ipv6Addr>,
        event_number_port: u16,
    ) -> Result<LoadBalancer> {
        // At least one of unicast_ipv4 or unicast_ipv6 must be provided
        if unicast_ipv4.is_none() && unicast_ipv6.is_none() {
            return Err(Error::Usage(
                "At least one of unicast_ipv4 or unicast_ipv6 must be provided".to_string(),
            ));
        }

        let fpga_lb_id = self.find_available_fpga_lb_id().await?;

        let unicast_mac_string = unicast_mac.to_string();
        let unicast_ipv4_string = unicast_ipv4.map(|ip| ip.to_string());
        let unicast_ipv6_string = unicast_ipv6.map(|ip| ip.to_string());

        let record = sqlx::query!(
            r#"
            INSERT INTO loadbalancer (
                unicast_mac_address,
                unicast_ipv4_address,
                unicast_ipv6_address,
                event_number_udp_port,
                fpga_lb_id
            )
            VALUES (?1, ?2, ?3, ?4, ?5)
            RETURNING id, unicast_mac_address,
                      unicast_ipv4_address, unicast_ipv6_address,
                      event_number_udp_port, fpga_lb_id, created_at, deleted_at
            "#,
            unicast_mac_string,
            unicast_ipv4_string,
            unicast_ipv6_string,
            event_number_port,
            fpga_lb_id,
        )
        .fetch_one(&self.write_pool)
        .await?;

        Ok(LoadBalancer {
            id: record.id,
            unicast_mac_address: record
                .unicast_mac_address
                .parse()
                .map_err(|_| Error::Config("Invalid unicast MAC address".into()))?,
            unicast_ipv4_address: record
                .unicast_ipv4_address
                .map(|s| s.parse().expect("invalid address in database")),
            unicast_ipv6_address: record
                .unicast_ipv6_address
                .map(|s| s.parse().expect("invalid address in database")),
            event_number_udp_port: record.event_number_udp_port as u16,
            fpga_lb_id: record.fpga_lb_id as u16,
            created_at: DateTime::<Utc>::from_timestamp_millis(record.created_at)
                .ok_or(Error::Parse("created_at out of range".to_string()))?,
            deleted_at: record.deleted_at.map(|dt| {
                DateTime::<Utc>::from_timestamp_millis(dt)
                    .expect("deleted_at set but out of range!")
            }),
        })
    }

    /// Fetches the latest cached global rules from the rule_cache table.
    pub async fn get_latest_rule_cache(&self) -> Result<Option<Vec<u8>>> {
        let record = sqlx::query!(
            r#"
            SELECT rules
            FROM rule_cache
            ORDER BY created_at DESC
            LIMIT 1
            "#
        )
        .fetch_optional(&self.read_pool)
        .await?;

        Ok(record.map(|r| r.rules))
    }

    /// Inserts a new global ruleset into the rule_cache table and keeps only the 10 most recent.
    pub async fn insert_rule_cache(&self, rules: &[u8]) -> Result<()> {
        let mut tx = self.write_pool.begin().await?;
        sqlx::query!(
            r#"
            INSERT INTO rule_cache (rules, created_at)
            VALUES (?1, unixepoch('subsec') * 1000)
            "#,
            rules
        )
        .execute(&mut *tx)
        .await?;

        // Delete all but the 10 most recent entries
        sqlx::query!(
            r#"
            DELETE FROM rule_cache
            WHERE id NOT IN (
                SELECT id FROM rule_cache ORDER BY created_at DESC LIMIT 10
            )
            "#
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Retrieves a loadbalancer by ID.
    pub async fn get_loadbalancer(&self, id: i64) -> Result<LoadBalancer> {
        let record = sqlx::query!(
            r#"
            SELECT id, unicast_mac_address,
                   unicast_ipv4_address, unicast_ipv6_address,
                   event_number_udp_port, fpga_lb_id, created_at, deleted_at
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
            unicast_mac_address: record
                .unicast_mac_address
                .parse()
                .map_err(|_| Error::Config("Invalid unicast MAC address".into()))?,
            unicast_ipv4_address: record
                .unicast_ipv4_address
                .map(|s| s.parse().expect("invalid address in database")),
            unicast_ipv6_address: record
                .unicast_ipv6_address
                .map(|s| s.parse().expect("invalid address in database")),
            event_number_udp_port: record.event_number_udp_port as u16,
            fpga_lb_id: record.fpga_lb_id as u16,
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
            SELECT id, unicast_mac_address,
                   unicast_ipv4_address, unicast_ipv6_address,
                   event_number_udp_port, fpga_lb_id, created_at, deleted_at
            FROM loadbalancer
            WHERE deleted_at IS NULL
            ORDER BY id
            "#
        )
        .fetch_all(&self.read_pool)
        .await?;

        let mut loadbalancers = Vec::with_capacity(records.len());
        for record in records {
            loadbalancers.push(LoadBalancer {
                id: record.id,
                unicast_mac_address: record
                    .unicast_mac_address
                    .parse()
                    .map_err(|_| Error::Config("Invalid unicast MAC address".into()))?,
                unicast_ipv4_address: record
                    .unicast_ipv4_address
                    .map(|s| s.parse().expect("invalid address in database")),
                unicast_ipv6_address: record
                    .unicast_ipv6_address
                    .map(|s| s.parse().expect("invalid address in database")),
                event_number_udp_port: record.event_number_udp_port as u16,
                fpga_lb_id: record.fpga_lb_id as u16,
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
        let unicast_ipv4_string = lb.unicast_ipv4_address.as_ref().map(|ip| ip.to_string());
        let unicast_ipv6_string = lb.unicast_ipv6_address.as_ref().map(|ip| ip.to_string());
        let record = sqlx::query!(
            r#"
            UPDATE loadbalancer
            SET unicast_mac_address = ?1,
                unicast_ipv4_address = ?2,
                unicast_ipv6_address = ?3,
                event_number_udp_port = ?4,
                fpga_lb_id = ?5
            WHERE id = ?6 AND deleted_at IS NULL
            RETURNING id, unicast_mac_address,
                      unicast_ipv4_address, unicast_ipv6_address,
                      event_number_udp_port, fpga_lb_id, created_at, deleted_at
            "#,
            unicast_mac_string,
            unicast_ipv4_string,
            unicast_ipv6_string,
            lb.event_number_udp_port,
            lb.fpga_lb_id,
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
            unicast_mac_address: record
                .unicast_mac_address
                .parse()
                .map_err(|_| Error::Config("Invalid unicast MAC address".into()))?,
            unicast_ipv4_address: record
                .unicast_ipv4_address
                .map(|s| s.parse().expect("invalid address in database")),
            unicast_ipv6_address: record
                .unicast_ipv6_address
                .map(|s| s.parse().expect("invalid address in database")),
            event_number_udp_port: record.event_number_udp_port as u16,
            fpga_lb_id: record.fpga_lb_id as u16,
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

    /// Updates only the IPv4 and IPv6 addresses for a loadbalancer by ID.
    pub async fn update_loadbalancer_addresses(
        &self,
        lb_id: i64,
        ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
    ) -> Result<()> {
        let ipv4_string = ipv4.map(|ip| ip.to_string());
        let ipv6_string = ipv6.map(|ip| ip.to_string());
        let result = sqlx::query!(
            r#"
            UPDATE loadbalancer
            SET unicast_ipv4_address = ?1,
                unicast_ipv6_address = ?2
            WHERE id = ?3 AND deleted_at IS NULL
            "#,
            ipv4_string,
            ipv6_string,
            lb_id
        )
        .execute(&self.write_pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(Error::NotFound("Loadbalancer not found".into()));
        }
        Ok(())
    }
}

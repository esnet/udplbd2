//! Provides the queries and pools needed to manipulate the state of the control plane and its LBs.
//! The core functions like epoch prediction and slot assignments are implemented in this module.
pub mod csv;
pub mod epoch;
pub mod load_balancer;
pub mod models;
pub mod reservation;
pub mod session;
#[cfg(test)]
pub mod tests;
pub mod timeseries;
pub mod token;

use crate::config::Config;
use crate::errors::Error;
use chrono::{DateTime, Utc};
use macaddr::MacAddr6;
use sqlx::migrate::Migrator;
use sqlx::{Pool, Sqlite};
use std::collections::HashSet;
use std::path::Path;
use tracing::{debug, info, trace, warn};

pub type Result<T> = std::result::Result<T, Error>;

// Embed the migrations at compile time
static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Provides methods to interact with the SQLite database that is core to udplbd
pub struct LoadBalancerDB {
    pub write_pool: Pool<Sqlite>,
    pub read_pool: Pool<Sqlite>,
    pub path: String,
}

impl LoadBalancerDB {
    /// Creates a new `LoadBalancerDB` instance with a connection pool and applies migrations.
    pub async fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        use sqlx::sqlite::SqliteConnectOptions;
        use sqlx::sqlite::SqlitePoolOptions;

        let path_str = path
            .as_ref()
            .to_str()
            .ok_or_else(|| Error::Config("Invalid path".into()))?
            .to_string();

        let options = SqliteConnectOptions::new()
            .filename(&path_str)
            .foreign_keys(true)
            .create_if_missing(true);

        let write_pool = SqlitePoolOptions::new()
            .max_connections(1) // Single connection for writes
            .connect_with(options.clone())
            .await?;

        let read_pool = SqlitePoolOptions::new()
            .max_connections(8) // Higher concurrency for reads
            .connect_with(options)
            .await?;

        MIGRATOR.run(&write_pool).await.map_err(Error::Migrate)?;

        let db = Self {
            write_pool,
            read_pool,
            path: path_str,
        };
        Ok(db)
    }

    /// Synchronize the database with the YAML config
    pub async fn sync_config(&self, config: &Config) -> Result<bool> {
        let mut changes = false;

        // Get all existing loadbalancers
        let existing_lbs = self.list_loadbalancers().await?;
        let mut existing_names: HashSet<String> =
            existing_lbs.iter().map(|lb| lb.name.clone()).collect();
        debug!("found {} existing load balancers", existing_lbs.len());

        // Process loadbalancers in config
        for lb_config in &config.lb.instances {
            let lb_name = lb_config.ipv4.to_string();
            if !existing_names.remove(&lb_name) {
                // LB doesn't exist in DB, create it
                info!("adding new load balancer to db: {}", lb_name);
                self.create_loadbalancer(
                    &lb_name,
                    config
                        .lb
                        .mac_unicast
                        .parse::<MacAddr6>()
                        .map_err(|_| Error::Config("invalid mac address".into()))?,
                    config
                        .lb
                        .mac_broadcast
                        .parse::<MacAddr6>()
                        .map_err(|_| Error::Config("invalid mac address".into()))?,
                    lb_config.ipv4,
                    lb_config.ipv6,
                    lb_config.event_number_port,
                )
                .await?;
                changes = true;
            } else {
                trace!("load balancer already exists: {}", lb_name);
            }
        }

        // Remove loadbalancers that exist in DB but not in config
        if !existing_names.is_empty() {
            warn!(
                "found {} load balancers in database that are not in config",
                existing_names.len()
            );
            for lb_name in existing_names {
                if let Some(lb) = existing_lbs.iter().find(|lb| lb.name == lb_name) {
                    info!("removing load balancer not in config: {}", lb_name);
                    self.delete_loadbalancer(lb.id).await?;
                    changes = true;
                }
            }
        } else {
            trace!("no extra load balancers to remove from database");
        }

        // Check if auth token exists and create if needed
        if let Ok(new_changes) = self.create_admin_token(&config.server.auth_token).await {
            changes |= new_changes;
        }

        Ok(changes)
    }

    pub async fn create_admin_token(&self, token: &str) -> Result<bool> {
        let token_exists = self.token_exists(token).await?;
        if !token_exists {
            info!("adding admin token to db");
            use sha2::{Digest, Sha256};
            // Hash the provided token
            let mut hasher = Sha256::new();
            hasher.update(token.as_bytes());
            let token_hash = hex::encode(hasher.finalize());

            // Insert token record directly
            sqlx::query!(
                "INSERT INTO token (name, token_hash) VALUES (?1, ?2) RETURNING id",
                "admin",
                token_hash
            )
            .fetch_one(&self.write_pool)
            .await?;

            // Add all permissions for this token
            sqlx::query!(
                "INSERT INTO token_global_permission (token_id, permission)
                 VALUES ((SELECT id FROM token WHERE token_hash = ?1), 'update')",
                token_hash
            )
            .execute(&self.write_pool)
            .await?;
            Ok(true)
        } else {
            trace!("auth token already exists");
            Ok(false)
        }
    }

    /// Cleans up old records from the database:
    /// - Removes soft-deleted records older than `older_than` from tables with deleted_at
    /// - For session_state and event_number: keeps 5 most recent records per active session/reservation,
    ///   deletes older records
    pub async fn cleanup_soft_deleted(&self, older_than: DateTime<Utc>) -> Result<()> {
        let mut tx = self.write_pool.begin().await?;
        let mut total_deleted = 0;
        let older_than_ms = older_than.timestamp_millis();

        // Tables with deleted_at column
        let tables_with_deleted_at = ["loadbalancer", "reservation", "sender", "session", "epoch"];

        // Delete old soft-deleted records
        for table in &tables_with_deleted_at {
            let result = sqlx::query(&format!("DELETE FROM {table} WHERE deleted_at < ?1"))
                .bind(older_than_ms)
                .execute(&mut *tx)
                .await
                .map_err(Error::Database)?;

            let rows = result.rows_affected();
            if rows > 0 {
                debug!("deleted {} soft-deleted rows from {}", rows, table);
                total_deleted += rows;
            }
        }

        // Clean up session_state entries
        let result = sqlx::query(
            "DELETE FROM session_state WHERE created_at < ?1
             AND id NOT IN (
                SELECT id FROM (
                    SELECT id FROM session_state
                    WHERE session_id IN (SELECT id FROM session WHERE deleted_at IS NULL)
                    ORDER BY created_at DESC
                    LIMIT 5
                )
             )",
        )
        .bind(older_than_ms)
        .execute(&mut *tx)
        .await
        .map_err(Error::Database)?;

        let rows = result.rows_affected();
        if rows > 0 {
            debug!("deleted {} old session_state entries", rows);
            total_deleted += rows;
        }

        // Clean up event_number entries
        let result = sqlx::query(
            "DELETE FROM event_number WHERE created_at < ?1
             AND id NOT IN (
                SELECT id FROM (
                    SELECT id FROM event_number
                    WHERE reservation_id IN (SELECT id FROM reservation WHERE deleted_at IS NULL)
                    ORDER BY created_at DESC
                    LIMIT 5
                )
             )",
        )
        .bind(older_than_ms)
        .execute(&mut *tx)
        .await
        .map_err(Error::Database)?;

        let rows = result.rows_affected();
        if rows > 0 {
            debug!("deleted {} old event_number entries", rows);
            total_deleted += rows;
        }

        tx.commit().await.map_err(Error::Database)?;

        if total_deleted > 0 {
            info!("deleted {} soft-deleted rows", total_deleted);
        }
        Ok(())
    }
}

#[allow(unused)]
pub use epoch::*;

#[allow(unused)]
pub use load_balancer::*;

#[allow(unused)]
pub use models::*;

#[allow(unused)]
pub use reservation::*;

#[allow(unused)]
pub use session::*;

#[allow(unused)]
pub use token::*;

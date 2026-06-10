// SPDX-License-Identifier: BSD-3-Clause-LBNL
//! Provides the queries and pools needed to manipulate the state of the control plane and its LBs.
//! The core functions like epoch prediction and slot assignments are implemented in this module.

pub mod csv;
pub mod epoch;
pub mod healthcheck;
pub mod load_balancer;
pub mod models;
pub mod reservation;
pub mod session;
#[cfg(test)]
pub mod tests;
pub mod timeseries;
pub mod token;

use crate::config::Config;
use crate::errors::{Error, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sqlx::migrate::Migrator;
use sqlx::{Pool, Row, Sqlite};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tokio::sync::Mutex;
use tracing::{debug, info, trace, warn};

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Provides methods to interact with the SQLite database that is core to udplbd
pub struct LoadBalancerDB {
    pub write_pool: Pool<Sqlite>,
    pub read_pool: Pool<Sqlite>,
    pub path: String,
    pub archive_manager: Option<Mutex<ArchiveDBManager>>,
}

impl LoadBalancerDB {
    /// Creates a new `LoadBalancerDB` instance with a connection pool and applies migrations.
    pub async fn new<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

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
            .max_connections(1)
            .connect_with(options.clone())
            .await
            .map_err(Error::Database)?;

        let read_pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await
            .map_err(Error::Database)?;

        MIGRATOR.run(&write_pool).await.map_err(Error::Migrate)?;

        Ok(Self {
            write_pool,
            read_pool,
            path: path_str,
            archive_manager: None,
        })
    }

    /// If the database file exists and has pending migrations, copy it to a backup file.
    /// The backup overwrites any previous backup to avoid unbounded growth.
    async fn backup_before_migrate(db_path: &Path) -> Result<()> {
        if !db_path.exists() {
            return Ok(());
        }

        // Open a temporary read-only connection to check applied migrations
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(db_path)
            .create_if_missing(false);

        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(Error::Database)?;

        // Check if the _sqlx_migrations table exists
        let table_exists: bool = sqlx::query_scalar::<_, i32>(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_sqlx_migrations'",
        )
        .fetch_one(&pool)
        .await
        .map(|count| count > 0)
        .unwrap_or(false);

        let applied_count = if table_exists {
            sqlx::query_scalar::<_, i32>("SELECT COUNT(*) FROM _sqlx_migrations")
                .fetch_one(&pool)
                .await
                .unwrap_or(0)
        } else {
            0
        };

        pool.close().await;

        let total_migrations = MIGRATOR.migrations.len() as i32;
        if applied_count >= total_migrations {
            debug!(
                "no pending migrations (applied={applied_count}, total={total_migrations}), skipping backup"
            );
            return Ok(());
        }

        let pending = total_migrations - applied_count;
        let backup_name = format!(
            "{}.pre-migrate.bak",
            db_path.file_name().unwrap_or_default().to_string_lossy()
        );
        let backup_path = db_path.with_file_name(&backup_name);

        info!(
            "{pending} pending migration(s), backing up database to {}",
            backup_path.display()
        );
        fs::copy(db_path, &backup_path).map_err(Error::IoError)?;

        Ok(())
    }

    /// Alternative constructor: create from config, using config.database.file and archive settings.
    pub async fn with_config(config: &Config) -> Result<Self> {
        let db_path = &config.database.file;

        if config.database.backup_before_migrate {
            Self::backup_before_migrate(db_path.as_path()).await?;
        }

        let mut db = Self::new(db_path).await?;

        // If an archive directory is configured, initialize ArchiveDBManager
        db.archive_manager = if let Some(ref dir) = config.database.archive_dir {
            let rotation_std = crate::config::parse_duration(&config.database.archive_rotation)
                .map_err(|e| Error::Config(format!("Invalid archive_rotation: {e}")))?;
            let rotation = ChronoDuration::from_std(rotation_std)
                .map_err(|e| Error::Config(format!("Invalid archive_rotation: {e}")))?;
            let keep = config.database.archive_keep;
            let mgr = ArchiveDBManager::new(dir.clone(), rotation, keep).await?;
            Some(Mutex::new(mgr))
        } else {
            None
        };

        db.sync_config(config).await?;
        Ok(db)
    }

    /// Synchronize the database with the YAML config
    pub async fn sync_config(&self, config: &Config) -> Result<bool> {
        let mut changes = false;

        // Apply SQLite pragmas based on config
        sqlx::query("PRAGMA journal_mode = WAL")
            .execute(&self.write_pool)
            .await
            .ok();
        sqlx::query("PRAGMA mmap_size = 30000000000")
            .execute(&self.write_pool)
            .await
            .ok();
        sqlx::query("PRAGMA page_size = 32768;")
            .execute(&self.write_pool)
            .await
            .ok();

        let sync_mode = if !config.database.fsync {
            "PRAGMA synchronous = OFF"
        } else {
            "PRAGMA synchronous = FULL"
        };
        sqlx::query(sync_mode).execute(&self.write_pool).await.ok();

        // Get all existing loadbalancers
        let existing_lbs = self.list_loadbalancers().await?;
        debug!("found {} existing load balancers", existing_lbs.len());

        // Track which DB entries have been matched
        let mut matched_db_ids = std::collections::HashSet::new();

        // For each config instance, try to match by either address and port
        for lb_config in &config.lb.instances {
            let port = lb_config.event_number_port;
            let ipv4 = lb_config.ipv4;
            let ipv6 = lb_config.ipv6;

            // Find a DB entry where either address matches and port matches
            let maybe_db = existing_lbs.iter().find(|db_lb| {
                db_lb.event_number_udp_port == port
                    && ((ipv4.is_some() && db_lb.unicast_ipv4_address == ipv4)
                        || (ipv6.is_some() && db_lb.unicast_ipv6_address == ipv6))
            });

            if let Some(db_lb) = maybe_db {
                matched_db_ids.insert(db_lb.id);

                // If addresses differ, update the DB entry
                if db_lb.unicast_ipv4_address != ipv4 || db_lb.unicast_ipv6_address != ipv6 {
                    info!(
                    "updating load balancer id {:?}: ipv4 {:?} -> {:?}, ipv6 {:?} -> {:?}, port {:?}",
                    db_lb.id, db_lb.unicast_ipv4_address, ipv4, db_lb.unicast_ipv6_address, ipv6, port
                    );
                    self.update_loadbalancer_addresses(db_lb.id, ipv4, ipv6)
                        .await?;
                    changes = true;
                } else {
                    debug!(
                        "load balancer already exists and matches: id {:?}, ipv4={:?}, ipv6={:?}, port={:?}",
                        db_lb.id, ipv4, ipv6, port
                    );
                }
            } else {
                // No match found, create new
                info!(
                    "adding new load balancer to db: ipv4={:?}, ipv6={:?}, port={:?}",
                    ipv4, ipv6, port
                );
                self.create_loadbalancer(
                    config
                        .lb
                        .mac_unicast
                        .as_ref()
                        .expect("no unicast mac address configured")
                        .parse::<macaddr::MacAddr6>()
                        .map_err(|_| Error::Config("invalid mac address".into()))?,
                    ipv4,
                    ipv6,
                    port,
                )
                .await?;
                changes = true;
            }
        }

        // Remove load balancers in DB that do not match any config instance by either address and port
        for db_lb in existing_lbs.iter() {
            if matched_db_ids.contains(&db_lb.id) {
                continue;
            }
            // If no config instance matches either address and port, remove
            let still_in_config = config.lb.instances.iter().any(|lb_config| {
                db_lb.event_number_udp_port == lb_config.event_number_port
                    && ((lb_config.ipv4.is_some() && db_lb.unicast_ipv4_address == lb_config.ipv4)
                        || (lb_config.ipv6.is_some()
                            && db_lb.unicast_ipv6_address == lb_config.ipv6))
            });
            if !still_in_config {
                info!(
                    "removing load balancer not in config: id {:?}, ipv4={:?}, ipv6={:?}, port={:?}",
                    db_lb.id,
                    db_lb.unicast_ipv4_address,
                    db_lb.unicast_ipv6_address,
                    db_lb.event_number_udp_port
                );
                self.delete_loadbalancer(db_lb.id).await?;
                changes = true;
            }
        }

        // Create admin token if missing
        if let Ok(new_changes) = self.create_admin_token(&config.server.auth_token).await {
            changes |= new_changes;
        }

        Ok(changes)
    }

    pub async fn create_admin_token(&self, token: &str) -> Result<bool> {
        let token_exists = self.token_exists(token).await?;
        if token_exists.is_none() {
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
            .await
            .map_err(Error::Database)?;

            // Add all permissions for this token
            sqlx::query!(
                "INSERT INTO token_global_permission (token_id, permission)
                 VALUES ((SELECT id FROM token WHERE token_hash = ?1), 'update')",
                token_hash
            )
            .execute(&self.write_pool)
            .await
            .map_err(Error::Database)?;
            Ok(true)
        } else {
            debug!("auth token already exists");
            Ok(false)
        }
    }

    /// Cleans up old records from the database:
    /// - If archiving is enabled:
    ///   • Rotate (or re‐use) an existing archive file via `archive_manager`.
    ///   • DETACH "archive" unconditionally (ignore errors).
    ///   • ATTACH that archive once.
    ///   • For each "deleted_at" table, INSERT … SELECT into archive.<table> and then DELETE.
    ///   • For each "created_at" table (stat_*), INSERT … SELECT into archive.<table> and then DELETE.
    ///   • For session_state and event_number, do the same in that single transaction.
    ///   • DETACH again, then COMMIT once.
    ///
    /// - If archiving is disabled:
    ///   • Just DELETE FROM main.<table> WHERE …
    ///   (no ATTACH at all).
    pub async fn cleanup_soft_deleted(&self, older_than: DateTime<Utc>) -> Result<()> {
        trace!("beginning cleanup process");
        let older_than_ms = older_than.timestamp_millis();
        let mut total_deleted = 0u64;
        let mut per_table: BTreeMap<&'static str, u64> = BTreeMap::new();
        let op_start = Instant::now();

        // STEP 1: Rotate / re‐use archive if enabled, and grab the path string.
        let (archive_path_opt, do_archive) = if let Some(archive_mutex) = &self.archive_manager
        {
            let mut mgr = archive_mutex.lock().await;
            let _ = mgr.get_or_rotate_and_get_pool(Utc::now()).await?;
            let path_buf = mgr
                .current_db_path
                .as_ref()
                .expect("archive_manager just created or re‐used a path")
                .clone();
            let path_str = path_buf.display().to_string();
            drop(mgr);
            (Some(path_str), true)
        } else {
            (None, false)
        };

        // STEP 2: Pre‐fetch all column‐lists BEFORE opening any transaction.
        let tables_with_deleted_at = [
            "sender",
            "session",
            "epoch",
            "reservation",
            "loadbalancer",
            "slot_demand",
        ];
        let tables_with_created_at = ["stat_global_sample", "stat_lb_sample", "stat_member_sample"];

        let mut deleted_col_lists: HashMap<&str, String> = HashMap::new();
        for &table in &tables_with_deleted_at {
            let mut temp_cache = TableMetadataCache::new();
            let columns = temp_cache.get_columns(&self.write_pool, table).await?;
            deleted_col_lists.insert(table, columns.join(", "));
        }

        let mut created_col_lists: HashMap<&str, String> = HashMap::new();
        for &table in &tables_with_created_at {
            let mut temp_cache = TableMetadataCache::new();
            let columns = temp_cache.get_columns(&self.write_pool, table).await?;
            created_col_lists.insert(table, columns.join(", "));
        }

        let session_table = "session_state";
        let session_col_list = {
            let mut temp_cache = TableMetadataCache::new();
            let columns = temp_cache
                .get_columns(&self.write_pool, session_table)
                .await?;
            columns.join(", ")
        };

        let event_table = "event_number";
        let event_col_list = {
            let mut temp_cache = TableMetadataCache::new();
            let columns = temp_cache
                .get_columns(&self.write_pool, event_table)
                .await?;
            columns.join(", ")
        };

        // STEP 3: If archiving is enabled, do everything in one write_pool transaction.
        if let (Some(archive_path), true) = (&archive_path_opt, do_archive) {
            // 3a) DETACH "archive" unconditionally, ignoring any error (it might not be attached).
            let _ = sqlx::query("DETACH DATABASE archive")
                .execute(&self.write_pool)
                .await;

            // 3b) Disable FK checks on main DB
            sqlx::query("PRAGMA foreign_keys = OFF;")
                .execute(&self.write_pool)
                .await
                .map_err(Error::Database)?;

            // 3c) Begin a single transaction on write_pool
            let mut tx = self.write_pool.begin().await.map_err(Error::Database)?;

            // 3d) ATTACH the archive DB under alias "archive"
            let attach_sql = format!("ATTACH DATABASE '{archive_path}' AS archive");
            sqlx::query(sqlx::AssertSqlSafe(attach_sql))
                .execute(&mut *tx)
                .await
                .map_err(Error::Database)?;

            // 3e) Archive + delete each "deleted_at" table
            for &table in &tables_with_deleted_at {
                let n = archive_old_rows_by_column(
                    &mut tx,
                    table,
                    &deleted_col_lists[table],
                    "deleted_at",
                    older_than_ms,
                )
                .await?;
                total_deleted += n;
                *per_table.entry(table).or_insert(0) += n;
            }

            // 3f) Archive + delete each "created_at" table
            for &table in &tables_with_created_at {
                let n = archive_old_rows_by_column(
                    &mut tx,
                    table,
                    &created_col_lists[table],
                    "created_at",
                    older_than_ms,
                )
                .await?;
                total_deleted += n;
                *per_table.entry(table).or_insert(0) += n;
            }

            // 3g) Prune session_state (keep 5 most‐recent per active session)
            let n = archive_prune_keeping_recent(
                &mut tx,
                session_table,
                &session_col_list,
                "session",
                "session_id",
                older_than_ms,
                5,
            )
            .await?;
            total_deleted += n;
            *per_table.entry(session_table).or_insert(0) += n;

            // 3h) Prune event_number (keep 5 most‐recent per active reservation)
            let n = archive_prune_keeping_recent(
                &mut tx,
                event_table,
                &event_col_list,
                "reservation",
                "reservation_id",
                older_than_ms,
                5,
            )
            .await?;
            total_deleted += n;
            *per_table.entry(event_table).or_insert(0) += n;

            // 3i) Re-enable FK checks, DETACH, and COMMIT
            let _ = sqlx::query("PRAGMA foreign_keys = ON;")
                .execute(&mut *tx)
                .await;
            let _ = sqlx::query("DETACH DATABASE archive")
                .execute(&mut *tx)
                .await;
            tx.commit().await.map_err(Error::Database)?;

            // 3j) Re-enable FK checks on main DB
            sqlx::query("PRAGMA foreign_keys = ON;")
                .execute(&self.write_pool)
                .await
                .map_err(Error::Database)?;

            vacuum_and_log(&self.write_pool, total_deleted, &per_table, op_start, true).await?;
            return Ok(());
        }

        // STEP 4: If archiving is disabled, do plain DELETEs.
        for &table in &tables_with_deleted_at {
            let n = delete_old_rows_by_column(&self.write_pool, table, "deleted_at", older_than_ms)
                .await?;
            total_deleted += n;
            *per_table.entry(table).or_insert(0) += n;
        }

        for &table in &tables_with_created_at {
            let n = delete_old_rows_by_column(&self.write_pool, table, "created_at", older_than_ms)
                .await?;
            total_deleted += n;
            *per_table.entry(table).or_insert(0) += n;
        }

        let n = prune_keeping_recent(
            &self.write_pool,
            session_table,
            "session",
            "session_id",
            older_than_ms,
            5,
        )
        .await?;
        total_deleted += n;
        *per_table.entry(session_table).or_insert(0) += n;

        let n = prune_keeping_recent(
            &self.write_pool,
            event_table,
            "reservation",
            "reservation_id",
            older_than_ms,
            5,
        )
        .await?;
        total_deleted += n;
        *per_table.entry(event_table).or_insert(0) += n;

        vacuum_and_log(&self.write_pool, total_deleted, &per_table, op_start, false).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Private helpers for cleanup_soft_deleted
// ---------------------------------------------------------------------------

/// Deletes rows older than `older_than_ms` from `table` using `column` as the timestamp.
/// Returns the number of rows deleted.
async fn delete_old_rows_by_column(
    pool: &Pool<Sqlite>,
    table: &str,
    column: &str,
    older_than_ms: i64,
) -> Result<u64> {
    let sql = format!("DELETE FROM `{table}` WHERE `{column}` < ?");
    let result = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(older_than_ms)
        .execute(pool)
        .await
        .map_err(Error::Database)?;
    Ok(result.rows_affected())
}

/// Within an open transaction that has the archive DB ATTACHed as "archive":
/// copies rows older than `older_than_ms` into `archive.<table>` then deletes
/// them from `main.<table>`. Returns the number of rows deleted from main.
async fn archive_old_rows_by_column(
    tx: &mut sqlx::SqliteConnection,
    table: &str,
    columns_csv: &str,
    column: &str,
    older_than_ms: i64,
) -> Result<u64> {
    let insert_sql = format!(
        "INSERT INTO archive.`{table}` ({columns_csv})
         SELECT {columns_csv} FROM main.`{table}` WHERE `{column}` < ?"
    );
    sqlx::query(sqlx::AssertSqlSafe(insert_sql))
        .bind(older_than_ms)
        .execute(&mut *tx)
        .await
        .map_err(Error::Database)?;

    let delete_sql = format!("DELETE FROM `{table}` WHERE `{column}` < ?");
    let result = sqlx::query(sqlx::AssertSqlSafe(delete_sql))
        .bind(older_than_ms)
        .execute(&mut *tx)
        .await
        .map_err(Error::Database)?;
    Ok(result.rows_affected())
}

/// Deletes rows from `table` that are older than `older_than_ms`, but keeps the
/// `keep_n` most-recent rows per active parent entity (those whose `deleted_at IS NULL`
/// in `parent_table`). Rows are linked via `fk_column` → `parent_table.id`.
/// Returns the number of rows deleted.
async fn prune_keeping_recent(
    pool: &Pool<Sqlite>,
    table: &str,
    parent_table: &str,
    fk_column: &str,
    older_than_ms: i64,
    keep_n: i64,
) -> Result<u64> {
    let sql = format!(
        "DELETE FROM `{table}` WHERE created_at < ? AND id NOT IN (
             SELECT id FROM (
                 SELECT id FROM `{table}`
                 WHERE `{fk_column}` IN (
                     SELECT id FROM `{parent_table}` WHERE deleted_at IS NULL
                 )
                 ORDER BY created_at DESC
                 LIMIT ?
             )
         )"
    );
    let result = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(older_than_ms)
        .bind(keep_n)
        .execute(pool)
        .await
        .map_err(Error::Database)?;
    Ok(result.rows_affected())
}

/// Within an open transaction that has the archive DB ATTACHed as "archive":
/// copies rows matching the pruning criteria into `archive.<table>` then deletes
/// them from `main.<table>`. Keeps the `keep_n` most-recent rows per active parent
/// entity (those whose `deleted_at IS NULL` in `parent_table`).
/// Returns the number of rows deleted from main.
async fn archive_prune_keeping_recent(
    tx: &mut sqlx::SqliteConnection,
    table: &str,
    columns_csv: &str,
    parent_table: &str,
    fk_column: &str,
    older_than_ms: i64,
    keep_n: i64,
) -> Result<u64> {
    let predicate = format!(
        "created_at < ? AND id NOT IN (
             SELECT id FROM (
                 SELECT id FROM `{table}`
                 WHERE `{fk_column}` IN (
                     SELECT id FROM `{parent_table}` WHERE deleted_at IS NULL
                 )
                 ORDER BY created_at DESC
                 LIMIT ?
             )
         )"
    );

    let insert_sql = format!(
        "INSERT INTO archive.`{table}` ({columns_csv})
         SELECT {columns_csv} FROM `{table}` WHERE {predicate}"
    );
    sqlx::query(sqlx::AssertSqlSafe(insert_sql))
        .bind(older_than_ms)
        .bind(keep_n)
        .execute(&mut *tx)
        .await
        .map_err(Error::Database)?;

    let delete_sql = format!("DELETE FROM `{table}` WHERE {predicate}");
    let result = sqlx::query(sqlx::AssertSqlSafe(delete_sql))
        .bind(older_than_ms)
        .bind(keep_n)
        .execute(&mut *tx)
        .await
        .map_err(Error::Database)?;
    Ok(result.rows_affected())
}

/// Runs VACUUM on `pool` (if `total_deleted > 0`) and logs a structured summary.
/// `archived` controls whether the verb in the log line is "archived" or "deleted".
async fn vacuum_and_log(
    pool: &Pool<Sqlite>,
    total_deleted: u64,
    per_table: &BTreeMap<&'static str, u64>,
    op_start: Instant,
    archived: bool,
) -> Result<()> {
    if total_deleted == 0 {
        return Ok(());
    }
    let vacuum_start = Instant::now();
    sqlx::query("VACUUM")
        .execute(pool)
        .await
        .map_err(Error::Database)?;
    let vacuum_ms = vacuum_start.elapsed().as_millis();

    let verb = if archived {
        "archived"
    } else {
        "deleted (no archive)"
    };
    let mut summary = format!("{verb} {total_deleted} total rows");
    if !per_table.is_empty() {
        let details: Vec<String> = per_table.iter().map(|(k, v)| format!("{v} {k}")).collect();
        summary.push_str(&format!(" ({})", details.join(", ")));
    }
    summary.push_str(&format!(" in {} ms", op_start.elapsed().as_millis()));
    summary.push_str(&format!(", VACUUM took {vacuum_ms} ms"));
    info!("{}", summary);
    Ok(())
}

/// Holds cached column‐lists per table (populated on first use).
struct TableMetadataCache {
    /// key = table name, value = Vec of column names
    columns: HashMap<String, Vec<String>>,
}

impl TableMetadataCache {
    fn new() -> Self {
        TableMetadataCache {
            columns: HashMap::new(),
        }
    }

    /// Fetch (and cache) the list of column names for `table` using the given pool.
    async fn get_columns(&mut self, pool: &Pool<Sqlite>, table: &str) -> Result<Vec<String>> {
        if let Some(cached) = self.columns.get(table) {
            return Ok(cached.clone());
        }

        let pragma_sql = format!("PRAGMA table_info(`{table}`)");
        let rows = sqlx::query(sqlx::AssertSqlSafe(pragma_sql))
            .fetch_all(pool)
            .await
            .map_err(Error::Database)?;

        let mut cols = Vec::with_capacity(rows.len());
        for row in rows {
            let col_name: String = row.get("name");
            cols.push(col_name);
        }

        self.columns.insert(table.to_string(), cols.clone());
        Ok(cols)
    }
}

/// Scans a directory for files named exactly `udplbd_archive_YYYYMMDDHHMMSS.db`,
/// parses out the timestamp, and returns `(latest_path, latest_timestamp)` if any exist.
fn find_latest_archive(dir: &Path) -> std::io::Result<Option<(PathBuf, DateTime<Utc>)>> {
    let mut latest: Option<(DateTime<Utc>, PathBuf)> = None;

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(stripped) = name.strip_prefix("udplbd_archive_") {
            if let Some(ts_part) = stripped.strip_suffix(".db") {
                if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(ts_part, "%Y%m%d%H%M%S") {
                    let utc_ts = DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc);
                    match &latest {
                        Some((prev_ts, _)) if *prev_ts >= utc_ts => {}
                        _ => {
                            latest = Some((utc_ts, entry.path()));
                        }
                    }
                }
            }
        }
    }

    Ok(latest.map(|(ts, path)| (path, ts)))
}

/// Manages the archive DB for soft-deleted rows, including rotation and pruning.
pub struct ArchiveDBManager {
    dir: PathBuf,
    rotation: ChronoDuration,
    keep: u32,

    /// Cached path to the "current" archive, if any
    current_db_path: Option<PathBuf>,
    current_db_time: Option<DateTime<Utc>>,
    pool: Option<Pool<Sqlite>>,
}

impl ArchiveDBManager {
    /// On startup, scan `dir` for the most-recent `archive_*.sqlite`.
    /// If found, open it and run any missing migrations.
    /// Otherwise, leave everything None so that the first cleanup call creates a new file.
    pub async fn new(dir: PathBuf, rotation: ChronoDuration, keep: u32) -> Result<Self> {
        // 1) Ensure the directory exists
        fs::create_dir_all(&dir).map_err(Error::IoError)?;

        // 2) Look for the latest "archive_YYYYMMDDHHMMSS.sqlite" on disk
        let (current_db_path, current_db_time, pool) = match find_latest_archive(&dir) {
            Err(e) => {
                // If the fs read_dir failed, propagate as IoError
                return Err(Error::IoError(e));
            }
            Ok(None) => {
                // No archive files found → leave None so that get_or_rotate creates one
                (None, None, None)
            }
            Ok(Some((path, ts))) => {
                // We found an existing archive file. Try to open & migrate it now.
                let options = sqlx::sqlite::SqliteConnectOptions::new()
                    .filename(&path)
                    .foreign_keys(true)
                    .create_if_missing(false);

                let pool = sqlx::sqlite::SqlitePoolOptions::new()
                    .max_connections(1)
                    .connect_with(options)
                    .await
                    .map_err(Error::Database)?;

                MIGRATOR.run(&pool).await.map_err(Error::Migrate)?;

                info!(
                    "found existing archive database: {} (timestamp {})",
                    path.display(),
                    ts
                );
                (Some(path), Some(ts), Some(pool))
            }
        };

        Ok(Self {
            dir,
            rotation,
            keep,
            current_db_path,
            current_db_time,
            pool,
        })
    }

    /// If "rotation" interval has elapsed (or no pool exists yet), drop the old pool
    /// and create a brand-new file. Otherwise, reuse the existing one.
    /// Always returns a valid `SqlitePool`.
    pub async fn get_or_rotate_and_get_pool(&mut self, now: DateTime<Utc>) -> Result<Pool<Sqlite>> {
        let needs_rotation = match self.current_db_time {
            Some(t) => now.signed_duration_since(t) >= self.rotation,
            None => true,
        };

        if needs_rotation {
            // Drop current handle (if any) so file handle is released
            self.drop_current_pool().await;
            // Create and migrate a brand-new archive file
            self.create_new_archive(now).await?;
            // Prune old dbs
            self.prune_old().map_err(Error::IoError)?;
        }

        // By now, `self.pool` must be Some(_)
        Ok(self.pool.as_ref().unwrap().clone())
    }

    /// Close existing pool (if any) before rotating.
    async fn drop_current_pool(&mut self) {
        if let Some(old_pool) = self.pool.take() {
            drop(old_pool);
        }
        self.current_db_path = None;
        self.current_db_time = None;
    }

    /// Create a new file-based SQLite archive DB, run migrations on it, and set the pool.
    async fn create_new_archive(&mut self, now: DateTime<Utc>) -> Result<()> {
        // Make a filename like "udplbd_archive_20250605120000.db"
        let filename = format!("udplbd_archive_{}.db", now.format("%Y%m%d%H%M%S"));
        let db_path = self.dir.join(&filename);

        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&db_path)
            .foreign_keys(true)
            .create_if_missing(true);

        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(Error::Database)?;

        // Run all migrations on this brand-new file
        MIGRATOR.run(&pool).await.map_err(Error::Migrate)?;

        self.current_db_path = Some(db_path.clone());
        self.current_db_time = Some(now);
        self.pool = Some(pool);

        info!("rotated archive database: {}", db_path.display());

        Ok(())
    }

    /// Remove all but the most recent `keep` files in `self.dir` matching "udplbd_archive_*.db".
    fn prune_old(&self) -> std::io::Result<()> {
        // Gather all "udplbd_archive_YYYYMMDDHHMMSS.db" files
        let mut candidates: Vec<(DateTime<Utc>, PathBuf)> = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(stripped) = name.strip_prefix("udplbd_archive_") {
                if let Some(ts_part) = stripped.strip_suffix(".db") {
                    if let Ok(naive) =
                        chrono::NaiveDateTime::parse_from_str(ts_part, "%Y%m%d%H%M%S")
                    {
                        let utc_time = DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc);
                        candidates.push((utc_time, entry.path()));
                    }
                }
            }
        }

        // Sort by timestamp ascending (oldest first)
        candidates.sort_by_key(|(ts, _)| *ts);

        // If more than `keep`, delete oldest first
        if (candidates.len() as u32) > self.keep {
            let excess = candidates.len() - self.keep as usize;
            for (_, ref path) in candidates.drain(..excess) {
                if let Err(e) = fs::remove_file(path) {
                    warn!("failed to delete old archive DB {}: {}", path.display(), e);
                } else {
                    info!("deleted old archive DB: {}", path.display());
                }
            }
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

// SPDX-License-Identifier: BSD-3-Clause-LBNL
// src/db/session.rs

use crate::db::models::{Session, SessionState};
use crate::db::{LoadBalancerDB, Result};
use crate::errors::Error;
use chrono::{DateTime, Utc};
use macaddr::MacAddr6;
use std::net::SocketAddr;
use tracing::info;

impl LoadBalancerDB {
    /// Gets the latest state update for a session
    pub async fn get_latest_session_state(&self, session_id: i64) -> Result<Option<SessionState>> {
        let record = sqlx::query!(
            r#"
            SELECT timestamp, is_ready, fill_percent, control_signal,
                   total_events_recv, total_events_reassembled, total_events_reassembly_err,
                   total_events_dequeued, total_event_enqueue_err, total_bytes_recv,
                   total_packets_recv
            FROM session_state
            WHERE session_id = ?1
            ORDER BY timestamp DESC
            LIMIT 1
            "#,
            session_id
        )
        .fetch_optional(&self.read_pool)
        .await?;

        Ok(record.map(|r| SessionState {
            timestamp: DateTime::<Utc>::from_timestamp_millis(r.timestamp)
                .expect("timestamp out of range"),
            is_ready: r.is_ready,
            fill_percent: r.fill_percent,
            control_signal: r.control_signal,
            total_events_recv: r.total_events_recv as u64,
            total_events_reassembled: r.total_events_reassembled as u64,
            total_events_reassembly_err: r.total_events_reassembly_err as u64,
            total_events_dequeued: r.total_events_dequeued as u64,
            total_event_enqueue_err: r.total_event_enqueue_err as u64,
            total_bytes_recv: r.total_bytes_recv as u64,
            total_packets_recv: r.total_packets_recv as u64,
        }))
    }

    /// Inserts a new session_state and updates session.latest_session_state_id
    #[allow(clippy::too_many_arguments)]
    pub async fn add_session_state_and_update_latest(
        &self,
        session_id: i64,
        timestamp: i64,
        is_ready: bool,
        fill_percent: f64,
        control_signal: f64,
        total_events_recv: i64,
        total_events_reassembled: i64,
        total_events_reassembly_err: i64,
        total_events_dequeued: i64,
        total_event_enqueue_err: i64,
        total_bytes_recv: i64,
        total_packets_recv: i64,
    ) -> Result<i64> {
        let mut tx = self.write_pool.begin().await?;

        // Insert session_state
        let state_record = sqlx::query!(
            r#"
            INSERT INTO session_state (
                session_id, timestamp, is_ready, fill_percent, control_signal,
                total_events_recv, total_events_reassembled, total_events_reassembly_err,
                total_events_dequeued, total_event_enqueue_err, total_bytes_recv,
                total_packets_recv
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            RETURNING id
            "#,
            session_id,
            timestamp,
            is_ready,
            fill_percent,
            control_signal,
            total_events_recv,
            total_events_reassembled,
            total_events_reassembly_err,
            total_events_dequeued,
            total_event_enqueue_err,
            total_bytes_recv,
            total_packets_recv
        )
        .fetch_one(&mut *tx)
        .await?;

        // Update session.latest_session_state_id and is_ready in one query
        sqlx::query!(
            "UPDATE session SET latest_session_state_id = ?1, is_ready = ?2, control_signal = ?3 WHERE id = ?4",
            state_record.id,
            is_ready,
            control_signal,
            session_id
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(state_record.id)
    }

    /// Marks sessions as not ready if their latest state update is older than 2 seconds,
    /// and soft deletes sessions that haven't been updated in the last 5 seconds,
    /// using the latest session state timestamp. Sessions with no state update are ignored.
    pub async fn cleanup_stale_sessions(&self) -> Result<()> {
        // Step 1: Mark as not ready (is_ready = FALSE) if latest state is older than 2 seconds
        let deactivated = sqlx::query!(
            r#"
            UPDATE session
            SET is_ready = FALSE
            WHERE deleted_at IS NULL
              AND created_at < strftime('%s', 'now', '-5 seconds') * 1000
              AND latest_session_state_id IS NOT NULL
              AND is_ready = TRUE
              AND (
                SELECT timestamp FROM session_state WHERE id = session.latest_session_state_id
              ) < strftime('%s', 'now', '-2 seconds') * 1000
            RETURNING id
            "#
        )
        .fetch_all(&self.write_pool)
        .await
        .map_err(Error::Database)?;

        let deactivated_ids: Vec<i64> = deactivated.into_iter().map(|r| r.id).collect();

        // Step 2: Soft delete (set deleted_at) if latest state is older than 5 seconds and session is older than 1 minute
        let deleted = sqlx::query!(
            r#"
            UPDATE session
            SET deleted_at = unixepoch('subsec') * 1000
            WHERE deleted_at IS NULL
              AND created_at < strftime('%s', 'now', '-5 seconds') * 1000
              AND latest_session_state_id IS NOT NULL
              AND (
                SELECT timestamp FROM session_state WHERE id = session.latest_session_state_id
              ) < strftime('%s', 'now', '-60 seconds') * 1000
            RETURNING id
            "#
        )
        .fetch_all(&self.write_pool)
        .await
        .map_err(Error::Database)?;

        let deleted_ids: Vec<i64> = deleted.into_iter().map(|r| r.id).collect();

        if !deactivated_ids.is_empty() || !deleted_ids.is_empty() {
            // Delete permissions for expired (soft-deleted) sessions
            if !deleted_ids.is_empty() {
                for id in &deleted_ids {
                    sqlx::query!(
                        "DELETE FROM token_session_permission WHERE session_id = ?1",
                        id
                    )
                    .execute(&self.write_pool)
                    .await
                    .map_err(Error::Database)?;
                }
            }

            self.delete_tokens_with_no_permissions().await?;
            if !deactivated_ids.is_empty() {
                info!("deactivated stale sessions: {:?}", deactivated_ids);
            }
            if !deleted_ids.is_empty() {
                info!("removed stale sessions: {:?}", deleted_ids);
            }
        }

        Ok(())
    }

    /// Adds a session to a reservation.
    #[allow(clippy::too_many_arguments)]
    pub async fn add_session(
        &self,
        reservation_id: i64,
        name: &str,
        initial_weight_factor: f64,
        addr: SocketAddr,
        port_range: u16,
        min_factor: f64,
        max_factor: f64,
        mac_address: MacAddr6,
        keep_lb_header: bool,
    ) -> Result<Session> {
        let ip_str = addr.ip().to_string();
        let mac_str = mac_address.to_string();
        let port = addr.port();
        let weight = 1000.0 * initial_weight_factor;
        let mut tx = self.write_pool.begin().await?;

        let now = chrono::Utc::now().timestamp_millis();
        let record = sqlx::query!(
            r#"
            INSERT INTO session (
                reservation_id, name, initial_weight_factor, weight, ip_address, udp_port, port_range,
                min_factor, max_factor, mac_address, keep_lb_header
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            RETURNING id, reservation_id, name, initial_weight_factor, weight, ip_address, udp_port,
                      port_range, min_factor, max_factor, mac_address, keep_lb_header, created_at, deleted_at
            "#,
            reservation_id,
            name,
            initial_weight_factor,
            weight,
            ip_str,
            port,
            port_range,
            min_factor,
            max_factor,
            mac_str,
            keep_lb_header
        )
        .fetch_one(&mut *tx)
        .await?;

        let state_record = sqlx::query!(
            r#"
            INSERT INTO session_state (
                session_id, timestamp, is_ready, fill_percent, control_signal,
                total_events_recv, total_events_reassembled, total_events_reassembly_err,
                total_events_dequeued, total_event_enqueue_err, total_bytes_recv,
                total_packets_recv
            ) VALUES (?1, ?2, 1, 0.0, 0.0, 0, 0, 0, 0, 0, 0, 0)
            RETURNING id
            "#,
            record.id,
            now
        )
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query!(
            "UPDATE session SET latest_session_state_id = ?1 WHERE id = ?2",
            state_record.id,
            record.id
        )
        .execute(&mut *tx)
        .await?;

        let session_row = sqlx::query!(
            r#"
            SELECT id, reservation_id, name, initial_weight_factor, weight, latest_session_state_id, is_ready, ip_address, udp_port,
                   port_range, min_factor, max_factor, mac_address, keep_lb_header, created_at, deleted_at
            FROM session
            WHERE id = ?1
            "#,
            record.id
        )
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;

        let session = Session {
            id: session_row.id,
            reservation_id: session_row.reservation_id,
            name: session_row.name,
            initial_weight_factor: session_row.initial_weight_factor,
            weight: session_row.weight,
            latest_session_state_id: session_row.latest_session_state_id,
            is_ready: session_row.is_ready,
            ip_address: session_row.ip_address.parse().unwrap(),
            udp_port: session_row.udp_port as u16,
            port_range: session_row.port_range as u16,
            mac_address: session_row.mac_address,
            min_factor: session_row.min_factor,
            max_factor: session_row.max_factor,
            keep_lb_header: session_row.keep_lb_header == 1,
            created_at: DateTime::<Utc>::from_timestamp_millis(session_row.created_at)
                .ok_or(Error::Parse("created_at out of range".to_string()))?,
            deleted_at: session_row.deleted_at.map(|dt| {
                DateTime::<Utc>::from_timestamp_millis(dt)
                    .expect("deleted_at set but out of range!")
            }),
        };

        Ok(session)
    }

    /// Helper function to get the loadbalancer_id for a session
    pub async fn get_loadbalancer_id_for_session(&self, session_id: i64) -> Result<i64> {
        let record = sqlx::query!(
            "SELECT lb.id
             FROM loadbalancer lb
             JOIN reservation r ON r.loadbalancer_id = lb.id
             JOIN session s ON s.reservation_id = r.id
             WHERE s.id = ?1",
            session_id
        )
        .fetch_one(&self.read_pool)
        .await
        .map_err(Error::Database)?;

        Ok(record.id)
    }

    /// Retrieves a session by ID.
    pub async fn get_session(&self, id: i64) -> Result<Session> {
        let record = sqlx::query!(
            r#"
            SELECT id, reservation_id, name, initial_weight_factor, weight, latest_session_state_id, is_ready, ip_address, udp_port,
                   port_range, min_factor, max_factor, mac_address, keep_lb_header, created_at, deleted_at
            FROM session
            WHERE id = ?1 AND deleted_at IS NULL
            "#,
            id
        )
        .fetch_optional(&self.read_pool)
        .await?;

        let record = record.ok_or_else(|| Error::NotFound(format!("Session {id} not found")))?;

        Ok(Session {
            id: record.id,
            reservation_id: record.reservation_id,
            name: record.name,
            initial_weight_factor: record.initial_weight_factor,
            weight: record.weight,
            latest_session_state_id: record.latest_session_state_id,
            is_ready: record.is_ready,
            ip_address: record
                .ip_address
                .parse()
                .map_err(|_| Error::Config("Invalid IP address".into()))?,
            udp_port: record.udp_port as u16,
            port_range: record.port_range as u16,
            mac_address: record.mac_address,
            min_factor: record.min_factor,
            max_factor: record.max_factor,
            keep_lb_header: record.keep_lb_header == 1,
            created_at: DateTime::<Utc>::from_timestamp_millis(record.created_at)
                .ok_or(Error::Parse("created_at out of range".to_string()))?,
            deleted_at: record.deleted_at.map(|dt| {
                DateTime::<Utc>::from_timestamp_millis(dt)
                    .expect("deleted_at set but out of range!")
            }),
        })
    }

    pub async fn delete_session(&self, id: i64) -> Result<()> {
        let mut tx = self.write_pool.begin().await?;

        // Hard delete token permissions for the session
        sqlx::query!(
            "DELETE FROM token_session_permission WHERE session_id = ?1",
            id
        )
        .execute(&mut *tx)
        .await
        .map_err(Error::Database)?;

        // Soft delete the session
        sqlx::query!(
            "UPDATE session SET deleted_at = unixepoch('subsec') * 1000 WHERE id = ?1",
            id
        )
        .execute(&mut *tx)
        .await
        .map_err(Error::Database)?;

        tx.commit().await.map_err(Error::Database)?;

        // Delete tokens with no remaining permissions
        self.delete_tokens_with_no_permissions().await?;

        Ok(())
    }
}

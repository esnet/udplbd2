// SPDX-License-Identifier: BSD-3-Clause-LBNL
// src/db/healthcheck.rs

use crate::db::LoadBalancerDB;
use crate::errors::Result;
use crate::healthcheck::{HealthCheckEvent, HealthCheckSeverity};
use chrono::{DateTime, Utc};
use std::str::FromStr;

impl LoadBalancerDB {
    /// Insert a new healthcheck event into the database.
    pub async fn insert_healthcheck_event(&self, event: &HealthCheckEvent) -> Result<i64> {
        let detected_at_ms = event.detected_at.timestamp_millis();
        let resolved_at_ms = event.resolved_at.map(|dt| dt.timestamp_millis());
        let severity_str = event.severity.as_str();

        let record = sqlx::query!(
            r#"
            INSERT INTO healthcheck_event (
                event_type, severity, loadbalancer_id, reservation_id, session_id,
                message, details, detected_at, resolved_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            RETURNING id
            "#,
            event.event_type,
            severity_str,
            event.loadbalancer_id,
            event.reservation_id,
            event.session_id,
            event.message,
            event.details,
            detected_at_ms,
            resolved_at_ms
        )
        .fetch_one(&self.write_pool)
        .await?;

        Ok(record.id)
    }

    /// Get a healthcheck event by ID.
    pub async fn get_healthcheck_event(&self, id: i64) -> Result<Option<HealthCheckEvent>> {
        let record = sqlx::query!(
            r#"
            SELECT id, event_type, severity, loadbalancer_id, reservation_id, session_id,
                   message, details, detected_at, resolved_at, created_at
            FROM healthcheck_event
            WHERE id = ?1
            "#,
            id
        )
        .fetch_optional(&self.read_pool)
        .await?;

        Ok(record.map(|r| HealthCheckEvent {
            id: Some(r.id),
            event_type: r.event_type,
            severity: HealthCheckSeverity::from_str(&r.severity)
                .unwrap_or(HealthCheckSeverity::Error),
            loadbalancer_id: r.loadbalancer_id,
            reservation_id: r.reservation_id,
            session_id: r.session_id,
            message: r.message,
            details: r.details,
            detected_at: DateTime::<Utc>::from_timestamp_millis(r.detected_at)
                .unwrap_or_else(Utc::now),
            resolved_at: r
                .resolved_at
                .and_then(DateTime::<Utc>::from_timestamp_millis),
        }))
    }

    /// List active healthcheck events for a specific session.
    pub async fn list_session_healthcheck_events(
        &self,
        session_id: i64,
    ) -> Result<Vec<HealthCheckEvent>> {
        let records = sqlx::query!(
            r#"
            SELECT id, event_type, severity, loadbalancer_id, reservation_id, session_id,
                   message, details, detected_at, resolved_at, created_at
            FROM healthcheck_event
            WHERE session_id = ?1
              AND resolved_at IS NULL
            ORDER BY detected_at DESC
            "#,
            session_id
        )
        .fetch_all(&self.read_pool)
        .await?;

        Ok(records
            .into_iter()
            .map(|r| HealthCheckEvent {
                id: Some(r.id),
                event_type: r.event_type,
                severity: HealthCheckSeverity::from_str(&r.severity)
                    .unwrap_or(HealthCheckSeverity::Error),
                loadbalancer_id: r.loadbalancer_id,
                reservation_id: r.reservation_id,
                session_id: r.session_id,
                message: r.message,
                details: r.details,
                detected_at: DateTime::<Utc>::from_timestamp_millis(r.detected_at)
                    .unwrap_or_else(Utc::now),
                resolved_at: r
                    .resolved_at
                    .and_then(DateTime::<Utc>::from_timestamp_millis),
            })
            .collect())
    }

    /// List active healthcheck events for a specific loadbalancer.
    pub async fn list_loadbalancer_healthcheck_events(
        &self,
        loadbalancer_id: i64,
    ) -> Result<Vec<HealthCheckEvent>> {
        let records = sqlx::query!(
            r#"
            SELECT id, event_type, severity, loadbalancer_id, reservation_id, session_id,
                   message, details, detected_at, resolved_at, created_at
            FROM healthcheck_event
            WHERE loadbalancer_id = ?1
              AND resolved_at IS NULL
            ORDER BY detected_at DESC
            "#,
            loadbalancer_id
        )
        .fetch_all(&self.read_pool)
        .await?;

        Ok(records
            .into_iter()
            .map(|r| HealthCheckEvent {
                id: Some(r.id),
                event_type: r.event_type,
                severity: HealthCheckSeverity::from_str(&r.severity)
                    .unwrap_or(HealthCheckSeverity::Error),
                loadbalancer_id: r.loadbalancer_id,
                reservation_id: r.reservation_id,
                session_id: r.session_id,
                message: r.message,
                details: r.details,
                detected_at: DateTime::<Utc>::from_timestamp_millis(r.detected_at)
                    .unwrap_or_else(Utc::now),
                resolved_at: r
                    .resolved_at
                    .and_then(DateTime::<Utc>::from_timestamp_millis),
            })
            .collect())
    }

    /// List active healthcheck events for a specific reservation.
    pub async fn list_reservation_healthcheck_events(
        &self,
        reservation_id: i64,
    ) -> Result<Vec<HealthCheckEvent>> {
        let records = sqlx::query!(
            r#"
            SELECT id, event_type, severity, loadbalancer_id, reservation_id, session_id,
                   message, details, detected_at, resolved_at, created_at
            FROM healthcheck_event
            WHERE reservation_id = ?1
              AND resolved_at IS NULL
            ORDER BY detected_at DESC
            "#,
            reservation_id
        )
        .fetch_all(&self.read_pool)
        .await?;

        Ok(records
            .into_iter()
            .map(|r| HealthCheckEvent {
                id: Some(r.id),
                event_type: r.event_type,
                severity: HealthCheckSeverity::from_str(&r.severity)
                    .unwrap_or(HealthCheckSeverity::Error),
                loadbalancer_id: r.loadbalancer_id,
                reservation_id: r.reservation_id,
                session_id: r.session_id,
                message: r.message,
                details: r.details,
                detected_at: DateTime::<Utc>::from_timestamp_millis(r.detected_at)
                    .unwrap_or_else(Utc::now),
                resolved_at: r
                    .resolved_at
                    .and_then(DateTime::<Utc>::from_timestamp_millis),
            })
            .collect())
    }

    /// Resolve a healthcheck event by marking it as resolved.
    pub async fn resolve_healthcheck_event(&self, id: i64) -> Result<()> {
        let resolved_at_ms = Utc::now().timestamp_millis();

        sqlx::query!(
            "UPDATE healthcheck_event SET resolved_at = ?1 WHERE id = ?2",
            resolved_at_ms,
            id
        )
        .execute(&self.write_pool)
        .await?;

        Ok(())
    }

    /// Get active (unresolved) healthcheck events for a session.
    pub async fn get_active_session_events(&self, session_id: i64) -> Result<Vec<String>> {
        let records = sqlx::query!(
            r#"
            SELECT message
            FROM healthcheck_event
            WHERE session_id = ?1
              AND resolved_at IS NULL
            ORDER BY detected_at DESC
            "#,
            session_id
        )
        .fetch_all(&self.read_pool)
        .await?;

        Ok(records.into_iter().map(|r| r.message).collect())
    }

    /// Get active (unresolved) healthcheck events for a loadbalancer.
    pub async fn get_active_loadbalancer_events(
        &self,
        loadbalancer_id: i64,
    ) -> Result<Vec<String>> {
        let records = sqlx::query!(
            r#"
            SELECT message
            FROM healthcheck_event
            WHERE loadbalancer_id = ?1
              AND resolved_at IS NULL
            ORDER BY detected_at DESC
            "#,
            loadbalancer_id
        )
        .fetch_all(&self.read_pool)
        .await?;

        Ok(records.into_iter().map(|r| r.message).collect())
    }
}

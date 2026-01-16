// SPDX-License-Identifier: BSD-3-Clause-LBNL
//! Health check module for detecting issues with load balancers, reservations, and sessions.
//!
//! This module is organized by scope:
//! - `global.rs`: Health checks that operate at the global/system level
//! - `loadbalancer.rs`: Health checks specific to load balancers
//! - `reservation.rs`: Health checks specific to reservations
//! - `session.rs`: Health checks specific to sessions

pub mod global;
pub mod loadbalancer;
pub mod reservation;
pub mod session;

use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, info, warn};

use crate::db::LoadBalancerDB;
use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Configuration for the health check system.
#[derive(Clone, Debug)]
pub struct HealthCheckConfig {
    pub enabled: bool,
    pub interval: Duration,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: Duration::from_secs(10),
        }
    }
}

/// Severity level for health check events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthCheckSeverity {
    Warning,
    Error,
    Critical,
}

impl HealthCheckSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            HealthCheckSeverity::Warning => "warning",
            HealthCheckSeverity::Error => "error",
            HealthCheckSeverity::Critical => "critical",
        }
    }
}

impl std::fmt::Display for HealthCheckSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Represents a health check event that has been detected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckEvent {
    pub id: Option<i64>,
    pub event_type: String,
    pub severity: HealthCheckSeverity,
    pub loadbalancer_id: Option<i64>,
    pub reservation_id: Option<i64>,
    pub session_id: Option<i64>,
    pub message: String,
    pub details: Option<String>,
    pub detected_at: chrono::DateTime<Utc>,
    pub resolved_at: Option<chrono::DateTime<Utc>>,
}

impl HealthCheckEvent {
    pub fn new(
        event_type: impl Into<String>,
        severity: HealthCheckSeverity,
        message: impl Into<String>,
    ) -> Self {
        Self {
            id: None,
            event_type: event_type.into(),
            severity,
            loadbalancer_id: None,
            reservation_id: None,
            session_id: None,
            message: message.into(),
            details: None,
            detected_at: Utc::now(),
            resolved_at: None,
        }
    }

    pub fn with_session(mut self, session_id: i64) -> Self {
        self.session_id = Some(session_id);
        self
    }

    pub fn with_reservation(mut self, reservation_id: i64) -> Self {
        self.reservation_id = Some(reservation_id);
        self
    }

    pub fn with_loadbalancer(mut self, loadbalancer_id: i64) -> Self {
        self.loadbalancer_id = Some(loadbalancer_id);
        self
    }

    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }
}

/// Starts the health check background task.
/// This should be called from start_server in lib.rs.
/// If config.enabled is false, the health check is not started.
pub fn start_healthcheck(db: Arc<LoadBalancerDB>, config: HealthCheckConfig) {
    if !config.enabled {
        warn!("health check disabled by config");
        return;
    }
    let interval = config.interval;
    tokio::spawn(async move {
        info!("starting health check task (interval: {:?})", interval);
        loop {
            if let Err(e) = run_health_checks(&db).await {
                error!("health check error: {:?}", e);
            }
            sleep(interval).await;
        }
    });
}

/// Run all health checks across all scopes.
async fn run_health_checks(db: &LoadBalancerDB) -> Result<(), sqlx::Error> {
    // Global health checks
    global::run_checks(db).await?;

    // Load balancer health checks
    loadbalancer::run_checks(db).await?;

    // Reservation health checks
    reservation::run_checks(db).await?;

    // Session health checks
    session::run_checks(db).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_as_str() {
        assert_eq!(HealthCheckSeverity::Warning.as_str(), "warning");
        assert_eq!(HealthCheckSeverity::Error.as_str(), "error");
        assert_eq!(HealthCheckSeverity::Critical.as_str(), "critical");
    }

    #[test]
    fn test_event_builder() {
        let event = HealthCheckEvent::new("test_event", HealthCheckSeverity::Warning, "Test message")
            .with_session(1)
            .with_reservation(2)
            .with_loadbalancer(3)
            .with_details("test details");

        assert_eq!(event.event_type, "test_event");
        assert_eq!(event.severity, HealthCheckSeverity::Warning);
        assert_eq!(event.message, "Test message");
        assert_eq!(event.session_id, Some(1));
        assert_eq!(event.reservation_id, Some(2));
        assert_eq!(event.loadbalancer_id, Some(3));
        assert_eq!(event.details, Some("test details".to_string()));
    }
}

// SPDX-License-Identifier: BSD-3-Clause-LBNL
//! Session health checks.

use crate::db::LoadBalancerDB;
use crate::healthcheck::{HealthCheckEvent, HealthCheckSeverity};
use chrono::Utc;
use tracing::{debug, warn};

/// Run all session health checks.
pub async fn run_checks(db: &LoadBalancerDB) -> Result<(), sqlx::Error> {
    check_receiver_packet_stall(db).await?;
    Ok(())
}

/// Health check: Detect if the number of packets to a receiver has increased for >3s
/// (via stat_member_sample table) but that receiver has not reported any received packets
/// (via session_state table) in that same time period.
///
/// This indicates a potential issue where the FPGA is sending packets to a receiver
/// but the receiver is not reporting them, suggesting packet loss, misconfiguration,
/// or receiver failure.
async fn check_receiver_packet_stall(db: &LoadBalancerDB) -> Result<(), sqlx::Error> {
    let now_ms = Utc::now().timestamp_millis();
    let three_seconds_ago_ms = now_ms - 3000;

    // Query to find sessions where:
    // 1. stat_member_sample shows increasing tx_pkts in the last 3 seconds
    // 2. session_state shows no increase in total_packets_recv in the last 3 seconds
    let problematic_sessions = sqlx::query!(
        r#"
        WITH member_stats AS (
            SELECT
                session_id,
                MIN(sampled_at) as first_sample_ts,
                MAX(sampled_at) as last_sample_ts,
                MIN(mbr_tx_pkts) as first_tx_pkts,
                MAX(mbr_tx_pkts) as last_tx_pkts
            FROM stat_member_sample
            WHERE sampled_at >= ?1
              AND session_id IS NOT NULL
            GROUP BY session_id
            HAVING COUNT(*) >= 2
               AND MAX(mbr_tx_pkts) > MIN(mbr_tx_pkts)
        ),
        session_stats AS (
            SELECT
                session_id,
                MIN(timestamp) as first_timestamp,
                MAX(timestamp) as last_timestamp,
                MIN(total_packets_recv) as first_recv_pkts,
                MAX(total_packets_recv) as last_recv_pkts
            FROM session_state
            WHERE timestamp >= ?1
            GROUP BY session_id
            HAVING COUNT(*) >= 1
        )
        SELECT
            ms.session_id,
            ms.first_sample_ts,
            ms.last_sample_ts,
            ms.first_tx_pkts,
            ms.last_tx_pkts,
            COALESCE(ss.first_recv_pkts, 0) as first_recv_pkts,
            COALESCE(ss.last_recv_pkts, 0) as last_recv_pkts,
            s.name as session_name,
            s.reservation_id,
            r.loadbalancer_id
        FROM member_stats ms
        LEFT JOIN session_stats ss ON ms.session_id = ss.session_id
        JOIN session s ON ms.session_id = s.id
        JOIN reservation r ON s.reservation_id = r.id
        WHERE s.deleted_at IS NULL
          AND r.deleted_at IS NULL
          AND (ss.session_id IS NULL OR ss.last_recv_pkts = ss.first_recv_pkts)
        "#,
        three_seconds_ago_ms
    )
    .fetch_all(&db.read_pool)
    .await?;

    for row in problematic_sessions {
        // Session_id should always be present since we're joining with session table
        let Some(session_id) = row.session_id else {
            continue;
        };
        let session_name = row.session_name;
        let reservation_id = row.reservation_id;
        let loadbalancer_id = row.loadbalancer_id;
        let Some(last_tx_pkts) = row.last_tx_pkts else {
            continue;
        };
        let Some(first_tx_pkts) = row.first_tx_pkts else {
            continue;
        };
        let tx_pkts_delta = last_tx_pkts - first_tx_pkts;
        let recv_pkts_delta = row.last_recv_pkts - row.first_recv_pkts;

        // Check if there's already an active event for this session
        let existing_event = sqlx::query!(
            r#"
            SELECT id FROM healthcheck_event
            WHERE event_type = 'receiver_packet_stall'
              AND session_id = ?1
              AND resolved_at IS NULL
            LIMIT 1
            "#,
            session_id
        )
        .fetch_optional(&db.read_pool)
        .await?;

        if existing_event.is_none() {
            // Create a new event
            let message = format!(
                "Receiver '{}' (session_id={}) is not reporting received packets despite FPGA sending {} packets in the last 3 seconds",
                session_name, session_id, tx_pkts_delta
            );
            let details = serde_json::json!({
                "session_id": session_id,
                "session_name": session_name,
                "reservation_id": reservation_id,
                "loadbalancer_id": loadbalancer_id,
                "tx_packets_delta": tx_pkts_delta,
                "recv_packets_delta": recv_pkts_delta,
                "first_sampled_at": row.first_sample_ts,
                "last_sampled_at": row.last_sample_ts,
            })
            .to_string();

            let event =
                HealthCheckEvent::new("receiver_packet_stall", HealthCheckSeverity::Error, message)
                    .with_session(session_id)
                    .with_reservation(reservation_id)
                    .with_loadbalancer(loadbalancer_id)
                    .with_details(details);

            db.insert_healthcheck_event(&event)
                .await
                .map_err(|e| sqlx::Error::Io(std::io::Error::other(e.to_string())))?;
            warn!(
                "detected receiver_packet_stall for session_id={} ({})",
                session_id, session_name
            );
        } else {
            debug!(
                "receiver_packet_stall already reported for session_id={}",
                session_id
            );
        }
    }

    // Resolve events where the issue is no longer present
    // An event is resolved if:
    // 1. The session has been deleted, OR
    // 2. Recent session_state shows packets are being received (increase in last 10 seconds)
    let ten_seconds_ago_ms = now_ms - 10000;
    sqlx::query!(
        r#"
        UPDATE healthcheck_event
        SET resolved_at = ?1
        WHERE event_type = 'receiver_packet_stall'
          AND resolved_at IS NULL
          AND (
            -- Session has been deleted
            session_id IN (SELECT id FROM session WHERE deleted_at IS NOT NULL)
            OR
            -- Session is now receiving packets
            session_id IN (
                SELECT session_id
                FROM session_state
                WHERE timestamp >= ?2
                GROUP BY session_id
                HAVING MAX(total_packets_recv) > MIN(total_packets_recv)
            )
          )
        "#,
        now_ms,
        ten_seconds_ago_ms
    )
    .execute(&db.write_pool)
    .await?;

    Ok(())
}

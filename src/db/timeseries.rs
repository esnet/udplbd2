// SPDX-License-Identifier: BSD-3-Clause-LBNL
use crate::db::{LoadBalancerDB, Result};
use crate::errors::Error;
use crate::proto::loadbalancer::v1::{FloatSample, FloatTimeseries, Timeseries};
use chrono::{DateTime, Utc};
use sqlx::sqlite::SqliteRow;
use sqlx::Row;
use std::collections::HashMap;

// ============================================================================
// TIMESERIES REGISTRY: Route Pattern -> Handler Mapping
// ============================================================================
//
// This registry defines all supported timeseries routes and their handlers.
// Each route pattern maps to specific fetcher operations.
//
// Route Patterns:
//   /smartnic/global                                           -> All global metrics
//   /smartnic/global/{metric}                                  -> Single global metric
//   /lb/*                                                      -> All reservations
//   /lb/{reservation_id}/*                                     -> All metrics for reservation
//   /lb/{reservation_id}/{metric}                              -> Single reservation metric
//   /lb/{reservation_id}/session/*                             -> All sessions for reservation
//   /lb/{reservation_id}/session/{session_id}/*                -> All metrics for session
//   /lb/{reservation_id}/session/{session_id}/{metric}         -> Single session metric
//

/// Fetcher operations that can be performed
#[derive(Debug, Clone)]
enum FetcherOp {
    AllGlobalStats,
    GlobalStatMetric(String),
    AllReservations,
    ReservationLbStats(i64),
    ReservationEventMetrics(i64),
    ReservationEpoch(i64),
    ReservationEventMetric(i64, String),
    ReservationEpochMetric(i64),
    ReservationLbStatMetric(i64, String),
    ReservationAllSessions(i64),
    SessionAllMetrics(i64, i64),
    SessionMemberStats(i64, i64),
    SessionStateMetric(i64, i64, String),
    SessionMemberStatMetric(i64, String),
}

/// Represents a parsed route with its handler
#[derive(Debug)]
enum Route {
    SmartnicGlobal,
    SmartnicGlobalMetric(String),
    AllReservations,
    ReservationAll(i64),
    ReservationMetric(i64, String),
    ReservationAllSessions(i64),
    SessionAll(i64, i64),
    SessionMetric(i64, i64, String),
    Invalid,
}

impl Route {
    /// Parse a selector string into a Route
    fn parse(selector: &str) -> Self {
        let parts: Vec<&str> = selector.split('/').filter(|s| !s.is_empty()).collect();

        if parts.is_empty() {
            return Self::Invalid;
        }

        match parts[0] {
            "smartnic" => Self::parse_smartnic(&parts),
            "lb" => Self::parse_lb(&parts),
            _ => Self::Invalid,
        }
    }

    fn parse_smartnic(parts: &[&str]) -> Self {
        match parts.len() {
            2 if parts[1] == "global" => Self::SmartnicGlobal,
            3 if parts[1] == "global" => Self::SmartnicGlobalMetric(parts[2].to_string()),
            _ => Self::Invalid,
        }
    }

    fn parse_lb(parts: &[&str]) -> Self {
        if parts.len() < 2 {
            return Self::Invalid;
        }

        if parts[1] == "*" {
            return Self::AllReservations;
        }

        let reservation_id = match parts[1].parse::<i64>() {
            Ok(id) => id,
            Err(_) => return Self::Invalid,
        };

        match parts.len() {
            2 => Self::Invalid,
            3 => {
                if parts[2] == "*" {
                    Self::ReservationAll(reservation_id)
                } else {
                    Self::ReservationMetric(reservation_id, parts[2].to_string())
                }
            }
            4 if parts[2] == "session" && parts[3] == "*" => {
                Self::ReservationAllSessions(reservation_id)
            }
            5 if parts[2] == "session" => {
                let session_id = match parts[3].parse::<i64>() {
                    Ok(id) => id,
                    Err(_) => return Self::Invalid,
                };
                if parts[4] == "*" {
                    Self::SessionAll(reservation_id, session_id)
                } else {
                    Self::SessionMetric(reservation_id, session_id, parts[4].to_string())
                }
            }
            _ => Self::Invalid,
        }
    }

    /// Get the fetcher operations for this route
    fn fetchers(&self) -> Vec<FetcherOp> {
        match self {
            Route::SmartnicGlobal => vec![FetcherOp::AllGlobalStats],
            Route::SmartnicGlobalMetric(metric) => {
                vec![FetcherOp::GlobalStatMetric(metric.clone())]
            }
            Route::AllReservations => vec![FetcherOp::AllReservations],
            Route::ReservationAll(rid) => vec![
                FetcherOp::ReservationLbStats(*rid),
                FetcherOp::ReservationEventMetrics(*rid),
                FetcherOp::ReservationEpoch(*rid),
                FetcherOp::ReservationAllSessions(*rid),
            ],
            Route::ReservationMetric(rid, metric) => vec![
                FetcherOp::ReservationEventMetric(*rid, metric.clone()),
                FetcherOp::ReservationEpochMetric(*rid),
                FetcherOp::ReservationLbStatMetric(*rid, metric.clone()),
            ],
            Route::ReservationAllSessions(rid) => {
                vec![FetcherOp::ReservationAllSessions(*rid)]
            }
            Route::SessionAll(rid, sid) => vec![
                FetcherOp::SessionAllMetrics(*rid, *sid),
                FetcherOp::SessionMemberStats(*rid, *sid),
            ],
            Route::SessionMetric(rid, sid, metric) => vec![
                FetcherOp::SessionStateMetric(*rid, *sid, metric.clone()),
                FetcherOp::SessionMemberStatMetric(*sid, metric.clone()),
            ],
            Route::Invalid => vec![],
        }
    }
}

// ============================================================================
// VALIDATION HELPERS
// ============================================================================

async fn validate_reservation(db: &LoadBalancerDB, reservation_id: i64) -> Result<bool> {
    let reservation = sqlx::query!(
        "SELECT id FROM reservation WHERE id = ? AND deleted_at IS NULL",
        reservation_id
    )
    .fetch_optional(&db.read_pool)
    .await?;
    Ok(reservation.is_some())
}

async fn validate_session(
    db: &LoadBalancerDB,
    reservation_id: i64,
    session_id: i64,
) -> Result<bool> {
    let session = sqlx::query!(
        "SELECT reservation_id FROM session WHERE id = ? AND deleted_at IS NULL",
        session_id
    )
    .fetch_optional(&db.read_pool)
    .await?;
    Ok(session.is_some_and(|s| s.reservation_id == reservation_id))
}

// ============================================================================
// DATABASE IMPLEMENTATION
// ============================================================================

impl sqlx::FromRow<'_, SqliteRow> for FloatSample {
    fn from_row(row: &SqliteRow) -> std::result::Result<Self, sqlx::Error> {
        Ok(FloatSample {
            timestamp: row.try_get("timestamp")?,
            value: row.try_get("value")?,
            meta: None,
        })
    }
}

impl LoadBalancerDB {
    /// Insert a row into stat_global_sample.
    pub async fn insert_stat_global_sample(
        &self,
        sample: &crate::db::models::StatGlobalSample,
    ) -> Result<()> {
        sqlx::query!(
            "INSERT INTO stat_global_sample (
                sampled_at,
                rx_rslt_drop_parse_fail,
                rx_rslt_drop_mac_dst_miss,
                rx_rslt_drop_not_ip,
                rx_rslt_drop_ip_dst_miss,
                rx_rslt_drop_arp_bad_tpa,
                rx_rslt_drop_icmpv4_echo_bad_dst,
                rx_rslt_drop_icmpv6_echo_bad_dst,
                rx_rslt_drop_ipv6nd_neigh_sol_bad_target,
                rx_rslt_ok_arp_req,
                rx_rslt_ok_icmpv4_echo,
                rx_rslt_ok_icmpv6_echo,
                rx_rslt_ok_ipv6nd_neigh_sol,
                rx_rslt_ok_host,
                rx_rslt_ok_lb
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            sample.sampled_at,
            sample.rx_rslt[0],
            sample.rx_rslt[1],
            sample.rx_rslt[2],
            sample.rx_rslt[3],
            sample.rx_rslt[4],
            sample.rx_rslt[5],
            sample.rx_rslt[6],
            sample.rx_rslt[7],
            sample.rx_rslt[8],
            sample.rx_rslt[9],
            sample.rx_rslt[10],
            sample.rx_rslt[11],
            sample.rx_rslt[12],
            sample.rx_rslt[13]
        )
        .execute(&self.write_pool)
        .await?;
        Ok(())
    }

    /// Insert a row into stat_lb_sample.
    pub async fn insert_stat_lb_sample(
        &self,
        sample: &crate::db::models::StatLbSample,
    ) -> Result<()> {
        sqlx::query!(
            "INSERT INTO stat_lb_sample (
                reservation_id,
                sampled_at,
                drop_bad_udplb_version,
                drop_blocked_src,
                drop_epoch_assign_miss,
                drop_lb_calendar_miss,
                drop_mbr_info_miss,
                drop_no_udplb_hdr,
                drop_not_ip,
                rx_bytes,
                rx_packets,
                rx_v2,
                rx_v3
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            sample.reservation_id,
            sample.sampled_at,
            sample.drop_bad_udplb_version,
            sample.drop_blocked_src,
            sample.drop_epoch_assign_miss,
            sample.drop_lb_calendar_miss,
            sample.drop_mbr_info_miss,
            sample.drop_no_udplb_hdr,
            sample.drop_not_ip,
            sample.rx_bytes,
            sample.rx_packets,
            sample.rx_v2,
            sample.rx_v3
        )
        .execute(&self.write_pool)
        .await?;
        Ok(())
    }

    /// Insert a row into stat_lb_scoped_sample.
    pub async fn insert_stat_lb_scoped_sample(
        &self,
        sample: &crate::db::models::StatLbScopedSample,
    ) -> Result<()> {
        sqlx::query!(
            "INSERT INTO stat_lb_scoped_sample (
                reservation_id,
                stat_scope_id,
                sampled_at,
                rx_bytes,
                rx_packets
            ) VALUES (?, ?, ?, ?, ?)",
            sample.reservation_id,
            sample.stat_scope_id,
            sample.sampled_at,
            sample.rx_bytes,
            sample.rx_packets
        )
        .execute(&self.write_pool)
        .await?;
        Ok(())
    }

    /// Insert a row into stat_member_sample.
    pub async fn insert_stat_member_sample(
        &self,
        sample: &crate::db::models::StatMemberSample,
    ) -> Result<()> {
        sqlx::query!(
            "INSERT INTO stat_member_sample (
                session_id,
                sampled_at,
                mbr_tx_pkts,
                mbr_tx_bytes
            ) VALUES (?, ?, ?, ?)",
            sample.session_id,
            sample.sampled_at,
            sample.mbr_tx_pkts,
            sample.mbr_tx_bytes
        )
        .execute(&self.write_pool)
        .await?;
        Ok(())
    }

    /// Main entry point: resolve selectors to timeseries using the registry
    pub async fn get_timeseries(
        &self,
        selectors: &[String],
        since: &DateTime<Utc>,
    ) -> Result<Vec<Timeseries>> {
        let mut result = Vec::new();

        for selector in selectors {
            let route = Route::parse(selector);
            let fetchers = route.fetchers();

            for fetcher in fetchers {
                let mut ts = self.execute_fetcher(fetcher, since).await?;
                result.append(&mut ts);
            }
        }

        Ok(result)
    }

    /// Execute a fetcher operation
    async fn execute_fetcher(
        &self,
        op: FetcherOp,
        since: &DateTime<Utc>,
    ) -> Result<Vec<Timeseries>> {
        match op {
            FetcherOp::AllGlobalStats => self.get_all_global_stat_timeseries(since).await,
            FetcherOp::GlobalStatMetric(metric) => {
                match self.get_global_stat_timeseries(&metric, since).await {
                    Ok(ts) => Ok(vec![ts]),
                    Err(_) => Ok(vec![]),
                }
            }
            FetcherOp::AllReservations => {
                let reservations =
                    sqlx::query!("SELECT id FROM reservation WHERE deleted_at IS NULL")
                        .fetch_all(&self.read_pool)
                        .await?;

                let mut result = Vec::new();
                for res in reservations {
                    let mut res_ts = self.get_all_reservation_timeseries(res.id, since).await?;
                    let mut lb_stats = self.get_all_lb_stat_timeseries(res.id, since).await?;
                    result.append(&mut res_ts);
                    result.append(&mut lb_stats);
                }
                Ok(result)
            }
            FetcherOp::ReservationLbStats(reservation_id) => {
                if !validate_reservation(self, reservation_id).await? {
                    return Ok(vec![]);
                }
                self.get_all_lb_stat_timeseries(reservation_id, since).await
            }
            FetcherOp::ReservationEventMetrics(reservation_id) => {
                if !validate_reservation(self, reservation_id).await? {
                    return Ok(vec![]);
                }
                let mut result = Vec::new();
                for metric in ["event_number", "avg_event_rate_hz"] {
                    if let Ok(ts) = self
                        .get_event_number_timeseries(reservation_id, metric, since)
                        .await
                    {
                        result.push(ts);
                    }
                }
                Ok(result)
            }
            FetcherOp::ReservationEpoch(reservation_id) => {
                if !validate_reservation(self, reservation_id).await? {
                    return Ok(vec![]);
                }
                match self.get_epoch_timeseries(reservation_id, since).await {
                    Ok(ts) => Ok(vec![ts]),
                    Err(_) => Ok(vec![]),
                }
            }
            FetcherOp::ReservationEventMetric(reservation_id, metric) => {
                if !validate_reservation(self, reservation_id).await? {
                    return Ok(vec![]);
                }
                if metric == "event_number" || metric == "avg_event_rate_hz" {
                    match self
                        .get_event_number_timeseries(reservation_id, &metric, since)
                        .await
                    {
                        Ok(ts) => Ok(vec![ts]),
                        Err(_) => Ok(vec![]),
                    }
                } else {
                    Ok(vec![])
                }
            }
            FetcherOp::ReservationEpochMetric(reservation_id) => {
                if !validate_reservation(self, reservation_id).await? {
                    return Ok(vec![]);
                }
                match self.get_epoch_timeseries(reservation_id, since).await {
                    Ok(ts) => Ok(vec![ts]),
                    Err(_) => Ok(vec![]),
                }
            }
            FetcherOp::ReservationLbStatMetric(reservation_id, metric) => {
                if !validate_reservation(self, reservation_id).await? {
                    return Ok(vec![]);
                }
                match self
                    .get_lb_stat_timeseries(reservation_id, &metric, since)
                    .await
                {
                    Ok(ts) => Ok(vec![ts]),
                    Err(_) => Ok(vec![]),
                }
            }
            FetcherOp::ReservationAllSessions(reservation_id) => {
                if !validate_reservation(self, reservation_id).await? {
                    return Ok(vec![]);
                }
                let sessions = sqlx::query!(
                    "SELECT id FROM session WHERE reservation_id = ? AND deleted_at IS NULL",
                    reservation_id
                )
                .fetch_all(&self.read_pool)
                .await?;

                let mut result = Vec::new();
                for session in sessions {
                    let mut s_ts = self.get_all_session_timeseries(session.id, since).await?;
                    result.append(&mut s_ts);
                    let mut m_ts = self
                        .get_all_member_stat_timeseries(reservation_id, session.id, since)
                        .await?;
                    result.append(&mut m_ts);
                }
                Ok(result)
            }
            FetcherOp::SessionAllMetrics(reservation_id, session_id) => {
                if !validate_session(self, reservation_id, session_id).await? {
                    return Ok(vec![]);
                }
                self.get_all_session_timeseries(session_id, since).await
            }
            FetcherOp::SessionMemberStats(reservation_id, session_id) => {
                if !validate_session(self, reservation_id, session_id).await? {
                    return Ok(vec![]);
                }
                self.get_all_member_stat_timeseries(reservation_id, session_id, since)
                    .await
            }
            FetcherOp::SessionStateMetric(reservation_id, session_id, metric) => {
                if !validate_session(self, reservation_id, session_id).await? {
                    return Ok(vec![]);
                }
                match self
                    .get_session_timeseries(session_id, &metric, since)
                    .await
                {
                    Ok(ts) => Ok(vec![ts]),
                    Err(_) => Ok(vec![]),
                }
            }
            FetcherOp::SessionMemberStatMetric(session_id, metric) => {
                match self
                    .get_member_stat_timeseries(session_id, &metric, since)
                    .await
                {
                    Ok(ts) => Ok(vec![ts]),
                    Err(_) => Ok(vec![]),
                }
            }
        }
    }

    // ========================================================================
    // ATOMIC FETCHER METHODS: Called by execute_fetcher
    // ========================================================================

    pub async fn get_global_stat_timeseries(
        &self,
        metric: &str,
        since: &DateTime<Utc>,
    ) -> Result<Timeseries> {
        let column_name = match metric {
            "rx_rslt_drop_parse_fail"
            | "rx_rslt_drop_mac_dst_miss"
            | "rx_rslt_drop_not_ip"
            | "rx_rslt_drop_ip_dst_miss"
            | "rx_rslt_drop_arp_bad_tpa"
            | "rx_rslt_drop_icmpv4_echo_bad_dst"
            | "rx_rslt_drop_icmpv6_echo_bad_dst"
            | "rx_rslt_drop_ipv6nd_neigh_sol_bad_target"
            | "rx_rslt_ok_arp_req"
            | "rx_rslt_ok_icmpv4_echo"
            | "rx_rslt_ok_icmpv6_echo"
            | "rx_rslt_ok_ipv6nd_neigh_sol"
            | "rx_rslt_ok_host"
            | "rx_rslt_ok_lb" => metric,
            _ => {
                return Err(Error::Usage(format!(
                    "Invalid global stat metric: {}",
                    metric
                )))
            }
        };

        let ts_name = format!("/smartnic/global/{}", metric);
        let since_ms = since.timestamp_millis();
        let query = format!(
            "SELECT sampled_at as timestamp, CAST({} AS FLOAT) as value
             FROM stat_global_sample
             WHERE sampled_at >= ?
             ORDER BY sampled_at ASC",
            column_name
        );
        let samples = sqlx::query_as::<sqlx::Sqlite, FloatSample>(&query)
            .bind(since_ms)
            .fetch_all(&self.read_pool)
            .await?;
        let float_ts = FloatTimeseries { data: samples };
        Ok(Timeseries {
            name: ts_name,
            unit: "".to_string(),
            timeseries: Some(
                crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(float_ts),
            ),
        })
    }

    pub async fn get_lb_stat_timeseries(
        &self,
        reservation_id: i64,
        metric: &str,
        since: &DateTime<Utc>,
    ) -> Result<Timeseries> {
        let allowed_metrics = [
            "drop_bad_udplb_version",
            "drop_blocked_src",
            "drop_epoch_assign_miss",
            "drop_lb_calendar_miss",
            "drop_mbr_info_miss",
            "drop_no_udplb_hdr",
            "drop_not_ip",
            "rx_bytes",
            "rx_packets",
        ];
        if !allowed_metrics.contains(&metric) {
            return Err(Error::Usage(format!("Invalid lb stat metric: {}", metric)));
        }
        let ts_name = format!("/lb/{}/{}", reservation_id, metric);
        let since_ms = since.timestamp_millis();
        let query = format!(
            "SELECT sampled_at as timestamp, CAST({} AS FLOAT) as value
             FROM stat_lb_sample
             WHERE reservation_id = ? AND sampled_at >= ?
             ORDER BY sampled_at ASC",
            metric
        );
        let samples = sqlx::query_as::<sqlx::Sqlite, FloatSample>(&query)
            .bind(reservation_id)
            .bind(since_ms)
            .fetch_all(&self.read_pool)
            .await?;
        let float_ts = FloatTimeseries { data: samples };
        Ok(Timeseries {
            name: ts_name,
            unit: "".to_string(),
            timeseries: Some(
                crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(float_ts),
            ),
        })
    }

    pub async fn get_member_stat_timeseries(
        &self,
        session_id: i64,
        metric: &str,
        since: &DateTime<Utc>,
    ) -> Result<Timeseries> {
        let allowed_metrics = ["mbr_tx_pkts", "mbr_tx_bytes"];
        if !allowed_metrics.contains(&metric) {
            return Err(Error::Usage(format!(
                "Invalid member stat metric: {}",
                metric
            )));
        }
        let ts_name = format!("/lb/{{reservation_id}}/session/{}/{}", session_id, metric);
        let since_ms = since.timestamp_millis();
        let query = format!(
            "SELECT sampled_at as timestamp, CAST({} AS FLOAT) as value
             FROM stat_member_sample
             WHERE session_id = ? AND sampled_at >= ?
             ORDER BY sampled_at ASC",
            metric
        );
        let samples = sqlx::query_as::<sqlx::Sqlite, FloatSample>(&query)
            .bind(session_id)
            .bind(since_ms)
            .fetch_all(&self.read_pool)
            .await?;
        let float_ts = FloatTimeseries { data: samples };
        Ok(Timeseries {
            name: ts_name,
            unit: "".to_string(),
            timeseries: Some(
                crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(float_ts),
            ),
        })
    }

    pub async fn get_session_timeseries(
        &self,
        session_id: i64,
        metric: &str,
        since: &DateTime<Utc>,
    ) -> Result<Timeseries> {
        let column = match metric {
            "fill_percent"
            | "control_signal"
            | "is_ready"
            | "total_events_recv"
            | "total_events_reassembled"
            | "total_events_reassembly_err"
            | "total_events_dequeued"
            | "total_event_enqueue_err"
            | "total_bytes_recv"
            | "total_packets_recv" => metric,
            _ => return Err(Error::Usage(format!("Invalid session metric: {metric}"))),
        };

        let session = sqlx::query!(
            "SELECT s.name, s.reservation_id
             FROM session s
             WHERE s.id = ? AND s.deleted_at IS NULL",
            session_id
        )
        .fetch_optional(&self.read_pool)
        .await?
        .ok_or_else(|| Error::NotFound(format!("Session {session_id} not found")))?;

        let ts_name = format!(
            "/lb/{}/session/{}/{}",
            session.reservation_id, session_id, metric
        );
        let since_ms = since.timestamp_millis();
        let query = format!(
            "SELECT timestamp, CAST({column} AS FLOAT) as value
             FROM session_state
             WHERE session_id = ? AND timestamp >= ?
             ORDER BY timestamp ASC"
        );
        let samples = sqlx::query_as::<sqlx::Sqlite, FloatSample>(&query)
            .bind(session_id)
            .bind(since_ms)
            .fetch_all(&self.read_pool)
            .await?;
        let float_ts = FloatTimeseries { data: samples };
        Ok(Timeseries {
            name: ts_name,
            unit: "".to_string(),
            timeseries: Some(
                crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(float_ts),
            ),
        })
    }

    pub async fn get_event_number_timeseries(
        &self,
        reservation_id: i64,
        metric: &str,
        since: &DateTime<Utc>,
    ) -> Result<Timeseries> {
        let column = match metric {
            "event_number" | "avg_event_rate_hz" => metric,
            _ => {
                return Err(Error::Usage(format!(
                    "Invalid event number metric: {metric}"
                )))
            }
        };
        let _reservation = sqlx::query!(
            "SELECT id FROM reservation
             WHERE id = ? AND deleted_at IS NULL",
            reservation_id
        )
        .fetch_optional(&self.read_pool)
        .await?
        .ok_or_else(|| Error::NotFound(format!("Reservation {reservation_id} not found")))?;
        let ts_name = format!("/lb/{}/{}", reservation_id, metric);
        let since_ms = since.timestamp_millis();
        let query = format!(
            "SELECT local_timestamp as timestamp, CAST({column} AS FLOAT) as value
             FROM event_number
             WHERE reservation_id = ? AND local_timestamp >= ?
             ORDER BY local_timestamp ASC"
        );
        let samples = sqlx::query_as::<sqlx::Sqlite, FloatSample>(&query)
            .bind(reservation_id)
            .bind(since_ms)
            .fetch_all(&self.read_pool)
            .await?;
        let float_ts = FloatTimeseries { data: samples };
        Ok(Timeseries {
            name: ts_name,
            unit: "".to_string(),
            timeseries: Some(
                crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(float_ts),
            ),
        })
    }

    pub async fn get_epoch_timeseries(
        &self,
        reservation_id: i64,
        since: &DateTime<Utc>,
    ) -> Result<Timeseries> {
        let _reservation = sqlx::query!(
            "SELECT id FROM reservation
             WHERE id = ? AND deleted_at IS NULL",
            reservation_id
        )
        .fetch_optional(&self.read_pool)
        .await?
        .ok_or_else(|| Error::NotFound(format!("Reservation {reservation_id} not found")))?;
        let ts_name = format!("/lb/{}/epoch/boundary_event", reservation_id);
        let since_ms = since.timestamp_millis();
        let query = "SELECT predicted_at as timestamp, CAST(boundary_event AS FLOAT) as value
                     FROM epoch
                     WHERE reservation_id = ? AND predicted_at >= ? AND deleted_at IS NULL
                     ORDER BY predicted_at ASC";
        let samples = sqlx::query_as::<sqlx::Sqlite, FloatSample>(query)
            .bind(reservation_id)
            .bind(since_ms)
            .fetch_all(&self.read_pool)
            .await?;
        let float_ts = FloatTimeseries { data: samples };
        Ok(Timeseries {
            name: ts_name,
            unit: "".to_string(),
            timeseries: Some(
                crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(float_ts),
            ),
        })
    }

    pub async fn get_all_global_stat_timeseries(
        &self,
        since: &DateTime<Utc>,
    ) -> Result<Vec<Timeseries>> {
        let since_ms = since.timestamp_millis();
        let rows = sqlx::query!(
            "SELECT sampled_at,
                rx_rslt_drop_parse_fail,
                rx_rslt_drop_mac_dst_miss,
                rx_rslt_drop_not_ip,
                rx_rslt_drop_ip_dst_miss,
                rx_rslt_drop_arp_bad_tpa,
                rx_rslt_drop_icmpv4_echo_bad_dst,
                rx_rslt_drop_icmpv6_echo_bad_dst,
                rx_rslt_drop_ipv6nd_neigh_sol_bad_target,
                rx_rslt_ok_arp_req,
                rx_rslt_ok_icmpv4_echo,
                rx_rslt_ok_icmpv6_echo,
                rx_rslt_ok_ipv6nd_neigh_sol,
                rx_rslt_ok_host,
                rx_rslt_ok_lb
             FROM stat_global_sample
             WHERE sampled_at >= ?
             ORDER BY sampled_at ASC",
            since_ms
        )
        .fetch_all(&self.read_pool)
        .await?;

        let metric_names = [
            "rx_rslt_drop_parse_fail",
            "rx_rslt_drop_mac_dst_miss",
            "rx_rslt_drop_not_ip",
            "rx_rslt_drop_ip_dst_miss",
            "rx_rslt_drop_arp_bad_tpa",
            "rx_rslt_drop_icmpv4_echo_bad_dst",
            "rx_rslt_drop_icmpv6_echo_bad_dst",
            "rx_rslt_drop_ipv6nd_neigh_sol_bad_target",
            "rx_rslt_ok_arp_req",
            "rx_rslt_ok_icmpv4_echo",
            "rx_rslt_ok_icmpv6_echo",
            "rx_rslt_ok_ipv6nd_neigh_sol",
            "rx_rslt_ok_host",
            "rx_rslt_ok_lb",
        ];

        let mut metric_data: HashMap<&str, Vec<FloatSample>> = HashMap::new();
        for &name in &metric_names {
            metric_data.insert(name, Vec::new());
        }

        for row in rows {
            let ts = row.sampled_at;
            let values = [
                row.rx_rslt_drop_parse_fail,
                row.rx_rslt_drop_mac_dst_miss,
                row.rx_rslt_drop_not_ip,
                row.rx_rslt_drop_ip_dst_miss,
                row.rx_rslt_drop_arp_bad_tpa,
                row.rx_rslt_drop_icmpv4_echo_bad_dst,
                row.rx_rslt_drop_icmpv6_echo_bad_dst,
                row.rx_rslt_drop_ipv6nd_neigh_sol_bad_target,
                row.rx_rslt_ok_arp_req,
                row.rx_rslt_ok_icmpv4_echo,
                row.rx_rslt_ok_icmpv6_echo,
                row.rx_rslt_ok_ipv6nd_neigh_sol,
                row.rx_rslt_ok_host,
                row.rx_rslt_ok_lb,
            ];

            for (i, &name) in metric_names.iter().enumerate() {
                metric_data.get_mut(name).unwrap().push(FloatSample {
                    timestamp: ts,
                    value: values[i] as f32,
                    meta: None,
                });
            }
        }

        Ok(metric_names
            .iter()
            .map(|&name| Timeseries {
                name: format!("/smartnic/global/{}", name),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries {
                            data: metric_data.get(name).unwrap().clone(),
                        },
                    ),
                ),
            })
            .collect())
    }

    pub async fn get_all_lb_stat_timeseries(
        &self,
        reservation_id: i64,
        since: &DateTime<Utc>,
    ) -> Result<Vec<Timeseries>> {
        let since_ms = since.timestamp_millis();
        let rows = sqlx::query!(
            "SELECT sampled_at,
                drop_bad_udplb_version,
                drop_blocked_src,
                drop_epoch_assign_miss,
                drop_lb_calendar_miss,
                drop_mbr_info_miss,
                drop_no_udplb_hdr,
                drop_not_ip,
                rx_bytes,
                rx_packets
             FROM stat_lb_sample
             WHERE reservation_id = ? AND sampled_at >= ?
             ORDER BY sampled_at ASC",
            reservation_id,
            since_ms
        )
        .fetch_all(&self.read_pool)
        .await?;

        let metric_names = [
            "drop_bad_udplb_version",
            "drop_blocked_src",
            "drop_epoch_assign_miss",
            "drop_lb_calendar_miss",
            "drop_mbr_info_miss",
            "drop_no_udplb_hdr",
            "drop_not_ip",
            "rx_bytes",
            "rx_packets",
        ];

        let mut metric_data: HashMap<&str, Vec<FloatSample>> = HashMap::new();
        for &name in &metric_names {
            metric_data.insert(name, Vec::new());
        }

        for row in rows {
            let ts = row.sampled_at;
            let values = [
                row.drop_bad_udplb_version,
                row.drop_blocked_src,
                row.drop_epoch_assign_miss,
                row.drop_lb_calendar_miss,
                row.drop_mbr_info_miss,
                row.drop_no_udplb_hdr,
                row.drop_not_ip,
                row.rx_bytes,
                row.rx_packets,
            ];

            for (i, &name) in metric_names.iter().enumerate() {
                metric_data.get_mut(name).unwrap().push(FloatSample {
                    timestamp: ts,
                    value: values[i] as f32,
                    meta: None,
                });
            }
        }

        Ok(metric_names
            .iter()
            .map(|&name| Timeseries {
                name: format!("/lb/{}/{}", reservation_id, name),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries {
                            data: metric_data.get(name).unwrap().clone(),
                        },
                    ),
                ),
            })
            .collect())
    }

    pub async fn get_all_member_stat_timeseries(
        &self,
        reservation_id: i64,
        session_id: i64,
        since: &DateTime<Utc>,
    ) -> Result<Vec<Timeseries>> {
        let since_ms = since.timestamp_millis();
        let rows = sqlx::query!(
            "SELECT sampled_at, mbr_tx_pkts, mbr_tx_bytes
             FROM stat_member_sample
             WHERE session_id = ? AND sampled_at >= ?
             ORDER BY sampled_at ASC",
            session_id,
            since_ms
        )
        .fetch_all(&self.read_pool)
        .await?;

        let mut mbr_tx_pkts = Vec::new();
        let mut mbr_tx_bytes = Vec::new();

        for row in rows {
            let ts = row.sampled_at;
            mbr_tx_pkts.push(FloatSample {
                timestamp: ts,
                value: row.mbr_tx_pkts as f32,
                meta: None,
            });
            mbr_tx_bytes.push(FloatSample {
                timestamp: ts,
                value: row.mbr_tx_bytes as f32,
                meta: None,
            });
        }

        Ok(vec![
            Timeseries {
                name: format!("/lb/{}/session/{}/mbr_tx_pkts", reservation_id, session_id),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries { data: mbr_tx_pkts },
                    ),
                ),
            },
            Timeseries {
                name: format!("/lb/{}/session/{}/mbr_tx_bytes", reservation_id, session_id),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries { data: mbr_tx_bytes },
                    ),
                ),
            },
        ])
    }

    pub async fn get_all_session_timeseries(
        &self,
        session_id: i64,
        since: &DateTime<Utc>,
    ) -> Result<Vec<Timeseries>> {
        let session = sqlx::query!(
            "SELECT s.name, s.reservation_id
             FROM session s
             WHERE s.id = ? AND s.deleted_at IS NULL",
            session_id
        )
        .fetch_optional(&self.read_pool)
        .await?
        .ok_or_else(|| Error::NotFound(format!("Session {session_id} not found")))?;

        let since_ms = since.timestamp_millis();
        let rows = sqlx::query!(
            "SELECT
                timestamp,
                fill_percent,
                control_signal,
                is_ready,
                total_events_recv,
                total_events_reassembled,
                total_events_reassembly_err,
                total_events_dequeued,
                total_event_enqueue_err,
                total_bytes_recv,
                total_packets_recv
             FROM session_state
             WHERE session_id = ? AND timestamp >= ?
             ORDER BY timestamp ASC",
            session_id,
            since_ms
        )
        .fetch_all(&self.read_pool)
        .await?;

        let metrics = [
            "fill_percent",
            "control_signal",
            "is_ready",
            "total_events_recv",
            "total_events_reassembled",
            "total_events_reassembly_err",
            "total_events_dequeued",
            "total_event_enqueue_err",
            "total_bytes_recv",
            "total_packets_recv",
        ];
        let mut metric_map: HashMap<&str, Vec<FloatSample>> = HashMap::new();
        for &m in &metrics {
            metric_map.insert(m, Vec::new());
        }
        for row in rows {
            for &m in &metrics {
                let value = match m {
                    "fill_percent" => row.fill_percent as f32,
                    "control_signal" => row.control_signal as f32,
                    "is_ready"
                        if row.is_ready => {
                            1.0
                        }
                    "total_events_recv" => row.total_events_recv as f32,
                    "total_events_reassembled" => row.total_events_reassembled as f32,
                    "total_events_reassembly_err" => row.total_events_reassembly_err as f32,
                    "total_events_dequeued" => row.total_events_dequeued as f32,
                    "total_event_enqueue_err" => row.total_event_enqueue_err as f32,
                    "total_bytes_recv" => row.total_bytes_recv as f32,
                    "total_packets_recv" => row.total_packets_recv as f32,
                    _ => 0.0,
                };
                let sample = FloatSample {
                    timestamp: row.timestamp,
                    value,
                    meta: None,
                };
                if let Some(vec) = metric_map.get_mut(m) {
                    vec.push(sample);
                }
            }
        }
        let mut result = Vec::new();
        for &m in &metrics {
            let ts_name = format!(
                "/lb/{}/session/{}/{}",
                session.reservation_id, session_id, m
            );
            if let Some(samples) = metric_map.get(m) {
                let float_ts = FloatTimeseries {
                    data: samples.clone(),
                };
                result.push(Timeseries {
                    name: ts_name,
                    unit: "".to_string(),
                    timeseries: Some(
                        crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                            float_ts,
                        ),
                    ),
                });
            }
        }
        Ok(result)
    }

    pub async fn get_all_reservation_timeseries(
        &self,
        reservation_id: i64,
        since: &DateTime<Utc>,
    ) -> Result<Vec<Timeseries>> {
        let mut result = Vec::new();
        let _reservation = sqlx::query!(
            "SELECT id FROM reservation
             WHERE id = ? AND deleted_at IS NULL",
            reservation_id
        )
        .fetch_optional(&self.read_pool)
        .await?
        .ok_or_else(|| Error::NotFound(format!("Reservation {reservation_id} not found")))?;

        for metric in ["event_number", "avg_event_rate_hz"].iter() {
            let ts = self
                .get_event_number_timeseries(reservation_id, metric, since)
                .await?;
            result.push(ts);
        }
        let epoch_ts = self.get_epoch_timeseries(reservation_id, since).await?;
        result.push(epoch_ts);

        let sessions = sqlx::query!(
            "SELECT id FROM session WHERE reservation_id = ? AND deleted_at IS NULL",
            reservation_id
        )
        .fetch_all(&self.read_pool)
        .await?;

        for session in sessions {
            let mut s_ts = self.get_all_session_timeseries(session.id, since).await?;
            result.append(&mut s_ts);
            let mut m_ts = self
                .get_all_member_stat_timeseries(reservation_id, session.id, since)
                .await?;
            result.append(&mut m_ts);
        }
        Ok(result)
    }

    pub async fn get_all_loadbalancer_timeseries(
        &self,
        lb_id: i64,
        since: &DateTime<Utc>,
    ) -> Result<Vec<Timeseries>> {
        let mut result = Vec::new();
        let reservations = sqlx::query!(
            "SELECT id FROM reservation
             WHERE loadbalancer_id = ?
             AND deleted_at IS NULL
             AND reserved_until > unixepoch('subsec') * 1000",
            lb_id
        )
        .fetch_all(&self.read_pool)
        .await?;
        for reservation in reservations {
            let mut res_ts = self
                .get_all_reservation_timeseries(reservation.id, since)
                .await?;
            result.append(&mut res_ts);
        }
        Ok(result)
    }
}

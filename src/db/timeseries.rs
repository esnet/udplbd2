use crate::db::{LoadBalancerDB, Result};
use crate::errors::Error;
use crate::proto::loadbalancer::v1::{FloatSample, FloatTimeseries, Timeseries};
use chrono::{DateTime, Utc};
use sqlx::sqlite::SqliteRow;
use sqlx::Row;
use std::collections::HashMap;

// Implement sqlx::FromRow for the generated FloatSample type.
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
    // Fetch timeseries data for session metrics and return a protobuf Timeseries.
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
            _ => return Err(Error::Usage(format!("Invalid session metric: {}", metric))),
        };

        let session = sqlx::query!(
            "SELECT s.name, s.reservation_id, r.loadbalancer_id
             FROM session s
             JOIN reservation r ON s.reservation_id = r.id
             WHERE s.id = ? AND s.deleted_at IS NULL",
            session_id
        )
        .fetch_optional(&self.read_pool)
        .await?
        .ok_or_else(|| Error::NotFound(format!("Session {} not found", session_id)))?;

        let ts_name = format!(
            "/lb/{}/reservation/{}/session/{}/{}",
            session.loadbalancer_id, session.reservation_id, session_id, metric
        );
        let since_ms = since.timestamp_millis();
        let query = format!(
            "SELECT timestamp, CAST({} AS FLOAT) as value
             FROM session_state
             WHERE session_id = ? AND timestamp >= ?
             ORDER BY timestamp ASC",
            column
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

    // Fetch timeseries data for reservation event numbers.
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
                    "Invalid event number metric: {}",
                    metric
                )))
            }
        };
        let reservation = sqlx::query!(
            "SELECT loadbalancer_id FROM reservation
             WHERE id = ? AND deleted_at IS NULL",
            reservation_id
        )
        .fetch_optional(&self.read_pool)
        .await?
        .ok_or_else(|| Error::NotFound(format!("Reservation {} not found", reservation_id)))?;
        let ts_name = format!(
            "/lb/{}/reservation/{}/{}",
            reservation.loadbalancer_id, reservation_id, metric
        );
        let since_ms = since.timestamp_millis();
        let query = format!(
            "SELECT local_timestamp as timestamp, CAST({} AS FLOAT) as value
             FROM event_number
             WHERE reservation_id = ? AND local_timestamp >= ?
             ORDER BY local_timestamp ASC",
            column
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

    // Fetch timeseries data for epoch boundaries.
    pub async fn get_epoch_timeseries(
        &self,
        reservation_id: i64,
        since: &DateTime<Utc>,
    ) -> Result<Timeseries> {
        let reservation = sqlx::query!(
            "SELECT loadbalancer_id FROM reservation
             WHERE id = ? AND deleted_at IS NULL",
            reservation_id
        )
        .fetch_optional(&self.read_pool)
        .await?
        .ok_or_else(|| Error::NotFound(format!("Reservation {} not found", reservation_id)))?;
        let ts_name = format!(
            "/lb/{}/reservation/{}/epoch/boundary_event",
            reservation.loadbalancer_id, reservation_id
        );
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

    // Aggregates all session metrics for a given session.
    pub async fn get_all_session_timeseries(
        &self,
        session_id: i64,
        since: &DateTime<Utc>,
    ) -> Result<Vec<Timeseries>> {
        let session = sqlx::query!(
            "SELECT s.name, s.reservation_id, r.loadbalancer_id
             FROM session s
             JOIN reservation r ON s.reservation_id = r.id
             WHERE s.id = ? AND s.deleted_at IS NULL",
            session_id
        )
        .fetch_optional(&self.read_pool)
        .await?
        .ok_or_else(|| Error::NotFound(format!("Session {} not found", session_id)))?;

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
                    "is_ready" => {
                        if row.is_ready {
                            1.0
                        } else {
                            0.0
                        }
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
                "/lb/{}/reservation/{}/session/{}/{}",
                session.loadbalancer_id, session.reservation_id, session_id, m
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

    // Aggregates all timeseries for a reservation, including event metrics, epoch, and session data.
    pub async fn get_all_reservation_timeseries(
        &self,
        reservation_id: i64,
        since: &DateTime<Utc>,
    ) -> Result<Vec<Timeseries>> {
        let mut result = Vec::new();
        let _reservation = sqlx::query!(
            "SELECT loadbalancer_id FROM reservation
             WHERE id = ? AND deleted_at IS NULL",
            reservation_id
        )
        .fetch_optional(&self.read_pool)
        .await?
        .ok_or_else(|| Error::NotFound(format!("Reservation {} not found", reservation_id)))?;

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
        }
        Ok(result)
    }

    // Aggregates all timeseries for a loadbalancer.
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

    // Resolves selectors into corresponding timeseries.
    pub async fn get_timeseries(
        &self,
        selectors: &[String],
        since: &DateTime<Utc>,
    ) -> Result<Vec<Timeseries>> {
        let mut result = Vec::new();
        for selector in selectors {
            let parts: Vec<&str> = selector.split('/').filter(|s| !s.is_empty()).collect();
            if parts.is_empty() {
                continue;
            }
            match parts[0] {
                "lb" => {
                    if parts.len() < 2 {
                        continue;
                    }
                    if parts[1] == "*" {
                        let lbs = self.list_loadbalancers().await?;
                        for lb in lbs {
                            let mut lb_ts =
                                self.get_all_loadbalancer_timeseries(lb.id, since).await?;
                            result.append(&mut lb_ts);
                        }
                        continue;
                    }
                    let lb_id = match parts[1].parse::<i64>() {
                        Ok(id) => id,
                        Err(_) => continue,
                    };
                    if parts.len() == 2 || parts[2] == "*" {
                        let mut lb_ts = self.get_all_loadbalancer_timeseries(lb_id, since).await?;
                        result.append(&mut lb_ts);
                    } else if parts[2] == "reservation" {
                        if parts.len() < 4 {
                            continue;
                        }
                        if parts[3] == "*" {
                            let reservations = sqlx::query!(
                                "SELECT id FROM reservation WHERE loadbalancer_id = ? AND deleted_at IS NULL AND reserved_until > unixepoch('subsec') * 1000",
                                lb_id
                            )
                            .fetch_all(&self.read_pool)
                            .await?;
                            for res in reservations {
                                let mut res_ts =
                                    self.get_all_reservation_timeseries(res.id, since).await?;
                                result.append(&mut res_ts);
                            }
                            continue;
                        }
                        let res_id = match parts[3].parse::<i64>() {
                            Ok(id) => id,
                            Err(_) => continue,
                        };
                        let reservation = sqlx::query!(
                            "SELECT loadbalancer_id FROM reservation WHERE id = ? AND deleted_at IS NULL",
                            res_id
                        )
                        .fetch_optional(&self.read_pool)
                        .await?;
                        if let Some(r) = reservation {
                            if r.loadbalancer_id != lb_id {
                                continue;
                            }
                        } else {
                            continue;
                        }
                        if parts.len() == 4 || parts[4] == "*" {
                            let mut res_ts =
                                self.get_all_reservation_timeseries(res_id, since).await?;
                            result.append(&mut res_ts);
                        } else if parts[4] == "session" {
                            if parts.len() < 6 {
                                continue;
                            }
                            if parts[5] == "*" {
                                let sessions = sqlx::query!(
                                    "SELECT id FROM session WHERE reservation_id = ? AND deleted_at IS NULL",
                                    res_id
                                )
                                .fetch_all(&self.read_pool)
                                .await?;
                                for session in sessions {
                                    let mut s_ts =
                                        self.get_all_session_timeseries(session.id, since).await?;
                                    result.append(&mut s_ts);
                                }
                                continue;
                            }
                            let session_id = match parts[5].parse::<i64>() {
                                Ok(id) => id,
                                Err(_) => continue,
                            };
                            let session = sqlx::query!(
                                "SELECT reservation_id FROM session WHERE id = ? AND deleted_at IS NULL",
                                session_id
                            )
                            .fetch_optional(&self.read_pool)
                            .await?;
                            if let Some(s) = session {
                                if s.reservation_id != res_id {
                                    continue;
                                }
                            } else {
                                continue;
                            }
                            if parts.len() == 6 || parts[6] == "*" {
                                let mut s_ts =
                                    self.get_all_session_timeseries(session_id, since).await?;
                                result.append(&mut s_ts);
                            } else {
                                let metric = parts[6];
                                if let Ok(ts) =
                                    self.get_session_timeseries(session_id, metric, since).await
                                {
                                    result.push(ts);
                                }
                            }
                        } else if parts[4] == "event_number" || parts[4] == "avg_event_rate_hz" {
                            if let Ok(ts) = self
                                .get_event_number_timeseries(res_id, parts[4], since)
                                .await
                            {
                                result.push(ts);
                            }
                        } else if parts[4] == "epoch"
                            && parts.len() > 5
                            && parts[5] == "boundary_event"
                        {
                            if let Ok(ts) = self.get_epoch_timeseries(res_id, since).await {
                                result.push(ts);
                            }
                        }
                    }
                }
                _ => continue,
            }
        }
        Ok(result)
    }
}

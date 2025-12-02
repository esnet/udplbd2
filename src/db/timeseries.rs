// SPDX-License-Identifier: BSD-3-Clause-LBNL
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
    /// Insert a row into stat_global_sample.
    pub async fn insert_stat_global_sample(
        &self,
        sample: &crate::db::models::StatGlobalSample,
    ) -> Result<()> {
        sqlx::query!(
            "INSERT INTO stat_global_sample (
                sample_ts_ms,
                rx_rslt_0, rx_rslt_1, rx_rslt_2, rx_rslt_3, rx_rslt_4, rx_rslt_5, rx_rslt_6,
                rx_rslt_7, rx_rslt_8, rx_rslt_9, rx_rslt_10, rx_rslt_11, rx_rslt_12, rx_rslt_13
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            sample.sample_ts_ms,
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
                sample_ts_ms,
                drop_blocked_src,
                drop_epoch_assign_miss,
                drop_lb_calendar_miss,
                drop_mbr_info_miss,
                drop_no_udplb_hdr,
                drop_not_ip,
                lb_ctx_rx_bytes,
                pkt_rx_bytes,
                pkt_rx_pkts
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            sample.reservation_id,
            sample.sample_ts_ms,
            sample.drop_blocked_src,
            sample.drop_epoch_assign_miss,
            sample.drop_lb_calendar_miss,
            sample.drop_mbr_info_miss,
            sample.drop_no_udplb_hdr,
            sample.drop_not_ip,
            sample.lb_ctx_rx_bytes,
            sample.pkt_rx_bytes,
            sample.pkt_rx_pkts
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
                sample_ts_ms,
                mbr_tx_pkts,
                mbr_tx_bytes
            ) VALUES (?, ?, ?, ?)",
            sample.session_id,
            sample.sample_ts_ms,
            sample.mbr_tx_pkts,
            sample.mbr_tx_bytes
        )
        .execute(&self.write_pool)
        .await?;
        Ok(())
    }

    // Fetch timeseries data for stat_global_sample (SmartNIC global metrics).
    pub async fn get_global_stat_timeseries(
        &self,
        metric: &str,
        since: &DateTime<Utc>,
    ) -> Result<Timeseries> {
        // Only allow rx_rslt_0..rx_rslt_13
        let allowed_metrics = [
            "rx_rslt_0",
            "rx_rslt_1",
            "rx_rslt_2",
            "rx_rslt_3",
            "rx_rslt_4",
            "rx_rslt_5",
            "rx_rslt_6",
            "rx_rslt_7",
            "rx_rslt_8",
            "rx_rslt_9",
            "rx_rslt_10",
            "rx_rslt_11",
            "rx_rslt_12",
            "rx_rslt_13",
        ];
        if !allowed_metrics.contains(&metric) {
            return Err(Error::Usage(format!(
                "Invalid global stat metric: {}",
                metric
            )));
        }
        let ts_name = format!("/smartnic/global/{}", metric);
        let since_ms = since.timestamp_millis();
        let query = format!(
            "SELECT sample_ts_ms as timestamp, CAST({} AS FLOAT) as value
             FROM stat_global_sample
             WHERE sample_ts_ms >= ?
             ORDER BY sample_ts_ms ASC",
            metric
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

    // Fetch timeseries data for stat_lb_sample (SmartNIC per-LB metrics).
    pub async fn get_lb_stat_timeseries(
        &self,
        reservation_id: i64,
        metric: &str,
        since: &DateTime<Utc>,
    ) -> Result<Timeseries> {
        // Only allow drop and rx counter columns
        let allowed_metrics = [
            "drop_blocked_src",
            "drop_epoch_assign_miss",
            "drop_lb_calendar_miss",
            "drop_mbr_info_miss",
            "drop_no_udplb_hdr",
            "drop_not_ip",
            "lb_ctx_rx_bytes",
            "pkt_rx_bytes",
            "pkt_rx_pkts",
        ];
        if !allowed_metrics.contains(&metric) {
            return Err(Error::Usage(format!("Invalid lb stat metric: {}", metric)));
        }
        let ts_name = format!("/lb/{}/{}", reservation_id, metric);
        let since_ms = since.timestamp_millis();
        let query = format!(
            "SELECT sample_ts_ms as timestamp, CAST({} AS FLOAT) as value
             FROM stat_lb_sample
             WHERE reservation_id = ? AND sample_ts_ms >= ?
             ORDER BY sample_ts_ms ASC",
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

    // Fetch timeseries data for stat_member_sample (SmartNIC per-member metrics).
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
            "SELECT sample_ts_ms as timestamp, CAST({} AS FLOAT) as value
             FROM stat_member_sample
             WHERE session_id = ? AND sample_ts_ms >= ?
             ORDER BY sample_ts_ms ASC",
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

    // Efficiently fetch all stat_global_sample metrics as timeseries.
    pub async fn get_all_global_stat_timeseries(
        &self,
        since: &DateTime<Utc>,
    ) -> Result<Vec<Timeseries>> {
        let since_ms = since.timestamp_millis();
        let rows = sqlx::query!(
            "SELECT sample_ts_ms,
                rx_rslt_0, rx_rslt_1, rx_rslt_2, rx_rslt_3, rx_rslt_4, rx_rslt_5, rx_rslt_6,
                rx_rslt_7, rx_rslt_8, rx_rslt_9, rx_rslt_10, rx_rslt_11, rx_rslt_12, rx_rslt_13
             FROM stat_global_sample
             WHERE sample_ts_ms >= ?
             ORDER BY sample_ts_ms ASC",
            since_ms
        )
        .fetch_all(&self.read_pool)
        .await?;

        let mut rx_rslt_0 = Vec::new();
        let mut rx_rslt_1 = Vec::new();
        let mut rx_rslt_2 = Vec::new();
        let mut rx_rslt_3 = Vec::new();
        let mut rx_rslt_4 = Vec::new();
        let mut rx_rslt_5 = Vec::new();
        let mut rx_rslt_6 = Vec::new();
        let mut rx_rslt_7 = Vec::new();
        let mut rx_rslt_8 = Vec::new();
        let mut rx_rslt_9 = Vec::new();
        let mut rx_rslt_10 = Vec::new();
        let mut rx_rslt_11 = Vec::new();
        let mut rx_rslt_12 = Vec::new();
        let mut rx_rslt_13 = Vec::new();

        for row in rows {
            let ts = row.sample_ts_ms;
            rx_rslt_0.push(FloatSample {
                timestamp: ts,
                value: row.rx_rslt_0 as f32,
                meta: None,
            });
            rx_rslt_1.push(FloatSample {
                timestamp: ts,
                value: row.rx_rslt_1 as f32,
                meta: None,
            });
            rx_rslt_2.push(FloatSample {
                timestamp: ts,
                value: row.rx_rslt_2 as f32,
                meta: None,
            });
            rx_rslt_3.push(FloatSample {
                timestamp: ts,
                value: row.rx_rslt_3 as f32,
                meta: None,
            });
            rx_rslt_4.push(FloatSample {
                timestamp: ts,
                value: row.rx_rslt_4 as f32,
                meta: None,
            });
            rx_rslt_5.push(FloatSample {
                timestamp: ts,
                value: row.rx_rslt_5 as f32,
                meta: None,
            });
            rx_rslt_6.push(FloatSample {
                timestamp: ts,
                value: row.rx_rslt_6 as f32,
                meta: None,
            });
            rx_rslt_7.push(FloatSample {
                timestamp: ts,
                value: row.rx_rslt_7 as f32,
                meta: None,
            });
            rx_rslt_8.push(FloatSample {
                timestamp: ts,
                value: row.rx_rslt_8 as f32,
                meta: None,
            });
            rx_rslt_9.push(FloatSample {
                timestamp: ts,
                value: row.rx_rslt_9 as f32,
                meta: None,
            });
            rx_rslt_10.push(FloatSample {
                timestamp: ts,
                value: row.rx_rslt_10 as f32,
                meta: None,
            });
            rx_rslt_11.push(FloatSample {
                timestamp: ts,
                value: row.rx_rslt_11 as f32,
                meta: None,
            });
            rx_rslt_12.push(FloatSample {
                timestamp: ts,
                value: row.rx_rslt_12 as f32,
                meta: None,
            });
            rx_rslt_13.push(FloatSample {
                timestamp: ts,
                value: row.rx_rslt_13 as f32,
                meta: None,
            });
        }

        Ok(vec![
            Timeseries {
                name: "/smartnic/global/rx_rslt_0".to_string(),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries { data: rx_rslt_0 },
                    ),
                ),
            },
            Timeseries {
                name: "/smartnic/global/rx_rslt_1".to_string(),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries { data: rx_rslt_1 },
                    ),
                ),
            },
            Timeseries {
                name: "/smartnic/global/rx_rslt_2".to_string(),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries { data: rx_rslt_2 },
                    ),
                ),
            },
            Timeseries {
                name: "/smartnic/global/rx_rslt_3".to_string(),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries { data: rx_rslt_3 },
                    ),
                ),
            },
            Timeseries {
                name: "/smartnic/global/rx_rslt_4".to_string(),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries { data: rx_rslt_4 },
                    ),
                ),
            },
            Timeseries {
                name: "/smartnic/global/rx_rslt_5".to_string(),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries { data: rx_rslt_5 },
                    ),
                ),
            },
            Timeseries {
                name: "/smartnic/global/rx_rslt_6".to_string(),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries { data: rx_rslt_6 },
                    ),
                ),
            },
            Timeseries {
                name: "/smartnic/global/rx_rslt_7".to_string(),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries { data: rx_rslt_7 },
                    ),
                ),
            },
            Timeseries {
                name: "/smartnic/global/rx_rslt_8".to_string(),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries { data: rx_rslt_8 },
                    ),
                ),
            },
            Timeseries {
                name: "/smartnic/global/rx_rslt_9".to_string(),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries { data: rx_rslt_9 },
                    ),
                ),
            },
            Timeseries {
                name: "/smartnic/global/rx_rslt_10".to_string(),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries { data: rx_rslt_10 },
                    ),
                ),
            },
            Timeseries {
                name: "/smartnic/global/rx_rslt_11".to_string(),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries { data: rx_rslt_11 },
                    ),
                ),
            },
            Timeseries {
                name: "/smartnic/global/rx_rslt_12".to_string(),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries { data: rx_rslt_12 },
                    ),
                ),
            },
            Timeseries {
                name: "/smartnic/global/rx_rslt_13".to_string(),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries { data: rx_rslt_13 },
                    ),
                ),
            },
        ])
    }

    // Efficiently fetch all stat_lb_sample metrics as timeseries for a reservation.
    pub async fn get_all_lb_stat_timeseries(
        &self,
        reservation_id: i64,
        since: &DateTime<Utc>,
    ) -> Result<Vec<Timeseries>> {
        let since_ms = since.timestamp_millis();
        let rows = sqlx::query!(
            "SELECT sample_ts_ms,
                drop_blocked_src,
                drop_epoch_assign_miss,
                drop_lb_calendar_miss,
                drop_mbr_info_miss,
                drop_no_udplb_hdr,
                drop_not_ip,
                lb_ctx_rx_bytes,
                pkt_rx_bytes,
                pkt_rx_pkts
             FROM stat_lb_sample
             WHERE reservation_id = ? AND sample_ts_ms >= ?
             ORDER BY sample_ts_ms ASC",
            reservation_id,
            since_ms
        )
        .fetch_all(&self.read_pool)
        .await?;

        let mut drop_blocked_src = Vec::new();
        let mut drop_epoch_assign_miss = Vec::new();
        let mut drop_lb_calendar_miss = Vec::new();
        let mut drop_mbr_info_miss = Vec::new();
        let mut drop_no_udplb_hdr = Vec::new();
        let mut drop_not_ip = Vec::new();
        let mut lb_ctx_rx_bytes = Vec::new();
        let mut pkt_rx_bytes = Vec::new();
        let mut pkt_rx_pkts = Vec::new();

        for row in rows {
            let ts = row.sample_ts_ms;
            drop_blocked_src.push(FloatSample {
                timestamp: ts,
                value: row.drop_blocked_src as f32,
                meta: None,
            });
            drop_epoch_assign_miss.push(FloatSample {
                timestamp: ts,
                value: row.drop_epoch_assign_miss as f32,
                meta: None,
            });
            drop_lb_calendar_miss.push(FloatSample {
                timestamp: ts,
                value: row.drop_lb_calendar_miss as f32,
                meta: None,
            });
            drop_mbr_info_miss.push(FloatSample {
                timestamp: ts,
                value: row.drop_mbr_info_miss as f32,
                meta: None,
            });
            drop_no_udplb_hdr.push(FloatSample {
                timestamp: ts,
                value: row.drop_no_udplb_hdr as f32,
                meta: None,
            });
            drop_not_ip.push(FloatSample {
                timestamp: ts,
                value: row.drop_not_ip as f32,
                meta: None,
            });
            lb_ctx_rx_bytes.push(FloatSample {
                timestamp: ts,
                value: row.lb_ctx_rx_bytes as f32,
                meta: None,
            });
            pkt_rx_bytes.push(FloatSample {
                timestamp: ts,
                value: row.pkt_rx_bytes as f32,
                meta: None,
            });
            pkt_rx_pkts.push(FloatSample {
                timestamp: ts,
                value: row.pkt_rx_pkts as f32,
                meta: None,
            });
        }

        Ok(vec![
            Timeseries {
                name: format!("/lb/{}/drop_blocked_src", reservation_id),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries {
                            data: drop_blocked_src,
                        },
                    ),
                ),
            },
            Timeseries {
                name: format!("/lb/{}/drop_epoch_assign_miss", reservation_id),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries {
                            data: drop_epoch_assign_miss,
                        },
                    ),
                ),
            },
            Timeseries {
                name: format!("/lb/{}/drop_lb_calendar_miss", reservation_id),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries {
                            data: drop_lb_calendar_miss,
                        },
                    ),
                ),
            },
            Timeseries {
                name: format!("/lb/{}/drop_mbr_info_miss", reservation_id),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries {
                            data: drop_mbr_info_miss,
                        },
                    ),
                ),
            },
            Timeseries {
                name: format!("/lb/{}/drop_no_udplb_hdr", reservation_id),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries {
                            data: drop_no_udplb_hdr,
                        },
                    ),
                ),
            },
            Timeseries {
                name: format!("/lb/{}/drop_not_ip", reservation_id),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries { data: drop_not_ip },
                    ),
                ),
            },
            Timeseries {
                name: format!("/lb/{}/lb_ctx_rx_bytes", reservation_id),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries {
                            data: lb_ctx_rx_bytes,
                        },
                    ),
                ),
            },
            Timeseries {
                name: format!("/lb/{}/pkt_rx_bytes", reservation_id),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries { data: pkt_rx_bytes },
                    ),
                ),
            },
            Timeseries {
                name: format!("/lb/{}/pkt_rx_pkts", reservation_id),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries { data: pkt_rx_pkts },
                    ),
                ),
            },
        ])
    }

    // Efficiently fetch all stat_member_sample metrics as timeseries for a session.
    pub async fn get_all_member_stat_timeseries(
        &self,
        reservation_id: i64,
        session_id: i64,
        since: &DateTime<Utc>,
    ) -> Result<Vec<Timeseries>> {
        let since_ms = since.timestamp_millis();

        let rows = sqlx::query!(
            "SELECT sample_ts_ms, mbr_tx_pkts, mbr_tx_bytes
             FROM stat_member_sample
             WHERE session_id = ? AND sample_ts_ms >= ?
             ORDER BY sample_ts_ms ASC",
            session_id,
            since_ms
        )
        .fetch_all(&self.read_pool)
        .await?;

        let mut mbr_tx_pkts = Vec::new();
        let mut mbr_tx_bytes = Vec::new();

        for row in rows {
            let ts = row.sample_ts_ms;
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
            _ => return Err(Error::Usage(format!("Invalid session metric: {metric}"))),
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
        .ok_or_else(|| Error::NotFound(format!("Session {session_id} not found")))?;

        let ts_name = format!(
            "/lb/{}/reservation/{}/session/{}/{}",
            session.loadbalancer_id, session.reservation_id, session_id, metric
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
                    "Invalid event number metric: {metric}"
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
        .ok_or_else(|| Error::NotFound(format!("Reservation {reservation_id} not found")))?;
        let ts_name = format!(
            "/lb/{}/reservation/{}/{}",
            reservation.loadbalancer_id, reservation_id, metric
        );
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
        .ok_or_else(|| Error::NotFound(format!("Reservation {reservation_id} not found")))?;
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

    /// Resolves selectors into corresponding timeseries.
    /// New structure: /lb/{reservation_id}/{metric}, /lb/{reservation_id}/session/{session_id}/{metric}, and * for all metrics.
    pub async fn get_timeseries(
        &self,
        selectors: &[String],
        since: &DateTime<Utc>,
    ) -> Result<Vec<Timeseries>> {
        fn parse_id(s: &str) -> Option<i64> {
            s.parse::<i64>().ok()
        }

        let mut result = Vec::new();

        for selector in selectors {
            let parts: Vec<&str> = selector.split('/').filter(|s| !s.is_empty()).collect();
            if parts.is_empty() {
                continue;
            }

            // /smartnic/global and /smartnic/global/{metric} retained for backward compatibility
            if parts[0] == "smartnic" {
                match parts.as_slice() {
                    ["smartnic", "global"] => {
                        let mut ts = self.get_all_global_stat_timeseries(since).await?;
                        result.append(&mut ts);
                    }
                    ["smartnic", "global", metric] => {
                        if let Ok(ts) = self.get_global_stat_timeseries(metric, since).await {
                            result.push(ts);
                        }
                    }
                    _ => {}
                }
                continue;
            }

            // /lb/*
            if parts[0] == "lb" {
                // /lb/*: all reservations
                if parts.get(1) == Some(&"*") {
                    let reservations =
                        sqlx::query!("SELECT id FROM reservation WHERE deleted_at IS NULL")
                            .fetch_all(&self.read_pool)
                            .await?;
                    for res in reservations {
                        let mut res_ts = self.get_all_reservation_timeseries(res.id, since).await?;
                        result.append(&mut res_ts);
                    }
                    continue;
                }

                // /lb/{reservation_id}
                let reservation_id = match parts.get(1).and_then(|s| parse_id(s)) {
                    Some(id) => id,
                    None => continue,
                };

                // Validate reservation exists
                let reservation = sqlx::query!(
                    "SELECT id FROM reservation WHERE id = ? AND deleted_at IS NULL",
                    reservation_id
                )
                .fetch_optional(&self.read_pool)
                .await?;
                if reservation.is_none() {
                    continue;
                }

                match parts.as_slice() {
                    // /lb/{reservation_id}/*
                    ["lb", _, "*"] => {
                        // All metrics for reservation: event_number, avg_event_rate_hz, epoch, stat_lb_sample metrics, all session metrics
                        for metric in [
                            "event_number",
                            "avg_event_rate_hz",
                            "drop_blocked_src",
                            "drop_epoch_assign_miss",
                            "drop_lb_calendar_miss",
                            "drop_mbr_info_miss",
                            "drop_no_udplb_hdr",
                            "drop_not_ip",
                            "lb_ctx_rx_bytes",
                            "pkt_rx_bytes",
                            "pkt_rx_pkts",
                        ]
                        .iter()
                        {
                            if let Ok(ts) = self
                                .get_event_number_timeseries(reservation_id, metric, since)
                                .await
                            {
                                result.push(ts);
                            } else if let Ok(ts) = self
                                .get_lb_stat_timeseries(reservation_id, metric, since)
                                .await
                            {
                                result.push(ts);
                            }
                        }
                        if let Ok(ts) = self.get_epoch_timeseries(reservation_id, since).await {
                            result.push(ts);
                        }
                        let sessions = sqlx::query!(
                            "SELECT id FROM session WHERE reservation_id = ? AND deleted_at IS NULL",
                            reservation_id
                        )
                        .fetch_all(&self.read_pool)
                        .await?;
                        for session in sessions {
                            let mut s_ts =
                                self.get_all_session_timeseries(session.id, since).await?;
                            result.append(&mut s_ts);
                            let mut m_ts = self
                                .get_all_member_stat_timeseries(reservation_id, session.id, since)
                                .await?;
                            result.append(&mut m_ts);
                        }
                    }
                    // /lb/{reservation_id}/{metric}
                    ["lb", _, metric] => {
                        // Try event_number, avg_event_rate_hz, epoch, stat_lb_sample metrics
                        if *metric == "event_number" || *metric == "avg_event_rate_hz" {
                            if let Ok(ts) = self
                                .get_event_number_timeseries(reservation_id, metric, since)
                                .await
                            {
                                result.push(ts);
                            }
                        } else if *metric == "epoch" {
                            if let Ok(ts) = self.get_epoch_timeseries(reservation_id, since).await {
                                result.push(ts);
                            }
                        } else {
                            // stat_lb_sample metrics
                            if let Ok(ts) = self
                                .get_lb_stat_timeseries(reservation_id, metric, since)
                                .await
                            {
                                result.push(ts);
                            }
                        }
                    }
                    // /lb/{reservation_id}/session/*
                    ["lb", _, "session", "*"] => {
                        let sessions = sqlx::query!(
                            "SELECT id FROM session WHERE reservation_id = ? AND deleted_at IS NULL",
                            reservation_id
                        )
                        .fetch_all(&self.read_pool)
                        .await?;
                        for session in sessions {
                            let mut s_ts =
                                self.get_all_session_timeseries(session.id, since).await?;
                            result.append(&mut s_ts);
                            let mut m_ts = self
                                .get_all_member_stat_timeseries(reservation_id, session.id, since)
                                .await?;
                            result.append(&mut m_ts);
                        }
                    }
                    // /lb/{reservation_id}/session/{session_id}/*
                    ["lb", _, "session", session_id, "*"] => {
                        let session_id = match parse_id(session_id) {
                            Some(id) => id,
                            None => continue,
                        };
                        let session = sqlx::query!(
                            "SELECT reservation_id FROM session WHERE id = ? AND deleted_at IS NULL",
                            session_id
                        )
                        .fetch_optional(&self.read_pool)
                        .await?;
                        if let Some(s) = session {
                            if s.reservation_id != reservation_id {
                                continue;
                            }
                        } else {
                            continue;
                        }
                        let mut s_ts = self.get_all_session_timeseries(session_id, since).await?;
                        result.append(&mut s_ts);
                        let mut m_ts = self
                            .get_all_member_stat_timeseries(reservation_id, session_id, since)
                            .await?;
                        result.append(&mut m_ts);
                    }
                    // /lb/{reservation_id}/session/{session_id}/{metric}
                    ["lb", _, "session", session_id, metric] => {
                        let session_id = match parse_id(session_id) {
                            Some(id) => id,
                            None => continue,
                        };
                        let session = sqlx::query!(
                            "SELECT reservation_id FROM session WHERE id = ? AND deleted_at IS NULL",
                            session_id
                        )
                        .fetch_optional(&self.read_pool)
                        .await?;
                        if let Some(s) = session {
                            if s.reservation_id != reservation_id {
                                continue;
                            }
                        } else {
                            continue;
                        }
                        // Try session_state metrics
                        if let Ok(ts) = self.get_session_timeseries(session_id, metric, since).await
                        {
                            result.push(ts);
                        } else if let Ok(ts) = self
                            .get_member_stat_timeseries(session_id, metric, since)
                            .await
                        {
                            result.push(ts);
                        }
                    }
                    _ => {}
                }
                continue;
            }
        }

        Ok(result)
    }
}

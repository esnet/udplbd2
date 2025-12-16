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
            sample.sample_ts_ms,
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
                sample_ts_ms,
                rx_bytes,
                rx_packets
            ) VALUES (?, ?, ?, ?, ?)",
            sample.reservation_id,
            sample.stat_scope_id,
            sample.sample_ts_ms,
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
        // Map old metric names to new column names for backward compatibility
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
            "SELECT sample_ts_ms as timestamp, CAST({} AS FLOAT) as value
             FROM stat_global_sample
             WHERE sample_ts_ms >= ?
             ORDER BY sample_ts_ms ASC",
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

    // Fetch timeseries data for stat_lb_sample (SmartNIC per-LB metrics).
    pub async fn get_lb_stat_timeseries(
        &self,
        reservation_id: i64,
        metric: &str,
        since: &DateTime<Utc>,
    ) -> Result<Timeseries> {
        // Only allow drop and rx counter columns
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
             WHERE sample_ts_ms >= ?
             ORDER BY sample_ts_ms ASC",
            since_ms
        )
        .fetch_all(&self.read_pool)
        .await?;

        let mut rx_rslt_drop_parse_fail = Vec::new();
        let mut rx_rslt_drop_mac_dst_miss = Vec::new();
        let mut rx_rslt_drop_not_ip = Vec::new();
        let mut rx_rslt_drop_ip_dst_miss = Vec::new();
        let mut rx_rslt_drop_arp_bad_tpa = Vec::new();
        let mut rx_rslt_drop_icmpv4_echo_bad_dst = Vec::new();
        let mut rx_rslt_drop_icmpv6_echo_bad_dst = Vec::new();
        let mut rx_rslt_drop_ipv6nd_neigh_sol_bad_target = Vec::new();
        let mut rx_rslt_ok_arp_req = Vec::new();
        let mut rx_rslt_ok_icmpv4_echo = Vec::new();
        let mut rx_rslt_ok_icmpv6_echo = Vec::new();
        let mut rx_rslt_ok_ipv6nd_neigh_sol = Vec::new();
        let mut rx_rslt_ok_host = Vec::new();
        let mut rx_rslt_ok_lb = Vec::new();

        for row in rows {
            let ts = row.sample_ts_ms;
            rx_rslt_drop_parse_fail.push(FloatSample {
                timestamp: ts,
                value: row.rx_rslt_drop_parse_fail as f32,
                meta: None,
            });
            rx_rslt_drop_mac_dst_miss.push(FloatSample {
                timestamp: ts,
                value: row.rx_rslt_drop_mac_dst_miss as f32,
                meta: None,
            });
            rx_rslt_drop_not_ip.push(FloatSample {
                timestamp: ts,
                value: row.rx_rslt_drop_not_ip as f32,
                meta: None,
            });
            rx_rslt_drop_ip_dst_miss.push(FloatSample {
                timestamp: ts,
                value: row.rx_rslt_drop_ip_dst_miss as f32,
                meta: None,
            });
            rx_rslt_drop_arp_bad_tpa.push(FloatSample {
                timestamp: ts,
                value: row.rx_rslt_drop_arp_bad_tpa as f32,
                meta: None,
            });
            rx_rslt_drop_icmpv4_echo_bad_dst.push(FloatSample {
                timestamp: ts,
                value: row.rx_rslt_drop_icmpv4_echo_bad_dst as f32,
                meta: None,
            });
            rx_rslt_drop_icmpv6_echo_bad_dst.push(FloatSample {
                timestamp: ts,
                value: row.rx_rslt_drop_icmpv6_echo_bad_dst as f32,
                meta: None,
            });
            rx_rslt_drop_ipv6nd_neigh_sol_bad_target.push(FloatSample {
                timestamp: ts,
                value: row.rx_rslt_drop_ipv6nd_neigh_sol_bad_target as f32,
                meta: None,
            });
            rx_rslt_ok_arp_req.push(FloatSample {
                timestamp: ts,
                value: row.rx_rslt_ok_arp_req as f32,
                meta: None,
            });
            rx_rslt_ok_icmpv4_echo.push(FloatSample {
                timestamp: ts,
                value: row.rx_rslt_ok_icmpv4_echo as f32,
                meta: None,
            });
            rx_rslt_ok_icmpv6_echo.push(FloatSample {
                timestamp: ts,
                value: row.rx_rslt_ok_icmpv6_echo as f32,
                meta: None,
            });
            rx_rslt_ok_ipv6nd_neigh_sol.push(FloatSample {
                timestamp: ts,
                value: row.rx_rslt_ok_ipv6nd_neigh_sol as f32,
                meta: None,
            });
            rx_rslt_ok_host.push(FloatSample {
                timestamp: ts,
                value: row.rx_rslt_ok_host as f32,
                meta: None,
            });
            rx_rslt_ok_lb.push(FloatSample {
                timestamp: ts,
                value: row.rx_rslt_ok_lb as f32,
                meta: None,
            });
        }

        Ok(vec![
            Timeseries {
                name: "/smartnic/global/rx_rslt_drop_parse_fail".to_string(),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries {
                            data: rx_rslt_drop_parse_fail,
                        },
                    ),
                ),
            },
            Timeseries {
                name: "/smartnic/global/rx_rslt_drop_mac_dst_miss".to_string(),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries {
                            data: rx_rslt_drop_mac_dst_miss,
                        },
                    ),
                ),
            },
            Timeseries {
                name: "/smartnic/global/rx_rslt_drop_not_ip".to_string(),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries {
                            data: rx_rslt_drop_not_ip,
                        },
                    ),
                ),
            },
            Timeseries {
                name: "/smartnic/global/rx_rslt_drop_ip_dst_miss".to_string(),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries {
                            data: rx_rslt_drop_ip_dst_miss,
                        },
                    ),
                ),
            },
            Timeseries {
                name: "/smartnic/global/rx_rslt_drop_arp_bad_tpa".to_string(),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries {
                            data: rx_rslt_drop_arp_bad_tpa,
                        },
                    ),
                ),
            },
            Timeseries {
                name: "/smartnic/global/rx_rslt_drop_icmpv4_echo_bad_dst".to_string(),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries {
                            data: rx_rslt_drop_icmpv4_echo_bad_dst,
                        },
                    ),
                ),
            },
            Timeseries {
                name: "/smartnic/global/rx_rslt_drop_icmpv6_echo_bad_dst".to_string(),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries {
                            data: rx_rslt_drop_icmpv6_echo_bad_dst,
                        },
                    ),
                ),
            },
            Timeseries {
                name: "/smartnic/global/rx_rslt_drop_ipv6nd_neigh_sol_bad_target".to_string(),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries {
                            data: rx_rslt_drop_ipv6nd_neigh_sol_bad_target,
                        },
                    ),
                ),
            },
            Timeseries {
                name: "/smartnic/global/rx_rslt_ok_arp_req".to_string(),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries {
                            data: rx_rslt_ok_arp_req,
                        },
                    ),
                ),
            },
            Timeseries {
                name: "/smartnic/global/rx_rslt_ok_icmpv4_echo".to_string(),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries {
                            data: rx_rslt_ok_icmpv4_echo,
                        },
                    ),
                ),
            },
            Timeseries {
                name: "/smartnic/global/rx_rslt_ok_icmpv6_echo".to_string(),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries {
                            data: rx_rslt_ok_icmpv6_echo,
                        },
                    ),
                ),
            },
            Timeseries {
                name: "/smartnic/global/rx_rslt_ok_ipv6nd_neigh_sol".to_string(),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries {
                            data: rx_rslt_ok_ipv6nd_neigh_sol,
                        },
                    ),
                ),
            },
            Timeseries {
                name: "/smartnic/global/rx_rslt_ok_host".to_string(),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries {
                            data: rx_rslt_ok_host,
                        },
                    ),
                ),
            },
            Timeseries {
                name: "/smartnic/global/rx_rslt_ok_lb".to_string(),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries {
                            data: rx_rslt_ok_lb,
                        },
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
             WHERE reservation_id = ? AND sample_ts_ms >= ?
             ORDER BY sample_ts_ms ASC",
            reservation_id,
            since_ms
        )
        .fetch_all(&self.read_pool)
        .await?;

        let mut drop_bad_udplb_version = Vec::new();
        let mut drop_blocked_src = Vec::new();
        let mut drop_epoch_assign_miss = Vec::new();
        let mut drop_lb_calendar_miss = Vec::new();
        let mut drop_mbr_info_miss = Vec::new();
        let mut drop_no_udplb_hdr = Vec::new();
        let mut drop_not_ip = Vec::new();
        let mut rx_bytes = Vec::new();
        let mut rx_packets = Vec::new();

        for row in rows {
            let ts = row.sample_ts_ms;
            drop_bad_udplb_version.push(FloatSample {
                timestamp: ts,
                value: row.drop_bad_udplb_version as f32,
                meta: None,
            });
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
            rx_bytes.push(FloatSample {
                timestamp: ts,
                value: row.rx_bytes as f32,
                meta: None,
            });
            rx_packets.push(FloatSample {
                timestamp: ts,
                value: row.rx_packets as f32,
                meta: None,
            });
        }

        Ok(vec![
            Timeseries {
                name: format!("/lb/{}/drop_bad_udplb_version", reservation_id),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries {
                            data: drop_bad_udplb_version,
                        },
                    ),
                ),
            },
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
                name: format!("/lb/{}/rx_bytes", reservation_id),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries { data: rx_bytes },
                    ),
                ),
            },
            Timeseries {
                name: format!("/lb/{}/rx_packets", reservation_id),
                unit: "".to_string(),
                timeseries: Some(
                    crate::proto::loadbalancer::v1::timeseries::Timeseries::FloatSamples(
                        FloatTimeseries { data: rx_packets },
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
                            "drop_bad_udplb_version",
                            "drop_blocked_src",
                            "drop_epoch_assign_miss",
                            "drop_lb_calendar_miss",
                            "drop_mbr_info_miss",
                            "drop_no_udplb_hdr",
                            "drop_not_ip",
                            "rx_bytes",
                            "rx_packets",
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

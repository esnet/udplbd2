// SPDX-License-Identifier: BSD-3-Clause-LBNL
//! Background task for collecting SmartNIC metrics and inserting them into the database.

use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, info};

use crate::db::models::{StatGlobalSample, StatLbSample, StatMemberSample};
use crate::db::LoadBalancerDB;
use crate::sncfg::client::MultiSNCfgClient;
use std::collections::HashMap;

/// Configuration for the SmartNIC metrics collector.
#[derive(Clone, Debug)]
pub struct MetricsCollectorConfig {
    pub enabled: bool,
    pub interval: Duration,
}

impl Default for MetricsCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: Duration::from_secs(10),
        }
    }
}

/// Starts the SmartNIC metrics collector background task.
/// This should be called from start_server in lib.rs.
/// If config.enabled is false, the collector is not started.
pub fn start_metrics_collector(
    db: Arc<LoadBalancerDB>,
    mut sncfg: MultiSNCfgClient,
    metrics_collector_config: MetricsCollectorConfig,
) {
    if !metrics_collector_config.enabled {
        info!("ESnet SmartNIC metrics collector is disabled by config, health check capability degraded");
        return;
    }
    let interval = metrics_collector_config.interval;
    tokio::spawn(async move {
        info!(
            "starting ESnet SmartNIC metrics collector (interval: {:?})",
            interval
        );
        loop {
            // Build fpga_lb_id -> reservation_id map for active reservations
            let lb_map = match sqlx::query!(
                "SELECT l.fpga_lb_id, r.id as reservation_id
                 FROM loadbalancer l
                 JOIN reservation r ON l.id = r.loadbalancer_id
                 WHERE l.deleted_at IS NULL
                   AND r.deleted_at IS NULL
                   AND r.reserved_until > unixepoch('subsec') * 1000"
            )
            .fetch_all(&db.read_pool)
            .await
            {
                Ok(rows) => rows
                    .into_iter()
                    .map(|row| (row.fpga_lb_id as u32, row.reservation_id))
                    .collect::<std::collections::HashMap<u32, i64>>(),
                Err(e) => {
                    error!("failed to query active reservations: {e:?}");
                    sleep(interval).await;
                    continue;
                }
            };

            // Build member_id -> session_id map for active sessions
            let session_map =
                match sqlx::query!("SELECT id as session_id FROM session WHERE deleted_at IS NULL")
                    .fetch_all(&db.read_pool)
                    .await
                {
                    Ok(rows) => rows
                        .into_iter()
                        .map(|row| (row.session_id as u32, row.session_id))
                        .collect::<std::collections::HashMap<u32, i64>>(),
                    Err(e) => {
                        error!("Failed to query active sessions: {:?}", e);
                        sleep(interval).await;
                        continue;
                    }
                };

            // Fetch metrics from all SmartNICs
            match sncfg.get_stats().await {
                Ok(all_metrics) => {
                    // Accumulate stats across all FPGAs
                    let mut global_sample = StatGlobalSample::default();
                    let mut lb_samples: HashMap<i64, StatLbSample> = HashMap::new();
                    let mut member_samples: HashMap<i64, StatMemberSample> = HashMap::new();

                    for metrics in all_metrics {
                        for metric in metrics {
                            let ts_ms = metric
                                .last_update
                                .as_ref()
                                .map(|ts| ts.seconds * 1000 + (ts.nanos as i64) / 1_000_000)
                                .unwrap_or(0);

                            match metric.name.as_str() {
                                // RX result classification buckets (global)
                                "rx_rslt_counter" => {
                                    for v in &metric.values {
                                        let idx = v.index as usize;
                                        if idx < global_sample.rx_rslt.len() {
                                            global_sample.rx_rslt[idx] += v.u64 as i64;
                                        }
                                    }
                                    global_sample.sample_ts_ms = ts_ms;
                                }
                                // Drop counters (per LB)
                                "lb_ctx_drop_blocked_src_pkt_counter"
                                | "lb_ctx_drop_epoch_assign_miss_pkt_counter"
                                | "lb_ctx_drop_lb_calendar_miss_pkt_counter"
                                | "lb_ctx_drop_mbr_info_miss_pkt_counter"
                                | "lb_ctx_drop_no_udplb_hdr_pkt_counter"
                                | "lb_ctx_drop_not_ip_pkt_counter"
                                // Receive counters (per LB)
                                | "lb_ctx_rx_byte_counter"
                                | "packet_rx_counter_bytes"
                                | "packet_rx_counter_packets" => {
                                    for v in &metric.values {
                                        let fpga_lb_id = v.index;
                                        if let Some(&reservation_id) = lb_map.get(&fpga_lb_id) {
                                            let entry = lb_samples.entry(reservation_id).or_insert_with(|| StatLbSample {
                                                reservation_id,
                                                sample_ts_ms: ts_ms,
                                                ..Default::default()
                                            });
                                            entry.sample_ts_ms = ts_ms;
                                            match metric.name.as_str() {
                                                "lb_ctx_drop_blocked_src_pkt_counter" => entry.drop_blocked_src += v.u64 as i64,
                                                "lb_ctx_drop_epoch_assign_miss_pkt_counter" => entry.drop_epoch_assign_miss += v.u64 as i64,
                                                "lb_ctx_drop_lb_calendar_miss_pkt_counter" => entry.drop_lb_calendar_miss += v.u64 as i64,
                                                "lb_ctx_drop_mbr_info_miss_pkt_counter" => entry.drop_mbr_info_miss += v.u64 as i64,
                                                "lb_ctx_drop_no_udplb_hdr_pkt_counter" => entry.drop_no_udplb_hdr += v.u64 as i64,
                                                "lb_ctx_drop_not_ip_pkt_counter" => entry.drop_not_ip += v.u64 as i64,
                                                "lb_ctx_rx_byte_counter" => entry.lb_ctx_rx_bytes += v.u64 as i64,
                                                "packet_rx_counter_bytes" => entry.pkt_rx_bytes += v.u64 as i64,
                                                "packet_rx_counter_packets" => entry.pkt_rx_pkts += v.u64 as i64,
                                                _ => {}
                                            }
                                        }
                                    }
                                }
                                // Per-member transmit counters
                                "lb_mbr_tx_pkt_counter" | "lb_mbr_tx_byte_counter" => {
                                    for v in &metric.values {
                                        let member_id = v.index;
                                        if let Some(&session_id) = session_map.get(&member_id) {
                                            let entry = member_samples.entry(session_id).or_insert_with(|| StatMemberSample {
                                                session_id,
                                                sample_ts_ms: ts_ms,
                                                ..Default::default()
                                            });
                                            entry.sample_ts_ms = ts_ms;
                                            match metric.name.as_str() {
                                                "lb_mbr_tx_pkt_counter" => entry.mbr_tx_pkts += v.u64 as i64,
                                                "lb_mbr_tx_byte_counter" => entry.mbr_tx_bytes += v.u64 as i64,
                                                _ => {}
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }

                    // Insert global sample if timestamp is set
                    if global_sample.sample_ts_ms != 0 {
                        if let Err(e) = db.insert_stat_global_sample(&global_sample).await {
                            error!("Failed to insert stat_global_sample: {:?}", e);
                        }
                    }

                    // Insert all lb_samples
                    for sample in lb_samples.values() {
                        if let Err(e) = db.insert_stat_lb_sample(sample).await {
                            error!("Failed to insert stat_lb_sample: {:?}", e);
                        }
                    }

                    // Insert all member_samples
                    for sample in member_samples.values() {
                        if let Err(e) = db.insert_stat_member_sample(sample).await {
                            error!("Failed to insert stat_member_sample: {:?}", e);
                        }
                    }
                }
                Err(_) => {
                    error!("Failed to fetch SmartNIC metrics");
                }
            }
            // Sleep before next collection
            sleep(interval).await;
        }
    });
}

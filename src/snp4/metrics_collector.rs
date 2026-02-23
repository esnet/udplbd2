// SPDX-License-Identifier: BSD-3-Clause-LBNL
//! Background task for collecting SmartNIC P4 pipeline metrics and inserting them into the database.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use crate::db::models::{StatGlobalSample, StatLbSample, StatLbScopedSample, StatMemberSample};
use crate::db::LoadBalancerDB;
use crate::proto::smartnic::p4_v2::{StatsMetric, StatsMetricScope};
use crate::snp4::client::MultiSNP4Client;

/// Configuration for the SmartNIC P4 pipeline metrics collector.
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

/// Synchronize scope information from metrics to the database.
/// Returns true if scopes changed (requiring metrics to be cleared).
async fn synchronize_scopes(
    db: &LoadBalancerDB,
    all_metrics: &[Vec<StatsMetric>],
) -> Result<bool, sqlx::Error> {
    // Collect all unique scopes from metrics
    let mut metric_scopes: HashMap<(String, String, String), ()> = HashMap::new();
    for metrics in all_metrics {
        for metric in metrics {
            if let Some(scope) = &metric.scope {
                let key = (
                    scope.domain.clone(),
                    scope.zone.clone(),
                    scope.block.clone(),
                );
                metric_scopes.insert(key, ());
            }
        }
    }

    // Get existing scopes from database
    let db_scopes = sqlx::query!("SELECT id, domain, zone, block FROM stat_scope")
        .fetch_all(&db.read_pool)
        .await?;

    let mut db_scope_set: HashMap<(String, String, String), i64> = HashMap::new();
    for row in &db_scopes {
        let key = (
            row.domain.clone().unwrap_or_default(),
            row.zone.clone().unwrap_or_default(),
            row.block.clone().unwrap_or_default(),
        );
        db_scope_set.insert(key, row.id);
    }

    // Check if scopes are out of sync
    let mut scopes_changed = false;

    // Check for new scopes in metrics that aren't in DB
    for (domain, zone, block) in metric_scopes.keys() {
        if !db_scope_set.contains_key(&(domain.clone(), zone.clone(), block.clone())) {
            scopes_changed = true;
            // Insert new scope
            sqlx::query!(
                "INSERT INTO stat_scope (domain, zone, block) VALUES (?, ?, ?)",
                domain,
                zone,
                block
            )
            .execute(&db.write_pool)
            .await?;
            info!(
                "added new metric scope: domain={}, zone={}, block={}",
                domain, zone, block
            );
        }
    }

    // Check for scopes in DB that aren't in metrics anymore
    for (domain, zone, block) in db_scope_set.keys() {
        if !metric_scopes.contains_key(&(domain.clone(), zone.clone(), block.clone())) {
            scopes_changed = true;
            warn!(
                "metric scope removed: domain={}, zone={}, block={}",
                domain, zone, block
            );
        }
    }

    Ok(scopes_changed)
}

/// Get or create a scope ID for the given scope.
async fn get_or_create_scope_id(
    db: &LoadBalancerDB,
    scope: &StatsMetricScope,
) -> Result<i64, sqlx::Error> {
    let domain = &scope.domain;
    let zone = &scope.zone;
    let block = &scope.block;

    // Try to get existing scope
    if let Some(row) = sqlx::query!(
        "SELECT id FROM stat_scope WHERE domain = ? AND zone = ? AND block = ?",
        domain,
        zone,
        block
    )
    .fetch_optional(&db.read_pool)
    .await?
    {
        return Ok(row.id);
    }

    // Create new scope
    let result = sqlx::query!(
        "INSERT INTO stat_scope (domain, zone, block) VALUES (?, ?, ?) RETURNING id",
        domain,
        zone,
        block
    )
    .fetch_one(&db.write_pool)
    .await?;

    Ok(result.id)
}

/// Starts the SmartNIC P4 pipeline metrics collector background task.
/// This should be called from start_server in lib.rs.
/// If config.enabled is false, the collector is not started.
/// Also starts the health check task with the same interval.
pub fn start_metrics_collector(
    db: Arc<LoadBalancerDB>,
    mut snp4: MultiSNP4Client,
    metrics_collector_config: MetricsCollectorConfig,
) {
    if !metrics_collector_config.enabled {
        warn!("health check capability degraded, metrics collector disabled by config");
        return;
    }
    let interval = metrics_collector_config.interval;

    // Start health check task with the same configuration
    let healthcheck_config = crate::healthcheck::HealthCheckConfig {
        enabled: true,
        interval,
    };
    crate::healthcheck::start_healthcheck(db.clone(), healthcheck_config);

    tokio::spawn(async move {
        info!(
            "starting ESnet SmartNIC P4 pipeline metrics collector (interval: {:?})",
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

            // Fetch metrics from all SmartNIC P4 pipelines
            match snp4.get_pipeline_stats().await {
                Ok(all_metrics) => {
                    // Synchronize scope information from metrics
                    match synchronize_scopes(&db, &all_metrics).await {
                        Ok(true) => {
                            warn!("metric scopes changed - clearing all metrics to resynchronize");
                            if let Err(e) = snp4.clear_pipeline_stats().await {
                                error!(
                                    "failed to clear pipeline stats after scope change: {:?}",
                                    e
                                );
                            }
                            sleep(interval).await;
                            continue;
                        }
                        Ok(false) => {
                            // Scopes are in sync, continue processing
                        }
                        Err(e) => {
                            warn!("failed to synchronize metric scopes: {:?}", e);
                        }
                    }

                    // Accumulate stats across all FPGAs
                    let mut global_sample = StatGlobalSample::default();
                    let mut lb_samples: HashMap<i64, StatLbSample> = HashMap::new();
                    let mut lb_scoped_samples: Vec<StatLbScopedSample> = Vec::new();
                    let mut member_samples: HashMap<i64, StatMemberSample> = HashMap::new();

                    let now = Utc::now();
                    let ts_ms = now.timestamp_millis();

                    for metrics in all_metrics {
                        for metric in metrics {
                            match metric.name.as_str() {
                                // RX result classification buckets (global)
                                "rx_rslt_counter" => {
                                    for v in &metric.values {
                                        let idx = v.index as usize;
                                        if idx < global_sample.rx_rslt.len() {
                                            global_sample.rx_rslt[idx] += v.u64 as i64;
                                        }
                                    }
                                    global_sample.sampled_at = ts_ms;
                                }
                                // Drop counters and V2/V3 counters (per LB)
                                "lb_ctx_drop_bad_udplb_version_pkt_counter"
                                | "lb_ctx_drop_blocked_src_pkt_counter"
                                | "lb_ctx_drop_epoch_assign_miss_pkt_counter"
                                | "lb_ctx_drop_lb_calendar_miss_pkt_counter"
                                | "lb_ctx_drop_mbr_info_miss_pkt_counter"
                                | "lb_ctx_drop_no_udplb_hdr_pkt_counter"
                                | "lb_ctx_drop_not_ip_pkt_counter"
                                | "lb_ctx_rx_v2_counter"
                                | "lb_ctx_rx_v3_counter" => {
                                    for v in &metric.values {
                                        let fpga_lb_id = v.index;
                                        if let Some(&reservation_id) = lb_map.get(&fpga_lb_id) {
                                            let entry = lb_samples
                                                .entry(reservation_id)
                                                .or_insert_with(|| StatLbSample {
                                                    reservation_id,
                                                    sampled_at: ts_ms,
                                                    ..Default::default()
                                                });
                                            entry.sampled_at = ts_ms;
                                            match metric.name.as_str() {
                                                "lb_ctx_drop_bad_udplb_version_pkt_counter" => {
                                                    entry.drop_bad_udplb_version += v.u64 as i64
                                                }
                                                "lb_ctx_drop_blocked_src_pkt_counter" => {
                                                    entry.drop_blocked_src += v.u64 as i64
                                                }
                                                "lb_ctx_drop_epoch_assign_miss_pkt_counter" => {
                                                    entry.drop_epoch_assign_miss += v.u64 as i64
                                                }
                                                "lb_ctx_drop_lb_calendar_miss_pkt_counter" => {
                                                    entry.drop_lb_calendar_miss += v.u64 as i64
                                                }
                                                "lb_ctx_drop_mbr_info_miss_pkt_counter" => {
                                                    entry.drop_mbr_info_miss += v.u64 as i64
                                                }
                                                "lb_ctx_drop_no_udplb_hdr_pkt_counter" => {
                                                    entry.drop_no_udplb_hdr += v.u64 as i64
                                                }
                                                "lb_ctx_drop_not_ip_pkt_counter" => {
                                                    entry.drop_not_ip += v.u64 as i64
                                                }
                                                "lb_ctx_rx_v2_counter" => {
                                                    entry.rx_v2 += v.u64 as i64
                                                }
                                                "lb_ctx_rx_v3_counter" => {
                                                    entry.rx_v3 += v.u64 as i64
                                                }
                                                _ => {}
                                            }
                                        }
                                    }
                                }
                                // Receive counters (per LB) - aggregated and per-scope
                                "lb_ctx_rx_byte_counter" | "lb_ctx_rx_pkt_counter" => {
                                    // Get scope_id for this metric
                                    let scope_id = if let Some(scope) = &metric.scope {
                                        match get_or_create_scope_id(&db, scope).await {
                                            Ok(id) => Some(id),
                                            Err(e) => {
                                                error!("failed to get scope_id: {:?}", e);
                                                None
                                            }
                                        }
                                    } else {
                                        None
                                    };

                                    for v in &metric.values {
                                        let fpga_lb_id = v.index;
                                        if let Some(&reservation_id) = lb_map.get(&fpga_lb_id) {
                                            // Aggregate metrics
                                            let entry = lb_samples
                                                .entry(reservation_id)
                                                .or_insert_with(|| StatLbSample {
                                                    reservation_id,
                                                    sampled_at: ts_ms,
                                                    ..Default::default()
                                                });
                                            entry.sampled_at = ts_ms;
                                            match metric.name.as_str() {
                                                "lb_ctx_rx_byte_counter" => {
                                                    entry.rx_bytes += v.u64 as i64
                                                }
                                                "lb_ctx_rx_pkt_counter" => {
                                                    entry.rx_packets += v.u64 as i64
                                                }
                                                _ => {}
                                            }

                                            // Store per-scope metrics
                                            if let Some(scope_id) = scope_id {
                                                lb_scoped_samples.push(StatLbScopedSample {
                                                    reservation_id,
                                                    stat_scope_id: scope_id,
                                                    sampled_at: ts_ms,
                                                    rx_bytes: if metric.name
                                                        == "lb_ctx_rx_byte_counter"
                                                    {
                                                        v.u64 as i64
                                                    } else {
                                                        0
                                                    },
                                                    rx_packets: if metric.name
                                                        == "lb_ctx_rx_pkt_counter"
                                                    {
                                                        v.u64 as i64
                                                    } else {
                                                        0
                                                    },
                                                });
                                            }
                                        }
                                    }
                                }
                                // Per-member transmit counters
                                "lb_mbr_tx_pkt_counter" | "lb_mbr_tx_byte_counter" => {
                                    for v in &metric.values {
                                        let member_id = v.index;
                                        if let Some(&session_id) = session_map.get(&member_id) {
                                            let entry = member_samples
                                                .entry(session_id)
                                                .or_insert_with(|| StatMemberSample {
                                                    session_id,
                                                    sampled_at: ts_ms,
                                                    ..Default::default()
                                                });
                                            entry.sampled_at = ts_ms;
                                            match metric.name.as_str() {
                                                "lb_mbr_tx_pkt_counter" => {
                                                    entry.mbr_tx_pkts += v.u64 as i64
                                                }
                                                "lb_mbr_tx_byte_counter" => {
                                                    entry.mbr_tx_bytes += v.u64 as i64
                                                }
                                                _ => {}
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }

                    let mut total_samples =
                        lb_samples.len() + lb_scoped_samples.len() + member_samples.len();
                    let total_lb_samplezs = lb_samples.len() + lb_scoped_samples.len();
                    let total_member_samples = member_samples.len();

                    // Insert global sample if timestamp is set
                    if global_sample.sampled_at != 0 {
                        if let Err(e) = db.insert_stat_global_sample(&global_sample).await {
                            error!("failed to insert stat_global_sample: {:?}", e);
                        }
                        total_samples += 1;
                    }

                    // Insert all lb_samples
                    for sample in lb_samples.values() {
                        if let Err(e) = db.insert_stat_lb_sample(sample).await {
                            error!("failed to insert stat_lb_sample: {:?}", e);
                        }
                    }

                    // Insert all lb_scoped_samples
                    for sample in &lb_scoped_samples {
                        if let Err(e) = db.insert_stat_lb_scoped_sample(sample).await {
                            error!("failed to insert stat_lb_scoped_sample: {:?}", e);
                        }
                    }

                    // Insert all member_samples
                    for sample in member_samples.values() {
                        if let Err(e) = db.insert_stat_member_sample(sample).await {
                            error!("failed to insert stat_member_sample: {:?}", e);
                        }
                    }

                    debug!("metrics_collector: collected {total_samples} total samples ({total_lb_samplezs} by lb, {total_member_samples} by member)");
                }
                Err(_) => {
                    error!("failed to fetch SmartNIC P4 pipeline metrics");
                }
            }
            // Sleep before next collection
            sleep(interval).await;
        }
    });
}

/// Clear stats for a specific member (session) by member_id.
/// This should be called when a new member is registered to reset counters.
/// Clears: lb_mbr_tx_pkt_counter, lb_mbr_tx_byte_counter
pub async fn clear_member_stats(snp4: &mut MultiSNP4Client, member_id: u32) {
    let member_counter_names = &["lb_mbr_tx_pkt_counter", "lb_mbr_tx_byte_counter"];

    if let Err(e) = snp4
        .clear_stats_by_names_and_index(member_counter_names, member_id)
        .await
    {
        error!("failed to clear stats for member_id {}: {:?}", member_id, e);
    } else {
        info!("cleared stats for member_id {}", member_id);
    }
}

/// Clear stats for a specific load balancer by fpga_lb_id.
/// This should be called when a new LB is reserved to reset counters.
/// Clears: lb_ctx_drop_blocked_src_pkt_counter, lb_ctx_drop_epoch_assign_miss_pkt_counter,
///         lb_ctx_drop_lb_calendar_miss_pkt_counter, lb_ctx_drop_mbr_info_miss_pkt_counter,
///         lb_ctx_drop_no_udplb_hdr_pkt_counter, lb_ctx_drop_not_ip_pkt_counter,
///         lb_ctx_rx_byte_counter, lb_ctx_rx_pkt_counter, lb_ctx_rx_v2_counter, lb_ctx_rx_v3_counter
pub async fn clear_lb_stats(snp4: &mut MultiSNP4Client, fpga_lb_id: u32) {
    let lb_counter_names = &[
        "lb_ctx_drop_bad_udplb_version_pkt_counter",
        "lb_ctx_drop_blocked_src_pkt_counter",
        "lb_ctx_drop_epoch_assign_miss_pkt_counter",
        "lb_ctx_drop_lb_calendar_miss_pkt_counter",
        "lb_ctx_drop_mbr_info_miss_pkt_counter",
        "lb_ctx_drop_no_udplb_hdr_pkt_counter",
        "lb_ctx_drop_not_ip_pkt_counter",
        "lb_ctx_rx_byte_counter",
        "lb_ctx_rx_pkt_counter",
        "lb_ctx_rx_v2_counter",
        "lb_ctx_rx_v3_counter",
    ];

    if let Err(e) = snp4
        .clear_stats_by_names_and_index(lb_counter_names, fpga_lb_id)
        .await
    {
        error!(
            "failed to clear stats for fpga_lb_id {}: {:?}",
            fpga_lb_id, e
        );
    } else {
        info!("cleared stats for fpga_lb_id {}", fpga_lb_id);
    }
}

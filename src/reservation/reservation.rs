// SPDX-License-Identifier: BSD-3-Clause-LBNL
use crate::db::{LoadBalancerDB, Result};
use crate::errors::Error;
use crate::metrics::LB_IS_ACTIVE;
use crate::proto::smartnic::p4_v2::TableRule;
use crate::snp4::client::MultiSNP4Client;
use crate::snp4::rules::{
    compare_rule_sets, deserialize_table_rules, serialize_table_rules, Layer2InputPacketFilterRule,
    TableUpdate,
};
use crate::util::{
    generate_solicited_node_multicast_ipv6, generate_solicited_node_multicast_mac, mac_to_u64,
};
use chrono::{Duration as ChronoDuration, Utc};
use macaddr::MacAddr6;
use sqlx;
use std::net::Ipv6Addr;
use std::{collections::HashMap, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    sync::{broadcast, Mutex},
    task::JoinHandle,
    time::{self, MissedTickBehavior},
};
use tracing::{debug, error, info, trace, warn};

/// Manages the lifecycle of load balancer reservations and their associated rules.
pub struct ReservationManager {
    db: Arc<LoadBalancerDB>,
    snp4: MultiSNP4Client,
    active_reservations: Arc<Mutex<HashMap<i64, ActiveReservation>>>,
    tick_interval: Duration,
    tick_offset: Duration,
    mac: MacAddr6,
    sync_addr: SocketAddr,
    pub dump_rules_dir: Option<PathBuf>,
    update_task: Option<JoinHandle<()>>,
    shutdown_tx: Option<broadcast::Sender<()>>,
    current_rules: Arc<Mutex<Vec<TableRule>>>,
}

impl ReservationManager {
    #[must_use]
    pub fn new(
        db: Arc<LoadBalancerDB>,
        snp4: MultiSNP4Client,
        tick_interval: Duration,
        tick_offset: Duration,
        mac: MacAddr6,
        sync_addr: SocketAddr,
    ) -> Self {
        Self {
            db,
            snp4,
            active_reservations: Arc::new(Mutex::new(HashMap::new())),
            tick_interval,
            tick_offset,
            mac,
            sync_addr,
            dump_rules_dir: None,
            update_task: None,
            shutdown_tx: None,
            current_rules: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Keep only the 10 most recent rule caches.
    async fn cache_rules(db: &Arc<LoadBalancerDB>, rules: &[TableRule]) {
        let _ = db.insert_rule_cache(&serialize_table_rules(rules)).await;
    }

    /// True if no active sessions exist across all reservations.
    async fn should_clear_tables(
        db: &Arc<LoadBalancerDB>,
        active: &Arc<Mutex<HashMap<i64, ActiveReservation>>>,
    ) -> bool {
        let reservations = active.lock().await;
        if reservations.is_empty() {
            return true;
        }
        for res in reservations.values() {
            if let Ok(sessions) = db.get_reservation_sessions(res.reservation_id).await {
                if !sessions.is_empty() {
                    return false;
                }
            }
        }
        true
    }

    pub async fn initialize(&mut self) -> Result<()> {
        for (res, lb) in self.db.list_reservations_with_load_balancer().await? {
            if res.reserved_until > Utc::now() {
                self.start_reservation(res.id, lb.event_number_udp_port)
                    .await?;
            }
        }

        let mut restored = false;
        if let Ok(Some(bytes)) = self.db.get_latest_rule_cache().await {
            let cached = deserialize_table_rules(&bytes);
            if !cached.is_empty() {
                info!("found cached rules, attempting to apply as updates");
                let upd = TableUpdate {
                    description: "restore cached rules".into(),
                    insertions: Vec::new(),
                    updates: cached.clone(),
                    deletions: Vec::new(),
                };
                if self.snp4.bulk_update(&[upd]).await.is_ok() {
                    info!("successfully restored cached rules");
                    let mut guard = self.current_rules.lock().await;
                    *guard = cached;
                    Self::cache_rules(&self.db, &guard).await;
                    restored = true;
                } else {
                    warn!("failed to restore cached rules");
                }
            }
        }

        if !restored {
            info!("resetting tables and applying default L2/L3 rules");
            if Self::should_clear_tables(&self.db, &self.active_reservations).await {
                self.snp4.clear_tables().await.map_err(|e| {
                    error!("failed to clear tables: {:#?}", e);
                    Error::NotInitialized(format!("clear tables: {e:?}"))
                })?;
            }
            let defaults = Self::generate_l2_l3_defaults(&self.db, self.mac).await?;
            let insert = TableUpdate {
                description: "initialize defaults".into(),
                insertions: defaults.clone(),
                updates: Vec::new(),
                deletions: Vec::new(),
            };
            self.snp4.bulk_update(&[insert]).await.map_err(|e| {
                error!("failed to insert defaults: {:#?}", e);
                Error::NotInitialized(format!("insert defaults: {e:?}"))
            })?;
            let mut guard = self.current_rules.lock().await;
            *guard = defaults;
            Self::cache_rules(&self.db, &guard).await;
        }

        let (tx, rx) = broadcast::channel(1);
        self.shutdown_tx = Some(tx.clone());
        let db = self.db.clone();
        let mut snp4 = self.snp4.clone();
        let active = self.active_reservations.clone();
        let current = self.current_rules.clone();
        let tick_interval = self.tick_interval;
        let offset = ChronoDuration::from_std(self.tick_offset)?;
        let mac = self.mac;
        let dump = self.dump_rules_dir.clone();
        self.update_task = Some(tokio::spawn(async move {
            if let Err(e) = ReservationManager::run(
                db,
                &mut snp4,
                active,
                current,
                tick_interval,
                offset,
                mac,
                dump,
                rx,
            )
            .await
            {
                panic!("update loop failed: {:?}", e);
            }
        }));

        Ok(())
    }

    async fn generate_l2_l3_defaults(
        db: &Arc<LoadBalancerDB>,
        mac: MacAddr6,
    ) -> Result<Vec<TableRule>> {
        let mut rules = Self::generate_global_l2_rules(mac);
        let lbs = db.list_loadbalancers().await?;
        for lb in lbs {
            rules.extend(Self::generate_l2_rule(mac, lb.unicast_ipv6_address));
            rules.extend(Self::generate_l3_rules(&lb));
        }
        Ok(rules)
    }

    fn generate_global_l2_rules(mac: MacAddr6) -> Vec<TableRule> {
        vec![
            Layer2InputPacketFilterRule {
                match_dest_mac_addr: mac_to_u64(mac),
                set_src_mac_addr: mac_to_u64(mac),
            }
            .into(),
            Layer2InputPacketFilterRule {
                match_dest_mac_addr: 0xffffffffffff,
                set_src_mac_addr: mac_to_u64(mac),
            }
            .into(),
            Layer2InputPacketFilterRule {
                match_dest_mac_addr: 0x333300000001,
                set_src_mac_addr: mac_to_u64(mac),
            }
            .into(),
        ]
    }

    fn generate_l2_rule(mac: MacAddr6, ip_addr: Ipv6Addr) -> Vec<TableRule> {
        vec![Layer2InputPacketFilterRule {
            match_dest_mac_addr: generate_solicited_node_multicast_mac(
                &generate_solicited_node_multicast_ipv6(&ip_addr),
            ),
            set_src_mac_addr: mac_to_u64(mac),
        }
        .into()]
    }

    fn generate_l3_rules(lb: &crate::db::models::LoadBalancer) -> Vec<TableRule> {
        use crate::snp4::rules::{EtherType, IpDstToLbInstanceRule};
        use crate::util::generate_solicited_node_multicast_ipv6;
        use std::net::IpAddr;

        vec![
            IpDstToLbInstanceRule {
                match_ether_type: EtherType::Ipv4,
                match_dest_ip_addr: IpAddr::V4(lb.unicast_ipv4_address),
                set_src_ip_addr: IpAddr::V4(lb.unicast_ipv4_address),
                set_lb_instance_id: lb.fpga_lb_id as u8,
            }
            .into(),
            IpDstToLbInstanceRule {
                match_ether_type: EtherType::Ipv4Arp,
                match_dest_ip_addr: IpAddr::V4(lb.unicast_ipv4_address),
                set_src_ip_addr: IpAddr::V4(lb.unicast_ipv4_address),
                set_lb_instance_id: lb.fpga_lb_id as u8,
            }
            .into(),
            IpDstToLbInstanceRule {
                match_ether_type: EtherType::Ipv6,
                match_dest_ip_addr: IpAddr::V6(lb.unicast_ipv6_address),
                set_src_ip_addr: IpAddr::V6(lb.unicast_ipv6_address),
                set_lb_instance_id: lb.fpga_lb_id as u8,
            }
            .into(),
            IpDstToLbInstanceRule {
                match_ether_type: EtherType::Ipv6,
                match_dest_ip_addr: IpAddr::V6(generate_solicited_node_multicast_ipv6(
                    &lb.unicast_ipv6_address,
                )),
                set_src_ip_addr: IpAddr::V6(lb.unicast_ipv6_address),
                set_lb_instance_id: lb.fpga_lb_id as u8,
            }
            .into(),
        ]
    }

    async fn next_epoch_rules(
        db: &Arc<LoadBalancerDB>,
        active: &Arc<Mutex<HashMap<i64, ActiveReservation>>>,
        mac: MacAddr6,
        offset: ChronoDuration,
        advance: bool,
    ) -> Result<Vec<TableRule>> {
        let mut rules = Self::generate_global_l2_rules(mac);
        let lbs = db.list_loadbalancers().await?;
        for lb in lbs {
            rules.extend(Self::generate_l2_rule(mac, lb.unicast_ipv6_address));
            rules.extend(Self::generate_l3_rules(&lb));
        }
        let reservations = active.lock().await;
        for res in reservations.values() {
            if let Ok(mut r) = res.generate_non_epoch_rules(db).await {
                rules.append(&mut r);
            }
        }
        for res in reservations.values() {
            if let Ok(sessions) = db.get_reservation_sessions(res.reservation_id).await {
                let boundary_event = res.predict_epoch_boundary_from_sync(offset);
                if advance {
                    db.advance_epoch(res.reservation_id, offset, boundary_event)
                        .await?;
                }
                if !sessions.is_empty() {
                    if let Ok(mut r) = res.generate_epoch_rules(db).await {
                        rules.append(&mut r);
                    }
                }
            }
        }
        Ok(rules)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        db: Arc<LoadBalancerDB>,
        snp4: &mut MultiSNP4Client,
        active: Arc<Mutex<HashMap<i64, ActiveReservation>>>,
        current: Arc<Mutex<Vec<TableRule>>>,
        tick_interval: Duration,
        offset: ChronoDuration,
        mac: MacAddr6,
        dump: Option<PathBuf>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<()> {
        let mut interval = time::interval(tick_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // 2) Acquire lock for expired/cleanup and curr update
                    let mut res_map = active.lock().await;
                    let start = std::time::Instant::now();
                    Self::check_expired_reservations(&db, &mut res_map).await?;
                    let elapsed = start.elapsed().as_millis();
                    trace!("check_expired_reservations ({}ms)", elapsed);

                    let start = std::time::Instant::now();
                    Self::cleanup_sessions(&db, &res_map).await;
                    let elapsed = start.elapsed().as_millis();
                    trace!("cleanup_sessions ({}ms)", elapsed);
                    drop(res_map);

                    // 1) Compute desired without holding the active lock
                    let start = std::time::Instant::now();
                    let desired = match Self::next_epoch_rules(&db, &active, mac, offset, true).await {
                        Ok(r) => r,
                        Err(e) => { error!("failed to generate rules: {}", e); continue; }
                    };
                    let elapsed = start.elapsed().as_millis();
                    trace!("next_epoch_rules ({}ms)", elapsed);

                    let mut curr = current.lock().await;
                    if desired != *curr {
                        // apply reload or diffs with dumps
                        if Self::should_clear_tables(&db, &active).await {
                            let start = std::time::Instant::now();
                            if snp4.clear_tables().await.is_err() {
                                error!("failed to clear tables on state transition");
                            } else {
                                let upd = TableUpdate {
                                    description: "reload all rules".into(),
                                    insertions: desired.clone(),
                                    updates: Vec::new(),
                                    deletions: Vec::new(),
                                };
                                let _ = snp4.bulk_update(&[upd]).await;
                                let elapsed = start.elapsed().as_millis();
                                trace!("rules reloaded due to no sessions ({}ms)", elapsed);
                            }
                        } else {
                            let total_start = std::time::Instant::now();
                            let db_start = std::time::Instant::now();
                            let diffs = compare_rule_sets(&curr, &desired);
                            let db_time = db_start.elapsed().as_millis();
                            let mut bulk_time = 0;
                            if !diffs.is_empty() {
                                if let Some(dir) = &dump {
                                    let dump_start = std::time::Instant::now();
                                    if let Err(e) = dump_updates_to_file(dir, &diffs).await {
                                        warn!("failed to dump rule updates: {}", e);
                                    }
                                    let dump_elapsed = dump_start.elapsed().as_millis();
                                    trace!("dump_updates_to_file ({}ms)", dump_elapsed);
                                }
                                let bulk_start = std::time::Instant::now();
                                if snp4.bulk_update(&diffs).await.is_err() {
                                    warn!("failed to apply rule diff update, attempting reload");
                                    let reload_bulk_start = std::time::Instant::now();
                                    if snp4.clear_tables().await.is_ok() {
                                        let reload = TableUpdate {
                                            description: "reload all rules".into(),
                                            insertions: desired.clone(),
                                            updates: Vec::new(),
                                            deletions: Vec::new(),
                                        };
                                        let _ = snp4.bulk_update(&[reload]).await;
                                    }
                                    bulk_time += reload_bulk_start.elapsed().as_millis();
                                }
                                bulk_time += bulk_start.elapsed().as_millis();
                                let summaries = diffs.iter().map(|u| format!("{}: +{}/-{}/*{}", u.description, u.insertions.len(), u.deletions.len(), u.updates.len())).collect::<Vec<_>>();
                                let total_elapsed = total_start.elapsed().as_millis();
                                info!(
                                    "rules updated: applied rule diff [{}] (total: {}ms, db: {}ms, bulk: {}ms)",
                                    summaries.join(", "),
                                    total_elapsed,
                                    db_time,
                                    bulk_time
                                );
                            }
                        }
                        *curr = desired.clone();
                        Self::cache_rules(&db, &desired).await;
                    }

                    // 3) Metrics update
                    let mut res_map = active.lock().await;
                    for res in res_map.values_mut() {
                        if let Ok(epoch) = db.get_latest_epoch(res.reservation_id).await {
                            if let Err(e) = res.update_metrics(&db, epoch).await {
                                warn!("failed to update metrics for {}: {}", res.reservation_id, e);
                            }
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("shutting down reservation manager");
                    return Ok(());
                }
            }
        }
    }

    /// Starts a new reservation sync and metric tracking.
    pub async fn start_reservation(&mut self, reservation_id: i64, port: u16) -> Result<()> {
        let mut reservations = self.active_reservations.lock().await;
        if reservations.contains_key(&reservation_id) {
            return Ok(());
        }
        let fpga_id = self.db.get_reservation_fpga_lb_id(reservation_id).await?;
        let mut r = ActiveReservation::new(reservation_id, fpga_id as u8);
        let mut addr = self.sync_addr;
        addr.set_port(port);
        r.start_event_sync(self.db.clone(), addr).await;
        reservations.insert(reservation_id, r);
        LB_IS_ACTIVE
            .with_label_values(&[&fpga_id.to_string()])
            .set(1.0);
        Ok(())
    }

    /// Returns the FPGA LB ID for a reservation, if active.
    pub async fn get_lb_id(&self, reservation_id: i64) -> Option<u8> {
        self.active_reservations
            .lock()
            .await
            .get(&reservation_id)
            .map(|r| r.lb_fpga_id)
    }

    /// Gracefully shuts down the manager and all active reservations.
    pub async fn shutdown(&mut self) {
        info!("initiating reservation manager shutdown");
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.update_task.take() {
            let _ = task.await;
        }
        let mut map = self.active_reservations.lock().await;
        for (_, mut r) in map.drain() {
            info!("stopping reservation {}", r.reservation_id);
            r.stop_event_sync().await;
        }
        debug!("Reservation manager shut down");
    }

    /// Stops a specific reservation.
    pub async fn stop_reservation(&mut self, reservation_id: i64) {
        let mut reservations = self.active_reservations.lock().await;
        if let Some(mut r) = reservations.remove(&reservation_id) {
            r.stop_event_sync().await;
            LB_IS_ACTIVE
                .with_label_values(&[&r.lb_fpga_id.to_string()])
                .set(0.0);
            info!(
                "stopped reservation {} with load balancer ID {}",
                reservation_id, r.lb_fpga_id
            );
        } else {
            warn!(
                "attempted to stop a non-existent reservation {}",
                reservation_id
            );
        }
    }

    async fn cleanup_sessions(
        db: &Arc<LoadBalancerDB>,
        reservations: &HashMap<i64, ActiveReservation>,
    ) {
        if !reservations.is_empty() && db.cleanup_stale_sessions().await.is_err() {
            warn!("failed to cleanup stale sessions");
        }
    }

    async fn check_expired_reservations(
        db: &Arc<LoadBalancerDB>,
        reservations: &mut HashMap<i64, ActiveReservation>,
    ) -> Result<()> {
        let rows = sqlx::query!(
            "SELECT id FROM reservation WHERE deleted_at IS NULL AND reserved_until < strftime('%s','now') * 1000"
        )
        .fetch_all(&db.read_pool)
        .await
        .map_err(Error::Database)?;
        for row in rows {
            info!("stopping expired reservation {}", row.id);
            reservations.remove(&row.id);
            db.delete_reservation(row.id).await?;
        }
        Ok(())
    }
}

async fn dump_updates_to_file(dir: &PathBuf, updates: &[TableUpdate]) -> std::io::Result<()> {
    use chrono::Utc;
    use std::fs::OpenOptions;
    use std::io::Write;

    // Ensure the directory exists.
    std::fs::create_dir_all(dir)?;

    let now_str = Utc::now().format("%Y%m%d_%H%M%S%.3f").to_string();
    let filename = format!("rule_delta_{}.txt", now_str);
    let path = dir.join(&filename);

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .append(false)
        .open(&path)?;

    writeln!(file, "# epoch generated at {}", Utc::now())?;

    for (idx, table_update) in updates.iter().enumerate() {
        writeln!(
            file,
            "\n## {}: {} (+{} insertions, -{} deletions, *{} updates)",
            idx,
            table_update.description,
            table_update.insertions.len(),
            table_update.deletions.len(),
            table_update.updates.len()
        )?;

        // Dump insertions.
        for ins in &table_update.insertions {
            writeln!(file, "insert {ins}")?;
        }
        // Dump updates.
        for up in &table_update.updates {
            writeln!(file, "update {up}")?;
        }
        // Dump deletions.
        for del in &table_update.deletions {
            writeln!(file, "delete {del}")?;
        }
    }

    Ok(())
}

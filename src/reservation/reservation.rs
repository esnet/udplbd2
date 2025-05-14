// SPDX-License-Identifier: BSD-3-Clause-LBNL
use crate::db::{LoadBalancerDB, Result};
use crate::errors::Error;
use crate::metrics::LB_IS_ACTIVE;
use crate::proto::smartnic::p4_v2::TableRule;
use crate::snp4::client::MultiSNP4Client;
use crate::snp4::rules::{compare_rule_sets, Layer2InputPacketFilterRule, TableUpdate};
use crate::util::mac_to_u64;
use chrono::Utc;
use macaddr::MacAddr6;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{self, MissedTickBehavior};
use tracing::{debug, error, info, warn};

/// Manages the lifecycle of load balancer reservations and their associated resources.
pub struct ReservationManager {
    db: Arc<LoadBalancerDB>,
    smartnic_clients: MultiSNP4Client,
    active_reservations: Arc<Mutex<HashMap<i64, ActiveReservation>>>,
    tick_interval: Duration,
    tick_offset: Duration,
    mac_address: MacAddr6,
    sync_address: SocketAddr,
    pub dump_rules_dir: Option<PathBuf>,
    update_task: Option<JoinHandle<()>>,
    shutdown_tx: Option<broadcast::Sender<()>>,
    /// Central state of all rules currently applied via the SmartNIC API.
    current_rules: Arc<Mutex<Vec<TableRule>>>,
}

impl ReservationManager {
    /// Creates a new reservation manager with the specified configuration.
    #[must_use]
    pub fn new(
        db: Arc<LoadBalancerDB>,
        smartnic_clients: MultiSNP4Client,
        tick_interval: Duration,
        tick_offset: Duration,
        mac_address: MacAddr6,
        sync_address: SocketAddr,
    ) -> Self {
        Self {
            db,
            smartnic_clients,
            active_reservations: Arc::new(Mutex::new(HashMap::new())),
            tick_interval,
            tick_offset,
            mac_address,
            sync_address,
            dump_rules_dir: None,
            update_task: None,
            shutdown_tx: None,
            current_rules: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Generates Layer 2 packet filtering rules for the load balancer.
    fn generate_l2_filter_rules(mac_address: MacAddr6) -> Vec<TableRule> {
        vec![
            Layer2InputPacketFilterRule {
                match_dest_mac_addr: mac_to_u64(mac_address),
                set_src_mac_addr: mac_to_u64(mac_address),
            }
            .into(),
            Layer2InputPacketFilterRule {
                match_dest_mac_addr: 0xffffffffffff,
                set_src_mac_addr: mac_to_u64(mac_address),
            }
            .into(),
            Layer2InputPacketFilterRule {
                match_dest_mac_addr: 0x333300000001,
                set_src_mac_addr: mac_to_u64(mac_address),
            }
            .into(),
        ]
    }

    /// Initializes the reservation manager and restores any active reservations.
    pub async fn initialize(&mut self) -> Result<()> {
        // Generate base (L2) rules.
        let base_rules = Self::generate_l2_filter_rules(self.mac_address);

        // Attempt to apply the initial (base) rules.
        let initial_update = TableUpdate {
            description: "initialize l2 rules".into(),
            insertions: base_rules.clone(),
            updates: Vec::new(),
            deletions: Vec::new(),
        };

        // First attempt: try insertions
        let result = self
            .smartnic_clients
            .bulk_update(&[initial_update.clone()])
            .await;

        if let Err(insert_error) = result {
            warn!("failed to insert rules, attempting update: {insert_error:#?}");
            let update_only = TableUpdate {
                description: "initialize l2 rules (update attempt)".into(),
                insertions: Vec::new(),
                updates: base_rules.clone(),
                deletions: Vec::new(),
            };
            let update_result = self.smartnic_clients.bulk_update(&[update_only]).await;
            if let Err(update_error) = update_result {
                warn!("failed to update rules, attempting table reset: {update_error:#?}");
                if let Err(reset_error) = self.smartnic_clients.clear_tables().await {
                    error!("failed to reset tables: {:#?}", reset_error);
                    return Err(Error::NotInitialized(format!(
                        "initialization failed: {insert_error:?}, {update_error:?}, {reset_error:?}"
                    )));
                }
                if let Err(final_error) = self
                    .smartnic_clients
                    .bulk_update(&[initial_update.clone()])
                    .await
                {
                    error!(
                        "failed to insert rules after table reset: {:#?}",
                        final_error
                    );
                    return Err(Error::NotInitialized("initialization failed".to_string()));
                }
            }
        }

        // Update the central rules state.
        {
            let mut current = self.current_rules.lock().await;
            *current = base_rules.clone();
        }

        // Start all active reservations from the database.
        let reservations = self.db.list_reservations_with_load_balancer().await?;
        for (reservation, load_balancer) in reservations {
            if reservation.reserved_until > Utc::now() {
                self.start_reservation(reservation.id, load_balancer.event_number_udp_port)
                    .await?;
            }
        }

        // Start the update task.
        let db = self.db.clone();
        let smartnic_clients = self.smartnic_clients.clone();
        let active_reservations = self.active_reservations.clone();
        let current_rules = self.current_rules.clone();
        let tick_interval = self.tick_interval;
        let tick_offset = self.tick_offset;
        let unicast_mac = self.mac_address;
        let dump_rules_dir = self.dump_rules_dir.clone();

        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        self.shutdown_tx = Some(shutdown_tx);

        self.update_task = Some(tokio::spawn(async move {
            if let Err(e) = Self::run(
                db,
                smartnic_clients,
                active_reservations,
                current_rules,
                tick_interval,
                tick_offset,
                unicast_mac,
                &dump_rules_dir,
                shutdown_rx,
            )
            .await
            {
                panic!("{e}");
            }
        }));

        Ok(())
    }

    /// Computes the full desired rule set and compares it to the central state.
    ///
    /// The desired set is built from the base L2 filter rules plus all the rules generated
    /// from each active reservation. Any differences are applied via the smartnic client.
    async fn update_rules(
        db: &Arc<LoadBalancerDB>,
        smartnic_clients: &mut MultiSNP4Client,
        active_reservations: &Arc<Mutex<HashMap<i64, ActiveReservation>>>,
        unicast_mac: MacAddr6,
        current_rules: &Arc<Mutex<Vec<TableRule>>>,
        dump_rule_dir: &Option<PathBuf>,
        offset: chrono::TimeDelta,
    ) {
        let start_time = Instant::now();

        // Start with the base L2 filter rules.
        let mut desired_rules = Self::generate_l2_filter_rules(unicast_mac);

        // Gather rules from all active reservations.
        {
            let mut reservations = active_reservations.lock().await;
            for reservation in reservations.values_mut() {
                // Only advance the epoch if there is at least one session for this reservation.
                let sessions = match db
                    .get_reservation_sessions(reservation.reservation_id)
                    .await
                {
                    Ok(sessions) => sessions,
                    Err(e) => {
                        error!(
                            "failed to get sessions for reservation {}: {}",
                            reservation.reservation_id, e
                        );
                        continue;
                    }
                };
                if sessions.is_empty() {
                    // No sessions for this reservation; skip epoch advancement.
                    continue;
                }

                let boundary_event = reservation.predict_epoch_boundary_from_sync(offset);
                let epoch = match db
                    .advance_epoch(reservation.reservation_id, offset, boundary_event)
                    .await
                {
                    Ok(epoch) => epoch,
                    Err(e) => {
                        error!(
                            "failed to advance epoch for reservation {}: {}",
                            reservation.reservation_id, e
                        );
                        continue;
                    }
                };

                // Update metrics
                if let Err(e) = reservation.update_metrics(db, epoch).await {
                    error!(
                        "failed to update metrics for reservation {}: {}",
                        reservation.reservation_id, e
                    );
                }

                // Generate reservation-specific rules.
                match reservation.generate_all_rules(db).await {
                    Ok(rules) => {
                        desired_rules.extend(rules.clone());
                        // Update the reservation’s own internal state (informational only).
                        reservation.set_current_rules(rules);
                    }
                    Err(e) => {
                        error!(
                            "failed to generate rules for reservation {}: {}",
                            reservation.reservation_id, e
                        );
                    }
                }
            }
        }

        // Compare against the central state.
        let mut current = current_rules.lock().await;
        if desired_rules != *current {
            let updates = compare_rule_sets(&current, &desired_rules);
            if !updates.is_empty() {
                if let Some(dir) = dump_rule_dir {
                    if let Err(e) = dump_updates_to_file(dir, &updates).await {
                        warn!("Failed to dump rule updates: {}", e);
                    }
                }
                // First, try to apply the diff update.
                if let Err(e) = smartnic_clients.bulk_update(&updates).await {
                    warn!(
                        "Failed to apply rule diff update, attempting reload: {:#?}",
                        e
                    );
                    // On error, clear tables and reload everything.
                    if let Err(e) = smartnic_clients.clear_tables().await {
                        error!("Failed to clear tables: {:#?}", e);
                        return;
                    }
                    let reload_update = TableUpdate {
                        description: "reload all rules".to_string(),
                        insertions: desired_rules.clone(),
                        updates: Vec::new(),
                        deletions: Vec::new(),
                    };
                    if let Err(e) = smartnic_clients.bulk_update(&[reload_update]).await {
                        error!("Failed to reload rules: {:#?}", e);
                        return;
                    }
                }
                let elapsed = start_time.elapsed().as_millis();
                debug!(
                    "rules updated ({}ms): applied {} diff updates",
                    elapsed,
                    updates.len()
                );
            }
            // Update the central state.
            *current = desired_rules;
        }
    }

    /// Cleans up stale sessions.
    async fn cleanup_sessions(
        db: &Arc<LoadBalancerDB>,
        reservations: &HashMap<i64, ActiveReservation>,
    ) {
        if !reservations.is_empty() {
            if let Err(e) = db.cleanup_stale_sessions().await {
                warn!("failed to cleanup stale sessions: {}", e);
            }
        }
    }

    /// Checks for and removes expired reservations.
    async fn check_expired_reservations(
        db: &Arc<LoadBalancerDB>,
        reservations: &mut HashMap<i64, ActiveReservation>,
    ) -> Result<()> {
        let expired = match sqlx::query!(
            "SELECT id FROM reservation
             WHERE deleted_at IS NULL
             AND reserved_until < unixepoch('subsec') * 1000"
        )
        .fetch_all(&db.read_pool)
        .await
        {
            Ok(rows) => rows,
            Err(e) => {
                error!("Failed to check for expired reservations: {}", e);
                return Err(Error::Database(e));
            }
        };

        for row in expired {
            info!("stopping expired reservation {}", row.id);
            if let Some(_reservation) = reservations.remove(&row.id) {
                info!("Removed expired reservation {}", row.id);
            }
            db.delete_reservation(row.id).await?;
        }
        Ok(())
    }

    /// Main loop that handles rule updates, session cleanup, and expired reservations.
    #[allow(clippy::too_many_arguments)]
    async fn run(
        db: Arc<LoadBalancerDB>,
        mut smartnic_clients: MultiSNP4Client,
        active_reservations: Arc<Mutex<HashMap<i64, ActiveReservation>>>,
        current_rules: Arc<Mutex<Vec<TableRule>>>,
        tick_interval: Duration,
        tick_offset: Duration,
        unicast_mac: MacAddr6,
        dump_rule_dir: &Option<PathBuf>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<()> {
        let mut interval = time::interval(tick_interval);
        let offset: chrono::Duration = chrono::Duration::from_std(tick_offset)?;
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    {
                        let mut reservations = active_reservations.lock().await;
                        Self::check_expired_reservations(&db, &mut reservations).await?;
                        Self::cleanup_sessions(&db, &reservations).await;
                    }
                    Self::update_rules(&db, &mut smartnic_clients, &active_reservations, unicast_mac, &current_rules, dump_rule_dir, offset).await;
                }
                _ = shutdown_rx.recv() => {
                    info!("Shutting down reservation manager");
                    return Ok(());
                }
            }
        }
    }

    /// Starts a new reservation.
    ///
    /// Note that the new reservation is added to the active reservations list
    /// and its rules will be picked up on the next periodic update.
    pub async fn start_reservation(
        &mut self,
        reservation_id: i64,
        sync_address_port: u16,
    ) -> Result<()> {
        let mut reservations = self.active_reservations.lock().await;

        if reservations.contains_key(&reservation_id) {
            return Ok(());
        }

        let reservation_record = self.db.get_reservation(reservation_id).await?;
        let lb_id = reservation_record.fpga_lb_id as u8;
        let mut reservation = ActiveReservation::new(reservation_id, lb_id);

        // Start the event sync server.
        let mut sync_addr = self.sync_address;
        sync_addr.set_port(sync_address_port);
        reservation
            .start_event_sync(self.db.clone(), sync_addr)
            .await;

        // Do not apply reservation rules directly – let update_rules handle it.
        reservations.insert(reservation_id, reservation);

        let lb_id_str = lb_id.to_string();
        LB_IS_ACTIVE.with_label_values(&[&lb_id_str]).set(1.0);

        Ok(())
    }

    pub async fn get_lb_id(&self, reservation_id: i64) -> Option<u8> {
        let reservations = self.active_reservations.lock().await;
        reservations.get(&reservation_id).map(|res| res.lb_fpga_id)
    }

    /// Cleanly shuts down the reservation manager and all its tasks.
    pub async fn shutdown(&mut self) {
        info!("Initiating reservation manager shutdown");

        // Send shutdown signal.
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        // Wait for the update task to complete.
        if let Some(task) = self.update_task.take() {
            let _ = task.await;
        }

        // Stop all reservations.
        let mut reservations = self.active_reservations.lock().await;
        for (id, mut reservation) in reservations.drain() {
            info!("Stopping reservation {}", id);
            reservation.stop_event_sync().await;
            // self.release_lb_id(reservation.lb_fpga_id).await;
        }

        debug!("Reservation manager shut down");
    }

    /// Stops a reservation.
    ///
    /// The reservation is removed from the active set so that on the next update
    /// its rules will be automatically removed from the SmartNIC.
    pub async fn stop_reservation(&mut self, reservation_id: i64) {
        let mut reservations = self.active_reservations.lock().await;

        if let Some(mut reservation) = reservations.remove(&reservation_id) {
            let lb_id = reservation.lb_fpga_id;

            // Do not directly remove rules; update_rules will compute the new desired state.
            reservation.stop_event_sync().await;

            let lb_id_str = lb_id.to_string();
            LB_IS_ACTIVE.with_label_values(&[&lb_id_str]).set(0.0);

            info!(
                "Stopped reservation {} with load balancer ID {}",
                reservation_id, lb_id
            );
        } else {
            warn!(
                "Attempted to stop a non-existent reservation {}",
                reservation_id
            );
        }
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

// SPDX-License-Identifier: BSD-3-Clause-LBNL
use crate::db::{Epoch, LoadBalancerDB};
use crate::errors::Result;
use crate::metrics::{
    EPOCHS_PROCESSED, LB_ACTIVE_SESSIONS, LB_EPOCH_BOUNDARY, LB_FILL_PERCENT_AVG,
    LB_FILL_PERCENT_MAX, LB_FILL_PERCENT_MIN, LB_FILL_PERCENT_STDDEV, LB_SLOTS_AVG, LB_SLOTS_MAX,
    LB_SLOTS_MIN, LB_SLOTS_STDDEV,
};
use crate::proto::smartnic::p4_v2::TableRule;
use crate::snp4::rules::*;
use crate::util::{mac_to_u64, range_as_power_of_two_prefixes, Prefix};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tracing::trace;

/// Represents an active load balancer reservation with its FPGA rules and state.
pub struct ActiveReservation {
    pub reservation_id: i64,
    pub lb_fpga_id: u8,
    current_rules: Vec<TableRule>,
    event_tasks: Vec<JoinHandle<()>>,
    shutdown_txs: Vec<broadcast::Sender<()>>,
    pub event_servers: Vec<Arc<EventIdSyncServer>>,
}

impl ActiveReservation {
    pub fn new(reservation_id: i64, lb_id: u8) -> Self {
        Self {
            reservation_id,
            lb_fpga_id: lb_id,
            current_rules: Vec::new(),
            event_tasks: Vec::new(),
            shutdown_txs: Vec::new(),
            event_servers: Vec::new(),
        }
    }

    pub async fn start_event_sync(&mut self, db: Arc<LoadBalancerDB>, address: SocketAddr) {
        let event_server = Arc::new(
            super::event_id_sync::EventIdSyncServer::new(db, self.reservation_id, address).await,
        );
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let event_task = tokio::spawn(event_server.clone().run(shutdown_rx));

        self.event_tasks.push(event_task);
        self.shutdown_txs.push(shutdown_tx);
        self.event_servers.push(event_server);
    }

    /// Returns the current predicted epoch boundary using the in-memory sync server
    pub fn predict_epoch_boundary_from_sync(&self, offset: chrono::Duration) -> Option<i64> {
        // Find the server with the most recent last_modified time
        let mut best: Option<(&Arc<EventIdSyncServer>, chrono::DateTime<chrono::Utc>)> = None;
        for srv in &self.event_servers {
            if let Some(ts) = srv.last_modified() {
                if best.is_none() || ts > best.as_ref().unwrap().1 {
                    best = Some((srv, ts));
                }
            }
        }
        if let Some((srv, _)) = best {
            Some(srv.predict_epoch_boundary(offset))
        } else {
            None
        }
    }

    pub async fn stop_event_sync(&mut self) {
        for tx in self.shutdown_txs.drain(..) {
            let _ = tx.send(());
        }
        for task in self.event_tasks.drain(..) {
            let _ = task.await;
        }
        self.event_servers.clear();
    }

    /// Returns the current rules for this reservation
    pub fn get_current_rules(&self) -> &[TableRule] {
        &self.current_rules
    }

    /// Updates the current rules for this reservation
    pub fn set_current_rules(&mut self, rules: Vec<TableRule>) {
        self.current_rules = rules;
    }

    /// Generates all rules for this reservation.
    /// Assumes epoch advancement has already occurred.
    pub async fn generate_all_rules(&self, db: &LoadBalancerDB) -> Result<Vec<TableRule>> {
        let mut rules = self.generate_non_epoch_rules(db).await?;
        rules.extend(self.generate_epoch_rules(db).await?);
        Ok(rules)
    }

    /// Generates all rules for this reservation except epoch-dependent rules.
    pub async fn generate_non_epoch_rules(&self, db: &LoadBalancerDB) -> Result<Vec<TableRule>> {
        let mut rules = Vec::new();
        // Get reservation and associated loadbalancer
        let reservation = db.get_reservation(self.reservation_id).await?;
        let lb = db.get_loadbalancer(reservation.loadbalancer_id).await?;
        rules.extend(self.generate_source_filter_rules(db).await?);
        let sessions = db.get_reservation_sessions(self.reservation_id).await?;
        if !sessions.is_empty() {
            rules.extend(self.generate_member_info_rules(&lb, &sessions).await?);
        }
        Ok(rules)
    }

    /// Creates whitelist rules for authorized sender IPs.
    async fn generate_source_filter_rules(&self, db: &LoadBalancerDB) -> Result<Vec<TableRule>> {
        let senders = db.get_reservation_senders(self.reservation_id).await?;
        Ok(senders
            .into_iter()
            .map(|addr| {
                IpSrcFilterRule {
                    match_lb_instance_id: self.lb_fpga_id,
                    match_src_ip_addr: addr,
                    priority: 0,
                }
                .into()
            })
            .collect())
    }

    /// Maps session IDs to network endpoints, handling both IPv4 and IPv6.
    /// Member IDs are truncated to u16 to fit FPGA constraints.
    async fn generate_member_info_rules(
        &self,
        lb: &crate::db::models::LoadBalancer,
        sessions: &[crate::db::models::Session],
    ) -> Result<Vec<TableRule>> {
        let mut rules = Vec::new();
        for session in sessions {
            let ether_type = match session.ip_address {
                IpAddr::V4(_) => EtherType::Ipv4,
                IpAddr::V6(_) => EtherType::Ipv6,
            };

            let member_id = (session.id % (u16::MAX as i64)) as u16;
            // Use the cached MAC address if available, otherwise use the loadbalancer's MAC
            let dest_mac = session
                .mac_address
                .as_ref()
                .map(|mac| mac_to_u64(mac.parse().unwrap()))
                .unwrap_or_else(|| mac_to_u64(lb.unicast_mac_address));

            rules.push(
                MemberInfoRule {
                    match_lb_instance_id: self.lb_fpga_id,
                    match_ether_type: ether_type,
                    match_member_id: member_id,
                    set_dest_mac_addr: dest_mac,
                    set_dest_ip_addr: session.ip_address,
                    set_dest_udp_port: session.udp_port,
                    set_entropy_bit_mask_width: session.port_range as u8,
                    set_keep_lb_header: session.keep_lb_header,
                    priority: 0,
                }
                .into(),
            );
        }
        Ok(rules)
    }

    /// Generates rules for epoch transitions and member mappings.
    /// Assumes epoch advancement has already occurred.
    pub async fn generate_epoch_rules(&self, db: &LoadBalancerDB) -> Result<Vec<TableRule>> {
        // Do NOT advance epoch here; just fetch recent epochs and generate rules
        let mut rules = Vec::new();
        // Get recent epochs including the most recent one
        let mut recent_epochs = sqlx::query!(
            r#"
            SELECT id, boundary_event, epoch_count, slots
            FROM epoch
            WHERE reservation_id = ?1 AND deleted_at IS NULL
            ORDER BY created_at DESC
            LIMIT 4
            "#,
            self.reservation_id
        )
        .fetch_all(&db.write_pool)
        .await?;

        recent_epochs.reverse(); // Process oldest to newest

        trace!(
            "generate_epoch_rules: reservation_id={}, epochs_found={}: {:?}",
            self.reservation_id,
            recent_epochs.len(),
            recent_epochs
                .iter()
                .map(|e| (e.id, e.boundary_event, e.epoch_count))
                .collect::<Vec<_>>()
        );

        for (i, epoch) in recent_epochs.iter().enumerate() {
            // Generate member map rules
            let slots: Vec<u16> = epoch
                .slots
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect();

            for (slot_idx, &member_id) in slots.iter().enumerate() {
                rules.push(
                    SlotToMemberRule {
                        match_lb_instance_id: self.lb_fpga_id,
                        match_epoch: (epoch.epoch_count % 4) as u32,
                        match_slot: slot_idx as u16,
                        set_member_id: member_id,
                        priority: 0,
                    }
                    .into(),
                );
            }

            let boundaries = if i < recent_epochs.len() - 1 {
                let next_boundary = recent_epochs[i + 1].boundary_event;
                range_as_power_of_two_prefixes(epoch.boundary_event as u64, next_boundary as u64)
            } else {
                vec![Prefix {
                    start: 0,
                    power_of_two: 64,
                }]
            };

            for boundary in boundaries {
                rules.push(
                    EventIdToEpochRule {
                        match_lb_instance_id: self.lb_fpga_id,
                        match_event: boundary.start,
                        match_event_prefix_len: 64 - boundary.power_of_two,
                        set_epoch: (epoch.epoch_count % 4) as u32,
                        priority: if i == recent_epochs.len() - 1 { 63 } else { 0 },
                    }
                    .into(),
                );
            }
        }

        Ok(rules)
    }

    /// Updates metrics related to slot assignment, epoch processing, and fill percentages.
    pub async fn update_metrics(&self, db: &LoadBalancerDB, epoch: Epoch) -> Result<()> {
        EPOCHS_PROCESSED.inc();

        let lb_id = self.lb_fpga_id.to_string();

        // Count how many slots are assigned to each host
        let mut host_slot_counts = std::collections::HashMap::new();
        for &host_id in &epoch.slots {
            *host_slot_counts.entry(host_id).or_insert(0) += 1;
        }

        // If no hosts have slots, return early
        if host_slot_counts.is_empty() {
            return Ok(());
        }
        LB_ACTIVE_SESSIONS
            .with_label_values(&[&lb_id])
            .set(host_slot_counts.len() as f64);

        // Get the slot counts as a vector for statistics calculation
        let slot_counts: Vec<f64> = host_slot_counts
            .values()
            .map(|&count| count as f64)
            .collect();
        let num_hosts = slot_counts.len() as f64;

        // Calculate sum, max, and min in a single loop
        let mut sum: f64 = 0.0;
        let mut max: f64 = f64::MIN;
        let mut min: f64 = f64::MAX;

        for &count in &slot_counts {
            sum += count;

            if count > max {
                max = count;
            }
            if count < min {
                min = count;
            }
        }

        // Calculate average
        let avg = sum / num_hosts;

        // Calculate variance and standard deviation
        let mut variance: f64 = 0.0;
        for &count in &slot_counts {
            variance += (count - avg).powi(2);
        }
        variance /= num_hosts;
        let stddev = variance.sqrt();

        LB_SLOTS_AVG.with_label_values(&[&lb_id]).set(avg);
        LB_SLOTS_STDDEV.with_label_values(&[&lb_id]).set(stddev);
        LB_SLOTS_MAX.with_label_values(&[&lb_id]).set(max);
        LB_SLOTS_MIN.with_label_values(&[&lb_id]).set(min);

        LB_EPOCH_BOUNDARY
            .with_label_values(&[&lb_id])
            .set(epoch.boundary_event as f64);

        // Get the latest session states to update fill metrics
        if let Ok(session_states) = db.get_latest_session_states(self.reservation_id).await {
            if !session_states.is_empty() {
                // Calculate fill percentage statistics
                let mut fill_sum = 0.0;
                let mut fill_max = 0.0;
                let mut fill_min = 1.0;
                let num_sessions = session_states.len() as f64;

                for (_, state) in &session_states {
                    let fill = state.fill_percent;
                    fill_sum += fill;

                    if fill > fill_max {
                        fill_max = fill;
                    }
                    if fill < fill_min {
                        fill_min = fill;
                    }
                }

                let fill_avg = fill_sum / num_sessions;

                // Calculate fill percentage standard deviation
                let mut fill_variance = 0.0;
                for (_, state) in &session_states {
                    fill_variance += (state.fill_percent - fill_avg).powi(2);
                }
                fill_variance /= num_sessions;
                let fill_stddev = fill_variance.sqrt();

                // Update fill metrics
                LB_FILL_PERCENT_AVG
                    .with_label_values(&[&lb_id])
                    .set(fill_avg);
                LB_FILL_PERCENT_STDDEV
                    .with_label_values(&[&lb_id])
                    .set(fill_stddev);
                LB_FILL_PERCENT_MAX
                    .with_label_values(&[&lb_id])
                    .set(fill_max);
                LB_FILL_PERCENT_MIN
                    .with_label_values(&[&lb_id])
                    .set(fill_min);
            }
        }

        Ok(())
    }
}

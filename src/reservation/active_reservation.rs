use crate::db::{LoadBalancerDB, Result};
use crate::proto::smartnic::p4_v2::TableRule;
use crate::snp4::rules::*;
use crate::util::{
    generate_solicited_node_multicast_ipv6, generate_solicited_node_multicast_mac, mac_to_u64,
    range_as_power_of_two_prefixes, Prefix,
};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

/// Represents an active load balancer reservation with its FPGA rules and state.
pub struct ActiveReservation {
    pub reservation_id: i64,
    pub lb_fpga_id: u8,
    current_rules: Vec<TableRule>,
    event_task: Option<JoinHandle<()>>,
    shutdown_tx: Option<broadcast::Sender<()>>,
}

impl ActiveReservation {
    pub fn new(reservation_id: i64, lb_id: u8) -> Self {
        Self {
            reservation_id,
            lb_fpga_id: lb_id,
            current_rules: Vec::new(),
            event_task: None,
            shutdown_tx: None,
        }
    }

    pub fn start_event_sync(&mut self, db: Arc<LoadBalancerDB>, address: SocketAddr) {
        let event_server = EventIdSyncServer::new(db, self.reservation_id, address);
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let event_task = tokio::spawn(event_server.run(shutdown_rx));

        self.event_task = Some(event_task);
        self.shutdown_tx = Some(shutdown_tx);
    }

    pub async fn stop_event_sync(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.event_task.take() {
            let _ = task.await;
        }
    }

    /// Returns the current rules for this reservation
    pub fn get_current_rules(&self) -> &[TableRule] {
        &self.current_rules
    }

    /// Updates the current rules for this reservation
    pub fn set_current_rules(&mut self, rules: Vec<TableRule>) {
        self.current_rules = rules;
    }

    /// Generates all rules for this reservation
    pub async fn generate_all_rules(&self, db: &LoadBalancerDB) -> Result<Vec<TableRule>> {
        let mut rules = Vec::new();

        // Get reservation and associated loadbalancer
        let reservation = db.get_reservation(self.reservation_id).await?;
        let lb = db.get_loadbalancer(reservation.loadbalancer_id).await?;

        rules.extend(self.generate_l2_filter_rules(&lb));
        rules.extend(self.generate_l3_filter_rules(&lb));
        rules.extend(self.generate_source_filter_rules(db).await?);

        let sessions = db.get_reservation_sessions(self.reservation_id).await?;

        if !sessions.is_empty() {
            rules.extend(self.generate_member_info_rules(&lb, &sessions).await?);
            rules.extend(self.generate_epoch_rules(db).await?);
        }

        Ok(rules)
    }

    /// Generates L2 filter rule for IPv6 neighbor discovery
    fn generate_l2_filter_rules(&self, lb: &crate::db::models::LoadBalancer) -> Vec<TableRule> {
        vec![Layer2InputPacketFilterRule {
            match_dest_mac_addr: generate_solicited_node_multicast_mac(&lb.unicast_ipv6_address),
            set_src_mac_addr: mac_to_u64(lb.unicast_mac_address),
        }
        .into()]
    }

    /// Generates L3 filter rules for IPv4/IPv6 and ARP handling.
    fn generate_l3_filter_rules(&self, lb: &crate::db::models::LoadBalancer) -> Vec<TableRule> {
        vec![
            IpDstToLbInstanceRule {
                match_ether_type: EtherType::Ipv4,
                match_dest_ip_addr: IpAddr::V4(lb.unicast_ipv4_address),
                set_src_ip_addr: IpAddr::V4(lb.unicast_ipv4_address),
                set_lb_instance_id: self.lb_fpga_id,
            }
            .into(),
            IpDstToLbInstanceRule {
                match_ether_type: EtherType::Ipv4Arp,
                match_dest_ip_addr: IpAddr::V4(lb.unicast_ipv4_address),
                set_src_ip_addr: IpAddr::V4(lb.unicast_ipv4_address),
                set_lb_instance_id: self.lb_fpga_id,
            }
            .into(),
            IpDstToLbInstanceRule {
                match_ether_type: EtherType::Ipv6,
                match_dest_ip_addr: IpAddr::V6(lb.unicast_ipv6_address),
                set_src_ip_addr: IpAddr::V6(lb.unicast_ipv6_address),
                set_lb_instance_id: self.lb_fpga_id,
            }
            .into(),
            IpDstToLbInstanceRule {
                match_ether_type: EtherType::Ipv6,
                match_dest_ip_addr: IpAddr::V6(generate_solicited_node_multicast_ipv6(
                    &lb.unicast_ipv6_address,
                )),
                set_src_ip_addr: IpAddr::V6(lb.unicast_ipv6_address),
                set_lb_instance_id: self.lb_fpga_id,
            }
            .into(),
        ]
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
    async fn generate_epoch_rules(&self, db: &LoadBalancerDB) -> Result<Vec<TableRule>> {
        let mut rules = Vec::new();
        let mut recent_epochs = sqlx::query!(
            r#"
            SELECT id, boundary_event, slots
            FROM epoch
            WHERE reservation_id = ?1 AND deleted_at IS NULL
            ORDER BY created_at DESC
            LIMIT 3
            "#,
            self.reservation_id
        )
        .fetch_all(&db.read_pool)
        .await?;

        recent_epochs.reverse(); // Process oldest to newest

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
                        match_epoch: epoch.id as u32,
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
                        set_epoch: epoch.id as u32,
                        priority: if i == recent_epochs.len() - 1 { 63 } else { 0 },
                    }
                    .into(),
                );
            }
        }

        Ok(rules)
    }
}

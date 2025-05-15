// SPDX-License-Identifier: BSD-3-Clause-LBNL
use crate::dataplane::protocol::{LBPayload, ReassemblyPayload, REASSEMBLY_HEADER_SIZE};
use crate::errors::Error;
use crate::proto::smartnic::p4_v2::{
    self, batch_request, batch_response, smartnic_p4_server::SmartnicP4, BatchOperation,
    BatchRequest, BatchResponse, DeviceInfo, DeviceInfoRequest, DeviceInfoResponse,
    PipelineInfoRequest, PipelineInfoResponse, PipelineStatsRequest, PipelineStatsResponse,
    ServerConfigRequest, ServerConfigResponse, ServerStatusRequest, ServerStatusResponse,
    StatsResponse, TableRequest, TableResponse, TableRule, TableRuleResponse,
};
use crate::snp4::rules::{
    parse_rule, EtherType, EventIdToEpochRule, IpSrcFilterRule, MemberInfoRule, RuleType,
    SlotToMemberRule,
};
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

const EC_OK: i32 = 1;

/// Represents a load balancer instance listening on a specific IP.
///
/// In this Tokio-based version, instead of spawning a blocking thread,
/// we spawn an asynchronous task that uses `tokio::net::UdpSocket`.
#[derive(Debug, Clone)]
struct MockLoadBalancer {
    lb_id: u8,
    src_ip: IpAddr,
    // Shared dataplane state.
    state: Arc<Mutex<MockDataplaneState>>,
    /// Shutdown flag (set by dataplane rule changes, for example)
    shutdown: Arc<AtomicBool>,
}

impl MockLoadBalancer {
    fn new(
        lb_id: u8,
        src_ip: IpAddr,
        state: Arc<Mutex<MockDataplaneState>>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            lb_id,
            src_ip,
            state,
            shutdown: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Spawns a Tokio task that binds a UDP socket on port 0x4c42
    /// and then continuously processes incoming UDP packets.
    ///
    /// Returns a JoinHandle for the spawned task.
    fn start(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            // Bind a UDP socket to our LB source IP at port 0x4c42.
            let addr = SocketAddr::new(self.src_ip, 0x4c42);
            let socket = match UdpSocket::bind(addr).await {
                Ok(s) => s,
                Err(e) => {
                    error!("failed to bind LB socket at {}: {}", addr, e);
                    return;
                }
            };

            // Pre-allocate a buffer.
            let mut buf = vec![0u8; 65536];
            info!("spawned new mock LB on {}:{}", self.src_ip, 0x4c42);

            loop {
                // Use a timeout so that we periodically check the shutdown flag.
                match tokio::time::timeout(Duration::from_millis(100), socket.recv_from(&mut buf))
                    .await
                {
                    // Got a packet.
                    Ok(Ok((len, src_addr))) => {
                        // If shutdown was requested, exit.
                        if self.shutdown.load(Ordering::Relaxed) {
                            break;
                        }

                        let data = &buf[..len];

                        // Lock the shared dataplane state.
                        // (Note: In production you might consider a try-lock or other strategy
                        // to avoid holding the lock for too long.)
                        let mut state = self.state.lock().await;
                        // Check whether the source IP is allowed.
                        if !state.is_source_allowed(self.lb_id, src_addr.ip()) {
                            continue;
                        }

                        // Process the packet and, if successful, forward it.
                        if let Some((payload, dst_addr)) = self.process_packet(data, &mut state) {
                            if let Err(e) = socket.send_to(&payload, dst_addr).await {
                                error!(
                                    "Failed to forward packet: could not send to {}: {}",
                                    dst_addr, e
                                );
                            }
                        }
                    }
                    // Underlying socket error.
                    Ok(Err(e)) => {
                        error!("Socket error on {}: {}", self.src_ip, e);
                        break;
                    }
                    // Timeout elapsed: check shutdown flag and then continue.
                    Err(_) => {
                        if self.shutdown.load(Ordering::Relaxed) {
                            break;
                        }
                        // Otherwise, loop again.
                    }
                }
            }
            info!("Mock LB task for {} shutting down", self.src_ip);
        })
    }

    /// Processes an incoming UDP packet.
    ///
    /// Returns an optional tuple with the payload to forward and the destination address.
    fn process_packet(
        &self,
        data: &[u8],
        state: &mut MockDataplaneState,
    ) -> Option<(Vec<u8>, SocketAddr)> {
        // Parse the LB header and payload.
        let lb_payload = match LBPayload::parse(data) {
            Some(payload) => payload,
            None => {
                debug!("failed to parse LB payload from data: {:?}", data);
                return None;
            }
        };

        if !lb_payload.header.is_valid() {
            debug!("invalid LB header in packet from {}.", self.src_ip);
            return None;
        }

        let tick = lb_payload.header.tick.get();

        // Look up the epoch based on the tick.
        let epoch = match state.get_epoch(self.lb_id, tick) {
            Some(epoch) => epoch,
            None => {
                debug!(
                    "no matching epoch found for lb_id {} with tick {}",
                    self.lb_id, tick
                );
                return None;
            }
        };

        // Calendar slot from lower 9 bits of tick.
        let slot = (tick & 0x1FF) as u16;

        // Look up the member ID from the calendar.
        let member_id = match state.get_member_id(self.lb_id, epoch, slot) {
            Some(id) => id,
            None => {
                debug!(
                    "no matching member ID for lb_id {} epoch {} slot {}",
                    self.lb_id, epoch, slot
                );
                return None;
            }
        };

        // Retrieve member info.
        let member = match state.get_member_info(self.lb_id, member_id) {
            Some(info) => info,
            None => {
                debug!(
                    "no member info for lb_id {} member_id {}",
                    self.lb_id, member_id
                );
                return None;
            }
        };

        // Calculate destination UDP port using entropy.
        let entropy_mask = (1u16 << member.set_entropy_bit_mask_width) - 1;
        let dst_port = member.set_dest_udp_port + (lb_payload.header.entropy.get() & entropy_mask);
        let dst_addr = SocketAddr::new(member.set_dest_ip_addr, dst_port);

        // ==== split‐event detection based on ReassemblyHeader ====
        if let Some(reasm) = ReassemblyPayload::parse(&lb_payload.body) {
            let rh = &reasm.header;
            let tick = rh.tick.get();
            let data_id = rh.data_id.get();
            let length = rh.length.get() as usize;
            // all fragments except the last carry a payload = total_body_len - header
            let frag_size = lb_payload.body.len() - REASSEMBLY_HEADER_SIZE;
            let total_parts = length.div_ceil(frag_size);

            let key = (tick, data_id);
            let mut remove = false;
            let mut log_split = None;
            {
                if let Some((first_dest, seen, expect)) = state.partial_event_routes.get_mut(&key) {
                    // split if dest changes
                    if *first_dest != dst_addr {
                        log_split = Some((*first_dest, dst_addr));
                    }
                    *seen += 1;
                    if *seen >= *expect {
                        remove = true;
                    }
                } else {
                    // first fragment seen
                    state
                        .partial_event_routes
                        .insert(key, (dst_addr, 1, total_parts));
                    if total_parts == 1 {
                        // single‐fragment event → remove immediately
                        remove = true;
                    }
                }
            }
            if let Some((first_dest, dst_addr)) = log_split {
                let epoch_rule = state.find_epoch_rule(self.lb_id, tick);
                let slot_rule = state.find_slot_rule(self.lb_id, epoch, slot);
                warn!(
                    "mock dp: split event detected tick={} data_id={} first→{} now→{}; epoch_rule={:?}, slot_rule={:?}",
                    tick, data_id, first_dest, dst_addr, epoch_rule, slot_rule
                );
            }
            if remove {
                state.partial_event_routes.remove(&key);
            }
        }

        Some((lb_payload.body.to_vec(), dst_addr))
    }
}

/// Simulated dataplane state.
///
/// Note: The only difference from the original is that we now store LB tasks
/// as tokio::task::JoinHandle rather than thread join handles.
#[derive(Debug, Default)]
struct MockDataplaneState {
    /// Maps LB source IP addresses to their LB instances.
    lb_instances: HashMap<IpAddr, MockLoadBalancer>,
    /// Maps lb_id to epoch assignment rules (sorted by prefix length, longest first).
    epochs: HashMap<u8, Vec<EventIdToEpochRule>>,
    /// Maps (lb_id, epoch, slot) to calendar (slot-to-member) rules.
    calendar: HashMap<(u8, u32, u16), SlotToMemberRule>,
    /// Maps (lb_id, member_id) to member info rules.
    members: HashMap<(u8, u16), MemberInfoRule>,
    /// Maps (lb_id, src_ip) to source filter rules.
    allowed_sources: HashMap<(u8, IpAddr), IpSrcFilterRule>,
    /// Active LB tasks.
    lb_tasks: HashMap<IpAddr, tokio::task::JoinHandle<()>>,
    /// Tracks (first_dest, seen_count, total_parts) per tick so we can detect splits
    /// and remove entries once fully forwarded.
    partial_event_routes: HashMap<(u64, u16), (SocketAddr, usize, usize)>,
}

impl MockDataplaneState {
    fn get_epoch(&self, lb_id: u8, tick: u64) -> Option<u32> {
        let entries = self.epochs.get(&lb_id)?;
        // Find the first rule with the longest matching prefix.
        for entry in entries {
            let mask = match entry.match_event_prefix_len {
                64 => u64::MAX,
                0 => 0, // Zero-length prefix: use mask 0.
                n => ((1u64 << n) - 1) << (64 - n),
            };

            if (tick & mask) == (entry.match_event & mask) {
                return Some(entry.set_epoch);
            }
        }
        None
    }

    fn get_member_id(&self, lb_id: u8, epoch: u32, slot: u16) -> Option<u16> {
        self.calendar
            .get(&(lb_id, epoch, slot))
            .map(|rule| rule.set_member_id)
    }

    fn get_member_info(&self, lb_id: u8, member_id: u16) -> Option<&MemberInfoRule> {
        self.members.get(&(lb_id, member_id))
    }

    fn is_source_allowed(&self, lb_id: u8, src_ip: IpAddr) -> bool {
        self.allowed_sources.contains_key(&(lb_id, src_ip))
    }

    fn delete_rule(&mut self, rule: &TableRule) -> Result<(), Error> {
        match parse_rule(rule)? {
            RuleType::IpDst(r) => {
                // Remove the LB instance and signal shutdown.
                if let Some(lb) = self.lb_instances.remove(&r.set_src_ip_addr) {
                    lb.shutdown.store(true, Ordering::Relaxed);
                }
                // Remove and drop the associated LB task.
                self.lb_tasks.remove(&r.set_src_ip_addr);
            }
            RuleType::IpSrc(r) => {
                self.allowed_sources
                    .remove(&(r.match_lb_instance_id, r.match_src_ip_addr));
            }
            RuleType::Epoch(r) => {
                if let Some(entries) = self.epochs.get_mut(&r.match_lb_instance_id) {
                    entries.retain(|e| {
                        e.match_event != r.match_event
                            || e.match_event_prefix_len != r.match_event_prefix_len
                    });
                }
            }
            RuleType::Slot(r) => {
                self.calendar
                    .remove(&(r.match_lb_instance_id, r.match_epoch, r.match_slot));
            }
            RuleType::MemberInfo(r) => {
                self.members
                    .remove(&(r.match_lb_instance_id, r.match_member_id));
            }
            _ => {}
        }
        Ok(())
    }

    /// Parses and applies a table rule.
    ///
    /// When `rule.replace` is true, an existing rule of the same type is replaced.
    /// For LB (IpDst) rules, this will create (or replace) a LB instance and spawn its task.
    fn parse_rule_params(
        &mut self,
        rule: &TableRule,
        shared: Arc<Mutex<MockDataplaneState>>,
    ) -> Result<(), Error> {
        match parse_rule(rule)? {
            RuleType::IpDst(r) => {
                // Only process IPv4 addresses.
                if !(r.match_dest_ip_addr.is_ipv4()
                    && r.match_ether_type as isize == EtherType::Ipv4 as isize)
                {
                    return Ok(());
                }
                // If replacing an existing LB, signal shutdown and remove its task.
                if rule.replace {
                    if let Some(existing_lb) = self.lb_instances.get(&r.set_src_ip_addr) {
                        existing_lb.shutdown.store(true, Ordering::Relaxed);
                    }
                    self.lb_tasks.remove(&r.set_src_ip_addr);
                }
                // Create a new LB instance.
                let lb =
                    MockLoadBalancer::new(r.set_lb_instance_id, r.set_src_ip_addr, shared.clone())
                        .map_err(|e| Error::Config(format!("Failed to create LB: {}", e)))?;
                let join_handle = lb.clone().start();
                self.lb_instances.insert(r.set_src_ip_addr, lb);
                self.lb_tasks.insert(r.set_src_ip_addr, join_handle);
            }
            RuleType::IpSrc(r) => {
                self.allowed_sources
                    .insert((r.match_lb_instance_id, r.match_src_ip_addr), r);
            }
            RuleType::Epoch(r) => {
                let entries = self.epochs.entry(r.match_lb_instance_id).or_default();
                if rule.replace {
                    if let Some(pos) = entries.iter().position(|e| {
                        e.match_event == r.match_event
                            && e.match_event_prefix_len == r.match_event_prefix_len
                    }) {
                        entries[pos] = r;
                    } else {
                        entries.push(r);
                    }
                } else {
                    entries.push(r);
                }
                // Ensure most specific (largest prefix) rules come first,
                // and for equal prefix, lower priority comes first.
                entries.sort_by(|a, b| {
                    b.match_event_prefix_len
                        .cmp(&a.match_event_prefix_len)
                        .then_with(|| a.priority.cmp(&b.priority))
                });
            }
            RuleType::Slot(r) => {
                self.calendar
                    .insert((r.match_lb_instance_id, r.match_epoch, r.match_slot), r);
            }
            RuleType::MemberInfo(r) => {
                self.members
                    .insert((r.match_lb_instance_id, r.match_member_id), r);
            }
            _ => {}
        }
        Ok(())
    }

    /// Find the epoch rule that matched this tick (so we can log it later).
    fn find_epoch_rule(&self, lb_id: u8, tick: u64) -> Option<&EventIdToEpochRule> {
        let entries = self.epochs.get(&lb_id)?;
        entries.iter().find(|entry| {
            let mask = match entry.match_event_prefix_len {
                64 => u64::MAX,
                0 => 0,
                n => ((1u64 << n) - 1) << (64 - n),
            };
            (tick & mask) == (entry.match_event & mask)
        })
    }

    /// Find the slot rule that matched this epoch & slot (so we can log it later).
    fn find_slot_rule(&self, lb_id: u8, epoch: u32, slot: u16) -> Option<&SlotToMemberRule> {
        self.calendar.get(&(lb_id, epoch, slot))
    }
}

/// Simulated dataplane implementing the SmartNIC P4 gRPC API.
///
/// (The gRPC methods are essentially the same as in the original code.)
pub struct MockDataplane {
    state: Arc<Mutex<MockDataplaneState>>,
}

impl MockDataplane {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(MockDataplaneState::default())),
        }
    }

    /// Process a table rule request.
    async fn process_table_rule(
        &self,
        op: BatchOperation,
        rule: &TableRule,
    ) -> Result<batch_response::Item, Status> {
        let mut state = self.state.lock().await;

        match op {
            BatchOperation::BopInsert => {
                if let Err(e) = state.parse_rule_params(rule, self.state.clone()) {
                    warn!("Failed to parse rule parameters: {}. Rule: {:?}", e, rule);
                }
            }
            BatchOperation::BopDelete => {
                if let Err(e) = state.delete_rule(rule) {
                    warn!("Failed to delete rule: {}", e);
                }
            }
            _ => {
                return Err(Status::invalid_argument("unimplemented batch operation"));
            }
        }

        Ok(batch_response::Item::TableRule(p4_v2::TableRuleResponse {
            error_code: EC_OK,
            dev_id: 0,
            pipeline_id: 0,
        }))
    }
}

impl Default for MockDataplane {
    fn default() -> Self {
        Self::new()
    }
}

#[tonic::async_trait]
impl SmartnicP4 for MockDataplane {
    type GetPipelineInfoStream = ReceiverStream<Result<PipelineInfoResponse, Status>>;
    type GetDeviceInfoStream = ReceiverStream<Result<DeviceInfoResponse, Status>>;
    type GetPipelineStatsStream = ReceiverStream<Result<PipelineStatsResponse, Status>>;
    type ClearPipelineStatsStream = ReceiverStream<Result<PipelineStatsResponse, Status>>;
    type GetServerConfigStream = ReceiverStream<Result<ServerConfigResponse, Status>>;
    type SetServerConfigStream = ReceiverStream<Result<ServerConfigResponse, Status>>;
    type GetServerStatusStream = ReceiverStream<Result<ServerStatusResponse, Status>>;
    type ClearTableStream = ReceiverStream<Result<TableResponse, Status>>;
    type BatchStream = ReceiverStream<Result<BatchResponse, Status>>;
    type InsertTableRuleStream = ReceiverStream<Result<TableRuleResponse, Status>>;
    type DeleteTableRuleStream = ReceiverStream<Result<TableRuleResponse, Status>>;
    type GetStatsStream = ReceiverStream<Result<StatsResponse, Status>>;
    type ClearStatsStream = ReceiverStream<Result<StatsResponse, Status>>;

    async fn get_pipeline_info(
        &self,
        _request: Request<PipelineInfoRequest>,
    ) -> Result<Response<Self::GetPipelineInfoStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let _ = tx
            .send(Ok(PipelineInfoResponse {
                error_code: EC_OK,
                dev_id: 0,
                pipeline_id: 0,
                info: None,
            }))
            .await;
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn get_device_info(
        &self,
        _request: Request<DeviceInfoRequest>,
    ) -> Result<Response<Self::GetDeviceInfoStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let _ = tx
            .send(Ok(DeviceInfoResponse {
                error_code: EC_OK,
                dev_id: 0,
                info: Some(DeviceInfo {
                    pci: None,
                    build: None,
                }),
            }))
            .await;
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn get_pipeline_stats(
        &self,
        _request: Request<PipelineStatsRequest>,
    ) -> Result<Response<Self::GetPipelineStatsStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let _ = tx
            .send(Ok(PipelineStatsResponse {
                error_code: EC_OK,
                dev_id: 0,
                pipeline_id: 0,
                stats: None,
            }))
            .await;
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn clear_pipeline_stats(
        &self,
        _request: Request<PipelineStatsRequest>,
    ) -> Result<Response<Self::ClearPipelineStatsStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let _ = tx
            .send(Ok(PipelineStatsResponse {
                error_code: EC_OK,
                dev_id: 0,
                pipeline_id: 0,
                stats: None,
            }))
            .await;
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn get_server_config(
        &self,
        _request: Request<ServerConfigRequest>,
    ) -> Result<Response<Self::GetServerConfigStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let _ = tx
            .send(Ok(ServerConfigResponse {
                error_code: EC_OK,
                config: None,
            }))
            .await;
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn set_server_config(
        &self,
        _request: Request<ServerConfigRequest>,
    ) -> Result<Response<Self::SetServerConfigStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let _ = tx
            .send(Ok(ServerConfigResponse {
                error_code: EC_OK,
                config: None,
            }))
            .await;
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn get_server_status(
        &self,
        _request: Request<ServerStatusRequest>,
    ) -> Result<Response<Self::GetServerStatusStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let _ = tx
            .send(Ok(ServerStatusResponse {
                error_code: EC_OK,
                status: None,
            }))
            .await;
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn clear_table(
        &self,
        request: Request<TableRequest>,
    ) -> Result<Response<Self::ClearTableStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        // Lock state and clear all tables if table_name is empty.
        let mut state = self.state.lock().await;

        if request.get_ref().table_name.is_empty() {
            // Clear all LB state and rules.
            let lb_instances = std::mem::take(&mut state.lb_instances);
            let lb_tasks = std::mem::take(&mut state.lb_tasks);

            state.epochs.clear();
            state.calendar.clear();
            state.members.clear();
            state.allowed_sources.clear();
            drop(state);

            // Signal shutdown for each LB.
            for lb in lb_instances.values() {
                lb.shutdown.store(true, Ordering::Relaxed);
            }
            // Await each LB task.
            for (_ip, handle) in lb_tasks {
                let _ = handle.await;
            }
        } else {
            // For non-empty table names, nothing is stored.
        }

        let _ = tx
            .send(Ok(TableResponse {
                error_code: EC_OK,
                dev_id: 0,
                pipeline_id: 0,
            }))
            .await;
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn batch(
        &self,
        request: Request<tonic::Streaming<BatchRequest>>,
    ) -> Result<Response<Self::BatchStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(4096);
        let mut stream = request.into_inner();

        while let Some(batch_req) = stream.message().await? {
            match batch_req.item {
                Some(batch_request::Item::TableRule(rule_request)) => {
                    let mut responses = Vec::new();
                    for rule in rule_request.rules {
                        match self
                            .process_table_rule(
                                BatchOperation::try_from(batch_req.op)
                                    .unwrap_or(BatchOperation::BopUnknown),
                                &rule,
                            )
                            .await
                        {
                            Ok(item) => responses.push(item),
                            Err(status) => {
                                let _ = tx.send(Err(status)).await;
                                continue;
                            }
                        }
                    }
                    for response in responses {
                        let _ = tx
                            .send(Ok(BatchResponse {
                                error_code: EC_OK,
                                op: batch_req.op,
                                item: Some(response),
                            }))
                            .await;
                    }
                }
                None => {
                    let _ = tx
                        .send(Err(Status::invalid_argument("Missing batch item")))
                        .await;
                }
                _ => {
                    let _ = tx.send(Err(Status::unimplemented("Not implemented"))).await;
                }
            }
        }
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn insert_table_rule(
        &self,
        _request: Request<p4_v2::TableRuleRequest>,
    ) -> Result<Response<Self::InsertTableRuleStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let _ = tx
            .send(Ok(TableRuleResponse {
                error_code: EC_OK,
                dev_id: 0,
                pipeline_id: 0,
            }))
            .await;
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn delete_table_rule(
        &self,
        _request: Request<p4_v2::TableRuleRequest>,
    ) -> Result<Response<Self::DeleteTableRuleStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let _ = tx
            .send(Ok(TableRuleResponse {
                error_code: EC_OK,
                dev_id: 0,
                pipeline_id: 0,
            }))
            .await;
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn get_stats(
        &self,
        _request: Request<p4_v2::StatsRequest>,
    ) -> Result<Response<Self::GetStatsStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let _ = tx
            .send(Ok(StatsResponse {
                error_code: EC_OK,
                dev_id: 0,
                stats: None,
            }))
            .await;
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn clear_stats(
        &self,
        _request: Request<p4_v2::StatsRequest>,
    ) -> Result<Response<Self::ClearStatsStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let _ = tx
            .send(Ok(StatsResponse {
                error_code: EC_OK,
                dev_id: 0,
                stats: None,
            }))
            .await;
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::smartnic::p4_v2::{
        r#match::Type as MatchType, Action, ActionParameter, Match, MatchKeyOnly, MatchKeyPrefix,
    };

    #[tokio::test]
    async fn test_batch_insert_rule() {
        let dp = MockDataplane::new();

        // Create a test rule.
        let rule = TableRule {
            table_name: "test_table".to_string(),
            matches: vec![Match {
                r#type: Some(MatchType::KeyOnly(MatchKeyOnly {
                    key: "test_key".to_string(),
                })),
            }],
            action: None,
            priority: 0,
            replace: false,
        };

        // Process the rule.
        let response = dp
            .process_table_rule(BatchOperation::BopInsert, &rule)
            .await
            .unwrap();

        if let batch_response::Item::TableRule(resp) = response {
            assert_eq!(resp.error_code, EC_OK);
        } else {
            panic!("Unexpected response type");
        }
    }

    #[tokio::test]
    async fn test_clear_table() {
        let dp = MockDataplane::new();

        // Insert a test rule.
        let rule = TableRule {
            table_name: "test_table".to_string(),
            matches: vec![],
            action: None,
            priority: 0,
            replace: false,
        };
        let _ = dp
            .process_table_rule(BatchOperation::BopInsert, &rule)
            .await
            .unwrap();

        // Clear all state (simulate clearing all tables).
        let request = Request::new(TableRequest {
            dev_id: 0,
            pipeline_id: 0,
            table_name: "".to_string(),
        });
        let _ = dp.clear_table(request).await.unwrap();

        // Verify that all rule maps and LB instances have been cleared.
        let state = dp.state.lock().await;
        assert!(state.lb_instances.is_empty());
        assert!(state.epochs.is_empty());
        assert!(state.calendar.is_empty());
        assert!(state.members.is_empty());
        assert!(state.allowed_sources.is_empty());
    }

    #[tokio::test]
    async fn test_epoch_lpm_match() {
        let dp = MockDataplane::new();

        // Create two epoch assignment rules with different prefix lengths.
        let rules = vec![
            // Most specific (32-bit prefix).
            TableRule {
                table_name: "epoch_assign_table".to_string(),
                matches: vec![
                    Match {
                        r#type: Some(MatchType::KeyOnly(MatchKeyOnly {
                            key: "0x01".to_string(), // lb_id = 1.
                        })),
                    },
                    Match {
                        r#type: Some(MatchType::KeyPrefix(MatchKeyPrefix {
                            key: "0x1234567800000000".to_string(),
                            prefix_length: 32,
                        })),
                    },
                ],
                action: Some(Action {
                    name: "do_assign_epoch".to_string(),
                    parameters: vec![ActionParameter {
                        value: "0x1".to_string(), // epoch 1.
                    }],
                }),
                priority: 0,
                replace: false,
            },
            // Less specific (16-bit prefix).
            TableRule {
                table_name: "epoch_assign_table".to_string(),
                matches: vec![
                    Match {
                        r#type: Some(MatchType::KeyOnly(MatchKeyOnly {
                            key: "0x01".to_string(), // lb_id = 1.
                        })),
                    },
                    Match {
                        r#type: Some(MatchType::KeyPrefix(MatchKeyPrefix {
                            key: "0x1234000000000000".to_string(),
                            prefix_length: 16,
                        })),
                    },
                ],
                action: Some(Action {
                    name: "do_assign_epoch".to_string(),
                    parameters: vec![ActionParameter {
                        value: "0x2".to_string(), // epoch 2.
                    }],
                }),
                priority: 0,
                replace: false,
            },
        ];

        for rule in rules {
            dp.process_table_rule(BatchOperation::BopInsert, &rule)
                .await
                .unwrap();
        }

        let state = dp.state.lock().await;
        let epoch = state
            .get_epoch(1, 0x1234567812345678)
            .expect("Failed to match 32-bit prefix");
        assert_eq!(epoch, 1);

        let epoch = state
            .get_epoch(1, 0x1234111111111111)
            .expect("Failed to match 16-bit prefix");
        assert_eq!(epoch, 2);

        assert!(state.get_epoch(1, 0x5555555555555555).is_none());
    }

    #[tokio::test]
    async fn test_calendar_lookup() {
        let dp = MockDataplane::new();

        // Create a calendar entry.
        let rule = TableRule {
            table_name: "load_balance_calendar_table".to_string(),
            matches: vec![
                Match {
                    r#type: Some(MatchType::KeyOnly(MatchKeyOnly {
                        key: "0x01".to_string(), // lb_id = 1.
                    })),
                },
                Match {
                    r#type: Some(MatchType::KeyOnly(MatchKeyOnly {
                        key: "0x01".to_string(), // epoch = 1.
                    })),
                },
                Match {
                    r#type: Some(MatchType::KeyOnly(MatchKeyOnly {
                        key: "0x42".to_string(), // slot = 0x42.
                    })),
                },
            ],
            action: Some(Action {
                name: "do_assign_member".to_string(),
                parameters: vec![ActionParameter {
                    value: "0x0123".to_string(), // member_id = 0x0123.
                }],
            }),
            priority: 0,
            replace: false,
        };

        dp.process_table_rule(BatchOperation::BopInsert, &rule)
            .await
            .unwrap();

        let state = dp.state.lock().await;
        let member_id = state
            .get_member_id(1, 1, 0x42)
            .expect("Failed to get member ID");
        assert_eq!(member_id, 0x0123);

        assert!(state.get_member_id(1, 1, 0x43).is_none());
    }
}

/// Reassemble EJFAT events
/// This file is included in both udplbd::dataplane::receiver and udplbd::dataplane::turmoil::receiver
use crate::api::client::ControlPlaneClient;
use crate::dataplane::meta_events::{MetaEventContext, MetaEventType};
use crate::dataplane::protocol::EjfatEvent;
use crate::dataplane::protocol::*;
use crate::errors::Error;
use crate::proto::loadbalancer::v1::PortRange;

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Mutex, RwLock};
use tokio::time::timeout;
use tracing::warn;
use zerocopy::FromBytes;

use std::collections::HashMap;
use thiserror::Error;

#[derive(Default, Debug, Clone, serde::Serialize)]
pub struct ReassemblyStats {
    pub total_events_recv: i64,
    pub total_events_reassembled: i64,
    pub total_events_reassembly_err: i64,
    pub total_events_dequeued: i64,
    pub total_event_enqueue_err: i64,
    pub total_bytes_recv: i64,
    pub total_packets_recv: i64,
}

pub struct ReassemblyBuffer {
    data: Vec<u8>,
    received_packets: Vec<bool>,
    expected_packets_count: usize,
    recieved_packets_count: usize,
}

impl ReassemblyBuffer {
    fn new(length: usize, packet_size: usize) -> Self {
        let num_packets = length.div_ceil(packet_size);
        Self {
            data: vec![0; length],
            received_packets: vec![false; num_packets],
            expected_packets_count: num_packets,
            recieved_packets_count: 0,
        }
    }

    fn insert(
        &mut self,
        offset: usize,
        packet_size: usize,
        fragment: &[u8],
    ) -> Result<(), ReassemblyError> {
        let packet_index = offset / packet_size;

        if offset + fragment.len() > self.data.len() {
            return Err(ReassemblyError::TooLargeForLength);
        }

        if self.received_packets[packet_index] {
            return Err(ReassemblyError::DuplicateOrOverlappingFragment);
        }

        self.data[offset..offset + fragment.len()].copy_from_slice(fragment);
        self.received_packets[packet_index] = true;
        self.recieved_packets_count += 1;

        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.recieved_packets_count == self.expected_packets_count
    }

    pub fn missing_packets(&self) -> Vec<usize> {
        self.received_packets
            .iter()
            .enumerate()
            .filter(|(_, &received)| !received)
            .map(|(i, _)| i)
            .collect()
    }

    pub fn has_missing_middle_packet(&self) -> bool {
        let num_packets = self.received_packets.len();
        self.received_packets[1..num_packets - 1]
            .iter()
            .any(|&received| !received)
    }

    pub fn received_packets_count(&self) -> usize {
        self.recieved_packets_count
    }
}

#[derive(Error, Debug)]
pub enum ReassemblyError {
    #[error("Packet contains more data than length field from previous")]
    TooLargeForLength,

    #[error("Packet too small")]
    PacketTooSmall,

    #[error("Duplicate or overlapping fragment")]
    DuplicateOrOverlappingFragment,

    #[error("Maximum memory limit reached")]
    MaxMemoryLimitReached,
}

const RE_OVERHEAD: usize =
    std::mem::size_of::<(u64, u16)>() + std::mem::size_of::<ReassemblyBuffer>();

pub struct Reassembler {
    pub buffers: HashMap<(u64, u16), ReassemblyBuffer>,
    pub max_memory: usize,
    pub total_memory_usage: usize,
    pub mtu: usize,
    pub pad_truncated: bool,
    pub meta_event_context: Option<MetaEventContext>,
}

impl Reassembler {
    pub fn new(
        max_memory: usize,
        mtu: usize,
        meta_event_context: Option<MetaEventContext>,
    ) -> Self {
        Self {
            buffers: HashMap::new(),
            max_memory,
            total_memory_usage: 0,
            mtu,
            pad_truncated: false,
            meta_event_context,
        }
    }

    #[inline]
    pub fn packet_size(&self) -> usize {
        self.mtu - TOTAL_HEADER_SIZE
    }

    pub async fn handle_packet(
        &mut self,
        buffer: &mut [u8],
        stats: &Arc<RwLock<ReassemblyStats>>,
    ) -> Result<Option<EjfatEvent>, ReassemblyError> {
        {
            let mut stats = stats.write().await;
            stats.total_packets_recv += 1;
            stats.total_bytes_recv += buffer.len() as i64;
        }

        let reassembly_packet = match ReassemblyPayload::mut_from_bytes(buffer) {
            Ok(packet) => packet,
            Err(_) => {
                let mut stats = stats.write().await;
                stats.total_events_reassembly_err += 1;
                return Err(ReassemblyError::PacketTooSmall);
            }
        };

        let packet_size = self.packet_size();
        let tick = reassembly_packet.header.tick.get();
        let data_id = reassembly_packet.header.data_id.get();
        let offset = reassembly_packet.header.offset.get();
        let length = reassembly_packet.header.length.get() as usize;

        let if_new_mem_required = RE_OVERHEAD + length;
        let mut memory_required = 0;
        if !self.buffers.contains_key(&(tick, data_id)) {
            memory_required = if_new_mem_required;
        }

        if self.total_memory_usage + memory_required > self.max_memory {
            self.discard_incomplete_buffers();
            self.discard_stale_buffers(1);
            if self.total_memory_usage + memory_required > self.max_memory {
                return Err(ReassemblyError::MaxMemoryLimitReached);
            }
        }

        let reassembly_buffer = self
            .buffers
            .entry((tick, data_id))
            .or_insert_with(|| ReassemblyBuffer::new(length, packet_size));

        if self.pad_truncated {
            let this_packet_size = if offset as usize + packet_size > length {
                length - offset as usize
            } else {
                packet_size
            };
            let mut new_packet = vec![0; this_packet_size];
            for (place, data) in new_packet.iter_mut().zip(&reassembly_packet.body) {
                *place = *data
            }
            reassembly_buffer.insert(offset as usize, packet_size, &new_packet)?;
        } else {
            reassembly_buffer.insert(offset as usize, packet_size, &reassembly_packet.body)?;
        }

        self.total_memory_usage += memory_required;

        if let Some(context) = &self.meta_event_context {
            context.emit(MetaEventType::Recv {
                tick,
                part: offset.div_ceil(packet_size as u32),
                total_parts: reassembly_buffer.expected_packets_count as u32,
            });
        }

        if reassembly_buffer.is_complete() {
            let event = EjfatEvent {
                tick,
                data_id,
                data: std::mem::take(&mut reassembly_buffer.data),
            };
            self.total_memory_usage -= if_new_mem_required;
            self.buffers.remove(&(tick, data_id));
            Ok(Some(event))
        } else {
            Ok(None)
        }
    }

    fn discard_stale_buffers(&mut self, n: usize) {
        let mut timestamp_keys: Vec<((u64, u16), u64)> =
            self.buffers.keys().map(|key| (*key, key.0)).collect();
        timestamp_keys.sort_by(|a, b| a.1.cmp(&b.1));
        for (key, _timestamp) in timestamp_keys.into_iter().take(n) {
            self.buffers.remove(&key);
        }
    }

    fn discard_incomplete_buffers(&mut self) {
        let mut buffers_to_discard = Vec::new();
        for ((event_number, data_id), buffer) in &self.buffers {
            if buffer.has_missing_middle_packet() {
                buffers_to_discard.push((*event_number, *data_id));
            }
        }
        for (event_number, data_id) in buffers_to_discard {
            let discarded_buffer = self.buffers.remove(&(event_number, data_id)).unwrap();
            let missing_packets = discarded_buffer.missing_packets();
            warn!(
                "discarded incomplete reassembly buffer for event {} data ID {}, missing packets: {:?}",
                event_number, data_id, missing_packets
            );
            self.total_memory_usage -= RE_OVERHEAD + discarded_buffer.data.len();
        }
    }
}

pub async fn listen_and_reassemble_with_offset(
    socket: UdpSocket,
    tx: mpsc::Sender<EjfatEvent>,
    header_offset: usize,
    reassembler: Arc<Mutex<Reassembler>>,
    stats: Arc<RwLock<ReassemblyStats>>, // Accept stats as a parameter
) {
    let mut buffer = vec![0; 65536];
    let stats_clone = stats.clone();
    let tx_clone = tx.clone();

    tokio::spawn(async move {
        loop {
            let (size, _) = match socket.recv_from(&mut buffer).await {
                Ok(res) => res,
                Err(e) => {
                    warn!("Failed to receive data: {}", e);
                    continue;
                }
            };

            let mut reasm = reassembler.lock().await;
            match reasm
                .handle_packet(&mut buffer[header_offset..size], &stats_clone)
                .await
            {
                Ok(Some(event)) => {
                    let tick = event.tick;
                    let mut stats = stats_clone.write().await;
                    stats.total_events_recv += 1;
                    match tx_clone.try_send(event) {
                        Err(TrySendError::Closed(_)) => {
                            panic!(
                                "ejfat::receiver::listen_and_reassemble_with_offset channel closed"
                            )
                        }
                        Err(TrySendError::Full(_)) => {
                            stats.total_event_enqueue_err += 1;
                        }
                        Ok(_) => {
                            stats.total_events_dequeued += 1;
                            if reasm.meta_event_context.is_some() {
                                reasm
                                    .meta_event_context
                                    .as_ref()
                                    .unwrap()
                                    .emit(MetaEventType::Reassemble { tick });
                            }
                        }
                    }
                }
                Ok(None) => {}
                Err(err) => {
                    warn!("{}", err);
                }
            }
        }
    });
}

pub async fn listen_and_reassemble(
    socket: UdpSocket,
    tx: mpsc::Sender<EjfatEvent>,
    mtu: usize,
    max_memory: usize,
    meta_event_context: Option<MetaEventContext>,
    stats: Arc<RwLock<ReassemblyStats>>, // Accept stats as a parameter
) {
    // Create the reassembler and wrap in Arc<Mutex<>>
    let reassembler = Arc::new(Mutex::new(Reassembler::new(
        max_memory,
        mtu,
        meta_event_context,
    )));
    listen_and_reassemble_with_offset(socket, tx, 0, reassembler, stats).await
}

pub struct PIDController {
    kp: f64,
    ki: f64,
    kd: f64,
    set_point: f64,
    integral: f64,
    previous_error: f64,
}

impl PIDController {
    pub fn new(kp: f64, ki: f64, kd: f64, set_point: f64) -> Self {
        PIDController {
            kp,
            ki,
            kd,
            set_point,
            integral: 0.0,
            previous_error: 0.0,
        }
    }

    pub fn update(&mut self, measured_value: f64) -> f64 {
        let error = self.set_point - measured_value;
        self.integral += error;
        let derivative = error - self.previous_error;
        self.previous_error = error;
        self.kp * error + self.ki * self.integral + self.kd * derivative
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn pid_loop(
    client: &mut ControlPlaneClient,
    tx: &mpsc::Sender<EjfatEvent>,
    set_point: usize,
    kp: f64,
    ki: f64,
    kd: f64,
    meta_event_context: Option<MetaEventContext>,
    stats: Arc<RwLock<ReassemblyStats>>,
) {
    let mut controller = PIDController::new(kp, ki, kd, set_point as f64);
    let event_context_opt = meta_event_context.clone();
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let queue_size = tx.max_capacity() as f64 - tx.capacity() as f64;
        let control_signal = controller.update(queue_size);
        if let Some(ref event_context) = event_context_opt {
            event_context.emit(MetaEventType::SendControl { control_signal })
        }

        let stats_snapshot = {
            let stats = stats.read().await;
            (
                stats.total_events_recv,
                stats.total_events_reassembled,
                stats.total_events_reassembly_err,
                stats.total_events_dequeued,
                stats.total_event_enqueue_err,
                stats.total_bytes_recv,
                stats.total_packets_recv,
            )
        };

        client
            .send_state(
                (queue_size / tx.capacity() as f64) as f32,
                control_signal as f32,
                true,
                stats_snapshot.0,
                stats_snapshot.1,
                stats_snapshot.2,
                stats_snapshot.3,
                stats_snapshot.4,
                stats_snapshot.5,
                stats_snapshot.6,
            )
            .await
            .expect("Failed to send state");
    }
}

pub struct Receiver {
    client: ControlPlaneClient,
    creation_time: Instant,
    first_packet_start: Option<Instant>,
    pub rx: mpsc::Receiver<EjfatEvent>,
    pub reassembler: Arc<Mutex<Reassembler>>,
    listen_task: Option<tokio::task::JoinHandle<()>>,
    pid_task: Option<tokio::task::JoinHandle<()>>,
}

impl Receiver {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        name: &str,
        ip_address: String,
        port: u16,
        weight: f32,
        mtu: usize,
        max_buffer_size: usize,
        kp: f64,
        ki: f64,
        kd: f64,
        sp: usize,
        min_factor: f32,
        max_factor: f32,
        offset: usize,
        client: &mut ControlPlaneClient,
        meta_event_context: Option<MetaEventContext>,
    ) -> Result<Self, Error> {
        let (tx, rx) = mpsc::channel(1024);
        let pid_loop_tx = tx.clone();
        let socket = UdpSocket::bind((ip_address.clone(), port)).await?;
        let keep_lb_header = offset > 0;

        let reg = client
            .register(
                name.into(),
                weight,
                ip_address.clone(),
                port,
                PortRange::PortRange1,
                min_factor,
                max_factor,
                keep_lb_header,
            )
            .await?
            .into_inner();

        let _meta_event_ctx_clone1 = meta_event_context.clone();
        let stats = Arc::new(RwLock::new(ReassemblyStats::default()));
        let stats_clone = stats.clone();

        // Create the reassembler and wrap in Arc<Mutex<>>
        let reassembler = Arc::new(Mutex::new(Reassembler::new(
            max_buffer_size,
            mtu,
            meta_event_context.clone(),
        )));

        let reassembler_clone = reassembler.clone();
        let listen_task_handle = tokio::spawn(async move {
            listen_and_reassemble_with_offset(socket, tx, offset, reassembler_clone, stats_clone)
                .await;
        });

        let mut receiver = Self {
            client: client.clone(),
            creation_time: Instant::now(),
            first_packet_start: None,
            rx,
            reassembler,
            listen_task: Some(listen_task_handle),
            pid_task: None,
        };

        let mut client2 = receiver.client.clone();
        client2.session_id = Some(reg.session_id.clone());
        let meta_event_ctx_clone2 = meta_event_context.clone();
        let pid_stats = stats.clone();

        let pid_task_handle = tokio::spawn(async move {
            pid_loop(
                &mut client2,
                &pid_loop_tx,
                sp,
                kp,
                ki,
                kd,
                meta_event_ctx_clone2,
                pid_stats,
            )
            .await
        });
        receiver.pid_task = Some(pid_task_handle);

        Ok(receiver)
    }

    pub async fn new_simple_uncontrolled(
        name: &str,
        ip_address: String,
        port: u16,
        mtu: usize,
        offset: usize,
        client: &mut ControlPlaneClient,
        meta_event_context: Option<MetaEventContext>,
    ) -> Result<Self, Error> {
        Receiver::new(
            name,
            ip_address,
            port,
            1.0,
            mtu,
            1_073_741_824,
            0.0,
            0.0,
            0.0,
            0,
            1.0,
            1.0,
            offset,
            client,
            meta_event_context,
        )
        .await
    }

    pub async fn count_packets(&mut self, num_packets: usize, timeout_duration: Duration) -> usize {
        let mut count = 0;
        while let Ok(Some(_)) = timeout(timeout_duration, self.rx.recv()).await {
            count += 1;
            if self.first_packet_start.is_none() {
                self.first_packet_start = Some(Instant::now());
            }
            if count >= num_packets {
                break;
            }
        }
        count
    }

    pub fn first_packet_duration(&self) -> Option<Duration> {
        self.first_packet_start
            .map(|start| start.duration_since(self.creation_time))
    }

    pub fn cancel_tasks(&mut self) {
        if let Some(listen_task) = self.listen_task.take() {
            listen_task.abort();
        }
        if let Some(pid_task) = self.pid_task.take() {
            pid_task.abort();
        }
    }

    pub fn clear(&mut self) {
        while self.rx.try_recv().is_ok() {}
    }
}

/// A builder for constructing Receiver instances.
pub struct ReceiverBuilder {
    name: String,
    ip_address: String,
    port: u16,
    weight: f32,
    mtu: usize,
    max_buffer_size: usize,
    kp: f64,
    ki: f64,
    kd: f64,
    sp: usize,
    min_factor: f32,
    max_factor: f32,
    offset: usize,
    meta_event_context: Option<MetaEventContext>,
}

impl ReceiverBuilder {
    pub fn new(name: impl Into<String>, ip_address: impl Into<String>, port: u16) -> Self {
        Self {
            name: name.into(),
            ip_address: ip_address.into(),
            port,
            weight: 1.0,
            mtu: 1500,
            max_buffer_size: 1_073_741_824,
            kp: 0.0,
            ki: 0.0,
            kd: 0.0,
            sp: 0,
            min_factor: 1.0,
            max_factor: 1.0,
            offset: 0,
            meta_event_context: None,
        }
    }

    pub fn weight(mut self, weight: f32) -> Self {
        self.weight = weight;
        self
    }

    pub fn mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu;
        self
    }

    pub fn max_buffer_size(mut self, size: usize) -> Self {
        self.max_buffer_size = size;
        self
    }

    pub fn pid_parameters(mut self, kp: f64, ki: f64, kd: f64, sp: usize) -> Self {
        self.kp = kp;
        self.ki = ki;
        self.kd = kd;
        self.sp = sp;
        self
    }

    pub fn factor_range(mut self, min_factor: f32, max_factor: f32) -> Self {
        self.min_factor = min_factor;
        self.max_factor = max_factor;
        self
    }

    pub fn offset(mut self, offset: usize) -> Self {
        self.offset = offset;
        self
    }

    pub fn meta_event_context(mut self, context: MetaEventContext) -> Self {
        self.meta_event_context = Some(context);
        self
    }

    pub async fn build(self, client: &mut ControlPlaneClient) -> Result<Receiver, Error> {
        Receiver::new(
            &self.name,
            self.ip_address,
            self.port,
            self.weight,
            self.mtu,
            self.max_buffer_size,
            self.kp,
            self.ki,
            self.kd,
            self.sp,
            self.min_factor,
            self.max_factor,
            self.offset,
            client,
            self.meta_event_context,
        )
        .await
    }
}

// SPDX-License-Identifier: BSD-3-Clause-LBNL
use crate::api::client::EjfatUrl;
use crate::dataplane::meta_events::{MetaEventContext, MetaEventType};
use crate::dataplane::protocol::*;
use crate::errors::Result;

use std::net::SocketAddr;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::warn;
use zerocopy::*;

use crate::api::client::ControlPlaneClient;

pub struct Sender {
    last_sync: u64,
    data_socket: UdpSocket,
    sync_socket: UdpSocket,
    mtu_size: u16,
    data_target: SocketAddr,
    sync_target: SocketAddr,
    pub meta_event_context: Option<MetaEventContext>,
    pub total_packets_sent: u64,
    pub autosync: bool,
}

impl Sender {
    /// Create a new Sender, binding the UDP sockets and setting up the target addresses.
    pub async fn new(
        data_target: SocketAddr,
        sync_target: SocketAddr,
        mtu_size: u16,
        meta_event_context: Option<MetaEventContext>,
    ) -> Result<Self> {
        let data_socket = UdpSocket::bind("0.0.0.0:0").await?;
        let sync_socket = UdpSocket::bind("0.0.0.0:0").await?;

        Ok(Self {
            last_sync: 0,
            data_socket,
            sync_socket,
            mtu_size,
            data_target,
            sync_target,
            meta_event_context,
            total_packets_sent: 0,
            autosync: true,
        })
    }

    /// Create a sender using an EJFAT URI
    pub async fn from_url(
        url: &EjfatUrl,
        meta_event_context: Option<MetaEventContext>,
    ) -> Result<Self> {
        let (data_target, sync_target) =
            match (url.data_host.as_ref(), url.sync_ip_address.as_ref()) {
                (Some(data_addr), Some(sync_addr)) => {
                    let data_target: SocketAddr = format!("{}:19522", data_addr).parse()?;
                    let sync_target: SocketAddr =
                        format!("{}:{}", sync_addr, url.sync_udp_port.unwrap_or(0)).parse()?;
                    (data_target, sync_target)
                }
                _ => {
                    let mut client = ControlPlaneClient::from_url(&url.to_string()).await?;
                    let response = client.get_load_balancer().await?.into_inner();

                    let data_target: SocketAddr =
                        format!("{}:19522", response.data_ipv4_address).parse()?;
                    let sync_target: SocketAddr = format!(
                        "{}:{}",
                        response.sync_ip_address, response.sync_udp_port as u16
                    )
                    .parse()?;
                    (data_target, sync_target)
                }
            };

        Sender::new(data_target, sync_target, 1500, meta_event_context).await
    }

    /// Create a sender without a sync address configured provided the data socket
    pub async fn from_data_socket(
        data_socket: UdpSocket,
        data_target: SocketAddr,
        meta_event_context: Option<MetaEventContext>,
    ) -> Result<Self> {
        let sync_socket = UdpSocket::bind("0.0.0.0:0").await?;

        Ok(Self {
            last_sync: 0,
            data_socket,
            sync_socket,
            mtu_size: 1500,
            data_target,
            sync_target: "0.0.0.0:0".parse().unwrap(), // Dummy address
            meta_event_context,
            total_packets_sent: 0,
            autosync: false,
        })
    }

    pub async fn send_sync(&mut self, tick: u64) {
        let mut sync_packet = SyncPayload::new();
        sync_packet.set_defaults();
        sync_packet.tick.set(tick);
        if let Err(e) = self
            .sync_socket
            .send_to(sync_packet.as_bytes(), self.sync_target)
            .await
        {
            warn!("failed to send sync: {e}");
            return;
        }
        self.last_sync = tick;
    }

    pub async fn send_sync_ts(&mut self) {
        let mut sync_packet = SyncPayload::new();
        sync_packet.set_tick_to_timestamp();
        self.last_sync = sync_packet.tick.get();
        if let Err(e) = self
            .sync_socket
            .send_to(sync_packet.as_bytes(), self.sync_target)
            .await
        {
            warn!("failed to send sync: {e}");
        }
    }

    pub async fn send(&mut self, buffer: &[u8], tick: u64, data_id: u16) -> u32 {
        let mut offset = 0;
        let header_size = LB_HEADER_SIZE + REASSEMBLY_HEADER_SIZE;
        let mut packet_buffer =
            vec![0u8; self.mtu_size as usize - IP_HEADER_SIZE - UDP_HEADER_SIZE].into_boxed_slice();
        let mut packets_sent = 0;

        while offset < buffer.len() {
            let remaining = buffer.len() - offset;
            let max_body_size = self.mtu_size as usize - TOTAL_HEADER_SIZE;
            let body_size = std::cmp::min(remaining, max_body_size);
            let total_packet_size = body_size + header_size;

            let packet_bytes = &mut packet_buffer[..total_packet_size];

            let lb_payload = LBPayload::mut_from_bytes(packet_bytes).unwrap();
            lb_payload.header.set_defaults();
            lb_payload.header.tick.set(tick);

            let reassembly_payload =
                ReassemblyPayload::mut_from_bytes(&mut lb_payload.body).unwrap();
            reassembly_payload.header.data_id.set(data_id);
            reassembly_payload.header.offset.set(offset as u32);
            reassembly_payload.header.length.set(buffer.len() as u32);
            reassembly_payload.header.tick.set(tick);

            let user_payload = &mut reassembly_payload.body;
            user_payload.copy_from_slice(&buffer[offset..offset + body_size]);

            if let Err(e) = self
                .data_socket
                .send_to(packet_bytes, self.data_target)
                .await
            {
                warn!("failed to send EJFAT event: {e}");
                return 0;
            }

            packets_sent += 1;

            if let Some(context) = &self.meta_event_context {
                let total_parts = buffer.len().div_ceil(max_body_size) as u32;
                context.emit(MetaEventType::Send {
                    tick,
                    part: packets_sent,
                    total_parts,
                });
            }

            offset += body_size;

            let duration = Duration::from_micros(5);
            let start = Instant::now();
            while Instant::now().duration_since(start) < duration {}
        }

        if self.autosync && tick - self.last_sync > 1_000_000 {
            self.send_sync(tick).await;
        }
        self.total_packets_sent += packets_sent as u64;
        packets_sent
    }

    pub async fn send_ts(&mut self, buffer: &[u8], data_id: u16) -> u32 {
        let tick = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;
        self.send(buffer, tick, data_id).await
    }

    pub async fn generate_test_stream(
        &mut self,
        count: usize,
        size: usize,
        interval: Duration,
        cancel: CancellationToken,
    ) {
        let mut i: usize = 0;
        loop {
            let test_data = vec![0xDA; size];
            tokio::select! {
                _ = self.send_ts(&test_data, 0) => {
                    i += 1;
                    if count != 0 && i >= count {
                        break;
                    }
                    sleep(interval).await;
                }
                _ = cancel.cancelled() => {
                    break;
                }
            }
        }
    }
}

// SPDX-License-Identifier: BSD-3-Clause-LBNL
use crate::db::epoch::{predict_epoch_boundary_from_samples, EventSample};
use crate::db::LoadBalancerDB;
use byteorder::{BigEndian, ByteOrder};
use chrono::{DateTime, Utc};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

pub const EVENT_ID_SYNC_MAGIC: u16 = 0x4C43;
pub const EVENT_ID_SYNC_VERSION: u8 = 2;

/// UDP server that implements the event ID synchronization protocol.
///
/// Protocol format (28 bytes total):
/// ```text
/// Bytes | Description
///  0-1  | Magic number (0x4C43)
///  2    | Version (2)
///  3-7  | Reserved
///  8-15 | Event number (u64, big-endian)
/// 16-19 | Event rate in Hz (u32, big-endian)
/// 20-27 | Remote timestamp in nanoseconds (u64, big-endian)
/// ```
pub struct EventIdSyncServer {
    db: Arc<LoadBalancerDB>,
    reservation_id: i64,
    address: SocketAddr,
    samples: Arc<Mutex<VecDeque<EventSample>>>, // in-memory buffer of recent samples
}

impl EventIdSyncServer {
    /// Creates a new event ID synchronization server.
    /// The server will persist event numbers to the database
    /// for the specified reservation.
    pub async fn new(db: Arc<LoadBalancerDB>, reservation_id: i64, address: SocketAddr) -> Self {
        // Load recent samples from DB for recovery
        let samples_db = sqlx::query!(
            r#"
            SELECT
                event_number,
                avg_event_rate_hz,
                local_timestamp,
                remote_timestamp
            FROM event_number
            WHERE reservation_id = ?1
            AND created_at >= (unixepoch('subsec') * 1000 - 60000)
            ORDER BY created_at DESC
            LIMIT 10
            "#,
            reservation_id
        )
        .fetch_all(&db.read_pool)
        .await
        .unwrap_or_default();

        let mut samples = VecDeque::new();
        for s in samples_db {
            samples.push_back(EventSample {
                event_number: s.event_number,
                avg_event_rate_hz: s.avg_event_rate_hz as i32,
                local_timestamp: s.local_timestamp,
                remote_timestamp: s.remote_timestamp,
            });
        }

        Self {
            db,
            reservation_id,
            address,
            samples: Arc::new(Mutex::new(samples)),
        }
    }

    /// Runs the event id sync server until a shutdown signal is received.
    /// Validates and processes incoming event ID packets.
    pub async fn run(self: Arc<Self>, mut shutdown_rx: broadcast::Receiver<()>) {
        let socket = match UdpSocket::bind(self.address).await {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to bind event number server: {}", e);
                return;
            }
        };

        info!(
            "started event number server for reservation {} on {}",
            self.reservation_id, self.address
        );

        let mut buf = [0u8; 28];

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    if let Err(e) = self.handle_packet(result, &buf).await {
                        error!("Error handling packet: {}", e);
                    }
                }
                _ = shutdown_rx.recv() => {
                    debug!("shut down event number server for reservation {}", self.reservation_id);
                    break;
                }
            }
        }
    }

    /// Processes a single event ID packet, validating protocol requirements
    /// and storing event data in the database. Invalid packets are logged
    /// but do not cause errors to be propagated.
    async fn handle_packet(
        &self,
        result: Result<(usize, SocketAddr), std::io::Error>,
        buf: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (n, addr) = result?;

        if n != 28 {
            warn!("invalid packet size: expected 28, got {}", n);
            return Ok(());
        }

        let magic_num = BigEndian::read_u16(&buf[0..2]);
        if magic_num != EVENT_ID_SYNC_MAGIC {
            warn!(
                "invalid magic number: expected {}, got {}",
                EVENT_ID_SYNC_MAGIC, magic_num
            );
            return Ok(());
        }

        let ver = buf[2];
        if ver != EVENT_ID_SYNC_VERSION {
            warn!("invalid version number: expected {EVENT_ID_SYNC_VERSION}, got {ver}");
            return Ok(());
        }

        let event_number = BigEndian::read_u64(&buf[8..16]);
        let event_rate = BigEndian::read_u32(&buf[16..20]);
        let remote_nanos = BigEndian::read_u64(&buf[20..28]);
        let remote_ts = DateTime::<Utc>::from_timestamp(
            (remote_nanos / 1_000_000_000) as i64,
            (remote_nanos % 1_000_000_000) as u32,
        )
        .unwrap();

        info!(
            "received event number packet from {}: event_number={}, avg_event_rate_hz={}, remote_timestamp={}",
            addr, event_number, event_rate, remote_ts
        );

        self.db
            .create_event_number(
                self.reservation_id,
                event_number as i64,
                event_rate as i32,
                Utc::now(),
                remote_ts,
            )
            .await?;

        // Update in-memory buffer
        let mut samples = self.samples.lock().unwrap();
        samples.push_front(EventSample {
            event_number: event_number as i64,
            avg_event_rate_hz: event_rate as i32,
            local_timestamp: Utc::now().timestamp_millis(),
            remote_timestamp: remote_ts.timestamp_millis(),
        });
        while samples.len() > 10 {
            samples.pop_back();
        }

        Ok(())
    }

    /// Returns the current predicted epoch boundary using in-memory samples
    pub fn predict_epoch_boundary(&self, offset: chrono::Duration) -> i64 {
        let samples = self.samples.lock().unwrap();
        let samples_vec: Vec<_> = samples.iter().cloned().collect();
        predict_epoch_boundary_from_samples(&samples_vec, offset)
    }
}

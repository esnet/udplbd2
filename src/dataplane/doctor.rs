// SPDX-License-Identifier: BSD-3-Clause-LBNL
//! Modular and comprehensive EJFAT dataplane doctor test.

use crate::api::client::{ControlPlaneClient, EjfatUrl};
use crate::dataplane::protocol::LBHeader;
use crate::dataplane::receiver::Receiver;
use crate::dataplane::sender::Sender;
use crate::errors::Result;
use crate::proto::loadbalancer::v1::IpFamily;

use prost_wkt_types::Timestamp;
use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use serde::Serialize;
use serde_json;
use tracing;

/// Aggregated output of all doctor tests for a single address.
#[derive(Debug, Serialize)]
pub struct DoctorOutput {
    pub address: String,
    pub reservation: ReservationResult,
    pub first_packet: FirstPacketResult,
    pub data_id: DataIdResult,
    pub packet_loss: PacketLossResult,
    pub dynamic_receiver: DynamicReceiverResult,
    pub distribution: DistributionResult,
    pub split_event: SplitEventResult,
    pub overview: OverviewResult,
    pub remove_add_sender: RemoveAddSenderResult,
    pub deregister: DeregisterResult,
    pub errors: Vec<String>,
}

impl fmt::Display for DoctorOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Print JSON output
        writeln!(f, "{}", serde_json::to_string_pretty(&self).unwrap())?;
        Ok(())
    }
}

// --- Result types for each test step ---

#[derive(Debug, Serialize)]
pub struct ReservationResult {
    pub lb_id: String,
    pub url: EjfatUrl,
}

#[derive(Debug, Serialize)]
pub struct FirstPacketResult {
    pub duration_ms: u128,
}

#[derive(Debug, Serialize)]
pub struct DataIdResult {
    pub correct: bool,
}

#[derive(Debug, Serialize)]
pub struct PacketLossResult {
    pub sent: usize,
    pub received: usize,
    pub lost: usize,
    pub loss_pct: f64,
}

#[derive(Debug, Serialize)]
pub struct DynamicReceiverResult {
    pub duration_ms: u128,
}

#[derive(Debug, Serialize)]
pub struct DistributionResult {
    pub sent: usize,
    pub recv1: usize,
    pub recv2: usize,
}

#[derive(Debug, Serialize)]
pub struct SplitEventResult {
    pub split_count: usize,
    pub split_keys: Vec<(u64, u16)>,
}

#[derive(Debug, Serialize)]
pub struct OverviewResult {
    pub found: bool,
    pub errors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RemoveAddSenderResult {
    pub after_remove: usize,
    pub remove_duration_ms: u128,
    pub add_sender_ok: bool,
}

#[derive(Debug, Serialize)]
pub struct DeregisterResult {
    pub ok: bool,
}

// --- Test context holding shared state ---

struct DoctorTestContext {
    client: ControlPlaneClient,
    parsed_url: EjfatUrl,
    lb_id: String,
    ip_address: IpAddr,
    port: u16,
    mtu: usize,
    with_lb_headers: bool,
}

// --- Modular test steps ---

async fn reserve_load_balancer(
    url: &str,
    ip_address: IpAddr,
    port: u16,
    mtu: usize,
    with_lb_headers: bool,
) -> Result<(DoctorTestContext, ReservationResult)> {
    let mut client = ControlPlaneClient::from_url(url).await?;
    let expiration = SystemTime::now() + Duration::from_secs(180);
    let expiration_timestamp = Timestamp::from(expiration);

    let ip_family = match ip_address {
        IpAddr::V4(_) => IpFamily::Ipv4,
        IpAddr::V6(_) => IpFamily::Ipv6,
    };

    let reply = client
        .reserve_load_balancer(
            "ejfat-doctor".to_string(),
            Some(expiration_timestamp),
            vec![ip_address.to_string()],
            ip_family,
        )
        .await?
        .into_inner();

    let mut parsed_url: EjfatUrl = url.parse().expect("Invalid EJFAT url");
    client.lb_id = Some(reply.lb_id.clone());
    parsed_url.update_from_reservation(&reply);

    parsed_url = match ip_family {
        IpFamily::Ipv4 => parsed_url.without_v6(),
        IpFamily::Ipv6 => parsed_url.without_v4(),
        _ => parsed_url,
    };

    let ctx = DoctorTestContext {
        client,
        parsed_url: parsed_url.clone(),
        lb_id: reply.lb_id.clone(),
        ip_address,
        port,
        mtu,
        with_lb_headers,
    };
    let res = ReservationResult {
        lb_id: reply.lb_id,
        url: parsed_url,
    };
    Ok((ctx, res))
}

async fn test_first_packet(ctx: &mut DoctorTestContext) -> Result<(Receiver, FirstPacketResult)> {
    let offset = if ctx.with_lb_headers {
        std::mem::size_of::<LBHeader>()
    } else {
        0
    };
    let mut receiver = Receiver::new_simple_uncontrolled(
        "doctor-node1",
        ctx.ip_address.to_string(),
        ctx.port,
        ctx.mtu,
        offset,
        &mut ctx.client,
        None,
    )
    .await?;
    let mut sender = Sender::from_url(&ctx.parsed_url, None, ctx.ip_address.is_ipv6()).await?;
    let cancel = CancellationToken::new();
    let cancel_cloned = cancel.clone();
    let jh = tokio::spawn(async move {
        sender
            .generate_test_stream(500, 1, Duration::from_millis(10), cancel_cloned)
            .await
    });
    let _ = receiver.count_packets(1, Duration::from_secs(5)).await;
    let mut duration = receiver
        .first_packet_duration()
        .expect("no packets received!");
    duration += Duration::from_millis(100);
    cancel.cancel();
    jh.await.unwrap();
    receiver.clear();
    Ok((
        receiver,
        FirstPacketResult {
            duration_ms: duration.as_millis(),
        },
    ))
}

async fn test_data_id(
    ctx: &mut DoctorTestContext,
    receiver: &mut Receiver,
) -> Result<DataIdResult> {
    let mut sender = Sender::from_url(&ctx.parsed_url, None, ctx.ip_address.is_ipv6()).await?;
    let data_id_test_data = vec![0u8; 100];
    sender.send_ts(&data_id_test_data, 1234).await;
    let correct = match timeout(Duration::from_secs(5), receiver.rx.recv()).await {
        Ok(Some(event)) => event.data_id == 1234,
        _ => false,
    };
    receiver.clear();
    Ok(DataIdResult { correct })
}

async fn test_packet_loss(
    ctx: &mut DoctorTestContext,
    receiver: &mut Receiver,
) -> Result<PacketLossResult> {
    let num_packets = 1000;
    let mut sender = Sender::from_url(&ctx.parsed_url, None, ctx.ip_address.is_ipv6()).await?;
    let cancel = CancellationToken::new();
    let cancel_cloned = cancel.clone();
    let jh = tokio::spawn(async move {
        sender
            .generate_test_stream(num_packets, 1, Duration::from_micros(5), cancel_cloned)
            .await
    });
    let received = receiver
        .count_packets(num_packets, Duration::from_millis(100))
        .await;
    let lost = num_packets - received;
    cancel.cancel();
    jh.await.unwrap();
    receiver.clear();
    Ok(PacketLossResult {
        sent: num_packets,
        received,
        lost,
        loss_pct: 100.0 - ((received as f64 / num_packets as f64) * 100.0),
    })
}

async fn test_dynamic_receiver(
    ctx: &mut DoctorTestContext,
) -> Result<(Receiver, DynamicReceiverResult)> {
    let offset = if ctx.with_lb_headers {
        std::mem::size_of::<LBHeader>()
    } else {
        0
    };
    let mut receiver2 = Receiver::new_simple_uncontrolled(
        "doctor-node2",
        ctx.ip_address.to_string(),
        ctx.port + 1,
        ctx.mtu,
        offset,
        &mut ctx.client,
        None,
    )
    .await?;
    let mut sender = Sender::from_url(&ctx.parsed_url, None, ctx.ip_address.is_ipv6()).await?;
    let cancel = CancellationToken::new();
    let cancel_cloned = cancel.clone();
    let jh = tokio::spawn(async move {
        sender
            .generate_test_stream(500, 1, Duration::from_millis(10), cancel_cloned)
            .await
    });
    let _ = receiver2.count_packets(1, Duration::from_secs(5)).await;
    let duration = receiver2
        .first_packet_duration()
        .expect("second receiver - no packets received!");
    cancel.cancel();
    jh.await.unwrap();
    receiver2.clear();
    Ok((
        receiver2,
        DynamicReceiverResult {
            duration_ms: duration.as_millis(),
        },
    ))
}

async fn test_distribution(
    ctx: &mut DoctorTestContext,
    receiver1: &mut Receiver,
    receiver2: &mut Receiver,
) -> Result<DistributionResult> {
    receiver1.clear();
    receiver2.clear();
    let mut sender = Sender::from_url(&ctx.parsed_url, None, ctx.ip_address.is_ipv6()).await?;
    let num_packets = 5000;
    let cancel = CancellationToken::new();
    let cancel_cloned = cancel.clone();
    let jh = tokio::spawn(async move {
        sender
            .generate_test_stream(num_packets, 20000, Duration::from_millis(5), cancel_cloned)
            .await
    });
    let (recv1, recv2): (usize, usize) = tokio::join!(
        receiver1.count_packets(num_packets, Duration::from_millis(2000)),
        receiver2.count_packets(num_packets, Duration::from_millis(2000))
    );
    cancel.cancel();
    jh.await.unwrap();
    Ok(DistributionResult {
        sent: num_packets,
        recv1,
        recv2,
    })
}

async fn test_split_event(receiver1: &Receiver, receiver2: &Receiver) -> Result<SplitEventResult> {
    use std::collections::HashSet;
    async fn incomplete_event_keys(receiver: &Receiver) -> HashSet<(u64, u16)> {
        let reassembler = receiver.reassembler.lock().await;
        reassembler
            .buffers
            .iter()
            .filter_map(|(key, buffer)| {
                if !buffer.is_complete() && buffer.received_packets_count() > 0 {
                    Some(*key)
                } else {
                    None
                }
            })
            .collect()
    }
    let split_candidates_1 = incomplete_event_keys(receiver1).await;
    let split_candidates_2 = incomplete_event_keys(receiver2).await;
    let split_events: HashSet<_> = split_candidates_1
        .intersection(&split_candidates_2)
        .cloned()
        .collect();
    Ok(SplitEventResult {
        split_count: split_events.len(),
        split_keys: split_events.into_iter().collect(),
    })
}

async fn test_overview(ctx: &mut DoctorTestContext) -> Result<OverviewResult> {
    let mut errors = Vec::new();
    let reply = ctx.client.overview().await?;
    let our_lb = reply
        .get_ref()
        .load_balancers
        .iter()
        .find(|lb| lb.reservation.as_ref().unwrap().lb_id == ctx.lb_id);
    let mut found = false;
    if let Some(lb) = our_lb {
        found = true;
        let reservation = lb.reservation.as_ref().unwrap();
        let status = lb.status.as_ref().unwrap();
        if reservation.lb_id != ctx.lb_id {
            errors.push("lb id mismatch".to_string());
        }
        if let Some(sync_addr_v4) = &ctx.parsed_url.sync_addr_v4 {
            if &reservation.sync_ipv4_address != sync_addr_v4 {
                errors.push("sync ipv4 mismatch".to_string());
            }
        }
        if let Some(sync_addr_v6) = &ctx.parsed_url.sync_addr_v6 {
            if &reservation.sync_ipv6_address != sync_addr_v6 {
                errors.push("sync ipv6 mismatch".to_string());
            }
        }
        if let Some(sync_udp_port) = ctx.parsed_url.sync_udp_port {
            if reservation.sync_udp_port as u16 != sync_udp_port {
                errors.push("sync udp port mismatch".to_string());
            }
        }
        if status.sender_addresses != vec![ctx.ip_address.to_string()] {
            errors.push("sender address mismatch".to_string());
        }
        if status.expires_at.is_none() {
            errors.push("expiration time is missing".to_string());
        }
    } else {
        errors.push("our lb not found in overview".to_string());
    }
    Ok(OverviewResult { found, errors })
}

async fn test_remove_add_sender(
    ctx: &mut DoctorTestContext,
    receiver: &mut Receiver,
) -> Result<RemoveAddSenderResult> {
    let mut sender = Sender::from_url(&ctx.parsed_url, None, ctx.ip_address.is_ipv6()).await?;
    let cancel = CancellationToken::new();
    let cancel_cloned = cancel.clone();
    let jh = tokio::spawn(async move {
        sender
            .generate_test_stream(500, 1, Duration::from_millis(10), cancel_cloned)
            .await
    });
    let remove_start = Instant::now();
    ctx.client
        .remove_senders(vec![ctx.ip_address.to_string()])
        .await?;
    let after_remove = receiver.count_packets(500, Duration::from_secs(1)).await;
    let remove_duration = remove_start.elapsed() - Duration::from_secs(1);
    cancel.cancel();
    jh.await.unwrap();

    // Add sender back
    let add_sender_ok = ctx
        .client
        .add_senders(vec![ctx.ip_address.to_string()])
        .await
        .is_ok();
    Ok(RemoveAddSenderResult {
        after_remove,
        remove_duration_ms: remove_duration.as_millis(),
        add_sender_ok,
    })
}

async fn test_deregister(ctx: &mut DoctorTestContext) -> Result<DeregisterResult> {
    let ok = ctx.client.deregister().await.is_ok();
    Ok(DeregisterResult { ok })
}

// --- Main doctor orchestrator ---

pub async fn doctor(
    url: String,
    ip_address: IpAddr,
    port: u16,
    mtu: usize,
    with_lb_headers: bool,
) -> Result<DoctorOutput> {
    let mut errors = Vec::new();

    tracing::info!("Starting reservation step");
    let (mut ctx, reservation) =
        reserve_load_balancer(&url, ip_address, port, mtu, with_lb_headers)
            .await
            .map_err(|e| {
                errors.push(format!("reservation: {e}"));
                e
            })?;

    tracing::info!("Starting first packet test; EJFAT_URI: {}", reservation.url);
    let (mut receiver1, first_packet) = test_first_packet(&mut ctx).await.map_err(|e| {
        errors.push(format!("first_packet: {e}"));
        e
    })?;

    tracing::info!("Starting data ID test; previous result: {:?}", first_packet);
    let data_id = test_data_id(&mut ctx, &mut receiver1).await.map_err(|e| {
        errors.push(format!("data_id: {e}"));
        e
    })?;

    tracing::info!("Starting packet loss test; previous result: {:?}", data_id);
    let packet_loss = test_packet_loss(&mut ctx, &mut receiver1)
        .await
        .map_err(|e| {
            errors.push(format!("packet_loss: {e}"));
            e
        })?;

    tracing::info!(
        "Starting dynamic receiver test; previous result: {:?}",
        packet_loss
    );
    let (mut receiver2, dynamic_receiver) = test_dynamic_receiver(&mut ctx).await.map_err(|e| {
        errors.push(format!("dynamic_receiver: {e}"));
        e
    })?;

    tracing::info!(
        "Starting distribution test; previous result: {:?}",
        dynamic_receiver
    );
    let distribution = test_distribution(&mut ctx, &mut receiver1, &mut receiver2)
        .await
        .map_err(|e| {
            errors.push(format!("distribution: {e}"));
            e
        })?;

    tracing::info!(
        "Starting split event test; previous result: {:?}",
        distribution
    );
    let split_event = test_split_event(&receiver1, &receiver2)
        .await
        .map_err(|e| {
            errors.push(format!("split_event: {e}"));
            e
        })?;

    tracing::info!("Starting overview test; previous result: {:?}", split_event);
    let overview = test_overview(&mut ctx).await.map_err(|e| {
        errors.push(format!("overview: {e}"));
        e
    })?;

    tracing::info!(
        "Starting remove/add sender test; previous result: {:?}",
        overview
    );
    let remove_add_sender = test_remove_add_sender(&mut ctx, &mut receiver1)
        .await
        .map_err(|e| {
            errors.push(format!("remove_add_sender: {e}"));
            e
        })?;

    tracing::info!(
        "Starting deregister test; previous result: {:?}",
        remove_add_sender
    );
    let deregister = test_deregister(&mut ctx).await.map_err(|e| {
        errors.push(format!("deregister: {e}"));
        e
    })?;

    // Cleanup
    receiver1.cancel_tasks();
    receiver2.cancel_tasks();
    let _ = ctx.client.free_load_balancer().await;

    let output = DoctorOutput {
        address: ip_address.to_string(),
        reservation,
        first_packet,
        data_id,
        packet_loss,
        dynamic_receiver,
        distribution,
        split_event,
        overview,
        remove_add_sender,
        deregister,
        errors,
    };

    Ok(output)
}

/// Run the doctor test for multiple addresses, returning a Vec of results.
pub async fn doctor_multi(
    url: String,
    addresses: Vec<String>,
    port: u16,
    mtu: usize,
    with_lb_headers: bool,
) -> Vec<Result<DoctorOutput>> {
    let mut results = Vec::new();
    for addr in addresses {
        let ip_addr = addr
            .parse::<IpAddr>()
            .expect("Invalid IP address in doctor_multi");
        let res = doctor(url.clone(), ip_addr, port, mtu, with_lb_headers).await;
        results.push(res);
    }
    results
}

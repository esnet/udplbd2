// SPDX-License-Identifier: BSD-3-Clause-LBNL
//! Modular and comprehensive EJFAT dataplane doctor test.

use crate::api::client::{ControlPlaneClient, EjfatUrl};
use crate::dataplane::protocol::LBHeader;
use crate::dataplane::receiver::{Receiver, ReceiverBuilder};
use crate::dataplane::sender::Sender;
use crate::errors::Result;
use crate::proto::loadbalancer::v1::{IpFamily, SessionSlotRanges, SlotRange};

use prost_wkt_types::Timestamp;
use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use serde::Serialize;
use serde_json;
use tracing;

/// Output for dynamic strategy tests (includes all common tests)
#[derive(Debug, Serialize)]
pub struct DynamicStrategyOutput {
    pub lb_id: String,
    pub url: EjfatUrl,
    pub first_packet_ms: u128,
    pub data_id_correct: bool,
    pub packets_sent: usize,
    pub packets_received: usize,
    pub packets_lost: usize,
    pub loss_pct: f64,
    pub dynamic_receiver_ms: u128,
    pub distribution_sent: usize,
    pub distribution_recv1: usize,
    pub distribution_recv2: usize,
    pub split_event_count: usize,
    pub split_event_keys: Vec<(u64, u16)>,
    pub overview_found: bool,
    pub overview_errors: Vec<String>,
    pub remove_add_after_remove: usize,
    pub remove_add_duration_ms: u128,
    pub remove_add_sender_ok: bool,
    pub deregister_ok: bool,
    pub errors: Vec<String>,
}

/// Output for static strategy tests (focused on slot demand updates)
#[derive(Debug, Serialize)]
pub struct StaticStrategyOutput {
    pub lb_id: String,
    pub url: EjfatUrl,
    pub first_packet_ms: u128,
    pub initial_recv1: usize,
    pub initial_recv2: usize,
    pub updated_recv1: usize,
    pub updated_recv2: usize,
    pub set_demands_ok: bool,
    pub errors: Vec<String>,
}

/// Output for explicit strategy tests (focused on slot coverage and loss)
#[derive(Debug, Serialize)]
pub struct ExplicitStrategyOutput {
    pub lb_id: String,
    pub url: EjfatUrl,
    pub first_packet_ms: u128,
    pub initial_recv: usize,
    pub initial_loss_pct: f64,
    pub updated_recv: usize,
    pub updated_loss_pct: f64,
    pub errors: Vec<String>,
}

/// Output for LB chaining test
#[derive(Debug, Serialize)]
pub struct ChainOutput {
    pub upstream_lb_id: String,
    pub downstream_lb_id: String,
    pub chain_id: String,
    pub chain_ok: bool,
    pub packets_sent: usize,
    pub packets_received: usize,
    pub first_packet_ms: Option<u128>,
    pub unchain_ok: bool,
    pub errors: Vec<String>,
}

/// Aggregated output of all doctor tests for a single address across all strategies.
#[derive(Debug, Serialize)]
pub struct DoctorOutput {
    pub address: String,
    pub dynamic: DynamicStrategyOutput,
    pub static_strategy: StaticStrategyOutput,
    pub explicit: ExplicitStrategyOutput,
}

impl fmt::Display for DoctorOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", serde_json::to_string_pretty(&self).unwrap())?;
        Ok(())
    }
}

async fn test_dynamic_strategy(
    url: &str,
    ip_address: IpAddr,
    port: u16,
    mtu: usize,
    with_lb_headers: bool,
) -> Result<DynamicStrategyOutput> {
    let mut errors = Vec::new();

    // Reserve load balancer
    tracing::info!("Reserving load balancer for dynamic strategy");
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
            "dynamic".to_string(),
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

    let lb_id = reply.lb_id.clone();
    let ejfat_url = parsed_url.clone();

    tracing::info!("Starting first packet test; EJFAT_URI: {}", ejfat_url);

    // Test first packet
    let offset = if with_lb_headers {
        std::mem::size_of::<LBHeader>()
    } else {
        0
    };
    let mut receiver1 = ReceiverBuilder::new("doctor-node1", ip_address.to_string(), port)
        .mtu(mtu)
        .offset(offset)
        .build(&mut client)
        .await?;

    let mut sender = Sender::from_url(&parsed_url, None, ip_address.is_ipv6()).await?;
    let cancel = CancellationToken::new();
    let cancel_cloned = cancel.clone();
    let jh = tokio::spawn(async move {
        sender
            .generate_test_stream(500, 1, Duration::from_millis(10), cancel_cloned)
            .await
    });
    let _ = receiver1.count_packets(1, Duration::from_secs(5)).await;
    let mut duration = receiver1
        .first_packet_duration()
        .ok_or_else(|| crate::errors::Error::Runtime("no packets received!".to_string()))?;
    duration += Duration::from_millis(100);
    cancel.cancel();
    jh.await.unwrap();
    receiver1.clear();
    let first_packet_ms = duration.as_millis();
    tracing::info!("✓ First packet test: {}ms", first_packet_ms);

    // Test data ID
    tracing::info!("Starting data ID test");
    let mut sender = Sender::from_url(&parsed_url, None, ip_address.is_ipv6()).await?;
    let data_id_test_data = vec![0u8; 100];
    sender.send_ts(&data_id_test_data, 1234).await;
    let data_id_correct = match timeout(Duration::from_secs(5), receiver1.rx.recv()).await {
        Ok(Some(event)) => event.data_id == 1234,
        _ => false,
    };
    receiver1.clear();
    tracing::info!(
        "✓ Data ID test: {}",
        if data_id_correct { "PASS" } else { "FAIL" }
    );

    // Test packet loss
    tracing::info!("Starting packet loss test");
    let num_packets = 1000;
    let mut sender = Sender::from_url(&parsed_url, None, ip_address.is_ipv6()).await?;
    let cancel = CancellationToken::new();
    let cancel_cloned = cancel.clone();
    let jh = tokio::spawn(async move {
        sender
            .generate_test_stream(num_packets, 1, Duration::from_micros(5), cancel_cloned)
            .await
    });
    let received = receiver1
        .count_packets(num_packets, Duration::from_millis(100))
        .await;
    let lost = num_packets - received;
    let loss_pct = 100.0 - ((received as f64 / num_packets as f64) * 100.0);
    cancel.cancel();
    jh.await.unwrap();
    receiver1.clear();
    let packets_sent = num_packets;
    let packets_received = received;
    let packets_lost = lost;
    tracing::info!(
        "✓ Packet loss test: sent={}, received={}, lost={}, loss={:.2}%",
        packets_sent,
        packets_received,
        packets_lost,
        loss_pct
    );

    // Test dynamic receiver
    tracing::info!("Starting dynamic receiver test");
    let mut receiver2 = ReceiverBuilder::new("doctor-node2", ip_address.to_string(), port + 1)
        .mtu(mtu)
        .offset(offset)
        .build(&mut client)
        .await?;
    let mut sender = Sender::from_url(&parsed_url, None, ip_address.is_ipv6()).await?;
    let cancel = CancellationToken::new();
    let cancel_cloned = cancel.clone();
    let jh = tokio::spawn(async move {
        sender
            .generate_test_stream(500, 1, Duration::from_millis(10), cancel_cloned)
            .await
    });
    let _ = receiver2.count_packets(1, Duration::from_secs(5)).await;
    let duration = receiver2.first_packet_duration().ok_or_else(|| {
        crate::errors::Error::Runtime("second receiver - no packets received!".to_string())
    })?;
    cancel.cancel();
    jh.await.unwrap();
    receiver2.clear();
    let dynamic_receiver_ms = duration.as_millis();
    tracing::info!("✓ Dynamic receiver test: {}ms", dynamic_receiver_ms);

    // Test distribution
    tracing::info!("Starting distribution test");
    receiver1.clear();
    receiver2.clear();
    let mut sender = Sender::from_url(&parsed_url, None, ip_address.is_ipv6()).await?;
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
    let distribution_sent = num_packets;
    let distribution_recv1 = recv1;
    let distribution_recv2 = recv2;
    tracing::info!(
        "✓ Distribution test: sent={}, recv1={}, recv2={}, total={}",
        distribution_sent,
        distribution_recv1,
        distribution_recv2,
        recv1 + recv2
    );

    // Test split events
    tracing::info!("Starting split event test");
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
    let split_candidates_1 = incomplete_event_keys(&receiver1).await;
    let split_candidates_2 = incomplete_event_keys(&receiver2).await;
    let split_events: HashSet<_> = split_candidates_1
        .intersection(&split_candidates_2)
        .cloned()
        .collect();
    let split_event_keys: Vec<_> = split_events.into_iter().collect();
    let split_event_count = split_event_keys.len();
    tracing::info!(
        "✓ Split event test: {} split events found",
        split_event_count
    );

    // Test remove/add sender
    tracing::info!("Starting remove/add sender test");
    let mut sender = Sender::from_url(&parsed_url, None, ip_address.is_ipv6()).await?;
    let cancel = CancellationToken::new();
    let cancel_cloned = cancel.clone();
    let jh = tokio::spawn(async move {
        sender
            .generate_test_stream(500, 1, Duration::from_millis(10), cancel_cloned)
            .await
    });
    let remove_start = Instant::now();
    client.remove_senders(vec![ip_address.to_string()]).await?;
    let after_remove = receiver1.count_packets(500, Duration::from_secs(1)).await;
    let remove_duration = remove_start.elapsed() - Duration::from_secs(1);
    cancel.cancel();
    jh.await.unwrap();
    let add_sender_ok = client
        .add_senders(vec![ip_address.to_string()])
        .await
        .is_ok();
    let remove_add_after_remove = after_remove;
    let remove_add_duration_ms = remove_duration.as_millis();
    let remove_add_sender_ok = add_sender_ok;
    tracing::info!(
        "✓ Remove/add sender test: after_remove={}, duration={}ms, add_ok={}",
        remove_add_after_remove,
        remove_add_duration_ms,
        remove_add_sender_ok
    );

    // Test overview
    tracing::info!("Starting overview test");
    let mut overview_errors = Vec::new();
    let reply = client.overview().await?;
    let our_lb = reply
        .get_ref()
        .load_balancers
        .iter()
        .find(|lb| lb.reservation.as_ref().unwrap().lb_id == lb_id);
    let mut overview_found = false;
    if let Some(lb) = our_lb {
        overview_found = true;
        if lb.name != "ejfat-doctor" {
            overview_errors.push("name mismatch".to_string());
        }
        let reservation = lb.reservation.as_ref().unwrap();
        let status = lb.status.as_ref().unwrap();
        if reservation.lb_id != lb_id {
            overview_errors.push("lb id mismatch".to_string());
        }
        if let Some(sync_addr_v4) = &parsed_url.sync_addr_v4 {
            if &reservation.sync_ipv4_address != sync_addr_v4 {
                overview_errors.push("sync ipv4 mismatch".to_string());
            }
        }
        if let Some(sync_addr_v6) = &parsed_url.sync_addr_v6 {
            if &reservation.sync_ipv6_address != sync_addr_v6 {
                overview_errors.push("sync ipv6 mismatch".to_string());
            }
        }
        if let Some(sync_udp_port) = parsed_url.sync_udp_port {
            if reservation.sync_udp_port as u16 != sync_udp_port {
                overview_errors.push("sync udp port mismatch".to_string());
            }
        }
        if status.sender_addresses != vec![ip_address.to_string()] {
            overview_errors.push("sender address mismatch".to_string());
        }
        if status.expires_at.is_none() {
            overview_errors.push("expiration time is missing".to_string());
        }
    } else {
        overview_errors.push("our lb not found in overview".to_string());
    }
    tracing::info!(
        "✓ Overview test: found={}, errors={}",
        overview_found,
        overview_errors.len()
    );

    // Test deregister
    tracing::info!("Starting deregister test");
    let deregister_ok = client.deregister().await.is_ok();
    tracing::info!(
        "✓ Deregister test: {}",
        if deregister_ok { "PASS" } else { "FAIL" }
    );

    // Cleanup receivers
    receiver1.cancel_tasks();
    receiver2.cancel_tasks();

    // Free the load balancer
    tracing::info!("Freeing load balancer {}", lb_id);
    if let Err(e) = client.free_load_balancer().await {
        tracing::warn!("Failed to free load balancer: {}", e);
        errors.push(format!("free_load_balancer: {e}"));
    } else {
        tracing::info!("freed load balancer {}", lb_id);
    }

    Ok(DynamicStrategyOutput {
        lb_id,
        url: ejfat_url,
        first_packet_ms,
        data_id_correct,
        packets_sent,
        packets_received,
        packets_lost,
        loss_pct,
        dynamic_receiver_ms,
        distribution_sent,
        distribution_recv1,
        distribution_recv2,
        split_event_count,
        split_event_keys,
        overview_found,
        overview_errors,
        remove_add_after_remove,
        remove_add_duration_ms,
        remove_add_sender_ok,
        deregister_ok,
        errors,
    })
}

async fn test_static_strategy(
    url: &str,
    ip_address: IpAddr,
    port: u16,
    mtu: usize,
    with_lb_headers: bool,
) -> Result<StaticStrategyOutput> {
    let mut errors = Vec::new();
    let base_port = port + 10; // Avoid conflicts with dynamic strategy

    // Reserve load balancer
    tracing::info!("Reserving load balancer for static strategy");
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
            "static".to_string(),
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

    let lb_id = reply.lb_id.clone();
    let ejfat_url = parsed_url.clone();

    tracing::info!("Starting first packet test; EJFAT_URI: {}", ejfat_url);

    // Test first packet to ensure LB is ready
    let offset = if with_lb_headers {
        std::mem::size_of::<LBHeader>()
    } else {
        0
    };
    let mut receiver1 = ReceiverBuilder::new("doctor-node1", ip_address.to_string(), base_port)
        .mtu(mtu)
        .offset(offset)
        .build(&mut client)
        .await?;

    let mut sender = Sender::from_url(&parsed_url, None, ip_address.is_ipv6()).await?;
    let cancel = CancellationToken::new();
    let cancel_cloned = cancel.clone();
    let jh = tokio::spawn(async move {
        sender
            .generate_test_stream(500, 1, Duration::from_millis(10), cancel_cloned)
            .await
    });
    let _ = receiver1.count_packets(1, Duration::from_secs(5)).await;
    let mut duration = receiver1
        .first_packet_duration()
        .ok_or_else(|| crate::errors::Error::Runtime("no packets received!".to_string()))?;
    duration += Duration::from_millis(100);
    cancel.cancel();
    jh.await.unwrap();
    receiver1.clear();
    let first_packet_ms = duration.as_millis();
    tracing::info!("✓ First packet test: {}ms", first_packet_ms);

    receiver1.cancel_tasks();
    client.deregister().await.ok();

    // Test static strategy slot demands
    tracing::info!("Starting static strategy slot demand test");

    // Register receiver 1 with slot demands
    let demands1 = vec![SlotRange {
        index: 0,
        length: 256,
    }];
    let mut receiver1 =
        ReceiverBuilder::new("doctor-static-1", ip_address.to_string(), base_port + 2)
            .mtu(mtu)
            .offset(offset)
            .slot_demands(demands1)
            .build(&mut client)
            .await?;
    let session_id1 = client.session_id.clone().unwrap();

    // Register receiver 2 with no slot demands
    let mut receiver2 =
        ReceiverBuilder::new("doctor-static-2", ip_address.to_string(), base_port + 3)
            .mtu(mtu)
            .offset(offset)
            .build(&mut client)
            .await?;
    let session_id2 = client.session_id.clone().unwrap();

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send traffic and check initial distribution
    let num_packets = 2000;
    let cancel = CancellationToken::new();
    let jh = {
        let mut sender = Sender::from_url(&parsed_url, None, ip_address.is_ipv6()).await?;
        let cancel_cloned = cancel.clone();
        tokio::spawn(async move {
            sender
                .generate_test_stream(num_packets, 20000, Duration::from_millis(5), cancel_cloned)
                .await
        })
    };

    let (initial_recv1, initial_recv2): (usize, usize) = tokio::join!(
        receiver1.count_packets(num_packets, Duration::from_millis(1000)),
        receiver2.count_packets(num_packets, Duration::from_millis(1000))
    );
    cancel.cancel();
    jh.await.unwrap();
    tracing::info!(
        "✓ Initial distribution: recv1={}, recv2={}",
        initial_recv1,
        initial_recv2
    );

    receiver1.clear();
    receiver2.clear();

    // Update slot demands for receiver 2
    let demands2 = vec![
        SessionSlotRanges {
            session_id: session_id1,
            slots: vec![SlotRange {
                index: 0,
                length: 128,
            }],
        },
        SessionSlotRanges {
            session_id: session_id2,
            slots: vec![SlotRange {
                index: -1,
                length: 384,
            }],
        },
    ];
    let set_demands_result = client.set_slot_demands(demands2).await;
    let set_demands_ok = set_demands_result.is_ok();
    if let Err(e) = set_demands_result {
        tracing::error!("✗ Set slot demands FAIL: {}", e);
    } else {
        tracing::info!("✓ Set slot demands: PASS");
    }

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send traffic again and check updated distribution
    let cancel = CancellationToken::new();
    let jh = {
        let mut sender = Sender::from_url(&parsed_url, None, ip_address.is_ipv6()).await?;
        let cancel_cloned = cancel.clone();
        tokio::spawn(async move {
            sender
                .generate_test_stream(num_packets, 20000, Duration::from_millis(5), cancel_cloned)
                .await
        })
    };

    let (updated_recv1, updated_recv2): (usize, usize) = tokio::join!(
        receiver1.count_packets(num_packets, Duration::from_millis(1000)),
        receiver2.count_packets(num_packets, Duration::from_millis(1000))
    );
    cancel.cancel();
    jh.await.unwrap();
    tracing::info!(
        "✓ Updated distribution: recv1={}, recv2={}",
        updated_recv1,
        updated_recv2
    );

    // Cleanup
    receiver1.cancel_tasks();
    receiver2.cancel_tasks();
    client.deregister().await.ok();

    tracing::info!("Freeing load balancer {}", lb_id);
    if let Err(e) = client.free_load_balancer().await {
        tracing::warn!("Failed to free load balancer: {}", e);
        errors.push(format!("free_load_balancer: {e}"));
    } else {
        tracing::info!("freed load balancer {}", lb_id);
    }

    Ok(StaticStrategyOutput {
        lb_id,
        url: ejfat_url,
        first_packet_ms,
        initial_recv1,
        initial_recv2,
        updated_recv1,
        updated_recv2,
        set_demands_ok,
        errors,
    })
}

async fn test_explicit_strategy(
    url: &str,
    ip_address: IpAddr,
    port: u16,
    mtu: usize,
    with_lb_headers: bool,
) -> Result<ExplicitStrategyOutput> {
    let mut errors = Vec::new();
    let base_port = port + 20; // Avoid conflicts with other strategies

    // Reserve load balancer
    tracing::info!("Reserving load balancer for explicit strategy");
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
            "explicit".to_string(),
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

    let lb_id = reply.lb_id.clone();
    let ejfat_url = parsed_url.clone();

    tracing::info!("Starting first packet test; EJFAT_URI: {}", ejfat_url);

    // Test first packet to ensure LB is ready (with slot demands for explicit strategy)
    let offset = if with_lb_headers {
        std::mem::size_of::<LBHeader>()
    } else {
        0
    };
    let slot_demands = vec![SlotRange {
        index: 0,
        length: 512,
    }];
    let mut receiver1 = ReceiverBuilder::new("doctor-node1", ip_address.to_string(), base_port)
        .mtu(mtu)
        .offset(offset)
        .slot_demands(slot_demands)
        .build(&mut client)
        .await?;

    let mut sender = Sender::from_url(&parsed_url, None, ip_address.is_ipv6()).await?;
    let cancel = CancellationToken::new();
    let cancel_cloned = cancel.clone();
    let jh = tokio::spawn(async move {
        sender
            .generate_test_stream(500, 1, Duration::from_millis(10), cancel_cloned)
            .await
    });
    let _ = receiver1.count_packets(1, Duration::from_secs(5)).await;
    let mut duration = receiver1
        .first_packet_duration()
        .ok_or_else(|| crate::errors::Error::Runtime("no packets received!".to_string()))?;
    duration += Duration::from_millis(100);
    cancel.cancel();
    jh.await.unwrap();
    receiver1.clear();
    let first_packet_ms = duration.as_millis();
    tracing::info!("✓ First packet test: {}ms", first_packet_ms);

    receiver1.cancel_tasks();
    client.deregister().await.ok();

    // Test explicit strategy slot coverage
    tracing::info!("Starting explicit strategy slot coverage test");

    // Register receiver 1 with partial slot coverage
    let demands1 = vec![SlotRange {
        index: 0,
        length: 256,
    }];
    let mut receiver1 =
        ReceiverBuilder::new("doctor-explicit-1", ip_address.to_string(), base_port + 2)
            .mtu(mtu)
            .offset(offset)
            .slot_demands(demands1)
            .build(&mut client)
            .await?;

    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Send traffic and check initial loss (should lose ~50% since only half slots covered)
    let num_packets = 2000;
    let cancel = CancellationToken::new();
    let jh = {
        let mut sender = Sender::from_url(&parsed_url, None, ip_address.is_ipv6()).await?;
        let cancel_cloned = cancel.clone();
        tokio::spawn(async move {
            sender
                .generate_test_stream(num_packets, 20000, Duration::from_millis(5), cancel_cloned)
                .await
        })
    };

    let initial_recv = receiver1
        .count_packets(num_packets, Duration::from_millis(1000))
        .await;
    cancel.cancel();
    jh.await.unwrap();
    let initial_loss_pct = 100.0 - ((initial_recv as f64 / num_packets as f64) * 100.0);
    tracing::info!(
        "✓ Initial slot coverage: recv={}, loss={:.2}%",
        initial_recv,
        initial_loss_pct
    );

    receiver1.clear();

    // Register receiver 2 to cover remaining slots
    let demands2 = vec![SlotRange {
        index: -1,
        length: 256,
    }];
    let mut receiver2 =
        ReceiverBuilder::new("doctor-explicit-2", ip_address.to_string(), base_port + 3)
            .mtu(mtu)
            .offset(offset)
            .slot_demands(demands2)
            .build(&mut client)
            .await?;

    tokio::time::sleep(Duration::from_millis(2000)).await;

    // Send traffic again and check updated loss (should be minimal now)
    let cancel = CancellationToken::new();
    let jh = {
        let mut sender = Sender::from_url(&parsed_url, None, ip_address.is_ipv6()).await?;
        let cancel_cloned = cancel.clone();
        tokio::spawn(async move {
            sender
                .generate_test_stream(num_packets, 20000, Duration::from_millis(5), cancel_cloned)
                .await
        })
    };

    let (updated_recv1, updated_recv2): (usize, usize) = tokio::join!(
        receiver1.count_packets(num_packets, Duration::from_millis(1000)),
        receiver2.count_packets(num_packets, Duration::from_millis(1000))
    );
    cancel.cancel();
    jh.await.unwrap();
    let updated_recv = updated_recv1 + updated_recv2;
    let updated_loss_pct = 100.0 - ((updated_recv as f64 / num_packets as f64) * 100.0);
    tracing::info!(
        "✓ Full slot coverage: recv1={}, recv2={}, total={}, loss={:.2}%",
        updated_recv1,
        updated_recv2,
        updated_recv,
        updated_loss_pct
    );

    // Cleanup
    receiver1.cancel_tasks();
    receiver2.cancel_tasks();
    client.deregister().await.ok();

    tracing::info!("Freeing load balancer {}", lb_id);
    if let Err(e) = client.free_load_balancer().await {
        tracing::warn!("Failed to free load balancer: {}", e);
        errors.push(format!("free_load_balancer: {e}"));
    } else {
        tracing::info!("freed load balancer {}", lb_id);
    }

    Ok(ExplicitStrategyOutput {
        lb_id,
        url: ejfat_url,
        first_packet_ms,
        initial_recv,
        initial_loss_pct,
        updated_recv,
        updated_loss_pct,
        errors,
    })
}

/// Test LB chaining: reserve two LBs on the same control plane, chain LB-B to LB-A,
/// send traffic to LB-A, and verify it arrives at a receiver registered on LB-B.
pub async fn test_chain(
    url: &str,
    ip_address: IpAddr,
    port: u16,
    mtu: usize,
    with_lb_headers: bool,
) -> Result<ChainOutput> {
    let mut errors = Vec::new();
    let base_port = port + 30; // Avoid conflicts with other strategies

    let ip_family = match ip_address {
        IpAddr::V4(_) => IpFamily::Ipv4,
        IpAddr::V6(_) => IpFamily::Ipv6,
    };
    let expiration = SystemTime::now() + Duration::from_secs(180);
    let expiration_timestamp = Timestamp::from(expiration);

    // Reserve LB-A (upstream)
    tracing::info!("reserving upstream LB (LB-A) for chain test");
    let mut client_a = ControlPlaneClient::from_url(url).await?;
    let reply_a = client_a
        .reserve_load_balancer(
            "doctor-chain-upstream".to_string(),
            Some(expiration_timestamp.clone()),
            vec![ip_address.to_string()],
            ip_family,
            "dynamic".to_string(),
        )
        .await?
        .into_inner();

    let lb_a_id = reply_a.lb_id.clone();
    client_a.lb_id = Some(lb_a_id.clone());

    let mut url_a: EjfatUrl = url.parse().expect("Invalid EJFAT url");
    url_a.update_from_reservation(&reply_a);
    url_a = match ip_family {
        IpFamily::Ipv4 => url_a.without_v6(),
        IpFamily::Ipv6 => url_a.without_v4(),
        _ => url_a,
    };

    tracing::info!("upstream LB-A reserved: id={}, EJFAT_URI={}", lb_a_id, url_a);

    // Reserve LB-B (downstream)
    tracing::info!("reserving downstream LB (LB-B) for chain test");
    let mut client_b = ControlPlaneClient::from_url(url).await?;
    let reply_b = client_b
        .reserve_load_balancer(
            "doctor-chain-downstream".to_string(),
            Some(expiration_timestamp),
            vec![],
            ip_family,
            "dynamic".to_string(),
        )
        .await?
        .into_inner();

    let lb_b_id = reply_b.lb_id.clone();
    client_b.lb_id = Some(lb_b_id.clone());

    let mut url_b: EjfatUrl = url.parse().expect("Invalid EJFAT url");
    url_b.update_from_reservation(&reply_b);
    url_b = match ip_family {
        IpFamily::Ipv4 => url_b.without_v6(),
        IpFamily::Ipv6 => url_b.without_v4(),
        _ => url_b,
    };

    tracing::info!("downstream LB-B reserved: id={}, EJFAT_URI={}", lb_b_id, url_b);

    // Chain LB-B to LB-A: registers LB-B's data address with LB-A as a receiver (keepLbHeader=true)
    tracing::info!("chaining LB-B to LB-A");
    let chain_result = client_b
        .chain_load_balancer(
            lb_b_id.clone(),
            url_a.to_string(),
            ip_family,
            1.0,
            0.5,
            2.0,
            vec![],
        )
        .await;

    let (chain_ok, chain_id) = match chain_result {
        Ok(reply) => {
            let chain_id = reply.into_inner().chain_id;
            tracing::info!("chain created: chain_id={}", chain_id);
            (true, chain_id)
        }
        Err(e) => {
            let msg = format!("chain_load_balancer failed: {e}");
            tracing::error!("{}", msg);
            errors.push(msg);
            // Cleanup and return early
            client_a.free_load_balancer().await.ok();
            client_b.free_load_balancer().await.ok();
            return Ok(ChainOutput {
                upstream_lb_id: lb_a_id,
                downstream_lb_id: lb_b_id,
                chain_id: String::new(),
                chain_ok: false,
                packets_sent: 0,
                packets_received: 0,
                first_packet_ms: None,
                unchain_ok: false,
                errors,
            });
        }
    };

    // Register a receiver on LB-B (the final destination for chained traffic)
    tracing::info!("registering receiver on LB-B");
    let offset = if with_lb_headers {
        std::mem::size_of::<LBHeader>()
    } else {
        0
    };
    let mut receiver = ReceiverBuilder::new("doctor-chain-recv", ip_address.to_string(), base_port)
        .mtu(mtu)
        .offset(offset)
        .build(&mut client_b)
        .await?;

    // Allow time for the chain registration and receiver to propagate
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Send traffic to LB-A's data plane
    tracing::info!("sending traffic to LB-A, expecting it to arrive at LB-B's receiver");
    let num_packets = 500;
    let mut sender = Sender::from_url(&url_a, None, ip_address.is_ipv6()).await?;
    let cancel = CancellationToken::new();
    let cancel_cloned = cancel.clone();
    let jh = tokio::spawn(async move {
        sender
            .generate_test_stream(num_packets, 1, Duration::from_millis(10), cancel_cloned)
            .await
    });

    // Wait for packets at LB-B's receiver
    let received = receiver.count_packets(num_packets, Duration::from_secs(10)).await;
    let first_packet_ms = receiver.first_packet_duration().map(|d| d.as_millis());
    cancel.cancel();
    jh.await.unwrap();

    tracing::info!(
        "chain traffic test: sent={}, received={}, first_packet_ms={:?}",
        num_packets, received, first_packet_ms
    );
    if received == 0 {
        errors.push("no packets received through chain".to_string());
    }

    // Unchain
    tracing::info!("unchaining LB-B from LB-A");
    let unchain_ok = match client_b
        .unchain_load_balancer(lb_b_id.clone(), chain_id.clone())
        .await
    {
        Ok(_) => {
            tracing::info!("unchain successful");
            true
        }
        Err(e) => {
            let msg = format!("unchain_load_balancer failed: {e}");
            tracing::error!("{}", msg);
            errors.push(msg);
            false
        }
    };

    // Cleanup
    receiver.cancel_tasks();
    client_b.deregister().await.ok();

    tracing::info!("Freeing LB-A ({})", lb_a_id);
    if let Err(e) = client_a.free_load_balancer().await {
        tracing::warn!("Failed to free LB-A: {}", e);
        errors.push(format!("free LB-A: {e}"));
    }

    tracing::info!("Freeing LB-B ({})", lb_b_id);
    if let Err(e) = client_b.free_load_balancer().await {
        tracing::warn!("Failed to free LB-B: {}", e);
        errors.push(format!("free LB-B: {e}"));
    }

    Ok(ChainOutput {
        upstream_lb_id: lb_a_id,
        downstream_lb_id: lb_b_id,
        chain_id,
        chain_ok,
        packets_sent: num_packets,
        packets_received: received,
        first_packet_ms,
        unchain_ok,
        errors,
    })
}

/// Run the doctor test for a single address, testing all strategies.
pub async fn doctor(
    url: &str,
    ip_address: IpAddr,
    port: u16,
    mtu: usize,
    with_lb_headers: bool,
) -> Result<DoctorOutput> {
    tracing::info!("Testing dynamic strategy");
    let dynamic = test_dynamic_strategy(url, ip_address, port, mtu, with_lb_headers).await?;

    tracing::info!("Testing static strategy");
    let static_strategy = test_static_strategy(url, ip_address, port, mtu, with_lb_headers).await?;

    tracing::info!("Testing explicit strategy");
    let explicit = test_explicit_strategy(url, ip_address, port, mtu, with_lb_headers).await?;

    Ok(DoctorOutput {
        address: ip_address.to_string(),
        dynamic,
        static_strategy,
        explicit,
    })
}

/// Run the doctor test for multiple addresses, returning a Vec of results.
pub async fn doctor_multi(
    url: &str,
    addresses: Vec<String>,
    port: u16,
    mtu: usize,
    with_lb_headers: bool,
) -> Vec<Result<DoctorOutput>> {
    let mut results = Vec::new();

    for addr in &addresses {
        let ip_addr = addr
            .parse::<IpAddr>()
            .expect("Invalid IP address in doctor_multi");

        let res = doctor(url, ip_addr, port, mtu, with_lb_headers).await;
        results.push(res);
    }
    results
}

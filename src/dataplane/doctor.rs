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

impl DoctorOutput {
    /// Renders the doctor results as JUnit XML.
    ///
    /// Each strategy maps to a `<testsuite>` and each individual check
    /// maps to a `<testcase>`.  A failing check produces a `<failure>`
    /// element containing the error message.
    pub fn to_junit_xml(&self) -> String {
        let mut suites = String::new();

        suites.push_str(&self.dynamic.to_junit_suite(&self.address));
        suites.push_str(&self.static_strategy.to_junit_suite(&self.address));
        suites.push_str(&self.explicit.to_junit_suite(&self.address));

        format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites>\n{suites}</testsuites>\n")
    }

    /// Produces a valid JUnit XML document representing a fatal error that
    /// prevented any tests from running (e.g. unable to connect to the control
    /// plane).  This ensures consumers always receive well-formed XML.
    pub fn error_xml(address: &str, error: &dyn std::fmt::Display) -> String {
        let msg = xml_escape(&error.to_string());
        let classname = xml_escape(&format!("ejfat.doctor.{address}"));
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <testsuites>\n\
             \x20 <testsuite name=\"doctor\" tests=\"1\" failures=\"1\" errors=\"0\">\n\
             \x20   <testcase classname=\"{classname}\" name=\"connect\">\n\
             \x20     <failure message=\"{msg}\" />\n\
             \x20   </testcase>\n\
             \x20 </testsuite>\n\
             </testsuites>\n"
        )
    }
}

/// Escapes special XML characters in attribute values and text content.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn junit_testcase(classname: &str, name: &str, failure: Option<&str>) -> String {
    match failure {
        None => format!(
            "    <testcase classname=\"{}\" name=\"{}\" />\n",
            xml_escape(classname),
            xml_escape(name)
        ),
        Some(msg) => format!(
            "    <testcase classname=\"{}\" name=\"{}\">\n      <failure message=\"{}\" />\n    </testcase>\n",
            xml_escape(classname),
            xml_escape(name),
            xml_escape(msg)
        ),
    }
}

impl DynamicStrategyOutput {
    fn to_junit_suite(&self, address: &str) -> String {
        let classname = format!("ejfat.doctor.{address}.dynamic");

        let mut cases = String::new();
        let mut failures = 0u32;

        // first packet – no hard pass/fail threshold, always passes
        cases.push_str(&junit_testcase(&classname, "first_packet", None));

        // data_id
        if self.data_id_correct {
            cases.push_str(&junit_testcase(&classname, "data_id", None));
        } else {
            failures += 1;
            cases.push_str(&junit_testcase(
                &classname,
                "data_id",
                Some("data id was incorrect"),
            ));
        }

        // packet loss (informational – no failure threshold enforced)
        cases.push_str(&junit_testcase(&classname, "packet_loss", None));

        // dynamic receiver
        cases.push_str(&junit_testcase(&classname, "dynamic_receiver", None));

        // distribution
        cases.push_str(&junit_testcase(&classname, "distribution", None));

        // split events
        cases.push_str(&junit_testcase(&classname, "split_events", None));

        // remove/add sender
        if self.remove_add_sender_ok {
            cases.push_str(&junit_testcase(&classname, "remove_add_sender", None));
        } else {
            failures += 1;
            cases.push_str(&junit_testcase(
                &classname,
                "remove_add_sender",
                Some("add_senders failed after remove_senders"),
            ));
        }

        // overview
        if self.overview_found && self.overview_errors.is_empty() {
            cases.push_str(&junit_testcase(&classname, "overview", None));
        } else {
            failures += 1;
            let msg = if self.overview_errors.is_empty() {
                "lb not found in overview".to_string()
            } else {
                self.overview_errors.join("; ")
            };
            cases.push_str(&junit_testcase(&classname, "overview", Some(&msg)));
        }

        // deregister
        if self.deregister_ok {
            cases.push_str(&junit_testcase(&classname, "deregister", None));
        } else {
            failures += 1;
            cases.push_str(&junit_testcase(
                &classname,
                "deregister",
                Some("deregister failed"),
            ));
        }

        // top-level errors
        for err in &self.errors {
            failures += 1;
            cases.push_str(&junit_testcase(&classname, "cleanup", Some(err)));
        }

        let tests = 9usize.saturating_add(self.errors.len());
        format!(
            "  <testsuite name=\"dynamic\" tests=\"{tests}\" failures=\"{failures}\" errors=\"0\">\n{cases}  </testsuite>\n"
        )
    }
}

impl StaticStrategyOutput {
    fn to_junit_suite(&self, address: &str) -> String {
        let classname = format!("ejfat.doctor.{address}.static");

        let mut cases = String::new();
        let mut failures = 0u32;

        cases.push_str(&junit_testcase(&classname, "first_packet", None));

        if self.set_demands_ok {
            cases.push_str(&junit_testcase(&classname, "set_slot_demands", None));
        } else {
            failures += 1;
            cases.push_str(&junit_testcase(
                &classname,
                "set_slot_demands",
                Some("set_slot_demands RPC failed"),
            ));
        }

        // distribution checks (informational)
        cases.push_str(&junit_testcase(&classname, "initial_distribution", None));
        cases.push_str(&junit_testcase(&classname, "updated_distribution", None));

        for err in &self.errors {
            failures += 1;
            cases.push_str(&junit_testcase(&classname, "cleanup", Some(err)));
        }

        let tests = 4usize.saturating_add(self.errors.len());
        format!(
            "  <testsuite name=\"static\" tests=\"{tests}\" failures=\"{failures}\" errors=\"0\">\n{cases}  </testsuite>\n"
        )
    }
}

impl ExplicitStrategyOutput {
    fn to_junit_suite(&self, address: &str) -> String {
        let classname = format!("ejfat.doctor.{address}.explicit");

        let mut cases = String::new();
        let mut failures = 0u32;

        cases.push_str(&junit_testcase(&classname, "first_packet", None));
        cases.push_str(&junit_testcase(&classname, "initial_slot_coverage", None));
        cases.push_str(&junit_testcase(&classname, "full_slot_coverage", None));

        for err in &self.errors {
            failures += 1;
            cases.push_str(&junit_testcase(&classname, "cleanup", Some(err)));
        }

        let tests = 3usize.saturating_add(self.errors.len());
        format!(
            "  <testsuite name=\"explicit\" tests=\"{tests}\" failures=\"{failures}\" errors=\"0\">\n{cases}  </testsuite>\n"
        )
    }
}

impl DynamicStrategyOutput {
    /// Returns true if the dynamic strategy test passed without errors.
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
            && self.overview_errors.is_empty()
            && self.data_id_correct
            && self.deregister_ok
            && self.remove_add_sender_ok
            && self.overview_found
    }
}

impl StaticStrategyOutput {
    /// Returns true if the static strategy test passed without errors.
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty() && self.set_demands_ok
    }
}

impl ExplicitStrategyOutput {
    /// Returns true if the explicit strategy test passed without errors.
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

impl DoctorOutput {
    /// Returns true if all strategy tests passed without errors.
    pub fn is_ok(&self) -> bool {
        self.dynamic.is_ok() && self.static_strategy.is_ok() && self.explicit.is_ok()
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

/// Run the doctor test for multiple addresses, returning a Vec of `(address, result)` pairs.
///
/// The address string is always returned alongside the result so callers can
/// produce meaningful output even when the test fails before a `DoctorOutput`
/// can be constructed.
pub async fn doctor_multi(
    url: &str,
    addresses: Vec<String>,
    port: u16,
    mtu: usize,
    with_lb_headers: bool,
) -> Vec<(String, Result<DoctorOutput>)> {
    let mut results = Vec::new();

    for addr in &addresses {
        let ip_addr = addr
            .parse::<IpAddr>()
            .expect("Invalid IP address in doctor_multi");

        let res = doctor(url, ip_addr, port, mtu, with_lb_headers).await;
        results.push((addr.clone(), res));
    }
    results
}

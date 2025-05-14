use crate::api::client::{ControlPlaneClient, EjfatUrl};
use crate::dataplane::protocol::LBHeader;
use crate::dataplane::receiver::Receiver;
use crate::dataplane::sender::Sender;
use crate::errors::{Error, Result};

use std::fmt;
use std::time::{Duration, Instant, SystemTime};

use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use prost_wkt_types::Timestamp;

pub struct DoctorOutput {
    responsivity_duration: Duration,
    responsivity_duration_receiver2: Duration,
    packets_sent: usize,
    packets_received: usize,
    packets_lost: usize,
    packets_sent_dist: usize,
    packets_received_dist_1: usize,
    packets_received_dist_2: usize,
    packets_after_remove: usize,
    remove_duration: Duration,
    data_id_correct: bool,
}

impl fmt::Display for DoctorOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let startup_ms = self.responsivity_duration.as_millis();
        let lpct = 100.0 - ((self.packets_received as f64 / self.packets_sent as f64) * 100.0);
        writeln!(f, "startup: {}ms", startup_ms)?;
        writeln!(f, "sent: {}", self.packets_sent)?;
        writeln!(f, "recv: {}", self.packets_received)?;
        writeln!(f, "lost: {} ({:.3}%)", self.packets_lost, lpct)?;
        writeln!(
            f,
            "register: {}ms",
            self.responsivity_duration_receiver2.as_millis()
        )?;
        writeln!(f, "sent both: {}", self.packets_sent_dist)?;
        writeln!(f, "recv 1: {}", self.packets_received_dist_1)?;
        writeln!(f, "recv 2: {}", self.packets_received_dist_2)?;
        writeln!(f, "remove: {}ms", self.remove_duration.as_millis())?;
        writeln!(f, "recv after remove: {}", self.packets_after_remove)?;
        writeln!(f, "data_id correct: {}", self.data_id_correct)?;
        Ok(())
    }
}

pub async fn doctor(
    url: String,
    ip_address: String,
    port: u16,
    mtu: usize,
    with_lb_headers: bool,
) -> Result<DoctorOutput> {
    eprintln!("Starting EJFAT doctor...");

    let mut errors = Vec::new();
    let mut client: Option<ControlPlaneClient> = None;
    let mut receiver: Option<Receiver> = None;
    let mut receiver2: Option<Receiver> = None;

    let result = async {
        // Initialize a control plane client and reserve an LB
        eprint!("testing reserve_load_balancer...");
        let mut parsed_url: EjfatUrl = url.parse().expect("Invalid EJFAT url");
        client = Some(ControlPlaneClient::from_url(&url).await?);
        let client_ref = client.as_mut().unwrap();

        // Set expiration time to three minutes from now
        let expiration = SystemTime::now() + Duration::from_secs(180);
        let expiration_timestamp = Timestamp::from(expiration);

        let reply = client_ref
            .reserve_load_balancer(
                "ejfat-doctor".to_string(),
                Some(expiration_timestamp),
                vec![ip_address.clone()],
            )
            .await?
            .into_inner();

        client_ref.lb_id = Some(reply.lb_id.clone());
        parsed_url.update_from_reservation(&reply);
        eprintln!("done.\n    url: {}", parsed_url);

        let offset = if with_lb_headers {
            std::mem::size_of::<LBHeader>()
        } else {
            0
        };

        eprint!("done.\ntesting receiver register/sendstate and time to first packet...");
        receiver = Some(
            Receiver::new_simple_uncontrolled(
                "doctor-node1",
                ip_address.clone(),
                port,
                mtu,
                offset,
                client_ref,
                None,
            )
            .await?,
        );

        let mut sender1 = Sender::from_url(&parsed_url, None).await?;
        let cancel1 = CancellationToken::new();
        let cancel1_cloned = cancel1.clone();
        let mut jh = tokio::spawn(async move {
            sender1
                .generate_test_stream(500, 1, Duration::from_millis(10), cancel1_cloned)
                .await
        });
        let _first_packet = receiver
            .as_mut()
            .unwrap()
            .count_packets(1, Duration::from_secs(5))
            .await;
        let mut responsivity_duration = receiver
            .as_mut()
            .unwrap()
            .first_packet_duration()
            .expect("no packets received!");
        responsivity_duration += Duration::from_millis(100);
        cancel1.cancel();
        jh.await.unwrap();
        receiver.as_mut().unwrap().clear();
        eprintln!(
            "done\n    duration_to_first_packet: {:?}",
            responsivity_duration
        );

        // Ensure data_id behavior is correct
        print!("testing data_id behavior...");
        let mut sender_data_id = Sender::from_url(&parsed_url, None).await?;
        let data_id_test_data = vec![0u8; 100];
        sender_data_id.send_ts(&data_id_test_data, 1234).await;
        let data_id_correct =
            match timeout(Duration::from_secs(5), receiver.as_mut().unwrap().rx.recv()).await {
                Ok(Some(event)) => event.data_id == 1234,
                _ => false,
            };
        if data_id_correct {
            println!("done. data_id correct.")
        } else {
            println!("error!");
            errors.push("data_id incorrect".to_string());
        }

        // Packet Loss Test: Send 1000 packets to get % loss
        eprint!("testing packet loss...");
        let num_packets: usize = 1000;
        let mut sender2 = Sender::from_url(&parsed_url, None).await?;
        let cancel2 = CancellationToken::new();
        let cancel2_cloned = cancel2.clone();
        jh = tokio::spawn(async move {
            sender2
                .generate_test_stream(num_packets, 1, Duration::from_micros(5), cancel2_cloned)
                .await
        });
        let received_packets = receiver
            .as_mut()
            .unwrap()
            .count_packets(num_packets, Duration::from_millis(100))
            .await;
        let lost_packets = num_packets - received_packets;
        cancel2.cancel();
        jh.await.unwrap();
        eprintln!(
            "done.\n    sent: {}\n    received: {}\n    lost: {}",
            num_packets, received_packets, lost_packets
        );

        eprintln!("registering second receiver");
        receiver2 = Some(
            Receiver::new_simple_uncontrolled(
                "doctor-node2",
                ip_address.clone(),
                port + 1,
                mtu,
                offset,
                client_ref,
                None,
            )
            .await?,
        );

        // Responsivity test for the second receiver
        eprint!("testing dynamic addition responsivity...");
        let mut sender3 = Sender::from_url(&parsed_url, None).await?;
        let cancel3 = CancellationToken::new();
        let cancel3_cloned = cancel3.clone();
        jh = tokio::spawn(async move {
            sender3
                .generate_test_stream(500, 1, Duration::from_millis(10), cancel3_cloned)
                .await
        });
        let _first_packet_receiver2 = receiver2
            .as_mut()
            .unwrap()
            .count_packets(1, Duration::from_secs(5))
            .await;
        let responsivity_duration_receiver2 = receiver2
            .as_mut()
            .unwrap()
            .first_packet_duration()
            .expect("second receiver - no packets received!");
        cancel3.cancel();
        jh.await.unwrap();
        receiver.as_mut().unwrap().clear();
        receiver2.as_mut().unwrap().clear();
        eprintln!(
            "done.\n    duration_to_first_packet: {:?}",
            responsivity_duration_receiver2
        );

        // Packet Distribution Test: Send 5000 events over 3 seconds and measure how many each receiver gets
        eprint!("testing event distribution...");
        let mut sender4 = Sender::from_url(&parsed_url, None).await?;
        let num_packets_dist = 5000;
        let cancel4 = CancellationToken::new();
        let cancel4_cloned = cancel4.clone();
        jh = tokio::spawn(async move {
            sender4
                .generate_test_stream(
                    num_packets_dist,
                    20000,
                    Duration::from_millis(5),
                    cancel4_cloned,
                )
                .await
        });

        // Count packets as before
        let (received_packets_dist_1, received_packets_dist_2): (usize, usize) = tokio::join!(
            receiver
                .as_mut()
                .unwrap()
                .count_packets(num_packets_dist, Duration::from_millis(2000)),
            receiver2
                .as_mut()
                .unwrap()
                .count_packets(num_packets_dist, Duration::from_millis(2000))
        );
        eprintln!(
            "done.\n    sent: {}\n    receiver1: {}\n    receiver2: {}",
            num_packets_dist, received_packets_dist_1, received_packets_dist_2
        );

        // --- Split event detection ---
        // This assumes you can access the reassembler and its buffers from the receiver.
        // If not, you may need to make the field pub or use a test-only accessor.
        use std::collections::HashSet;

        // Helper to extract incomplete buffer keys from a receiver's reassembler (async)
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

        let split_candidates_1 = incomplete_event_keys(receiver.as_ref().unwrap()).await;
        let split_candidates_2 = incomplete_event_keys(receiver2.as_ref().unwrap()).await;
        let split_events: HashSet<_> = split_candidates_1
            .intersection(&split_candidates_2)
            .collect();

        eprintln!(
            "split event detection: receiver1 incomplete: {}, receiver2 incomplete: {}, split events: {}",
            split_candidates_1.len(),
            split_candidates_2.len(),
            split_events.len()
        );
        if !split_events.is_empty() {
            eprintln!("Split events detected: {:?}", split_events);
        }

        // Test overview
        eprint!("testing overview...");
        let overview_reply = client_ref.overview().await?;
        let our_lb = overview_reply.get_ref().load_balancers.iter().find(|lb| {
            &lb.reservation.as_ref().unwrap().lb_id == client_ref.lb_id.as_ref().unwrap()
        });
        if let Some(lb) = our_lb {
            eprintln!("done.\n    found our LB in overview");
            let reservation = lb.reservation.as_ref().unwrap();
            let status = lb.status.as_ref().unwrap();
            if &reservation.lb_id != client_ref.lb_id.as_ref().unwrap() {
                errors.push("lb id mismatch".to_string());
            }
            if &reservation.sync_ip_address != parsed_url.sync_ip_address.as_ref().unwrap() {
                errors.push("sync ip mismatch".to_string());
            }
            if reservation.sync_udp_port as u16 != parsed_url.sync_udp_port.unwrap() {
                errors.push("sync udp port mismatch".to_string());
            }
            if status.sender_addresses != vec![ip_address.clone()] {
                errors.push("sender address mismatch".to_string());
            }
            if status.expires_at.is_none() {
                errors.push("expiration time is missing".to_string());
            }
        } else {
            errors.push("our lb not found in overview".to_string());
        }

        // Test get_load_balancer
        eprint!("testing get_load_balancer...");
        let mut get_lb_err = false;
        let get_lb_reply = client_ref.get_load_balancer().await?;
        let lb_details = get_lb_reply.get_ref();
        if &lb_details.lb_id != client_ref.lb_id.as_ref().unwrap() {
            errors.push("lb id mismatch in get_load_balancer".to_string());
            get_lb_err = true;
        }
        if &lb_details.sync_ip_address != parsed_url.sync_ip_address.as_ref().unwrap() {
            errors.push("sync ip mismatch in get_load_balancer".to_string());
            get_lb_err = true;
        }
        if lb_details.sync_udp_port as u16 != parsed_url.sync_udp_port.unwrap() {
            errors.push("sync udp port mismatch in get_load_balancer".to_string());
            get_lb_err = true;
        }
        if get_lb_err {
            eprintln!("error.")
        } else {
            eprintln!("done.")
        }

        // Responsiveness to RemoveSenders test
        eprint!("testing responsiveness to RemoveSenders...");
        cancel4.cancel();
        jh.await.unwrap();
        let mut sender5 = Sender::from_url(&parsed_url, None).await?;
        let cancel5 = CancellationToken::new();
        let cancel5_cloned = cancel5.clone();
        jh = tokio::spawn(async move {
            sender5
                .generate_test_stream(500, 1, Duration::from_millis(10), cancel5_cloned)
                .await
        });

        let remove_start = Instant::now();
        client_ref.remove_senders(vec![ip_address.clone()]).await?;
        let packets_after_remove = receiver
            .as_mut()
            .unwrap()
            .count_packets(500, Duration::from_secs(1))
            .await;
        let remove_duration = remove_start.elapsed() - Duration::from_secs(1);
        eprintln!(
            "done.\n    duration: {:?}\n    packets after remove: {}",
            remove_duration, packets_after_remove
        );
        jh.await.unwrap();

        // Test AddSenders
        eprint!("testing AddSenders...");
        let _ = client_ref.add_senders(vec![ip_address.clone()]).await?;

        // Verify that the sender was added back
        let overview_reply = client_ref.overview().await?;
        let our_lb = overview_reply.get_ref().load_balancers.iter().find(|lb| {
            &lb.reservation.as_ref().unwrap().lb_id == client_ref.lb_id.as_ref().unwrap()
        });
        if let Some(lb) = our_lb {
            let status = lb.status.as_ref().unwrap();
            if status.sender_addresses != vec![ip_address.clone()] {
                eprintln!("error: sender address not added back");
                errors.push("error: sender address not added back".to_string());
            } else {
                eprintln!("done.");
            }
        } else {
            errors.push("our lb not found in overview after AddSenders".to_string());
        }

        // Test deregister
        eprint!("testing deregister...");
        let _ = client_ref.deregister().await?;
        eprintln!("done.");

        Ok(DoctorOutput {
            responsivity_duration,
            responsivity_duration_receiver2,
            packets_sent: num_packets,
            packets_received: received_packets,
            packets_lost: lost_packets,
            packets_sent_dist: num_packets_dist,
            packets_received_dist_1: received_packets_dist_1,
            packets_received_dist_2: received_packets_dist_2,
            packets_after_remove,
            remove_duration,
            data_id_correct,
        })
    }
    .await;

    // Cleanup
    if let Some(r) = receiver.as_mut() {
        r.cancel_tasks();
    }
    if let Some(r) = receiver2.as_mut() {
        r.cancel_tasks();
    }
    if let Some(c) = client.as_mut() {
        if let Err(e) = c.free_load_balancer().await {
            eprintln!("Error freeing load balancer: {:?}", e);
        }
    }

    // Handle errors and result
    if !errors.is_empty() {
        eprintln!("fail - doctor completed with errors:");
        for error in &errors {
            eprintln!("  - {}", error);
        }
        Err(Error::TestFailure(format!(
            "{} errors occurred",
            errors.len()
        )))
    } else {
        match result {
            Ok(output) => {
                eprintln!("success - doctor did not detect any errors.");
                Ok(output)
            }
            Err(e) => {
                eprintln!("doctor failed: {:?}", e);
                Err(e)
            }
        }
    }
}

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use std::fs::File;
use std::io::Read;
use std::time::Duration;
use std::{fmt, sync::atomic::AtomicUsize};

use crate::api::client::{ControlPlaneClient, EjfatUrl};
use crate::dataplane::meta_events::{MetaEventManager, MetaEventType};
use crate::dataplane::receiver::Receiver;
use crate::dataplane::sender::Sender;
use crate::errors::Result;

static COUNTER: AtomicUsize = AtomicUsize::new(1);
fn get_id() -> usize {
    COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TestConfig {
    pub sender: SenderConfig,
    pub receivers: Vec<ReceiverConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SenderConfig {
    pub rate: u64,          // in microseconds
    pub event_count: usize, // Number of events
    pub event_size: usize,  // Size of events in bytes
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReceiverConfig {
    pub rate: u64, // in microseconds
    #[serde(default = "default_name")]
    pub name: String,
    #[serde(default)]
    pub kp: f64,
    #[serde(default)]
    pub ki: f64,
    #[serde(default)]
    pub kd: f64,
    #[serde(default)]
    pub min_factor: f32,
    #[serde(default)]
    pub max_factor: f32,
    #[serde(default = "default_sp")]
    pub sp: usize,
}

fn default_name() -> String {
    format!("node-{:03}", get_id())
}

fn default_sp() -> usize {
    5
}

pub fn load_config_from_json(file_path: &str) -> Result<TestConfig> {
    let mut file = File::open(file_path)?;
    let mut data = String::new();
    file.read_to_string(&mut data)?;
    let config: TestConfig = serde_json::from_str(&data)?;
    Ok(config)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TestOutput {
    events_sent: usize,
    events_received: Vec<usize>,
    receiver_names: Vec<String>,
}

impl fmt::Display for TestOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut events_recieved = 0;
        writeln!(f, "events sent: {}", self.events_sent)?;
        for (i, received) in self.events_received.iter().enumerate() {
            events_recieved += received;
            writeln!(f, "{} recv: {}", self.receiver_names[i], received)?;
        }
        let total_lost: usize = self.events_sent - events_recieved;
        let total_loss_pct = 100.0 - ((events_recieved as f64 / self.events_sent as f64) * 100.0);
        writeln!(
            f,
            "total recv: {} (lost {}, {:.3}%)",
            events_recieved, total_lost, total_loss_pct
        )?;
        Ok(())
    }
}

pub async fn run_test(
    url: String,
    config: TestConfig,
    ip_address: String,
    port: u16,
    meta_event_manager: &MetaEventManager,
) -> Result<TestOutput> {
    let TestConfig { sender, receivers } = config;
    let SenderConfig {
        rate: send_rate_hz,
        event_count,
        event_size,
    } = sender;
    let send_rate_micros = 1_000_000 / send_rate_hz;
    let mut parsed_url: EjfatUrl = url.parse().expect("Invalid EJFAT url");
    let mut control_plane_client = ControlPlaneClient::from_url(&url).await?;
    let reservation_reply = control_plane_client
        .reserve_load_balancer("test-runner".to_string(), None, vec![ip_address.clone()])
        .await?
        .into_inner();

    control_plane_client.lb_id = Some(reservation_reply.lb_id.clone());
    parsed_url.update_from_reservation(&reservation_reply);

    let mut tasks = vec![];
    let mut receiver_names = vec![];
    let mut current_port = port;
    let cancel_token = CancellationToken::new();

    for receiver_config in receivers {
        eprintln!("register {}", receiver_config.name);
        receiver_names.push(receiver_config.name.clone());
        let recv_event_context = meta_event_manager.create_context(receiver_config.name.clone());
        let mut receiver = Receiver::new(
            &receiver_config.name,
            ip_address.clone(),
            current_port,
            1.0,
            1500,
            1_073_741_824,
            receiver_config.kp,
            receiver_config.ki,
            receiver_config.kd,
            receiver_config.sp,
            receiver_config.min_factor,
            receiver_config.max_factor,
            0,
            &mut control_plane_client,
            recv_event_context,
        )
        .await?;

        let recv_event_context2 = meta_event_manager.create_context(receiver_config.name.clone());
        let receiver_rate_micros = 1_000_000 / receiver_config.rate;

        let cancel_token_child = cancel_token.clone();

        let task = tokio::spawn(async move {
            let mut count = 0;
            loop {
                tokio::select! {
                    // If a new event is received, process it normally.
                    event = receiver.rx.recv() => {
                        if let Some(event) = event {
                            count += 1;
                            // Simulate processing delay.
                            tokio::time::sleep(Duration::from_micros(receiver_rate_micros)).await;
                            if let Some(ref ctx) = recv_event_context2 {
                                ctx.emit(MetaEventType::Complete { tick: event.tick });
                            }
                        } else {
                            // The channel is closed.
                            break;
                        }
                    }
                    // Once cancellation is signaled (i.e. sender finished), drain any remaining events.
                    _ = cancel_token_child.cancelled() => {
                        // Drain the remaining queue without waiting for new events.
                        while let Ok(event) = receiver.rx.try_recv() {
                            count += 1;
                            tokio::time::sleep(Duration::from_micros(receiver_rate_micros)).await;
                            if let Some(ref ctx) = recv_event_context2 {
                                ctx.emit(MetaEventType::Complete { tick: event.tick });
                            }
                        }
                        break;
                    }
                }
            }
            count
        });
        tasks.push(task);
        current_port += 1;
    }

    // Allow an epoch to pass
    eprintln!("waiting for next epoch");
    tokio::time::sleep(Duration::from_millis(1000)).await;

    eprintln!("starting event processing");

    eprintln!("starting sender");
    // Start the sender task after receiver tasks have started
    let sender_event_context = meta_event_manager.create_context("S1");
    let mut sender_instance = Sender::from_url(&parsed_url, sender_event_context).await?;
    let cancel_token_cloned = cancel_token.clone();

    sender_instance
        .generate_test_stream(
            event_count,
            event_size,
            Duration::from_micros(send_rate_micros),
            cancel_token_cloned,
        )
        .await;

    cancel_token.cancel();
    let mut events_received = vec![0; tasks.len()];

    for (i, task) in tasks.into_iter().enumerate() {
        let received = task.await.unwrap();
        events_received[i] = received;
    }

    cancel_token.cancel();

    let _ = control_plane_client.free_load_balancer().await;

    Ok(TestOutput {
        events_sent: event_count,
        events_received,
        receiver_names,
    })
}

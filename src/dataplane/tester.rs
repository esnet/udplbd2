// SPDX-License-Identifier: BSD-3-Clause-LBNL
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::time::Duration;
use std::{fmt, sync::atomic::AtomicUsize};

use crate::api::client::{ControlPlaneClient, EjfatUrl};
use crate::dataplane::meta_events::{MetaEventManager, MetaEventType};
use crate::dataplane::receiver::Receiver;
use crate::dataplane::sender::Sender;
use crate::errors::Result;
use crate::proto::loadbalancer::v1::{IpFamily, SlotRange};

static COUNTER: AtomicUsize = AtomicUsize::new(1);
fn get_id() -> usize {
    COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Node configuration within a chain topology.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NodeConfig {
    /// Environment variable holding the EJFAT URI for this node's control plane.
    pub uri_env: String,
    /// Strategy for this node (e.g., "explicit", "round_robin").
    /// If not specified, defaults to the CLI-provided strategy.
    #[serde(default)]
    pub strategy: Option<String>,
}

/// Optional chain topology configuration.
///
/// `nodes` maps a logical node name to its configuration (URI environment variable and optional strategy).
/// If the named environment variable is not set, the resolved default URL (passed to [`run_test`])
/// is used as a fallback, so tests that chain multiple sessions on the same control plane can simply write
/// `{"A": {"uri_env": "EJFAT_URI"}, "B": {"uri_env": "EJFAT_URI"}}` without requiring the variable to be set
/// in the environment.
///
/// `edges` is a list of `(upstream, downstream)` pairs that describe which LBs should
/// be chained together.  The upstream LB will forward traffic to the downstream LB.
///
/// Example JSON:
/// ```json
/// {
///   "nodes": {
///     "A": {"uri_env": "EJFAT_URI_A", "strategy": "explicit"},
///     "B": {"uri_env": "EJFAT_URI_B", "strategy": "round_robin"}
///   },
///   "edges": [["A", "B"]]
/// }
/// ```
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChainConfig {
    /// Map from node name → node configuration.
    pub nodes: HashMap<String, NodeConfig>,
    /// Directed edges from upstream node name to downstream node name.
    pub edges: Vec<(String, String)>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TestConfig {
    /// Single sender (backward-compatible).  Mutually exclusive with `senders`.
    pub sender: Option<SenderConfig>,
    /// Multiple senders.  When present, takes precedence over `sender`.
    #[serde(default)]
    pub senders: Vec<SenderConfig>,
    pub receivers: Vec<ReceiverConfig>,
    /// Optional chain topology.  When absent the test behaves as a single-node test
    /// using the resolved default URL (the original behaviour).
    #[serde(default)]
    pub chain: Option<ChainConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SenderConfig {
    pub rate: u64,          // events per second
    pub event_count: usize, // Number of events
    pub event_size: usize,  // Size of events in bytes
    /// The chain node this sender should target.  Defaults to the single root node
    /// when there is exactly one; must be set explicitly when there are multiple.
    #[serde(default)]
    pub node: Option<String>,
    /// The `data_id` written into every LB packet header.  Defaults to `0`.
    #[serde(default)]
    pub data_id: u16,
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
    #[serde(default = "default_slot_demands")]
    pub slot_demands: Vec<SlotRange>,
    /// The chain node this receiver should register with.  Defaults to "default" for
    /// backward compatibility, or to the single leaf node when there is exactly one.
    #[serde(default)]
    pub node: Option<String>,
}

fn default_name() -> String {
    format!("node-{:03}", get_id())
}

fn default_sp() -> usize {
    5
}

fn default_slot_demands() -> Vec<SlotRange> {
    Vec::new()
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
            "total recv: {events_recieved} (lost {total_lost}, {total_loss_pct:.3}%)"
        )?;
        Ok(())
    }
}

/// Resolve the EJFAT URI for a node.
///
/// Reads the environment variable named by `envvar`.  If the variable is not set (or is
/// empty), `default_url` is returned instead.  This allows test configs that reference
/// `"EJFAT_URI"` (or any other variable) to work even when the variable is not present
/// in the environment, as long as the URL was already resolved through the normal udplbd
/// config machinery and passed in as `default_url`.
fn resolve_node_url(envvar: &str, default_url: &str) -> String {
    match std::env::var(envvar) {
        Ok(v) if !v.is_empty() => v,
        _ => default_url.to_string(),
    }
}

/// Run a dataplane test, optionally with a chain topology.
///
/// When `config.chain` is `None` a trivial single-node topology is synthesised using
/// the already-resolved `url` parameter (original behaviour).
///
/// When `config.chain` is `Some`, each node's EJFAT URI is resolved by reading the
/// environment variable named in `chain.nodes`; if that variable is not set the
/// already-resolved `url` is used as a fallback.
///
/// Multiple senders are supported via `config.senders`.  Each sender specifies the
/// chain node it should target (`sender.node`) and the `data_id` to embed in every
/// packet header.  All root nodes (nodes with no incoming edges) must have at least
/// one sender targeting them.
pub async fn run_test(
    url: String,
    config: TestConfig,
    ip_address: std::net::IpAddr,
    port: u16,
    meta_event_manager: &MetaEventManager,
    strategy: String,
) -> Result<TestOutput> {
    let TestConfig {
        sender,
        mut senders,
        receivers,
        chain,
    } = config;

    // Normalise: if only the singular `sender` field is set, promote it.
    if senders.is_empty() {
        if let Some(s) = sender {
            senders.push(s);
        }
    }

    if senders.is_empty() {
        return Err(crate::errors::Error::Runtime(
            "TestConfig must have at least one sender".to_string(),
        ));
    }

    let ip_family = match ip_address {
        std::net::IpAddr::V4(_) => IpFamily::Ipv4,
        std::net::IpAddr::V6(_) => IpFamily::Ipv6,
    };

    // ── Build the effective chain config ──────────────────────────────────────
    let chain_config = chain.unwrap_or_else(|| {
        // Single-node fallback: one node named "default" whose URI is the resolved `url`.
        let mut nodes = HashMap::new();
        nodes.insert(
            "default".to_string(),
            NodeConfig {
                uri_env: "EJFAT_URI".to_string(),
                strategy: None,
            },
        );
        ChainConfig {
            nodes,
            edges: vec![],
        }
    });

    // ── 1. Reserve a load balancer for every node ─────────────────────────────
    // node_name → (client, parsed_url, lb_id)
    let mut node_clients: HashMap<String, (ControlPlaneClient, EjfatUrl, String)> = HashMap::new();

    for (node_name, node_cfg) in &chain_config.nodes {
        let node_url = resolve_node_url(&node_cfg.uri_env, &url);
        let node_strategy = node_cfg
            .strategy
            .clone()
            .unwrap_or_else(|| strategy.clone());

        eprintln!("reserving LB for node '{}'", node_name);
        let reserve_result: crate::errors::Result<_> = async {
            let mut client = ControlPlaneClient::from_url(&node_url).await?;
            let reservation_reply = client
                .reserve_load_balancer(
                    format!("test-runner-{}", node_name),
                    None,
                    vec![ip_address.to_string()],
                    ip_family,
                    node_strategy,
                )
                .await?
                .into_inner();
            Ok((client, reservation_reply))
        }
        .await;

        match reserve_result {
            Ok((mut client, reservation_reply)) => {
                let lb_id = reservation_reply.lb_id.clone();
                client.lb_id = Some(lb_id.clone());

                let mut parsed_url: EjfatUrl = node_url.parse().expect("Invalid EJFAT url");
                parsed_url.update_from_reservation(&reservation_reply);

                eprintln!("node '{}' reserved: lb_id={}", node_name, lb_id);
                node_clients.insert(node_name.clone(), (client, parsed_url, lb_id));
            }
            Err(e) => {
                // Free any LBs that were already reserved before returning the error.
                for (failed_node, (mut c, _, _)) in node_clients {
                    eprintln!("freeing LB for node '{}' (reservation failed)", failed_node);
                    let _ = c.free_load_balancer().await;
                }
                return Err(e);
            }
        }
    }

    // Run the rest of the test and always clean up reservations afterwards,
    // regardless of whether the inner logic succeeds or fails.
    let cancel_token = CancellationToken::new();
    let result = run_test_inner(
        &chain_config,
        &mut node_clients,
        senders,
        receivers,
        ip_address,
        ip_family,
        port,
        meta_event_manager,
        cancel_token,
    )
    .await;

    // ── Cleanup: always unchain and free, even on error ───────────────────────
    // Collect chain_ids from the result (they are returned alongside the output).
    let (chain_ids, inner_result) = match result {
        Ok((chain_ids, output)) => (chain_ids, Ok(output)),
        Err((chain_ids, e)) => (chain_ids, Err(e)),
    };

    // ── 7. Unchain edges ──────────────────────────────────────────────────────
    for (downstream_name, chain_id) in chain_ids {
        let (client_b, _, lb_b_id) = node_clients
            .get_mut(&downstream_name)
            .expect("downstream node not found during cleanup");
        eprintln!(
            "unchaining downstream '{}' (chain_id={})",
            downstream_name, chain_id
        );
        let _ = client_b
            .unchain_load_balancer(lb_b_id.clone(), chain_id)
            .await;
    }

    // ── 8. Free all load balancers ────────────────────────────────────────────
    for (node_name, (mut client, _, _)) in node_clients {
        eprintln!("freeing LB for node '{}'", node_name);
        let _ = client.free_load_balancer().await;
    }

    inner_result
}

/// Inner test logic that runs after all LBs are reserved.
///
/// Returns `Ok((chain_ids, output))` on success, or `Err((chain_ids, error))` on failure.
/// In both cases the accumulated `chain_ids` are returned so the caller can always unchain
/// any edges that were established before the failure.
#[allow(clippy::too_many_arguments)]
async fn run_test_inner(
    chain_config: &ChainConfig,
    node_clients: &mut HashMap<String, (ControlPlaneClient, EjfatUrl, String)>,
    senders: Vec<SenderConfig>,
    receivers: Vec<ReceiverConfig>,
    ip_address: std::net::IpAddr,
    ip_family: IpFamily,
    port: u16,
    meta_event_manager: &MetaEventManager,
    cancel_token: CancellationToken,
) -> std::result::Result<
    (Vec<(String, String)>, TestOutput),
    (Vec<(String, String)>, crate::errors::Error),
> {
    let mut chain_ids: Vec<(String, String)> = Vec::new();

    // Wrap the fallible logic so we can always return chain_ids alongside any error.
    let result: crate::errors::Result<TestOutput> = async {
        // ── 2. Establish chain edges ──────────────────────────────────────────────
        for (upstream_name, downstream_name) in &chain_config.edges {
            let upstream_url = node_clients
                .get(upstream_name)
                .map(|(_, u, _)| u.to_string())
                .unwrap_or_else(|| {
                    panic!("edge references unknown upstream node '{}'", upstream_name)
                });

            let (client_b, _, lb_b_id) =
                node_clients.get_mut(downstream_name).unwrap_or_else(|| {
                    panic!(
                        "edge references unknown downstream node '{}'",
                        downstream_name
                    )
                });

            eprintln!(
                "chaining '{}' → '{}' (lb_id={})",
                upstream_name, downstream_name, lb_b_id
            );

            let reply = client_b
                .chain_load_balancer(
                    lb_b_id.clone(),
                    upstream_url,
                    ip_family,
                    1.0,
                    0.5,
                    2.0,
                    vec![],
                )
                .await
                .map_err(|e| {
                    crate::errors::Error::Runtime(format!(
                        "chain_load_balancer '{}' → '{}' failed: {}",
                        upstream_name, downstream_name, e
                    ))
                })?
                .into_inner();

            eprintln!(
                "chain '{}' → '{}' established: chain_id={}",
                upstream_name, downstream_name, reply.chain_id
            );
            chain_ids.push((downstream_name.clone(), reply.chain_id));
        }

        // ── 3. Determine root and leaf nodes ──────────────────────────────────────
        let upstream_set: std::collections::HashSet<&String> =
            chain_config.edges.iter().map(|(u, _)| u).collect();
        let downstream_set: std::collections::HashSet<&String> =
            chain_config.edges.iter().map(|(_, d)| d).collect();

        // Root nodes: not a downstream of any edge.
        let root_nodes: Vec<&String> = chain_config
            .nodes
            .keys()
            .filter(|n| !downstream_set.contains(n))
            .collect();

        // Leaf nodes: not an upstream of any edge.
        let leaf_nodes: Vec<&String> = chain_config
            .nodes
            .keys()
            .filter(|n| !upstream_set.contains(n))
            .collect();

        // ── 4. Resolve sender target nodes and validate ───────────────────────────
        // Each sender must specify a target node.  When there is exactly one root node
        // and the sender does not specify a node, default to that root.
        let resolved_senders: Vec<(SenderConfig, String)> = senders
            .into_iter()
            .map(|s| {
                let target = match s.node.clone() {
                    Some(n) => {
                        if !chain_config.nodes.contains_key(&n) {
                            panic!("sender targets unknown node '{}'", n);
                        }
                        n
                    }
                    None => {
                        if root_nodes.len() == 1 {
                            root_nodes[0].clone()
                        } else {
                            panic!(
                                "sender.node must be set explicitly when there are {} root nodes",
                                root_nodes.len()
                            );
                        }
                    }
                };
                (s, target)
            })
            .collect();

        // Validate: every root node must have at least one sender.
        for root in &root_nodes {
            if !resolved_senders.iter().any(|(_, t)| t == *root) {
                return Err(crate::errors::Error::Runtime(format!(
                    "root node '{}' has no sender assigned",
                    root
                )));
            }
        }

        // Total events sent = sum across all senders.
        let total_events_sent: usize = resolved_senders.iter().map(|(s, _)| s.event_count).sum();

        eprintln!(
            "receivers will be registered on leaf nodes: {:?}",
            leaf_nodes
        );

        // ── 5. Register receivers on leaf nodes ───────────────────────────────────
        let mut tasks = vec![];
        let mut receiver_names = vec![];

        for (current_port, receiver_config) in (port..).zip(receivers) {
            // Determine which node this receiver should register with.
            let target_node_name = match &receiver_config.node {
                Some(n) => {
                    // Explicit node selection
                    if !chain_config.nodes.contains_key(n) {
                        return Err(crate::errors::Error::Runtime(format!(
                            "receiver '{}' targets unknown node '{}'",
                            receiver_config.name, n
                        )));
                    }
                    n.clone()
                }
                None => {
                    // Default: use leaf nodes (round-robin if multiple)
                    let leaf_idx = tasks.len() % leaf_nodes.len();
                    leaf_nodes[leaf_idx].clone()
                }
            };

            eprintln!(
                "register {} on node '{}'",
                receiver_config.name, target_node_name
            );
            receiver_names.push(receiver_config.name.clone());

            let recv_event_context =
                meta_event_manager.create_context(receiver_config.name.clone());

            let (leaf_client, _, _) = node_clients
                .get_mut(&target_node_name)
                .expect("target node not found");

            let mut receiver = Receiver::new(
                &receiver_config.name,
                ip_address.to_string(),
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
                leaf_client,
                recv_event_context,
                receiver_config.slot_demands,
            )
            .await?;

            let recv_event_context2 =
                meta_event_manager.create_context(receiver_config.name.clone());
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
        }

        // Allow an epoch to pass (and chain propagation time)
        eprintln!("waiting for next epoch");
        tokio::time::sleep(Duration::from_millis(1000)).await;

        eprintln!("starting event processing");

        // ── 6. Launch all senders concurrently ───────────────────────────────────
        // All senders run in parallel; we wait for all of them to finish before
        // cancelling the receivers.
        let mut sender_handles = vec![];

        for (sender_cfg, target_node) in resolved_senders {
            let (_, sender_url, _) = node_clients
                .get(&target_node)
                .expect("sender target node not found");
            let sender_url = sender_url.clone();

            let send_rate_micros = 1_000_000 / sender_cfg.rate;
            let event_count = sender_cfg.event_count;
            let event_size = sender_cfg.event_size;
            let data_id = sender_cfg.data_id;
            let is_ipv6 = ip_address.is_ipv6();

            let sender_event_context =
                meta_event_manager.create_context(format!("sender-{}", target_node));
            let cancel_token_cloned = cancel_token.clone();

            eprintln!("starting sender → node '{}'", target_node);

            let handle = tokio::spawn(async move {
                let mut sender_instance =
                    Sender::from_url(&sender_url, sender_event_context, is_ipv6)
                        .await
                        .expect("failed to create sender");

                let mut i: usize = 0;
                loop {
                    let test_data = vec![0xDA_u8; event_size];
                    tokio::select! {
                        _ = sender_instance.send_ts(&test_data, data_id) => {
                            i += 1;
                            if event_count != 0 && i >= event_count {
                                break;
                            }
                            tokio::time::sleep(Duration::from_micros(send_rate_micros)).await;
                        }
                        _ = cancel_token_cloned.cancelled() => {
                            break;
                        }
                    }
                }
            });
            sender_handles.push(handle);
        }

        // Wait for all senders to finish.
        for handle in sender_handles {
            handle.await.unwrap();
        }

        cancel_token.cancel();
        let mut events_received = vec![0; tasks.len()];

        for (i, task) in tasks.into_iter().enumerate() {
            let received = task.await.unwrap();
            events_received[i] = received;
        }

        Ok(TestOutput {
            events_sent: total_events_sent,
            events_received,
            receiver_names,
        })
    }
    .await;

    match result {
        Ok(output) => Ok((chain_ids, output)),
        Err(e) => Err((chain_ids, e)),
    }
}

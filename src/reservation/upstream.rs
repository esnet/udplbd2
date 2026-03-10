// SPDX-License-Identifier: BSD-3-Clause-LBNL
//! Background task for sending aggregated SendState updates to upstream control planes.

use crate::api::client::{BearerInterceptor, ControlPlaneClient};
use crate::db::models::UpstreamChain;
use crate::db::LoadBalancerDB;
use crate::errors::Result;
use crate::proto::loadbalancer::v1::load_balancer_client::LoadBalancerClient;
use std::collections::HashMap;
use std::sync::Arc;
use tonic::transport::{Channel, ClientTlsConfig};
use tracing::{error, trace, warn};

/// Aggregated state for a reservation, computed once and sent to all upstream chains.
struct AggregatedState {
    is_ready: bool,
    fill_percent: f32,
    control_signal: f32,
    total_events_recv: i64,
    total_events_reassembled: i64,
    total_events_reassembly_err: i64,
    total_events_dequeued: i64,
    total_event_enqueue_err: i64,
    total_bytes_recv: i64,
    total_packets_recv: i64,
}

/// Creates a ControlPlaneClient for an upstream chain.
async fn create_upstream_client(chain: &UpstreamChain) -> Result<ControlPlaneClient> {
    let channel = if chain.upstream_tls_enabled {
        let tls_config = ClientTlsConfig::new().with_enabled_roots();
        Channel::from_shared(format!(
            "https://{}:{}",
            chain.upstream_grpc_host, chain.upstream_grpc_port
        ))
        .map_err(|e| crate::errors::Error::Network(e.to_string()))?
        .tls_config(tls_config)?
        .connect()
        .await?
    } else {
        Channel::from_shared(format!(
            "http://{}:{}",
            chain.upstream_grpc_host, chain.upstream_grpc_port
        ))
        .map_err(|e| crate::errors::Error::Network(e.to_string()))?
        .connect()
        .await?
    };
    let bearer_interceptor = BearerInterceptor {
        token: chain.upstream_session_token.clone(),
    };
    let client = LoadBalancerClient::with_interceptor(channel, bearer_interceptor);
    Ok(ControlPlaneClient::new(
        client,
        Some(chain.upstream_lb_id.clone()),
        Some(chain.upstream_session_id.clone()),
    ))
}

/// Deregisters from an upstream control plane. Used by UnchainLoadBalancer and auto-deregister on free.
pub async fn deregister_upstream(chain: &UpstreamChain) -> Result<()> {
    let mut client = create_upstream_client(chain).await?;
    client.deregister().await?;
    Ok(())
}

/// Computes the aggregated state for a reservation by averaging across all sessions.
async fn compute_aggregated_state(
    db: &LoadBalancerDB,
    reservation_id: i64,
) -> Result<AggregatedState> {
    let sessions = db.get_reservation_sessions(reservation_id).await?;

    let mut total_fill_percent: f64 = 0.0;
    let mut total_control_signal: f64 = 0.0;
    let mut count: usize = 0;
    let mut any_ready = false;
    let mut sum_events_recv: i64 = 0;
    let mut sum_events_reassembled: i64 = 0;
    let mut sum_events_reassembly_err: i64 = 0;
    let mut sum_events_dequeued: i64 = 0;
    let mut sum_event_enqueue_err: i64 = 0;
    let mut sum_bytes_recv: i64 = 0;
    let mut sum_packets_recv: i64 = 0;

    for session in &sessions {
        if let Ok(Some(state)) = db.get_latest_session_state(session.id).await {
            count += 1;
            total_fill_percent += state.fill_percent;
            total_control_signal += state.control_signal;
            if state.is_ready {
                any_ready = true;
            }
            sum_events_recv += state.total_events_recv as i64;
            sum_events_reassembled += state.total_events_reassembled as i64;
            sum_events_reassembly_err += state.total_events_reassembly_err as i64;
            sum_events_dequeued += state.total_events_dequeued as i64;
            sum_event_enqueue_err += state.total_event_enqueue_err as i64;
            sum_bytes_recv += state.total_bytes_recv as i64;
            sum_packets_recv += state.total_packets_recv as i64;
        }
    }

    let is_ready = !sessions.is_empty() && any_ready;
    let avg_fill_percent = if count > 0 {
        (total_fill_percent / count as f64) as f32
    } else {
        0.0
    };
    let avg_control_signal = if count > 0 {
        (total_control_signal / count as f64) as f32
    } else {
        0.0
    };

    Ok(AggregatedState {
        is_ready,
        fill_percent: avg_fill_percent,
        control_signal: avg_control_signal,
        total_events_recv: sum_events_recv,
        total_events_reassembled: sum_events_reassembled,
        total_events_reassembly_err: sum_events_reassembly_err,
        total_events_dequeued: sum_events_dequeued,
        total_event_enqueue_err: sum_event_enqueue_err,
        total_bytes_recv: sum_bytes_recv,
        total_packets_recv: sum_packets_recv,
    })
}

/// Cache key that captures the connection-relevant fields of an upstream chain.
/// If any of these change, we need to create a new client.
#[derive(Clone, PartialEq, Eq)]
struct ChainCacheKey {
    upstream_grpc_host: String,
    upstream_grpc_port: u16,
    upstream_tls_enabled: bool,
    upstream_session_token: String,
    upstream_lb_id: String,
    upstream_session_id: String,
}

impl ChainCacheKey {
    fn from_chain(chain: &UpstreamChain) -> Self {
        Self {
            upstream_grpc_host: chain.upstream_grpc_host.clone(),
            upstream_grpc_port: chain.upstream_grpc_port,
            upstream_tls_enabled: chain.upstream_tls_enabled,
            upstream_session_token: chain.upstream_session_token.clone(),
            upstream_lb_id: chain.upstream_lb_id.clone(),
            upstream_session_id: chain.upstream_session_id.clone(),
        }
    }
}

struct CachedClient {
    key: ChainCacheKey,
    client: ControlPlaneClient,
}

/// Starts the background task that periodically sends aggregated SendState to all upstream chains.
pub fn start_upstream_send_state(db: Arc<LoadBalancerDB>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(100));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Cache of clients keyed by chain ID. Invalidated when chain config changes or on error.
        let mut client_cache: HashMap<i64, CachedClient> = HashMap::new();

        loop {
            interval.tick().await;

            let chains = match db.list_active_upstream_chains().await {
                Ok(chains) => chains,
                Err(e) => {
                    error!("upstream_send_state: failed to list chains: {}", e);
                    continue;
                }
            };

            if chains.is_empty() {
                // Remove all cached clients when there are no active chains
                client_cache.clear();
                continue;
            }

            // Remove cached clients for chains that no longer exist
            let active_chain_ids: std::collections::HashSet<i64> =
                chains.iter().map(|c| c.id).collect();
            client_cache.retain(|id, _| active_chain_ids.contains(id));

            // Group chains by reservation_id so we compute aggregate once per reservation
            let mut chains_by_reservation: HashMap<i64, Vec<&UpstreamChain>> = HashMap::new();
            for chain in &chains {
                chains_by_reservation
                    .entry(chain.reservation_id)
                    .or_default()
                    .push(chain);
            }

            for (reservation_id, reservation_chains) in &chains_by_reservation {
                let state = match compute_aggregated_state(&db, *reservation_id).await {
                    Ok(state) => state,
                    Err(e) => {
                        warn!(
                            "upstream_send_state: failed to compute state for reservation {}: {}",
                            reservation_id, e
                        );
                        continue;
                    }
                };

                for chain in reservation_chains {
                    let cache_key = ChainCacheKey::from_chain(chain);

                    // Check if we have a cached client with matching config
                    let needs_new_client = match client_cache.get(&chain.id) {
                        Some(cached) => cached.key != cache_key,
                        None => true,
                    };

                    if needs_new_client {
                        match create_upstream_client(chain).await {
                            Ok(client) => {
                                client_cache.insert(
                                    chain.id,
                                    CachedClient {
                                        key: cache_key,
                                        client,
                                    },
                                );
                            }
                            Err(e) => {
                                warn!(
                                    "upstream_send_state: failed to connect to upstream for chain {}: {}",
                                    chain.id, e
                                );
                                continue;
                            }
                        }
                    }

                    let cached = client_cache.get_mut(&chain.id).unwrap();
                    if let Err(e) = cached
                        .client
                        .send_state(
                            state.fill_percent,
                            state.control_signal,
                            state.is_ready,
                            state.total_events_recv,
                            state.total_events_reassembled,
                            state.total_events_reassembly_err,
                            state.total_events_dequeued,
                            state.total_event_enqueue_err,
                            state.total_bytes_recv,
                            state.total_packets_recv,
                        )
                        .await
                    {
                        warn!(
                            "upstream_send_state: send failed for chain {} (reservation {}): {}",
                            chain.id, chain.reservation_id, e
                        );
                        // Remove the cached client so we reconnect on the next tick
                        client_cache.remove(&chain.id);
                    } else {
                        trace!(
                            "upstream_send_state: chain={}, reservation={}, is_ready={}, fill={:.2}%",
                            chain.id,
                            chain.reservation_id,
                            state.is_ready,
                            state.fill_percent * 100.0
                        );
                    }
                }
            }
        }
    });
}

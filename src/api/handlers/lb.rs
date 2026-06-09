// SPDX-License-Identifier: BSD-3-Clause-LBNL
/// API handlers for functions related to reserving, querying, freeing LBs
use chrono::{Duration, TimeZone, Utc};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::SystemTime;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use super::super::service::LoadBalancerService;
use crate::api::client::EjfatUrl;
use crate::api::client::{BearerInterceptor, ControlPlaneClient};
use crate::db::models::{Permission, PermissionType, Resource};
use crate::proto::loadbalancer::v1::{
    load_balancer_client::LoadBalancerClient, AddSendersReply, AddSendersRequest, ChainGraphEdge,
    ChainLoadBalancerReply, ChainLoadBalancerRequest, ExtendReservationReply,
    ExtendReservationRequest, FreeLoadBalancerReply, FreeLoadBalancerRequest, GetChainGraphReply,
    GetChainGraphRequest, GetLoadBalancerRequest, IpFamily, LoadBalancerStatusReply,
    LoadBalancerStatusRequest, PortRange, RemoveSendersReply, RemoveSendersRequest,
    ReserveLoadBalancerReply, ReserveLoadBalancerRequest, ResetLoadBalancerReply,
    ResetLoadBalancerRequest, SlotRange, UnchainLoadBalancerReply, UnchainLoadBalancerRequest,
    WorkerStatus,
};
use crate::util::is_valid_name;
use tonic::transport::{Channel, ClientTlsConfig};

impl LoadBalancerService {
    pub(crate) async fn handle_reserve_load_balancer(
        &self,
        request: Request<ReserveLoadBalancerRequest>,
    ) -> Result<Response<ReserveLoadBalancerReply>, Status> {
        let token = Self::extract_token(request.metadata())?;
        let remote_addr = request.remote_addr();
        let grpc_authority = request
            .extensions()
            .get::<crate::api::GrpcAuthority>()
            .cloned();
        let request = request.into_inner();

        let all_lbs = self
            .db
            .list_loadbalancers()
            .await
            .map_err(|e| Status::internal(format!("Failed to list load balancers: {e}")))?;

        let mut has_permission_to_any = false;
        let mut available_lb = None;
        let mut token_id: Option<i64> = None;

        for lb in all_lbs {
            let (ok, found_token_id) = self
                .validate_token(
                    &token,
                    Resource::LoadBalancer(lb.id),
                    PermissionType::Reserve,
                )
                .await?;
            if !ok {
                continue;
            } else {
                token_id = found_token_id;
            }

            has_permission_to_any = true;

            let existing_reservation = sqlx::query!(
                r#"
                SELECT id
                FROM reservation
                WHERE loadbalancer_id = ?1
                AND deleted_at IS NULL
                AND reserved_until > unixepoch('subsec') * 1000
                "#,
                lb.id
            )
            .fetch_optional(&self.db.read_pool)
            .await
            .map_err(|e| Status::internal(format!("Failed to check reservations: {e}")))?;

            if existing_reservation.is_none() {
                available_lb = Some(lb);
                break;
            }
        }

        if !has_permission_to_any {
            let src = remote_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            warn!(
                "reserve_load_balancer: permission denied (no permission to reserve any load balancers). source={}",
                src
            );
            return Err(Status::permission_denied(
                "No permission to reserve any load balancers",
            ));
        }

        let lb = available_lb.ok_or_else(|| {
            let src = remote_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            warn!(
                "reserve_load_balancer: failed - all accessible load balancers reserved. source={}",
                src
            );
            Status::resource_exhausted("All accessible load balancers are currently reserved")
        })?;

        if !is_valid_name(&request.name) {
            return Err(Status::invalid_argument("Name must contain only alphanumeric characters plus '.' ':' '/' '_' '-', and two periods may not follow each other"));
        }

        let duration = match request.until {
            Some(ts) => {
                let expiry = Utc
                    .timestamp_opt(ts.seconds, ts.nanos as u32)
                    .single()
                    .ok_or_else(|| Status::invalid_argument("Invalid expiration timestamp"))?;
                let now = Utc::now();
                expiry.signed_duration_since(now).to_std().map_err(|_| {
                    Status::invalid_argument("Expiration time must be in the future")
                })?
            }
            None => Duration::days(365).to_std().unwrap(), // Default to 1 year
        };

        // Determine strategy
        let strategy = if request.strategy.is_empty() {
            "dynamic".to_string()
        } else {
            request.strategy.clone()
        };

        let reservation = self
            .db
            .create_reservation_with_strategy(
                lb.id,
                &request.name,
                chrono::Duration::from_std(duration).unwrap(),
                &strategy,
            )
            .await
            .map_err(|e| Status::internal(format!("Failed to create reservation: {e}")))?;

        // Seed sync with our own UNIX time
        let now = Utc::now();
        let unix_time_micros = now.timestamp_micros();
        let event_rate_hz: i32 = 1_000_000;
        self.db
            .create_event_number(reservation.id, unix_time_micros, event_rate_hz, now, now)
            .await
            .map_err(|e| Status::internal(format!("Failed to create initial sync data: {e}")))?;

        let initial_senders = request.sender_addresses.clone();
        for addr_str in &request.sender_addresses {
            let addr = IpAddr::from_str(addr_str)
                .map_err(|_| Status::invalid_argument("Invalid sender IP address"))?;
            self.db
                .add_sender(reservation.id, addr)
                .await
                .map_err(|e| Status::internal(format!("Failed to add sender: {e}")))?;
        }
        let src = remote_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        info!(
            "reserve_load_balancer: reservation_id={}, initial_senders={:?}, token_id={:?}, source={}",
            reservation.id, initial_senders, token_id, src
        );

        let new_token_name = format!("reservation-{}", reservation.id);
        let token = self
            .db
            .create_token(
                new_token_name.as_str(),
                Some(token.as_str()),
                vec![Permission {
                    resource: Resource::Reservation(reservation.id),
                    permission: PermissionType::Update,
                }],
            )
            .await
            .map_err(|e| Status::internal(format!("Failed to create token: {e}")))?;

        let mut manager = self.manager.lock().await;

        crate::snp4::metrics_collector::clear_lb_stats(&mut manager.snp4, lb.fpga_lb_id as u32)
            .await;

        manager
            .start_reservation(reservation.id, lb.event_number_udp_port)
            .await
            .map_err(|_| {
                Status::internal(format!(
                    "Failed to start reservation server on port {}",
                    lb.event_number_udp_port
                ))
            })?;

        // Resolve data addresses: in mock mode, use address_map mappings if available
        let address_map = self.config.mock.as_ref().map(|m| &m.address_map);

        let (data_ipv4_address, mapped_v4_port) = match lb.unicast_ipv4_address {
            Some(ip) if self.mock_mode => match address_map.and_then(|m| m.get(&IpAddr::V4(ip))) {
                Some(mapped) => (mapped.ip().to_string(), Some(mapped.port())),
                None => (ip.to_string(), None),
            },
            Some(ip) => (ip.to_string(), None),
            None => (String::new(), None),
        };

        let (data_ipv6_address, mapped_v6_port) = match lb.unicast_ipv6_address {
            Some(ip) if self.mock_mode => match address_map.and_then(|m| m.get(&IpAddr::V6(ip))) {
                Some(mapped) => (mapped.ip().to_string(), Some(mapped.port())),
                None => (ip.to_string(), None),
            },
            Some(ip) => (ip.to_string(), None),
            None => (String::new(), None),
        };

        let (data_min_port, data_max_port) = if self.mock_mode {
            let port = mapped_v4_port.or(mapped_v6_port).unwrap_or(19522) as u32;
            (port, port)
        } else {
            (16384, 32767)
        };

        let sync_ipv4_address = manager
            .sync_addr_v4
            .map(|ip| ip.ip().to_string())
            .unwrap_or_default();
        let sync_ipv6_address = manager
            .sync_addr_v6
            .map(|ip| ip.ip().to_string())
            .unwrap_or_default();
        let sync_udp_port = u32::from(lb.event_number_udp_port);
        let lb_id = reservation.id.to_string();

        // Parse the gRPC authority (host:port) for the EJFAT URI
        let (grpc_host, grpc_port) = match &grpc_authority {
            Some(auth) => {
                if let Some(idx) = auth.0.rfind(':') {
                    (
                        auth.0[..idx].to_string(),
                        auth.0[idx + 1..].parse::<u16>().ok(),
                    )
                } else {
                    (auth.0.clone(), None)
                }
            }
            None => {
                let listen = &self.config.server.listen[0];
                (listen.ip().to_string(), Some(listen.port()))
            }
        };

        let ejfat_url = EjfatUrl {
            token: Some(token.clone()),
            grpc_host,
            grpc_port,
            lb_id: Some(lb_id.clone()),
            sync_addr_v4: if sync_ipv4_address.is_empty() {
                None
            } else {
                Some(sync_ipv4_address.clone())
            },
            sync_addr_v6: if sync_ipv6_address.is_empty() {
                None
            } else {
                Some(sync_ipv6_address.clone())
            },
            sync_udp_port: Some(sync_udp_port as u16),
            data_addr_v4: if data_ipv4_address.is_empty() {
                None
            } else {
                Some(data_ipv4_address.clone())
            },
            data_addr_v6: if data_ipv6_address.is_empty() {
                None
            } else {
                Some(data_ipv6_address.clone())
            },
            data_min_port: data_min_port as u16,
            data_max_port: data_max_port as u16,
            tls_enabled: self.config.server.tls.enable,
        };

        Ok(Response::new(ReserveLoadBalancerReply {
            token,
            lb_id,
            sync_ipv4_address,
            sync_ipv6_address,
            sync_udp_port,
            data_ipv4_address,
            data_ipv6_address,
            fpga_lb_id: lb.fpga_lb_id as u32,
            data_min_port,
            data_max_port,
            strategy: reservation.strategy,
            ejfat_uri: ejfat_url.to_string(),
        }))
    }

    pub(crate) async fn handle_get_load_balancer(
        &self,
        request: Request<GetLoadBalancerRequest>,
    ) -> Result<Response<ReserveLoadBalancerReply>, Status> {
        let token = Self::extract_token(request.metadata())?;
        let remote_addr = request.remote_addr();
        let request = request.into_inner();
        let reservation_id = request
            .lb_id
            .parse::<i64>()
            .map_err(|_| Status::invalid_argument("Invalid load balancer ID"))?;

        let (ok, token_id) = self
            .validate_token(
                &token,
                Resource::Reservation(reservation_id),
                PermissionType::ReadOnly,
            )
            .await?;
        if !ok {
            let src = remote_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            warn!(
                "get_load_balancer: permission denied. reservation_id={}, token_id={}, source={}",
                reservation_id,
                token_id.unwrap_or(-1),
                src
            );
            return Err(Status::permission_denied("Permission denied"));
        }

        let reservation = self
            .db
            .get_reservation(reservation_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get reservation: {e}")))?;

        let lb = self
            .db
            .get_loadbalancer(reservation.loadbalancer_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get load balancer: {e}")))?;

        // Resolve data addresses: in mock mode, use address_map mappings if available
        let address_map = self.config.mock.as_ref().map(|m| &m.address_map);

        let (data_ipv4_address, mapped_v4_port) = match lb.unicast_ipv4_address {
            Some(ip) if self.mock_mode => match address_map.and_then(|m| m.get(&IpAddr::V4(ip))) {
                Some(mapped) => (mapped.ip().to_string(), Some(mapped.port())),
                None => (ip.to_string(), None),
            },
            Some(ip) => (ip.to_string(), None),
            None => (String::new(), None),
        };

        let (data_ipv6_address, mapped_v6_port) = match lb.unicast_ipv6_address {
            Some(ip) if self.mock_mode => match address_map.and_then(|m| m.get(&IpAddr::V6(ip))) {
                Some(mapped) => (mapped.ip().to_string(), Some(mapped.port())),
                None => (ip.to_string(), None),
            },
            Some(ip) => (ip.to_string(), None),
            None => (String::new(), None),
        };

        let (data_min_port, data_max_port) = if self.mock_mode {
            let port = mapped_v4_port.or(mapped_v6_port).unwrap_or(19522) as u32;
            (port, port)
        } else {
            (16384, 32767)
        };

        let manager = self.manager.lock().await;

        Ok(Response::new(ReserveLoadBalancerReply {
            token: String::new(), // No token for get operations
            lb_id: reservation.id.to_string(),
            sync_ipv4_address: manager
                .sync_addr_v4
                .map(|ip| ip.ip().to_string())
                .unwrap_or_default(),
            sync_ipv6_address: manager
                .sync_addr_v6
                .map(|ip| ip.ip().to_string())
                .unwrap_or_default(),
            sync_udp_port: u32::from(lb.event_number_udp_port),
            data_ipv4_address,
            data_ipv6_address,
            fpga_lb_id: lb.fpga_lb_id as u32,
            data_min_port,
            data_max_port,
            strategy: if reservation.strategy.is_empty() {
                "dynamic".to_string()
            } else {
                reservation.strategy.clone()
            },
            ejfat_uri: String::new(),
        }))
    }

    pub(crate) async fn handle_load_balancer_status(
        &self,
        request: Request<LoadBalancerStatusRequest>,
    ) -> Result<Response<LoadBalancerStatusReply>, Status> {
        let token = Self::extract_token(request.metadata())?;
        let remote_addr = request.remote_addr();
        let request = request.into_inner();
        let reservation_id = request
            .lb_id
            .parse::<i64>()
            .map_err(|_| Status::invalid_argument("Invalid load balancer ID"))?;

        let (ok, token_id) = self
            .validate_token(
                &token,
                Resource::Reservation(reservation_id),
                PermissionType::ReadOnly,
            )
            .await?;
        if !ok {
            let src = remote_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            warn!(
                "load_balancer_status: permission denied. reservation_id={}, token_id={}, source={}",
                reservation_id, token_id.unwrap_or(-1), src
            );
            return Err(Status::permission_denied("Permission denied"));
        }

        let reservation = self
            .db
            .get_reservation(reservation_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get reservation: {e}")))?;

        let sessions = self
            .db
            .get_reservation_sessions(reservation_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get sessions: {e}")))?;

        let senders = self
            .db
            .get_reservation_senders(reservation_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get senders: {e}")))?;

        // Try to get the latest epoch; if it fails, use 0/defaults
        let (current_epoch, current_predicted_event_number, slot_counts, epoch_slots) =
            match self.db.get_latest_epoch(reservation_id).await {
                Ok(latest_epoch) => {
                    let mut slot_counts = HashMap::new();
                    for &slot in &latest_epoch.slots {
                        *slot_counts.entry(slot).or_insert(0) += 1;
                    }
                    (
                        latest_epoch.id as u64,
                        latest_epoch.boundary_event,
                        slot_counts,
                        latest_epoch.slots,
                    )
                }
                Err(_) => (0, 0, HashMap::new(), Vec::new()),
            };

        let mut workers = Vec::new();

        for session in sessions {
            let state = self
                .db
                .get_latest_session_state(session.id)
                .await
                .map_err(|e| Status::internal(format!("Failed to get session state: {e}")))?;

            let slots_assigned = slot_counts.get(&(session.id as u16)).unwrap_or(&0);

            // Fetch health issues for this session (all active issues)
            let session_health_issues =
                self.db
                    .list_session_healthcheck_events(session.id)
                    .await
                    .map_err(|e| Status::internal(format!("Failed to get health issues: {e}")))?;

            let health_issues = session_health_issues
                .into_iter()
                .map(|event| {
                    use crate::proto::loadbalancer::v1::HealthIssue;
                    HealthIssue {
                        r#type: event.event_type,
                        severity: event.severity.as_str().to_string(),
                        message: event.message,
                        details: event
                            .details
                            .as_ref()
                            .and_then(|d| serde_json::from_str(d).ok()),
                        detected_at: Some(prost_wkt_types::Timestamp::from(SystemTime::from(
                            event.detected_at,
                        ))),
                    }
                })
                .collect();

            // Fetch slot demands for this session from the database
            let demands = sqlx::query!(
                "SELECT slot_index, slot_length FROM slot_demand WHERE session_id = ?1 AND deleted_at IS NULL",
                session.id
            )
            .fetch_all(&self.db.read_pool)
            .await
            .map_err(|e| Status::internal(format!("Failed to get slot demands: {e}")))?;

            let slot_demands: Vec<SlotRange> = demands
                .into_iter()
                .map(|row| SlotRange {
                    index: row.slot_index as i32,
                    length: row.slot_length as u32,
                })
                .collect();

            // Compute contiguous slot ranges assigned to this session from the latest epoch
            let session_u16 = session.id as u16;
            let slots: Vec<SlotRange> = {
                let mut ranges = Vec::new();
                let mut i = 0;
                while i < epoch_slots.len() {
                    if epoch_slots[i] == session_u16 {
                        let start = i as i32;
                        let mut len: usize = 1;
                        while (i + len) < epoch_slots.len() && epoch_slots[i + len] == session_u16 {
                            len += 1;
                        }
                        ranges.push(SlotRange {
                            index: start,
                            length: len as u32,
                        });
                        i += len;
                    } else {
                        i += 1;
                    }
                }
                ranges
            };

            workers.push(WorkerStatus {
                name: session.name,
                fill_percent: state.as_ref().map_or(0.0, |s| s.fill_percent) as f32,
                control_signal: state.as_ref().map_or(0.0, |s| s.control_signal) as f32,
                slots_assigned: *slots_assigned as u32,
                ip_address: session.ip_address.to_string(),
                udp_port: session.udp_port as u32,
                port_range: session.port_range.into(),
                min_factor: session.min_factor as f32,
                max_factor: session.max_factor as f32,
                last_updated: state
                    .as_ref()
                    .map(|s| prost_wkt_types::Timestamp::from(SystemTime::from(s.timestamp))),
                keep_lb_header: session.keep_lb_header,
                total_events_recv: state.as_ref().map_or(0, |s| s.total_events_recv) as i64,
                total_events_reassembled: state.as_ref().map_or(0, |s| s.total_events_reassembled)
                    as i64,
                total_events_reassembly_err: state
                    .as_ref()
                    .map_or(0, |s| s.total_events_reassembly_err)
                    as i64,
                total_events_dequeued: state.as_ref().map_or(0, |s| s.total_events_dequeued) as i64,
                total_event_enqueue_err: state.as_ref().map_or(0, |s| s.total_event_enqueue_err)
                    as i64,
                total_bytes_recv: state.as_ref().map_or(0, |s| s.total_bytes_recv) as i64,
                total_packets_recv: state.as_ref().map_or(0, |s| s.total_packets_recv) as i64,
                slot_demands,
                slots,
                health_issues,
                session_id: session.id,
            });
        }

        // Fetch health issues for the loadbalancer (all active issues)
        let lb_health_issues = self
            .db
            .list_loadbalancer_healthcheck_events(reservation.loadbalancer_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get LB health issues: {e}")))?;

        let health_issues = lb_health_issues
            .into_iter()
            .map(|event| {
                use crate::proto::loadbalancer::v1::HealthIssue;
                HealthIssue {
                    r#type: event.event_type,
                    severity: event.severity.as_str().to_string(),
                    message: event.message,
                    details: event
                        .details
                        .as_ref()
                        .and_then(|d| serde_json::from_str(d).ok()),
                    detected_at: Some(prost_wkt_types::Timestamp::from(SystemTime::from(
                        event.detected_at,
                    ))),
                }
            })
            .collect();

        Ok(Response::new(LoadBalancerStatusReply {
            timestamp: Some(prost_wkt_types::Timestamp::from(SystemTime::now())),
            current_epoch,
            current_predicted_event_number,
            workers,
            sender_addresses: senders.into_iter().map(|addr| addr.to_string()).collect(),
            expires_at: Some(prost_wkt_types::Timestamp::from(SystemTime::from(
                reservation.reserved_until,
            ))),
            slot_resolution: 512,
            health_issues,
        }))
    }

    pub async fn handle_set_slot_demands(
        &self,
        request: tonic::Request<crate::proto::loadbalancer::v1::SetSlotDemandsRequest>,
    ) -> std::result::Result<
        tonic::Response<crate::proto::loadbalancer::v1::SetSlotDemandsReply>,
        tonic::Status,
    > {
        // Extract token from request metadata
        let token = Self::extract_token(request.metadata())?;
        let remote_addr = request.remote_addr();
        let req = request.into_inner();
        let lb_id = req
            .lb_id
            .parse::<i64>()
            .map_err(|_| tonic::Status::invalid_argument("Invalid lbId"))?;

        // Permission check: must have UPDATE permission to the session (reservation)
        let (ok, token_id) = self
            .validate_token(&token, Resource::Reservation(lb_id), PermissionType::Update)
            .await?;
        if !ok {
            let src = remote_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            warn!(
                "set_slot_demands: permission denied. reservation_id={}, token_id={}, source={}",
                lb_id,
                token_id.unwrap_or(-1),
                src
            );
            return Err(tonic::Status::permission_denied("Permission denied"));
        }

        // Gather all slot demands
        let mut slot_demands = Vec::new();
        for session_slot_ranges in &req.slot_constraints {
            let session_id = if session_slot_ranges.session_id.is_empty() {
                None
            } else {
                Some(
                    session_slot_ranges
                        .session_id
                        .parse::<i64>()
                        .map_err(|_| tonic::Status::invalid_argument("Invalid sessionId"))?,
                )
            };
            for slot in &session_slot_ranges.slots {
                slot_demands.push((session_id, slot.index, slot.length));
            }
        }

        // Update slot demands in DB
        self.db
            .set_slot_demands(lb_id, slot_demands)
            .await
            .map_err(|e| tonic::Status::internal(format!("Failed to set slot demands: {e}")))?;

        // If any slot demands are set, update reservation strategy to "static"
        if !req.slot_constraints.is_empty() {
            sqlx::query!(
                "UPDATE reservation SET strategy = ?1 WHERE id = ?2",
                "static",
                lb_id
            )
            .execute(&self.db.write_pool)
            .await
            .map_err(|e| tonic::Status::internal(format!("Failed to update strategy: {e}")))?;
        }

        Ok(tonic::Response::new(
            crate::proto::loadbalancer::v1::SetSlotDemandsReply {},
        ))
    }

    pub(crate) async fn handle_free_load_balancer(
        &self,
        request: Request<FreeLoadBalancerRequest>,
    ) -> Result<Response<FreeLoadBalancerReply>, Status> {
        let token = Self::extract_token(request.metadata())?;
        let remote_addr = request.remote_addr();
        let request = request.into_inner();
        let reservation_id = request
            .lb_id
            .parse::<i64>()
            .map_err(|_| Status::invalid_argument("Invalid load balancer ID"))?;

        let (ok, token_id) = self
            .validate_token(
                &token,
                Resource::Reservation(reservation_id),
                PermissionType::Update,
            )
            .await?;
        if !ok {
            let src = remote_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            warn!(
                "free_load_balancer: permission denied. reservation_id={}, token_id={}, source={}",
                reservation_id,
                token_id.unwrap_or(-1),
                src
            );
            return Err(Status::permission_denied("Permission denied"));
        }

        // Deregister from all upstream chains (best-effort)
        if let Ok(chains) = self
            .db
            .list_upstream_chains_for_reservation(reservation_id)
            .await
        {
            for chain in &chains {
                if let Err(e) = crate::reservation::upstream::deregister_upstream(chain).await {
                    warn!(
                        "free_load_balancer: failed to deregister from upstream chain {}: {}",
                        chain.id, e
                    );
                }
            }
            if let Err(e) = self
                .db
                .delete_upstream_chains_for_reservation(reservation_id)
                .await
            {
                warn!(
                    "free_load_balancer: failed to delete upstream chains for reservation {}: {}",
                    reservation_id, e
                );
            }
        }

        // Stop the reservation server
        self.manager
            .lock()
            .await
            .stop_reservation(reservation_id)
            .await;

        // Get and verify the reservation exists
        self.db
            .delete_reservation(reservation_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get reservation: {e}")))?;

        let src = remote_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        info!(
            "free_load_balancer: reservation_id={}, token_id={:?}, source={}",
            reservation_id, token_id, src
        );

        Ok(Response::new(FreeLoadBalancerReply {}))
    }

    pub(crate) async fn handle_add_senders(
        &self,
        request: Request<AddSendersRequest>,
    ) -> Result<Response<AddSendersReply>, Status> {
        let token = Self::extract_token(request.metadata())?;
        let remote_addr = request.remote_addr();
        let request = request.into_inner();
        let reservation_id = request
            .lb_id
            .parse::<i64>()
            .map_err(|_| Status::invalid_argument("Invalid load balancer ID"))?;

        let (ok, token_id) = self
            .validate_token(
                &token,
                Resource::Reservation(reservation_id),
                PermissionType::Update,
            )
            .await?;
        if !ok {
            let src = remote_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            warn!(
                "add_senders: permission denied. reservation_id={}, token_id={}, source={}, attempted_senders={:?}",
                reservation_id,
                token_id.unwrap_or(-1),
                src,
                request.sender_addresses
            );
            return Err(Status::permission_denied("Permission denied"));
        }

        for addr_str in &request.sender_addresses {
            let addr = IpAddr::from_str(addr_str)
                .map_err(|_| Status::invalid_argument("Invalid sender IP address"))?;
            self.db
                .add_sender(reservation_id, addr)
                .await
                .map_err(|e| Status::internal(format!("Failed to add sender: {e}")))?;
        }

        let src = remote_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        info!(
            "add_senders: reservation_id={}, senders={:?}, token_id={:?}, source={}",
            reservation_id, request.sender_addresses, token_id, src
        );

        Ok(Response::new(AddSendersReply {}))
    }

    pub(crate) async fn handle_remove_senders(
        &self,
        request: Request<RemoveSendersRequest>,
    ) -> Result<Response<RemoveSendersReply>, Status> {
        let token = Self::extract_token(request.metadata())?;
        let remote_addr = request.remote_addr();
        let request = request.into_inner();
        let reservation_id = request
            .lb_id
            .parse::<i64>()
            .map_err(|_| Status::invalid_argument("Invalid load balancer ID"))?;

        let (ok, token_id) = self
            .validate_token(
                &token,
                Resource::Reservation(reservation_id),
                PermissionType::Update,
            )
            .await?;
        if !ok {
            let src = remote_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            warn!(
                "remove_senders: permission denied. reservation_id={}, token_id={}, source={}, attempted_senders={:?}",
                reservation_id,
                token_id.unwrap_or(-1),
                src,
                request.sender_addresses
            );
            return Err(Status::permission_denied("Permission denied"));
        }

        for addr_str in &request.sender_addresses {
            let addr = IpAddr::from_str(addr_str)
                .map_err(|_| Status::invalid_argument("Invalid sender IP address"))?;
            self.db
                .remove_sender(reservation_id, addr)
                .await
                .map_err(|e| Status::internal(format!("Failed to remove sender: {e}")))?;
        }

        let src = remote_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        info!(
            "remove_senders: reservation_id={}, senders={:?}, token_id={:?}, source={}",
            reservation_id, request.sender_addresses, token_id, src
        );

        Ok(Response::new(RemoveSendersReply {}))
    }

    pub(crate) async fn handle_reset_load_balancer(
        &self,
        request: Request<ResetLoadBalancerRequest>,
    ) -> Result<Response<ResetLoadBalancerReply>, Status> {
        let token = Self::extract_token(request.metadata())?;
        let remote_addr = request.remote_addr();
        let request = request.into_inner();
        let reservation_id = request
            .lb_id
            .parse::<i64>()
            .map_err(|_| Status::invalid_argument("Invalid load balancer ID"))?;

        let (ok, token_id) = self
            .validate_token(
                &token,
                Resource::Reservation(reservation_id),
                PermissionType::Update,
            )
            .await?;
        if !ok {
            let src = remote_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            warn!(
                "reset_load_balancer: permission denied. reservation_id={}, token_id={}, source={}",
                reservation_id,
                token_id.unwrap_or(-1),
                src
            );
            return Err(Status::permission_denied("Permission denied"));
        }

        if request.sync {
            self.db
                .clear_sync_data(reservation_id)
                .await
                .map_err(|e| Status::internal(format!("Failed to clear sync data: {e}")))?;

            // Seed sync with our own UNIX time
            let now = Utc::now();
            let unix_time_micros = now.timestamp_micros();
            let event_rate_hz: i32 = 1_000_000;
            self.db
                .create_event_number(reservation_id, unix_time_micros, event_rate_hz, now, now)
                .await
                .map_err(|e| {
                    Status::internal(format!("Failed to create initial sync data: {e}"))
                })?;
        }

        if request.epochs {
            self.db
                .clear_epochs(reservation_id)
                .await
                .map_err(|e| Status::internal(format!("Failed to clear epochs: {e}")))?;
        }

        if request.senders {
            self.db
                .clear_senders(reservation_id)
                .await
                .map_err(|e| Status::internal(format!("Failed to clear senders: {e}")))?;
        }

        if request.workers {
            self.db
                .clear_sessions(reservation_id)
                .await
                .map_err(|e| Status::internal(format!("Failed to clear workers: {e}")))?;
        }

        let src = remote_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        info!(
            "reset_load_balancer: reservation_id={}, sync={}, epochs={}, senders={}, workers={}, token_id={:?}, source={}",
            reservation_id, request.sync, request.epochs, request.senders, request.workers, token_id, src
        );

        Ok(Response::new(ResetLoadBalancerReply {
            sync: request.sync,
            epochs: request.epochs,
            senders: request.senders,
            workers: request.workers,
        }))
    }

    pub(crate) async fn handle_extend_reservation(
        &self,
        request: Request<ExtendReservationRequest>,
    ) -> Result<Response<ExtendReservationReply>, Status> {
        let token = Self::extract_token(request.metadata())?;
        let remote_addr = request.remote_addr();
        let request = request.into_inner();
        let reservation_id = request
            .lb_id
            .parse::<i64>()
            .map_err(|_| Status::invalid_argument("Invalid load balancer ID"))?;

        let (ok, token_id) = self
            .validate_token(
                &token,
                Resource::Reservation(reservation_id),
                PermissionType::Update,
            )
            .await?;
        if !ok {
            let src = remote_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            warn!(
                "extend_reservation: permission denied. reservation_id={}, token_id={}, source={}",
                reservation_id,
                token_id.unwrap_or(-1),
                src
            );
            return Err(Status::permission_denied("Permission denied"));
        }

        let until = request.until.map(|ts| {
            Utc.timestamp_opt(ts.seconds, ts.nanos as u32)
                .single()
                .expect("Invalid timestamp")
        });

        let new_until = self
            .db
            .extend_reservation(reservation_id, until)
            .await
            .map_err(|e| Status::internal(format!("Failed to extend reservation: {e}")))?;

        let src = remote_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        info!(
            "extend_reservation: reservation_id={}, new_until={}, token_id={:?}, source={}",
            reservation_id, new_until, token_id, src
        );

        Ok(Response::new(ExtendReservationReply {
            until: Some(prost_wkt_types::Timestamp::from(SystemTime::from(
                new_until,
            ))),
        }))
    }

    pub(crate) async fn handle_chain_load_balancer(
        &self,
        request: Request<ChainLoadBalancerRequest>,
    ) -> Result<Response<ChainLoadBalancerReply>, Status> {
        let token = Self::extract_token(request.metadata())?;
        let remote_addr = request.remote_addr();
        let request = request.into_inner();
        let reservation_id = request
            .lb_id
            .parse::<i64>()
            .map_err(|_| Status::invalid_argument("Invalid load balancer ID"))?;

        let (ok, token_id) = self
            .validate_token(
                &token,
                Resource::Reservation(reservation_id),
                PermissionType::Update,
            )
            .await?;
        if !ok {
            let src = remote_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            warn!(
                "chain_load_balancer: permission denied. reservation_id={}, token_id={}, source={}",
                reservation_id,
                token_id.unwrap_or(-1),
                src
            );
            return Err(Status::permission_denied("Permission denied"));
        }

        // Parse the EJFAT URI
        let ejfat_url: EjfatUrl = request
            .ejfat_uri
            .parse()
            .map_err(|e| Status::invalid_argument(format!("Invalid EJFAT URI: {e}")))?;

        let upstream_lb_id = ejfat_url
            .lb_id
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("EJFAT URI must include a load balancer ID"))?
            .clone();

        let upstream_token = ejfat_url
            .token
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("EJFAT URI must include a token"))?
            .clone();

        let upstream_grpc_port = ejfat_url
            .grpc_port
            .ok_or_else(|| Status::invalid_argument("EJFAT URI must include a gRPC port"))?;

        // Validate IP family
        let ip_family = IpFamily::try_from(request.ip_family)
            .map_err(|_| Status::invalid_argument("Invalid IP family"))?;
        if ip_family == IpFamily::DualStack {
            return Err(Status::invalid_argument(
                "DUAL_STACK is not supported for ChainLoadBalancer, use IPV4 or IPV6",
            ));
        }

        // Get the local reservation and its load balancer
        let reservation = self
            .db
            .get_reservation(reservation_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get reservation: {e}")))?;

        let lb = self
            .db
            .get_loadbalancer(reservation.loadbalancer_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get load balancer: {e}")))?;

        // Get the LB's data plane address for the requested IP family
        let address_map = self.config.mock.as_ref().map(|m| &m.address_map);

        let (ip_address, data_port) = match ip_family {
            IpFamily::Ipv4 => {
                let ip = lb.unicast_ipv4_address.ok_or_else(|| {
                    Status::failed_precondition(
                        "Load balancer does not have an IPv4 address configured",
                    )
                })?;
                if self.mock_mode {
                    match address_map.and_then(|m| m.get(&IpAddr::V4(ip))) {
                        Some(mapped) => (mapped.ip().to_string(), mapped.port()),
                        None => (ip.to_string(), 19522),
                    }
                } else {
                    (ip.to_string(), 19522)
                }
            }
            IpFamily::Ipv6 => {
                let ip = lb.unicast_ipv6_address.ok_or_else(|| {
                    Status::failed_precondition(
                        "Load balancer does not have an IPv6 address configured",
                    )
                })?;
                if self.mock_mode {
                    match address_map.and_then(|m| m.get(&IpAddr::V6(ip))) {
                        Some(mapped) => (mapped.ip().to_string(), mapped.port()),
                        None => (ip.to_string(), 19522),
                    }
                } else {
                    (ip.to_string(), 19522)
                }
            }
            _ => unreachable!(),
        };

        let port_range = if self.mock_mode {
            PortRange::PortRange1
        } else {
            PortRange::PortRange16384
        };

        // Connect to the upstream control plane and register
        let channel = if ejfat_url.tls_enabled {
            let tls_config = ClientTlsConfig::new().with_enabled_roots();
            Channel::from_shared(format!(
                "https://{}:{}",
                ejfat_url.grpc_host, upstream_grpc_port
            ))
            .map_err(|e| Status::internal(format!("Failed to create channel: {e}")))?
            .tls_config(tls_config)
            .map_err(|e| Status::internal(format!("Failed to configure TLS: {e}")))?
            .connect()
            .await
            .map_err(|e| {
                Status::unavailable(format!("Failed to connect to upstream control plane: {e}"))
            })?
        } else {
            Channel::from_shared(format!(
                "http://{}:{}",
                ejfat_url.grpc_host, upstream_grpc_port
            ))
            .map_err(|e| Status::internal(format!("Failed to create channel: {e}")))?
            .connect()
            .await
            .map_err(|e| {
                Status::unavailable(format!("Failed to connect to upstream control plane: {e}"))
            })?
        };

        let bearer_interceptor = BearerInterceptor {
            token: upstream_token.clone(),
        };
        let client = LoadBalancerClient::with_interceptor(channel, bearer_interceptor);
        let mut upstream_client =
            ControlPlaneClient::new(client, Some(upstream_lb_id.clone()), None);

        // Query the upstream for its data plane addresses
        let upstream_info = upstream_client
            .get_load_balancer()
            .await
            .map_err(|e| {
                Status::internal(format!("Failed to get upstream load balancer info: {e}"))
            })?
            .into_inner();

        let upstream_data_ipv4 = if upstream_info.data_ipv4_address.is_empty() {
            None
        } else {
            Some(upstream_info.data_ipv4_address)
        };
        let upstream_data_ipv6 = if upstream_info.data_ipv6_address.is_empty() {
            None
        } else {
            Some(upstream_info.data_ipv6_address)
        };

        // Cycle detection: check if adding this chain would create a forwarding loop.
        // Build the compound identity "host:port/lb_id" for this node's reservation.
        let listen = &self.config.server.listen[0];
        let my_compound_id = format!("{}:{}/{}", listen.ip(), listen.port(), reservation_id);
        match upstream_client
            .get_chain_graph(upstream_lb_id.clone(), vec![my_compound_id])
            .await
        {
            Ok(reply) => {
                if reply.into_inner().cycle_detected {
                    return Err(Status::failed_precondition(
                        "ChainLoadBalancer would create a forwarding cycle",
                    ));
                }
            }
            Err(e) => {
                warn!(
                    "chain_load_balancer: cycle check failed (upstream unreachable), proceeding optimistically: {e}"
                );
            }
        }

        let register_reply = upstream_client
            .register(
                format!("chain-{reservation_id}"),
                request.weight,
                ip_address,
                data_port,
                port_range,
                request.min_factor,
                request.max_factor,
                true, // keepLbHeader
                request.slot_demands,
            )
            .await
            .map_err(|e| {
                Status::internal(format!(
                    "Failed to register with upstream control plane: {e}"
                ))
            })?;

        let reply = register_reply.into_inner();
        let upstream_session_token = reply.token;
        let upstream_session_id = reply.session_id;

        // Store the upstream chain in the database
        let chain = self
            .db
            .create_upstream_chain(
                reservation_id,
                &ejfat_url.grpc_host,
                upstream_grpc_port,
                ejfat_url.tls_enabled,
                &upstream_lb_id,
                &upstream_token,
                &upstream_session_token,
                &upstream_session_id,
                upstream_data_ipv4.as_deref(),
                upstream_data_ipv6.as_deref(),
            )
            .await
            .map_err(|e| Status::internal(format!("Failed to store upstream chain: {e}")))?;

        let src = remote_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        info!(
            "chain_load_balancer: reservation_id={}, chain_id={}, upstream={}:{}/lb/{}, token_id={:?}, source={}",
            reservation_id, chain.id, ejfat_url.grpc_host, upstream_grpc_port, upstream_lb_id, token_id, src
        );

        Ok(Response::new(ChainLoadBalancerReply {
            chain_id: chain.id.to_string(),
        }))
    }

    pub(crate) async fn handle_unchain_load_balancer(
        &self,
        request: Request<UnchainLoadBalancerRequest>,
    ) -> Result<Response<UnchainLoadBalancerReply>, Status> {
        let token = Self::extract_token(request.metadata())?;
        let remote_addr = request.remote_addr();
        let request = request.into_inner();
        let reservation_id = request
            .lb_id
            .parse::<i64>()
            .map_err(|_| Status::invalid_argument("Invalid load balancer ID"))?;
        let chain_id = request
            .chain_id
            .parse::<i64>()
            .map_err(|_| Status::invalid_argument("Invalid chain ID"))?;

        let (ok, token_id) = self
            .validate_token(
                &token,
                Resource::Reservation(reservation_id),
                PermissionType::Update,
            )
            .await?;
        if !ok {
            let src = remote_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            warn!(
                "unchain_load_balancer: permission denied. reservation_id={}, token_id={}, source={}",
                reservation_id,
                token_id.unwrap_or(-1),
                src
            );
            return Err(Status::permission_denied("Permission denied"));
        }

        // Get the upstream chain and verify it belongs to this reservation
        let chain = self
            .db
            .get_upstream_chain(chain_id)
            .await
            .map_err(|e| Status::not_found(format!("Upstream chain not found: {e}")))?;

        if chain.reservation_id != reservation_id {
            return Err(Status::invalid_argument(
                "Chain does not belong to this reservation",
            ));
        }

        // Deregister from the upstream control plane (best-effort)
        if let Err(e) = crate::reservation::upstream::deregister_upstream(&chain).await {
            warn!(
                "unchain_load_balancer: failed to deregister from upstream (chain_id={}): {}",
                chain_id, e
            );
        }

        // Soft-delete the chain
        self.db
            .delete_upstream_chain(chain_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to delete upstream chain: {e}")))?;

        let src = remote_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        info!(
            "unchain_load_balancer: reservation_id={}, chain_id={}, token_id={:?}, source={}",
            reservation_id, chain_id, token_id, src
        );

        Ok(Response::new(UnchainLoadBalancerReply {}))
    }

    pub(crate) async fn handle_get_chain_graph(
        &self,
        request: Request<GetChainGraphRequest>,
    ) -> Result<Response<GetChainGraphReply>, Status> {
        let token = Self::extract_token(request.metadata())?;
        let request = request.into_inner();
        let reservation_id = request
            .lb_id
            .parse::<i64>()
            .map_err(|_| Status::invalid_argument("Invalid load balancer ID"))?;

        let (ok, _) = self
            .validate_token(
                &token,
                Resource::Reservation(reservation_id),
                PermissionType::ReadOnly,
            )
            .await?;
        if !ok {
            return Err(Status::permission_denied("Permission denied"));
        }

        // Derive this node's compound identity: "host:port/lb_id"
        let listen = &self.config.server.listen[0];
        let my_compound_id = format!("{}:{}/{}", listen.ip(), listen.port(), reservation_id);

        // If we appear in the visited set, the caller found a cycle back to us
        if request.visited.contains(&my_compound_id) {
            return Ok(Response::new(GetChainGraphReply {
                edges: vec![],
                cycle_detected: true,
            }));
        }

        // Fetch local LB data-plane addresses for the downstream side of edges
        let reservation = self
            .db
            .get_reservation(reservation_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get reservation: {e}")))?;
        let lb = self
            .db
            .get_loadbalancer(reservation.loadbalancer_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get load balancer: {e}")))?;
        let downstream_data_ipv4 = lb
            .unicast_ipv4_address
            .map(|ip| ip.to_string())
            .unwrap_or_default();
        let downstream_data_ipv6 = lb
            .unicast_ipv6_address
            .map(|ip| ip.to_string())
            .unwrap_or_default();

        let chains = self
            .db
            .list_upstream_chains_for_reservation(reservation_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list upstream chains: {e}")))?;

        let mut edges = Vec::new();
        let mut new_visited = request.visited.clone();
        new_visited.push(my_compound_id);

        for chain in &chains {
            edges.push(ChainGraphEdge {
                upstream_lb_id: chain.upstream_lb_id.clone(),
                upstream_data_ipv4: chain
                    .upstream_data_ipv4
                    .map(|ip| ip.to_string())
                    .unwrap_or_default(),
                upstream_data_ipv6: chain
                    .upstream_data_ipv6
                    .map(|ip| ip.to_string())
                    .unwrap_or_default(),
                downstream_lb_id: reservation_id.to_string(),
                downstream_data_ipv4: downstream_data_ipv4.clone(),
                downstream_data_ipv6: downstream_data_ipv6.clone(),
                chain_id: chain.id.to_string(),
            });

            let ejfat_token = match &chain.upstream_ejfat_token {
                Some(t) => t.clone(),
                None => {
                    warn!(
                        "get_chain_graph: chain {} has no ejfat token, skipping recursion",
                        chain.id
                    );
                    continue;
                }
            };

            let mut upstream_client =
                match crate::reservation::upstream::create_upstream_client(chain, &ejfat_token)
                    .await
                {
                    Ok(c) => c,
                    Err(e) => {
                        warn!(
                            "get_chain_graph: cannot connect to upstream {}:{} (chain {}): {}",
                            chain.upstream_grpc_host, chain.upstream_grpc_port, chain.id, e
                        );
                        continue;
                    }
                };

            match upstream_client
                .get_chain_graph(chain.upstream_lb_id.clone(), new_visited.clone())
                .await
            {
                Ok(reply) => {
                    let reply = reply.into_inner();
                    if reply.cycle_detected {
                        return Ok(Response::new(GetChainGraphReply {
                            edges,
                            cycle_detected: true,
                        }));
                    }
                    edges.extend(reply.edges);
                }
                Err(e) => {
                    warn!(
                        "get_chain_graph: upstream {}:{} error (chain {}): {}",
                        chain.upstream_grpc_host, chain.upstream_grpc_port, chain.id, e
                    );
                }
            }
        }

        Ok(Response::new(GetChainGraphReply {
            edges,
            cycle_detected: false,
        }))
    }
}

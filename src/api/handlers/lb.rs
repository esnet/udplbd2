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
use crate::db::models::{Permission, PermissionType, Resource};
use crate::proto::loadbalancer::v1::{
    AddSendersReply, AddSendersRequest, FreeLoadBalancerReply, FreeLoadBalancerRequest,
    GetLoadBalancerRequest, LoadBalancerStatusReply, LoadBalancerStatusRequest, RemoveSendersReply,
    RemoveSendersRequest, ReserveLoadBalancerReply, ReserveLoadBalancerRequest, WorkerStatus,
};
use crate::util::is_valid_name;

impl LoadBalancerService {
    pub(crate) async fn handle_reserve_load_balancer(
        &self,
        request: Request<ReserveLoadBalancerRequest>,
    ) -> Result<Response<ReserveLoadBalancerReply>, Status> {
        let token = Self::extract_token(request.metadata())?;
        let remote_addr = request.remote_addr();
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

        // Determine if this is a mock LB (127.0.0.1 or ::1)
        let is_mock = lb
            .unicast_ipv4_address
            .map(|ip| ip == std::net::Ipv4Addr::LOCALHOST)
            .unwrap_or(false)
            || lb
                .unicast_ipv6_address
                .map(|ip| ip == std::net::Ipv6Addr::LOCALHOST)
                .unwrap_or(false);

        let (data_min_port, data_max_port) = if is_mock {
            (19522, 19522)
        } else {
            (16384, 32767)
        };

        Ok(Response::new(ReserveLoadBalancerReply {
            token,
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
            data_ipv4_address: lb
                .unicast_ipv4_address
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            data_ipv6_address: lb
                .unicast_ipv6_address
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            fpga_lb_id: lb.fpga_lb_id as u32,
            data_min_port,
            data_max_port,
            strategy: reservation.strategy,
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

        // Determine if this is a mock LB (127.0.0.1 or ::1)
        let is_mock = lb
            .unicast_ipv4_address
            .map(|ip| ip == std::net::Ipv4Addr::LOCALHOST)
            .unwrap_or(false)
            || lb
                .unicast_ipv6_address
                .map(|ip| ip == std::net::Ipv6Addr::LOCALHOST)
                .unwrap_or(false);

        let (data_min_port, data_max_port) = if is_mock {
            (19522, 19522)
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
            data_ipv4_address: lb
                .unicast_ipv4_address
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            data_ipv6_address: lb
                .unicast_ipv6_address
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            fpga_lb_id: lb.fpga_lb_id as u32,
            data_min_port,
            data_max_port,
            strategy: if reservation.strategy.is_empty() {
                "dynamic".to_string()
            } else {
                reservation.strategy.clone()
            },
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
        let (current_epoch, current_predicted_event_number, slot_counts) =
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
                    )
                }
                Err(_) => (0, 0, HashMap::new()),
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
            let session_health_issues = self
                .db
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
                slot_demands: Vec::new(), // TODO: fetch from database
                slots: Vec::new(),        // TODO: use latest epoch data
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
}

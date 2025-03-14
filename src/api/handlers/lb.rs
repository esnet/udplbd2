/// API handlers for functions related to reserving, querying, freeing LBs
use chrono::{Duration, TimeZone, Utc};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::SystemTime;
use tonic::{Request, Response, Status};

use super::super::service::LoadBalancerService;
use crate::db::models::{Permission, PermissionType, Resource};
use crate::proto::loadbalancer::v1::{
    AddSendersReply, AddSendersRequest, FreeLoadBalancerReply, FreeLoadBalancerRequest,
    GetLoadBalancerRequest, LoadBalancerStatusReply, LoadBalancerStatusRequest, RemoveSendersReply,
    RemoveSendersRequest, ReserveLoadBalancerReply, ReserveLoadBalancerRequest, WorkerStatus,
};

impl LoadBalancerService {
    pub(crate) async fn handle_reserve_load_balancer(
        &self,
        request: Request<ReserveLoadBalancerRequest>,
    ) -> Result<Response<ReserveLoadBalancerReply>, Status> {
        let token = Self::extract_token(request.metadata())?;
        let request = request.into_inner();

        let all_lbs = self
            .db
            .list_loadbalancers()
            .await
            .map_err(|e| Status::internal(format!("Failed to list load balancers: {e}")))?;

        let mut has_permission_to_any = false;
        let mut available_lb = None;

        for lb in all_lbs {
            if !self
                .validate_token(
                    &token,
                    Resource::LoadBalancer(lb.id),
                    PermissionType::Reserve,
                )
                .await?
            {
                continue;
            }

            has_permission_to_any = true;

            let existing_reservation = sqlx::query!(
                r#"
                SELECT id
                FROM reservation
                WHERE loadbalancer_id = ?1
                AND deleted_at IS NULL
                AND reserved_until > CURRENT_TIMESTAMP
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
            return Err(Status::permission_denied(
                "No permission to reserve any load balancers",
            ));
        }

        let lb = available_lb.ok_or_else(|| {
            Status::resource_exhausted("All accessible load balancers are currently reserved")
        })?;

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

        let reservation = self
            .db
            .create_reservation(lb.id, chrono::Duration::from_std(duration).unwrap())
            .await
            .map_err(|e| Status::internal(format!("Failed to create reservation: {e}")))?;

        self.manager
            .lock()
            .await
            .start_reservation(reservation.id, lb.event_number_udp_port)
            .await
            .map_err(|_| {
                Status::internal(format!(
                    "Failed to start reservation server on port {}",
                    lb.event_number_udp_port
                ))
            })?;

        for addr_str in request.sender_addresses {
            let addr = IpAddr::from_str(&addr_str)
                .map_err(|_| Status::invalid_argument("Invalid sender IP address"))?;
            self.db
                .add_sender(reservation.id, addr)
                .await
                .map_err(|e| Status::internal(format!("Failed to add sender: {e}")))?;
        }

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

        Ok(Response::new(ReserveLoadBalancerReply {
            token,
            lb_id: reservation.id.to_string(),
            sync_ip_address: self.sync_address.ip().to_string(),
            sync_udp_port: u32::from(lb.event_number_udp_port),
            data_ipv4_address: lb.unicast_ipv4_address.to_string(),
            data_ipv6_address: lb.unicast_ipv6_address.to_string(),
            fpga_lb_id: reservation.id as u32,
        }))
    }

    pub(crate) async fn handle_get_load_balancer(
        &self,
        request: Request<GetLoadBalancerRequest>,
    ) -> Result<Response<ReserveLoadBalancerReply>, Status> {
        let token = Self::extract_token(request.metadata())?;
        let request = request.into_inner();
        let reservation_id = request
            .lb_id
            .parse::<i64>()
            .map_err(|_| Status::invalid_argument("Invalid load balancer ID"))?;

        if !self
            .validate_token(
                &token,
                Resource::Reservation(reservation_id),
                PermissionType::ReadOnly,
            )
            .await?
        {
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

        Ok(Response::new(ReserveLoadBalancerReply {
            token: String::new(), // No token for get operations
            lb_id: reservation.id.to_string(),
            sync_ip_address: self.sync_address.ip().to_string(),
            sync_udp_port: u32::from(lb.event_number_udp_port),
            data_ipv4_address: lb.unicast_ipv4_address.to_string(),
            data_ipv6_address: lb.unicast_ipv6_address.to_string(),
            fpga_lb_id: reservation.id as u32,
        }))
    }

    pub(crate) async fn handle_load_balancer_status(
        &self,
        request: Request<LoadBalancerStatusRequest>,
    ) -> Result<Response<LoadBalancerStatusReply>, Status> {
        let token = Self::extract_token(request.metadata())?;
        let request = request.into_inner();
        let reservation_id = request
            .lb_id
            .parse::<i64>()
            .map_err(|_| Status::invalid_argument("Invalid load balancer ID"))?;

        if !self
            .validate_token(
                &token,
                Resource::Reservation(reservation_id),
                PermissionType::ReadOnly,
            )
            .await?
        {
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

        let latest_epoch = self
            .db
            .get_latest_epoch(reservation_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get latest epoch: {e}")))?;

        let mut workers = Vec::new();
        let mut slot_counts = HashMap::new();

        // Count slots assigned to each worker
        for &slot in &latest_epoch.slots {
            *slot_counts.entry(slot).or_insert(0) += 1;
        }

        for session in sessions {
            let state = self
                .db
                .get_latest_session_state(session.id)
                .await
                .map_err(|e| Status::internal(format!("Failed to get session state: {e}")))?;

            let slots_assigned = slot_counts.get(&(session.id as u16)).unwrap_or(&0);

            workers.push(WorkerStatus {
                name: session.name,
                fill_percent: state.as_ref().map_or(0.0, |s| s.fill_percent) as f32,
                control_signal: state.as_ref().map_or(0.0, |s| s.control_signal) as f32,
                slots_assigned: *slots_assigned as u32,
                last_updated: state
                    .map(|s| prost_types::Timestamp::from(SystemTime::from(s.timestamp))),
            });
        }

        Ok(Response::new(LoadBalancerStatusReply {
            timestamp: Some(prost_types::Timestamp::from(SystemTime::now())),
            current_epoch: latest_epoch.id as u64,
            current_predicted_event_number: latest_epoch.boundary_event,
            workers,
            sender_addresses: senders.into_iter().map(|addr| addr.to_string()).collect(),
            expires_at: Some(prost_types::Timestamp::from(SystemTime::from(
                reservation.reserved_until,
            ))),
        }))
    }

    pub(crate) async fn handle_free_load_balancer(
        &self,
        request: Request<FreeLoadBalancerRequest>,
    ) -> Result<Response<FreeLoadBalancerReply>, Status> {
        let token = Self::extract_token(request.metadata())?;
        let request = request.into_inner();
        let reservation_id = request
            .lb_id
            .parse::<i64>()
            .map_err(|_| Status::invalid_argument("Invalid load balancer ID"))?;

        if !self
            .validate_token(
                &token,
                Resource::Reservation(reservation_id),
                PermissionType::Update,
            )
            .await?
        {
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

        Ok(Response::new(FreeLoadBalancerReply {}))
    }

    pub(crate) async fn handle_add_senders(
        &self,
        request: Request<AddSendersRequest>,
    ) -> Result<Response<AddSendersReply>, Status> {
        let token = Self::extract_token(request.metadata())?;
        let request = request.into_inner();
        let reservation_id = request
            .lb_id
            .parse::<i64>()
            .map_err(|_| Status::invalid_argument("Invalid load balancer ID"))?;

        if !self
            .validate_token(
                &token,
                Resource::Reservation(reservation_id),
                PermissionType::Update,
            )
            .await?
        {
            return Err(Status::permission_denied("Permission denied"));
        }

        for addr_str in request.sender_addresses {
            let addr = IpAddr::from_str(&addr_str)
                .map_err(|_| Status::invalid_argument("Invalid sender IP address"))?;
            self.db
                .add_sender(reservation_id, addr)
                .await
                .map_err(|e| Status::internal(format!("Failed to add sender: {e}")))?;
        }

        Ok(Response::new(AddSendersReply {}))
    }

    pub(crate) async fn handle_remove_senders(
        &self,
        request: Request<RemoveSendersRequest>,
    ) -> Result<Response<RemoveSendersReply>, Status> {
        let token = Self::extract_token(request.metadata())?;
        let request = request.into_inner();
        let reservation_id = request
            .lb_id
            .parse::<i64>()
            .map_err(|_| Status::invalid_argument("Invalid load balancer ID"))?;

        if !self
            .validate_token(
                &token,
                Resource::Reservation(reservation_id),
                PermissionType::Update,
            )
            .await?
        {
            return Err(Status::permission_denied("Permission denied"));
        }

        for addr_str in request.sender_addresses {
            let addr = IpAddr::from_str(&addr_str)
                .map_err(|_| Status::invalid_argument("Invalid sender IP address"))?;
            self.db
                .remove_sender(reservation_id, addr)
                .await
                .map_err(|e| Status::internal(format!("Failed to remove sender: {e}")))?;
        }

        Ok(Response::new(RemoveSendersReply {}))
    }
}

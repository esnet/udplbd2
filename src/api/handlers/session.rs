/// API handlers for functions related to registering, deregistering, updating sessions with an LB
use std::net::IpAddr;
use std::str::FromStr;
use tonic::{Request, Response, Status};

use super::super::service::LoadBalancerService;
use crate::db::models::{Permission, PermissionType, Resource};
use crate::proto::loadbalancer::v1::{
    DeregisterReply, DeregisterRequest, RegisterReply, RegisterRequest, SendStateReply,
    SendStateRequest,
};

impl LoadBalancerService {
    pub(crate) async fn handle_register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterReply>, Status> {
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
                PermissionType::Register,
            )
            .await?
        {
            return Err(Status::permission_denied("Permission denied"));
        }

        let addr = IpAddr::from_str(&request.ip_address)
            .map_err(|_| Status::invalid_argument("Invalid IP address"))?;
        let socket_addr = std::net::SocketAddr::new(addr, request.udp_port as u16);

        // Get MAC address for the IP
        let mac_address = self
            .get_mac_addr(addr)
            .await
            .map_err(|e| Status::internal(format!("Failed to get MAC address: {e}")))?;

        let session = self
            .db
            .add_session(
                reservation_id,
                &request.name,
                f64::from(request.weight),
                socket_addr,
                request.port_range as u16,
                f64::from(request.min_factor),
                f64::from(request.max_factor),
                mac_address,
                request.keep_lb_header,
            )
            .await
            .map_err(|e| Status::internal(format!("Failed to add session: {e}")))?;

        let new_token_name = format!("session-{}", session.id);
        let token = self
            .db
            .create_token(
                new_token_name.as_str(),
                Some(token.as_str()),
                vec![Permission {
                    resource: Resource::Session(session.id),
                    permission: PermissionType::Update,
                }],
            )
            .await
            .map_err(|e| Status::internal(format!("Failed to create token: {e}")))?;

        Ok(Response::new(RegisterReply {
            token,
            session_id: session.id.to_string(),
        }))
    }

    pub(crate) async fn handle_deregister(
        &self,
        request: Request<DeregisterRequest>,
    ) -> Result<Response<DeregisterReply>, Status> {
        let token = Self::extract_token(request.metadata())?;
        let request = request.into_inner();
        let session_id = request
            .session_id
            .parse::<i64>()
            .map_err(|_| Status::invalid_argument("Invalid session ID"))?;

        if !self
            .validate_token(
                &token,
                Resource::Session(session_id),
                PermissionType::Update,
            )
            .await?
        {
            return Err(Status::permission_denied("Permission denied"));
        }

        sqlx::query!(
            "UPDATE session SET deleted_at = unixepoch('subsec') * 1000 WHERE id = ?1 AND deleted_at IS NULL",
            session_id
        )
        .execute(&self.db.write_pool)
        .await
        .map_err(|e| Status::internal(format!("Failed to delete session: {e}")))?;

        // Force an epoch update since session composition changed
        let sessions = sqlx::query!(
            "SELECT reservation_id FROM session WHERE id = ?1",
            session_id
        )
        .fetch_one(&self.db.write_pool)
        .await
        .map_err(|e| Status::internal(format!("Failed to get reservation ID: {e}")))?;

        self.db
            .advance_epoch(sessions.reservation_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to advance epoch: {e}")))?;

        Ok(Response::new(DeregisterReply {}))
    }

    pub(crate) async fn handle_send_state(
        &self,
        request: Request<SendStateRequest>,
    ) -> Result<Response<SendStateReply>, Status> {
        let token = Self::extract_token(request.metadata())?;
        let request = request.into_inner();
        let session_id = request
            .session_id
            .parse::<i64>()
            .map_err(|_| Status::invalid_argument("Invalid session ID"))?;

        if !self
            .validate_token(
                &token,
                Resource::Session(session_id),
                PermissionType::Update,
            )
            .await?
        {
            return Err(Status::permission_denied("Permission denied"));
        }

        let mut dt = chrono::DateTime::from_timestamp(0, 0).unwrap();
        if let Some(ts) = request.timestamp {
            dt = chrono::DateTime::from_timestamp(ts.seconds, ts.nanos as u32).unwrap();
        }
        let dt_ms = dt.timestamp_millis();

        // Update session state
        sqlx::query!(
            r#"
            INSERT INTO session_state (
                session_id, timestamp, is_ready, fill_percent, control_signal,
                total_events_recv, total_events_reassembled, total_events_reassembly_err,
                total_events_dequeued, total_event_enqueue_err, total_bytes_recv,
                total_packets_recv
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            "#,
            session_id,
            dt_ms,
            request.is_ready,
            request.fill_percent,
            request.control_signal,
            request.total_events_recv,
            request.total_events_reassembled,
            request.total_events_reassembly_err,
            request.total_events_dequeued,
            request.total_event_enqueue_err,
            request.total_bytes_recv,
            request.total_packets_recv
        )
        .execute(&self.db.write_pool)
        .await
        .map_err(|e| Status::internal(format!("Failed to update session state: {e}")))?;

        Ok(Response::new(SendStateReply {}))
    }
}

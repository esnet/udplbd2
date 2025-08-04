// SPDX-License-Identifier: BSD-3-Clause-LBNL
/// API handlers for LB system administration (Overview, Version, etc.)
use tonic::{Request, Response, Status};
use tracing::{debug, warn};

use super::super::service::LoadBalancerService;
use crate::proto::loadbalancer::v1::{
    GetLoadBalancerRequest, LoadBalancerStatusRequest, Overview, OverviewReply, OverviewRequest,
    VersionReply, VersionRequest,
};

impl LoadBalancerService {
    pub(crate) async fn handle_overview(
        &self,
        request: Request<OverviewRequest>,
    ) -> Result<Response<OverviewReply>, Status> {
        let token = Self::extract_token(request.metadata())?;
        let remote_addr = request.remote_addr();
        if !self
            .db
            .token_exists(&token)
            .await
            .map_err(|e| Status::internal(format!("Token validation failed: {e}")))?
        {
            let src = remote_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            warn!("overview: permission denied. source={}", src);
            return Err(Status::permission_denied("Permission denied"));
        }

        let mut load_balancers = Vec::new();
        let token_str = format!("Bearer {token}");

        let lbs = self
            .db
            .list_loadbalancers()
            .await
            .map_err(|e| Status::internal(format!("Failed to list load balancers: {e}")))?;

        'lbs: for lb in lbs {
            // Attempt to find an active reservation for this LB
            let reservation = sqlx::query!(
                r#"
                SELECT id, name FROM reservation
                WHERE loadbalancer_id = ?1
                AND deleted_at IS NULL
                AND reserved_until > unixepoch('subsec') * 1000
                ORDER BY created_at DESC
                LIMIT 1
                "#,
                lb.id
            )
            .fetch_optional(&self.db.read_pool)
            .await
            .map_err(|e| Status::internal(format!("Failed to query reservation: {e}")))?;

            let (reservation_details, name, status) = if let Some(res) = reservation {
                // Get full reservation details
                let mut request = Request::new(GetLoadBalancerRequest {
                    lb_id: res.id.to_string(),
                });
                request
                    .metadata_mut()
                    .insert("authorization", token_str.parse().unwrap());
                let reservation_reply_res = self.handle_get_load_balancer(request).await;
                if reservation_reply_res.is_err() {
                    // skip the reservations the token can't access
                    continue 'lbs;
                }
                let reservation_reply = reservation_reply_res?.into_inner();

                // Get status
                let mut status_request = Request::new(LoadBalancerStatusRequest {
                    lb_id: res.id.to_string(),
                });
                status_request
                    .metadata_mut()
                    .insert("authorization", token_str.parse().unwrap());
                let status_reply = self
                    .handle_load_balancer_status(status_request)
                    .await?
                    .into_inner();

                (Some(reservation_reply), res.name, Some(status_reply))
            } else {
                (None, "<unreserved>".to_string(), None)
            };

            if reservation_details.is_some() {
                load_balancers.push(Overview {
                    name,
                    reservation: reservation_details,
                    status,
                });
            }
        }

        let src = remote_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        debug!("overview: source={}", src);
        Ok(Response::new(OverviewReply { load_balancers }))
    }

    pub(crate) async fn handle_version(
        &self,
        request: Request<VersionRequest>,
    ) -> Result<Response<VersionReply>, Status> {
        let token = Self::extract_token(request.metadata())?;
        let remote_addr = request.remote_addr();
        if !self
            .db
            .token_exists(&token)
            .await
            .map_err(|e| Status::internal(format!("Token validation failed: {e}")))?
        {
            let src = remote_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            warn!("version: permission denied. source={}", src);
            return Err(Status::permission_denied("Permission denied"));
        }

        let src = remote_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        debug!("version: source={}", src);
        Ok(Response::new(VersionReply {
            commit: env!("UDPLBD_BUILD", "unknown").to_string(),
            build: env!("CARGO_PKG_VERSION").to_string(),
            compat_tag: "0.3.1".to_string(),
        }))
    }
}

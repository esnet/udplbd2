// SPDX-License-Identifier: BSD-3-Clause-LBNL
/// API handlers for timeseries data
use chrono::{TimeZone, Utc};
use std::collections::HashSet;
use tonic::{Request, Response, Status};
use tracing::{debug, warn};

use super::super::service::LoadBalancerService;
use crate::db::models::{PermissionType, Resource};
use crate::proto::loadbalancer::v1::{
    Timeseries as ProtoTimeseries, TimeseriesRequest, TimeseriesResponse,
};

impl LoadBalancerService {
    pub(crate) async fn handle_timeseries(
        &self,
        request: Request<TimeseriesRequest>,
    ) -> Result<Response<TimeseriesResponse>, Status> {
        let token = Self::extract_token(request.metadata())?;
        let remote_addr = request.remote_addr();
        let request = request.into_inner();

        // Parse the since timestamp
        let since = if let Some(ts) = request.since {
            Utc.timestamp_opt(ts.seconds, ts.nanos as u32)
                .single()
                .ok_or_else(|| Status::invalid_argument("Invalid since timestamp"))?
        } else {
            // Default to 1 minute ago if not specified
            Utc::now() - chrono::Duration::minutes(1)
        };

        let src = remote_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        debug!(
            "timeseries: request selectors={:?}, since={:?}, source={}",
            &request.series_selector, &request.since, src
        );

        // Pre-filter selectors based on permissions.
        // If the user requests "*" (i.e. all), use a dedicated expansion.
        let authorized_selectors =
            if request.series_selector.len() == 1 && request.series_selector[0].trim() == "*" {
                Self::expand_all_authorized_selectors(self, token.as_str()).await?
            } else {
                self.filter_authorized_selectors(token.as_str(), &request.series_selector)
                    .await?
            };

        debug!(
            "timeseries: authorized selectors={:?}, source={}",
            &authorized_selectors, src
        );

        if authorized_selectors.is_empty() {
            warn!(
                "timeseries: no authorized selectors for selectors={:?}, source={}",
                &request.series_selector, src
            );
            // No authorized selectors, return empty response
            return Ok(Response::new(TimeseriesResponse {
                timeseries: Vec::new(),
                since: Some(prost_wkt_types::Timestamp {
                    seconds: since.timestamp(),
                    nanos: since.timestamp_subsec_nanos() as i32,
                }),
            }));
        }

        // Get timeseries data only for authorized selectors
        let timeseries_data = self
            .db
            .get_timeseries(&authorized_selectors, &since)
            .await
            .map_err(|e| Status::internal(format!("Failed to get timeseries data: {e}")))?;

        // Convert to proto format
        let proto_timeseries: Vec<ProtoTimeseries> = timeseries_data
            .into_iter()
            .map(|ts: ProtoTimeseries| self.convert_to_proto_timeseries(ts))
            .collect();

        debug!(
            "timeseries: response {} series, selectors={:?}, source={}",
            proto_timeseries.len(),
            &authorized_selectors,
            src
        );

        Ok(Response::new(TimeseriesResponse {
            timeseries: proto_timeseries,
            since: Some(prost_wkt_types::Timestamp {
                seconds: since.timestamp(),
                nanos: since.timestamp_subsec_nanos() as i32,
            }),
        }))
    }

    // Helper method to filter selectors based on token permissions.
    // For non-"*" selectors, this expands wildcards in the input selectors and then
    // intersects them with the allowed patterns derived from the token's permissions.
    async fn filter_authorized_selectors(
        &self,
        token: &str,
        selectors: &[String],
    ) -> Result<Vec<String>, Status> {
        // Step 1: Expand request selectors.
        // For selectors without wildcards, push them directly.
        // For wildcards, query the DB to replace with concrete IDs.
        let mut expanded_request = HashSet::new();
        for selector in selectors {
            let parts: Vec<&str> = selector.split('/').filter(|s| !s.is_empty()).collect();
            if parts.is_empty() || parts[0] != "lb" {
                continue;
            }
            // If there are no wildcards, add as-is.
            if !selector.contains('*') {
                expanded_request.insert(selector.clone());
                continue;
            }
            // Expand loadbalancer wildcard: pattern "/lb/*"
            if parts.len() >= 2 && parts[1] == "*" {
                if let Ok(lbs) = self.db.list_loadbalancers().await {
                    for lb in lbs {
                        let concrete = selector.replace("/lb/*", &format!("/lb/{}", lb.id));
                        expanded_request.insert(concrete);
                    }
                }
            }
            // Expand reservation wildcard: pattern "/lb/{reservation_id}/session/*"
            if parts.len() >= 4 && parts[2] == "session" && parts[3] == "*" {
                if let Ok(reservation_id) = parts[1].parse::<i64>() {
                    if let Ok(session_list) = self.db.get_reservation_sessions(reservation_id).await
                    {
                        for sess in session_list {
                            let concrete = selector.replace(
                                &format!("/lb/{}/session/*", reservation_id),
                                &format!("/lb/{}/session/{}", reservation_id, sess.id),
                            );
                            expanded_request.insert(concrete);
                        }
                    }
                }
            }
        }

        // Step 2: Convert token permissions into allowed selector patterns.
        let token_details = self
            .db
            .get_token_details(token)
            .await
            .map_err(|e| Status::permission_denied(format!("permission denied: {e}")))?;
        let mut allowed_patterns = Vec::new();
        if token_details
            .as_ref()
            .map(|td| {
                td.permissions
                    .iter()
                    .any(|p| matches!(p.resource, Resource::All))
            })
            .unwrap_or(false)
        {
            return Ok(expanded_request.into_iter().collect());
        }
        if let Some(td) = token_details {
            // Fetch all reservations once for efficiency
            let all_reservations = self.db.list_reservations().await.unwrap_or_default();

            for perm in td.permissions {
                match perm.resource {
                    Resource::LoadBalancer(lb_id) => {
                        // Permission for a loadbalancer grants access to all its reservations
                        for res in all_reservations.iter().filter(|r| r.loadbalancer_id == lb_id) {
                            allowed_patterns.push(format!("/lb/{}/", res.id));
                        }
                    }
                    Resource::Reservation(res_id) => {
                        allowed_patterns.push(format!("/lb/{}/", res_id));
                    }
                    Resource::Session(session_id) => {
                        allowed_patterns.push(format!("/session/{session_id}"));
                    }
                    _ => {}
                }
            }
        }

        // Step 3: Intersection: a concrete selector is authorized if it matches one of the allowed patterns.
        let mut authorized = Vec::new();
        'outer: for req in expanded_request {
            for pattern in &allowed_patterns {
                if pattern.contains("/session/") {
                    if req.contains(pattern) {
                        authorized.push(req);
                        continue 'outer;
                    }
                } else if req.starts_with(pattern) {
                    authorized.push(req);
                    continue 'outer;
                }
            }
        }

        Ok(authorized)
    }

    // Helper method to expand "*" (all selectors) based solely on token permissions.
    // This method returns a list of concrete selectors that the token has read-only access to.
    async fn expand_all_authorized_selectors(&self, token: &str) -> Result<Vec<String>, Status> {
        let mut allowed = Vec::new();
        // First, check if the token has global permission.
        let token_details = self
            .db
            .get_token_details(token)
            .await
            .map_err(|e| Status::permission_denied(format!("permission denied: {e}")))?;
        if token_details
            .as_ref()
            .map(|td| {
                td.permissions
                    .iter()
                    .any(|p| matches!(p.resource, Resource::All))
            })
            .unwrap_or(false)
        {
            // Global permission: return selector with wildcard for loadbalancers.
            allowed.push("/lb/*".to_string());
            return Ok(allowed);
        }
        // Otherwise, expand based on specific permissions.
        // Fetch reservations once for efficiency
        let all_reservations = self.db.list_reservations().await.unwrap_or_default();

        if let Ok(lbs) = self.db.list_loadbalancers().await {
            for lb in lbs {
                let (ok, _) = self
                    .validate_token(
                        token,
                        Resource::LoadBalancer(lb.id),
                        PermissionType::ReadOnly,
                    )
                    .await?;
                if ok {
                    // Permission for LB grants access to all its reservations
                    for res in all_reservations.iter().filter(|r| r.loadbalancer_id == lb.id) {
                        allowed.push(format!("/lb/{}", res.id));
                    }
                } else {
                    // Check individual reservations for this loadbalancer
                    let lb_res: Vec<_> = all_reservations
                        .iter()
                        .filter(|r| r.loadbalancer_id == lb.id)
                        .collect();
                    for res in lb_res {
                        let (ok, _) = self
                            .validate_token(
                                token,
                                Resource::Reservation(res.id),
                                PermissionType::ReadOnly,
                            )
                            .await?;
                        if ok {
                            allowed.push(format!("/lb/{}", res.id));
                        } else if let Ok(sessions) =
                            self.db.get_reservation_sessions(res.id).await
                        {
                            for sess in sessions {
                                let (ok, _) = self
                                    .validate_token(
                                        token,
                                        Resource::Session(sess.id),
                                        PermissionType::ReadOnly,
                                    )
                                    .await?;
                                if ok {
                                    allowed.push(format!(
                                        "/lb/{}/session/{}",
                                        res.id, sess.id
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(allowed)
    }

    // Helper method to convert TimeseriesData to ProtoTimeseries.
    // Currently a passthrough conversion.
    fn convert_to_proto_timeseries(&self, ts: ProtoTimeseries) -> ProtoTimeseries {
        ts
    }
}

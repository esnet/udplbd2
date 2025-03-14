/// API handlers for token management
use tonic::{Request, Response, Status};

use super::super::service::LoadBalancerService;
use crate::db::{
    models::{Permission, PermissionType, Resource},
    LoadBalancerDB,
};
use crate::proto::loadbalancer::v1::token_permission::{
    PermissionType as ProtoPermissionType, ResourceType,
};
use crate::proto::loadbalancer::v1::{
    CreateTokenReply, CreateTokenRequest, ListChildTokensReply, ListChildTokensRequest,
    ListTokenPermissionsReply, ListTokenPermissionsRequest, RevokeTokenReply, RevokeTokenRequest,
    TokenDetails, TokenPermission, TokenSelector,
};

impl LoadBalancerService {
    async fn resolve_token(
        &self,
        selector: Option<TokenSelector>,
        request_token: String,
    ) -> Result<i64, Status> {
        match selector {
            Some(TokenSelector { token_selector }) => match token_selector {
                Some(crate::proto::loadbalancer::v1::token_selector::TokenSelector::Id(0)) => self
                    .db
                    .get_token_id(&request_token)
                    .await
                    .map_err(|e| Status::internal(format!("Failed to get token ID: {e}")))?
                    .ok_or_else(|| Status::not_found("Token not found")),
                Some(crate::proto::loadbalancer::v1::token_selector::TokenSelector::Id(id)) => {
                    Ok(id as i64)
                }
                Some(crate::proto::loadbalancer::v1::token_selector::TokenSelector::Token(
                    token,
                )) => self
                    .db
                    .get_token_id(&token)
                    .await
                    .map_err(|e| Status::internal(format!("Failed to get token ID: {e}")))?
                    .ok_or_else(|| Status::not_found("Token not found")),
                None => self
                    .db
                    .get_token_id(&request_token)
                    .await
                    .map_err(|e| Status::internal(format!("Failed to get token ID: {e}")))?
                    .ok_or_else(|| Status::not_found("Token not found")),
            },
            None => self
                .db
                .get_token_id(&request_token)
                .await
                .map_err(|e| Status::internal(format!("Failed to get token ID: {e}")))?
                .ok_or_else(|| Status::not_found("Token not found")),
        }
    }

    pub(crate) async fn handle_create_token(
        &self,
        request: Request<CreateTokenRequest>,
    ) -> Result<Response<CreateTokenReply>, Status> {
        let parent_token = Self::extract_token(request.metadata())?;
        let request = request.into_inner();
        let mut permissions = Vec::new();

        // Get parent token's permissions to validate child permissions
        let parent_details = self
            .db
            .get_token_details(&parent_token)
            .await
            .map_err(|e| Status::internal(format!("Failed to get parent token details: {e}")))?
            .ok_or_else(|| Status::not_found("Parent token not found"))?;

        for perm in request.permissions {
            let mut has_permission = false;
            let resource = match perm.resource_type() {
                ResourceType::All => Resource::All,
                ResourceType::LoadBalancer => {
                    if perm.resource_id.is_empty() {
                        return Err(Status::invalid_argument(
                            "Resource ID required for LOAD_BALANCER permission",
                        ));
                    }
                    Resource::LoadBalancer(
                        perm.resource_id
                            .parse()
                            .map_err(|_| Status::invalid_argument("Invalid load balancer ID"))?,
                    )
                }
                ResourceType::Reservation => {
                    if perm.resource_id.is_empty() {
                        return Err(Status::invalid_argument(
                            "Resource ID required for RESERVATION permission",
                        ));
                    }
                    Resource::Reservation(
                        perm.resource_id
                            .parse()
                            .map_err(|_| Status::invalid_argument("Invalid reservation ID"))?,
                    )
                }
                ResourceType::Session => {
                    if perm.resource_id.is_empty() {
                        return Err(Status::invalid_argument(
                            "Resource ID required for SESSION permission",
                        ));
                    }
                    Resource::Session(
                        perm.resource_id
                            .parse()
                            .map_err(|_| Status::invalid_argument("Invalid session ID"))?,
                    )
                }
            };

            let permission = PermissionType::from(perm.permission());

            // Check if parent has sufficient permission for this resource
            for parent_perm in &parent_details.permissions {
                let has_resource_permission = match (&parent_perm.resource, &resource) {
                    // Global admin can grant anything
                    (Resource::All, _) => true,
                    // Resource-specific permissions must match exactly and have sufficient level
                    (Resource::LoadBalancer(id1), Resource::LoadBalancer(id2)) => id1 == id2,
                    (Resource::Reservation(id1), Resource::Reservation(id2)) => id1 == id2,
                    (Resource::Session(id1), Resource::Session(id2)) => id1 == id2,
                    // LoadBalancer permission implies permission on its reservations
                    (Resource::LoadBalancer(lb_id), Resource::Reservation(res_id)) => {
                        // Check if reservation belongs to this loadbalancer
                        if let Ok(res) = sqlx::query!(
                            "SELECT loadbalancer_id FROM reservation WHERE id = ?1",
                            res_id
                        )
                        .fetch_optional(&self.db.read_pool)
                        .await
                        {
                            res.map(|r| r.loadbalancer_id == *lb_id).unwrap_or(false)
                        } else {
                            false
                        }
                    }
                    // LoadBalancer/Reservation permission implies permission on its sessions
                    (Resource::LoadBalancer(lb_id), Resource::Session(session_id)) => {
                        // Check if session belongs to this loadbalancer
                        if let Ok(res) = sqlx::query!(
                            r#"
                            SELECT r.loadbalancer_id
                            FROM session s
                            JOIN reservation r ON r.id = s.reservation_id
                            WHERE s.id = ?1
                            "#,
                            session_id
                        )
                        .fetch_optional(&self.db.read_pool)
                        .await
                        {
                            res.map(|r| r.loadbalancer_id == *lb_id).unwrap_or(false)
                        } else {
                            false
                        }
                    }
                    (Resource::Reservation(res_id), Resource::Session(session_id)) => {
                        // Check if session belongs to this reservation
                        if let Ok(res) = sqlx::query!(
                            "SELECT reservation_id FROM session WHERE id = ?1",
                            session_id
                        )
                        .fetch_optional(&self.db.read_pool)
                        .await
                        {
                            res.map(|r| r.reservation_id == *res_id).unwrap_or(false)
                        } else {
                            false
                        }
                    }
                    _ => false,
                };

                if has_resource_permission
                    && LoadBalancerDB::permission_implies(&parent_perm.permission, &permission)
                {
                    has_permission = true;
                    break;
                }
            }

            if !has_permission {
                return Err(Status::permission_denied(format!(
                    "Parent token does not have sufficient permission to grant {:?} on {:?}",
                    permission, resource
                )));
            }

            permissions.push(Permission {
                resource,
                permission,
            });
        }

        let new_token = self
            .db
            .create_token(&request.name, Some(&parent_token), permissions)
            .await
            .map_err(|e| Status::internal(format!("Failed to create token: {e}")))?;

        Ok(Response::new(CreateTokenReply { token: new_token }))
    }

    pub(crate) async fn handle_list_token_permissions(
        &self,
        request: Request<ListTokenPermissionsRequest>,
    ) -> Result<Response<ListTokenPermissionsReply>, Status> {
        let request_token = Self::extract_token(request.metadata())?;
        let request = request.into_inner();

        // Determine which token ID to use
        let target_token_id = self
            .resolve_token(request.target, request_token.clone())
            .await?;

        // Get target token's details
        let details = self
            .db
            .get_token_details_by_id(target_token_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get token details: {e}")))?
            .ok_or_else(|| Status::not_found("Token not found"))?;

        // If the target token is not the request token, check permissions
        if target_token_id
            != self
                .db
                .get_token_id(&request_token)
                .await
                .map_err(|e| Status::internal(format!("Failed to get request token ID: {e}")))?
                .ok_or_else(|| Status::not_found("Request token not found"))?
        {
            // Get request token's permissions
            let request_token_details = self
                .db
                .get_token_details(&request_token)
                .await
                .map_err(|e| Status::internal(format!("Failed to get request token details: {e}")))?
                .ok_or_else(|| Status::not_found("Request token not found"))?;

            // Check if request token has permission to view the target token
            let has_permission = request_token_details.permissions.iter().any(|perm| {
                matches!(perm.resource, Resource::All)
                    && matches!(perm.permission, PermissionType::Update)
            });

            if !has_permission {
                // Check if the target token is a child of the request token
                let children = self
                    .db
                    .list_child_tokens(&request_token)
                    .await
                    .map_err(|e| Status::internal(format!("Failed to list child tokens: {e}")))?;

                let is_child = children.iter().any(|child| child.name == details.name);

                if !is_child {
                    return Err(Status::permission_denied(
                        "Token does not have permission to view requested token",
                    ));
                }
            }
        }

        let proto_permissions: Vec<TokenPermission> = details
            .permissions
            .into_iter()
            .map(|perm| {
                let (resource_type, resource_id) = match perm.resource {
                    Resource::All => (ResourceType::All, String::new()),
                    Resource::LoadBalancer(id) => (ResourceType::LoadBalancer, id.to_string()),
                    Resource::Reservation(id) => (ResourceType::Reservation, id.to_string()),
                    Resource::Session(id) => (ResourceType::Session, id.to_string()),
                };

                TokenPermission {
                    resource_type: resource_type.into(),
                    resource_id,
                    permission: ProtoPermissionType::from(perm.permission).into(),
                }
            })
            .collect();

        Ok(Response::new(ListTokenPermissionsReply {
            token: Some(TokenDetails {
                name: details.name,
                permissions: proto_permissions,
                created_at: details.created_at.to_rfc3339(),
            }),
        }))
    }

    pub(crate) async fn handle_list_child_tokens(
        &self,
        request: Request<ListChildTokensRequest>,
    ) -> Result<Response<ListChildTokensReply>, Status> {
        let request_token = Self::extract_token(request.metadata())?;
        let request = request.into_inner();

        // Determine which token ID to use
        let parent_token_id = self
            .resolve_token(request.target, request_token.clone())
            .await?;

        // If the parent token is not the request token, check permissions
        let request_token_id = self
            .db
            .get_token_id(&request_token)
            .await
            .map_err(|e| Status::internal(format!("Failed to get request token ID: {e}")))?
            .ok_or_else(|| Status::not_found("Request token not found"))?;

        if parent_token_id != request_token_id {
            // Get request token's permissions
            let request_token_details = self
                .db
                .get_token_details_by_id(request_token_id)
                .await
                .map_err(|e| Status::internal(format!("Failed to get request token details: {e}")))?
                .ok_or_else(|| Status::not_found("Request token not found"))?;

            // Check if request token has permission to list child tokens of the parent token
            let has_permission = request_token_details.permissions.iter().any(|perm| {
                matches!(perm.resource, Resource::All)
                    && matches!(perm.permission, PermissionType::Update)
            });

            if !has_permission {
                return Err(Status::permission_denied(
                    "Token does not have permission to list child tokens of the requested token",
                ));
            }
        }

        let children = self
            .db
            .list_child_tokens_by_id(parent_token_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list child tokens: {e}")))?;

        let mut proto_tokens = Vec::new();
        for child in children {
            let mut proto_permissions = Vec::new();
            for perm in child.permissions {
                let (resource_type, resource_id) = match perm.resource {
                    Resource::All => (ResourceType::All, String::new()),
                    Resource::LoadBalancer(id) => (ResourceType::LoadBalancer, id.to_string()),
                    Resource::Reservation(id) => (ResourceType::Reservation, id.to_string()),
                    Resource::Session(id) => (ResourceType::Session, id.to_string()),
                };

                let permission_type = ProtoPermissionType::from(perm.permission);

                proto_permissions.push(TokenPermission {
                    resource_type: resource_type.into(),
                    resource_id,
                    permission: permission_type.into(),
                });
            }

            proto_tokens.push(TokenDetails {
                name: child.name,
                permissions: proto_permissions,
                created_at: child.created_at.to_rfc3339(),
            });
        }

        Ok(Response::new(ListChildTokensReply {
            tokens: proto_tokens,
        }))
    }

    pub(crate) async fn handle_revoke_token(
        &self,
        request: Request<RevokeTokenRequest>,
    ) -> Result<Response<RevokeTokenReply>, Status> {
        let request_token = Self::extract_token(request.metadata())?;
        let request = request.into_inner();

        // Determine which token ID to revoke
        let token_to_revoke_id = self
            .resolve_token(request.target, request_token.clone())
            .await?;

        // Get request token ID
        let request_token_id = self
            .db
            .get_token_id(&request_token)
            .await
            .map_err(|e| Status::internal(format!("Failed to get request token ID: {e}")))?
            .ok_or_else(|| Status::not_found("Request token not found"))?;

        // Get request token's permissions
        let request_token_details = self
            .db
            .get_token_details_by_id(request_token_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get request token details: {e}")))?
            .ok_or_else(|| Status::not_found("Request token not found"))?;

        // Check if request token has permission to revoke the target token
        let mut has_permission = request_token_details.permissions.iter().any(|perm| {
            matches!(perm.resource, Resource::All)
                && matches!(perm.permission, PermissionType::Update)
        });

        if !has_permission {
            // Check if the token to revoke is a child of the request token
            let children = self
                .db
                .list_child_tokens_by_id(request_token_id)
                .await
                .map_err(|e| Status::internal(format!("Failed to list child tokens: {e}")))?;

            has_permission = children.iter().any(|child| child.id == token_to_revoke_id);
        }

        if !has_permission {
            return Err(Status::permission_denied(
                "Token does not have permission to revoke the requested token",
            ));
        }

        self.db
            .revoke_token_by_id(token_to_revoke_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to revoke token: {e}")))?;

        Ok(Response::new(RevokeTokenReply {}))
    }
}

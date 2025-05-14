// SPDX-License-Identifier: BSD-3-Clause-LBNL
/// Struct that holds the state required to operate the gRPC server (LoadBalancerDB, ReservationManager)
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::{metadata::MetadataMap, Status};

use crate::db::models::{PermissionType, Resource};
use crate::db::LoadBalancerDB;

#[derive(Clone)]
pub struct LoadBalancerService {
    pub(crate) db: Arc<LoadBalancerDB>,
    pub(crate) manager: Arc<Mutex<ReservationManager>>,
    pub(crate) sync_address: SocketAddr,
}

impl LoadBalancerService {
    #[must_use]
    pub fn new(
        db: Arc<LoadBalancerDB>,
        manager: Arc<Mutex<ReservationManager>>,
        sync_addr: SocketAddr,
    ) -> Self {
        Self {
            db,
            manager,
            sync_address: sync_addr,
        }
    }

    pub(crate) async fn validate_token(
        &self,
        token: &str,
        resource: Resource,
        permission: PermissionType,
    ) -> Result<bool, Status> {
        self.db
            .validate_token(token, resource, permission)
            .await
            .map_err(|e| Status::internal(format!("Token validation failed: {e}")))
    }

    pub(crate) fn extract_token(metadata: &MetadataMap) -> Result<String, Status> {
        let auth = metadata
            .get("authorization")
            .ok_or_else(|| Status::unauthenticated("Missing authorization token"))?
            .to_str()
            .map_err(|_| Status::invalid_argument("Invalid authorization token"))?;

        match auth.strip_prefix("Bearer ") {
            Some(token) => Ok(token.to_owned()),
            None => Err(Status::invalid_argument(
                "Invalid token format: missing Bearer prefix",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::metadata::MetadataValue;

    #[test]
    fn test_extract_token() {
        let mut metadata = MetadataMap::new();
        metadata.insert(
            "authorization",
            MetadataValue::from_static("Bearer test-token"),
        );
        assert_eq!(
            LoadBalancerService::extract_token(&metadata).unwrap(),
            "test-token"
        );
    }

    #[test]
    fn test_extract_token_missing() {
        let metadata = MetadataMap::new();
        assert!(LoadBalancerService::extract_token(&metadata).is_err());
    }

    #[test]
    fn test_extract_token_invalid_format() {
        let mut metadata = MetadataMap::new();
        metadata.insert("authorization", MetadataValue::from_static("test-token"));
        assert!(LoadBalancerService::extract_token(&metadata).is_err());
    }
}

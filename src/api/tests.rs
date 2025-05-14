// SPDX-License-Identifier: BSD-3-Clause-LBNL
/// API handler tests
use crate::proto::loadbalancer::v1::{
    CreateTokenRequest, RegisterRequest, ReserveLoadBalancerRequest,
};
use crate::snp4::client::MultiSNP4Client;
use tokio::sync::Mutex;
use tonic::metadata::MetadataValue;
use tonic::Request;

use std::sync::Arc;
use std::time::Duration;

use crate::db::tests::setup_db;
use crate::reservation::ReservationManager;

use super::service::LoadBalancerService;

/// Creates a test service instance with an in-memory database
pub async fn create_test_service() -> LoadBalancerService {
    let db = Arc::new(setup_db().await);
    let clients = MultiSNP4Client::new(vec![]);

    let manager = Arc::new(Mutex::new(ReservationManager::new(
        db.clone(),
        clients,
        Duration::from_secs(1),
        Duration::from_millis(1000),
        "00:1A:2B:3C:4D:5E".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )));
    LoadBalancerService::new(db, manager, "127.0.0.1:0".parse().unwrap())
}

#[tokio::test]
async fn test_create_token_invalid_parent() {
    let service = create_test_service().await;
    let mut request = Request::new(CreateTokenRequest {
        name: "test".to_string(),
        permissions: vec![],
    });
    request
        .metadata_mut()
        .insert("authorization", MetadataValue::from_static("invalid"));

    let result = service.handle_create_token(request).await;
    assert!(result.is_err());
}

// Add more tests as needed

#[tokio::test]
async fn test_register_invalid_token() {
    let service = create_test_service().await;
    let mut request = Request::new(RegisterRequest {
        lb_id: "1".to_string(),
        name: "test".to_string(),
        ip_address: "127.0.0.1".to_string(),
        udp_port: 8000,
        port_range: 100,
        weight: 1.0,
        min_factor: 0.0,
        max_factor: 1.0,
        keep_lb_header: false,
    });
    request
        .metadata_mut()
        .insert("authorization", MetadataValue::from_static("invalid"));

    let result = service.handle_register(request).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_reserve_load_balancer_invalid_token() {
    let service = create_test_service().await;
    let mut request = Request::new(ReserveLoadBalancerRequest {
        until: None,
        sender_addresses: vec![],
        name: "test".to_string(),
    });
    request
        .metadata_mut()
        .insert("authorization", MetadataValue::from_static("invalid"));

    let result = service.handle_reserve_load_balancer(request).await;
    assert!(result.is_err());
}

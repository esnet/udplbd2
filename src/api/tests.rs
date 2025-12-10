// SPDX-License-Identifier: BSD-3-Clause-LBNL
/// API handler tests
use crate::config::Config;
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

/// Creates a test service instance with an in-memory database and custom config
pub async fn create_test_service_with_config(config: Config) -> (LoadBalancerService, i64) {
    let db = Arc::new(setup_db().await);
    let clients = MultiSNP4Client::new(vec![]);

    let manager = Arc::new(Mutex::new(ReservationManager::new(
        db.clone(),
        clients,
        Duration::from_secs(1),
        Duration::from_millis(1000),
        "00:1A:2B:3C:4D:5E".parse().unwrap(),
        "127.0.0.1:0".parse().ok(),
        "[::1]:0".parse().ok(),
    )));

    // Create a root token for testing
    db.create_admin_token("test").await.unwrap();

    // Create a reservation without sessions (we'll register them in tests)
    let (_, reservation) =
        crate::db::tests::setup_test_loadbalancer_with_sessions(&db, vec![]).await;

    let config = Arc::new(config);
    (
        LoadBalancerService::new(db, manager, config),
        reservation.id,
    )
}

/// Creates a test service instance with an in-memory database using default config
/// Returns a service with a reservation that has 2 default sessions
pub async fn create_test_service() -> (LoadBalancerService, i64, i64) {
    let db = Arc::new(setup_db().await);
    let clients = MultiSNP4Client::new(vec![]);

    let manager = Arc::new(Mutex::new(ReservationManager::new(
        db.clone(),
        clients,
        Duration::from_secs(1),
        Duration::from_millis(1000),
        "00:1A:2B:3C:4D:5E".parse().unwrap(),
        "127.0.0.1:0".parse().ok(),
        "[::1]:0".parse().ok(),
    )));

    // Create a reservation with default sessions (for backward compatibility with existing tests)
    let (_, reservation) = crate::db::tests::setup_test_loadbalancer(&db).await;
    let sessions = db.get_reservation_sessions(reservation.id).await.unwrap();
    let session_id = sessions[0].id;

    let config = Arc::new(Config::turmoil());
    (
        LoadBalancerService::new(db, manager, config),
        reservation.id,
        session_id,
    )
}

#[tokio::test]
async fn test_create_token_invalid_parent() {
    let (service, _, _) = create_test_service().await;
    let mut request = Request::new(CreateTokenRequest {
        name: "test".to_string(),
        permissions: vec![],
    });
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::from_static("Bearer invalid"),
    );

    let result = service.handle_create_token(request).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("not found"),
        "Expected error to contain 'not found', got: {}",
        err
    );
}

#[tokio::test]
async fn test_get_load_balancer_invalid_token() {
    let (service, reservation_id, _) = create_test_service().await;
    let mut request = Request::new(crate::proto::loadbalancer::v1::GetLoadBalancerRequest {
        lb_id: reservation_id.to_string(),
    });
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::from_static("Bearer invalid"),
    );
    let result = service.handle_get_load_balancer(request).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("permission"),
        "Expected error to contain 'permission', got: {}",
        err
    );
}

#[tokio::test]
async fn test_load_balancer_status_invalid_token() {
    let (service, reservation_id, _) = create_test_service().await;
    let mut request = Request::new(crate::proto::loadbalancer::v1::LoadBalancerStatusRequest {
        lb_id: reservation_id.to_string(),
    });
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::from_static("Bearer invalid"),
    );
    let result = service.handle_load_balancer_status(request).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("permission"),
        "Expected error to contain 'permission', got: {}",
        err
    );
}

#[tokio::test]
async fn test_free_load_balancer_invalid_token() {
    let (service, reservation_id, _) = create_test_service().await;
    let mut request = Request::new(crate::proto::loadbalancer::v1::FreeLoadBalancerRequest {
        lb_id: reservation_id.to_string(),
    });
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::from_static("Bearer invalid"),
    );
    let result = service.handle_free_load_balancer(request).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("permission"));
}

#[tokio::test]
async fn test_add_senders_invalid_token() {
    let (service, reservation_id, _) = create_test_service().await;
    let mut request = Request::new(crate::proto::loadbalancer::v1::AddSendersRequest {
        lb_id: reservation_id.to_string(),
        sender_addresses: vec![],
    });
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::from_static("Bearer invalid"),
    );
    let result = service.handle_add_senders(request).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("permission"),
        "Expected error to contain 'permission', got: {}",
        err
    );
}

#[tokio::test]
async fn test_remove_senders_invalid_token() {
    let (service, reservation_id, _) = create_test_service().await;
    let mut request = Request::new(crate::proto::loadbalancer::v1::RemoveSendersRequest {
        lb_id: reservation_id.to_string(),
        sender_addresses: vec![],
    });
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::from_static("Bearer invalid"),
    );
    let result = service.handle_remove_senders(request).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("permission"),
        "Expected error to contain 'permission', got: {}",
        err
    );
}

#[tokio::test]
async fn test_register_invalid_token() {
    let (service, reservation_id, _) = create_test_service().await;
    let mut request = Request::new(RegisterRequest {
        lb_id: reservation_id.to_string(),
        name: "test".to_string(),
        ip_address: "127.0.0.1".to_string(),
        udp_port: 8000,
        port_range: 100,
        weight: 1.0,
        min_factor: 0.0,
        max_factor: 1.0,
        keep_lb_header: false,
        slot_demands: Vec::new(),
    });
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::from_static("Bearer invalid"),
    );

    let result = service.handle_register(request).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("permission"),
        "Expected error to contain 'permission', got: {}",
        err
    );
}

#[tokio::test]
async fn test_reserve_load_balancer_invalid_token() {
    let (service, _, _) = create_test_service().await;
    let mut request = Request::new(ReserveLoadBalancerRequest {
        until: None,
        sender_addresses: vec![],
        name: "test".to_string(),
        ..Default::default()
    });
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::from_static("Bearer invalid"),
    );

    let result = service.handle_reserve_load_balancer(request).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("permission"),
        "Expected error to contain 'permission', got: {}",
        err
    );
}

#[tokio::test]
async fn test_set_slot_demands_invalid_token() {
    let (service, reservation_id, _) = create_test_service().await;
    let mut request = Request::new(crate::proto::loadbalancer::v1::SetSlotDemandsRequest {
        lb_id: reservation_id.to_string(),
        slot_constraints: Vec::new(),
    });
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::from_static("Bearer invalid"),
    );
    let result = service.handle_set_slot_demands(request).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("permission"));
}

#[tokio::test]
async fn test_deregister_invalid_token() {
    let (service, reservation_id, session_id) = create_test_service().await;
    let mut request = Request::new(crate::proto::loadbalancer::v1::DeregisterRequest {
        lb_id: reservation_id.to_string(),
        session_id: session_id.to_string(),
    });
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::from_static("Bearer invalid"),
    );
    let result = service.handle_deregister(request).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("permission"));
}

#[tokio::test]
async fn test_send_state_invalid_token() {
    let (service, reservation_id, session_id) = create_test_service().await;
    let mut request = Request::new(crate::proto::loadbalancer::v1::SendStateRequest {
        lb_id: reservation_id.to_string(),
        session_id: session_id.to_string(),
        timestamp: None,
        fill_percent: 0.0,
        control_signal: 0.0,
        is_ready: false,
        total_events_recv: 0,
        total_events_reassembled: 0,
        total_events_reassembly_err: 0,
        total_events_dequeued: 0,
        total_event_enqueue_err: 0,
        total_bytes_recv: 0,
        total_packets_recv: 0,
    });
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::from_static("Bearer invalid"),
    );
    let result = service.handle_send_state(request).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("permission"),
        "Expected error to contain 'permission', got: {}",
        err
    );
}

#[tokio::test]
async fn test_overview_invalid_token() {
    let (service, _, _) = create_test_service().await;
    let mut request = Request::new(crate::proto::loadbalancer::v1::OverviewRequest {});
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::from_static("Bearer invalid"),
    );
    let result = service.handle_overview(request).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("permission"),
        "Expected error to contain 'permission', got: {}",
        err
    );
}

#[tokio::test]
async fn test_timeseries_invalid_token() {
    let (service, _, _) = create_test_service().await;
    let mut request = Request::new(crate::proto::loadbalancer::v1::TimeseriesRequest {
        series_selector: vec!["/lb/1/*".to_string()],
        since: None,
    });
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::from_static("Bearer invalid"),
    );
    let result = service.handle_timeseries(request).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("permission"),
        "Expected error to contain 'permission', got: {}",
        err
    );
}

#[tokio::test]
async fn test_version_invalid_token() {
    let (service, _, _) = create_test_service().await;
    let mut request = Request::new(crate::proto::loadbalancer::v1::VersionRequest {});
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::from_static("Bearer invalid"),
    );
    let result = service.handle_version(request).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("permission"),
        "Expected error to contain 'permission', got: {}",
        err
    );
}

#[tokio::test]
async fn test_list_token_permissions_invalid_token() {
    let (service, _, _) = create_test_service().await;
    let mut request = Request::new(
        crate::proto::loadbalancer::v1::ListTokenPermissionsRequest {
            target: Some(crate::proto::loadbalancer::v1::TokenSelector {
                token_selector: Some(
                    crate::proto::loadbalancer::v1::token_selector::TokenSelector::Token(
                        "test".to_string(),
                    ),
                ),
            }),
        },
    );
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::from_static("Bearer invalid"),
    );
    let result = service.handle_list_token_permissions(request).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("not found"),
        "Expected error to contain 'not found', got: {}",
        err
    );
}

#[tokio::test]
async fn test_list_child_tokens_invalid_token() {
    let (service, _, _) = create_test_service().await;
    let mut request = Request::new(crate::proto::loadbalancer::v1::ListChildTokensRequest {
        target: Some(crate::proto::loadbalancer::v1::TokenSelector {
            token_selector: Some(
                crate::proto::loadbalancer::v1::token_selector::TokenSelector::Token(
                    "test".to_string(),
                ),
            ),
        }),
    });
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::from_static("Bearer invalid"),
    );
    let result = service.handle_list_child_tokens(request).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("not found"),
        "Expected error to contain 'not found', got: {}",
        err
    );
}

#[tokio::test]
async fn test_revoke_token_invalid_token() {
    let (service, _, _) = create_test_service().await;
    let mut request = Request::new(crate::proto::loadbalancer::v1::RevokeTokenRequest {
        target: Some(crate::proto::loadbalancer::v1::TokenSelector {
            token_selector: Some(
                crate::proto::loadbalancer::v1::token_selector::TokenSelector::Token(
                    "test".to_string(),
                ),
            ),
        }),
    });
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::from_static("Bearer invalid"),
    );
    let result = service.handle_revoke_token(request).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("not found"),
        "Expected error to contain 'not found', got: {}",
        err
    );
}

// IP Validation Tests

#[tokio::test]
async fn test_register_ip_validation_loopback_denied() {
    let mut config = Config::turmoil();
    config.server.allow_loopback = false;
    let (service, reservation_id) = create_test_service_with_config(config).await;

    // Test IPv4 loopback
    let mut request = Request::new(RegisterRequest {
        lb_id: reservation_id.to_string(),
        name: "test-session-v4".to_string(),
        ip_address: "127.0.0.1".to_string(),
        udp_port: 8000,
        port_range: 100,
        weight: 1.0,
        min_factor: 0.0,
        max_factor: 1.0,
        keep_lb_header: false,
        slot_demands: Vec::new(),
    });
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from("Bearer test").unwrap(),
    );

    let result = service.handle_register(request).await;
    assert!(
        result.is_err(),
        "Registration should fail for IPv4 loopback when allow_loopback is false"
    );
    assert!(result.unwrap_err().message().contains("loopback"));

    // Test IPv6 loopback
    let mut request = Request::new(RegisterRequest {
        lb_id: reservation_id.to_string(),
        name: "test-session-v6".to_string(),
        ip_address: "::1".to_string(),
        udp_port: 8000,
        port_range: 100,
        weight: 1.0,
        min_factor: 0.0,
        max_factor: 1.0,
        keep_lb_header: false,
        slot_demands: Vec::new(),
    });
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from("Bearer test").unwrap(),
    );

    let result = service.handle_register(request).await;
    assert!(
        result.is_err(),
        "Registration should fail for IPv6 loopback when allow_loopback is false"
    );
    assert!(result.unwrap_err().message().contains("loopback"));
}

#[tokio::test]
async fn test_register_ip_validation_private_denied() {
    let mut config = Config::turmoil();
    config.server.allow_private = false;
    config.server.allow_loopback = true; // Allow loopback so we only test private
    let (service, reservation_id) = create_test_service_with_config(config).await;

    let test_cases = vec![
        // RFC 1918 private ranges
        ("10.0.0.1", "RFC 1918: 10.0.0.0/8"),
        ("10.255.255.254", "RFC 1918: 10.0.0.0/8 (upper bound)"),
        ("172.16.0.1", "RFC 1918: 172.16.0.0/12"),
        ("172.31.255.254", "RFC 1918: 172.16.0.0/12 (upper bound)"),
        ("192.168.1.1", "RFC 1918: 192.168.0.0/16"),
        ("192.168.255.254", "RFC 1918: 192.168.0.0/16 (upper bound)"),
        // Shared address space (RFC 6598)
        ("100.64.0.1", "RFC 6598: Shared address space 100.64.0.0/10"),
        (
            "100.127.255.254",
            "RFC 6598: Shared address space (upper bound)",
        ),
        // Link-local (RFC 3927)
        ("169.254.0.1", "RFC 3927: Link-local 169.254.0.0/16"),
        ("169.254.255.254", "RFC 3927: Link-local (upper bound)"),
        // Documentation addresses (RFC 5737)
        ("192.0.2.1", "RFC 5737: Documentation 192.0.2.0/24"),
        ("198.51.100.1", "RFC 5737: Documentation 198.51.100.0/24"),
        ("203.0.113.1", "RFC 5737: Documentation 203.0.113.0/24"),
        // Benchmarking (RFC 2544)
        ("198.18.0.1", "RFC 2544: Benchmarking 198.18.0.0/15"),
        ("198.19.255.254", "RFC 2544: Benchmarking (upper bound)"),
        // IPv6 addresses
        ("fc00::1", "RFC 4193: IPv6 ULA fc00::/7"),
        (
            "fdff:ffff:ffff:ffff:ffff:ffff:ffff:fffe",
            "RFC 4193: IPv6 ULA (upper bound)",
        ),
        ("fe80::1", "RFC 4291: IPv6 link-local fe80::/10"),
        (
            "febf:ffff:ffff:ffff:ffff:ffff:ffff:fffe",
            "RFC 4291: IPv6 link-local (upper bound)",
        ),
        ("2001:db8::1", "RFC 3849: IPv6 documentation 2001:db8::/32"),
    ];

    for (ip, description) in test_cases {
        let mut request = Request::new(RegisterRequest {
            lb_id: reservation_id.to_string(),
            name: format!("test-session-{}", ip.replace([':', '.'], "-")),
            ip_address: ip.to_string(),
            udp_port: 8000,
            port_range: 100,
            weight: 1.0,
            min_factor: 0.0,
            max_factor: 1.0,
            keep_lb_header: false,
            slot_demands: Vec::new(),
        });
        request.metadata_mut().insert(
            "authorization",
            MetadataValue::try_from("Bearer test").unwrap(),
        );

        let result = service.handle_register(request).await;
        assert!(
            result.is_err(),
            "Registration should fail for {} ({})",
            description,
            ip
        );
        assert!(
            result.unwrap_err().message().contains("private"),
            "Error should mention 'private' for {} ({})",
            description,
            ip
        );
    }
}

#[tokio::test]
async fn test_register_ip_validation_private_allowed() {
    let mut config = Config::turmoil();
    config.server.allow_private = true;
    config.server.allow_loopback = true;
    let (service, reservation_id) = create_test_service_with_config(config).await;

    let test_cases = vec![
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.100",
        "fc00::1",
        "fe80::1",
    ];

    for ip in test_cases {
        let mut request = Request::new(RegisterRequest {
            lb_id: reservation_id.to_string(),
            name: format!("test-session-{}", ip.replace([':', '.'], "-")),
            ip_address: ip.to_string(),
            udp_port: 8000,
            port_range: 100,
            weight: 1.0,
            min_factor: 0.0,
            max_factor: 1.0,
            keep_lb_header: false,
            slot_demands: Vec::new(),
        });
        request.metadata_mut().insert(
            "authorization",
            MetadataValue::try_from("Bearer test").unwrap(),
        );

        let result = service.handle_register(request).await;
        // MAC address lookup will fail for these test IPs, but that's OK - it means the IP validation passed
        if result.is_err() {
            let err_stat = result.unwrap_err();
            assert!(
                err_stat.message().contains("MAC") || err_stat.message().contains("mac"),
                "Error should be about MAC address lookup, not IP validation, for {}: {}",
                ip,
                err_stat.message()
            );
        }
    }
}

#[tokio::test]
async fn test_register_ip_validation_public_allowed() {
    let mut config = Config::turmoil();
    config.server.allow_private = false;
    config.server.allow_loopback = false;
    let (service, reservation_id) = create_test_service_with_config(config).await;

    let mut request = Request::new(RegisterRequest {
        lb_id: reservation_id.to_string(),
        name: "test-session-public".to_string(),
        ip_address: "8.8.8.8".to_string(),
        udp_port: 8000,
        port_range: 100,
        weight: 1.0,
        min_factor: 0.0,
        max_factor: 1.0,
        keep_lb_header: false,
        slot_demands: Vec::new(),
    });
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from("Bearer test").unwrap(),
    );

    let result = service.handle_register(request).await;
    if result.is_err() {
        let err_stat = result.unwrap_err();
        assert!(
            err_stat.message().contains("MAC") || err_stat.message().contains("mac"),
            "Error should be about MAC address lookup, not IP validation, for 8.8.8.8: {}",
            err_stat.message()
        );
    }
}

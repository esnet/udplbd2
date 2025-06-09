// SPDX-License-Identifier: BSD-3-Clause-LBNL
use crate::config::{Config, DatabaseConfig};
#[cfg(test)]
use crate::db::*;
use chrono::Duration;
use chrono::{Duration as ChronoDuration, Utc};
use macaddr::MacAddr6;
use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tempfile::tempdir;
use uuid::Uuid;

pub async fn setup_db() -> LoadBalancerDB {
    let test_id = Uuid::new_v4();
    let path = format!("/tmp/udplbd-test-{test_id}.db");
    LoadBalancerDB::new(&path).await.unwrap()
}

impl Drop for LoadBalancerDB {
    fn drop(&mut self) {
        // Extract the database path from the connection string
        let conn = self.write_pool.connect_options();
        let path = conn.get_filename();
        let _ = std::fs::remove_file(path);
    }
}

/// Creates a test loadbalancer with a reservation, sessions, and senders
pub async fn setup_test_loadbalancer(db: &LoadBalancerDB) -> (LoadBalancer, Reservation) {
    // Create loadbalancer
    let name = format!("test-lb-{}", Uuid::new_v4());
    let unicast_mac: MacAddr6 = "00:11:22:33:44:55".parse().unwrap();
    let broadcast_mac: MacAddr6 = "FF:FF:FF:FF:FF:FF".parse().unwrap();
    let ipv4 = Ipv4Addr::new(192, 168, 1, 1);
    let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let port = 8000;

    let lb = db
        .create_loadbalancer(&name, unicast_mac, broadcast_mac, ipv4, ipv6, port)
        .await
        .unwrap();

    // Create reservation
    let reservation = db
        .create_reservation(lb.id, Duration::minutes(30))
        .await
        .unwrap();

    // Add sessions
    let session_addrs = [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8001),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 8002),
    ];

    for (i, addr) in session_addrs.iter().enumerate() {
        db.add_session(
            reservation.id,
            &format!("test-session-{i}"),
            1.0,
            *addr,
            1000,
            0.0,
            2.0,
            "00:11:22:33:44:56".parse().unwrap(),
            false,
        )
        .await
        .unwrap();
    }

    // Add senders
    let sender_addrs = vec![
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 11)),
    ];

    for addr in sender_addrs {
        db.add_sender(reservation.id, addr).await.unwrap();
    }

    (lb, reservation)
}

#[tokio::test]
async fn test_archive_db_rotation_and_pruning() {
    // Integration test: archive DB rotation/pruning with LoadBalancerDB, no sleep, using historical times

    // Setup temp dir for archive DBs
    let dir = tempdir().unwrap();
    let archive_dir = dir.path().to_path_buf();

    // Prepare config with archive enabled, short rotation, keep=2
    let db_file = dir.path().join("udplbd.db");
    let mut config = Config::turmoil();
    config.database = DatabaseConfig {
        file: db_file,
        archive_dir: Some(archive_dir.clone()),
        archive_rotation: "10s".to_string(),
        archive_keep: 2,
        fsync: false,
        cleanup_interval: "10s".to_string(),
        cleanup_age: "10s".to_string(),
    };

    // Create DB with archive manager
    let db = LoadBalancerDB::with_config(&config).await.unwrap();

    // Insert and soft-delete a loadbalancer to trigger archiving
    let lbs = db.list_loadbalancers().await.unwrap();
    let lb_id = lbs[0].id;
    db.delete_loadbalancer(lb_id).await.unwrap();

    // Simulate rotations at different historical times by directly rotating the archive manager
    let base = Utc::now() - ChronoDuration::seconds(100);
    let t0 = base;
    let t1 = base + ChronoDuration::seconds(10);
    let t2 = base + ChronoDuration::seconds(20);
    let t3 = base + ChronoDuration::seconds(30);

    // Each call should create/rotate a new archive DB, locking only for each call
    {
        let mut archive_manager = db.archive_manager.as_ref().unwrap().lock().await;
        let _ = archive_manager
            .get_or_rotate_and_get_pool(t0)
            .await
            .unwrap();
    }
    {
        let mut archive_manager = db.archive_manager.as_ref().unwrap().lock().await;
        let _ = archive_manager
            .get_or_rotate_and_get_pool(t1)
            .await
            .unwrap();
    }
    {
        let mut archive_manager = db.archive_manager.as_ref().unwrap().lock().await;
        let _ = archive_manager
            .get_or_rotate_and_get_pool(t2)
            .await
            .unwrap();
    }
    {
        let mut archive_manager = db.archive_manager.as_ref().unwrap().lock().await;
        let _ = archive_manager
            .get_or_rotate_and_get_pool(t3)
            .await
            .unwrap();
    }
    // Force a final rotation with the current time to ensure the current archive is the most recent
    {
        let mut archive_manager = db.archive_manager.as_ref().unwrap().lock().await;
        let _ = archive_manager
            .get_or_rotate_and_get_pool(Utc::now())
            .await
            .unwrap();
    }

    // Now call cleanup to archive the soft-deleted row
    db.cleanup_soft_deleted(Utc::now()).await.unwrap();

    // There should be only `keep` archive DBs left (the most recent)
    let mut files: Vec<_> = fs::read_dir(&archive_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
        .filter(|e| {
            let fname = e.file_name();
            let fname_str = fname.to_string_lossy();
            fname_str.starts_with("udplbd_archive_") && fname_str.ends_with(".db")
        })
        .collect();

    // Sort by filename to get the most recent
    files.sort_by_key(|e| e.file_name());

    assert_eq!(
        files.len(),
        2,
        "Should only keep the most recent 2 archive DBs, found {}: {:?}",
        files.len(),
        files.iter().map(|e| e.file_name()).collect::<Vec<_>>()
    );

    // The remaining files should be the last two created
    let file_names: Vec<_> = files
        .iter()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert!(
        file_names[0] < file_names[1],
        "Archive DB filenames should be sorted in ascending order"
    );

    // Optionally, check that the archived loadbalancer exists in one of the archive DBs
    let archive_db_path = files.last().unwrap().path();
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&archive_db_path)
        .create_if_missing(false);
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();

    let archived_ids: HashSet<i64> = sqlx::query("SELECT id FROM loadbalancer")
        .fetch_all(&pool)
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get::<i64, _>("id"))
        .collect();
    assert!(
        archived_ids.contains(&lb_id),
        "Archived loadbalancer id should be present in archive DB"
    );
}

#[sqlx::test]
async fn test_loadbalancer_crud_and_associations() {
    let db = setup_db().await;
    let (lb, reservation) = setup_test_loadbalancer(&db).await;

    // Verify loadbalancer fields
    assert_eq!(lb.name, lb.name);
    assert_eq!(lb.unicast_mac_address.to_string(), "00:11:22:33:44:55");
    assert_eq!(lb.broadcast_mac_address.to_string(), "FF:FF:FF:FF:FF:FF");
    assert_eq!(lb.unicast_ipv4_address.to_string(), "192.168.1.1");
    assert_eq!(lb.event_number_udp_port, 8000);
    assert!(lb.deleted_at.is_none());

    // Verify reservation
    assert_eq!(reservation.loadbalancer_id, lb.id);
    assert!(reservation.reserved_until > chrono::Utc::now());

    // Verify sessions
    let sessions = db.get_reservation_sessions(reservation.id).await.unwrap();
    assert_eq!(sessions.len(), 2);
    for (i, session) in sessions.iter().enumerate() {
        assert_eq!(session.name, format!("test-session-{i}"));
        assert_eq!(session.initial_weight_factor, 1.0);
        assert_eq!(session.weight, 1000.0);
        assert_eq!(session.port_range, 1000);
        assert_eq!(session.min_factor, 0.0);
        assert_eq!(session.max_factor, 2.0);
        assert!(session.deleted_at.is_none());
    }

    // Verify senders
    let senders = db.get_reservation_senders(reservation.id).await.unwrap();
    assert_eq!(senders.len(), 2);
    assert!(senders.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))));
    assert!(senders.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 11))));

    // Test listing loadbalancers
    let listed_lbs = db.list_loadbalancers().await.unwrap();
    assert!(listed_lbs.iter().any(|listed_lb| listed_lb.id == lb.id));

    // Test updating loadbalancer
    let mut updated_lb = lb.clone();
    updated_lb.name = "updated-name".to_string();
    updated_lb.unicast_mac_address = "AA:BB:CC:DD:EE:FF".parse().unwrap();
    updated_lb.event_number_udp_port = 9000;

    let updated_lb = db.update_loadbalancer(&updated_lb).await.unwrap();
    assert_eq!(updated_lb.name, "updated-name");
    assert_eq!(
        updated_lb.unicast_mac_address.to_string(),
        "AA:BB:CC:DD:EE:FF"
    );
    assert_eq!(updated_lb.event_number_udp_port, 9000);

    // Test soft delete
    db.delete_loadbalancer(lb.id).await.unwrap();
    assert!(matches!(
        db.get_loadbalancer(lb.id).await,
        Err(Error::NotFound(_))
    ));
}

#[sqlx::test]
async fn test_error_cases() {
    let db = setup_db().await;

    // Test getting non-existent loadbalancer
    let result = db.get_loadbalancer(999).await;
    assert!(matches!(result, Err(Error::NotFound(_))));

    // Test updating non-existent loadbalancer
    let (lb, _) = setup_test_loadbalancer(&db).await;
    let mut nonexistent_lb = lb.clone();
    nonexistent_lb.id = 999;

    let result = db.update_loadbalancer(&nonexistent_lb).await;
    assert!(matches!(result, Err(Error::NotFound(_))));

    // Test deleting non-existent loadbalancer
    let result = db.delete_loadbalancer(999).await;
    assert!(matches!(result, Err(Error::NotFound(_))));
}

#[sqlx::test]
async fn test_slot_generation() {
    let db = setup_db().await;
    let (_lb, reservation) = setup_test_loadbalancer(&db).await;
    let mac_address: MacAddr6 = "00:11:22:33:44:55".parse().unwrap();

    // setup_test_loadbalancer already added 2 sessions with weight 1.0
    // Add 3 more sessions with different weights
    let additional_sessions = vec![
        ("session3", 1.0, 0.0, 2.0),
        ("session4", 2.0, 0.0, 2.0),
        ("session5", 0.5, 0.0, 2.0),
    ];

    for (name, weight_factor, min_factor, max_factor) in &additional_sessions {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8000);
        db.add_session(
            reservation.id,
            name,
            *weight_factor,
            addr,
            1000,
            *min_factor,
            *max_factor,
            mac_address,
            false,
        )
        .await
        .unwrap();
    }

    // Now we should have 5 total sessions (2 from setup + 3 new ones)
    let sessions = db.get_reservation_sessions(reservation.id).await.unwrap();
    assert_eq!(
        sessions.len(),
        5,
        "Expected 5 sessions (2 from setup + 3 new ones)"
    );

    let ts = chrono::Utc::now().timestamp_millis();
    for session in &sessions {
        assert!(db
            .add_session_state_and_update_latest(
                session.id, ts, true, 0.0, 0.0, 0, 0, 0, 0, 0, 0, 0
            )
            .await
            .is_ok())
    }

    // Test with default session states (should use defaults)
    let slots = db
        .generate_epoch_assignments(reservation.id, true)
        .await
        .unwrap();
    assert_eq!(slots.len(), NUM_SLOTS);

    // Verify distribution roughly matches weights
    let mut counts = std::collections::HashMap::new();
    for &slot in &slots {
        if slot != 65535 {
            *counts.entry(slot).or_insert(0) += 1;
        }
    }

    assert_eq!(
        counts.len(),
        5,
        "Should have slots assigned to all 5 sessions"
    );

    // Highest weight should have most slots
    let slot_counts: Vec<_> = counts.iter().map(|(_, &count)| count).collect();
    assert!(
        slot_counts.iter().any(|&count| count > NUM_SLOTS / 3),
        "Session with weight 2.0 should have the most slots"
    );

    // Add some event number data before testing epoch advancement
    sqlx::query!(
        r#"
    INSERT INTO event_number (
        reservation_id, event_number, avg_event_rate_hz,
        local_timestamp, remote_timestamp
    )
    VALUES (?1, ?2, ?3, unixepoch('subsec') * 1000, unixepoch('subsec') * 1000)
    "#,
        reservation.id,
        1000_i64, // event_number
        100_i64,  // avg_event_rate_hz
    )
    .execute(&db.write_pool)
    .await
    .unwrap();

    // Test session state readiness
    sqlx::query!(
        r#"
    INSERT INTO session_state (
        session_id, timestamp, is_ready, fill_percent, control_signal,
        total_events_recv, total_events_reassembled,
        total_events_reassembly_err, total_events_dequeued,
        total_event_enqueue_err, total_bytes_recv, total_packets_recv
    )
    VALUES (?1, unixepoch('subsec') * 1000, false, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    "#,
        sessions[0].id
    )
    .execute(&db.write_pool)
    .await
    .unwrap();

    // Test full epoch advancement
    let epoch = db
        .advance_epoch(reservation.id, chrono::Duration::milliseconds(800), None)
        .await
        .unwrap();
    assert_eq!(epoch.slots.len(), NUM_SLOTS);
}

#[sqlx::test]
async fn test_epoch_maintenance() {
    let db = setup_db().await;
    let (_lb, reservation) = setup_test_loadbalancer(&db).await;

    // Create 6 epochs
    let slots = vec![1u16; NUM_SLOTS];

    let mut latest_epoch_id = None;
    for i in 1..=6 {
        let boundary: i64 = i64::from(i * 1000);
        let epoch = db
            .create_epoch(reservation.id, boundary, &slots)
            .await
            .unwrap();
        latest_epoch_id = Some(epoch.id);
    }

    // Verify only 5 epochs remain active
    let active_epochs = sqlx::query!(
        "SELECT COUNT(*) as count FROM epoch
        WHERE reservation_id = $1 AND deleted_at IS NULL",
        reservation.id
    )
    .fetch_one(&db.read_pool)
    .await
    .unwrap();

    assert_eq!(active_epochs.count, 5);

    // Verify we can fetch the latest epoch
    if let Some(epoch_id) = latest_epoch_id {
        assert!(db.get_epoch(epoch_id).await.is_ok());
    }
}

#[sqlx::test]
async fn test_token_crud() {
    let db = setup_db().await;
    let (lb, _) = setup_test_loadbalancer(&db).await;

    // Create a token with various permissions
    let permissions = vec![
        Permission {
            resource: Resource::All,
            permission: PermissionType::ReadOnly,
        },
        Permission {
            resource: Resource::LoadBalancer(lb.id),
            permission: PermissionType::Update,
        },
    ];

    // Test token creation
    let token = db
        .create_token("test-token", None, permissions)
        .await
        .unwrap();
    assert!(!token.is_empty());

    // Test token validation with wildcard permission
    let is_valid = db
        .validate_token(&token, Resource::LoadBalancer(2), PermissionType::ReadOnly)
        .await
        .unwrap();
    assert!(is_valid, "Wildcard permission should grant access");

    // Test token revocation
    db.revoke_token(&token).await.unwrap();

    // Verify token is no longer valid after revocation
    let is_valid = db
        .validate_token(&token, Resource::LoadBalancer(1), PermissionType::Update)
        .await
        .unwrap();
    assert!(!is_valid, "Token should not be valid after revocation");
}

#[sqlx::test]
async fn test_hierarchical_permissions() {
    let db = setup_db().await;
    let (lb, reservation) = setup_test_loadbalancer(&db).await;

    // Get first session ID from the test loadbalancer
    let sessions = db.get_reservation_sessions(reservation.id).await.unwrap();
    let session_id = sessions[0].id;

    // Create a token with loadbalancer-level permission
    let permissions = vec![Permission {
        resource: Resource::LoadBalancer(lb.id),
        permission: PermissionType::Update,
    }];

    let token = db
        .create_token("test-token", None, permissions)
        .await
        .unwrap();

    // Verify token works for the loadbalancer
    let is_valid = db
        .validate_token(
            &token,
            Resource::LoadBalancer(lb.id),
            PermissionType::Update,
        )
        .await
        .unwrap();
    assert!(is_valid, "Token should be valid for loadbalancer");

    // Verify token works for session under the loadbalancer
    let is_valid = db
        .validate_token(
            &token,
            Resource::Session(session_id),
            PermissionType::Update,
        )
        .await
        .unwrap();
    assert!(
        is_valid,
        "Token should be valid for session under loadbalancer"
    );

    // Verify token doesn't work for a different loadbalancer
    let is_valid = db
        .validate_token(
            &token,
            Resource::LoadBalancer(lb.id + 1),
            PermissionType::Update,
        )
        .await
        .unwrap();
    assert!(
        !is_valid,
        "Token should not be valid for different loadbalancer"
    );
}

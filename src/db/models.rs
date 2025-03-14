// src/db/models.rs

use chrono::{DateTime, Utc};
use macaddr::MacAddr6;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancer {
    pub id: i64,
    pub name: String,
    pub unicast_mac_address: MacAddr6,
    pub broadcast_mac_address: MacAddr6,
    pub unicast_ipv4_address: Ipv4Addr,
    pub unicast_ipv6_address: Ipv6Addr,
    pub event_number_udp_port: u16,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reservation {
    pub id: i64,
    pub loadbalancer_id: i64,
    pub reserved_until: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: i64,
    pub reservation_id: i64,
    pub name: String,
    pub weight: f64,
    pub ip_address: IpAddr,
    pub udp_port: u16,
    pub port_range: u16,
    pub mac_address: Option<String>,
    pub min_factor: f64,
    pub max_factor: f64,
    pub keep_lb_header: bool,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub timestamp: DateTime<Utc>,
    pub is_ready: bool,
    pub fill_percent: f64,
    pub control_signal: f64,
    pub total_events_recv: u64,
    pub total_events_reassembled: u64,
    pub total_events_reassembly_err: u64,
    pub total_events_dequeued: u64,
    pub total_event_enqueue_err: u64,
    pub total_bytes_recv: u64,
    pub total_packets_recv: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Epoch {
    pub id: i64,
    pub reservation_id: i64,
    pub epoch_fpga_id: String,
    pub boundary_event: u64,
    pub predicted_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub slots: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub id: i64,
    pub token_hash: String,
    pub permissions: Vec<Permission>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Permission {
    pub resource: Resource,
    pub permission: PermissionType,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Resource {
    All,
    LoadBalancer(i64),
    Reservation(i64),
    Session(i64),
}

impl std::str::FromStr for Resource {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        match parts.first().copied() {
            Some("*") => Ok(Resource::All),
            Some("lb") => parts
                .get(1)
                .ok_or_else(|| "Missing load balancer id".to_string())
                .and_then(|id| {
                    id.parse()
                        .map_err(|_| format!("Invalid load balancer id: {}", id))
                        .map(Resource::LoadBalancer)
                }),
            Some("res") => parts
                .get(1)
                .ok_or_else(|| "Missing reservation id".to_string())
                .and_then(|id| {
                    id.parse()
                        .map_err(|_| format!("Invalid reservation id: {}", id))
                        .map(Resource::Reservation)
                }),
            Some("ses") => parts
                .get(1)
                .ok_or_else(|| "Missing session id".to_string())
                .and_then(|id| {
                    id.parse()
                        .map_err(|_| format!("Invalid session id: {}", id))
                        .map(Resource::Session)
                }),
            Some(unknown) => Err(format!("Unknown resource type: {}", unknown)),
            None => Err("Empty resource string".to_string()),
        }
    }
}

impl std::fmt::Display for Resource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Resource::All => write!(f, "*"),
            Resource::LoadBalancer(id) => write!(f, "lb:{}", id),
            Resource::Reservation(id) => write!(f, "res:{}", id),
            Resource::Session(id) => write!(f, "ses:{}", id),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PermissionType {
    Update,
    Reserve,
    Register,
    ReadOnly,
}

impl std::fmt::Display for PermissionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PermissionType::Update => write!(f, "update"),
            PermissionType::Reserve => write!(f, "reserve"),
            PermissionType::Register => write!(f, "register"),
            PermissionType::ReadOnly => write!(f, "readonly"),
        }
    }
}

impl std::str::FromStr for PermissionType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "update" => Ok(PermissionType::Update),
            "reserve" => Ok(PermissionType::Reserve),
            "register" => Ok(PermissionType::Register),
            "readonly" => Ok(PermissionType::ReadOnly),
            _ => Err("Invalid permission type".to_string()),
        }
    }
}

// SPDX-License-Identifier: BSD-3-Clause-LBNL
use crate::errors::Error;
/// gRPC client for the udplbd gRPC API
use crate::proto::loadbalancer::v1::{
    load_balancer_client::LoadBalancerClient, token_selector, AddSendersReply, AddSendersRequest,
    CreateTokenReply, CreateTokenRequest, DeregisterReply, DeregisterRequest,
    FreeLoadBalancerReply, FreeLoadBalancerRequest, GetLoadBalancerRequest, ListChildTokensReply,
    ListChildTokensRequest, ListTokenPermissionsReply, ListTokenPermissionsRequest, OverviewReply,
    OverviewRequest, PortRange, RegisterReply, RegisterRequest, RemoveSendersReply,
    RemoveSendersRequest, ReserveLoadBalancerReply, ReserveLoadBalancerRequest, RevokeTokenReply,
    RevokeTokenRequest, SendStateReply, SendStateRequest, TokenPermission, TokenSelector,
    VersionReply, VersionRequest,
};
use prost_wkt_types::Timestamp;
use serde::Serialize;
use std::fmt;
use std::str::FromStr;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tonic::{metadata::MetadataValue, service::Interceptor, Request, Status};

type ControlPlaneTonicClient = LoadBalancerClient<InterceptedService<Channel, BearerInterceptor>>;

#[derive(Clone)]
pub struct ControlPlaneClient {
    pub client: ControlPlaneTonicClient,
    pub session_id: Option<String>,
    pub lb_id: Option<String>,
}

impl ControlPlaneClient {
    pub fn new(
        client: ControlPlaneTonicClient,
        lb_id: Option<String>,
        session_id: Option<String>,
    ) -> Self {
        Self {
            client,
            lb_id,
            session_id,
        }
    }

    pub async fn from_url(url: &str) -> Result<Self, tonic::transport::Error> {
        let parsed_url: EjfatUrl = url.parse().unwrap();
        let token = parsed_url
            .token
            .clone()
            .expect("cannot make requests without token");
        let bearer_interceptor = BearerInterceptor { token };

        let grpc_host = parsed_url.grpc_host;
        let grpc_port = parsed_url
            .grpc_port
            .expect("URL missing control plane port");

        let channel = if parsed_url.tls_enabled {
            let tls_config = ClientTlsConfig::new().with_enabled_roots();
            Channel::from_shared(format!("https://{}:{}", grpc_host, grpc_port))
                .unwrap()
                .tls_config(tls_config)
                .unwrap()
                .connect()
                .await?
        } else {
            Channel::from_shared(format!("http://{}:{}", grpc_host, grpc_port))
                .unwrap()
                .connect()
                .await?
        };

        let client = LoadBalancerClient::with_interceptor(channel, bearer_interceptor);
        Ok(Self::new(client, parsed_url.lb_id, None))
    }

    pub async fn turmoil() -> Result<Self, tonic::transport::Error> {
        let channel = Endpoint::new("http://server:19523")?
            .connect_with_connector(crate::dataplane::turmoil::connector::connector())
            .await?;
        let interceptor = BearerInterceptor {
            token: "test".to_string(),
        };
        Ok(Self {
            client: LoadBalancerClient::with_interceptor(channel, interceptor),
            lb_id: Some("1".to_string()),
            session_id: None,
        })
    }

    pub async fn reserve_load_balancer(
        &mut self,
        name: String,
        until: Option<Timestamp>,
        sender_addresses: Vec<String>,
        ip_family: crate::proto::loadbalancer::v1::IpFamily,
    ) -> std::result::Result<tonic::Response<ReserveLoadBalancerReply>, tonic::Status> {
        let request = ReserveLoadBalancerRequest {
            name,
            until,
            sender_addresses,
            ip_family: ip_family as i32,
        };
        let reply = self.client.reserve_load_balancer(request).await?;
        self.lb_id = Some(reply.get_ref().lb_id.clone());
        Ok(reply)
    }

    pub async fn get_load_balancer(
        &mut self,
    ) -> std::result::Result<tonic::Response<ReserveLoadBalancerReply>, tonic::Status> {
        let request = GetLoadBalancerRequest {
            lb_id: self
                .lb_id
                .clone()
                .expect("cannot get_load_balancer when lb_id is None"),
        };
        let reply = self.client.get_load_balancer(request).await?;
        Ok(reply)
    }

    pub async fn add_senders(
        &mut self,
        sender_addresses: Vec<String>,
    ) -> std::result::Result<tonic::Response<AddSendersReply>, tonic::Status> {
        let request = AddSendersRequest {
            lb_id: self
                .lb_id
                .clone()
                .expect("cannot add senders when lb_id is None"),
            sender_addresses,
        };
        self.client.add_senders(request).await
    }

    pub async fn remove_senders(
        &mut self,
        sender_addresses: Vec<String>,
    ) -> std::result::Result<tonic::Response<RemoveSendersReply>, tonic::Status> {
        let request = RemoveSendersRequest {
            lb_id: self
                .lb_id
                .clone()
                .expect("cannot remove senders when lb_id is None"),
            sender_addresses,
        };
        self.client.remove_senders(request).await
    }

    pub async fn free_load_balancer(
        &mut self,
    ) -> std::result::Result<tonic::Response<FreeLoadBalancerReply>, tonic::Status> {
        let request = FreeLoadBalancerRequest {
            lb_id: self
                .lb_id
                .clone()
                .expect("cannot free_load_balancer when lb_id is None"),
        };
        let reply = self.client.free_load_balancer(request).await?;
        self.lb_id = None;
        Ok(reply)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn register(
        &mut self,
        name: String,
        weight: f32,
        ip_address: String,
        udp_port: u16,
        port_range: PortRange,
        min_factor: f32,
        max_factor: f32,
        keep_lb_header: bool,
    ) -> std::result::Result<tonic::Response<RegisterReply>, tonic::Status> {
        let request = RegisterRequest {
            lb_id: self
                .lb_id
                .clone()
                .expect("cannot register before reserving"),
            name,
            weight,
            ip_address,
            udp_port: udp_port as u32,
            port_range: port_range as i32,
            min_factor,
            max_factor,
            keep_lb_header,
        };
        let reply = self.client.register(request).await?;
        self.session_id = Some(reply.get_ref().session_id.clone());
        Ok(reply)
    }

    pub async fn deregister(
        &mut self,
    ) -> std::result::Result<tonic::Response<DeregisterReply>, tonic::Status> {
        let request = DeregisterRequest {
            lb_id: self
                .lb_id
                .clone()
                .expect("cannot deregister before reserving"),
            session_id: self
                .session_id
                .clone()
                .expect("cannot deregister before registering"),
        };
        let reply = self.client.deregister(request).await?;
        self.session_id = None;
        Ok(reply)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_state(
        &mut self,
        fill_percent: f32,
        control_signal: f32,
        is_ready: bool,
        total_events_recv: i64,
        total_events_reassembled: i64,
        total_events_reassembly_err: i64,
        total_events_dequeued: i64,
        total_event_enqueue_err: i64,
        total_bytes_recv: i64,
        total_packets_recv: i64,
    ) -> std::result::Result<tonic::Response<SendStateReply>, tonic::Status> {
        let request = SendStateRequest {
            lb_id: self
                .lb_id
                .clone()
                .expect("cannot send_state when lb_id is None (did you call send_state before reserving?)"),
            session_id: self
                .session_id
                .clone()
                .expect("cannot send_state when session_id is None (did you call send_state before registering?)"),
            timestamp: Some(prost_wkt_types::Timestamp::from(std::time::SystemTime::now())),
            fill_percent,
            control_signal,
            is_ready,
            total_events_recv,
            total_events_reassembled,
            total_events_reassembly_err,
            total_events_dequeued,
            total_event_enqueue_err,
            total_bytes_recv,
            total_packets_recv,
        };
        let reply = self.client.send_state(request).await?;
        Ok(reply)
    }

    pub async fn overview(
        &mut self,
    ) -> std::result::Result<tonic::Response<OverviewReply>, tonic::Status> {
        let request = OverviewRequest {};
        let reply = self.client.overview(request).await?;
        Ok(reply)
    }

    pub async fn version(
        &mut self,
    ) -> std::result::Result<tonic::Response<VersionReply>, tonic::Status> {
        let request = VersionRequest {};
        let reply = self.client.version(request).await?;
        Ok(reply)
    }

    pub async fn create_token(
        &mut self,
        name: String,
        permissions: Vec<TokenPermission>,
    ) -> std::result::Result<tonic::Response<CreateTokenReply>, tonic::Status> {
        let request = CreateTokenRequest { name, permissions };
        self.client.create_token(request).await
    }

    pub async fn list_token_permissions_for_token(
        &mut self,
        token: String,
    ) -> std::result::Result<tonic::Response<ListTokenPermissionsReply>, tonic::Status> {
        let request = ListTokenPermissionsRequest {
            target: Some(TokenSelector {
                token_selector: Some(token_selector::TokenSelector::Token(token)),
            }),
        };
        self.client.list_token_permissions(request).await
    }

    pub async fn list_token_permissions_by_id(
        &mut self,
        id: u32,
    ) -> std::result::Result<tonic::Response<ListTokenPermissionsReply>, tonic::Status> {
        let request = ListTokenPermissionsRequest {
            target: Some(TokenSelector {
                token_selector: Some(token_selector::TokenSelector::Id(id)),
            }),
        };
        self.client.list_token_permissions(request).await
    }

    pub async fn list_token_permissions(
        &mut self,
    ) -> std::result::Result<tonic::Response<ListTokenPermissionsReply>, tonic::Status> {
        self.list_token_permissions_by_id(0).await
    }

    pub async fn list_child_tokens_for_token(
        &mut self,
        token: String,
    ) -> std::result::Result<tonic::Response<ListChildTokensReply>, tonic::Status> {
        let request = ListChildTokensRequest {
            target: Some(TokenSelector {
                token_selector: Some(token_selector::TokenSelector::Token(token)),
            }),
        };
        self.client.list_child_tokens(request).await
    }

    pub async fn list_child_tokens_by_id(
        &mut self,
        id: u32,
    ) -> std::result::Result<tonic::Response<ListChildTokensReply>, tonic::Status> {
        let request = ListChildTokensRequest {
            target: Some(TokenSelector {
                token_selector: Some(token_selector::TokenSelector::Id(id)),
            }),
        };
        self.client.list_child_tokens(request).await
    }

    pub async fn list_child_tokens(
        &mut self,
    ) -> std::result::Result<tonic::Response<ListChildTokensReply>, tonic::Status> {
        self.list_child_tokens_by_id(0).await
    }

    pub async fn revoke_token(
        &mut self,
        token: String,
    ) -> std::result::Result<tonic::Response<RevokeTokenReply>, tonic::Status> {
        let request = RevokeTokenRequest {
            target: Some(TokenSelector {
                token_selector: Some(token_selector::TokenSelector::Token(token)),
            }),
        };
        self.client.revoke_token(request).await
    }

    pub async fn revoke_token_by_id(
        &mut self,
        id: u32,
    ) -> std::result::Result<tonic::Response<RevokeTokenReply>, tonic::Status> {
        let request = RevokeTokenRequest {
            target: Some(TokenSelector {
                token_selector: Some(token_selector::TokenSelector::Id(id)),
            }),
        };
        self.client.revoke_token(request).await
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EjfatUrl {
    pub token: Option<String>,
    pub grpc_host: String,
    pub grpc_port: Option<u16>,
    /// When present, indicates a non-admin URL (load-balancer endpoint)
    pub lb_id: Option<String>,
    pub sync_addr_v4: Option<String>,
    pub sync_addr_v6: Option<String>,
    pub sync_udp_port: Option<u16>,
    /// The host for the data endpoint.
    pub data_addr_v4: Option<String>,
    pub data_addr_v6: Option<String>,
    // TODO: Vec<PortRange>, support multiple port range entries
    /// The lower bound of the data port range.
    pub data_min_port: u16,
    /// The upper bound of the data port range.
    pub data_max_port: u16,
    pub tls_enabled: bool,
}

impl EjfatUrl {
    /// Updates fields from a reservation reply.
    pub fn update_from_reservation(&mut self, reply: &ReserveLoadBalancerReply) {
        self.token = Some(reply.token.clone());
        self.lb_id = Some(reply.lb_id.clone());
        self.sync_addr_v4 = Some(reply.sync_ipv4_address.clone());
        self.sync_addr_v6 = Some(reply.sync_ipv6_address.clone());
        self.sync_udp_port = Some(reply.sync_udp_port as u16);
        // For backward compatibility, update the data host.
        self.data_addr_v4 = Some(reply.data_ipv4_address.clone());
        self.data_addr_v6 = Some(reply.data_ipv6_address.clone());
        // If not set elsewhere, assume the full port range.
        self.data_min_port = reply.data_min_port as u16;
        self.data_max_port = reply.data_max_port as u16;
    }

    /// Returns true if this URL is an admin URL (i.e. no load-balancer ID).
    pub fn is_admin_url(&self) -> bool {
        self.lb_id.is_none()
    }

    pub fn without_v6(&self) -> EjfatUrl {
        let mut v4_only = self.clone();
        v4_only.data_addr_v6 = None;
        v4_only.sync_addr_v6 = None;
        v4_only
    }

    pub fn without_v4(&self) -> EjfatUrl {
        let mut v6_only = self.clone();
        v6_only.data_addr_v4 = None;
        v6_only.sync_addr_v4 = None;
        v6_only
    }
}

impl fmt::Display for EjfatUrl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut url = String::new();
        url.push_str("ejfat");
        if self.tls_enabled {
            url.push('s');
        }
        url.push_str("://");
        if let Some(token) = &self.token {
            url.push_str(token);
            url.push('@');
        }
        url.push_str(&self.grpc_host);
        if let Some(port) = self.grpc_port {
            url.push(':');
            url.push_str(&port.to_string());
        }
        // For admin URLs, use a simple "/" path; for others, use "/lb/<lb_id>".
        if self.is_admin_url() {
            url.push('/');
        } else {
            url.push_str("/lb/");
            if let Some(lb_id) = &self.lb_id {
                url.push_str(lb_id);
            }
        }
        // Build query parameters.
        let mut query_params = Vec::new();
        if let Some(sync_ip) = &self.sync_addr_v4 {
            let mut sync_param = format!("sync={}", sync_ip);
            if let Some(sync_port) = self.sync_udp_port {
                sync_param.push(':');
                sync_param.push_str(&sync_port.to_string());
            }
            query_params.push(sync_param);
        }
        if let Some(sync_v6) = &self.sync_addr_v6 {
            if !sync_v6.is_empty() {
                let mut sync_param = format!("sync=[{}]", sync_v6);
                if let Some(sync_port) = self.sync_udp_port {
                    sync_param.push(':');
                    sync_param.push_str(&sync_port.to_string());
                }
                query_params.push(sync_param);
            }
        }
        if let Some(data_v4) = &self.data_addr_v4 {
            query_params.push(format!(
                "data={}:{}-{}",
                data_v4, self.data_min_port, self.data_max_port
            ));
        }
        if let Some(data_v6) = &self.data_addr_v6 {
            if !data_v6.is_empty() {
                query_params.push(format!(
                    "data=[{}]:{}-{}",
                    data_v6, self.data_min_port, self.data_max_port
                ));
            }
        }
        if !query_params.is_empty() {
            url.push('?');
            url.push_str(&query_params.join("&"));
        }
        write!(f, "{}", url)
    }
}

impl std::str::FromStr for EjfatUrl {
    type Err = Error; // Use a generic error for now

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Example: ejfat://token@host:port/lb/123?sync=1.2.3.4:5678&sync=fe80::1:5678&data=1.2.3.4:10000-20000&data=[fe80::1]:10000-20000
        // Parse scheme
        let (tls_enabled, rest) = if let Some(rest) = s.strip_prefix("ejfats://") {
            (true, rest)
        } else if let Some(rest) = s.strip_prefix("ejfat://") {
            (false, rest)
        } else {
            return Err(Error::Parse(
                "EJFAT URI has invalid scheme, must be ejfat:// or ejfats://".to_string(),
            ));
        };

        // Split off query
        let (main, query) = match rest.find('?') {
            Some(idx) => (&rest[..idx], Some(&rest[idx + 1..])),
            None => (rest, None),
        };

        // Parse token and host/port
        let (token, hostportpath) = if let Some(idx) = main.find('@') {
            (Some(main[..idx].to_string()), &main[idx + 1..])
        } else {
            (None, main)
        };

        // Split host/port from path
        let (hostport, path) = if let Some(idx) = hostportpath.find('/') {
            (&hostportpath[..idx], &hostportpath[idx..])
        } else {
            (hostportpath, "/")
        };

        // Parse host and port
        let (grpc_host, grpc_port) = if let Some(idx) = hostport.rfind(':') {
            let host = &hostport[..idx];
            let port = hostport[idx + 1..].parse::<u16>().ok();
            (host.to_string(), port)
        } else {
            (hostport.to_string(), None)
        };

        // Parse path for lb_id
        let mut lb_id = None;
        let mut path_iter = path.split('/').filter(|s| !s.is_empty());
        if let Some(first) = path_iter.next() {
            if first == "lb" {
                lb_id = path_iter.next().map(|s| s.to_string());
            }
        }

        // Defaults
        let mut sync_ip_address = None;
        let mut sync_addr_v6 = None;
        let mut sync_udp_port = None;
        let mut data_host = None;
        let mut data_addr_v6 = None;
        let mut data_min_port = 16384;
        let mut data_max_port = 32767;

        // Parse query params
        if let Some(query) = query {
            for param in query.split('&') {
                let mut kv = param.splitn(2, '=');
                let key = kv.next().unwrap_or("");
                let value = kv.next().unwrap_or("");
                if key == "sync" {
                    // Split address and port
                    let (addr, port) = if let Some(idx) = value.rfind(':') {
                        (&value[..idx], value[idx + 1..].parse::<u16>().ok())
                    } else {
                        (value, None)
                    };
                    if addr.contains(':') && !addr.chars().all(|c| c.is_ascii_digit() || c == '.') {
                        // IPv6
                        if sync_addr_v6.is_none() {
                            sync_addr_v6 =
                                Some(addr.trim_matches(|c| c == '[' || c == ']').to_string());
                            if sync_udp_port.is_none() {
                                sync_udp_port = port;
                            }
                        }
                    } else {
                        // IPv4
                        if sync_ip_address.is_none() {
                            sync_ip_address = Some(addr.to_string());
                            if sync_udp_port.is_none() {
                                sync_udp_port = port;
                            }
                        }
                    }
                } else if key == "data" {
                    // Format: host:min-max or host:port or just host
                    let (addr, port_spec) = if let Some(idx) = value.find(':') {
                        (&value[..idx], Some(&value[idx + 1..]))
                    } else {
                        (value, None)
                    };
                    let (min_port, max_port) = if let Some(port_spec) = port_spec {
                        if let Some(dash_idx) = port_spec.find('-') {
                            let (min_str, max_str) = port_spec.split_at(dash_idx);
                            let max_str = &max_str[1..];
                            (
                                min_str.parse::<u16>().unwrap_or(16384),
                                max_str.parse::<u16>().unwrap_or(32767),
                            )
                        } else {
                            let port = port_spec.parse::<u16>().unwrap_or(19522);
                            (port, port)
                        }
                    } else {
                        (19522, 19522)
                    };
                    if addr.contains(':') && !addr.chars().all(|c| c.is_ascii_digit() || c == '.') {
                        // IPv6
                        if data_addr_v6.is_none() {
                            data_addr_v6 =
                                Some(addr.trim_matches(|c| c == '[' || c == ']').to_string());
                            data_min_port = min_port;
                            data_max_port = max_port;
                        }
                    } else {
                        // IPv4
                        if data_host.is_none() {
                            data_host = Some(addr.to_string());
                            data_min_port = min_port;
                            data_max_port = max_port;
                        }
                    }
                }
            }
        }

        Ok(EjfatUrl {
            token,
            grpc_host,
            grpc_port,
            lb_id,
            sync_addr_v4: sync_ip_address,
            sync_addr_v6,
            sync_udp_port,
            data_addr_v4: data_host,
            data_addr_v6,
            data_min_port,
            data_max_port,
            tls_enabled,
        })
    }
}

#[derive(Debug, Clone)]
pub struct BearerInterceptor {
    pub token: String,
}

impl Interceptor for BearerInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let metadata = request.metadata_mut();
        metadata.insert(
            "authorization",
            MetadataValue::from_str(&format!("Bearer {}", self.token)).unwrap(),
        );
        Ok(request)
    }
}

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
use prost_types::Timestamp;
use std::fmt;
use std::str::FromStr;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tonic::{metadata::MetadataValue, service::Interceptor, Request, Status};
use url::ParseError;
use url::Url;

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
    ) -> std::result::Result<tonic::Response<ReserveLoadBalancerReply>, tonic::Status> {
        let request = ReserveLoadBalancerRequest {
            name,
            until,
            sender_addresses,
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
            timestamp: Some(prost_types::Timestamp::from(std::time::SystemTime::now())),
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EjfatUrl {
    pub token: Option<String>,
    pub grpc_host: String,
    pub grpc_port: Option<u16>,
    /// When present, indicates a non-admin URL (load-balancer endpoint)
    pub lb_id: Option<String>,
    pub sync_ip_address: Option<String>,
    pub sync_udp_port: Option<u16>,
    /// The host for the data endpoint.
    pub data_host: Option<String>,
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
        self.sync_ip_address = Some(reply.sync_ip_address.clone());
        self.sync_udp_port = Some(reply.sync_udp_port as u16);
        // For backward compatibility, update the data host.
        self.data_host = Some(reply.data_ipv4_address.clone());
        // If not set elsewhere, assume the full port range.
        self.data_min_port = 16384;
        self.data_max_port = 32767;
    }

    /// Returns true if this URL is an admin URL (i.e. no load-balancer ID).
    pub fn is_admin_url(&self) -> bool {
        self.lb_id.is_none()
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
        if let Some(sync_ip) = &self.sync_ip_address {
            let mut sync_param = format!("sync={}", sync_ip);
            if let Some(sync_port) = self.sync_udp_port {
                sync_param.push(':');
                sync_param.push_str(&sync_port.to_string());
            }
            query_params.push(sync_param);
        }
        if let Some(data_host) = &self.data_host {
            // Always include explicit min and max ports.
            query_params.push(format!(
                "data={}:{}-{}",
                data_host, self.data_min_port, self.data_max_port
            ));
        }
        if !query_params.is_empty() {
            url.push('?');
            url.push_str(&query_params.join("&"));
        }
        write!(f, "{}", url)
    }
}

impl std::str::FromStr for EjfatUrl {
    type Err = ParseError; // Assume ParseError is defined elsewhere

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(s)?;
        let tls_enabled = url.scheme().ends_with('s');
        let token = url.username().to_string();
        let grpc_host = url.host_str().expect("invalid host").to_string();
        let grpc_port = url.port();
        // Determine the path. For admin URLs, the path will be "/" (or empty)
        let path_segments: Vec<_> = url.path_segments().map(|c| c.collect()).unwrap_or_default();
        // If the first nonempty segment is "lb", then treat the second as lb_id.
        let lb_id = if let Some(first) = path_segments.iter().find(|s| !s.is_empty()) {
            if *first == "lb" {
                path_segments.get(1).map(|s| s.to_string())
            } else {
                None
            }
        } else {
            None
        };

        let query_pairs = url.query_pairs().into_owned().collect::<Vec<_>>();

        // Parse sync parameter.
        let sync_pair = query_pairs.iter().find(|(k, _)| k == "sync");
        let sync_ip_address = sync_pair.map(|(_, v)| v.split(':').next().unwrap_or("").to_string());
        let sync_udp_port =
            sync_pair.and_then(|(_, v)| v.split(':').nth(1).and_then(|p| p.parse::<u16>().ok()));

        // Defaults for data port range.
        let mut data_min_port = 16384;
        let mut data_max_port = 32767;
        let mut data_host = None;
        if let Some((_, data_value)) = query_pairs.iter().find(|(k, _)| k == "data") {
            // Check if a colon is present.
            if let Some(idx) = data_value.find(':') {
                let (host_part, port_spec) = data_value.split_at(idx);
                data_host = Some(host_part.to_string());
                // Remove the colon.
                let port_spec = &port_spec[1..];
                if let Some(dash_idx) = port_spec.find('-') {
                    let (min_str, max_str_with_dash) = port_spec.split_at(dash_idx);
                    let max_str = &max_str_with_dash[1..]; // skip the hyphen
                    if let (Ok(min), Ok(max)) = (min_str.parse::<u16>(), max_str.parse::<u16>()) {
                        data_min_port = min;
                        data_max_port = max;
                    }
                } else {
                    // Single port: assign both min and max to that value.
                    if let Ok(port) = port_spec.parse::<u16>() {
                        data_min_port = port;
                        data_max_port = port;
                    }
                }
            } else {
                // Only the host is provided; use defaults for ports.
                data_host = Some(data_value.to_string());
            }
        }

        Ok(EjfatUrl {
            token: if token.is_empty() { None } else { Some(token) },
            grpc_host,
            grpc_port,
            lb_id,
            sync_ip_address,
            sync_udp_port,
            data_host,
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

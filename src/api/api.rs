// SPDX-License-Identifier: BSD-3-Clause-LBNL
use crate::{
    metrics::INBOUND_GRPC,
    proto::loadbalancer::v1::{
        load_balancer_server, AddSendersReply, AddSendersRequest, ChainLoadBalancerReply,
        ChainLoadBalancerRequest, CreateTokenReply, CreateTokenRequest, DeregisterReply,
        DeregisterRequest, ExtendReservationReply, ExtendReservationRequest,
        FreeLoadBalancerReply, FreeLoadBalancerRequest, GetLoadBalancerRequest,
        ListChildTokensReply, ListChildTokensRequest, ListTokenPermissionsReply,
        ListTokenPermissionsRequest, LoadBalancerStatusReply, LoadBalancerStatusRequest,
        OverviewReply, OverviewRequest, RegisterReply, RegisterRequest, RemoveSendersReply,
        RemoveSendersRequest, ReserveLoadBalancerReply, ReserveLoadBalancerRequest,
        ResetLoadBalancerReply, ResetLoadBalancerRequest, RevokeTokenReply, RevokeTokenRequest,
        SendStateReply, SendStateRequest, SetSlotDemandsReply, SetSlotDemandsRequest,
        TimeseriesRequest, TimeseriesResponse, UnchainLoadBalancerReply,
        UnchainLoadBalancerRequest, GetChainGraphRequest, GetChainGraphReply,
        VersionReply, VersionRequest,
    },
};
use tonic::{Request, Response, Status};

#[tonic::async_trait]
impl load_balancer_server::LoadBalancer for LoadBalancerService {
    async fn reserve_load_balancer(
        &self,
        request: Request<ReserveLoadBalancerRequest>,
    ) -> Result<Response<ReserveLoadBalancerReply>, Status> {
        INBOUND_GRPC.inc();
        self.handle_reserve_load_balancer(request).await
    }

    async fn get_load_balancer(
        &self,
        request: Request<GetLoadBalancerRequest>,
    ) -> Result<Response<ReserveLoadBalancerReply>, Status> {
        INBOUND_GRPC.inc();
        self.handle_get_load_balancer(request).await
    }

    async fn load_balancer_status(
        &self,
        request: Request<LoadBalancerStatusRequest>,
    ) -> Result<Response<LoadBalancerStatusReply>, Status> {
        INBOUND_GRPC.inc();
        self.handle_load_balancer_status(request).await
    }

    async fn free_load_balancer(
        &self,
        request: Request<FreeLoadBalancerRequest>,
    ) -> Result<Response<FreeLoadBalancerReply>, Status> {
        INBOUND_GRPC.inc();
        self.handle_free_load_balancer(request).await
    }

    async fn reset_load_balancer(
        &self,
        request: Request<ResetLoadBalancerRequest>,
    ) -> Result<Response<ResetLoadBalancerReply>, Status> {
        INBOUND_GRPC.inc();
        self.handle_reset_load_balancer(request).await
    }

    async fn extend_reservation(
        &self,
        request: Request<ExtendReservationRequest>,
    ) -> Result<Response<ExtendReservationReply>, Status> {
        INBOUND_GRPC.inc();
        self.handle_extend_reservation(request).await
    }

    async fn add_senders(
        &self,
        request: Request<AddSendersRequest>,
    ) -> Result<Response<AddSendersReply>, Status> {
        INBOUND_GRPC.inc();
        self.handle_add_senders(request).await
    }

    async fn remove_senders(
        &self,
        request: Request<RemoveSendersRequest>,
    ) -> Result<Response<RemoveSendersReply>, Status> {
        INBOUND_GRPC.inc();
        self.handle_remove_senders(request).await
    }

    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterReply>, Status> {
        INBOUND_GRPC.inc();
        self.handle_register(request).await
    }

    async fn deregister(
        &self,
        request: Request<DeregisterRequest>,
    ) -> Result<Response<DeregisterReply>, Status> {
        INBOUND_GRPC.inc();
        self.handle_deregister(request).await
    }

    async fn set_slot_demands(
        &self,
        request: Request<SetSlotDemandsRequest>,
    ) -> Result<Response<SetSlotDemandsReply>, Status> {
        INBOUND_GRPC.inc();
        self.handle_set_slot_demands(request).await
    }

    async fn send_state(
        &self,
        request: Request<SendStateRequest>,
    ) -> Result<Response<SendStateReply>, Status> {
        INBOUND_GRPC.inc();
        self.handle_send_state(request).await
    }

    async fn overview(
        &self,
        request: Request<OverviewRequest>,
    ) -> Result<Response<OverviewReply>, Status> {
        INBOUND_GRPC.inc();
        self.handle_overview(request).await
    }

    async fn version(
        &self,
        request: Request<VersionRequest>,
    ) -> Result<Response<VersionReply>, Status> {
        INBOUND_GRPC.inc();
        self.handle_version(request).await
    }

    async fn create_token(
        &self,
        request: Request<CreateTokenRequest>,
    ) -> Result<Response<CreateTokenReply>, Status> {
        INBOUND_GRPC.inc();
        self.handle_create_token(request).await
    }

    async fn list_token_permissions(
        &self,
        request: Request<ListTokenPermissionsRequest>,
    ) -> Result<Response<ListTokenPermissionsReply>, Status> {
        INBOUND_GRPC.inc();
        self.handle_list_token_permissions(request).await
    }

    async fn list_child_tokens(
        &self,
        request: Request<ListChildTokensRequest>,
    ) -> Result<Response<ListChildTokensReply>, Status> {
        INBOUND_GRPC.inc();
        self.handle_list_child_tokens(request).await
    }

    async fn revoke_token(
        &self,
        request: Request<RevokeTokenRequest>,
    ) -> Result<Response<RevokeTokenReply>, Status> {
        INBOUND_GRPC.inc();
        self.handle_revoke_token(request).await
    }

    async fn timeseries(
        &self,
        request: Request<TimeseriesRequest>,
    ) -> Result<Response<TimeseriesResponse>, Status> {
        INBOUND_GRPC.inc();
        self.handle_timeseries(request).await
    }

    async fn chain_load_balancer(
        &self,
        request: Request<ChainLoadBalancerRequest>,
    ) -> Result<Response<ChainLoadBalancerReply>, Status> {
        INBOUND_GRPC.inc();
        self.handle_chain_load_balancer(request).await
    }

    async fn unchain_load_balancer(
        &self,
        request: Request<UnchainLoadBalancerRequest>,
    ) -> Result<Response<UnchainLoadBalancerReply>, Status> {
        INBOUND_GRPC.inc();
        self.handle_unchain_load_balancer(request).await
    }

    async fn get_chain_graph(
        &self,
        request: Request<GetChainGraphRequest>,
    ) -> Result<Response<GetChainGraphReply>, Status> {
        INBOUND_GRPC.inc();
        self.handle_get_chain_graph(request).await
    }
}

/// The gRPC host authority extracted from the HTTP request, for use in constructing EJFAT URIs.
#[derive(Clone, Debug)]
pub struct GrpcAuthority(pub String);

// Middleware to ensure both REST and gRPC requests have the necessary
// extensions to be able to read the remote_addr and local_addr
pub async fn fix_connect_info(
    axum::extract::State(local): axum::extract::State<std::net::SocketAddr>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // Extract the host authority from the HTTP request URI or Host header
    let authority = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .or_else(|| {
            req.headers()
                .get("host")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        });
    if let Some(authority) = authority {
        req.extensions_mut().insert(GrpcAuthority(authority));
    }

    req.extensions_mut()
        .insert(tonic::transport::server::TcpConnectInfo {
            local_addr: Some(local),
            remote_addr: Some(addr),
        });
    next.run(req).await
}

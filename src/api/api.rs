// SPDX-License-Identifier: BSD-3-Clause-LBNL
use crate::{
    metrics::INBOUND_GRPC,
    proto::loadbalancer::v1::{
        load_balancer_server, AddSendersReply, AddSendersRequest, CreateTokenReply,
        CreateTokenRequest, DeregisterReply, DeregisterRequest, FreeLoadBalancerReply,
        FreeLoadBalancerRequest, GetLoadBalancerRequest, ListChildTokensReply,
        ListChildTokensRequest, ListTokenPermissionsReply, ListTokenPermissionsRequest,
        LoadBalancerStatusReply, LoadBalancerStatusRequest, OverviewReply, OverviewRequest,
        RegisterReply, RegisterRequest, RemoveSendersReply, RemoveSendersRequest,
        ReserveLoadBalancerReply, ReserveLoadBalancerRequest, RevokeTokenReply, RevokeTokenRequest,
        SendStateReply, SendStateRequest, TimeseriesRequest, TimeseriesResponse, VersionReply,
        VersionRequest,
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
}

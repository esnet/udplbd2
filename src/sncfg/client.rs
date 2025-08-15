// SPDX-License-Identifier: BSD-3-Clause-LBNL
//! Tonic gRPC client for the smartnic-config gRPC API

use crate::proto::smartnic::cfg_v2::{
    smartnic_config_client::SmartnicConfigClient, BatchRequest, BatchResponse, DefaultsRequest,
    DefaultsResponse, DeviceInfo, DeviceInfoRequest, DeviceStatus, DeviceStatusRequest, HostConfig,
    HostConfigRequest, HostConfigResponse, HostStatsRequest, HostStatsResponse, ModuleGpioRequest,
    ModuleGpioResponse, ModuleInfoRequest, ModuleInfoResponse, ModuleMemRequest, ModuleMemResponse,
    ModuleStatusRequest, ModuleStatusResponse, PortConfig, PortConfigRequest, PortConfigResponse,
    PortStatsRequest, PortStatsResponse, PortStatusRequest, PortStatusResponse, ServerConfig,
    ServerConfigRequest, ServerStatus, ServerStatusRequest, StatsMetric, StatsRequest,
    StatsResponse, SwitchConfig, SwitchConfigRequest, SwitchConfigResponse, SwitchStatsRequest,
    SwitchStatsResponse,
};
use futures::{future::join_all, StreamExt};
use tonic::{
    service::{interceptor::InterceptedService, Interceptor},
    transport::{Channel, ClientTlsConfig},
    Request, Status,
};
// use tracing::{trace, warn};

#[derive(Debug, Clone)]
pub struct SNCfgClient {
    api: SmartnicConfigClient<InterceptedService<Channel, BearerTokenInterceptor>>,
    device_id: i32,
}

impl SNCfgClient {
    pub async fn new(
        addr: &str,
        device_id: i32,
        verify: bool,
        auth_token: impl Into<String>,
    ) -> Result<Self, tonic::transport::Error> {
        let mut channel = Channel::from_shared(addr.to_string()).unwrap();

        if addr.starts_with("https://") {
            let tls_config = ClientTlsConfig::new().with_enabled_roots();
            if !verify {
                // TODO: Support disabling TLS verification if needed
                unimplemented!()
            }
            channel = channel.tls_config(tls_config)?;
        }

        let channel = channel.connect().await?;
        let interceptor = BearerTokenInterceptor::new(auth_token);

        Ok(Self {
            api: SmartnicConfigClient::with_interceptor(channel, interceptor),
            device_id,
        })
    }

    pub async fn get_device_info(&mut self) -> Result<Vec<DeviceInfo>, Status> {
        let request = Request::new(DeviceInfoRequest {
            dev_id: self.device_id,
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["get_device_info"])
            .inc();

        let mut stream = self
            .api
            .get_device_info(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["get_device_info"])
                    .inc();
            })?
            .into_inner();

        let mut device_infos = Vec::new();

        while let Some(response) = stream.message().await? {
            if let Some(info) = response.info {
                device_infos.push(info);
            }
        }

        Ok(device_infos)
    }

    pub async fn get_device_status(&mut self) -> Result<Vec<DeviceStatus>, Status> {
        let request = Request::new(DeviceStatusRequest {
            dev_id: self.device_id,
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["get_device_status"])
            .inc();

        let mut stream = self
            .api
            .get_device_status(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["get_device_status"])
                    .inc();
            })?
            .into_inner();

        let mut statuses = Vec::new();

        while let Some(response) = stream.message().await? {
            if let Some(status) = response.status {
                statuses.push(status);
            }
        }

        Ok(statuses)
    }

    pub async fn set_defaults(&mut self, profile: i32) -> Result<Vec<DefaultsResponse>, Status> {
        let request = Request::new(DefaultsRequest {
            dev_id: self.device_id,
            profile,
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["set_defaults"])
            .inc();

        let mut stream = self
            .api
            .set_defaults(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["set_defaults"])
                    .inc();
            })?
            .into_inner();

        let mut responses = Vec::new();
        while let Some(response) = stream.message().await? {
            responses.push(response);
        }
        Ok(responses)
    }

    // --- HostConfig ---
    pub async fn get_host_config(
        &mut self,
        host_id: i32,
    ) -> Result<Vec<HostConfigResponse>, Status> {
        let request = Request::new(HostConfigRequest {
            dev_id: self.device_id,
            host_id,
            config: None,
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["get_host_config"])
            .inc();

        let mut stream = self
            .api
            .get_host_config(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["get_host_config"])
                    .inc();
            })?
            .into_inner();

        let mut responses = Vec::new();

        while let Some(response) = stream.message().await? {
            responses.push(response);
        }

        Ok(responses)
    }

    pub async fn set_host_config(
        &mut self,
        host_id: i32,
        config: HostConfig,
    ) -> Result<Vec<HostConfigResponse>, Status> {
        let request = Request::new(HostConfigRequest {
            dev_id: self.device_id,
            host_id,
            config: Some(config),
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["set_host_config"])
            .inc();

        let mut stream = self
            .api
            .set_host_config(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["set_host_config"])
                    .inc();
            })?
            .into_inner();

        let mut responses = Vec::new();
        while let Some(response) = stream.message().await? {
            responses.push(response);
        }
        Ok(responses)
    }

    // --- HostStats ---
    pub async fn get_host_stats(&mut self, host_id: i32) -> Result<Vec<HostStatsResponse>, Status> {
        let request = Request::new(HostStatsRequest {
            dev_id: self.device_id,
            host_id,
            filters: None,
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["get_host_stats"])
            .inc();

        let mut stream = self
            .api
            .get_host_stats(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["get_host_stats"])
                    .inc();
            })?
            .into_inner();

        let mut responses = Vec::new();

        while let Some(response) = stream.message().await? {
            responses.push(response);
        }

        Ok(responses)
    }

    pub async fn clear_host_stats(
        &mut self,
        host_id: i32,
    ) -> Result<Vec<HostStatsResponse>, Status> {
        let request = Request::new(HostStatsRequest {
            dev_id: self.device_id,
            host_id,
            filters: None,
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["clear_host_stats"])
            .inc();

        let mut stream = self
            .api
            .clear_host_stats(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["clear_host_stats"])
                    .inc();
            })?
            .into_inner();

        let mut responses = Vec::new();
        while let Some(response) = stream.message().await? {
            responses.push(response);
        }
        Ok(responses)
    }

    // --- ModuleGpio ---
    pub async fn get_module_gpio(
        &mut self,
        mod_id: i32,
    ) -> Result<Vec<ModuleGpioResponse>, Status> {
        let request = Request::new(ModuleGpioRequest {
            dev_id: self.device_id,
            mod_id,
            gpio: None,
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["get_module_gpio"])
            .inc();

        let mut stream = self
            .api
            .get_module_gpio(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["get_module_gpio"])
                    .inc();
            })?
            .into_inner();

        let mut responses = Vec::new();
        while let Some(response) = stream.message().await? {
            responses.push(response);
        }
        Ok(responses)
    }

    pub async fn set_module_gpio(
        &mut self,
        mod_id: i32,
        gpio: crate::proto::smartnic::cfg_v2::ModuleGpio,
    ) -> Result<Vec<ModuleGpioResponse>, Status> {
        let request = Request::new(ModuleGpioRequest {
            dev_id: self.device_id,
            mod_id,
            gpio: Some(gpio),
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["set_module_gpio"])
            .inc();

        let mut stream = self
            .api
            .set_module_gpio(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["set_module_gpio"])
                    .inc();
            })?
            .into_inner();

        let mut responses = Vec::new();
        while let Some(response) = stream.message().await? {
            responses.push(response);
        }
        Ok(responses)
    }

    // --- ModuleInfo ---
    pub async fn get_module_info(
        &mut self,
        mod_id: i32,
    ) -> Result<Vec<ModuleInfoResponse>, Status> {
        let request = Request::new(ModuleInfoRequest {
            dev_id: self.device_id,
            mod_id,
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["get_module_info"])
            .inc();

        let mut stream = self
            .api
            .get_module_info(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["get_module_info"])
                    .inc();
            })?
            .into_inner();

        let mut responses = Vec::new();
        while let Some(response) = stream.message().await? {
            responses.push(response);
        }
        Ok(responses)
    }

    // --- ModuleMem ---
    pub async fn get_module_mem(
        &mut self,
        mod_id: i32,
        mem: crate::proto::smartnic::cfg_v2::ModuleMem,
    ) -> Result<Vec<ModuleMemResponse>, Status> {
        let request = Request::new(ModuleMemRequest {
            dev_id: self.device_id,
            mod_id,
            mem: Some(mem),
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["get_module_mem"])
            .inc();

        let mut stream = self
            .api
            .get_module_mem(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["get_module_mem"])
                    .inc();
            })?
            .into_inner();

        let mut responses = Vec::new();
        while let Some(response) = stream.message().await? {
            responses.push(response);
        }
        Ok(responses)
    }

    pub async fn set_module_mem(
        &mut self,
        mod_id: i32,
        mem: crate::proto::smartnic::cfg_v2::ModuleMem,
    ) -> Result<Vec<ModuleMemResponse>, Status> {
        let request = Request::new(ModuleMemRequest {
            dev_id: self.device_id,
            mod_id,
            mem: Some(mem),
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["set_module_mem"])
            .inc();

        let mut stream = self
            .api
            .set_module_mem(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["set_module_mem"])
                    .inc();
            })?
            .into_inner();

        let mut responses = Vec::new();
        while let Some(response) = stream.message().await? {
            responses.push(response);
        }
        Ok(responses)
    }

    // --- ModuleStatus ---
    pub async fn get_module_status(
        &mut self,
        mod_id: i32,
    ) -> Result<Vec<ModuleStatusResponse>, Status> {
        let request = Request::new(ModuleStatusRequest {
            dev_id: self.device_id,
            mod_id,
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["get_module_status"])
            .inc();

        let mut stream = self
            .api
            .get_module_status(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["get_module_status"])
                    .inc();
            })?
            .into_inner();

        let mut responses = Vec::new();
        while let Some(response) = stream.message().await? {
            responses.push(response);
        }
        Ok(responses)
    }

    // --- PortConfig ---
    pub async fn set_port_config(
        &mut self,
        port_id: i32,
        config: PortConfig,
    ) -> Result<Vec<PortConfigResponse>, Status> {
        let request = Request::new(PortConfigRequest {
            dev_id: self.device_id,
            port_id,
            config: Some(config),
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["set_port_config"])
            .inc();

        let mut stream = self
            .api
            .set_port_config(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["set_port_config"])
                    .inc();
            })?
            .into_inner();

        let mut responses = Vec::new();
        while let Some(response) = stream.message().await? {
            responses.push(response);
        }
        Ok(responses)
    }

    // --- PortStats ---
    pub async fn clear_port_stats(
        &mut self,
        port_id: i32,
    ) -> Result<Vec<PortStatsResponse>, Status> {
        let request = Request::new(PortStatsRequest {
            dev_id: self.device_id,
            port_id,
            filters: None,
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["clear_port_stats"])
            .inc();

        let mut stream = self
            .api
            .clear_port_stats(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["clear_port_stats"])
                    .inc();
            })?
            .into_inner();

        let mut responses = Vec::new();
        while let Some(response) = stream.message().await? {
            responses.push(response);
        }
        Ok(responses)
    }

    // --- Stats ---
    pub async fn clear_stats(&mut self) -> Result<Vec<StatsResponse>, Status> {
        let request = Request::new(StatsRequest {
            dev_id: self.device_id,
            filters: None,
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["clear_stats"])
            .inc();

        let mut stream = self
            .api
            .clear_stats(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["clear_stats"])
                    .inc();
            })?
            .into_inner();

        let mut responses = Vec::new();
        while let Some(response) = stream.message().await? {
            responses.push(response);
        }
        Ok(responses)
    }

    // --- SwitchConfig ---
    pub async fn set_switch_config(
        &mut self,
        config: SwitchConfig,
    ) -> Result<Vec<SwitchConfigResponse>, Status> {
        let request = Request::new(SwitchConfigRequest {
            dev_id: self.device_id,
            config: Some(config),
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["set_switch_config"])
            .inc();

        let mut stream = self
            .api
            .set_switch_config(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["set_switch_config"])
                    .inc();
            })?
            .into_inner();

        let mut responses = Vec::new();
        while let Some(response) = stream.message().await? {
            responses.push(response);
        }
        Ok(responses)
    }

    // --- SwitchStats ---
    pub async fn clear_switch_stats(&mut self) -> Result<Vec<SwitchStatsResponse>, Status> {
        let request = Request::new(SwitchStatsRequest {
            dev_id: self.device_id,
            filters: None,
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["clear_switch_stats"])
            .inc();

        let mut stream = self
            .api
            .clear_switch_stats(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["clear_switch_stats"])
                    .inc();
            })?
            .into_inner();

        let mut responses = Vec::new();
        while let Some(response) = stream.message().await? {
            responses.push(response);
        }
        Ok(responses)
    }

    pub async fn get_port_config(
        &mut self,
        port_id: i32,
    ) -> Result<Vec<PortConfigResponse>, Status> {
        let request = Request::new(PortConfigRequest {
            dev_id: self.device_id,
            port_id,
            config: None,
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["get_port_config"])
            .inc();

        let mut stream = self
            .api
            .get_port_config(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["get_port_config"])
                    .inc();
            })?
            .into_inner();

        let mut responses = Vec::new();

        while let Some(response) = stream.message().await? {
            responses.push(response);
        }

        Ok(responses)
    }

    pub async fn get_port_status(
        &mut self,
        port_id: i32,
    ) -> Result<Vec<PortStatusResponse>, Status> {
        let request = Request::new(PortStatusRequest {
            dev_id: self.device_id,
            port_id,
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["get_port_status"])
            .inc();

        let mut stream = self
            .api
            .get_port_status(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["get_port_status"])
                    .inc();
            })?
            .into_inner();

        let mut responses = Vec::new();

        while let Some(response) = stream.message().await? {
            responses.push(response);
        }

        Ok(responses)
    }

    pub async fn get_port_stats(&mut self, port_id: i32) -> Result<Vec<PortStatsResponse>, Status> {
        let request = Request::new(PortStatsRequest {
            dev_id: self.device_id,
            port_id,
            filters: None,
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["get_port_stats"])
            .inc();

        let mut stream = self
            .api
            .get_port_stats(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["get_port_stats"])
                    .inc();
            })?
            .into_inner();

        let mut responses = Vec::new();

        while let Some(response) = stream.message().await? {
            responses.push(response);
        }

        Ok(responses)
    }

    pub async fn get_switch_config(&mut self) -> Result<Vec<SwitchConfigResponse>, Status> {
        let request = Request::new(SwitchConfigRequest {
            dev_id: self.device_id,
            config: None,
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["get_switch_config"])
            .inc();

        let mut stream = self
            .api
            .get_switch_config(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["get_switch_config"])
                    .inc();
            })?
            .into_inner();

        let mut responses = Vec::new();

        while let Some(response) = stream.message().await? {
            responses.push(response);
        }

        Ok(responses)
    }

    pub async fn get_switch_stats(&mut self) -> Result<Vec<SwitchStatsResponse>, Status> {
        let request = Request::new(SwitchStatsRequest {
            dev_id: self.device_id,
            filters: None,
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["get_switch_stats"])
            .inc();

        let mut stream = self
            .api
            .get_switch_stats(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["get_switch_stats"])
                    .inc();
            })?
            .into_inner();

        let mut responses = Vec::new();

        while let Some(response) = stream.message().await? {
            responses.push(response);
        }

        Ok(responses)
    }

    pub async fn get_stats(&mut self) -> Result<Vec<StatsMetric>, Status> {
        let request = Request::new(StatsRequest {
            dev_id: self.device_id,
            filters: None,
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["get_stats"])
            .inc();

        let mut stream = self
            .api
            .get_stats(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["get_stats"])
                    .inc();
            })?
            .into_inner();

        let mut metrics = Vec::new();

        while let Some(response) = stream.message().await? {
            if let Some(stats) = response.stats {
                metrics.extend(stats.metrics);
            }
        }

        Ok(metrics)
    }

    pub async fn get_server_config(&mut self) -> Result<ServerConfig, Status> {
        let request = Request::new(ServerConfigRequest { config: None });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["get_server_config"])
            .inc();

        let mut stream = self
            .api
            .get_server_config(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["get_server_config"])
                    .inc();
            })?
            .into_inner();

        let mut config = None;

        while let Some(response) = stream.message().await? {
            config = response.config;
        }

        config.ok_or_else(|| Status::not_found("No server config found"))
    }

    pub async fn set_server_config(&mut self, config: ServerConfig) -> Result<(), Status> {
        let request = Request::new(ServerConfigRequest {
            config: Some(config),
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["set_server_config"])
            .inc();

        let mut stream = self
            .api
            .set_server_config(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["set_server_config"])
                    .inc();
            })?
            .into_inner();

        while stream.message().await?.is_some() {}

        Ok(())
    }

    pub async fn get_server_status(&mut self) -> Result<ServerStatus, Status> {
        let request = Request::new(ServerStatusRequest {});

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["get_server_status"])
            .inc();

        let mut stream = self
            .api
            .get_server_status(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["get_server_status"])
                    .inc();
            })?
            .into_inner();

        let mut status = None;

        while let Some(response) = stream.message().await? {
            status = response.status;
        }

        status.ok_or_else(|| Status::not_found("No server status found"))
    }

    pub async fn batch(
        &mut self,
        requests: Vec<BatchRequest>,
    ) -> Result<Vec<BatchResponse>, BatchError> {
        let outbound = async_stream::stream! {
            for request in requests {
                yield request;
            }
        };

        let response_stream = self
            .api
            .batch(Request::new(outbound))
            .await
            .map_err(BatchError::Error)?
            .into_inner();

        let mut responses = Vec::new();
        tokio::pin!(response_stream);

        while let Some(response) = response_stream.next().await {
            responses.push(response.map_err(BatchError::Error)?);
        }

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["batch"])
            .inc();

        Ok(responses)
    }
}

#[derive(Debug, Clone)]
pub struct MultiSNCfgClient {
    clients: Vec<SNCfgClient>,
}

impl MultiSNCfgClient {
    #[must_use]
    pub fn new(clients: Vec<SNCfgClient>) -> Self {
        Self { clients }
    }

    pub async fn set_defaults(
        &mut self,
        profile: i32,
    ) -> Result<Vec<Vec<DefaultsResponse>>, Vec<Result<Vec<DefaultsResponse>, Status>>> {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.set_defaults(profile))
            .collect();

        let results: Vec<Result<Vec<DefaultsResponse>, Status>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(results.into_iter().map(Result::unwrap).collect())
        } else {
            Err(results)
        }
    }

    pub async fn get_host_config(
        &mut self,
        host_id: i32,
    ) -> Result<Vec<Vec<HostConfigResponse>>, Vec<Result<Vec<HostConfigResponse>, Status>>> {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.get_host_config(host_id))
            .collect();

        let results: Vec<Result<Vec<HostConfigResponse>, Status>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(results.into_iter().map(Result::unwrap).collect())
        } else {
            Err(results)
        }
    }

    pub async fn set_host_config(
        &mut self,
        host_id: i32,
        config: HostConfig,
    ) -> Result<Vec<Vec<HostConfigResponse>>, Vec<Result<Vec<HostConfigResponse>, Status>>> {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.set_host_config(host_id, config.clone()))
            .collect();

        let results: Vec<Result<Vec<HostConfigResponse>, Status>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(results.into_iter().map(Result::unwrap).collect())
        } else {
            Err(results)
        }
    }

    pub async fn get_host_stats(
        &mut self,
        host_id: i32,
    ) -> Result<Vec<Vec<HostStatsResponse>>, Vec<Result<Vec<HostStatsResponse>, Status>>> {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.get_host_stats(host_id))
            .collect();

        let results: Vec<Result<Vec<HostStatsResponse>, Status>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(results.into_iter().map(Result::unwrap).collect())
        } else {
            Err(results)
        }
    }

    pub async fn clear_host_stats(
        &mut self,
        host_id: i32,
    ) -> Result<Vec<Vec<HostStatsResponse>>, Vec<Result<Vec<HostStatsResponse>, Status>>> {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.clear_host_stats(host_id))
            .collect();

        let results: Vec<Result<Vec<HostStatsResponse>, Status>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(results.into_iter().map(Result::unwrap).collect())
        } else {
            Err(results)
        }
    }

    pub async fn get_module_gpio(
        &mut self,
        mod_id: i32,
    ) -> Result<Vec<Vec<ModuleGpioResponse>>, Vec<Result<Vec<ModuleGpioResponse>, Status>>> {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.get_module_gpio(mod_id))
            .collect();

        let results: Vec<Result<Vec<ModuleGpioResponse>, Status>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(results.into_iter().map(Result::unwrap).collect())
        } else {
            Err(results)
        }
    }

    pub async fn set_module_gpio(
        &mut self,
        mod_id: i32,
        gpio: crate::proto::smartnic::cfg_v2::ModuleGpio,
    ) -> Result<Vec<Vec<ModuleGpioResponse>>, Vec<Result<Vec<ModuleGpioResponse>, Status>>> {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.set_module_gpio(mod_id, gpio.clone()))
            .collect();

        let results: Vec<Result<Vec<ModuleGpioResponse>, Status>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(results.into_iter().map(Result::unwrap).collect())
        } else {
            Err(results)
        }
    }

    pub async fn get_module_info(
        &mut self,
        mod_id: i32,
    ) -> Result<Vec<Vec<ModuleInfoResponse>>, Vec<Result<Vec<ModuleInfoResponse>, Status>>> {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.get_module_info(mod_id))
            .collect();

        let results: Vec<Result<Vec<ModuleInfoResponse>, Status>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(results.into_iter().map(Result::unwrap).collect())
        } else {
            Err(results)
        }
    }

    pub async fn get_module_mem(
        &mut self,
        mod_id: i32,
        mem: crate::proto::smartnic::cfg_v2::ModuleMem,
    ) -> Result<Vec<Vec<ModuleMemResponse>>, Vec<Result<Vec<ModuleMemResponse>, Status>>> {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.get_module_mem(mod_id, mem.clone()))
            .collect();

        let results: Vec<Result<Vec<ModuleMemResponse>, Status>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(results.into_iter().map(Result::unwrap).collect())
        } else {
            Err(results)
        }
    }

    pub async fn set_module_mem(
        &mut self,
        mod_id: i32,
        mem: crate::proto::smartnic::cfg_v2::ModuleMem,
    ) -> Result<Vec<Vec<ModuleMemResponse>>, Vec<Result<Vec<ModuleMemResponse>, Status>>> {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.set_module_mem(mod_id, mem.clone()))
            .collect();

        let results: Vec<Result<Vec<ModuleMemResponse>, Status>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(results.into_iter().map(Result::unwrap).collect())
        } else {
            Err(results)
        }
    }

    pub async fn get_module_status(
        &mut self,
        mod_id: i32,
    ) -> Result<Vec<Vec<ModuleStatusResponse>>, Vec<Result<Vec<ModuleStatusResponse>, Status>>>
    {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.get_module_status(mod_id))
            .collect();

        let results: Vec<Result<Vec<ModuleStatusResponse>, Status>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(results.into_iter().map(Result::unwrap).collect())
        } else {
            Err(results)
        }
    }

    pub async fn set_port_config(
        &mut self,
        port_id: i32,
        config: PortConfig,
    ) -> Result<Vec<Vec<PortConfigResponse>>, Vec<Result<Vec<PortConfigResponse>, Status>>> {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.set_port_config(port_id, config.clone()))
            .collect();

        let results: Vec<Result<Vec<PortConfigResponse>, Status>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(results.into_iter().map(Result::unwrap).collect())
        } else {
            Err(results)
        }
    }

    pub async fn clear_port_stats(
        &mut self,
        port_id: i32,
    ) -> Result<Vec<Vec<PortStatsResponse>>, Vec<Result<Vec<PortStatsResponse>, Status>>> {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.clear_port_stats(port_id))
            .collect();

        let results: Vec<Result<Vec<PortStatsResponse>, Status>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(results.into_iter().map(Result::unwrap).collect())
        } else {
            Err(results)
        }
    }

    pub async fn clear_stats(
        &mut self,
    ) -> Result<Vec<Vec<StatsResponse>>, Vec<Result<Vec<StatsResponse>, Status>>> {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.clear_stats())
            .collect();

        let results: Vec<Result<Vec<StatsResponse>, Status>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(results.into_iter().map(Result::unwrap).collect())
        } else {
            Err(results)
        }
    }

    pub async fn set_switch_config(
        &mut self,
        config: SwitchConfig,
    ) -> Result<Vec<Vec<SwitchConfigResponse>>, Vec<Result<Vec<SwitchConfigResponse>, Status>>>
    {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.set_switch_config(config.clone()))
            .collect();

        let results: Vec<Result<Vec<SwitchConfigResponse>, Status>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(results.into_iter().map(Result::unwrap).collect())
        } else {
            Err(results)
        }
    }

    pub async fn clear_switch_stats(
        &mut self,
    ) -> Result<Vec<Vec<SwitchStatsResponse>>, Vec<Result<Vec<SwitchStatsResponse>, Status>>> {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.clear_switch_stats())
            .collect();

        let results: Vec<Result<Vec<SwitchStatsResponse>, Status>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(results.into_iter().map(Result::unwrap).collect())
        } else {
            Err(results)
        }
    }

    pub async fn get_port_config(
        &mut self,
        port_id: i32,
    ) -> Result<Vec<Vec<PortConfigResponse>>, Vec<Result<Vec<PortConfigResponse>, Status>>> {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.get_port_config(port_id))
            .collect();

        let results: Vec<Result<Vec<PortConfigResponse>, Status>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(results.into_iter().map(Result::unwrap).collect())
        } else {
            Err(results)
        }
    }

    pub async fn get_port_status(
        &mut self,
        port_id: i32,
    ) -> Result<Vec<Vec<PortStatusResponse>>, Vec<Result<Vec<PortStatusResponse>, Status>>> {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.get_port_status(port_id))
            .collect();

        let results: Vec<Result<Vec<PortStatusResponse>, Status>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(results.into_iter().map(Result::unwrap).collect())
        } else {
            Err(results)
        }
    }

    pub async fn get_port_stats(
        &mut self,
        port_id: i32,
    ) -> Result<Vec<Vec<PortStatsResponse>>, Vec<Result<Vec<PortStatsResponse>, Status>>> {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.get_port_stats(port_id))
            .collect();

        let results: Vec<Result<Vec<PortStatsResponse>, Status>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(results.into_iter().map(Result::unwrap).collect())
        } else {
            Err(results)
        }
    }

    pub async fn get_switch_config(
        &mut self,
    ) -> Result<Vec<Vec<SwitchConfigResponse>>, Vec<Result<Vec<SwitchConfigResponse>, Status>>>
    {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.get_switch_config())
            .collect();

        let results: Vec<Result<Vec<SwitchConfigResponse>, Status>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(results.into_iter().map(Result::unwrap).collect())
        } else {
            Err(results)
        }
    }

    pub async fn get_switch_stats(
        &mut self,
    ) -> Result<Vec<Vec<SwitchStatsResponse>>, Vec<Result<Vec<SwitchStatsResponse>, Status>>> {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.get_switch_stats())
            .collect();

        let results: Vec<Result<Vec<SwitchStatsResponse>, Status>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(results.into_iter().map(Result::unwrap).collect())
        } else {
            Err(results)
        }
    }

    pub async fn get_device_info(
        &mut self,
    ) -> Result<Vec<Vec<DeviceInfo>>, Vec<Result<Vec<DeviceInfo>, Status>>> {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.get_device_info())
            .collect();

        let results: Vec<Result<Vec<DeviceInfo>, Status>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(results.into_iter().map(Result::unwrap).collect())
        } else {
            Err(results)
        }
    }

    pub async fn get_device_status(
        &mut self,
    ) -> Result<Vec<Vec<DeviceStatus>>, Vec<Result<Vec<DeviceStatus>, Status>>> {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.get_device_status())
            .collect();

        let results: Vec<Result<Vec<DeviceStatus>, Status>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(results.into_iter().map(Result::unwrap).collect())
        } else {
            Err(results)
        }
    }

    pub async fn get_stats(
        &mut self,
    ) -> Result<Vec<Vec<StatsMetric>>, Vec<Result<Vec<StatsMetric>, Status>>> {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.get_stats())
            .collect();

        let results: Vec<Result<Vec<StatsMetric>, Status>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(results.into_iter().map(Result::unwrap).collect())
        } else {
            Err(results)
        }
    }

    pub async fn get_server_config(&mut self) -> Result<ServerConfig, Status> {
        self.clients
            .first_mut()
            .ok_or_else(|| Status::failed_precondition("No clients available"))?
            .get_server_config()
            .await
    }

    pub async fn set_server_config(
        &mut self,
        config: ServerConfig,
    ) -> Result<Vec<()>, Vec<Result<(), Status>>> {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.set_server_config(config.clone()))
            .collect();

        let results: Vec<Result<(), Status>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(results.into_iter().map(Result::unwrap).collect())
        } else {
            Err(results)
        }
    }

    pub async fn get_server_status(&mut self) -> Result<ServerStatus, Status> {
        self.clients
            .first_mut()
            .ok_or_else(|| Status::failed_precondition("No clients available"))?
            .get_server_status()
            .await
    }
}

#[derive(Clone)]
pub struct BearerTokenInterceptor {
    token: String,
}

impl BearerTokenInterceptor {
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }
}

impl Interceptor for BearerTokenInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let token = format!("Bearer {}", self.token);
        request.metadata_mut().insert(
            "authorization",
            token
                .parse()
                .map_err(|_| Status::invalid_argument("Invalid authorization header value"))?,
        );
        Ok(request)
    }
}

#[derive(Debug)]
pub enum BatchError {
    Error(Status),
}

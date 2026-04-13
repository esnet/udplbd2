// SPDX-License-Identifier: BSD-3-Clause-LBNL
//! Tonic gRPC client for the smartnic-config gRPC API

use crate::{
    grpc_common::{create_grpc_channel, fan_out, stream_collect, BearerTokenInterceptor},
    proto::smartnic::cfg_v2::{
        smartnic_config_client::SmartnicConfigClient, BatchRequest, BatchResponse, DefaultsRequest,
        DefaultsResponse, DeviceInfo, DeviceInfoRequest, DeviceStatus, DeviceStatusRequest,
        HostConfig, HostConfigRequest, HostConfigResponse, HostStatsRequest, HostStatsResponse,
        ModuleGpioRequest, ModuleGpioResponse, ModuleInfoRequest, ModuleInfoResponse,
        ModuleMemRequest, ModuleMemResponse, ModuleStatusRequest, ModuleStatusResponse, PortConfig,
        PortConfigRequest, PortConfigResponse, PortStatsRequest, PortStatsResponse,
        PortStatusRequest, PortStatusResponse, ServerConfig, ServerConfigRequest, ServerStatus,
        ServerStatusRequest, StatsMetric, StatsRequest, StatsResponse, SwitchConfig,
        SwitchConfigRequest, SwitchConfigResponse, SwitchStatsRequest, SwitchStatsResponse,
    },
};
use futures::StreamExt;
use std::path::PathBuf;
use tonic::{service::interceptor::InterceptedService, transport::Channel, Request, Status};

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
        ca_file: Option<PathBuf>,
        auth_token: impl Into<String>,
    ) -> Result<Self, tonic::transport::Error> {
        let channel = create_grpc_channel(addr, verify, ca_file, "sn-cfg").await?;
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
        stream_collect(
            "get_device_info",
            request,
            |r| self.api.get_device_info(r),
            |resp| resp.info,
        )
        .await
    }

    pub async fn get_device_status(&mut self) -> Result<Vec<DeviceStatus>, Status> {
        let request = Request::new(DeviceStatusRequest {
            dev_id: self.device_id,
        });
        stream_collect(
            "get_device_status",
            request,
            |r| self.api.get_device_status(r),
            |resp| resp.status,
        )
        .await
    }

    pub async fn set_defaults(&mut self, profile: i32) -> Result<Vec<DefaultsResponse>, Status> {
        let request = Request::new(DefaultsRequest {
            dev_id: self.device_id,
            profile,
        });
        stream_collect("set_defaults", request, |r| self.api.set_defaults(r), Some).await
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
        stream_collect(
            "get_host_config",
            request,
            |r| self.api.get_host_config(r),
            Some,
        )
        .await
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
        stream_collect(
            "set_host_config",
            request,
            |r| self.api.set_host_config(r),
            Some,
        )
        .await
    }

    // --- HostStats ---
    pub async fn get_host_stats(&mut self, host_id: i32) -> Result<Vec<HostStatsResponse>, Status> {
        let request = Request::new(HostStatsRequest {
            dev_id: self.device_id,
            host_id,
            filters: None,
        });
        stream_collect(
            "get_host_stats",
            request,
            |r| self.api.get_host_stats(r),
            Some,
        )
        .await
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
        stream_collect(
            "clear_host_stats",
            request,
            |r| self.api.clear_host_stats(r),
            Some,
        )
        .await
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
        stream_collect(
            "get_module_gpio",
            request,
            |r| self.api.get_module_gpio(r),
            Some,
        )
        .await
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
        stream_collect(
            "set_module_gpio",
            request,
            |r| self.api.set_module_gpio(r),
            Some,
        )
        .await
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
        stream_collect(
            "get_module_info",
            request,
            |r| self.api.get_module_info(r),
            Some,
        )
        .await
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
        stream_collect(
            "get_module_mem",
            request,
            |r| self.api.get_module_mem(r),
            Some,
        )
        .await
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
        stream_collect(
            "set_module_mem",
            request,
            |r| self.api.set_module_mem(r),
            Some,
        )
        .await
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
        stream_collect(
            "get_module_status",
            request,
            |r| self.api.get_module_status(r),
            Some,
        )
        .await
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
        stream_collect(
            "set_port_config",
            request,
            |r| self.api.set_port_config(r),
            Some,
        )
        .await
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
        stream_collect(
            "clear_port_stats",
            request,
            |r| self.api.clear_port_stats(r),
            Some,
        )
        .await
    }

    // --- Stats ---
    pub async fn clear_stats(&mut self) -> Result<Vec<StatsResponse>, Status> {
        let request = Request::new(StatsRequest {
            dev_id: self.device_id,
            filters: None,
        });
        stream_collect("clear_stats", request, |r| self.api.clear_stats(r), Some).await
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
        stream_collect(
            "set_switch_config",
            request,
            |r| self.api.set_switch_config(r),
            Some,
        )
        .await
    }

    // --- SwitchStats ---
    pub async fn clear_switch_stats(&mut self) -> Result<Vec<SwitchStatsResponse>, Status> {
        let request = Request::new(SwitchStatsRequest {
            dev_id: self.device_id,
            filters: None,
        });
        stream_collect(
            "clear_switch_stats",
            request,
            |r| self.api.clear_switch_stats(r),
            Some,
        )
        .await
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
        stream_collect(
            "get_port_config",
            request,
            |r| self.api.get_port_config(r),
            Some,
        )
        .await
    }

    pub async fn get_port_status(
        &mut self,
        port_id: i32,
    ) -> Result<Vec<PortStatusResponse>, Status> {
        let request = Request::new(PortStatusRequest {
            dev_id: self.device_id,
            port_id,
        });
        stream_collect(
            "get_port_status",
            request,
            |r| self.api.get_port_status(r),
            Some,
        )
        .await
    }

    pub async fn get_port_stats(&mut self, port_id: i32) -> Result<Vec<PortStatsResponse>, Status> {
        let request = Request::new(PortStatsRequest {
            dev_id: self.device_id,
            port_id,
            filters: None,
        });
        stream_collect(
            "get_port_stats",
            request,
            |r| self.api.get_port_stats(r),
            Some,
        )
        .await
    }

    pub async fn get_switch_config(&mut self) -> Result<Vec<SwitchConfigResponse>, Status> {
        let request = Request::new(SwitchConfigRequest {
            dev_id: self.device_id,
            config: None,
        });
        stream_collect(
            "get_switch_config",
            request,
            |r| self.api.get_switch_config(r),
            Some,
        )
        .await
    }

    pub async fn get_switch_stats(&mut self) -> Result<Vec<SwitchStatsResponse>, Status> {
        let request = Request::new(SwitchStatsRequest {
            dev_id: self.device_id,
            filters: None,
        });
        stream_collect(
            "get_switch_stats",
            request,
            |r| self.api.get_switch_stats(r),
            Some,
        )
        .await
    }

    pub async fn get_stats(&mut self) -> Result<Vec<StatsMetric>, Status> {
        let request = Request::new(StatsRequest {
            dev_id: self.device_id,
            filters: None,
        });
        // Each response carries a nested list of metrics; flatten them all.
        let responses = stream_collect(
            "get_stats",
            request,
            |r| self.api.get_stats(r),
            |resp| resp.stats,
        )
        .await?;
        Ok(responses.into_iter().flat_map(|s| s.metrics).collect())
    }

    pub async fn get_server_config(&mut self) -> Result<ServerConfig, Status> {
        let request = Request::new(ServerConfigRequest { config: None });
        let mut configs = stream_collect(
            "get_server_config",
            request,
            |r| self.api.get_server_config(r),
            |resp| resp.config,
        )
        .await?;
        configs
            .pop()
            .ok_or_else(|| Status::not_found("No server config found"))
    }

    pub async fn set_server_config(&mut self, config: ServerConfig) -> Result<(), Status> {
        let request = Request::new(ServerConfigRequest {
            config: Some(config),
        });
        stream_collect(
            "set_server_config",
            request,
            |r| self.api.set_server_config(r),
            |_| None::<()>,
        )
        .await?;
        Ok(())
    }

    pub async fn get_server_status(&mut self) -> Result<ServerStatus, Status> {
        let request = Request::new(ServerStatusRequest {});
        let mut statuses = stream_collect(
            "get_server_status",
            request,
            |r| self.api.get_server_status(r),
            |resp| resp.status,
        )
        .await?;
        statuses
            .pop()
            .ok_or_else(|| Status::not_found("No server status found"))
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
        fan_out(
            self.clients
                .iter_mut()
                .map(|c| c.set_defaults(profile))
                .collect(),
        )
        .await
    }

    pub async fn get_host_config(
        &mut self,
        host_id: i32,
    ) -> Result<Vec<Vec<HostConfigResponse>>, Vec<Result<Vec<HostConfigResponse>, Status>>> {
        fan_out(
            self.clients
                .iter_mut()
                .map(|c| c.get_host_config(host_id))
                .collect(),
        )
        .await
    }

    pub async fn set_host_config(
        &mut self,
        host_id: i32,
        config: HostConfig,
    ) -> Result<Vec<Vec<HostConfigResponse>>, Vec<Result<Vec<HostConfigResponse>, Status>>> {
        fan_out(
            self.clients
                .iter_mut()
                .map(|c| c.set_host_config(host_id, config.clone()))
                .collect(),
        )
        .await
    }

    pub async fn get_host_stats(
        &mut self,
        host_id: i32,
    ) -> Result<Vec<Vec<HostStatsResponse>>, Vec<Result<Vec<HostStatsResponse>, Status>>> {
        fan_out(
            self.clients
                .iter_mut()
                .map(|c| c.get_host_stats(host_id))
                .collect(),
        )
        .await
    }

    pub async fn clear_host_stats(
        &mut self,
        host_id: i32,
    ) -> Result<Vec<Vec<HostStatsResponse>>, Vec<Result<Vec<HostStatsResponse>, Status>>> {
        fan_out(
            self.clients
                .iter_mut()
                .map(|c| c.clear_host_stats(host_id))
                .collect(),
        )
        .await
    }

    pub async fn get_module_gpio(
        &mut self,
        mod_id: i32,
    ) -> Result<Vec<Vec<ModuleGpioResponse>>, Vec<Result<Vec<ModuleGpioResponse>, Status>>> {
        fan_out(
            self.clients
                .iter_mut()
                .map(|c| c.get_module_gpio(mod_id))
                .collect(),
        )
        .await
    }

    pub async fn set_module_gpio(
        &mut self,
        mod_id: i32,
        gpio: crate::proto::smartnic::cfg_v2::ModuleGpio,
    ) -> Result<Vec<Vec<ModuleGpioResponse>>, Vec<Result<Vec<ModuleGpioResponse>, Status>>> {
        fan_out(
            self.clients
                .iter_mut()
                .map(|c| c.set_module_gpio(mod_id, gpio))
                .collect(),
        )
        .await
    }

    pub async fn get_module_info(
        &mut self,
        mod_id: i32,
    ) -> Result<Vec<Vec<ModuleInfoResponse>>, Vec<Result<Vec<ModuleInfoResponse>, Status>>> {
        fan_out(
            self.clients
                .iter_mut()
                .map(|c| c.get_module_info(mod_id))
                .collect(),
        )
        .await
    }

    pub async fn get_module_mem(
        &mut self,
        mod_id: i32,
        mem: crate::proto::smartnic::cfg_v2::ModuleMem,
    ) -> Result<Vec<Vec<ModuleMemResponse>>, Vec<Result<Vec<ModuleMemResponse>, Status>>> {
        fan_out(
            self.clients
                .iter_mut()
                .map(|c| c.get_module_mem(mod_id, mem.clone()))
                .collect(),
        )
        .await
    }

    pub async fn set_module_mem(
        &mut self,
        mod_id: i32,
        mem: crate::proto::smartnic::cfg_v2::ModuleMem,
    ) -> Result<Vec<Vec<ModuleMemResponse>>, Vec<Result<Vec<ModuleMemResponse>, Status>>> {
        fan_out(
            self.clients
                .iter_mut()
                .map(|c| c.set_module_mem(mod_id, mem.clone()))
                .collect(),
        )
        .await
    }

    pub async fn get_module_status(
        &mut self,
        mod_id: i32,
    ) -> Result<Vec<Vec<ModuleStatusResponse>>, Vec<Result<Vec<ModuleStatusResponse>, Status>>>
    {
        fan_out(
            self.clients
                .iter_mut()
                .map(|c| c.get_module_status(mod_id))
                .collect(),
        )
        .await
    }

    pub async fn set_port_config(
        &mut self,
        port_id: i32,
        config: PortConfig,
    ) -> Result<Vec<Vec<PortConfigResponse>>, Vec<Result<Vec<PortConfigResponse>, Status>>> {
        fan_out(
            self.clients
                .iter_mut()
                .map(|c| c.set_port_config(port_id, config))
                .collect(),
        )
        .await
    }

    pub async fn clear_port_stats(
        &mut self,
        port_id: i32,
    ) -> Result<Vec<Vec<PortStatsResponse>>, Vec<Result<Vec<PortStatsResponse>, Status>>> {
        fan_out(
            self.clients
                .iter_mut()
                .map(|c| c.clear_port_stats(port_id))
                .collect(),
        )
        .await
    }

    pub async fn clear_stats(
        &mut self,
    ) -> Result<Vec<Vec<StatsResponse>>, Vec<Result<Vec<StatsResponse>, Status>>> {
        fan_out(self.clients.iter_mut().map(|c| c.clear_stats()).collect()).await
    }

    pub async fn set_switch_config(
        &mut self,
        config: SwitchConfig,
    ) -> Result<Vec<Vec<SwitchConfigResponse>>, Vec<Result<Vec<SwitchConfigResponse>, Status>>>
    {
        fan_out(
            self.clients
                .iter_mut()
                .map(|c| c.set_switch_config(config.clone()))
                .collect(),
        )
        .await
    }

    pub async fn clear_switch_stats(
        &mut self,
    ) -> Result<Vec<Vec<SwitchStatsResponse>>, Vec<Result<Vec<SwitchStatsResponse>, Status>>> {
        fan_out(
            self.clients
                .iter_mut()
                .map(|c| c.clear_switch_stats())
                .collect(),
        )
        .await
    }

    pub async fn get_port_config(
        &mut self,
        port_id: i32,
    ) -> Result<Vec<Vec<PortConfigResponse>>, Vec<Result<Vec<PortConfigResponse>, Status>>> {
        fan_out(
            self.clients
                .iter_mut()
                .map(|c| c.get_port_config(port_id))
                .collect(),
        )
        .await
    }

    pub async fn get_port_status(
        &mut self,
        port_id: i32,
    ) -> Result<Vec<Vec<PortStatusResponse>>, Vec<Result<Vec<PortStatusResponse>, Status>>> {
        fan_out(
            self.clients
                .iter_mut()
                .map(|c| c.get_port_status(port_id))
                .collect(),
        )
        .await
    }

    pub async fn get_port_stats(
        &mut self,
        port_id: i32,
    ) -> Result<Vec<Vec<PortStatsResponse>>, Vec<Result<Vec<PortStatsResponse>, Status>>> {
        fan_out(
            self.clients
                .iter_mut()
                .map(|c| c.get_port_stats(port_id))
                .collect(),
        )
        .await
    }

    pub async fn get_switch_config(
        &mut self,
    ) -> Result<Vec<Vec<SwitchConfigResponse>>, Vec<Result<Vec<SwitchConfigResponse>, Status>>>
    {
        fan_out(
            self.clients
                .iter_mut()
                .map(|c| c.get_switch_config())
                .collect(),
        )
        .await
    }

    pub async fn get_switch_stats(
        &mut self,
    ) -> Result<Vec<Vec<SwitchStatsResponse>>, Vec<Result<Vec<SwitchStatsResponse>, Status>>> {
        fan_out(
            self.clients
                .iter_mut()
                .map(|c| c.get_switch_stats())
                .collect(),
        )
        .await
    }

    pub async fn get_device_info(
        &mut self,
    ) -> Result<Vec<Vec<DeviceInfo>>, Vec<Result<Vec<DeviceInfo>, Status>>> {
        fan_out(
            self.clients
                .iter_mut()
                .map(|c| c.get_device_info())
                .collect(),
        )
        .await
    }

    pub async fn get_device_status(
        &mut self,
    ) -> Result<Vec<Vec<DeviceStatus>>, Vec<Result<Vec<DeviceStatus>, Status>>> {
        fan_out(
            self.clients
                .iter_mut()
                .map(|c| c.get_device_status())
                .collect(),
        )
        .await
    }

    pub async fn get_stats(
        &mut self,
    ) -> Result<Vec<Vec<StatsMetric>>, Vec<Result<Vec<StatsMetric>, Status>>> {
        fan_out(self.clients.iter_mut().map(|c| c.get_stats()).collect()).await
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
        fan_out(
            self.clients
                .iter_mut()
                .map(|c| c.set_server_config(config.clone()))
                .collect(),
        )
        .await
    }

    pub async fn get_server_status(&mut self) -> Result<ServerStatus, Status> {
        self.clients
            .first_mut()
            .ok_or_else(|| Status::failed_precondition("No clients available"))?
            .get_server_status()
            .await
    }
}

#[derive(Debug)]
pub enum BatchError {
    Error(Status),
}

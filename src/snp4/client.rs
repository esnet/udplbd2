//! Tonic gRPC client for the smartnic-p4 gRPC API
use crate::{
    proto::smartnic::p4_v2::{batch_response, ErrorCode},
    snp4::rules::TableUpdate,
};
use futures::{future::join_all, StreamExt};
use tonic::{
    service::{interceptor::InterceptedService, Interceptor},
    transport::{Channel, ClientTlsConfig, Endpoint},
    Request, Status,
};
use tracing::{trace, warn};

use crate::proto::smartnic::p4_v2::{
    batch_request, smartnic_p4_client::SmartnicP4Client, BatchOperation, BatchRequest,
    BatchResponse, DeviceInfo, DeviceInfoRequest, PipelineInfoRequest, PipelineInfoResponse,
    PipelineStatsRequest, ServerConfig, ServerConfigRequest, ServerDebug, ServerDebugFlag,
    ServerStatus, ServerStatusRequest, StatsMetric, TableRequest, TableResponse, TableRule,
    TableRuleRequest,
};

// use tracing::{debug, info};

#[derive(Debug, Clone)]
pub struct SNP4Client {
    api: SmartnicP4Client<InterceptedService<Channel, BearerTokenInterceptor>>,
    pipeline_id: i32,
    device_id: i32,
}

impl SNP4Client {
    pub async fn new(
        addr: &str,
        pipeline_id: i32,
        device_id: i32,
        verify: bool,
        auth_token: impl Into<String>,
    ) -> Result<Self, tonic::transport::Error> {
        let mut channel = Channel::from_shared(addr.to_string()).unwrap();

        if addr.starts_with("https://") {
            let tls_config = ClientTlsConfig::new().with_enabled_roots();
            if !verify {
                // TODO
                unimplemented!()
            }
            channel = channel.tls_config(tls_config)?;
        }

        let channel = channel.connect().await?;
        let interceptor = BearerTokenInterceptor::new(auth_token);

        Ok(Self {
            api: SmartnicP4Client::with_interceptor(channel, interceptor),
            pipeline_id,
            device_id,
        })
    }

    pub async fn turmoil() -> Result<Self, tonic::transport::Error> {
        let channel = Endpoint::new("http://dataplane:50051")?
            .connect_with_connector(crate::dataplane::turmoil::connector::connector())
            .await?;
        let interceptor = BearerTokenInterceptor::new("test");
        Ok(Self {
            api: SmartnicP4Client::with_interceptor(channel, interceptor),
            pipeline_id: 0,
            device_id: 0,
        })
    }

    pub async fn get_pipeline_info(&mut self) -> Result<Vec<PipelineInfoResponse>, Status> {
        let request = Request::new(PipelineInfoRequest {
            dev_id: self.device_id,
            pipeline_id: self.pipeline_id,
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["get_pipeline_info"])
            .inc();
        let mut stream = self
            .api
            .get_pipeline_info(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["get_pipeline_info"])
                    .inc();
            })?
            .into_inner();
        let mut responses = Vec::new();

        while let Some(response) = stream.message().await? {
            responses.push(response);
        }

        Ok(responses)
    }

    pub async fn clear_tables(&mut self) -> Result<Vec<TableResponse>, Status> {
        let request = Request::new(TableRequest {
            dev_id: self.device_id,
            pipeline_id: self.pipeline_id,
            table_name: String::new(), // Empty for all tables
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["clear_table"])
            .inc();
        let mut stream = self
            .api
            .clear_table(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["clear_table"])
                    .inc();
            })?
            .into_inner();
        let mut responses = Vec::new();

        while let Some(response) = stream.message().await? {
            responses.push(response);
        }

        Ok(responses)
    }

    pub async fn clear_table(&mut self, table_name: &str) -> Result<Vec<TableResponse>, Status> {
        let request = Request::new(TableRequest {
            dev_id: self.device_id,
            pipeline_id: self.pipeline_id,
            table_name: table_name.to_string(),
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["clear_table"])
            .inc();

        let mut stream = self
            .api
            .clear_table(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["clear_table"])
                    .inc();
            })?
            .into_inner();

        let mut responses = Vec::new();

        while let Some(response) = stream.message().await? {
            responses.push(response);
        }

        Ok(responses)
    }

    pub async fn batch(
        &mut self,
        requests: Vec<BatchRequest>,
    ) -> Result<Vec<BatchResponse>, BatchError> {
        // Log the batch requests at debug and trace levels
        let cloned_requests = requests.clone();
        for request in &requests {
            if let Some(batch_request::Item::TableRule(table_rule_request)) = &request.item {
                trace!(
                    "batch request: Operation = {:?}, Device ID = {}, Pipeline ID = {}",
                    request.op,
                    table_rule_request.dev_id,
                    table_rule_request.pipeline_id
                );

                // Log the table rules in the request
                for rule in &table_rule_request.rules {
                    trace!("  rule: {}", rule);
                }
            }
        }

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

        // Collect failed rules by matching indices
        let mut failed_rules = Vec::new();

        for (req_index, request) in cloned_requests.iter().enumerate() {
            if let Some(batch_request::Item::TableRule(table_rule_request)) = &request.item {
                if let Some(batch_response::Item::TableRule(rule_response)) =
                    &responses[req_index].item
                {
                    if rule_response.error_code != ErrorCode::EcOk as i32 {
                        // Match the failing response to the rule using the index
                        if let Some(rule) = table_rule_request.rules.get(req_index) {
                            failed_rules.push(rule.to_string());
                        }
                    }
                }
            }
        }

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["batch"])
            .inc();

        if !failed_rules.is_empty() {
            warn!(
                "Batch operation completed with errors. Failed rules:\n{}",
                failed_rules.join("\n")
            );
            crate::metrics::SMARTNIC_GRPC_ERRORS
                .with_label_values(&["batch"])
                .inc();
            return Err(BatchError::Incomplete(responses));
        }

        Ok(responses)
    }

    // Helper for creating batch requests
    fn create_batch_requests(
        &self,
        op: BatchOperation,
        rules: &[TableRule],
        replace: bool,
    ) -> Vec<BatchRequest> {
        let mut rules = rules.to_vec();
        for rule in &mut rules {
            rule.replace = replace;
        }

        vec![BatchRequest {
            op: op as i32,
            item: Some(batch_request::Item::TableRule(TableRuleRequest {
                dev_id: self.device_id,
                pipeline_id: self.pipeline_id,
                rules,
            })),
        }]
    }

    pub async fn bulk_update(
        &mut self,
        updates: &[TableUpdate],
    ) -> Result<Vec<BatchResponse>, BatchError> {
        let mut all_responses = Vec::new();

        for update in updates {
            // Handle insertions
            if !update.insertions.is_empty() {
                let requests = self.create_batch_requests(
                    BatchOperation::BopInsert,
                    &update.insertions,
                    false,
                );
                match self.batch(requests).await {
                    Ok(responses) => all_responses.extend(responses),
                    Err(err) => return Err(err),
                }
            }
        }

        for update in updates {
            // Handle updates
            if !update.updates.is_empty() {
                let requests =
                    self.create_batch_requests(BatchOperation::BopInsert, &update.updates, true);
                match self.batch(requests).await {
                    Ok(responses) => all_responses.extend(responses),
                    Err(err) => return Err(err),
                }
            }
        }

        for i in (0..updates.len()).rev() {
            let update = &updates[i];
            // Handle deletions
            if !update.deletions.is_empty() {
                let requests =
                    self.create_batch_requests(BatchOperation::BopDelete, &update.deletions, false);
                match self.batch(requests).await {
                    Ok(responses) => all_responses.extend(responses),
                    Err(err) => return Err(err),
                }
            }
        }

        Ok(all_responses)
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

    pub async fn get_pipeline_stats(&mut self) -> Result<Vec<StatsMetric>, Status> {
        let request = Request::new(PipelineStatsRequest {
            dev_id: self.device_id,
            pipeline_id: self.pipeline_id,
            filters: None,
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["get_pipeline_stats"])
            .inc();

        let mut stream = self
            .api
            .get_pipeline_stats(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["get_pipeline_stats"])
                    .inc();
            })?
            .into_inner();

        let mut stats = Vec::new();

        while let Some(response) = stream.message().await? {
            if let Some(pipeline_stats) = response.stats {
                stats.extend(pipeline_stats.metrics);
            }
        }

        Ok(stats)
    }

    pub async fn clear_pipeline_stats(&mut self) -> Result<(), Status> {
        let request = Request::new(PipelineStatsRequest {
            dev_id: self.device_id,
            pipeline_id: self.pipeline_id,
            filters: None,
        });

        crate::metrics::SMARTNIC_GRPC
            .with_label_values(&["clear_pipeline_stats"])
            .inc();

        let mut stream = self
            .api
            .clear_pipeline_stats(request)
            .await
            .inspect_err(|_| {
                crate::metrics::SMARTNIC_GRPC_ERRORS
                    .with_label_values(&["clear_pipeline_stats"])
                    .inc();
            })?
            .into_inner();

        while stream.message().await?.is_some() {}

        Ok(())
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

    pub async fn set_server_config(
        &mut self,
        enables: Vec<ServerDebugFlag>,
        disables: Vec<ServerDebugFlag>,
    ) -> Result<(), Status> {
        let request = Request::new(ServerConfigRequest {
            config: Some(ServerConfig {
                debug: Some(ServerDebug {
                    enables: enables.into_iter().map(|f| f as i32).collect(),
                    disables: disables.into_iter().map(|f| f as i32).collect(),
                }),
            }),
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
}

#[derive(Debug, Clone)]
pub struct MultiSNP4Client {
    clients: Vec<SNP4Client>,
}

impl MultiSNP4Client {
    #[must_use]
    pub fn new(clients: Vec<SNP4Client>) -> Self {
        Self { clients }
    }

    pub async fn bulk_update(
        &mut self,
        updates: &[TableUpdate],
    ) -> Result<Vec<Vec<BatchResponse>>, Vec<Result<Vec<BatchResponse>, BatchError>>> {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.bulk_update(updates))
            .collect();

        let results: Vec<Result<Vec<BatchResponse>, BatchError>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(results.into_iter().map(Result::unwrap).collect())
        } else {
            Err(results)
        }
    }

    pub async fn get_pipeline_info(
        &mut self,
    ) -> Result<Vec<Vec<PipelineInfoResponse>>, Vec<Result<Vec<PipelineInfoResponse>, Status>>>
    {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.get_pipeline_info())
            .collect();

        let results: Vec<Result<Vec<PipelineInfoResponse>, Status>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(results.into_iter().map(Result::unwrap).collect())
        } else {
            Err(results)
        }
    }

    pub async fn clear_tables(
        &mut self,
    ) -> Result<Vec<Vec<TableResponse>>, Vec<Result<Vec<TableResponse>, Status>>> {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.clear_tables())
            .collect();

        let results: Vec<Result<Vec<TableResponse>, Status>> = join_all(futures).await;

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

    pub async fn get_pipeline_stats(
        &mut self,
    ) -> Result<Vec<Vec<StatsMetric>>, Vec<Result<Vec<StatsMetric>, Status>>> {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.get_pipeline_stats())
            .collect();

        let results: Vec<Result<Vec<StatsMetric>, Status>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(results.into_iter().map(Result::unwrap).collect())
        } else {
            Err(results)
        }
    }

    pub async fn clear_pipeline_stats(&mut self) -> Result<(), Vec<Result<(), Status>>> {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.clear_pipeline_stats())
            .collect();

        let results: Vec<Result<(), Status>> = join_all(futures).await;

        if results.iter().all(|r| r.is_ok()) {
            Ok(())
        } else {
            Err(results)
        }
    }

    // These remain unchanged as they only use the first client
    pub async fn get_server_config(&mut self) -> Result<ServerConfig, Status> {
        self.clients
            .first_mut()
            .ok_or_else(|| Status::failed_precondition("No clients available"))?
            .get_server_config()
            .await
    }

    pub async fn set_server_config(
        &mut self,
        enables: Vec<ServerDebugFlag>,
        disables: Vec<ServerDebugFlag>,
    ) -> Result<Vec<()>, Vec<Result<(), Status>>> {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|client| client.set_server_config(enables.clone(), disables.clone()))
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
    Incomplete(Vec<BatchResponse>), // Partial success with the full response list
    Error(Status),                  // API error
}

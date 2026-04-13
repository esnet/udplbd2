// SPDX-License-Identifier: BSD-3-Clause-LBNL
//! Tonic gRPC client for the smartnic-p4 gRPC API
use crate::{
    grpc_common::{create_grpc_channel, fan_out, stream_collect, BearerTokenInterceptor},
    proto::smartnic::p4_v2::{batch_response, ErrorCode},
    snp4::rules::TableUpdate,
};
use futures::StreamExt;
use tonic::{
    service::interceptor::InterceptedService,
    transport::{Channel, Endpoint},
    Request, Status,
};
use tracing::{debug, trace, warn};

use crate::proto::smartnic::p4_v2::{
    batch_request, smartnic_p4_client::SmartnicP4Client, BatchOperation, BatchRequest,
    BatchResponse, DeviceInfo, DeviceInfoRequest, PipelineInfoRequest, PipelineInfoResponse,
    PipelineStatsRequest, ServerConfig, ServerConfigRequest, ServerDebug, ServerDebugFlag,
    ServerStatus, ServerStatusRequest, StatsMetric, TableRequest, TableResponse, TableRule,
    TableRuleRequest,
};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct SNP4Client {
    api: SmartnicP4Client<InterceptedService<Channel, BearerTokenInterceptor>>,
    pipeline_id: i32,
    device_id: i32,
    pub clear_table_repeats: usize,
}

impl SNP4Client {
    pub async fn new(
        addr: &str,
        pipeline_id: i32,
        device_id: i32,
        verify: bool,
        ca_file: Option<PathBuf>,
        auth_token: impl Into<String>,
    ) -> Result<Self, tonic::transport::Error> {
        let channel = create_grpc_channel(addr, verify, ca_file, "sn-p4").await?;
        let interceptor = BearerTokenInterceptor::new(auth_token);

        Ok(Self {
            api: SmartnicP4Client::with_interceptor(channel, interceptor),
            pipeline_id,
            device_id,
            clear_table_repeats: 1,
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
            clear_table_repeats: 1,
        })
    }

    pub async fn get_pipeline_info(&mut self) -> Result<Vec<PipelineInfoResponse>, Status> {
        let request = Request::new(PipelineInfoRequest {
            dev_id: self.device_id,
            pipeline_id: self.pipeline_id,
        });
        stream_collect("get_pipeline_info", request, |r| self.api.get_pipeline_info(r), Some).await
    }

    pub async fn clear_tables(&mut self) -> Result<Vec<TableResponse>, Status> {
        debug!(
            "clearing all tables {} times (dev_id={}, pipeline_id={})",
            self.clear_table_repeats, self.device_id, self.pipeline_id
        );

        let mut all_responses = Vec::new();
        for _ in 0..self.clear_table_repeats {
            let responses = self.clear_tables_once().await?;
            all_responses.extend(responses);
        }
        Ok(all_responses)
    }

    pub async fn clear_tables_once(&mut self) -> Result<Vec<TableResponse>, Status> {
        let request = Request::new(TableRequest {
            dev_id: self.device_id,
            pipeline_id: self.pipeline_id,
            table_name: String::new(),
        });
        stream_collect("clear_table", request, |r| self.api.clear_table(r), Some).await
    }

    /// Clear the table multiple times as configured by clear_table_repeats.
    pub async fn clear_table(&mut self, table_name: &str) -> Result<Vec<TableResponse>, Status> {
        debug!(
            "clearing table '{}' {} times (dev_id={}, pipeline_id={})",
            table_name, self.clear_table_repeats, self.device_id, self.pipeline_id
        );

        let mut all_responses = Vec::new();
        for _ in 0..self.clear_table_repeats {
            let responses = self.clear_table_once(table_name).await?;
            all_responses.extend(responses);
        }
        Ok(all_responses)
    }

    async fn clear_table_once(&mut self, table_name: &str) -> Result<Vec<TableResponse>, Status> {
        let request = Request::new(TableRequest {
            dev_id: self.device_id,
            pipeline_id: self.pipeline_id,
            table_name: table_name.to_string(),
        });
        stream_collect("clear_table", request, |r| self.api.clear_table(r), Some).await
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
        stream_collect(
            "get_device_info",
            request,
            |r| self.api.get_device_info(r),
            |resp| resp.info,
        )
        .await
    }

    pub async fn get_pipeline_stats(&mut self) -> Result<Vec<StatsMetric>, Status> {
        let request = Request::new(PipelineStatsRequest {
            dev_id: self.device_id,
            pipeline_id: self.pipeline_id,
            filters: None,
        });
        // Each response carries a nested list of metrics; flatten them all.
        let responses = stream_collect(
            "get_pipeline_stats",
            request,
            |r| self.api.get_pipeline_stats(r),
            |resp| resp.stats,
        )
        .await?;
        Ok(responses.into_iter().flat_map(|s| s.metrics).collect())
    }

    pub async fn clear_pipeline_stats(&mut self) -> Result<(), Status> {
        self.clear_pipeline_stats_with_filters(None).await
    }

    pub async fn clear_pipeline_stats_with_filters(
        &mut self,
        filters: Option<crate::proto::smartnic::p4_v2::StatsFilters>,
    ) -> Result<(), Status> {
        let request = Request::new(PipelineStatsRequest {
            dev_id: self.device_id,
            pipeline_id: self.pipeline_id,
            filters,
        });
        stream_collect(
            "clear_pipeline_stats",
            request,
            |r| self.api.clear_pipeline_stats(r),
            |_| None::<()>,
        )
        .await?;
        Ok(())
    }

    /// Clear stats for specific metric names at a specific index.
    /// This is useful for clearing counters for a specific member or LB.
    pub async fn clear_stats_by_names_and_index(
        &mut self,
        metric_names: &[&str],
        index: u32,
    ) -> Result<(), Status> {
        use crate::proto::smartnic::p4_v2::{
            stats_metric_filter, stats_metric_match, StatsFilters, StatsMetricFilter,
            StatsMetricMatch, StatsMetricMatchIndexSlice, StatsMetricMatchIndices,
            StatsMetricMatchString,
        };

        // Build a filter that matches (name is one of the specified metrics) AND (index equals the specified index)
        let name_filters: Vec<StatsMetricFilter> = metric_names
            .iter()
            .map(|name| StatsMetricFilter {
                negated: false,
                term: Some(stats_metric_filter::Term::Match(StatsMetricMatch {
                    attribute: Some(stats_metric_match::Attribute::Name(
                        StatsMetricMatchString {
                            method: Some(
                                crate::proto::smartnic::p4_v2::stats_metric_match_string::Method::Exact(
                                    name.to_string(),
                                ),
                            ),
                        },
                    )),
                })),
            })
            .collect();

        let index_filter = StatsMetricFilter {
            negated: false,
            term: Some(stats_metric_filter::Term::Match(StatsMetricMatch {
                attribute: Some(stats_metric_match::Attribute::Indices(
                    StatsMetricMatchIndices {
                        slices: vec![StatsMetricMatchIndexSlice {
                            start: index as i32,
                            end: index as i32,
                            step: 1,
                        }],
                    },
                )),
            })),
        };

        let filters = Some(StatsFilters {
            non_zero: false,
            metric_filter: Some(StatsMetricFilter {
                negated: false,
                term: Some(stats_metric_filter::Term::AllSet(
                    stats_metric_filter::Set {
                        members: vec![
                            StatsMetricFilter {
                                negated: false,
                                term: Some(stats_metric_filter::Term::AnySet(
                                    stats_metric_filter::Set {
                                        members: name_filters,
                                    },
                                )),
                            },
                            index_filter,
                        ],
                    },
                )),
            }),
            with_labels: false,
            ..Default::default()
        });

        self.clear_pipeline_stats_with_filters(filters).await
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
            .map(|c| c.bulk_update(updates))
            .collect();
        let results = futures::future::join_all(futures).await;
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
        fan_out(
            self.clients
                .iter_mut()
                .map(|c| c.get_pipeline_info())
                .collect(),
        )
        .await
    }

    pub async fn clear_tables(
        &mut self,
    ) -> Result<Vec<Vec<TableResponse>>, Vec<Result<Vec<TableResponse>, Status>>> {
        fan_out(
            self.clients
                .iter_mut()
                .map(|c| c.clear_tables())
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

    pub async fn get_pipeline_stats(
        &mut self,
    ) -> Result<Vec<Vec<StatsMetric>>, Vec<Result<Vec<StatsMetric>, Status>>> {
        fan_out(
            self.clients
                .iter_mut()
                .map(|c| c.get_pipeline_stats())
                .collect(),
        )
        .await
    }

    pub async fn clear_pipeline_stats(&mut self) -> Result<(), Vec<Result<(), Status>>> {
        self.clear_pipeline_stats_with_filters(None).await
    }

    pub async fn clear_pipeline_stats_with_filters(
        &mut self,
        filters: Option<crate::proto::smartnic::p4_v2::StatsFilters>,
    ) -> Result<(), Vec<Result<(), Status>>> {
        fan_out(
            self.clients
                .iter_mut()
                .map(|c| c.clear_pipeline_stats_with_filters(filters.clone()))
                .collect(),
        )
        .await
        .map(|_| ())
    }

    /// Clear stats for specific metric names at a specific index across all clients.
    /// This is useful for clearing counters for a specific member or LB.
    pub async fn clear_stats_by_names_and_index(
        &mut self,
        metric_names: &[&str],
        index: u32,
    ) -> Result<(), Vec<Result<(), Status>>> {
        // Collect owned strings so the closures don't borrow `metric_names`
        // with a lifetime shorter than the async futures.
        let names: Vec<String> = metric_names.iter().map(|s| s.to_string()).collect();
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|c| {
                let names = names.clone();
                async move {
                    let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
                    c.clear_stats_by_names_and_index(&name_refs, index).await
                }
            })
            .collect();
        fan_out(futures).await.map(|_| ())
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
        fan_out(
            self.clients
                .iter_mut()
                .map(|c| c.set_server_config(enables.clone(), disables.clone()))
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
    Incomplete(Vec<BatchResponse>), // Partial success with the full response list
    Error(Status),                  // API error
}

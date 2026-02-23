// SPDX-License-Identifier: BSD-3-Clause-LBNL
//! CLI subcommands for configuration management, including autoconfigure.
//! Outputs only the smartnic section as YAML, with port determined from SN_INGRESS_PORT in .env.

use clap::{Args, Parser, Subcommand};

use crate::config::Config;
use crate::errors::Result;
use crate::sncfg::setup::auto_configure_smartnics;

#[derive(Parser, Debug)]
#[command(
    name = "sncfg",
    about = "Interact with ESnet SmartNIC sn-cfg (requires server config)"
)]
pub struct SncfgCli {
    #[command(subcommand)]
    pub command: SncfgCommand,
}

#[derive(Subcommand, Debug)]
pub enum SncfgCommand {
    /// Reinit sn-cfg settings if dataplane was restarted seperately from control plane
    Setup(SetupArgs),
    /// Display all available metrics from the smartnic
    Stats(StatsArgs),
}

#[derive(Args, Debug)]
pub struct SetupArgs {}

#[derive(Args, Debug)]
pub struct StatsArgs {}

impl SncfgCli {
    pub async fn run(&self, config: &mut Config) -> Result<()> {
        match &self.command {
            SncfgCommand::Setup(args) => setup_command(args, config).await,
            SncfgCommand::Stats(args) => stats_command(args, config).await,
        }
    }
}

async fn setup_command(_args: &SetupArgs, config: &mut Config) -> Result<()> {
    let mut cfg_clients = crate::build_sncfg_clients(config).await?;
    auto_configure_smartnics(&mut cfg_clients).await?;
    Ok(())
}

async fn stats_command(_args: &StatsArgs, config: &mut Config) -> Result<()> {
    let mut cfg_clients = crate::build_sncfg_clients(config).await?;

    // Get metrics from all smartnics
    let all_metrics = match cfg_clients.get_stats().await {
        Ok(metrics) => metrics,
        Err(errors) => {
            eprintln!("errors getting stats from smartnics:");
            for (idx, result) in errors.iter().enumerate() {
                if let Err(e) = result {
                    eprintln!("  Smartnic {}: {}", idx, e);
                }
            }
            return Err(crate::errors::Error::Runtime(
                "failed to get stats from one or more smartnics".into(),
            ));
        }
    };

    let json = serde_json::to_string_pretty(&all_metrics).map_err(|e| {
        crate::errors::Error::Runtime(format!("failed to serialize to JSON: {}", e))
    })?;
    println!("{}", json);

    Ok(())
}

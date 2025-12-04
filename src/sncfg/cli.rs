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
}

#[derive(Args, Debug)]
pub struct SetupArgs {}

impl SncfgCli {
    pub async fn run(&self, config: &mut Config) -> Result<()> {
        match &self.command {
            SncfgCommand::Setup(args) => setup_command(args, config).await,
        }
    }
}

async fn setup_command(_args: &SetupArgs, config: &mut Config) -> Result<()> {
    // Build SNCfg clients using the shared function from lib.rs
    let mut cfg_clients = crate::build_sncfg_clients(config).await?;

    // Call auto_configure_smartnics
    auto_configure_smartnics(&mut cfg_clients).await?;

    Ok(())
}

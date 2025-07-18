// SPDX-License-Identifier: BSD-3-Clause-LBNL
//! FPGA auto-configuration logic for SmartNICs using SNCfgClient.

use crate::errors::Result;
use crate::sncfg::client::MultiSNCfgClient;
use tracing::{error, info};

/// Automatically configure all SmartNIC FPGAs using the provided MultiSNCfgClient.
/// This should be called at startup before dataplane use.
pub async fn auto_configure_smartnics(clients: &mut MultiSNCfgClient) -> Result<()> {
    // Show device info
    match clients.get_device_info().await {
        Ok(devs) => info!("Device info: {:#?}", devs),
        Err(e) => error!("Failed to get device info: {:#?}", e),
    }

    // TODO: Implement the following configuration steps using SNCfgClient:
    // - Configure switch: egress 0:physical, 1:physical
    // - Configure switch: ingress 0:physical:app, 1:physical:app, bypass straight
    // - Show switch config
    // - Configure host: --host-id 0 --reset-dma-queues --dma-queues pf:0:1
    // - Configure host: --host-id 1 --reset-dma-queues --dma-queues pf:1:1
    // - Show host
    // - Configure port: --state enable
    // - Show port status
    Ok(())
}

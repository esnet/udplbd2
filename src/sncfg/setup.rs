// SPDX-License-Identifier: BSD-3-Clause-LBNL
//! FPGA auto-configuration logic for SmartNICs using SNCfgClient.

use crate::errors::Result;
use crate::proto::smartnic::cfg_v2::{
    HostConfig, HostDmaConfig, HostFunctionDmaConfig, HostFunctionId, HostFunctionType, PortConfig,
    PortState, SwitchBypassMode, SwitchConfig, SwitchDestination, SwitchEgressSelector,
    SwitchIngressSelector, SwitchInterface,
};
use crate::sncfg::client::MultiSNCfgClient;
use macaddr::MacAddr6;
use std::str::FromStr;
use tracing::{error, info};

/// Automatically configure all SmartNIC FPGAs using the provided MultiSNCfgClient.
/// This should be called at startup before dataplane use.
pub async fn auto_configure_smartnics(clients: &mut MultiSNCfgClient) -> Result<()> {
    // Show device info
    // Gather device info for summary
    let device_infos = match clients.get_device_info().await {
        Ok(devs) => devs,
        Err(e) => {
            error!("Failed to get device info: {:#?}", e);
            return Err(crate::errors::Error::Runtime(
                "failed to get device info, check token?".to_string(),
            ));
        }
    };

    // 1. Configure switch: egress 0:physical, 1:physical; ingress 0:physical:app, 1:physical:app; bypass straight
    let switch_config = SwitchConfig {
        ingress_selectors: vec![
            SwitchIngressSelector {
                index: 0,
                intf: SwitchInterface::SwIntfPhysical as i32,
                dest: SwitchDestination::SwDestApp as i32,
            },
            SwitchIngressSelector {
                index: 1,
                intf: SwitchInterface::SwIntfPhysical as i32,
                dest: SwitchDestination::SwDestApp as i32,
            },
        ],
        egress_selectors: vec![
            SwitchEgressSelector {
                index: 0,
                intf: SwitchInterface::SwIntfPhysical as i32,
            },
            SwitchEgressSelector {
                index: 1,
                intf: SwitchInterface::SwIntfPhysical as i32,
            },
        ],
        bypass_mode: SwitchBypassMode::SwBypassStraight as i32,
    };

    // Switch config
    clients
        .set_switch_config(switch_config)
        .await
        .map_err(|_| crate::errors::Error::Runtime("failed to set switch config".to_string()))?;

    // Host configs
    let mut base_queue = 0;
    let num_queues_per_func = 1;
    for host_id in 0..=1 {
        let dma_config = HostDmaConfig {
            functions: vec![HostFunctionDmaConfig {
                func_id: Some(HostFunctionId {
                    ftype: HostFunctionType::HostFuncPhysical as i32,
                    index: 0,
                }),
                base_queue: base_queue,
                num_queues: num_queues_per_func,
            }],
            reset: true,
        };
        base_queue += num_queues_per_func;
        let host_config = HostConfig {
            dma: Some(dma_config),
            flow_control: None,
        };
        clients
            .set_host_config(host_id as i32, host_config)
            .await
            .map_err(|_| crate::errors::Error::Runtime("failed to set host config".to_string()))?;
    }

    // Port configs
    for port_id in 0..=1 {
        let port_config = PortConfig {
            state: PortState::Enable as i32,
            fec: 0,
            loopback: 0,
            flow_control: None,
        };
        clients
            .set_port_config(port_id, port_config)
            .await
            .map_err(|_| crate::errors::Error::Runtime("failed to set port config".to_string()))?;
    }

    // Compose summary message for all FPGAs across all clients/cards
    let mut summary = String::from("configured FPGAs:");
    let mut hw_versions = std::collections::HashSet::new();
    let mut fw_versions = std::collections::HashSet::new();
    let mut flat_devices = Vec::new();

    // Flatten Vec<Vec<DeviceInfo>> into flat_devices
    for client_devs in &device_infos {
        for dev in client_devs {
            flat_devices.push(dev);
        }
    }

    for (i, dev) in flat_devices.iter().enumerate() {
        let card = dev
            .card
            .as_ref()
            .map(|c| c.name.as_str())
            .unwrap_or("unknown");
        let pci = dev
            .pci
            .as_ref()
            .map(|p| p.bus_id.as_str())
            .unwrap_or("unknown");
        let (hw, fw) = dev
            .build
            .as_ref()
            .and_then(|b| b.env.as_ref())
            .map(|env| (env.hw_version.as_str(), env.fw_version.as_str()))
            .unwrap_or(("unknown", "unknown"));
        summary.push_str(&format!(
            " {}. {} {} hw: {} fw: {}",
            i + 1,
            card,
            pci,
            hw,
            fw
        ));
        if i + 1 < flat_devices.len() {
            summary.push(',');
        }
        hw_versions.insert(hw);
        fw_versions.insert(fw);
    }
    if hw_versions.len() > 1 || fw_versions.len() > 1 {
        summary.push_str(" [WARNING: version mismatch]");
    }
    info!("{}", summary);

    Ok(())
}

/// Returns the smallest MAC address from all sn-cfg clients.
/// Returns None if no MAC addresses are found or if parsing fails for all.
pub async fn smallest_mac_address(clients: &mut MultiSNCfgClient) -> Result<Option<MacAddr6>> {
    // Get device info from all clients
    let device_infos = match clients.get_device_info().await {
        Ok(devs) => devs,
        Err(e) => {
            error!("Failed to get device info: {:#?}", e);
            return Err(crate::errors::Error::Runtime(
                "failed to get device info, check token?".to_string(),
            ));
        }
    };

    // Collect all MAC address strings from DeviceCardInfo
    let mac_strs = device_infos
        .iter()
        .flat_map(|devs| devs.iter())
        .filter_map(|dev| dev.card.as_ref())
        .flat_map(|card| card.mac_addrs.iter())
        .collect::<Vec<_>>();

    // Parse all MAC addresses, filter out invalid ones
    let mut macs: Vec<MacAddr6> = mac_strs
        .iter()
        .filter_map(|mac_str| MacAddr6::from_str(mac_str).ok())
        .collect();

    // Find the smallest MAC address
    macs.sort();
    Ok(macs.first().cloned())
}

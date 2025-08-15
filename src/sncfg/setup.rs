// SPDX-License-Identifier: BSD-3-Clause-LBNL
//! FPGA auto-configuration logic for SmartNICs using SNCfgClient.

use crate::errors::Result;
use crate::proto::smartnic::cfg_v2::{
    HostConfig, HostDmaConfig, HostFunctionDmaConfig, HostFunctionId, HostFunctionType, PortConfig,
    PortState, SwitchBypassMode, SwitchConfig, SwitchDestination, SwitchEgressSelector,
    SwitchIngressSelector, SwitchInterface,
};
use crate::sncfg::client::MultiSNCfgClient;
use tracing::{error, info};

/// Automatically configure all SmartNIC FPGAs using the provided MultiSNCfgClient.
/// This should be called at startup before dataplane use.
pub async fn auto_configure_smartnics(clients: &mut MultiSNCfgClient) -> Result<()> {
    // Show device info
    // Gather device info for summary
    let device_infos: Vec<_>;
    match clients.get_device_info().await {
        Ok(devs) => {
            device_infos = devs.clone();
        }
        Err(e) => {
            error!("Failed to get device info: {:#?}", e);
            return Err(crate::errors::Error::Runtime(
                "failed to get device info, check token?".to_string(),
            ));
        }
    }

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
    for host_id in 0..=1 {
        let dma_config = HostDmaConfig {
            functions: vec![HostFunctionDmaConfig {
                func_id: Some(HostFunctionId {
                    ftype: HostFunctionType::HostFuncPhysical as i32,
                    index: host_id,
                }),
                base_queue: 0,
                num_queues: 1,
            }],
            reset: true,
        };
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

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
use tracing::{debug, error, info, warn};

/// Automatically configure all SmartNIC FPGAs using the provided MultiSNCfgClient.
/// This function is idempotent: it reads the current configuration from each FPGA and
/// only applies changes for settings that differ from the desired state.
pub async fn auto_configure_smartnics(clients: &mut MultiSNCfgClient) -> Result<()> {
    let sncfg = clients.client_labels();

    // Gather device info for summary
    let device_infos = match clients.get_device_info().await {
        Ok(devs) => devs,
        Err(e) => {
            error!(sncfg, "failed to get device info: {:#?}", e);
            return Err(crate::errors::Error::Runtime(
                "failed to get device info, check token?".to_string(),
            ));
        }
    };

    // 1. Configure switch: read current config, only set if it differs from desired.
    let desired_switch_config = SwitchConfig {
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

    let needs_switch_update = match clients.get_switch_config().await {
        Ok(per_client_resps) => {
            // Check every client's every response; if any device differs, update all.
            per_client_resps
                .iter()
                .flatten()
                .any(|resp| resp.config.as_ref() != Some(&desired_switch_config))
        }
        Err(e) => {
            warn!(
                sncfg,
                "failed to read switch config, will apply desired config: {:#?}", e
            );
            true
        }
    };

    let mut changed = false;

    if needs_switch_update {
        clients
            .set_switch_config(desired_switch_config)
            .await
            .map_err(|_| crate::errors::Error::Runtime("failed to set switch config".to_string()))?;
        info!(sncfg, "switch config applied");
        changed = true;
    }

    // 2. Host (DMA) config: read then write only if different.
    // The `reset` flag on HostDmaConfig is a write-only trigger; the FPGA always reports it as
    // false. We compare only the function entries we own; the FPGA may report additional entries
    // for other function types which we leave untouched.
    let mut base_queue = 0u32;
    let num_queues_per_func = 1u32;
    for host_id in 0..=1i32 {
        let desired_func = HostFunctionDmaConfig {
            func_id: Some(HostFunctionId {
                ftype: HostFunctionType::HostFuncPhysical as i32,
                index: 0,
            }),
            base_queue,
            num_queues: num_queues_per_func,
        };
        base_queue += num_queues_per_func;

        let needs_host_update = match clients.get_host_config(host_id).await {
            Ok(per_client_resps) => per_client_resps.iter().flatten().any(|resp| {
                // Check only that our desired function entry is present and correct; ignore
                // other function entries and the flow_control field.
                let current_funcs = resp
                    .config
                    .as_ref()
                    .and_then(|c| c.dma.as_ref())
                    .map(|d| d.functions.as_slice())
                    .unwrap_or(&[]);
                !current_funcs.contains(&desired_func)
            }),
            Err(e) => {
                warn!(
                    sncfg,
                    host_id, "failed to read host config, will apply desired config: {:#?}", e
                );
                true
            }
        };

        if needs_host_update {
            let host_config = HostConfig {
                dma: Some(HostDmaConfig {
                    functions: vec![desired_func],
                    reset: true,
                }),
                flow_control: None,
            };
            clients
                .set_host_config(host_id, host_config)
                .await
                .map_err(|_| {
                    crate::errors::Error::Runtime("failed to set host config".to_string())
                })?;
            info!(sncfg, host_id, "host config applied");
            changed = true;
        }
    }

    // 3. Port config: read then write only if different.
    for port_id in 0..=1i32 {
        let write_port_config = PortConfig {
            state: PortState::Enable as i32,
            fec: 0,
            loopback: 0,
            flow_control: None,
        };

        let needs_port_update = match clients.get_port_config(port_id).await {
            Ok(per_client_resps) => per_client_resps.iter().flatten().any(|resp| {
                let Some(c) = resp.config.as_ref() else {
                    return true;
                };
                // Port is correctly configured when it is enabled; we don't manage fec/loopback
                // beyond what the FPGA normalises them to after our initial write.
                c.state != write_port_config.state
            }),
            Err(e) => {
                warn!(
                    sncfg,
                    port_id, "failed to read port config, will apply desired config: {:#?}", e
                );
                true
            }
        };

        if needs_port_update {
            clients
                .set_port_config(port_id, write_port_config)
                .await
                .map_err(|_| {
                    crate::errors::Error::Runtime("failed to set port config".to_string())
                })?;
            info!(sncfg, port_id, "port config applied");
            changed = true;
        }
    }

    // Compose summary message for all FPGAs across all clients/cards
    let mut summary = String::from("verified FPGA configuration:");
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
        info!(sncfg, "{}", summary);
    } else if changed {
        info!(sncfg, "{}", summary);
    } else {
        debug!(sncfg, "{}", summary);
    }

    Ok(())
}

/// Returns the smallest MAC address from all sn-cfg clients.
/// Returns None if no MAC addresses are found or if parsing fails for all.
pub async fn smallest_mac_address(clients: &mut MultiSNCfgClient) -> Result<Option<MacAddr6>> {
    let sncfg = clients.client_labels();

    // Get device info from all clients
    let device_infos = match clients.get_device_info().await {
        Ok(devs) => devs,
        Err(e) => {
            error!(sncfg, "failed to get device info: {:#?}", e);
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

// SPDX-License-Identifier: BSD-3-Clause-LBNL
use crate::errors::{Error, Result};
use macaddr::MacAddr6;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::process::Command;
use std::str::FromStr;
use std::time::Duration;

/// Finds the next hop for a given destination IP by checking system routing tables
/// If interface is provided, only routes on that interface are considered
/// Uses Longest Prefix Match (LPM) to select the most specific route
pub async fn next_hop(ip: IpAddr, interface: Option<&str>) -> Result<Option<IpAddr>> {
    // Use netstat to get routing information on macOS
    let output = Command::new("netstat")
        .args(["-rn", "-f", "inet"])
        .output()
        .map_err(|e| Error::CommandExecution(format!("Failed to execute netstat: {}", e)))?;

    if !output.status.success() {
        return Err(Error::CommandExecution(
            "netstat command failed".to_string(),
        ));
    }

    let output = String::from_utf8(output.stdout)
        .map_err(|e| Error::CommandExecution(format!("Invalid netstat output: {}", e)))?;

    // Skip header lines
    let mut lines = output
        .lines()
        .skip_while(|line| !line.contains("Destination"));
    if let Some(header) = lines.next() {
        // Find the gateway, netmask, and interface column indices
        let headers: Vec<&str> = header.split_whitespace().collect();
        let gateway_idx = headers.iter().position(|&h| h == "Gateway").unwrap_or(1);
        let netmask_idx = headers.iter().position(|&h| h == "Netmask").unwrap_or(2);
        let interface_idx = headers
            .iter()
            .position(|&h| h == "Netif" || h == "Interface")
            .unwrap_or(headers.len().saturating_sub(1));

        // Find the best matching route using Longest Prefix Match
        let mut best_match: Option<(u8, IpAddr)> = None;

        for line in lines {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() > gateway_idx.max(netmask_idx).max(interface_idx) {
                // If an interface was specified, filter routes by that interface
                if let Some(required_iface) = interface {
                    if fields.len() > interface_idx && fields[interface_idx] != required_iface {
                        continue;
                    }
                }

                let (dest_ip, prefix_len) = if fields[0] == "default" {
                    (
                        match ip {
                            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                        },
                        0u8,
                    )
                } else if let Ok(dest) = IpAddr::from_str(fields[0]) {
                    let prefix = if fields.len() > netmask_idx {
                        parse_netmask_to_prefix(fields[netmask_idx], &dest).unwrap_or(32)
                    } else {
                        32 // Host route if no netmask specified
                    };
                    (dest, prefix)
                } else {
                    continue;
                };

                if let Ok(route_network) = ipnetwork::IpNetwork::new(dest_ip, prefix_len) {
                    if route_network.contains(ip)
                        && (best_match.is_none() || prefix_len > best_match.as_ref().unwrap().0)
                    {
                        if let Ok(gateway) = IpAddr::from_str(fields[gateway_idx]) {
                            best_match = Some((prefix_len, gateway));
                        }
                    }
                }
            }
        }

        if let Some((_, gateway)) = best_match {
            return Ok(Some(gateway));
        }
    }

    Ok(None)
}

/// Parse a netmask string to prefix length
fn parse_netmask_to_prefix(netmask: &str, dest: &IpAddr) -> Option<u8> {
    // Try parsing as hex (e.g., 0xffffff00)
    if let Some(hex_str) = netmask.strip_prefix("0x") {
        if let Ok(mask_val) = u32::from_str_radix(hex_str, 16) {
            return Some(mask_val.count_ones() as u8);
        }
    }

    // Try parsing as dotted decimal (e.g., 255.255.255.0)
    if let Ok(mask_ip) = Ipv4Addr::from_str(netmask) {
        let mask_val = u32::from(mask_ip);
        return Some(mask_val.count_ones() as u8);
    }

    // Default to /32 for IPv4 or /128 for IPv6 if we can't parse
    match dest {
        IpAddr::V4(_) => Some(32),
        IpAddr::V6(_) => Some(128),
    }
}

/// Sends a UDP ping to the specified IP address
async fn ping(ip: IpAddr) -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| Error::Network(format!("Failed to bind socket: {}", e)))?;

    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .map_err(|e| Error::Network(format!("Failed to set socket timeout: {}", e)))?;

    socket
        .connect(SocketAddr::new(ip, 33434))
        .map_err(|e| Error::Network(format!("Failed to connect socket: {}", e)))?;

    socket
        .send(b"ping")
        .map_err(|e| Error::Network(format!("Failed to send ping: {}", e)))?;

    Ok(())
}

/// Gets the MAC address of a local interface with the given IP
pub async fn local_mac(ip: IpAddr) -> Result<Option<MacAddr6>> {
    // Use ifconfig to get interface information on macOS
    let output = Command::new("ifconfig")
        .output()
        .map_err(|e| Error::CommandExecution(format!("Failed to execute ifconfig: {}", e)))?;

    if !output.status.success() {
        return Err(Error::CommandExecution(
            "ifconfig command failed".to_string(),
        ));
    }

    let output = String::from_utf8(output.stdout)
        .map_err(|e| Error::CommandExecution(format!("Invalid ifconfig output: {}", e)))?;

    let mut interface_data = Vec::new();
    let mut current_interface = None;
    let mut current_mac = None;
    let mut current_ips = Vec::new();

    // First pass: collect all interface data
    for line in output.lines() {
        if line.starts_with("        ") {
            // Interface property line
            let line = line.trim();
            if line.starts_with("ether ") {
                if let Some(addr) = line.strip_prefix("ether ") {
                    current_mac = Some(addr.trim().to_string());
                }
            } else if line.starts_with("inet ") {
                if let Some(addr) = line.strip_prefix("inet ") {
                    if let Some(addr) = addr.split_whitespace().next() {
                        if let Ok(ip_addr) = IpAddr::from_str(addr) {
                            current_ips.push(ip_addr);
                        }
                    }
                }
            }
        } else if !line.is_empty() {
            // New interface section
            if let Some(name) = line.split(':').next() {
                // Save previous interface data if any
                if let (Some(iface), Some(mac)) = (current_interface.take(), current_mac.take()) {
                    interface_data.push((iface, mac, std::mem::take(&mut current_ips)));
                }
                current_interface = Some(name.trim().to_string());
            }
        }
    }
    // Save last interface
    if let (Some(iface), Some(mac)) = (current_interface, current_mac) {
        interface_data.push((iface, mac, current_ips));
    }

    // Find matching interface
    for (_iface, mac, ips) in interface_data {
        if ips.contains(&ip) {
            return Ok(Some(mac.parse().unwrap()));
        }
    }

    Ok(None)
}

/// Gets the MAC address of a neighbor with the given IP
pub async fn neighbor_mac(ip: IpAddr) -> Result<Option<MacAddr6>> {
    // Try to ensure the neighbor is in the cache
    let _ = ping(ip).await;

    // Use arp to get neighbor MAC address on macOS
    let output = Command::new("arp")
        .args(["-n", ip.to_string().as_str()])
        .output()
        .map_err(|e| Error::CommandExecution(format!("Failed to execute arp: {}", e)))?;

    if !output.status.success() {
        return Err(Error::CommandExecution("arp command failed".to_string()));
    }

    let output = String::from_utf8(output.stdout)
        .map_err(|e| Error::CommandExecution(format!("Invalid arp output: {}", e)))?;

    // Skip header line and parse ARP table
    let mut lines = output.lines().skip_while(|line| !line.contains("("));
    if let Some(_header) = lines.next() {
        for line in lines {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 2 {
                // Handle both IPv4 and IPv6 formats
                let addr_str = fields[0].trim_end_matches(['(', ')']);
                if let Ok(addr) = IpAddr::from_str(addr_str) {
                    if addr == ip {
                        // MAC address is typically in the second field
                        let mac = fields[1].trim_matches(|c| c == '(' || c == ')');
                        if !mac.is_empty() && mac.contains(':') {
                            return Ok(Some(mac.parse().unwrap()));
                        }
                    }
                }
            }
        }
    }

    Ok(None)
}

/// Gets the MAC address for a given IP address by checking local interfaces and neighbors
/// If interface is provided, only routes on that interface are considered
pub async fn get_mac_addr(ip: IpAddr, interface: Option<&str>) -> Result<MacAddr6> {
    if ip == IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
        || ip == IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
        || ip == IpAddr::V6(Ipv6Addr::LOCALHOST)
    {
        // for debugging :)
        return Ok(MacAddr6::new(0x02, 0x00, 0xDE, 0xCA, 0xFB, 0xAD));
    }
    for _ in 0..2 {
        // First try to find the next hop
        if let Ok(Some(next_hop)) = next_hop(ip, interface).await {
            // Ping the next hop to populate ARP cache
            let _ = ping(next_hop).await;

            // Try to get the MAC address of the next hop
            if let Ok(Some(mac)) = neighbor_mac(next_hop).await {
                return Ok(mac);
            }
        } else {
            // No next hop found, try direct communication
            let _ = ping(ip).await;

            // Check if it's a neighbor
            if let Ok(Some(mac)) = neighbor_mac(ip).await {
                return Ok(mac);
            }

            // Check if it's one of our interfaces
            if let Ok(Some(mac)) = local_mac(ip).await {
                return Ok(mac);
            }
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    Err(Error::MacAddressNotFound(format!(
        "Could not find MAC address for {}",
        ip
    )))
}

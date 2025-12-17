// SPDX-License-Identifier: BSD-3-Clause-LBNL
use crate::errors::{Error, Result};
use futures::stream::TryStreamExt;
use ipnetwork::IpNetwork;
use macaddr::MacAddr6;
use net_route::Handle;
use netlink_packet_route::address::AddressAttribute;
use netlink_packet_route::link::LinkAttribute;
use netlink_packet_route::neighbour::{NeighbourAddress, NeighbourAttribute};
use rtnetlink::{new_connection, IpVersion};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tracing::trace;

/// Looks up the interface index for a given interface name
async fn get_ifindex(interface_name: &str) -> Result<Option<u32>> {
    trace!(
        "get_ifindex: called with interface_name={:?}",
        interface_name
    );
    let (connection, handle, _) = new_connection().map_err(|e| {
        trace!("get_ifindex: failed to initialize rtnetlink: {}", e);
        Error::CommandExecution(format!("Failed to initialize rtnetlink: {e}"))
    })?;
    tokio::spawn(connection);

    let mut links = handle.link().get().execute();

    while let Some(link) = links.try_next().await.map_err(|e| {
        trace!("get_ifindex: failed to fetch links: {}", e);
        Error::CommandExecution(format!("Failed to fetch links: {e}"))
    })? {
        let link_name = link.attributes.iter().find_map(|attr| match attr {
            LinkAttribute::IfName(name) => Some(name.clone()),
            _ => None,
        });

        if let Some(name) = link_name {
            trace!(
                "get_ifindex: checking link name={:?}, index={}",
                name,
                link.header.index
            );
            if name == interface_name {
                trace!(
                    "get_ifindex: found matching interface, index={}",
                    link.header.index
                );
                return Ok(Some(link.header.index));
            }
        }
    }

    trace!(
        "get_ifindex: no matching interface found for name={:?}",
        interface_name
    );
    Ok(None)
}

/// Finds the next hop for a given destination IP by checking system routing tables
/// If interface is provided, only routes on that interface are considered
/// Uses Longest Prefix Match (LPM) to select the most specific route
pub async fn next_hop(ip: IpAddr, interface: Option<&str>) -> Result<Option<IpAddr>> {
    trace!(
        "next_hop: called with ip={:?}, interface={:?}",
        ip,
        interface
    );

    // Get the interface index if an interface name was provided
    let ifindex = if let Some(iface) = interface {
        match get_ifindex(iface).await? {
            Some(idx) => {
                trace!("next_hop: using interface {} with index {}", iface, idx);
                Some(idx)
            }
            None => {
                trace!("next_hop: interface {} not found", iface);
                return Err(Error::CommandExecution(format!(
                    "Interface '{}' not found",
                    iface
                )));
            }
        }
    } else {
        None
    };

    let handle = Handle::new().map_err(|e| {
        Error::CommandExecution(format!("Failed to initialize net_route handle: {e}"))
    })?;
    let routes = handle
        .list()
        .await
        .map_err(|e| Error::CommandExecution(format!("Failed to fetch routes: {e}")))?;

    // Find the best matching route using Longest Prefix Match
    let mut best_match: Option<(u8, Option<IpAddr>)> = None;

    for route in routes {
        // If an interface index was specified, filter routes by that interface
        if let Some(required_ifindex) = ifindex {
            if route.ifindex != required_ifindex {
                trace!(
                    "next_hop: skipping route on ifindex={}, required={}",
                    route.ifindex,
                    required_ifindex
                );
                continue;
            }
        }

        let dest_net = IpNetwork::new(route.destination, route.prefix)?;
        trace!(
            "next_hop: checking route with dest_net={:?}, prefix={}, gateway={:?}, ifindex={}",
            dest_net,
            route.prefix,
            route.gateway,
            route.ifindex
        );
        if dest_net.contains(ip) {
            trace!(
                "next_hop: route matches ip={:?}, prefix={}",
                ip,
                route.prefix
            );
            if best_match.is_none() || route.prefix > best_match.as_ref().unwrap().0 {
                trace!(
                    "next_hop: updating best match to prefix={}, gateway={:?}",
                    route.prefix,
                    route.gateway
                );
                best_match = Some((route.prefix, route.gateway));
            }
        }
    }

    if let Some((prefix, gateway)) = best_match {
        trace!(
            "next_hop: returning best match with prefix={}, gateway={:?}",
            prefix,
            gateway
        );
        Ok(gateway)
    } else {
        trace!("next_hop: no matching route found for ip={:?}", ip);
        Ok(None)
    }
}

/// Sends a UDP ping to the specified IP address
async fn ping(ip: IpAddr) -> Result<()> {
    use tokio::net::UdpSocket;

    trace!("ping: called with ip={:?}", ip);

    let bind_addr = match ip {
        IpAddr::V4(_) => "0.0.0.0:0",
        IpAddr::V6(_) => "[::]:0",
    };

    let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
        trace!("ping: failed to bind socket: {}", e);
        Error::Network(format!("Failed to bind socket: {e}"))
    })?;

    socket.connect((ip, 33434)).await.map_err(|e| {
        trace!("ping: failed to connect socket: {}", e);
        Error::Network(format!("Failed to connect socket: {e}"))
    })?;

    socket.send(b"ping").await.map_err(|e| {
        trace!("ping: failed to send ping: {}", e);
        Error::Network(format!("Failed to send ping: {e}"))
    })?;

    trace!("ping: sent ping to {:?}", ip);
    Ok(())
}

/// Gets the MAC address of a local interface with the given IP
pub async fn local_mac(ip: IpAddr) -> Result<Option<MacAddr6>> {
    trace!("local_mac: called with ip={:?}", ip);
    let (connection, handle, _) = new_connection().map_err(|e| {
        trace!("local_mac: failed to initialize rtnetlink: {}", e);
        Error::CommandExecution(format!("Failed to initialize rtnetlink: {e}"))
    })?;
    tokio::spawn(connection);

    let mut links = handle.link().get().execute();

    while let Some(link) = links.try_next().await.map_err(|e| {
        trace!("local_mac: failed to fetch links: {}", e);
        Error::CommandExecution(format!("Failed to fetch links: {e}"))
    })? {
        let link_index = link.header.index;
        trace!("local_mac: checking link index={}", link_index);

        // Get MAC address from this interface
        let mac = link.attributes.iter().find_map(|attr| match attr {
            LinkAttribute::Address(addr) if addr.len() == 6 => Some(MacAddr6::new(
                addr[0], addr[1], addr[2], addr[3], addr[4], addr[5],
            )),
            _ => None,
        });

        if let Some(mac_addr) = mac {
            trace!(
                "local_mac: found mac address={:?} on link index={}",
                mac_addr,
                link_index
            );
            // Check if this interface has the target IP address
            let mut addrs = handle
                .address()
                .get()
                .set_link_index_filter(link_index)
                .execute();

            while let Some(addr) = addrs.try_next().await.map_err(|e| {
                trace!("local_mac: failed to fetch addresses: {}", e);
                Error::CommandExecution(format!("Failed to fetch addresses: {e}"))
            })? {
                for attr in &addr.attributes {
                    if let AddressAttribute::Address(interface_ip) = attr {
                        trace!(
                            "local_mac: found interface_ip={:?} on link index={}",
                            interface_ip,
                            link_index
                        );
                        if *interface_ip == ip {
                            trace!("local_mac: matched ip, returning mac={:?}", mac_addr);
                            return Ok(Some(mac_addr));
                        }
                    }
                }
            }
        }
    }

    trace!("local_mac: no matching mac found for ip={:?}", ip);
    Ok(None)
}

/// Gets the MAC address of a neighbor with the given IP
pub async fn neighbor_mac(ip: IpAddr) -> Result<Option<MacAddr6>> {
    trace!("neighbor_mac: called with ip={:?}", ip);
    let (connection, handle, _) = new_connection().map_err(|e| {
        trace!("neighbor_mac: failed to initialize rtnetlink: {}", e);
        Error::CommandExecution(format!("Failed to initialize rtnetlink: {e}"))
    })?;
    tokio::spawn(connection);

    let mut neighbours = handle
        .neighbours()
        .get()
        .set_family(match ip {
            IpAddr::V4(_) => IpVersion::V4,
            IpAddr::V6(_) => IpVersion::V6,
        })
        .execute();

    while let Some(neighbor) = neighbours.try_next().await.map_err(|e| {
        trace!("neighbor_mac: failed to fetch neighbors: {}", e);
        Error::CommandExecution(format!("Failed to fetch neighbors: {e}"))
    })? {
        if neighbor
            .attributes
            .iter()
            .any(|attr| matches!(attr, NeighbourAttribute::Destination(NeighbourAddress::Inet(addr)) if addr == &ip) || matches!(attr, NeighbourAttribute::Destination(NeighbourAddress::Inet6(addr)) if addr == &ip))
        {
            trace!("neighbor_mac: found neighbor with matching ip={:?}", ip);
            if let Some(mac) = neighbor.attributes.iter().find_map(|attr| {
                if let NeighbourAttribute::LinkLocalAddress(mac) = attr {
                    Some(MacAddr6::new(
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                    ))
                } else {
                    None
                }
            }) {
                trace!("neighbor_mac: found mac={:?} for ip={:?}", mac, ip);
                return Ok(Some(mac));
            }
        }
    }

    trace!(
        "neighbor_mac: no matching neighbor mac found for ip={:?}",
        ip
    );
    Ok(None)
}

/// Gets the MAC address for a given IP address by checking local interfaces and neighbors
/// If interface is provided, only routes on that interface are considered
pub async fn get_mac_addr(ip: IpAddr, interface: Option<&str>) -> Result<MacAddr6> {
    trace!(
        "get_mac_addr: called with ip={:?}, interface={:?}",
        ip,
        interface
    );
    if ip == IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
        || ip == IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
        || ip == IpAddr::V6(Ipv6Addr::LOCALHOST)
    {
        // for debugging :)
        trace!("get_mac_addr: special-case IP, returning dummy MAC");
        return Ok(MacAddr6::new(0x02, 0x00, 0xDE, 0xCA, 0xFB, 0xAD));
    }
    for attempt in 0..2 {
        trace!("get_mac_addr: attempt {}", attempt + 1);
        if let Ok(Some(next_hop)) = next_hop(ip, interface).await {
            trace!("get_mac_addr: found next_hop={:?}", next_hop);
            let _ = ping(next_hop).await;

            if let Ok(Some(mac)) = neighbor_mac(next_hop).await {
                trace!(
                    "get_mac_addr: found neighbor mac={:?} for next_hop={:?}",
                    mac,
                    next_hop
                );
                return Ok(mac);
            }
        } else {
            trace!("get_mac_addr: no next_hop, pinging ip={:?}", ip);
            let _ = ping(ip).await;

            if let Ok(Some(mac)) = local_mac(ip).await {
                trace!("get_mac_addr: found local mac={:?} for ip={:?}", mac, ip);
                return Ok(mac);
            }

            if let Ok(Some(mac)) = neighbor_mac(ip).await {
                trace!("get_mac_addr: found neighbor mac={:?} for ip={:?}", mac, ip);
                return Ok(mac);
            }
        }

        trace!("get_mac_addr: sleeping before retry");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    trace!("get_mac_addr: could not find MAC address for {:?}", ip);
    Err(Error::MacAddressNotFound(format!(
        "Could not find MAC address for {ip}"
    )))
}

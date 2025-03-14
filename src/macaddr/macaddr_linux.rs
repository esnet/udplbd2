use crate::errors::{Error, Result};
use futures::stream::TryStreamExt;
use ipnetwork::IpNetwork;
use macaddr::MacAddr6;
use net_route::Handle;
use netlink_packet_route::link::LinkAttribute;
use netlink_packet_route::neighbour::{NeighbourAddress, NeighbourAttribute};
use rtnetlink::{new_connection, IpVersion};
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::time::Duration;

/// Finds the next hop for a given destination IP by checking system routing tables
pub async fn next_hop(ip: IpAddr) -> Result<Option<IpAddr>> {
    let handle = Handle::new().map_err(|e| {
        Error::CommandExecution(format!("Failed to initialize net_route handle: {}", e))
    })?;
    let routes = handle
        .list()
        .await
        .map_err(|e| Error::CommandExecution(format!("Failed to fetch routes: {}", e)))?;

    for route in routes {
        let dest_net = IpNetwork::new(route.destination, route.prefix)?;
        if dest_net.contains(ip) {
            return Ok(route.gateway);
        }
    }

    Ok(None)
}

/// Sends a UDP ping to the specified IP address
async fn ping(ip: IpAddr) -> Result<()> {
    use tokio::net::UdpSocket;

    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| Error::Network(format!("Failed to bind socket: {}", e)))?;

    socket
        .connect((ip, 33434))
        .await
        .map_err(|e| Error::Network(format!("Failed to connect socket: {}", e)))?;

    socket
        .send(b"ping")
        .await
        .map_err(|e| Error::Network(format!("Failed to send ping: {}", e)))?;

    Ok(())
}

/// Gets the MAC address of a local interface with the given IP
pub async fn local_mac(ip: IpAddr) -> Result<Option<MacAddr6>> {
    let (connection, handle, _) = new_connection()
        .map_err(|e| Error::CommandExecution(format!("Failed to initialize rtnetlink: {}", e)))?;
    tokio::spawn(connection);

    let mut links = handle.link().get().execute();
    let octets: Vec<u8> = match ip {
        IpAddr::V4(addr) => addr.octets().into(),
        IpAddr::V6(addr) => addr.octets().into(),
    };

    while let Some(link) = links
        .try_next()
        .await
        .map_err(|e| Error::CommandExecution(format!("Failed to fetch links: {}", e)))?
    {
        if link
            .attributes
            .iter()
            .any(|attr| matches!(attr, LinkAttribute::Address(addr) if *addr == octets))
        {
            if let Some(mac) = link.attributes.iter().find_map(|attr| {
                if let LinkAttribute::PermAddress(mac) = attr {
                    Some(MacAddr6::new(
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                    ))
                } else {
                    None
                }
            }) {
                return Ok(Some(mac));
            }
        }
    }

    Ok(None)
}

/// Gets the MAC address of a neighbor with the given IP
pub async fn neighbor_mac(ip: IpAddr) -> Result<Option<MacAddr6>> {
    let (connection, handle, _) = new_connection()
        .map_err(|e| Error::CommandExecution(format!("Failed to initialize rtnetlink: {}", e)))?;
    tokio::spawn(connection);

    let mut neighbours = handle
        .neighbours()
        .get()
        .set_family(IpVersion::V4)
        .execute();

    while let Some(neighbor) = neighbours
        .try_next()
        .await
        .map_err(|e| Error::CommandExecution(format!("Failed to fetch neighbors: {}", e)))?
    {
        if neighbor
            .attributes
            .iter()
            .any(|attr| matches!(attr, NeighbourAttribute::Destination(NeighbourAddress::Inet(addr)) if addr == &ip) || matches!(attr, NeighbourAttribute::Destination(NeighbourAddress::Inet6(addr)) if addr == &ip))
        {
            if let Some(mac) = neighbor.attributes.iter().find_map(|attr| {
                if let NeighbourAttribute::LinkLocalAddress(mac) = attr {
                    Some(MacAddr6::new(
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                    ))
                } else {
                    None
                }
            }) {
                return Ok(Some(mac));
            }
        }
    }

    Ok(None)
}

/// Gets the MAC address for a given IP address by checking local interfaces and neighbors
pub async fn get_mac_addr(ip: IpAddr) -> Result<MacAddr6> {
    if ip == IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)) || ip == IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
    {
        // for debugging :)
        return Ok(MacAddr6::new(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB));
    }
    for _ in 0..2 {
        if let Ok(Some(next_hop)) = next_hop(ip).await {
            let _ = ping(next_hop).await;

            if let Ok(Some(mac)) = neighbor_mac(next_hop).await {
                return Ok(mac);
            }
        } else {
            let _ = ping(ip).await;

            if let Ok(Some(mac)) = neighbor_mac(ip).await {
                return Ok(mac);
            }

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

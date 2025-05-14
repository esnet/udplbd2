// SPDX-License-Identifier: BSD-3-Clause-LBNL
/// Reassemble EJFAT events
/// This file is included in both udplbd::dataplane::receiver and udplbd::dataplane::turmoil::receiver
use crate::dataplane::protocol::EjfatEvent;
use crate::dataplane::protocol::*;
use crate::dataplane::receiver::{Reassembler, ReassemblyStats};
use crate::errors::Error;

use chrono::{DateTime, Utc};
use std::collections::{BTreeMap, HashMap};
use std::convert::TryInto;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::runtime::Runtime;
use tokio::sync::RwLock;
use tracing::{info, trace};
use zerocopy::*;
use zerocopy_derive::*;

use serde::Serialize;

/// Indicates which stage a packet reached during parsing.
#[derive(Debug, Serialize)]
pub enum ParsingStage {
    FrameHeader,
    IpHeader,
    UdpHeader,
    LBHeader,
    ReassemblyHeader,
}

/// A summary of the reassembly header fields extracted from a packet.
#[derive(Debug, Serialize, Clone)]
pub struct ReassemblyHeaderInfo {
    pub tick: u64,
    pub data_id: u16,
    /// Note: This offset is the one inside the reassembly header (i.e. within the reassembly buffer)
    pub contained_data_offset: u32,
    pub length: u32,
}

/// The overall parsing result for each packet.
#[derive(Debug, Serialize)]
pub enum PacketParseState {
    /// The packet was parsed successfully.
    Parsed {
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        timestamp: SystemTime,
        frame_type: FrameType,
        ip_version: IpVersion,
        udp_header: UdpHeader,
        lb_header: Option<LBHeader>,
        reassembly_header: Option<ReassemblyHeaderInfo>,
    },
    /// The packet reached a given stage but then failed.
    Incomplete { stage: ParsingStage, error: String },
}

/// Intermediate structure used to pass parsed header values.
/// Now we include the computed offset from the start of the packet to the beginning
/// of the reassembly header.
struct ParsedPacketData {
    pub src_socket: SocketAddr,
    pub dst_socket: SocketAddr,
    pub timestamp: SystemTime,
    pub frame_type: FrameType,
    pub ip_version: IpVersion,
    pub udp_header: UdpHeader,
    pub lb_header: Option<LBHeader>,
    pub reassembly_header: ReassemblyHeaderInfo,
    /// Offset from the start of `packet_data` to where the reassembly header begins.
    pub reassembly_header_offset: usize,
}

/// A report generated after processing a PCAP file.
#[derive(Debug, Serialize)]
pub struct PcapReassemblyReport {
    /// Fully reassembled events
    #[serde(skip_serializing)]
    pub reassembled: Vec<EjfatEvent>,
    /// Errors encountered while processing packets.
    pub errors: Vec<String>,
    /// Incomplete events still in the reassembly buffers.
    /// Each tuple contains (tick, data_id, missing packet indices).
    pub incomplete_events: Vec<(u64, u16, Vec<usize>)>,
    /// LBHeader information for each packet.
    pub lb_headers: Vec<LBHeader>,
    /// Final reassembly statistics.
    pub stats: ReassemblyStats,
    /// Packet metadata for every packet processed, showing how far parsing got.
    pub packet_metadata: Vec<PacketParseState>,
    /// Mapping from each EJFAT event (tick, data_id) to indices into packet_metadata.
    pub event_packet_indices: HashMap<(u64, u16), Vec<usize>>,
}

impl fmt::Display for PcapReassemblyReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Print basic summary information.
        writeln!(f, "# PCAP Reassembly Report")?;
        writeln!(f, "{} reassembled events", self.reassembled.len())?;
        writeln!(f, "{} errors", self.errors.len())?;
        writeln!(f, "{} incomplete events", self.incomplete_events.len())?;
        writeln!(f, "{} EJFAT packets", self.lb_headers.len())?;
        writeln!(f, " \nReassembly Statistics:\n{:#?}", self.stats)?;
        writeln!(f)?;

        // Helper closure to format a packet's metadata.
        let format_metadata = |meta: &PacketParseState| -> String {
            match meta {
                PacketParseState::Parsed {
                    src_addr,
                    dst_addr,
                    timestamp,
                    ..
                } => {
                    // Format the timestamp into a human-readable string.
                    let ts: String = DateTime::<Utc>::from(*timestamp)
                        .to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
                    format!("from {src_addr} to {dst_addr} pcap_ts {ts} good")
                }
                PacketParseState::Incomplete { stage, error } => {
                    format!("incompletely parsed at {:?}: {}", stage, error)
                }
            }
        };

        // Process each incomplete (partially reassembled) event.
        writeln!(f, "\n## Partially Reassembled Events")?;
        for (tick, data_id, missing_packets) in &self.incomplete_events {
            // Retrieve the received packet indices for this event.
            let received_indices = self.event_packet_indices.get(&(*tick, *data_id));
            let received_count = received_indices.map_or(0, |v| v.len());
            let missing_count = missing_packets.len();
            let total_packets = received_count + missing_count;

            writeln!(
                f,
                "\nevent {tick} data_id {data_id} is missing {missing_count} of {total_packets} expected packets",
            )?;

            if total_packets == 0 {
                continue;
            }

            // Determine the per-packet payload size.
            // We assume that at least one received packet is available so that we can use its reassembly header.
            let payload_size = if let Some(PacketParseState::Parsed {
                reassembly_header: Some(header),
                ..
            }) = received_indices
                .and_then(|v| v.first())
                .and_then(|&idx| self.packet_metadata.get(idx))
            {
                // Compute the per-packet payload size.
                header.length / total_packets as u32
            } else {
                0
            };

            if payload_size == 0 {
                continue;
            }

            // Build a combined sorted map where:
            // - For each received packet, compute its index as: contained_data_offset / payload_size.
            // - Also insert any missing packet indices.
            let mut combined: BTreeMap<usize, Option<&PacketParseState>> = BTreeMap::new();

            if let Some(received) = received_indices {
                for &meta_idx in received {
                    if let Some(meta) = self.packet_metadata.get(meta_idx) {
                        if let PacketParseState::Parsed {
                            reassembly_header: Some(header),
                            ..
                        } = meta
                        {
                            let computed_index =
                                (header.contained_data_offset / payload_size) as usize;
                            combined.insert(computed_index, Some(meta));
                        }
                    }
                }
            }

            // Insert missing packet indices (if they are not already present).
            for &missing_idx in missing_packets {
                combined.entry(missing_idx).or_insert(None);
            }

            // Print the combined sorted list.
            for (pkt_index, meta_opt) in combined {
                if let Some(meta) = meta_opt {
                    writeln!(
                        f,
                        "  {tick}/{data_id}/{pkt_index:04} {}",
                        format_metadata(meta)
                    )?;
                } else {
                    writeln!(f, "  {tick}/{data_id}/{pkt_index:04} missing!",)?;
                }
            }
        }

        // Print any errors encountered.
        writeln!(f, "\n## Errors")?;
        for (i, error) in self.errors.iter().enumerate() {
            writeln!(f, "  {}. {}", i + 1, error)?;
        }
        Ok(())
    }
}

/// PCAP Global Header
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct PcapGlobalHeader {
    magic_number: u32,  // Magic number
    version_major: u16, // Major version number
    version_minor: u16, // Minor version number
    thiszone: i32,      // GMT to local correction
    sigfigs: u32,       // Accuracy of timestamps
    snaplen: u32,       // Max length of captured packets
    network: u32,       // Data link type
}

/// PCAP Packet Header
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone)]
#[repr(C, packed)]
struct PcapPacketHeader {
    ts_sec: u32,   // Timestamp seconds
    ts_usec: u32,  // Timestamp microseconds
    incl_len: u32, // Number of octets of packet saved in file
    orig_len: u32, // Actual length of packet
}

/// Ethernet Frame Header
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone)]
#[repr(C, packed)]
struct EthernetHeader {
    dst_mac: [u8; 6], // Destination MAC address
    src_mac: [u8; 6], // Source MAC address
    ether_type: u16,  // EtherType field
}

/// Loopback Frame Header
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone)]
#[repr(C, packed)]
struct LoopbackHeader {
    family: u32, // Address family
}

/// IPv4 Header
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone)]
#[repr(C, packed)]
struct IPv4Header {
    version_ihl: u8,      // Version (4 bits) + Internet header length (4 bits)
    tos: u8,              // Type of service
    total_length: u16,    // Total length
    identification: u16,  // Identification
    flags_fragment: u16,  // Flags (3 bits) + Fragment offset (13 bits)
    ttl: u8,              // Time to live
    protocol: u8,         // Protocol
    header_checksum: u16, // Header checksum
    src_addr: [u8; 4],    // Source address
    dst_addr: [u8; 4],    // Destination address
                          // Options and padding are variable and not included in this struct
}

impl IPv4Header {
    /// Get the header length in bytes.
    fn header_length(&self) -> usize {
        ((self.version_ihl & 0x0F) as usize) * 4
    }
    fn protocol(&self) -> u8 {
        self.protocol
    }
}

/// IPv6 Header
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone)]
#[repr(C, packed)]
struct IPv6Header {
    version_traffic_flow: u32, // Version (4 bits) + Traffic class (8 bits) + Flow label (20 bits)
    payload_length: u16,       // Payload length
    next_header: u8,           // Next header
    hop_limit: u8,             // Hop limit
    src_addr: [u8; 16],        // Source address
    dst_addr: [u8; 16],        // Destination address
}

impl IPv6Header {
    fn protocol(&self) -> u8 {
        self.next_header
    }
}

/// UDP Header
#[derive(
    Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy, Serialize,
)]
#[repr(C, packed)]
pub struct UdpHeader {
    src_port: u16, // Source port
    dst_port: u16, // Destination port
    length: u16,   // Length
    checksum: u16, // Checksum
}

impl UdpHeader {
    fn src_port(&self) -> u16 {
        u16::from_be(self.src_port)
    }
    fn dst_port(&self) -> u16 {
        u16::from_be(self.dst_port)
    }
}

/// Represents a port range for a specific IP address
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct PortRange {
    pub ip: IpAddr,
    pub start_port: u16,
    pub end_port: u16,
}

impl PortRange {
    /// Create a new port range.
    fn new(ip: IpAddr, start_port: u16, end_port: u16) -> Self {
        Self {
            ip,
            start_port,
            end_port,
        }
    }
    /// Check if a socket address is within this port range.
    fn contains(&self, addr: &SocketAddr) -> bool {
        addr.ip() == self.ip && addr.port() >= self.start_port && addr.port() <= self.end_port
    }
}

/// Frame type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub enum FrameType {
    Ethernet,
    Loopback,
    Unknown,
}

/// IP protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub enum IpVersion {
    IPv4,
    IPv6,
    Unknown,
}

/// Reassemble events from a PCAP file with support for multiple reassemblers.
/// - `pcap_file`: the path to the PCAP file.
/// - `lb`: whether to expect LB headers in the packets.
/// - `reassemblers`: an optional map of port ranges to reassemblers.
///
/// When processing a packet, if its destination SocketAddr does not match any existing
/// PortRange, the function will check whether it is within 32 ports of an existing range on the same IP.
/// If so, that PortRange is expanded (with a log message). Otherwise, a new reassembler is created.
pub fn reassemble_from_pcap_with_reassemblers<P: AsRef<Path>>(
    pcap_file: P,
    lb: bool,
    reassemblers: Option<HashMap<PortRange, Reassembler>>,
) -> Result<PcapReassemblyReport, Error> {
    // PCAP file format constants.
    const PCAP_MAGIC: u32 = 0xa1b2c3d4;
    const PCAP_MAGIC_SWAPPED: u32 = 0xd4c3b2a1;
    const PCAP_HEADER_SIZE: usize = 24;
    const PACKET_HEADER_SIZE: usize = 16;
    const LB_HEADER_SIZE: usize = 8; // adjust if needed
    const REASSEMBLY_HEADER_SIZE: usize = 16; // adjust if needed

    // Open the PCAP file.
    let mut file = File::open(pcap_file)?;

    // Read global header.
    let mut global_header_buf = [0u8; PCAP_HEADER_SIZE];
    file.read_exact(&mut global_header_buf)?;
    let magic = u32::from_le_bytes(global_header_buf[0..4].try_into().unwrap());
    let swap_endian = magic == PCAP_MAGIC_SWAPPED;
    if magic != PCAP_MAGIC && magic != PCAP_MAGIC_SWAPPED {
        return Err(Error::Parse("Invalid PCAP magic number".to_string()));
    }

    // Create a Tokio runtime for reassembler operations.
    let rt = Runtime::new()?;

    // Initialize or use provided reassemblers map. Default: a catch-all reassembler.
    let mut reassemblers_map = reassemblers.unwrap_or_else(|| {
        let mut map = HashMap::new();
        map.insert(
            PortRange::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0, 65535),
            Reassembler::new(20_073_741_824, 9000, None),
        );
        map
    });

    // For final report tracking.
    let stats = Arc::new(RwLock::new(ReassemblyStats::default()));
    let mut reassembled = Vec::new();
    let mut errors = Vec::new();
    let lb_headers = Vec::new();
    let mut packet_metadata: Vec<PacketParseState> = Vec::new();
    let mut event_packet_indices: HashMap<(u64, u16), Vec<usize>> = HashMap::new();

    let mut packet_header_buf = [0u8; PACKET_HEADER_SIZE];
    let mut packet_count = 0;

    while let Ok(()) = file.read_exact(&mut packet_header_buf) {
        packet_count += 1;
        // Parse PCAP packet header.
        let pcap_hdr = if swap_endian {
            PcapPacketHeader {
                ts_sec: u32::from_be_bytes(packet_header_buf[0..4].try_into().unwrap()),
                ts_usec: u32::from_be_bytes(packet_header_buf[4..8].try_into().unwrap()),
                incl_len: u32::from_be_bytes(packet_header_buf[8..12].try_into().unwrap()),
                orig_len: u32::from_be_bytes(packet_header_buf[12..16].try_into().unwrap()),
            }
        } else {
            PcapPacketHeader {
                ts_sec: u32::from_le_bytes(packet_header_buf[0..4].try_into().unwrap()),
                ts_usec: u32::from_le_bytes(packet_header_buf[4..8].try_into().unwrap()),
                incl_len: u32::from_le_bytes(packet_header_buf[8..12].try_into().unwrap()),
                orig_len: u32::from_le_bytes(packet_header_buf[12..16].try_into().unwrap()),
            }
        };

        let caplen = pcap_hdr.incl_len as usize;

        // Read packet data.
        let mut packet_data = vec![0u8; caplen];
        if let Err(e) = file.read_exact(&mut packet_data) {
            errors.push(format!("Failed to read packet data: {}", e));
            break;
        }

        // Capture the packet timestamp.
        let timestamp = UNIX_EPOCH
            .checked_add(Duration::from_secs(pcap_hdr.ts_sec as u64))
            .and_then(|t| t.checked_add(Duration::from_micros(pcap_hdr.ts_usec as u64)))
            .unwrap_or_else(SystemTime::now);

        // Parse the packet.
        let parsed_data = (|| -> Result<ParsedPacketData, (ParsingStage, String)> {
            // Start with the full packet_data slice.
            let mut rem = &packet_data[..];

            // --- Ethernet or Loopback Frame Header ---
            let (mut frame_type, mut ip_version) =
                if let Ok((eth_hdr, new_rem)) = EthernetHeader::ref_from_prefix(rem) {
                    let ether_type = u16::from_be(eth_hdr.ether_type);
                    rem = new_rem;
                    if ether_type == 0x0800 || ether_type == 0x86DD {
                        (
                            FrameType::Ethernet,
                            if ether_type == 0x0800 {
                                IpVersion::IPv4
                            } else {
                                IpVersion::IPv6
                            },
                        )
                    } else {
                        (FrameType::Unknown, IpVersion::Unknown)
                    }
                } else {
                    (FrameType::Unknown, IpVersion::Unknown)
                };

            if let FrameType::Unknown = frame_type {
                if let Ok((lb_hdr, new_rem)) = LoopbackHeader::ref_from_prefix(rem) {
                    let family = if swap_endian {
                        u32::from_be(lb_hdr.family)
                    } else {
                        u32::from_le(lb_hdr.family)
                    };
                    rem = new_rem;
                    if family == 2 || family == 30 {
                        frame_type = FrameType::Loopback;
                        ip_version = if family == 2 {
                            IpVersion::IPv4
                        } else {
                            IpVersion::IPv6
                        };
                    } else {
                        return Err((
                            ParsingStage::FrameHeader,
                            "Unknown address family in Loopback header".to_string(),
                        ));
                    }
                } else {
                    return Err((
                        ParsingStage::FrameHeader,
                        "Packet too small for any frame header".to_string(),
                    ));
                }
            }

            // --- IP Header ---
            let (src_ip, dst_ip) = if ip_version == IpVersion::IPv4 {
                let (ipv4_hdr, new_rem) = IPv4Header::ref_from_prefix(rem).map_err(|_| {
                    (
                        ParsingStage::IpHeader,
                        format!("Packet {} too small for IPv4 header", packet_count),
                    )
                })?;
                if ipv4_hdr.protocol() != 17 {
                    return Err((
                        ParsingStage::IpHeader,
                        format!("Packet {} is not UDP", packet_count),
                    ));
                }
                let header_len = ipv4_hdr.header_length();
                rem = if header_len > std::mem::size_of::<IPv4Header>() {
                    &rem[header_len..]
                } else {
                    new_rem
                };
                let src = IpAddr::V4(Ipv4Addr::new(
                    ipv4_hdr.src_addr[0],
                    ipv4_hdr.src_addr[1],
                    ipv4_hdr.src_addr[2],
                    ipv4_hdr.src_addr[3],
                ));
                let dst = IpAddr::V4(Ipv4Addr::new(
                    ipv4_hdr.dst_addr[0],
                    ipv4_hdr.dst_addr[1],
                    ipv4_hdr.dst_addr[2],
                    ipv4_hdr.dst_addr[3],
                ));
                (src, dst)
            } else if ip_version == IpVersion::IPv6 {
                let (ipv6_hdr, new_rem) = IPv6Header::ref_from_prefix(rem).map_err(|_| {
                    (
                        ParsingStage::IpHeader,
                        format!("Packet {} too small for IPv6 header", packet_count),
                    )
                })?;
                if ipv6_hdr.protocol() != 17 {
                    return Err((
                        ParsingStage::IpHeader,
                        format!("Packet {} is not UDP", packet_count),
                    ));
                }
                rem = new_rem;
                let src = {
                    let s = &ipv6_hdr.src_addr;
                    IpAddr::V6(Ipv6Addr::new(
                        ((s[0] as u16) << 8) | s[1] as u16,
                        ((s[2] as u16) << 8) | s[3] as u16,
                        ((s[4] as u16) << 8) | s[5] as u16,
                        ((s[6] as u16) << 8) | s[7] as u16,
                        ((s[8] as u16) << 8) | s[9] as u16,
                        ((s[10] as u16) << 8) | s[11] as u16,
                        ((s[12] as u16) << 8) | s[13] as u16,
                        ((s[14] as u16) << 8) | s[15] as u16,
                    ))
                };
                let dst = {
                    let s = &ipv6_hdr.dst_addr;
                    IpAddr::V6(Ipv6Addr::new(
                        ((s[0] as u16) << 8) | s[1] as u16,
                        ((s[2] as u16) << 8) | s[3] as u16,
                        ((s[4] as u16) << 8) | s[5] as u16,
                        ((s[6] as u16) << 8) | s[7] as u16,
                        ((s[8] as u16) << 8) | s[9] as u16,
                        ((s[10] as u16) << 8) | s[11] as u16,
                        ((s[12] as u16) << 8) | s[13] as u16,
                        ((s[14] as u16) << 8) | s[15] as u16,
                    ))
                };
                (src, dst)
            } else {
                return Err((
                    ParsingStage::IpHeader,
                    format!("Packet {}: Unknown IP version", packet_count),
                ));
            };

            // --- UDP Header ---
            let (udp, new_rem) = UdpHeader::ref_from_prefix(rem).map_err(|_| {
                (
                    ParsingStage::UdpHeader,
                    format!("Packet {} too small for UDP header", packet_count),
                )
            })?;
            rem = new_rem;
            let src_port = udp.src_port();
            let dst_port = udp.dst_port();
            let src_socket = SocketAddr::new(src_ip, src_port);
            let dst_socket = SocketAddr::new(dst_ip, dst_port);

            // --- LB Header (optional) ---
            let parsed_lb = if lb {
                if rem.len() < LB_HEADER_SIZE {
                    return Err((
                        ParsingStage::LBHeader,
                        format!("Packet {} too small for LB header", packet_count),
                    ));
                }
                let (lb_hdr, new_rem) = LBHeader::ref_from_prefix(rem).map_err(|_| {
                    (
                        ParsingStage::LBHeader,
                        format!("Failed to parse LB header in packet {}", packet_count),
                    )
                })?;
                if !lb_hdr.is_valid() {
                    return Err((
                        ParsingStage::LBHeader,
                        format!("Invalid LB header in packet {}", packet_count),
                    ));
                }
                rem = new_rem;
                Some(lb_hdr)
            } else {
                None
            };

            // --- Reassembly Header ---
            // At this point, 'rem' is the slice starting immediately after all other headers.
            // Compute the offset from the start of packet_data to 'rem'.
            let consumed = packet_data.len() - rem.len();

            if rem.len() < REASSEMBLY_HEADER_SIZE {
                return Err((ParsingStage::ReassemblyHeader, format!(
                    "Packet {} too small for ReassemblyHeader (available: {} bytes, needed: {} bytes)",
                    packet_count,
                    rem.len(),
                    REASSEMBLY_HEADER_SIZE,
                )));
            }
            // Split off the reassembly header from the end of 'rem'.
            // Assume ReassemblyPayload::ref_from_suffix splits 'rem' into:
            // (payload_prefix, reassembly_payload)
            let (payload_prefix, reassembly_payload) = ReassemblyPayload::ref_from_suffix(rem)
                .map_err(|e| {
                    (
                        ParsingStage::ReassemblyHeader,
                        format!(
                            "Failed to parse ReassemblyPayload from packet {}: {:?}",
                            packet_count, e
                        ),
                    )
                })?;
            // Compute the offset in the full packet at which the reassembly header starts.
            let reassembly_header_offset = consumed + payload_prefix.len();
            let r_header = &reassembly_payload.header;
            let reassembly_info = ReassemblyHeaderInfo {
                tick: r_header.tick.get(),
                data_id: r_header.data_id.get(),
                contained_data_offset: r_header.offset.get(),
                length: r_header.length.get(),
            };

            Ok(ParsedPacketData {
                src_socket,
                dst_socket,
                timestamp,
                frame_type,
                ip_version,
                udp_header: *udp,
                lb_header: parsed_lb.cloned(),
                reassembly_header: reassembly_info,
                reassembly_header_offset,
            })
        })();

        // Record the packet parse state.
        let packet_index = packet_metadata.len();
        let parsed_packet = match parsed_data {
            Ok(data) => {
                packet_metadata.push(PacketParseState::Parsed {
                    src_addr: data.src_socket,
                    dst_addr: data.dst_socket,
                    timestamp: data.timestamp,
                    frame_type: data.frame_type,
                    ip_version: data.ip_version,
                    udp_header: data.udp_header,
                    lb_header: data.lb_header,
                    reassembly_header: Some(data.reassembly_header.clone()),
                });
                let event_id = (data.reassembly_header.tick, data.reassembly_header.data_id);
                event_packet_indices
                    .entry(event_id)
                    .or_default()
                    .push(packet_index);
                data
            }
            Err((stage, err_msg)) => {
                packet_metadata.push(PacketParseState::Incomplete {
                    stage,
                    error: err_msg.clone(),
                });
                errors.push(err_msg);
                continue;
            }
        };

        // --- Reassembly Processing ---
        // Select the appropriate reassembler based on the destination socket.
        let dst_socket = parsed_packet.dst_socket;
        let mut selected_range: Option<PortRange> = None;
        for key in reassemblers_map.keys() {
            if key.contains(&dst_socket) {
                selected_range = Some(key.clone());
                break;
            }
        }
        if selected_range.is_none() {
            let mut candidate: Option<PortRange> = None;
            for key in reassemblers_map.keys() {
                if key.ip == dst_socket.ip()
                    && ((dst_socket.port() as i32 - key.start_port as i32).abs() < 32
                        || (dst_socket.port() as i32 - key.end_port as i32).abs() < 32)
                {
                    candidate = Some(key.clone());
                    break;
                }
            }
            if let Some(mut cand) = candidate {
                if let Some(reasm) = reassemblers_map.remove(&cand) {
                    let old_cand = cand.clone();
                    cand.start_port = cand.start_port.min(dst_socket.port());
                    cand.end_port = cand.end_port.max(dst_socket.port());
                    reassemblers_map.insert(cand.clone(), reasm);
                    selected_range = Some(cand.clone());
                    info!("Assigning {} to existing reassembler; expanding range from {}:{}-{} to {}:{}-{}",
                        dst_socket,
                        old_cand.ip, old_cand.start_port, old_cand.end_port,
                        cand.ip, cand.start_port, cand.end_port);
                }
            }
        }
        if selected_range.is_none() {
            let new_range = PortRange::new(dst_socket.ip(), dst_socket.port(), dst_socket.port());
            reassemblers_map.insert(
                new_range.clone(),
                Reassembler::new(20_073_741_824, 9000, None),
            );
            selected_range = Some(new_range);
            info!("Creating new reassembler for {}", dst_socket);
        }
        let range_used = selected_range.unwrap();
        let reassembler = reassemblers_map.get_mut(&range_used).unwrap();

        // Use the computed offset (from the start of packet_data) to get the section containing the reassembly header.
        let header_offset = parsed_packet.reassembly_header_offset;
        if header_offset > packet_data.len() {
            errors.push(format!(
                "Invalid reassembly header offset {} in packet {}",
                header_offset, packet_count
            ));
            continue;
        }
        let payload = &packet_data[header_offset..];
        let mut payload_vec = payload.to_vec();

        match rt.block_on(reassembler.handle_packet(&mut payload_vec, &stats)) {
            Ok(Some(event)) => {
                trace!(
                    "Packet {}: Successfully reassembled event tick={}, data_id={}, data_len={}",
                    packet_count,
                    event.tick,
                    event.data_id,
                    event.data.len()
                );
                {
                    let mut stats_guard = rt.block_on(stats.write());
                    stats_guard.total_events_reassembled += 1;
                }
                reassembled.push(event);
            }
            Ok(None) => {
                trace!(
                    "Packet {}: Processed successfully, waiting for more packets",
                    packet_count
                );
            }
            Err(e) => {
                let error_msg = format!("Reassembly error in packet {}: {}", packet_count, e);
                trace!("{}", error_msg);
                errors.push(error_msg);
                let mut stats_guard = rt.block_on(stats.write());
                stats_guard.total_events_reassembly_err += 1;
            }
        }
    }

    // Collect incomplete events from each reassembler.
    let mut incomplete_events = Vec::new();
    for reassembler in reassemblers_map.values() {
        for ((tick, data_id), buffer) in &reassembler.buffers {
            incomplete_events.push((*tick, *data_id, buffer.missing_packets()));
        }
    }
    let final_stats = rt.block_on(async { stats.read().await.clone() });

    Ok(PcapReassemblyReport {
        reassembled,
        errors,
        incomplete_events,
        lb_headers,
        stats: final_stats,
        packet_metadata,
        event_packet_indices,
    })
}

/// Reassemble events from a PCAP file (without using the pcap crate) by reading the file manually.
/// - `pcap_file`: the path to the PCAP file.
/// - `lb`: whether to expect LB headers in the packets.
///
/// Uses a default maximum memory of 20 GB.
pub fn reassemble_from_pcap<P: AsRef<Path>>(
    pcap_file: P,
    lb: bool,
) -> Result<PcapReassemblyReport, Error> {
    let mut reassemblers = HashMap::new();
    reassemblers.insert(
        PortRange::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0, 65535),
        Reassembler::new(20_073_741_824, 9000, None),
    );
    reassemble_from_pcap_with_reassemblers(pcap_file, lb, Some(reassemblers))
}

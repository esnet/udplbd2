// SPDX-License-Identifier: BSD-3-Clause-LBNL
//! Misc. helper functions
use std::net::{IpAddr, Ipv6Addr};

use tracing::warn;

/// Returns true if the name is a valid DNS name (letters, digits, hyphens, periods) plus slashes, underscores, colons
/// - Each label must start and end with a letter or digit.
/// - Labels are separated by periods.
/// - No empty labels, no consecutive periods.
/// - Hyphens allowed but not at start/end of label.
/// - Slashes and colons to enable different names for mutiple processes on the same host (e.g. /1 or :port)
/// - Underscores allowed for backwards compatibility
pub fn is_valid_name(name: &str) -> bool {
    if name.is_empty() {
        return true;
    }
    if name.len() > 253 {
        return false;
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        let bytes = label.as_bytes();
        if !bytes[0].is_ascii_alphanumeric() || !bytes[label.len() - 1].is_ascii_alphanumeric() {
            return false;
        }
        for &b in bytes {
            if !(b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b':' || b == b'/') {
                return false;
            }
        }
    }
    true
}

/// Converts a 48-bit MAC address to its u64 representation.
/// The MAC address is left-aligned in the resulting u64, with the remaining
/// 16 most significant bits set to zero.
///
/// # Arguments
/// * `mac` - The MAC address to convert
///
/// # Returns
/// A u64 containing the MAC address in the least significant 48 bits
pub fn mac_to_u64(mac: macaddr::MacAddr6) -> u64 {
    let bytes = mac.as_bytes();
    ((bytes[0] as u64) << 40)
        | ((bytes[1] as u64) << 32)
        | ((bytes[2] as u64) << 24)
        | ((bytes[3] as u64) << 16)
        | ((bytes[4] as u64) << 8)
        | (bytes[5] as u64)
}

/// Generates the MAC address for IPv6 Neighbor Discovery's Solicited-Node multicast address.
/// The multicast MAC address is derived from the IPv6 address by taking the low-order 24 bits
/// of the IPv6 address and appending them to the prefix 33:33:00:00:00:00.
///
/// # Arguments
/// * `ipv6` - The IPv6 address for which to generate the solicited-node multicast MAC
///
/// # Returns
/// A u64 containing the multicast MAC address in the least significant 48 bits
///
/// # References
/// - RFC 4861: Neighbor Discovery for IP version 6 (IPv6)
/// - RFC 2464: Transmission of IPv6 Packets over Ethernet Networks
pub fn generate_solicited_node_multicast_mac(ipv6: &Ipv6Addr) -> u64 {
    let octets = ipv6.octets();
    0x3333ff000000 | ((octets[13] as u64) << 16) | ((octets[14] as u64) << 8) | (octets[15] as u64)
}

/// Generates the IPv6 Solicited-Node multicast address for a given IPv6 address.
/// As specified in RFC 4861, the solicited-node multicast address is formed by
/// taking the low-order 24 bits of the target IPv6 address and appending them to
/// the prefix FF02:0:0:0:0:1:FF00::/104.
///
/// # Arguments
/// * `ipv6` - The IPv6 address for which to generate the solicited-node multicast address
///
/// # Returns
/// The solicited-node multicast IPv6 address
///
/// # References
/// - RFC 4861: Neighbor Discovery for IP version 6 (IPv6)
pub fn generate_solicited_node_multicast_ipv6(ipv6: &Ipv6Addr) -> Ipv6Addr {
    let octets = ipv6.octets();
    let mut new_octets = [0; 16];
    new_octets[0] = 0xff;
    new_octets[1] = 0x02;
    new_octets[10] = 0x00;
    new_octets[11] = 0x01;
    new_octets[12] = 0xff;
    new_octets[13] = octets[13];
    new_octets[14] = octets[14];
    new_octets[15] = octets[15];
    Ipv6Addr::from(new_octets)
}

/// Check if an IP address is a private/non-globally-routable address
///
/// This includes all addresses that are not globally reachable according to IANA registries:
/// - RFC 1918 private addresses
/// - RFC 4193 Unique Local Addresses (IPv6)
/// - RFC 4291 Link-Local addresses (IPv6)
/// - Shared address space (100.64.0.0/10)
/// - Link-local addresses (169.254.0.0/16)
/// - And other special-purpose addresses
pub fn is_private_ip(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();

            // RFC 1918 private ranges:
            // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            octets[0] == 10
                || (octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31))
                || (octets[0] == 192 && octets[1] == 168)
                // Shared address space (RFC 6598): 100.64.0.0/10
                || (octets[0] == 100 && (octets[1] >= 64 && octets[1] <= 127))
                // Link-local (RFC 3927): 169.254.0.0/16
                || (octets[0] == 169 && octets[1] == 254)
                // Documentation addresses (RFC 5737): 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
                // Benchmarking (RFC 2544): 198.18.0.0/15
                || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        }
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            let first_segment = segments[0];

            // RFC 4193 Unique Local Addresses (ULA): fc00::/7
            // RFC 4291 Link-Local addresses: fe80::/10
            (first_segment & 0xfe00 == 0xfc00)
                || (first_segment & 0xffc0 == 0xfe80)
                // Documentation prefix (RFC 3849): 2001:db8::/32
                || (first_segment == 0x2001 && segments[1] == 0x0db8)
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Prefix {
    pub start: u64,
    pub power_of_two: u32,
}

/// Decomposes a range into a sequence of power-of-two prefixes that exactly cover
/// the specified boundary defined by the range [start, end).
///
/// # Arguments
/// * `start` - The inclusive start of the range
/// * `end` - The exclusive end of the range
///
/// # Returns
/// A vector of `Prefix` structs, each representing a power-of-two range segment
pub fn range_as_power_of_two_prefixes(start: u64, end: u64) -> Vec<Prefix> {
    if start == 0 && (end == 0 || end == u64::MAX) {
        return vec![Prefix {
            start: 0,
            power_of_two: 64,
        }];
    }

    let mut result = Vec::new();
    let mut current_start = start;

    if end <= start {
        warn!("next boundary {end} is smaller than or equal to previous boundary {start}");
        return vec![Prefix {
            start: 0,
            power_of_two: 64,
        }];
    }

    while current_start < end {
        // Calculate the prefix length based on the least significant set bit in "current_start"
        let mut exponent = current_start.trailing_zeros();
        if exponent >= 64 {
            exponent = 63;
        }

        let mut prefix_length = 1u64 << exponent;

        // Ensure the prefix does not extend beyond "end"
        while (exponent > 0 && current_start.saturating_add(prefix_length) > end)
            || (current_start.wrapping_add(prefix_length) < start)
        {
            exponent -= 1;
            prefix_length >>= 1;
        }

        // Add the prefix to the result
        result.push(Prefix {
            start: current_start,
            power_of_two: exponent,
        });

        // Increment current_start by prefix_length, safely handling overflow
        current_start = current_start.saturating_add(prefix_length);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;
    use std::str::FromStr;

    #[test]
    fn test_mac_to_u64() {
        let mac = macaddr::MacAddr6::from_str("00:11:22:33:44:55").unwrap();
        assert_eq!(mac_to_u64(mac), 0x001122334455);
    }

    #[test]
    fn test_solicited_node_multicast() {
        let ipv6 = Ipv6Addr::from_str("2001:db8::1:2:3").unwrap();
        let mac = generate_solicited_node_multicast_mac(&ipv6);
        assert_eq!(mac & 0xFFFFFF000000, 0x3333FF000000);

        let multicast = generate_solicited_node_multicast_ipv6(&ipv6);
        assert_eq!(multicast.segments()[0], 0xff02);
        assert_eq!(multicast.segments()[5], 0x0001);
        assert_eq!(
            multicast.segments()[6],
            0xff00 | (ipv6.segments()[6] & 0xff)
        );
        assert_eq!(multicast.segments()[7], ipv6.segments()[7]);
    }

    #[test]
    fn test_range_as_power_of_two_prefixes() {
        let prefixes = range_as_power_of_two_prefixes(0, u64::MAX);
        assert_eq!(
            prefixes,
            vec![Prefix {
                start: 0,
                power_of_two: 64
            }]
        );

        let prefixes = range_as_power_of_two_prefixes(16, 20);
        assert_eq!(
            prefixes,
            vec![Prefix {
                start: 16,
                power_of_two: 2
            }]
        );

        let prefixes = range_as_power_of_two_prefixes(16, 32);
        assert_eq!(
            prefixes,
            vec![Prefix {
                start: 16,
                power_of_two: 4
            },]
        );

        let prefixes = range_as_power_of_two_prefixes(2, 7);
        assert_eq!(
            prefixes,
            vec![
                Prefix {
                    start: 2,
                    power_of_two: 1
                },
                Prefix {
                    start: 4,
                    power_of_two: 1
                },
                Prefix {
                    start: 6,
                    power_of_two: 0
                },
            ]
        );

        let prefixes = range_as_power_of_two_prefixes(u64::MAX - 3, u64::MAX);
        assert_eq!(
            prefixes,
            vec![
                Prefix {
                    start: u64::MAX - 3,
                    power_of_two: 1
                },
                Prefix {
                    start: u64::MAX - 1,
                    power_of_two: 0
                }
            ]
        );
    }
}

// IP family for sync server selection, matches proto discriminants
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpFamily {
    DualStack = 0,
    Ipv4 = 1,
    Ipv6 = 2,
}

impl From<u32> for IpFamily {
    fn from(val: u32) -> Self {
        match val {
            1 => IpFamily::Ipv4,
            2 => IpFamily::Ipv6,
            _ => IpFamily::DualStack,
        }
    }
}

/// Resolves slot demands, handling index -1 (auto-placement) and conflict checking.
///
/// # Arguments
/// * `existing_ranges` - Already occupied ranges as (start, end) tuples
/// * `slot_demands` - Vec of (session_id, slot_index, slot_length) where slot_index -1 means auto-place
///
/// # Returns
/// A Result containing Vec of (session_id, resolved_slot_index, slot_length) with no conflicts,
/// or an error string describing the conflict.
pub fn resolve_slot_ranges<T: Clone>(
    existing_ranges: &[(i32, i32)],
    slot_demands: Vec<(T, i32, u32)>,
) -> Result<Vec<(T, i32, u32)>, String> {
    let mut occupied: Vec<(i32, i32)> = existing_ranges.to_vec();
    occupied.sort_by_key(|&(start, _)| start);

    let mut resolved = Vec::new();
    for (session_id, mut slot_index, slot_length) in slot_demands {
        let range_len = slot_length as i32;
        if slot_index == -1 {
            // Find first gap between occupied ranges large enough for range_len
            let mut prev_end = 0;
            let mut found = false;
            for &(occ_start, occ_end) in &occupied {
                if occ_start - prev_end >= range_len {
                    slot_index = prev_end;
                    found = true;
                    break;
                }
                prev_end = occ_end;
            }
            // If no gap found, place after last occupied range
            if !found {
                slot_index = prev_end;
            }
        }
        // Check for overlap with any occupied range
        let start = slot_index;
        let end = start + range_len;
        for &(occ_start, occ_end) in &occupied {
            if start < occ_end && end > occ_start {
                return Err(format!("Slot demand conflict at range [{}, {})", start, end));
            }
        }
        // Insert new range into occupied, keep sorted
        let insert_pos = occupied.partition_point(|&(s, _)| s < start);
        occupied.insert(insert_pos, (start, end));
        resolved.push((session_id, slot_index, slot_length));
    }
    Ok(resolved)
}

#[cfg(test)]
mod slot_range_tests {
    use super::*;

    #[test]
    fn test_resolve_empty_existing() {
        let existing: Vec<(i32, i32)> = vec![];
        let demands = vec![
            (1, 0, 128u32),
            (2, -1, 128u32),
        ];
        let result = resolve_slot_ranges(&existing, demands).unwrap();
        assert_eq!(result, vec![(1, 0, 128), (2, 128, 128)]);
    }

    #[test]
    fn test_resolve_with_gap() {
        let existing = vec![(0, 100), (200, 300)];
        let demands = vec![(1, -1, 50u32)];
        let result = resolve_slot_ranges(&existing, demands).unwrap();
        assert_eq!(result, vec![(1, 100, 50)]);
    }

    #[test]
    fn test_resolve_conflict() {
        let existing = vec![(0, 128)];
        let demands = vec![(1, 64, 128u32)];
        let result = resolve_slot_ranges(&existing, demands);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("conflict"));
    }

    #[test]
    fn test_resolve_no_conflict_adjacent() {
        let existing = vec![(0, 128)];
        let demands = vec![(1, 128, 128u32)];
        let result = resolve_slot_ranges(&existing, demands).unwrap();
        assert_eq!(result, vec![(1, 128, 128)]);
    }
}

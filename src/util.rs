//! Misc. helper functions
use std::net::Ipv6Addr;

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
    0x333300000000 | ((octets[13] as u64) << 16) | ((octets[14] as u64) << 8) | (octets[15] as u64)
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
    if start == 0 && end == u64::MAX {
        return vec![Prefix {
            start: 0,
            power_of_two: 64,
        }];
    }

    let mut result = Vec::new();
    let mut current_start = start;

    while current_start < end {
        // Calculate the prefix length based on the least significant set bit in "current_start"
        let mut exponent = current_start.trailing_zeros();
        if exponent >= 64 {
            exponent = 63;
        }

        let mut prefix_length = 1u64 << exponent;

        // Ensure the prefix does not extend beyond "end"
        while exponent > 0 && (current_start.saturating_add(prefix_length) > end) {
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
        assert_eq!(mac & 0xFFFFFF000000, 0x333300000000);

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
            vec![Prefix {
                start: u64::MAX - 3,
                power_of_two: 2
            },]
        );
    }
}

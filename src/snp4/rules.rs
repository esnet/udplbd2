//! Types for every rule in udplb that can be coverted To/From the `TableRule` in the smartnic-p4 protobuf API.
use crate::errors::{Error, Result};
use crate::proto::smartnic::p4_v2::{
    self, r#match::Type as MatchType, Action, ActionParameter, Match, MatchKeyOnly, MatchKeyPrefix,
    TableRule,
};
use std::{
    collections::HashMap,
    fmt,
    net::IpAddr,
    net::{Ipv4Addr, Ipv6Addr},
};

// Helper functions for hex conversion
fn hex<T: std::fmt::LowerHex>(val: T) -> String {
    format!("{val:#x}")
}

fn hexip(addr: IpAddr) -> String {
    match addr {
        IpAddr::V4(v4) => hex(u32::from_be_bytes(v4.octets())),
        IpAddr::V6(v6) => hex(u128::from_be_bytes(v6.octets())),
    }
}

impl TryFrom<TableRule> for Layer2InputPacketFilterRule {
    type Error = Error;

    fn try_from(rule: TableRule) -> Result<Self> {
        if rule.table_name != "mac_dst_filter_table" {
            return Err(Error::NotFound(format!(
                "Expected mac_dst_filter_table, got {}",
                rule.table_name
            )));
        }

        let action = rule
            .action
            .ok_or_else(|| Error::Config("Missing action".into()))?;
        if action.name != "set_mac_sa" {
            return Err(Error::Config("Invalid action".into()));
        }

        if rule.matches.len() < 2 {
            return Err(Error::Config("Missing match fields".into()));
        }

        let dest_mac_addr = parse_hex_u64(get_key_only(rule.matches[1].r#type.as_ref())?)
            .ok_or_else(|| Error::Config("Invalid dest MAC address".into()))?;
        let src_mac_addr = parse_hex_u64(&action.parameters[0].value)
            .ok_or_else(|| Error::Config("Invalid src MAC address".into()))?;

        Ok(Layer2InputPacketFilterRule {
            match_dest_mac_addr: dest_mac_addr,
            set_src_mac_addr: src_mac_addr,
        })
    }
}

// Helper functions for creating Match and Action types
fn match_wildcard(key: String, mask: String) -> Match {
    Match {
        r#type: Some(MatchType::KeyMask(p4_v2::MatchKeyMask { key, mask })),
    }
}

fn match_exact(key: String) -> Match {
    Match {
        r#type: Some(MatchType::KeyOnly(p4_v2::MatchKeyOnly { key })),
    }
}

fn param(value: String) -> ActionParameter {
    ActionParameter { value }
}

#[derive(Debug, Clone, Copy)]
pub enum EtherType {
    Ipv4 = 0x0800,
    Ipv4Arp = 0x0806,
    Ipv6 = 0x86dd,
}

#[derive(Debug)]
pub struct Layer2InputPacketFilterRule {
    pub match_dest_mac_addr: u64,
    pub set_src_mac_addr: u64,
}

impl From<Layer2InputPacketFilterRule> for TableRule {
    fn from(r: Layer2InputPacketFilterRule) -> Self {
        TableRule {
            table_name: "mac_dst_filter_table".into(),
            matches: vec![
                match_wildcard(hex(0x0), hex(0x0)),
                match_exact(hex(r.match_dest_mac_addr)),
            ],
            action: Some(Action {
                name: "set_mac_sa".into(),
                parameters: vec![param(hex(r.set_src_mac_addr))],
            }),
            priority: 0,
            replace: false,
        }
    }
}

#[derive(Debug)]
pub struct IpDstToLbInstanceRule {
    pub match_ether_type: EtherType,
    pub match_dest_ip_addr: IpAddr,
    pub set_src_ip_addr: IpAddr,
    pub set_lb_instance_id: u8,
}

impl From<IpDstToLbInstanceRule> for TableRule {
    fn from(r: IpDstToLbInstanceRule) -> Self {
        TableRule {
            table_name: "ip_dst_filter_table".into(),
            matches: vec![
                match_wildcard(hex(0x0), hex(0x0)),
                match_exact(hex(r.match_ether_type as u32)),
                match_exact(hexip(r.match_dest_ip_addr)),
            ],
            action: Some(Action {
                name: "set_ip_sa".into(),
                parameters: vec![
                    param(hexip(r.set_src_ip_addr)),
                    param(hex(r.set_lb_instance_id)),
                ],
            }),
            priority: 0,
            replace: false,
        }
    }
}

impl TryFrom<TableRule> for IpDstToLbInstanceRule {
    type Error = Error;

    fn try_from(rule: TableRule) -> Result<Self> {
        if rule.table_name != "ip_dst_filter_table" {
            return Err(Error::NotFound(format!(
                "Expected ip_dst_filter_table, got {}",
                rule.table_name
            )));
        }

        let action = rule
            .action
            .ok_or_else(|| Error::Config("Missing action".into()))?;
        if action.name != "set_ip_sa" || action.parameters.len() < 2 {
            return Err(Error::Config("Invalid action".into()));
        }

        if rule.matches.len() < 3 {
            return Err(Error::Config("Missing match fields".into()));
        }

        let ether_type = parse_hex_u32(get_key_only(rule.matches[1].r#type.as_ref())?)
            .ok_or_else(|| Error::Config("Invalid ether_type".into()))?;

        let dest_ip =
            if ether_type == EtherType::Ipv4 as u32 || ether_type == EtherType::Ipv4Arp as u32 {
                IpAddr::V4(
                    parse_ipv4(get_key_only(rule.matches[2].r#type.as_ref())?)
                        .ok_or_else(|| Error::Config("Invalid IPv4 address".into()))?,
                )
            } else if ether_type == EtherType::Ipv6 as u32 {
                IpAddr::V6(
                    parse_ipv6(get_key_only(rule.matches[2].r#type.as_ref())?)
                        .ok_or_else(|| Error::Config("Invalid IPv6 address".into()))?,
                )
            } else {
                return Err(Error::Config("Invalid ether_type".into()));
            };

        let src_ip = if action.parameters[0].value.len() <= 10 {
            IpAddr::V4(
                parse_ipv4(&action.parameters[0].value)
                    .ok_or_else(|| Error::Config("Invalid IPv4 address".into()))?,
            )
        } else {
            IpAddr::V6(
                parse_ipv6(&action.parameters[0].value)
                    .ok_or_else(|| Error::Config("Invalid IPv6 address".into()))?,
            )
        };
        let lb_id = parse_hex_u8(&action.parameters[1].value)
            .ok_or_else(|| Error::Config("Invalid LB ID".into()))?;

        Ok(IpDstToLbInstanceRule {
            match_ether_type: if ether_type == EtherType::Ipv4 as u32 {
                EtherType::Ipv4
            } else {
                EtherType::Ipv6
            },
            match_dest_ip_addr: dest_ip,
            set_src_ip_addr: src_ip,
            set_lb_instance_id: lb_id,
        })
    }
}

#[derive(Debug)]
pub struct IpSrcFilterRule {
    pub match_lb_instance_id: u8,
    pub match_src_ip_addr: IpAddr,
    pub priority: u32,
}

impl From<IpSrcFilterRule> for TableRule {
    fn from(r: IpSrcFilterRule) -> Self {
        TableRule {
            table_name: match r.match_src_ip_addr {
                IpAddr::V4(_) => "ipv4_src_filter_table",
                IpAddr::V6(_) => "ipv6_src_filter_table",
            }
            .into(),
            matches: vec![
                match_exact(hex(r.match_lb_instance_id)),
                match_exact(hexip(r.match_src_ip_addr)),
            ],
            action: Some(Action {
                name: "allow_ip_src".into(),
                parameters: vec![],
            }),
            priority: r.priority,
            replace: false,
        }
    }
}

impl TryFrom<TableRule> for IpSrcFilterRule {
    type Error = Error;

    fn try_from(rule: TableRule) -> Result<Self> {
        if rule.table_name != "ipv4_src_filter_table" && rule.table_name != "ipv6_src_filter_table"
        {
            return Err(Error::NotFound(format!(
                "Expected ipv4/ipv6_src_filter_table, got {}",
                rule.table_name
            )));
        }

        let action = rule
            .action
            .ok_or_else(|| Error::Config("Missing action".into()))?;
        if action.name != "allow_ip_src" {
            return Err(Error::Config("Invalid action".into()));
        }

        if rule.matches.len() < 2 {
            return Err(Error::Config("Missing match fields".into()));
        }

        let lb_id = parse_hex_u8(get_key_only(rule.matches[0].r#type.as_ref())?)
            .ok_or_else(|| Error::Config("Invalid LB ID".into()))?;

        let src_ip = if rule.table_name == "ipv4_src_filter_table" {
            IpAddr::V4(
                parse_ipv4(get_key_only(rule.matches[1].r#type.as_ref())?)
                    .ok_or_else(|| Error::Config("Invalid IPv4 address".into()))?,
            )
        } else {
            IpAddr::V6(
                parse_ipv6(get_key_only(rule.matches[1].r#type.as_ref())?)
                    .ok_or_else(|| Error::Config("Invalid IPv6 address".into()))?,
            )
        };

        Ok(IpSrcFilterRule {
            match_lb_instance_id: lb_id,
            match_src_ip_addr: src_ip,
            priority: rule.priority,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct EventIdToEpochRule {
    pub match_lb_instance_id: u8,
    pub match_event: u64,
    pub match_event_prefix_len: u32,
    pub set_epoch: u32,
    pub priority: u32,
}

impl From<EventIdToEpochRule> for TableRule {
    fn from(r: EventIdToEpochRule) -> Self {
        TableRule {
            table_name: "epoch_assign_table".into(),
            matches: vec![
                match_exact(hex(r.match_lb_instance_id)),
                match_prefix(hex(r.match_event), r.match_event_prefix_len),
            ],
            action: Some(Action {
                name: "do_assign_epoch".into(),
                parameters: vec![param(hex(r.set_epoch))],
            }),
            priority: r.priority,
            replace: false,
        }
    }
}

impl TryFrom<TableRule> for EventIdToEpochRule {
    type Error = Error;

    fn try_from(rule: TableRule) -> Result<Self> {
        if rule.table_name != "epoch_assign_table" {
            return Err(Error::NotFound(format!(
                "Expected epoch_assign_table, got {}",
                rule.table_name
            )));
        }

        let action = rule
            .action
            .ok_or_else(|| Error::Config("Missing action".into()))?;
        if action.name != "do_assign_epoch" || action.parameters.is_empty() {
            return Err(Error::Config("Invalid action".into()));
        }

        if rule.matches.len() < 2 {
            return Err(Error::Config("Missing match fields".into()));
        }

        let lb_id = parse_hex_u8(get_key_only(rule.matches[0].r#type.as_ref())?)
            .ok_or_else(|| Error::Config("Invalid LB ID".into()))?;

        let (event_key, prefix_len) = get_key_prefix(rule.matches[1].r#type.as_ref())?;
        let event =
            parse_hex_u64(event_key).ok_or_else(|| Error::Config("Invalid event".into()))?;

        let epoch = parse_hex_u32(&action.parameters[0].value)
            .ok_or_else(|| Error::Config("Invalid epoch".into()))?;

        Ok(EventIdToEpochRule {
            match_lb_instance_id: lb_id,
            match_event: event,
            match_event_prefix_len: prefix_len,
            set_epoch: epoch,
            priority: rule.priority,
        })
    }
}

#[derive(Debug)]
pub struct SlotToMemberRule {
    pub match_lb_instance_id: u8,
    pub match_epoch: u32,
    pub match_slot: u16,
    pub set_member_id: u16,
    pub priority: u32,
}

impl From<SlotToMemberRule> for TableRule {
    fn from(r: SlotToMemberRule) -> Self {
        TableRule {
            table_name: "load_balance_calendar_table".into(),
            matches: vec![
                match_exact(hex(r.match_lb_instance_id)),
                match_exact(hex(r.match_epoch)),
                match_exact(hex(r.match_slot)),
            ],
            action: Some(Action {
                name: "do_assign_member".into(),
                parameters: vec![param(hex(r.set_member_id))],
            }),
            priority: r.priority,
            replace: false,
        }
    }
}

impl TryFrom<TableRule> for SlotToMemberRule {
    type Error = Error;

    fn try_from(rule: TableRule) -> Result<Self> {
        if rule.table_name != "load_balance_calendar_table" {
            return Err(Error::NotFound(format!(
                "Expected load_balance_calendar_table, got {}",
                rule.table_name
            )));
        }

        let action = rule
            .action
            .ok_or_else(|| Error::Config("Missing action".into()))?;
        if action.name != "do_assign_member" || action.parameters.is_empty() {
            return Err(Error::Config("Invalid action".into()));
        }

        if rule.matches.len() < 3 {
            return Err(Error::Config("Missing match fields".into()));
        }

        let lb_id = parse_hex_u8(get_key_only(rule.matches[0].r#type.as_ref())?)
            .ok_or_else(|| Error::Config("Invalid LB ID".into()))?;
        let epoch = parse_hex_u32(get_key_only(rule.matches[1].r#type.as_ref())?)
            .ok_or_else(|| Error::Config("Invalid epoch".into()))?;
        let slot = parse_hex_u16(get_key_only(rule.matches[2].r#type.as_ref())?)
            .ok_or_else(|| Error::Config("Invalid slot".into()))?;
        let member_id = parse_hex_u16(&action.parameters[0].value)
            .ok_or_else(|| Error::Config("Invalid member ID".into()))?;

        Ok(SlotToMemberRule {
            match_lb_instance_id: lb_id,
            match_epoch: epoch,
            match_slot: slot,
            set_member_id: member_id,
            priority: rule.priority,
        })
    }
}

#[derive(Debug)]
pub struct MemberInfoRule {
    pub match_lb_instance_id: u8,
    pub match_ether_type: EtherType,
    pub match_member_id: u16,
    pub set_dest_mac_addr: u64,
    pub set_dest_ip_addr: IpAddr,
    pub set_dest_udp_port: u16,
    pub set_entropy_bit_mask_width: u8,
    pub set_keep_lb_header: bool,
    pub priority: u32,
}

impl From<MemberInfoRule> for TableRule {
    fn from(r: MemberInfoRule) -> Self {
        TableRule {
            table_name: "member_info_lookup_table".into(),
            matches: vec![
                match_exact(hex(r.match_lb_instance_id)),
                match_exact(hex(r.match_ether_type as u32)),
                match_exact(hex(r.match_member_id)),
            ],
            action: Some(Action {
                name: match r.set_dest_ip_addr {
                    IpAddr::V4(_) => "do_ipv4_member_rewrite",
                    IpAddr::V6(_) => "do_ipv6_member_rewrite",
                }
                .into(),
                parameters: vec![
                    param(hex(r.set_dest_mac_addr)),
                    param(hexip(r.set_dest_ip_addr)),
                    param(hex(r.set_dest_udp_port)),
                    param(hex(r.set_entropy_bit_mask_width as u16)),
                    param(hex(r.set_keep_lb_header as u8)),
                ],
            }),
            priority: r.priority,
            replace: false,
        }
    }
}

impl TryFrom<TableRule> for MemberInfoRule {
    type Error = Error;

    fn try_from(rule: TableRule) -> Result<Self> {
        if rule.table_name != "member_info_lookup_table" {
            return Err(Error::NotFound(format!(
                "Expected member_info_lookup_table, got {}",
                rule.table_name
            )));
        }

        let action = rule
            .action
            .ok_or_else(|| Error::Config("Missing action".into()))?;
        if (action.name != "do_ipv4_member_rewrite" && action.name != "do_ipv6_member_rewrite")
            || action.parameters.len() < 4
        {
            return Err(Error::Config("Invalid action".into()));
        }

        if rule.matches.len() < 3 {
            return Err(Error::Config("Missing match fields".into()));
        }

        let lb_id = parse_hex_u8(get_key_only(rule.matches[0].r#type.as_ref())?)
            .ok_or_else(|| Error::Config("Invalid LB ID".into()))?;
        let ether_type = parse_hex_u32(get_key_only(rule.matches[1].r#type.as_ref())?)
            .ok_or_else(|| Error::Config("Invalid ether_type".into()))?;
        let member_id = parse_hex_u16(get_key_only(rule.matches[2].r#type.as_ref())?)
            .ok_or_else(|| Error::Config("Invalid member ID".into()))?;

        let mac_addr = parse_hex_u64(&action.parameters[0].value)
            .ok_or_else(|| Error::Config("Invalid MAC address".into()))?;
        let ip_addr = if action.name == "do_ipv4_member_rewrite" {
            IpAddr::V4(
                parse_ipv4(&action.parameters[1].value)
                    .ok_or_else(|| Error::Config("Invalid IPv4 address".into()))?,
            )
        } else {
            IpAddr::V6(
                parse_ipv6(&action.parameters[1].value)
                    .ok_or_else(|| Error::Config("Invalid IPv6 address".into()))?,
            )
        };
        let udp_port = parse_hex_u16(&action.parameters[2].value)
            .ok_or_else(|| Error::Config("Invalid UDP port".into()))?;
        let entropy_bits = parse_hex_u8(&action.parameters[3].value)
            .ok_or_else(|| Error::Config("Invalid entropy bits".into()))?;

        let keep_lb_header = parse_hex_u8(&action.parameters[4].value)
            .ok_or_else(|| Error::Config("Invalid keep_lb_header bits".into()))?
            == 1;

        Ok(MemberInfoRule {
            match_lb_instance_id: lb_id,
            match_ether_type: if ether_type == EtherType::Ipv4 as u32 {
                EtherType::Ipv4
            } else {
                EtherType::Ipv6
            },
            match_member_id: member_id,
            set_dest_mac_addr: mac_addr,
            set_dest_ip_addr: ip_addr,
            set_dest_udp_port: udp_port,
            set_entropy_bit_mask_width: entropy_bits,
            set_keep_lb_header: keep_lb_header,
            priority: rule.priority,
        })
    }
}

fn match_prefix(key: String, prefix_length: u32) -> Match {
    Match {
        r#type: Some(MatchType::KeyPrefix(p4_v2::MatchKeyPrefix {
            key,
            prefix_length,
        })),
    }
}

#[derive(Debug, Clone)]
pub struct TableUpdate {
    pub description: String,
    pub insertions: Vec<TableRule>,
    pub updates: Vec<TableRule>,
    pub deletions: Vec<TableRule>,
}

pub fn matches_to_string(rule: &TableRule) -> String {
    rule.matches
        .iter()
        .map(|m| match &m.r#type {
            Some(MatchType::KeyMask(km)) => format!("{}&&&{}", km.key, km.mask),
            Some(MatchType::KeyOnly(ko)) => ko.key.clone(),
            Some(MatchType::KeyPrefix(kp)) => format!("{}/{}", kp.key, kp.prefix_length),
            Some(MatchType::Range(r)) => format!("{}-{}", r.lower, r.upper),
            Some(MatchType::Unused(u)) => format!("{u}"),
            None => "_".to_string(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

// Helper function to extract key string for comparison
pub fn rule_key(rule: &TableRule) -> String {
    format!("{} {}", rule.table_name, matches_to_string(rule))
}

// Helper function to extract value string for comparison
pub fn rule_value(rule: &TableRule) -> String {
    rule.action
        .as_ref()
        .map(|a| {
            a.parameters
                .iter()
                .map(|p| p.value.clone())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default()
}

impl fmt::Display for TableRule {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(action) = &self.action {
            write!(
                f,
                "{} {} {} => {}",
                self.table_name,
                action.name,
                matches_to_string(self),
                rule_value(self)
            )
        } else {
            write!(f, "{}", rule_key(self),)
        }
    }
}

#[must_use]
pub fn compare_rule_sets(old_rules: &[TableRule], new_rules: &[TableRule]) -> Vec<TableUpdate> {
    let mut updates_by_table: HashMap<String, TableUpdate> = HashMap::new();
    let mut table_order: Vec<String> = Vec::new(); // To maintain the order of tables

    // Index old rules by key for efficient lookup
    let mut old_by_key: HashMap<String, &TableRule> =
        old_rules.iter().map(|r| (rule_key(r), r)).collect();

    // Process new rules
    for new_rule in new_rules {
        let table_name = new_rule.table_name.clone();

        // Record table order
        if !updates_by_table.contains_key(&table_name) {
            table_order.push(table_name.clone());
            updates_by_table.insert(
                table_name.clone(),
                TableUpdate {
                    description: table_name.clone(),
                    insertions: Vec::new(),
                    updates: Vec::new(),
                    deletions: Vec::new(),
                },
            );
        }

        let table_update = updates_by_table.get_mut(&table_name).unwrap();
        let key = rule_key(new_rule);

        if let Some(old_rule) = old_by_key.remove(&key) {
            if rule_value(old_rule) != rule_value(new_rule) {
                table_update.updates.push(new_rule.clone());
            }
        } else {
            table_update.insertions.push(new_rule.clone());
        }
    }

    // Remaining old rules are deletions
    for (_key, old_rule) in old_by_key {
        let table_name = old_rule.table_name.clone();

        // Ensure deletions are also ordered
        if !updates_by_table.contains_key(&table_name) {
            table_order.push(table_name.clone());
            updates_by_table.insert(
                table_name.clone(),
                TableUpdate {
                    description: table_name.clone(),
                    insertions: Vec::new(),
                    updates: Vec::new(),
                    deletions: Vec::new(),
                },
            );
        }

        let table_update = updates_by_table.get_mut(&table_name).unwrap();
        table_update.deletions.push(old_rule.clone());
    }

    // Preserve table order from new_rules
    table_order
        .into_iter()
        .filter_map(|name| updates_by_table.remove(&name))
        .collect()
}

// Helper functions for match field access
fn get_key_only(r#type: Option<&MatchType>) -> Result<&str> {
    match r#type {
        Some(MatchType::KeyOnly(MatchKeyOnly { key })) => Ok(key),
        _ => Err(Error::Config("Expected key-only match".into())),
    }
}

fn get_key_prefix(r#type: Option<&MatchType>) -> Result<(&str, u32)> {
    match r#type {
        Some(MatchType::KeyPrefix(MatchKeyPrefix { key, prefix_length })) => {
            Ok((key, *prefix_length))
        }
        _ => Err(Error::Config("Expected key-prefix match".into())),
    }
}

// Helper functions for parsing hex strings
fn parse_hex_u8(s: &str) -> Option<u8> {
    u8::from_str_radix(&s[2..s.len()], 16).ok()
}

fn parse_hex_u16(s: &str) -> Option<u16> {
    u16::from_str_radix(&s[2..s.len()], 16).ok()
}

fn parse_hex_u32(s: &str) -> Option<u32> {
    u32::from_str_radix(&s[2..s.len()], 16).ok()
}

fn parse_hex_u64(s: &str) -> Option<u64> {
    u64::from_str_radix(&s[2..s.len()], 16).ok()
}

fn parse_hex_u128(s: &str) -> Option<u128> {
    u128::from_str_radix(&s[2..s.len()], 16).ok()
}

fn parse_ipv4(s: &str) -> Option<Ipv4Addr> {
    let n = parse_hex_u32(s)?;
    Some(Ipv4Addr::from(n))
}

fn parse_ipv6(s: &str) -> Option<Ipv6Addr> {
    let n = parse_hex_u128(s)?;
    Some(Ipv6Addr::from(n))
}

#[derive(Debug)]
pub enum RuleType {
    IpDst(IpDstToLbInstanceRule),
    IpSrc(IpSrcFilterRule),
    Epoch(EventIdToEpochRule),
    Slot(SlotToMemberRule),
    MemberInfo(MemberInfoRule),
    Layer2(Layer2InputPacketFilterRule),
}

pub fn parse_rule(rule: &TableRule) -> Result<RuleType> {
    match rule.table_name.as_str() {
        "ip_dst_filter_table" => Ok(RuleType::IpDst(IpDstToLbInstanceRule::try_from(
            rule.clone(),
        )?)),
        "ipv4_src_filter_table" | "ipv6_src_filter_table" => {
            Ok(RuleType::IpSrc(IpSrcFilterRule::try_from(rule.clone())?))
        }
        "epoch_assign_table" => Ok(RuleType::Epoch(EventIdToEpochRule::try_from(rule.clone())?)),
        "load_balance_calendar_table" => {
            Ok(RuleType::Slot(SlotToMemberRule::try_from(rule.clone())?))
        }
        "member_info_lookup_table" => Ok(RuleType::MemberInfo(MemberInfoRule::try_from(
            rule.clone(),
        )?)),
        "mac_dst_filter_table" => Ok(RuleType::Layer2(Layer2InputPacketFilterRule::try_from(
            rule.clone(),
        )?)),
        _ => Err(Error::NotFound(format!(
            "Unknown table: {}",
            rule.table_name
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_sample_rule(
        table: &str,
        key: &str,
        action_name: &str,
        params: Vec<&str>,
    ) -> TableRule {
        TableRule {
            table_name: table.to_string(),
            matches: vec![match_exact(key.to_string())],
            action: Some(Action {
                name: action_name.to_string(),
                parameters: params.into_iter().map(|p| param(p.to_string())).collect(),
            }),
            priority: 0,
            replace: false,
        }
    }

    #[test]
    fn test_empty_rules() {
        let old_rules: Vec<TableRule> = vec![];
        let new_rules: Vec<TableRule> = vec![];

        let result = compare_rule_sets(&old_rules, &new_rules);
        assert!(result.is_empty());
    }

    #[test]
    fn test_only_insertions() {
        let old_rules: Vec<TableRule> = vec![];
        let new_rules = vec![
            create_sample_rule("table1", "key1", "action1", vec!["param1"]),
            create_sample_rule("table1", "key2", "action2", vec!["param2"]),
        ];

        let result = compare_rule_sets(&old_rules, &new_rules);
        assert_eq!(result.len(), 1);

        let table_update = &result[0];
        assert_eq!(table_update.description, "table1");
        assert_eq!(table_update.insertions.len(), 2);
        assert!(table_update.updates.is_empty());
        assert!(table_update.deletions.is_empty());
    }

    #[test]
    fn test_only_deletions() {
        let old_rules = vec![
            create_sample_rule("table1", "key1", "action1", vec!["param1"]),
            create_sample_rule("table1", "key2", "action2", vec!["param2"]),
        ];
        let new_rules: Vec<TableRule> = vec![];

        let result = compare_rule_sets(&old_rules, &new_rules);
        assert_eq!(result.len(), 1);

        let table_update = &result[0];
        assert_eq!(table_update.description, "table1");
        assert!(table_update.insertions.is_empty());
        assert!(table_update.updates.is_empty());
        assert_eq!(table_update.deletions.len(), 2);
    }

    #[test]
    fn test_insertions_and_deletions() {
        let old_rules = vec![create_sample_rule(
            "table1",
            "key1",
            "action1",
            vec!["param1"],
        )];
        let new_rules = vec![create_sample_rule(
            "table1",
            "key2",
            "action2",
            vec!["param2"],
        )];

        let result = compare_rule_sets(&old_rules, &new_rules);
        assert_eq!(result.len(), 1);

        let table_update = &result[0];
        assert_eq!(table_update.description, "table1");
        assert_eq!(table_update.insertions.len(), 1);
        assert_eq!(table_update.deletions.len(), 1);
        assert!(table_update.updates.is_empty());
    }

    #[test]
    fn test_updates() {
        let old_rules = vec![create_sample_rule(
            "table1",
            "key1",
            "action1",
            vec!["param1"],
        )];
        let new_rules = vec![create_sample_rule(
            "table1",
            "key1",
            "action1",
            vec!["param2"],
        )];

        let result = compare_rule_sets(&old_rules, &new_rules);
        assert_eq!(result.len(), 1);

        let table_update = &result[0];
        assert_eq!(table_update.description, "table1");
        assert!(table_update.insertions.is_empty());
        assert!(table_update.deletions.is_empty());
        assert_eq!(table_update.updates.len(), 1);
    }

    #[test]
    fn test_mixed_changes() {
        let old_rules = vec![
            create_sample_rule("table1", "key1", "action1", vec!["param1"]),
            create_sample_rule("table2", "key3", "action3", vec!["param3"]),
        ];
        let new_rules = vec![
            create_sample_rule("table1", "key1", "action1", vec!["param2"]),
            create_sample_rule("table2", "key4", "action4", vec!["param4"]),
        ];

        let result = compare_rule_sets(&old_rules, &new_rules);
        assert_eq!(result.len(), 2);

        let table1_update = &result[0];
        assert_eq!(table1_update.description, "table1");
        assert!(table1_update.insertions.is_empty());
        assert!(table1_update.deletions.is_empty());
        assert_eq!(table1_update.updates.len(), 1);

        let table2_update = &result[1];
        assert_eq!(table2_update.description, "table2");
        assert_eq!(table2_update.insertions.len(), 1);
        assert_eq!(table2_update.deletions.len(), 1);
        assert!(table2_update.updates.is_empty());
    }
}

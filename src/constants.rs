//! Common constants used mostly by the `smartnic` and `dataplane` modules
pub const MAX_LAYER_2_INPUT_PACKET_FILTER_ROW: usize = 64;
pub const MAX_LAYER_3_INPUT_PACKET_FILTER_ROW: usize = 64;
pub const MAX_EPOCH_ASSIGNMENT_ROW: usize = 512;
pub const MAX_MEMBER_MAP_ROW: usize = 8192;
pub const MAX_MEMBER_INFO_ROW: usize = 4096;
pub const MAX_LB_INSTANCES: usize = 4;
pub const CALENDAR_SLOT_BITSIZE: usize = 9;
pub const SLOTS_PER_EPOCH: usize = 512;
pub const MAX_EPOCHS_PER_LB_INSTANCE: usize =
    (MAX_MEMBER_MAP_ROW / MAX_LB_INSTANCES) / SLOTS_PER_EPOCH;

use serde::ser::SerializeStruct;
use std::{fmt, mem::size_of, time::SystemTime};
use zerocopy::{byteorder::*, *};
use zerocopy_derive::*;

pub const IP_HEADER_SIZE: usize = 20;
pub const UDP_HEADER_SIZE: usize = 8;
pub const REASSEMBLY_HEADER_SIZE: usize = size_of::<ReassemblyHeader>();
pub const LB_HEADER_SIZE: usize = size_of::<LBHeader>();
pub const TOTAL_HEADER_SIZE: usize =
    IP_HEADER_SIZE + UDP_HEADER_SIZE + REASSEMBLY_HEADER_SIZE + LB_HEADER_SIZE;

#[derive(Debug)]
pub struct EjfatEvent {
    pub tick: u64,
    pub data_id: u16,
    pub data: Vec<u8>,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
pub struct LBHeader {
    pub magic_l: u8,
    pub magic_b: u8,
    pub version: u8,
    pub protocol: u8,
    _reserved1: U16<NetworkEndian>,
    pub entropy: U16<NetworkEndian>,
    pub tick: U64<NetworkEndian>,
}

/// Custom Serialize implementation for LBHeader.
/// This converts the zerocopy types (U16, U64) to plain integers.
impl serde::Serialize for LBHeader {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("LBHeader", 7)?;
        state.serialize_field("magic_l", &self.magic_l)?;
        state.serialize_field("magic_b", &self.magic_b)?;
        state.serialize_field("version", &self.version)?;
        state.serialize_field("protocol", &self.protocol)?;
        state.serialize_field("_reserved1", &self._reserved1.get())?;
        state.serialize_field("entropy", &self.entropy.get())?;
        state.serialize_field("tick", &self.tick.get())?;
        state.end()
    }
}

impl LBHeader {
    pub fn new() -> Self {
        LBHeader {
            magic_l: b'L',
            magic_b: b'B',
            version: 2,
            protocol: 1,
            _reserved1: U16::new(0),
            entropy: U16::new(0),
            tick: U64::new(0),
        }
    }

    pub fn set_defaults(&mut self) -> &mut Self {
        self.magic_l = b'L';
        self.magic_b = b'B';
        self.version = 2;
        self.protocol = 1;
        self
    }

    pub fn is_valid(&self) -> bool {
        self.magic_l == b'L' && self.magic_b == b'B' && self.version == 2
    }

    pub fn set_tick_to_timestamp(&mut self) -> &mut Self {
        let tick = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        self.tick.set(tick);
        self
    }
}

impl Default for LBHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for LBHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LBHeader\n  version  = {}\n  protocol = {}\n  entropy  = {}\n  tick     = {}",
            self.version,
            self.protocol,
            self.entropy.get(),
            self.tick.get()
        )
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct LBPayload {
    pub header: LBHeader,
    pub body: [u8],
}

impl LBPayload {
    pub fn parse<B: ByteSlice>(bytes: B) -> Option<Ref<B, LBPayload>> {
        Ref::from_bytes(bytes).ok()
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct ReassemblyHeader {
    pub version_and_reserved: u8,
    pub reserved: u8,
    pub data_id: U16<NetworkEndian>,
    pub offset: U32<NetworkEndian>,
    pub length: U32<NetworkEndian>,
    pub tick: U64<NetworkEndian>,
}

impl ReassemblyHeader {
    pub fn new(data_id: u16, offset: u32, length: u32, tick: u64) -> Self {
        ReassemblyHeader {
            version_and_reserved: 1 << 4,
            reserved: 0,
            data_id: U16::new(data_id),
            offset: U32::new(offset),
            length: U32::new(length),
            tick: U64::new(tick),
        }
    }
}

impl fmt::Display for ReassemblyHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ReassemblyHeader\n  data_id = {}\n  offset  = {}\n  length  = {}\n  tick    = {}",
            self.data_id.get(),
            self.offset.get(),
            self.length.get(),
            self.tick.get(),
        )
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct ReassemblyPayload {
    pub header: ReassemblyHeader,
    pub body: [u8],
}

impl ReassemblyPayload {
    pub fn parse<B: ByteSlice>(bytes: B) -> Option<Ref<B, ReassemblyPayload>> {
        Ref::from_bytes(bytes).ok()
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct SyncPayload {
    magic_l: u8,
    magic_c: u8,
    version: u8,
    reserved: u8,
    pub src_id: U32<NetworkEndian>,
    pub tick: U64<NetworkEndian>,
    pub evt_rate: U32<NetworkEndian>,
    pub unix_time_nano: U64<NetworkEndian>,
}

impl SyncPayload {
    pub fn new() -> Self {
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        SyncPayload {
            magic_l: b'L',
            magic_c: b'C',
            version: 2,
            reserved: 0,
            src_id: U32::new(0),
            tick: U64::new(0),
            evt_rate: U32::new(1_000_000_000),
            unix_time_nano: U64::new(ts),
        }
    }

    pub fn set_defaults(&mut self) -> &mut Self {
        self.magic_l = b'L';
        self.magic_c = b'C';
        self.version = 2;
        self
    }

    pub fn set_tick_to_timestamp(&mut self) -> &mut Self {
        let tick = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        self.evt_rate.set(1_000_000_000);
        self.tick.set(tick);
        self.unix_time_nano.set(tick);
        self
    }

    pub fn is_valid(&self) -> bool {
        self.magic_l == b'L' && self.magic_c == b'C' && self.version == 2
    }
}

impl Default for SyncPayload {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for EjfatEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "tick {} data_id {}", self.tick, self.data_id)?;
        for (i, chunk) in self.data.chunks(16).enumerate() {
            let hex_line: Vec<String> = chunk.iter().map(|byte| format!("{:02x}", byte)).collect();
            let utf8_line: String = chunk
                .iter()
                .map(|&byte| if byte.is_ascii() { byte as char } else { '.' })
                .collect();
            writeln!(f, "{:08x} | {} | {}", i * 16, hex_line.join(" "), utf8_line)?;
        }
        Ok(())
    }
}

//! Determines how to set the MAC address for receivers in the member info table. Finds the correct MAC address
//! whether its a local address, on the LAN, or on the WAN using netlink on Linux and `ifconfig` on macOS (for debug only).
#[cfg(target_os = "linux")]
mod linux {
    include!("macaddr/macaddr_linux.rs");
}

#[cfg(target_os = "macos")]
mod macos {
    include!("macaddr/macaddr_macos.rs");
}

// Re-export the appropriate implementation based on target OS
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "macos")]
pub use macos::*;

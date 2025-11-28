mod bsd;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux::{
    EthernetHeader, Ipv4Header, LinuxSocket, LinuxSocketErrors, PacketFrame, TcpFlags, TcpHeader,
    resolve_mac,
};

#[cfg(target_os = "windows")]
mod windows;

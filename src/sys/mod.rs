mod bsd;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{LinuxSocket, LinuxSocketErrors, resolve_mac};

#[cfg(target_os = "windows")]
mod windows;

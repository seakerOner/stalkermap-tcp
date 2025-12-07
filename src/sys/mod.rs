mod bsd;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux::{LinuxSocket, LinuxSocketErrors};

#[cfg(target_os = "windows")]
mod windows;

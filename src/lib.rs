//! # Stalkermap-TCP (WIP)
//!
//! - TCP utilities with custom handshakes for multiple port‑scanning techniques
//! - TCP for working with stalkermap scanner
//!
//! **(no functionality yet, still early in development)**

pub mod sys;
pub use sys::{LinuxSocket, LinuxSocketErrors};

pub mod tcp;

// RFC 9293

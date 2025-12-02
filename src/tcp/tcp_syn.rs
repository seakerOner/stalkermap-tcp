use crate::tcp::internal;
use crate::{LinuxSocket, LinuxSocketErrors};

pub struct TcpSyn {
    linux_socket: LinuxSocket,
}

#[derive(Debug)]
pub enum TcpSynErrors {
    LinuxSocketErr(LinuxSocketErrors),
    Io(std::io::Error),
}

impl TcpSyn {
    pub fn init() -> Result<Self, TcpSynErrors> {
        #[cfg(target_os = "linux")]
        {
            let mut socket = LinuxSocket::new().map_err(|e| TcpSynErrors::LinuxSocketErr(e))?;

            socket
                .set_ops()
                .map_err(|e| TcpSynErrors::LinuxSocketErr(e))?;

            Ok(Self {
                linux_socket: socket,
            })
        }
    }

    /// Don't use this, still work in progress :D
    pub fn connect(&mut self, ip: std::net::Ipv4Addr, port: u16) -> Result<(), TcpSynErrors> {
        #[cfg(target_os = "linux")]
        {
            use crate::sys::resolve_mac;

            let dst_mac = resolve_mac(&self.linux_socket, ip).map_err(|e| TcpSynErrors::Io(e))?;

            let mut packet = internal::PacketFrame::new_tcp(
                &[internal::TcpFlags::SYN],
                ip,
                port,
                dst_mac,
                self.linux_socket.default_gateway.octets(),
                self.linux_socket.src_mac,
            );

            self.linux_socket
                .send_raw_packet(dst_mac, libc::ETH_P_IP as u16, &packet.serialize_raw(&[]))
                .map_err(|e| TcpSynErrors::LinuxSocketErr(e))?;

            Ok(())
        }
    }
}

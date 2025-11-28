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
            use crate::LinuxSocket;

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
    pub fn connect(&mut self, ip: std::net::Ipv4Addr, _port: u16) -> Result<(), TcpSynErrors> {
        #[cfg(target_os = "linux")]
        {
            use crate::sys::resolve_mac;

            let dst_mac = resolve_mac(&self.linux_socket, ip).map_err(|e| TcpSynErrors::Io(e))?;

            //TODO: Build ETHERNET/IPV4/TCP frame
            let packet = [0u8; 5];

            self.linux_socket
                .send_raw_packet(dst_mac, libc::ETH_P_IP as u16, &packet)
                .map_err(|e| TcpSynErrors::LinuxSocketErr(e))?;

            Ok(())
        }
    }
}

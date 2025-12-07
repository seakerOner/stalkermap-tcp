use std::sync::Arc;

use tokio::sync::mpsc::Sender;

use crate::tcp::TcpFamily;
use crate::tcp::internal::reactor::{DispatchedFrame, Dispatcher, PacketReactorMode};
use crate::tcp::internal::{self, TcpConnection, reactor::PacketReactor};
use crate::{LinuxSocket, LinuxSocketErrors};

pub struct TcpSyn {
    linux_socket: Arc<LinuxSocket>,
    sender_for_dispacher: Sender<DispatchedFrame>,
}

#[derive(Debug)]
pub enum TcpSynErrors {
    LinuxSocketErr(LinuxSocketErrors),
    Io(std::io::Error),
}

impl TcpSyn {
    pub fn init(reactor_mode: PacketReactorMode) -> Result<(Self, PacketReactor), TcpSynErrors> {
        #[cfg(target_os = "linux")]
        {
            let mut socket = LinuxSocket::new().map_err(|e| TcpSynErrors::LinuxSocketErr(e))?;

            let (mmap, ptr_length) = socket
                .set_ops()
                .map_err(|e| TcpSynErrors::LinuxSocketErr(e))?;

            let mut reactor = PacketReactor::new(socket.fd, (mmap, ptr_length), reactor_mode)
                .map_err(|e| TcpSynErrors::Io(e))?;

            Ok((
                Self {
                    linux_socket: Arc::new(socket),
                    sender_for_dispacher: reactor.get_raw_dispatcher(),
                },
                reactor,
            ))
        }

        #[cfg(target_os = "windows")]
        {
            todo!("Implementation on Windows OS is not yet completed");
        }
    }

    /// Don't use this, still work in progress :D
    pub fn try_connect(
        &self,
        ip: std::net::Ipv4Addr,
        port: u16,
    ) -> Result<TcpConnection, TcpSynErrors> {
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
                .send_raw_packet(dst_mac, libc::ETH_P_IP as u16, &packet.serialize(&[]))
                .map_err(|e| TcpSynErrors::LinuxSocketErr(e))?;

            Ok(TcpConnection::new(
                packet,
                TcpFamily::TcpSyn,
                Dispatcher {
                    inner: self.sender_for_dispacher.clone(),
                },
            ))
        }

        #[cfg(target_os = "windows")]
        {
            todo!("Implementation on Windows OS is not yet completed");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn tcp_syn_send_packet_test() {
        let (tcp, _reactor) = TcpSyn::init(PacketReactorMode::default()).unwrap();
        // run this on a asynchronous task (e.g: Tokio Task or equivalent) or on a seperate thread
        //reactor.run();

        let r = tcp.try_connect(Ipv4Addr::new(127, 0, 0, 1), 8080);
        assert!(r.is_ok());

        // HACK:
        // let x = r.unwrap().connection_status().await;
    }
}

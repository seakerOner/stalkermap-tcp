// High‑level summary for Linux raw networking:
//
// 1. AF_PACKET is used to create a raw socket bound to an interface.
//    - The same AF_PACKET socket fd is used for sendto() of raw frames.
//    - It is protocol‑agnostic: you serialize your own TCP/IP headers.
//
// 2. TPACKET_V3 is enabled on this AF_PACKET socket to receive packets efficiently.
//    - The kernel writes packets into this shared ring area (zero‑copy).
//    - User space polls/reads frames directly from the mmap'd ring.
//
// 3. All TCP logic (flags, seq/ack, retransmission, state machine, matching responses)
//    is implemented entirely in user space; the kernel does not manage TCP state here.
//
// In short: AF_PACKET for raw TX, TPACKET_V3 for zero‑copy RX, TCP state is all ours. :D

use libc::{AF_PACKET, ETH_P_ALL, SOCK_RAW, htons, sockaddr_ll, socket};
use std::mem;

use std::os::fd::RawFd;

// open packet socket to send raw packets at the device driver (OSI Layer 2) level.
fn open_af_packet() -> RawFd {
    unsafe {
        let fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL as u16) as i32);

        if fd < 0 {
            panic!("AF_PACKET sys call failed");
        }

        fd
    }
}

fn bind_interface(fd: RawFd, if_index: i32) {
    unsafe {
        let mut addr: sockaddr_ll = mem::zeroed();
        addr.sll_family = AF_PACKET as u16;
        addr.sll_protocol = htons(ETH_P_ALL as u16);
        addr.sll_ifindex = if_index;

        let ret = libc::bind(
            fd,
            &addr as *const sockaddr_ll as *const libc::sockaddr,
            mem::size_of::<sockaddr_ll>() as u32,
        );

        if ret < 0 {
            panic!("AF_PACKET sys call bind failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_af_packet_test() {
        let if_index = 2;

        let fd = open_af_packet();
        bind_interface(fd, if_index);

        let mut buf = [0u8; u16::MAX as usize];
        unsafe {
            let n = libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0);
            assert!(n > 0);
        }
    }
}

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

use libc::{
    AF_PACKET, ETH_P_ALL, SOCK_RAW, htons, if_nametoindex, setsockopt, sockaddr_ll, socket,
};
use std::ffi::c_void;
use std::fs;
use std::io::{self, BufRead};
use std::mem;
use std::os::fd::RawFd;

const TPACKET_V3: libc::c_int = 2;

// open packet socket to send raw packets at the device driver (OSI Layer 2) level.
fn open_af_packet() -> RawFd {
    unsafe {
        let fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL as u16) as i32);

        if fd < 0 {
            let err = *libc::__errno_location();
            if err == libc::EPERM || err == libc::EACCES {
                panic!(
                    "AF_PACKET sys call failed;\n Error number: {}; No permissions \n \n Error: CAP_NET_RAW or root privileges required to use raw AF_PACKET sockets.\n - Run with: sudo <cmd>\n - Or give the binary capability: sudo setcap cap_net_raw+ep <binary>\n
                    ",
                    err
                );
            } else {
                panic!("AF_PACKET sys call failed; Error number: {}", err);
            }
        }

        fd
    }
}

fn get_default_ifindex() -> io::Result<i32> {
    let file = fs::File::open("/proc/net/route")?;
    let reader = io::BufReader::new(file);

    for line in reader.lines().skip(1) {
        let line = line?;
        let cols: Vec<&str> = line.split_whitespace().collect();

        if cols.len() < 2 {
            continue;
        }

        let iface = cols[0];
        let destination = cols[1];

        if destination == "00000000" {
            let c_name = std::ffi::CString::new(iface).unwrap();
            let index = unsafe { if_nametoindex(c_name.as_ptr()) };

            if index == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("if_nametoindex failed for {}", iface),
                ));
            }
            return Ok(index as i32);
        }
    }

    let fallback = unsafe { if_nametoindex(std::ffi::CString::new("lo").unwrap().as_ptr()) };

    if fallback != 0 {
        return Ok(fallback as i32);
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "No usable route found",
    ))
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

fn set_sock_opt(fd: RawFd) -> *mut c_void {
    let version = TPACKET_V3;

    let r = unsafe {
        setsockopt(
            fd,
            libc::SOL_PACKET,
            libc::PACKET_VERSION,
            &version as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    assert!(r == 0, "Failed to set PACKET_VERSION TPACKET_V3");

    let req = libc::tpacket_req3 {
        tp_block_size: 1 << 20, // 1MB blocks
        tp_block_nr: 64,
        tp_frame_size: 2048,
        tp_frame_nr: (64 * (1 << 20)) / 2048,
        tp_retire_blk_tov: 60, // timeout
        tp_sizeof_priv: 0,
        tp_feature_req_word: 0,
    };

    let ret = unsafe {
        setsockopt(
            fd,
            libc::SOL_PACKET,
            libc::PACKET_RX_RING,
            &req as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::tpacket_req3>() as libc::socklen_t,
        )
    };

    assert!(ret == 0, "Failed to set PACKET_RX_RING");

    let mmap_len = (req.tp_block_size * req.tp_block_nr) as usize;

    unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            mmap_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    }
}

fn close_socket(fd: RawFd) {
    unsafe { libc::close(fd) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_af_packet_test() {
        let if_index = get_default_ifindex();

        assert!(if_index.is_ok());

        let fd = open_af_packet();

        bind_interface(fd, if_index.unwrap());

        let mut buf = [0u8; u16::MAX as usize];
        unsafe {
            let n = libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0);
            assert!(n > 0);
        }
    }

    #[test]
    fn linux_af_packet_test_with_ring_buffer() {
        let if_index = get_default_ifindex();

        assert!(if_index.is_ok());

        let fd = open_af_packet();

        bind_interface(fd, if_index.unwrap());

        let mmap_ptr = set_sock_opt(fd);

        assert!(!mmap_ptr.is_null(), "mmap returned null pointer");
        close_socket(fd);
    }
}

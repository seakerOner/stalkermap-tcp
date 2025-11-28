// High‑level summary for Linux raw networking:
//
// 1. AF_PACKET is used to create a raw socket bound to an interface.
//    - The same AF_PACKET socket fd is used for sendto() of raw frames.
//    - It is protocol‑agnostic: you serialize your own TCP/IP headers.
//
// 2. TPACKET_V3 is enabled on this AF_PACKET socket to receive packets efficiently.
//    - The kernel writes packets into this shared ring area (zero copy).
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
use std::net::Ipv4Addr;
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

fn lookup_arp_cache(ip: Ipv4Addr) -> io::Result<Option<[u8; 6]>> {
    let file = fs::File::open("proc/net/arp")?;
    let reader = io::BufReader::new(file);

    for line in reader.lines().skip(1) {
        let line = line?;
        let cols: Vec<&str> = line.split_whitespace().collect();

        if cols.len() < 6 {
            continue;
        }

        let ip_addr = cols[0];
        if ip_addr != ip.to_string() {
            continue;
        }

        let hw_addr = cols[3];
        if hw_addr == "00:00:00:00:00:00" {
            return Ok(None);
        }

        let bytes: Vec<u8> = hw_addr
            .split(':')
            .filter_map(|s| u8::from_str_radix(s, 16).ok())
            .collect();

        if bytes.len() != 6 {
            continue;
        }

        let mut mac = [0u8; 6];
        mac.copy_from_slice(&bytes);
        return Ok(Some(mac));
    }
    Ok(None)
}

pub fn resolve_mac(socket: &LinuxSocket, dst_ip: Ipv4Addr) -> io::Result<[u8; 6]> {
    if let Some(mac) = lookup_arp_cache(dst_ip)? {
        return Ok(mac);
    }

    if let Some(mac) = lookup_arp_cache(socket.default_gateway)? {
        return Ok(mac);
    }

    // Gateway MAC missing... Needs ARP request (not implemented yet)
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "MAC address not found in ARP for dst or gateway",
    ))
}

fn get_default_ifindex_and_default_gateway() -> io::Result<(i32, Ipv4Addr)> {
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
        let gateway_hex = cols[2];

        if destination == "00000000" {
            let c_name = std::ffi::CString::new(iface).unwrap();
            let index = unsafe { if_nametoindex(c_name.as_ptr()) };

            if index == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("if_nametoindex failed for {}", iface),
                ));
            }

            let g = u32::from_str_radix(gateway_hex, 16).unwrap();

            return Ok((index as i32, Ipv4Addr::from(g.swap_bytes())));
        }
    }

    let fallback = unsafe { if_nametoindex(std::ffi::CString::new("lo").unwrap().as_ptr()) };

    if fallback != 0 {
        return Ok((fallback as i32, Ipv4Addr::new(127, 0, 0, 1)));
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

fn set_sock_opt(fd: RawFd) -> Result<(*mut c_void, usize), SetSockOpsErrors> {
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

    if r != 0 {
        return Err(SetSockOpsErrors::PacketVersion(
            "Failed to set PACKET_VERSION TPACKET_V3".to_string(),
        ));
    }

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

    if ret != 0 {
        return Err(SetSockOpsErrors::RingBuffer(
            "Failed to set PACKET_RX_RING".to_string(),
        ));
    }

    let mmap_len = (req.tp_block_size * req.tp_block_nr) as usize;

    let mmap = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            mmap_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };

    if mmap.is_null() {
        return Err(SetSockOpsErrors::Mmap(
            "Failed set mmap on ring buffer".to_string(),
        ));
    }

    Ok((mmap, mmap_len))
}

#[derive(Debug)]
pub enum SetSockOpsErrors {
    PacketVersion(String),
    RingBuffer(String),
    Mmap(String),
}

#[derive(Debug)]
pub struct LinuxSocket {
    pub fd: RawFd,
    pub ifindex: i32,
    pub default_gateway: Ipv4Addr,
    pub mmap: Option<(*mut c_void, usize)>,
}

impl LinuxSocket {
    pub fn new() -> Result<Self, LinuxSocketErrors> {
        let (ifindex, default_gateway) = get_default_ifindex_and_default_gateway()
            .map_err(|e| LinuxSocketErrors::DefaultIfIndex(e))?;

        let fd = open_af_packet();
        bind_interface(fd, ifindex);

        Ok(LinuxSocket {
            fd,
            default_gateway,
            ifindex,
            mmap: None,
        })
    }

    pub fn set_ops(&mut self) -> Result<(), LinuxSocketErrors> {
        let (mmap, ptr_len) =
            set_sock_opt(self.fd).map_err(|e| LinuxSocketErrors::SetSockOps(e))?;

        self.mmap.replace((mmap, ptr_len));
        Ok(())
    }

    pub fn send_raw_packet(
        &self,
        dst_mac: [u8; 6],
        ether_type: u16,
        packet: &[u8],
    ) -> Result<(), LinuxSocketErrors> {
        unsafe {
            let mut addr: sockaddr_ll = mem::zeroed();
            addr.sll_family = AF_PACKET as u16;
            addr.sll_ifindex = self.ifindex;
            addr.sll_protocol = htons(ether_type);
            addr.sll_halen = 6;
            addr.sll_addr[..6].copy_from_slice(&dst_mac);

            let sent = libc::sendto(
                self.fd,
                packet.as_ptr() as *const _ as *const c_void,
                packet.len(),
                0,
                &addr as *const sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<sockaddr_ll>() as u32,
            );

            if sent == -1 {
                return Err(LinuxSocketErrors::SendingPacket(io::Error::last_os_error()));
            }
            Ok(())
        }
    }
}

impl Drop for LinuxSocket {
    fn drop(&mut self) {
        if let Some((mmap, ptr_len)) = self.mmap.take() {
            let res = unsafe { libc::munmap(mmap, ptr_len) };
            if res != 0 {
                eprintln!("Failed to remove any mappings from the adress space");
            }
        }

        unsafe { libc::close(self.fd) };
    }
}

#[derive(Debug)]
pub enum LinuxSocketErrors {
    DefaultIfIndex(std::io::Error),
    SetSockOps(SetSockOpsErrors),
    SendingPacket(std::io::Error),
}

pub struct PacketFrame {
    pub ethernet_header: EthernetHeader,
    pub ipv4_header: Ipv4Header,
    pub tcp_header: TcpHeader,
}

impl PacketFrame {
    pub fn new(
        ethernet_header: EthernetHeader,
        ipv4_header: Ipv4Header,
        tcp_header: TcpHeader,
    ) -> Self {
        PacketFrame {
            ethernet_header,
            ipv4_header,
            tcp_header,
        }
    }

    pub fn serialize(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1500);

        self.ethernet_header.serialize(&mut buf);

        {
            let ip_header = &mut self.ipv4_header;
            ip_header.total_length = (20 + 20 + payload.len() as u16).to_be();

            let mut tmp = Vec::new();
            ip_header.serialize(&mut tmp);
            ip_header.header_checksum = checksum(&tmp);

            ip_header.serialize(&mut buf);
        }

        {
            let tcp_header = &mut self.tcp_header;

            let mut tmp = Vec::new();
            tcp_header.serialize(&mut tmp);

            let mut pseudo = Vec::new();
            pseudo.extend_from_slice(&self.ipv4_header.src_ip);
            pseudo.extend_from_slice(&self.ipv4_header.dst_ip);
            pseudo.push(0);
            pseudo.push(6); // TCP
            let tcp_len = (tmp.len() + payload.len()) as u16;
            pseudo.extend_from_slice(&tcp_len.to_be_bytes());
            pseudo.extend_from_slice(&tmp);
            pseudo.extend_from_slice(payload);

            tcp_header.checksum = checksum(&pseudo);

            tcp_header.serialize(&mut buf);
        }
        self.tcp_header.serialize(&mut buf);

        buf.extend_from_slice(payload);

        buf
    }
}

pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6], //6bytes
    pub ethertype: u16,   //2bytes
}

impl EthernetHeader {
    pub fn new(dst_mac: [u8; 6], src_mac: [u8; 6], ethertype: u16) -> Self {
        EthernetHeader {
            dst_mac,
            src_mac,
            ethertype: ethertype.to_be(),
        }
    }

    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.dst_mac);
        buf.extend_from_slice(&self.src_mac);
        buf.extend_from_slice(&self.ethertype.to_be_bytes());
    }
}

// https://www.rfc-editor.org/rfc/rfc791#section-3.1
pub struct Ipv4Header {
    pub version_ihl: u8,     // version << 4 | internet header length
    pub type_of_service: u8, // DSCP << 2 | ECN
    pub total_length: u16,
    pub identification: u16,
    pub flags_and_fragment: u16, // flags << 13 | fragment_offset
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
}

impl Ipv4Header {
    pub fn new(src_ip: [u8; 4], dst_ip: [u8; 4], payload_len: usize) -> Self {
        let ihl: u8 = 5;
        let version: u8 = 4;
        let version_ihl = (version << 4) | ihl;

        let total_length = (20 + payload_len) as u16;

        Ipv4Header {
            version_ihl,
            type_of_service: 0,
            total_length: total_length.to_be(),
            identification: 0,     // change this
            flags_and_fragment: 0, // DF=0 MF=0 offset=0
            ttl: 64,
            protocol: 6,        // TCP
            header_checksum: 0, // calculated later
            src_ip,
            dst_ip,
        }
    }

    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.push(self.version_ihl);
        buf.push(self.type_of_service);
        buf.extend_from_slice(&self.total_length.to_be_bytes());
        buf.extend_from_slice(&self.identification.to_be_bytes());
        buf.extend_from_slice(&self.flags_and_fragment.to_be_bytes());
        buf.push(self.ttl);
        buf.push(self.protocol);
        buf.extend_from_slice(&self.header_checksum.to_be_bytes());
        buf.extend_from_slice(&self.src_ip);
        buf.extend_from_slice(&self.dst_ip);
    }
}

pub struct TcpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub seq_number: u32,
    pub ack_number: u32,
    pub data_offset_reserved_flags: u16, // data_offset << 12 | flags
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

impl TcpHeader {
    pub fn new(
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: TcpFlags,
        window_size: u16,
    ) -> Self {
        let data_offset: u16 = 5;

        let data_offset_reserved_flags = (data_offset << 12) | (flags as u16 & 0x0FFF);

        TcpHeader {
            source_port: src_port.to_be(),
            destination_port: dst_port.to_be(),
            seq_number: seq.to_be(),
            ack_number: ack.to_be(),
            data_offset_reserved_flags: data_offset_reserved_flags.to_be(),
            window_size: window_size.to_be(),
            checksum: 0,
            urgent_ptr: 0,
        }
    }

    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.source_port.to_be_bytes());
        buf.extend_from_slice(&self.destination_port.to_be_bytes());
        buf.extend_from_slice(&self.seq_number.to_be_bytes());
        buf.extend_from_slice(&self.ack_number.to_be_bytes());
        buf.extend_from_slice(&self.data_offset_reserved_flags.to_be_bytes());
        buf.extend_from_slice(&self.window_size.to_be_bytes());
        buf.extend_from_slice(&self.checksum.to_be_bytes());
        buf.extend_from_slice(&self.urgent_ptr.to_be_bytes());
    }
}

pub enum TcpFlags {
    FIN = 0x01,
    SYN = 0x02,
    RST = 0x04,
    PSH = 0x08,
    ACK = 0x10,
    URG = 0x20,
    ECE = 0x40,
    CWR = 0x80,
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;

    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }

    if let Some(&rem) = chunks.remainder().first() {
        sum += (rem as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn linux_af_packet_test() {
        let (if_index, _default_gateway) = get_default_ifindex_and_default_gateway().unwrap();

        let fd = open_af_packet();

        bind_interface(fd, if_index);

        let mut buf = [0u8; u16::MAX as usize];
        unsafe {
            let n = libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0);
            assert!(n > 0);
        }
    }

    #[test]
    fn linux_af_packet_test_with_ring_buffer() {
        let (if_index, _default_gateway) = get_default_ifindex_and_default_gateway().unwrap();

        let fd = open_af_packet();

        bind_interface(fd, if_index);

        let mmap_ptr = set_sock_opt(fd);

        assert!(mmap_ptr.is_ok());

        let (mmap, len) = mmap_ptr.unwrap();

        let res = unsafe { libc::munmap(mmap, len) };

        assert!(res == 0);
    }

    #[test]
    fn linux_socket_test() {
        let socket = LinuxSocket::new();

        assert!(socket.is_ok());

        let mut s = socket.unwrap();

        let res = s.set_ops();

        assert!(res.is_ok());
    }
}

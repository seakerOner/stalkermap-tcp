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

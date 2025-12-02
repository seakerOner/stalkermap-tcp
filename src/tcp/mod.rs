pub mod internal;
//use internal::{EthernetHeader, Ipv4Header, PacketFrame, TcpFlags, TcpHeader};

pub mod tcp_syn;

// # SYN Scan (Half-open scan)
//
// Send(SYN) -> if Open   -> SYN/ACK -> Send(RST)
//             -> if Closed -> Send(RST)
//
// # Full TCP handshake (normal handshake, probably will not be implemented, for that there is more
// robust options)
//
// Send(SYN) -> SYN/ACK -> Send(ACK)
//
// # FIN Scan
//
// Send(FIN) -> if Open   -> Stays silent
//             -> if Closed -> Send(RST)
//
// # Xmas Scan
//
// Send(FIN + PSH + URG) -> if Open   -> Stays silent
//                       -> if Closed -> Send(RST)
//
// # Null Scan
//
// Send(no_flags) -> if Open   -> Stays silent
//                -> if Closed -> Send(RST)
//
// # ACK Scan
//
// Send(ACK) -> if unfiltered -> RST
//           -> if filtered   -> Stays silent or filtered ICMP (?)
//
// # Maimon Scan (?)

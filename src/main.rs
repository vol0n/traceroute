use socket2::{Socket, SockAddr, Domain, Type, Protocol};
use std::net::{Ipv4Addr, SocketAddrV4, IpAddr, SocketAddr};
use std::{error::Error, fmt, time::{Duration, Instant}, mem::MaybeUninit};
use dns_lookup::{getaddrinfo, getnameinfo, AddrInfo, LookupError};
use byteorder::{ByteOrder, NetworkEndian, BigEndian};
use uapi::c::NI_NAMEREQD;
use clap::Parser;


#[derive(Debug)]
pub enum TracerError {
    BadAddress,
    ParseError,
    Internal(String),
}

impl fmt::Display for TracerError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let error = match self {
            TracerError::BadAddress => "Could not convert to IP address",
            TracerError::ParseError => "Could not parse the incoming packet",
            TracerError::Internal(s) => s
        };
        write!(fmt, "{}", error)
    }
}

impl Error for TracerError {}

#[derive(Clone)]
pub enum Icmpv4Message {
    EchoReply {
        id: u16,
        seq_num: u16,
        data: Vec<u8>,
    },
    EchoMessage {
        id: u16,
        seq_num: u16,
        data: Vec<u8>,
    },
    TimeLimitExceeded {
        raw_ip_header: Vec<u8>,
        original_8b: [u8; 8],
    },
}

#[derive(Clone)]
pub struct Icmpv4Packet {
    icmp_type: u8,
    code: u8,
    checksum: u16,
    message: Icmpv4Message,
}

impl TryInto<Vec<u8>> for Icmpv4Packet {
    type Error = TracerError;
    fn try_into(self) -> Result<Vec<u8>, TracerError> {
        let mut bytes: Vec<u8> = vec![self.icmp_type, self.code];
        let mut buf = vec![2; 2];
        NetworkEndian::write_u16(&mut buf, self.checksum);
        bytes.append(&mut buf.clone());
        match self.message {
            Icmpv4Message::EchoMessage { id, seq_num, mut data } => {
                NetworkEndian::write_u16(&mut buf, id);
                bytes.append(&mut buf.clone());
                NetworkEndian::write_u16(&mut buf, seq_num);
                bytes.append(&mut buf);
                bytes.append(&mut data);

                Ok(bytes)
            }
            _ => {
                return Err(TracerError::Internal("".to_string()));
            }
        }
    }
}

impl TryFrom<&[u8]> for Icmpv4Packet {
    type Error = TracerError;
    fn try_from(b: &[u8]) -> Result<Self, TracerError> {
        let get_ihl = |b: &[u8]| -> usize {
            ((b[0] & 0x0f) * 4).into()
        };

        let ihl: usize = get_ihl(b);

        // skip ip header
        let bytes = &b[ihl..];
        let (icmp_type, code, checksum) = (bytes[0], bytes[1], NetworkEndian::read_u16(&bytes[2..4]));
        let p = match icmp_type {
            11 => {
                let inner_ihl = get_ihl(&bytes[8..]);
                let tl_ip_bytes = bytes[8..inner_ihl].to_vec();
                let original_8b: [u8; 8] = bytes[inner_ihl..(inner_ihl + 8)].try_into().unwrap();
                Icmpv4Message::TimeLimitExceeded {
                    raw_ip_header: tl_ip_bytes,
                    original_8b,
                }
            }
            0 => {
                Icmpv4Message::EchoReply {
                    id: NetworkEndian::read_u16(&bytes[4..6]),
                    seq_num: NetworkEndian::read_u16(&bytes[6..8]),
                    data: bytes[8..].to_vec(),
                }
            }
            _ => return Err(TracerError::ParseError)
        };
        Ok(Icmpv4Packet {
            icmp_type,
            code,
            checksum,
            message: p,
        })
    }
}

fn sum_bytes(bs: &[u8]) -> u32 {
    if bs.len() == 0 {
        return 0;
    }

    let len = bs.len();
    let mut data = &bs[..];
    let mut sum = 0u32;
    while data.len() >= 2 {
        sum += NetworkEndian::read_u16(&data[0..2]) as u32;
        data = &data[2..];
    }

    if (len % 2) != 0 {
        sum += (data[0] as u32) << 8;
    }
    return sum;
}

pub fn calc_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;

    sum += sum_bytes(&bytes);

    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    !sum as u16
}

pub fn gethostname(addr: SocketAddr) -> Option<String> {
    if let Ok((name, _)) = getnameinfo(&addr, NI_NAMEREQD) {
        return Some(name)
    }
    None
}

pub fn trace(dest: &str, max_hops: u8, timeout: u64) -> Result<(), TracerError> {
    // setup socket
    let raw_socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).unwrap();
    let dest_ip = if let Some(addrinfo) = getaddrinfo(Some(dest), None, None).unwrap().nth(0) {
        addrinfo.unwrap()
    } else {
        return Err(TracerError::BadAddress);
    };
    if let Some(host) = gethostname(dest_ip.sockaddr) {
        println!("trace route to {} ({})", dest_ip.sockaddr.ip(), host);
    } else {
        println!("trace route to {}", dest_ip.sockaddr.ip());
    }
    raw_socket.bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0).into()).unwrap();
    raw_socket.set_read_timeout(Some(Duration::from_secs(timeout))).unwrap();

    // icmp echo message
    let mut ping = Icmpv4Packet {
        icmp_type: 8,
        code: 0,
        checksum: 0,
        message: Icmpv4Message::EchoMessage {
            id: 42,
            seq_num: 0,
            data: vec![],
        },
    };

    let mut buf: [u8; 500] = [0; 500];
    let mut gates: Vec<Ipv4Addr> = vec![];

    for hops in 1..max_hops {
        let p_count = 3;
        let mut last_sender_sock_addr: String = "0.0.0.0".to_string();
        print!("{} ", hops);
        let mut reached_dest = false;
        for _ in 0..p_count {
            ping.checksum = 0;
            if let Icmpv4Message::EchoMessage { seq_num: mut seq_num, .. } = ping.message {
                seq_num = seq_num + 1;
            }
            let checksum = calc_checksum(&TryInto::<Vec<u8>>::try_into(ping.clone()).unwrap());
            ping.checksum = checksum;

            raw_socket.set_ttl(hops.try_into().unwrap()).unwrap();
            let sent_time = Instant::now();
            let b: Vec<u8> = ping.clone().try_into().unwrap();
            raw_socket.send_to(&b, &dest_ip.sockaddr.into()).unwrap();

            let resp = raw_socket.recv_from(unsafe { &mut *(&mut buf as *mut [u8] as *mut [MaybeUninit<u8>]) });
            let elapsed = Instant::now() - sent_time;

            match resp {
                Ok((read_count, addr)) => {
                    let icmp_packet: Icmpv4Packet = buf[0..read_count].try_into().unwrap();
                    let addr_ipv4 = *addr.as_socket_ipv4().unwrap().ip();
                    match icmp_packet.message {
                        Icmpv4Message::EchoReply { .. } => {
                            reached_dest = true;
                        }
                        Icmpv4Message::TimeLimitExceeded { .. } => {
                        }
                        _ => { continue }
                    }
                    let ip_str = addr.as_socket_ipv4().unwrap().ip().to_string();
                    if ip_str != last_sender_sock_addr {
                        if let Some(host) = gethostname(addr.as_socket().unwrap())  {
                            print!("{} ({}) ", addr_ipv4, host);
                        } else {
                            print!("{} ", addr_ipv4);
                        }
                    }
                    last_sender_sock_addr = ip_str;
                    print!("{:.3?} ", elapsed);
                }
                Err(e) => {
                    print!("* ");
                }
            }
        }
        if reached_dest {
            break;
        }
        println!();
    }

    Ok(())
}

#[derive(Parser)]
struct Cli {
    ip: String,
    max_ttl: u8,
    timeout: u64,
}

fn main() {
    let cli_args = Cli::parse();
    trace(&cli_args.ip, cli_args.max_ttl, cli_args.timeout).unwrap();
}

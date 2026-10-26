//! The adapter's wire formats: encapsulation frames, the common packet format, CIP requests, replies and paths,
//! the Forward Open and Forward Close requests, and class 1 I/O frames. Pure functions, no I/O.

use std::net::{Ipv4Addr, SocketAddrV4};

/// A connection triad: connection serial, originator vendor, originator serial.
pub(crate) type Triad = (u16, u16, u32);

/// Size of an encapsulation header.
pub(crate) const HEADER: usize = 24;

/// Common packet format item types.
pub(crate) const NULL_ADDRESS: u16 = 0x0000;
pub(crate) const CONNECTED_ADDRESS: u16 = 0x00A1;
pub(crate) const CONNECTED_DATA: u16 = 0x00B1;
pub(crate) const UNCONNECTED_DATA: u16 = 0x00B2;
pub(crate) const SOCKADDR_T_O: u16 = 0x8001;
pub(crate) const SEQUENCED_ADDRESS: u16 = 0x8002;

pub(crate) fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    data.get(at..at.checked_add(2)?)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

pub(crate) fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    data.get(at..at.checked_add(4)?)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// An encapsulation frame: header (command, length, session, status, context, options) and data.
pub(crate) fn encap(
    command: u16,
    session: u32,
    status: u32,
    context: &[u8],
    data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + data.len());
    out.extend(command.to_le_bytes());
    out.extend((data.len() as u16).to_le_bytes());
    out.extend(session.to_le_bytes());
    out.extend(status.to_le_bytes());
    out.extend(context);
    out.extend(0u32.to_le_bytes());
    out.extend(data);
    out
}

/// The items of a common packet format starting at `at` with its item count; None unless they fill the rest of
/// `data` exactly.
pub(crate) fn items(data: &[u8], at: usize) -> Option<Vec<(u16, &[u8])>> {
    let count = usize::from(u16_at(data, at)?);
    let mut pos = at + 2;
    let mut items = Vec::with_capacity(count.min(8));
    for _ in 0..count {
        let kind = u16_at(data, pos)?;
        let size = usize::from(u16_at(data, pos + 2)?);
        items.push((kind, data.get(pos + 4..pos + 4 + size)?));
        pos += 4 + size;
    }
    (pos == data.len()).then_some(items)
}

/// The items of SendRRData / SendUnitData data (interface handle and timeout first).
pub(crate) fn cpf_items(data: &[u8]) -> Option<Vec<(u16, &[u8])>> {
    items(data, 6)
}

/// Item count and items.
pub(crate) fn encode_items(items: &[(u16, &[u8])]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + items.iter().map(|(_, d)| 4 + d.len()).sum::<usize>());
    out.extend((items.len() as u16).to_le_bytes());
    for (kind, data) in items {
        out.extend(kind.to_le_bytes());
        out.extend((data.len() as u16).to_le_bytes());
        out.extend(*data);
    }
    out
}

/// SendRRData / SendUnitData data: interface handle 0, timeout 0, then the items.
pub(crate) fn cpf(items: &[(u16, &[u8])]) -> Vec<u8> {
    let mut out = vec![0u8; 6];
    out.extend(encode_items(items));
    out
}

/// A CIP reply: reply service, reserved, general status, extended status size and words, then data.
pub(crate) fn reply(service: u8, general: u8, extended: &[u16], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 2 * extended.len() + data.len());
    out.extend([service | 0x80, 0, general, extended.len() as u8]);
    for word in extended {
        out.extend(word.to_le_bytes());
    }
    out.extend(data);
    out
}

/// One segment of a padded EPATH.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Seg {
    Port { port: u16, link: Vec<u8> },
    Class(u32),
    Instance(u32),
    Point(u32),
    Attribute(u32),
    Key(Key),
    Data(Vec<u8>),
}

/// An electronic key segment (format 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Key {
    pub vendor: u16,
    pub device_type: u16,
    pub product_code: u16,
    /// Major revision with the compatibility bit (0x80).
    pub major: u8,
    pub minor: u8,
}

/// Parses a padded EPATH; None for a segment it does not know or a short path.
pub(crate) fn parse_path(path: &[u8]) -> Option<Vec<Seg>> {
    let mut segs = Vec::new();
    let mut at = 0;
    while at < path.len() {
        let first = path[at];
        // logical segments: 8-bit value, 16-bit value after a pad byte, 32-bit value after a pad byte
        let logical = |at: usize| -> Option<(u32, usize)> {
            match first & 0x03 {
                0 => Some((u32::from(*path.get(at + 1)?), 2)),
                1 => Some((u32::from(u16_at(path, at + 2)?), 4)),
                2 => Some((u32_at(path, at + 2)?, 6)),
                _ => None,
            }
        };
        let (seg, size) = match first {
            0x00..=0x1F => {
                let extended = first & 0x10 != 0;
                let mut pos = at + 1;
                let link_size = if extended {
                    pos += 1;
                    usize::from(*path.get(at + 1)?)
                } else {
                    1
                };
                let port = if first & 0x0F == 0x0F {
                    pos += 2;
                    u16_at(path, pos - 2)?
                } else {
                    u16::from(first & 0x0F)
                };
                let link = path.get(pos..pos + link_size)?.to_vec();
                let size = (pos + link_size - at).next_multiple_of(2);
                (Seg::Port { port, link }, size)
            }
            0x20..=0x22 => logical(at).map(|(v, s)| (Seg::Class(v), s))?,
            0x24..=0x26 => logical(at).map(|(v, s)| (Seg::Instance(v), s))?,
            0x2C..=0x2E => logical(at).map(|(v, s)| (Seg::Point(v), s))?,
            0x30..=0x32 => logical(at).map(|(v, s)| (Seg::Attribute(v), s))?,
            0x34 => {
                if path.get(at + 1) != Some(&0x04) {
                    return None;
                }
                let key = Key {
                    vendor: u16_at(path, at + 2)?,
                    device_type: u16_at(path, at + 4)?,
                    product_code: u16_at(path, at + 6)?,
                    major: *path.get(at + 8)?,
                    minor: *path.get(at + 9)?,
                };
                (Seg::Key(key), 10)
            }
            0x80 => {
                let words = usize::from(*path.get(at + 1)?);
                (
                    Seg::Data(path.get(at + 2..at + 2 + 2 * words)?.to_vec()),
                    2 + 2 * words,
                )
            }
            _ => return None,
        };
        segs.push(seg);
        at += size;
    }
    (at == path.len()).then_some(segs)
}

/// A CIP request's path and request data.
#[derive(Debug)]
pub(crate) struct Request<'a> {
    pub path: Vec<Seg>,
    pub data: &'a [u8],
}

/// Parses a CIP request; None if its path is short or unknown.
pub(crate) fn parse_request(message: &[u8]) -> Option<Request<'_>> {
    let words = usize::from(*message.get(1)?);
    let path = message.get(2..2 + 2 * words)?;
    Some(Request {
        path: parse_path(path)?,
        data: &message[2 + 2 * words..],
    })
}

/// The class and instance a request path names (an instance-less path names instance 0, the class).
pub(crate) fn class_instance(path: &[Seg]) -> Option<(u32, u32)> {
    match path {
        [Seg::Class(c), Seg::Instance(i), ..] => Some((*c, *i)),
        [Seg::Class(c)] | [Seg::Class(c), Seg::Attribute(_)] => Some((*c, 0)),
        _ => None,
    }
}

/// The attribute a request path names.
pub(crate) fn attribute(path: &[Seg]) -> Option<u32> {
    path.iter().find_map(|s| match s {
        Seg::Attribute(a) => Some(*a),
        _ => None,
    })
}

/// How a connection is carried in one direction (network connection parameters, bits 13-14 or 29-30).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NetType {
    Null,
    Multicast,
    PointToPoint,
    Reserved,
}

/// The network connection parameters of one direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NetParams {
    /// Connection size in bytes (sequence count and run/idle header included).
    pub size: usize,
    pub net: NetType,
    pub variable: bool,
}

impl NetParams {
    fn decode(value: u32, large: bool) -> Self {
        let (size, variable, net) = if large {
            (value & 0xFFFF, value >> 25 & 1, value >> 29 & 3)
        } else {
            (value & 0x01FF, value >> 9 & 1, value >> 13 & 3)
        };
        NetParams {
            size: size as usize,
            variable: variable == 1,
            net: match net {
                0 => NetType::Null,
                1 => NetType::Multicast,
                2 => NetType::PointToPoint,
                _ => NetType::Reserved,
            },
        }
    }
}

/// A Forward Open or Large Forward Open request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ForwardOpen {
    pub o_t_id: u32,
    pub t_o_id: u32,
    pub serial: u16,
    pub vendor: u16,
    pub originator_serial: u32,
    /// Connection timeout multiplier code: the timeout is the O->T RPI times 4 << code.
    pub multiplier: u8,
    /// Requested packet intervals in microseconds.
    pub o_t_rpi: u32,
    pub o_t: NetParams,
    pub t_o_rpi: u32,
    pub t_o: NetParams,
    /// Transport class and trigger: bit 7 direction, bits 4-6 trigger, bits 0-3 class.
    pub transport: u8,
    pub path: Vec<u8>,
}

impl ForwardOpen {
    /// Decodes the request data (after the Connection Manager path).
    pub(crate) fn decode(data: &[u8], large: bool) -> Option<Self> {
        let params = if large { 4 } else { 2 };
        let read_params = |at: usize| {
            if large {
                u32_at(data, at)
            } else {
                u16_at(data, at).map(u32::from)
            }
        };
        let t_o_at = 26 + params;
        let path_at = t_o_at + 4 + params + 1; // after the transport class and trigger
        let words = usize::from(*data.get(path_at)?);
        Some(ForwardOpen {
            o_t_id: u32_at(data, 2)?,
            t_o_id: u32_at(data, 6)?,
            serial: u16_at(data, 10)?,
            vendor: u16_at(data, 12)?,
            originator_serial: u32_at(data, 14)?,
            multiplier: *data.get(18)?,
            o_t_rpi: u32_at(data, 22)?,
            o_t: NetParams::decode(read_params(26)?, large),
            t_o_rpi: u32_at(data, t_o_at)?,
            t_o: NetParams::decode(read_params(t_o_at + 4)?, large),
            transport: *data.get(path_at - 1)?,
            path: data.get(path_at + 1..path_at + 1 + 2 * words)?.to_vec(),
        })
    }

    /// The connection timeout: the O->T RPI times the multiplier.
    pub(crate) fn timeout_us(&self) -> u64 {
        u64::from(self.o_t_rpi) * (4u64 << self.multiplier.min(7))
    }

    /// The reply data of a successful open.
    pub(crate) fn reply(&self, o_t_id: u32, t_o_id: u32, o_t_api: u32, t_o_api: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(26);
        out.extend(o_t_id.to_le_bytes());
        out.extend(t_o_id.to_le_bytes());
        out.extend(self.triad_bytes());
        out.extend(o_t_api.to_le_bytes());
        out.extend(t_o_api.to_le_bytes());
        out.extend([0, 0]); // application reply size, reserved
        out
    }

    /// The reply data of a refused open: the connection triad, remaining path size and a reserved byte.
    pub(crate) fn refusal(&self) -> Vec<u8> {
        let mut out = self.triad_bytes();
        out.extend([0, 0]);
        out
    }

    fn triad_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(10);
        out.extend(self.serial.to_le_bytes());
        out.extend(self.vendor.to_le_bytes());
        out.extend(self.originator_serial.to_le_bytes());
        out
    }

    /// The connection triad: connection serial, originator vendor, originator serial.
    pub(crate) fn triad(&self) -> Triad {
        (self.serial, self.vendor, self.originator_serial)
    }
}

/// A Forward Close request: the connection triad and the connection path.
pub(crate) fn decode_forward_close(data: &[u8]) -> Option<(Triad, &[u8])> {
    let triad = (u16_at(data, 2)?, u16_at(data, 4)?, u32_at(data, 6)?);
    let words = usize::from(*data.get(10)?);
    Some((triad, data.get(12..12 + 2 * words)?))
}

/// The reply data of a Forward Close.
pub(crate) fn forward_close_reply((serial, vendor, originator_serial): Triad) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    out.extend(serial.to_le_bytes());
    out.extend(vendor.to_le_bytes());
    out.extend(originator_serial.to_le_bytes());
    out.extend([0, 0]);
    out
}

/// A socket address item: family, port and address big-endian, 8 zero bytes.
pub(crate) fn sockaddr(addr: SocketAddrV4) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..2].copy_from_slice(&2u16.to_be_bytes());
    out[2..4].copy_from_slice(&addr.port().to_be_bytes());
    out[4..8].copy_from_slice(&addr.ip().octets());
    out
}

/// Decodes a socket address item.
pub(crate) fn decode_sockaddr(data: &[u8]) -> Option<SocketAddrV4> {
    if data.len() != 16 || data[..2] != [0, 2] {
        return None;
    }
    let port = u16::from_be_bytes([data[2], data[3]]);
    Some(SocketAddrV4::new(
        Ipv4Addr::new(data[4], data[5], data[6], data[7]),
        port,
    ))
}

/// A class 1 I/O frame: the sequenced address item and the connected data item, whose data starts with the
/// 16-bit CIP sequence count.
pub(crate) fn encode_io(connection: u32, sequence: u32, cip_sequence: u16, data: &[u8]) -> Vec<u8> {
    let mut address = [0u8; 8];
    address[..4].copy_from_slice(&connection.to_le_bytes());
    address[4..].copy_from_slice(&sequence.to_le_bytes());
    let mut payload = Vec::with_capacity(2 + data.len());
    payload.extend(cip_sequence.to_le_bytes());
    payload.extend(data);
    encode_items(&[(SEQUENCED_ADDRESS, &address), (CONNECTED_DATA, &payload)])
}

/// A decoded class 1 I/O frame.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct IoFrame<'a> {
    pub connection: u32,
    pub sequence: u32,
    /// The connected data item: 16-bit CIP sequence count, then the data.
    pub payload: &'a [u8],
}

/// Decodes a class 1 I/O frame; None for anything else.
pub(crate) fn decode_io(frame: &[u8]) -> Option<IoFrame<'_>> {
    match items(frame, 0)?.as_slice() {
        [(SEQUENCED_ADDRESS, address), (CONNECTED_DATA, payload), ..] if address.len() == 8 => {
            Some(IoFrame {
                connection: u32_at(address, 0)?,
                sequence: u32_at(address, 4)?,
                payload,
            })
        }
        _ => None,
    }
}

/// The multicast address CIP allocates to a device (CIP Vol 2, 3-5.3): 239.192.1.0 plus 32 addresses for each
/// host ID, wrapping after 1024 hosts.
pub(crate) fn multicast_address(ip: Ipv4Addr, mask: Ipv4Addr) -> Ipv4Addr {
    let host = u32::from(ip) & !u32::from(mask);
    let index = host.wrapping_sub(1) & 0x3FF;
    Ipv4Addr::from(u32::from(Ipv4Addr::new(239, 192, 1, 0)) + index * 32)
}

/// A short string: length byte and ASCII bytes, cut at 255.
pub(crate) fn short_string(text: &str) -> Vec<u8> {
    let bytes = &text.as_bytes()[..text.len().min(255)];
    let mut out = Vec::with_capacity(1 + bytes.len());
    out.push(bytes.len() as u8);
    out.extend(bytes);
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A Forward Open as a Logix controller sends it for a Generic Ethernet Module: exclusive owner, 20 ms,
    /// output assembly 150 (32 bytes, run/idle header), input assembly 100 (256 bytes, multicast), config
    /// instance 151 of size 0.
    pub(crate) fn logix_forward_open() -> Vec<u8> {
        let mut data = vec![0x0A, 0x0E]; // priority/tick, timeout ticks
        data.extend(0x1234_0001u32.to_le_bytes()); // O->T id (the target chooses)
        data.extend(0x2234_0002u32.to_le_bytes()); // T->O id
        data.extend(0x0042u16.to_le_bytes()); // connection serial
        data.extend(0x0001u16.to_le_bytes()); // originator vendor
        data.extend(0x00C0_FFEEu32.to_le_bytes()); // originator serial
        data.extend([2, 0, 0, 0]); // timeout multiplier x16, reserved
        data.extend(20_000u32.to_le_bytes());
        data.extend((0x4800u16 | 38).to_le_bytes()); // point-to-point, scheduled priority, fixed, 32 + 4 + 2
        data.extend(20_000u32.to_le_bytes());
        data.extend((0x2800u16 | 258).to_le_bytes()); // multicast, 256 + 2
        data.push(0x01); // class 1, cyclic, client
        let path = [0x20, 0x04, 0x24, 0x97, 0x2C, 0x96, 0x2C, 0x64];
        data.push((path.len() / 2) as u8);
        data.extend(path);
        data
    }

    #[test]
    fn forward_open_decodes_a_logix_generic_module_request() {
        let fo = ForwardOpen::decode(&logix_forward_open(), false).expect("decode");
        assert_eq!(fo.triad(), (0x42, 1, 0x00C0_FFEE));
        assert_eq!((fo.o_t_rpi, fo.t_o_rpi), (20_000, 20_000));
        assert_eq!(
            fo.o_t,
            NetParams {
                size: 38,
                net: NetType::PointToPoint,
                variable: false
            }
        );
        assert_eq!(
            (fo.t_o.size, fo.t_o.net, fo.t_o.variable),
            (258, NetType::Multicast, false)
        );
        assert_eq!(fo.timeout_us(), 20_000 * 16);
        assert_eq!(fo.transport, 1);
        assert_eq!(
            parse_path(&fo.path).expect("path"),
            [
                Seg::Class(4),
                Seg::Instance(0x97),
                Seg::Point(0x96),
                Seg::Point(0x64)
            ]
        );
    }

    #[test]
    fn large_forward_open_reads_32_bit_parameters() {
        let mut data = vec![0x0A, 0x0E];
        data.extend([0u8; 16]);
        data.extend([0, 0, 0, 0]);
        data.extend(1000u32.to_le_bytes());
        data.extend((0x4000_0000u32 | 0x0200_0000 | 4000).to_le_bytes()); // p2p, variable, 4000
        data.extend(2000u32.to_le_bytes());
        data.extend((0x2000_0000u32 | 600).to_le_bytes()); // multicast, 600
        data.push(0x01);
        data.extend([1, 0x20, 0x04]);
        let fo = ForwardOpen::decode(&data, true).expect("decode");
        assert_eq!(
            fo.o_t,
            NetParams {
                size: 4000,
                net: NetType::PointToPoint,
                variable: true
            }
        );
        assert_eq!((fo.t_o.size, fo.t_o.net), (600, NetType::Multicast));
        assert_eq!(fo.path, [0x20, 0x04]);
    }

    #[test]
    fn short_forward_opens_do_not_decode() {
        let data = logix_forward_open();
        for len in 0..data.len() {
            assert_eq!(ForwardOpen::decode(&data[..len], false), None, "{len}");
        }
    }

    #[test]
    fn paths_parse_keys_data_ports_and_wide_logical_segments() {
        let path = [
            0x34, 0x04, 0x01, 0x00, 0x2B, 0x00, 0x05, 0x00, 0x81, 0x02, // key, compatible 1.2
            0x20, 0x04, 0x25, 0x00, 0x2C, 0x01, // class 4, instance 300
            0x80, 0x01, 0xAA, 0xBB, // two bytes of data
        ];
        assert_eq!(
            parse_path(&path).expect("path"),
            [
                Seg::Key(Key {
                    vendor: 1,
                    device_type: 0x2B,
                    product_code: 5,
                    major: 0x81,
                    minor: 2
                }),
                Seg::Class(4),
                Seg::Instance(300),
                Seg::Data(vec![0xAA, 0xBB]),
            ]
        );
        let mut ip = vec![0x12, 9];
        ip.extend(b"192.0.2.1\0"); // an odd-length link address is padded
        ip.extend([0x01, 0x03]);
        assert_eq!(
            parse_path(&ip).expect("path"),
            [
                Seg::Port {
                    port: 2,
                    link: b"192.0.2.1".to_vec()
                },
                Seg::Port {
                    port: 1,
                    link: vec![3]
                }
            ]
        );
        assert_eq!(parse_path(&[0x20]), None);
        assert_eq!(parse_path(&[0x91, 0x01, b'a', 0]), None);
    }

    #[test]
    fn io_frames_roundtrip() {
        let frame = encode_io(0x1122_3344, 7, 3, &[1, 2, 3]);
        assert_eq!(
            frame,
            [
                2, 0, 0x02, 0x80, 8, 0, 0x44, 0x33, 0x22, 0x11, 7, 0, 0, 0, 0xB1, 0, 5, 0, 3, 0, 1,
                2, 3
            ]
        );
        assert_eq!(
            decode_io(&frame),
            Some(IoFrame {
                connection: 0x1122_3344,
                sequence: 7,
                payload: &[3, 0, 1, 2, 3]
            })
        );
        assert_eq!(decode_io(&frame[..frame.len() - 1]), None);
        assert_eq!(decode_io(&[]), None);
    }

    #[test]
    fn sockaddrs_are_big_endian() {
        let addr = SocketAddrV4::new(Ipv4Addr::new(239, 192, 1, 32), 2222);
        let item = sockaddr(addr);
        assert_eq!(item[..8], [0, 2, 0x08, 0xAE, 239, 192, 1, 32]);
        assert_eq!(decode_sockaddr(&item), Some(addr));
        assert_eq!(decode_sockaddr(&item[..15]), None);
    }

    #[test]
    fn multicast_addresses_follow_the_cip_allocation() {
        let mask = Ipv4Addr::new(255, 255, 255, 0);
        let addr = |ip: [u8; 4]| multicast_address(Ipv4Addr::from(ip), mask);
        assert_eq!(addr([192, 168, 1, 1]), Ipv4Addr::new(239, 192, 1, 0));
        assert_eq!(addr([192, 168, 1, 10]), Ipv4Addr::new(239, 192, 2, 32));
        let wide = Ipv4Addr::new(255, 255, 0, 0);
        assert_eq!(
            multicast_address(Ipv4Addr::new(10, 0, 4, 1), wide),
            Ipv4Addr::new(239, 192, 1, 0)
        ); // host 1025 wraps to host 1
    }
}

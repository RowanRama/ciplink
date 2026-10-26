//! The objects explicit messages reach: Identity, Message Router, Assembly, Port, TCP/IP Interface, Ethernet
//! Link, File (the EDS) and the ciplink object.

use super::state::State;
use super::wire::{self, Seg, reply, short_string};
use super::{AssemblyKind, CIPLINK_OBJECT, CIPLINK_SIGNATURE, ConnectionKind};
use std::net::Ipv4Addr;

const GET_ATTRIBUTES_ALL: u8 = 0x01;
const GET_ATTRIBUTE_SINGLE: u8 = 0x0E;
const INITIATE_UPLOAD: u8 = 0x4B;
const UPLOAD_TRANSFER: u8 = 0x4F;

/// The File object instance of the EDS and icon.
const EDS_INSTANCE: u32 = 0xC8;
/// The most bytes of one upload transfer: a reply has to fit an unconnected message.
const MAX_TRANSFER: usize = 240;
/// Connections the ciplink object lists at most, to fit an unconnected reply.
const MAX_LISTED: usize = 16;

/// General status codes.
const NOT_SUPPORTED: u8 = 0x08;
const ATTRIBUTE_NOT_SUPPORTED: u8 = 0x14;
const PATH_UNKNOWN: u8 = 0x05;
const NO_OBJECT: u8 = 0x16;
const STATE_CONFLICT: u8 = 0x0C;
const NOT_ENOUGH_DATA: u8 = 0x13;

/// What a TCP session knows when it answers: the local address it is connected to and its subnet mask, and an
/// EDS upload under way.
#[derive(Debug)]
pub(crate) struct Ctx {
    pub local: Ipv4Addr,
    pub mask: Ipv4Addr,
    upload: Option<Upload>,
}

impl Ctx {
    pub(crate) fn new(local: Ipv4Addr, mask: Ipv4Addr) -> Self {
        Ctx {
            local,
            mask,
            upload: None,
        }
    }
}

/// An EDS upload: the transfer size, the next transfer number and the offset of the next transfer, and the last
/// transfer (its number and offset) so that a retry gets it again.
#[derive(Debug)]
struct Upload {
    size: usize,
    next: u8,
    offset: usize,
    last: Option<(u8, usize)>,
}

/// Answers an explicit message to the adapter's own objects.
pub(crate) fn message(state: &mut State, ctx: &mut Ctx, message: &[u8]) -> Vec<u8> {
    let service = message.first().copied().unwrap_or(0);
    let Some(request) = wire::parse_request(message) else {
        return reply(service, 0x04, &[], &[]); // path segment error
    };
    let Some((class, instance)) = wire::class_instance(&request.path) else {
        return reply(service, PATH_UNKNOWN, &[], &[]);
    };
    let attribute = wire::attribute(&request.path);
    let result = match class {
        0x01 => identity(state, service, instance, attribute),
        0x04 => assembly(state, service, instance, attribute),
        0xF4 => port(ctx, service, instance, attribute),
        0xF5 => tcp_ip(ctx, service, instance, attribute),
        0xF6 => ethernet_link(state, service, instance, attribute),
        0x37 if state.config.eds.is_some() => {
            file(state, ctx, service, instance, attribute, request.data)
        }
        c if c == u32::from(CIPLINK_OBJECT) => ciplink(state, service, instance),
        0x02 => Err(NOT_SUPPORTED),
        _ => Err(PATH_UNKNOWN),
    };
    match result {
        Ok(data) => reply(service, 0, &[], &data),
        Err(general) => reply(service, general, &[], &[]),
    }
}

/// Answers Get_Attribute_Single from `get` (None: attribute not supported), anything else not supported.
fn single(
    service: u8,
    attribute: Option<u32>,
    get: impl FnOnce(u32) -> Option<Vec<u8>>,
) -> Result<Vec<u8>, u8> {
    match (service, attribute) {
        (GET_ATTRIBUTE_SINGLE, Some(a)) => get(a).ok_or(ATTRIBUTE_NOT_SUPPORTED),
        (GET_ATTRIBUTE_SINGLE, None) => Err(NOT_ENOUGH_DATA),
        _ => Err(NOT_SUPPORTED),
    }
}

/// Class attributes every object answers: revision 1, one instance.
fn class_attribute(attribute: u32) -> Option<Vec<u8>> {
    match attribute {
        1..=3 => Some(1u16.to_le_bytes().to_vec()),
        _ => None,
    }
}

fn identity_all(state: &State) -> Vec<u8> {
    let id = &state.config.identity;
    let mut out = Vec::with_capacity(16 + id.product_name.len());
    out.extend(id.vendor_id.to_le_bytes());
    out.extend(id.device_type.to_le_bytes());
    out.extend(id.product_code.to_le_bytes());
    out.extend([id.revision.0, id.revision.1]);
    out.extend(state.identity_status().to_le_bytes());
    out.extend(id.serial.to_le_bytes());
    out.extend(short_string(&id.product_name));
    out
}

/// The ListIdentity reply data: item count, then the CIP identity item (0x0C) with the address `ip:port`.
pub(crate) fn list_identity(state: &State, ip: Ipv4Addr, port: u16) -> Vec<u8> {
    let mut item = Vec::with_capacity(64);
    item.extend(1u16.to_le_bytes()); // encapsulation protocol version
    item.extend(wire::sockaddr(std::net::SocketAddrV4::new(ip, port)));
    item.extend(identity_all(state));
    item.push(3); // state: operational
    wire::encode_items(&[(0x0C, &item)])
}

fn identity(
    state: &State,
    service: u8,
    instance: u32,
    attribute: Option<u32>,
) -> Result<Vec<u8>, u8> {
    match instance {
        0 => single(service, attribute, class_attribute),
        1 if service == GET_ATTRIBUTES_ALL => Ok(identity_all(state)),
        1 => {
            let id = &state.config.identity;
            single(service, attribute, |a| {
                Some(match a {
                    1 => id.vendor_id.to_le_bytes().to_vec(),
                    2 => id.device_type.to_le_bytes().to_vec(),
                    3 => id.product_code.to_le_bytes().to_vec(),
                    4 => vec![id.revision.0, id.revision.1],
                    5 => state.identity_status().to_le_bytes().to_vec(),
                    6 => id.serial.to_le_bytes().to_vec(),
                    7 => short_string(&id.product_name),
                    8 => vec![3],
                    _ => return None,
                })
            })
        }
        _ => Err(NO_OBJECT),
    }
}

fn assembly(
    state: &State,
    service: u8,
    instance: u32,
    attribute: Option<u32>,
) -> Result<Vec<u8>, u8> {
    if instance == 0 {
        return single(service, attribute, |a| match a {
            1 => Some(2u16.to_le_bytes().to_vec()),
            2 => {
                let max = state
                    .assemblies
                    .iter()
                    .map(|a| a.instance)
                    .max()
                    .unwrap_or(0);
                Some((max as u16).to_le_bytes().to_vec())
            }
            _ => None,
        });
    }
    let a = state.assembly(instance).ok_or(NO_OBJECT)?;
    single(service, attribute, |attr| match attr {
        3 => Some(a.data.clone()),
        4 => Some((a.data.len() as u16).to_le_bytes().to_vec()),
        _ => None,
    })
}

/// One EtherNet/IP port, number 2 like an Allen-Bradley device's, its link the Ethernet Link object.
fn port(ctx: &Ctx, service: u8, instance: u32, attribute: Option<u32>) -> Result<Vec<u8>, u8> {
    match instance {
        0 => single(service, attribute, class_attribute),
        1 => single(service, attribute, |a| match a {
            1 => Some(4u16.to_le_bytes().to_vec()), // EtherNet/IP
            2 => Some(2u16.to_le_bytes().to_vec()),
            3 => Some(vec![0x02, 0x00, 0x20, 0xF6, 0x24, 0x01]),
            4 => Some(short_string("A")),
            7 => {
                let ip = ctx.local.to_string();
                let mut segment = vec![0x12, ip.len() as u8];
                segment.extend(ip.as_bytes());
                segment.resize(segment.len().next_multiple_of(2), 0);
                Some(segment)
            }
            _ => None,
        }),
        _ => Err(NO_OBJECT),
    }
}

fn tcp_ip(ctx: &Ctx, service: u8, instance: u32, attribute: Option<u32>) -> Result<Vec<u8>, u8> {
    match instance {
        0 => single(service, attribute, class_attribute),
        1 => single(service, attribute, |a| match a {
            1 => Some(1u32.to_le_bytes().to_vec()), // a valid configuration
            2 | 3 => Some(0u32.to_le_bytes().to_vec()), // set by the operating system, not by CIP
            4 => Some(vec![0x02, 0x00, 0x20, 0xF6, 0x24, 0x01]),
            5 => {
                let mut data = [u32::from(ctx.local), u32::from(ctx.mask), 0, 0, 0]
                    .map(u32::to_le_bytes)
                    .concat();
                data.extend([0, 0]); // no domain name
                Some(data)
            }
            6 => Some(vec![0, 0]), // no host name
            _ => None,
        }),
        _ => Err(NO_OBJECT),
    }
}

fn ethernet_link(
    state: &State,
    service: u8,
    instance: u32,
    attribute: Option<u32>,
) -> Result<Vec<u8>, u8> {
    match instance {
        0 => single(service, attribute, class_attribute),
        1 => single(service, attribute, |a| match a {
            1 => Some(100u32.to_le_bytes().to_vec()),  // Mbit/s
            2 => Some(0x0Fu32.to_le_bytes().to_vec()), // link up, full duplex, negotiated
            3 => Some(state.config.mac.to_vec()),
            _ => None,
        }),
        _ => Err(NO_OBJECT),
    }
}

/// A STRINGI of one English ISO 8859-1 short string.
fn stringi(text: &str) -> Vec<u8> {
    let mut out = vec![1];
    out.extend(b"eng");
    out.push(0xDA);
    out.extend(4u16.to_le_bytes());
    out.extend(short_string(text));
    out
}

/// The file checksum: the two's complement of the 16-bit sum of the file's bytes.
fn checksum(file: &[u8]) -> u16 {
    0u16.wrapping_sub(
        file.iter()
            .fold(0u16, |sum, b| sum.wrapping_add(u16::from(*b))),
    )
}

fn file(
    state: &State,
    ctx: &mut Ctx,
    service: u8,
    instance: u32,
    attribute: Option<u32>,
    data: &[u8],
) -> Result<Vec<u8>, u8> {
    let eds = state.config.eds.as_deref().unwrap_or_default();
    match instance {
        0 => return single(service, attribute, class_attribute),
        EDS_INSTANCE => {}
        _ => return Err(NO_OBJECT),
    }
    match service {
        INITIATE_UPLOAD => {
            let wanted = usize::from(*data.first().ok_or(NOT_ENOUGH_DATA)?);
            let size = wanted.clamp(1, MAX_TRANSFER);
            ctx.upload = Some(Upload {
                size,
                next: 0,
                offset: 0,
                last: None,
            });
            let mut out = (eds.len() as u32).to_le_bytes().to_vec();
            out.push(size as u8);
            Ok(out)
        }
        UPLOAD_TRANSFER => {
            let number = *data.first().ok_or(NOT_ENOUGH_DATA)?;
            let upload = ctx.upload.as_mut().ok_or(STATE_CONFLICT)?;
            let offset = match upload.last {
                Some((last, offset)) if last == number => offset, // a retry
                _ if number == upload.next => {
                    let offset = upload.offset;
                    upload.last = Some((number, offset));
                    upload.next = number.wrapping_add(1);
                    upload.offset = (offset + upload.size).min(eds.len());
                    offset
                }
                _ => return Err(STATE_CONFLICT), // transfer out of sequence
            };
            let end = (offset + upload.size).min(eds.len());
            let (first, last) = (offset == 0, end == eds.len());
            let packet_type = match (first, last) {
                (true, true) => 4,
                (true, false) => 0,
                (false, false) => 1,
                (false, true) => 2,
            };
            let mut out = vec![number, packet_type];
            out.extend(&eds[offset..end]);
            if last {
                out.extend(checksum(eds).to_le_bytes());
            }
            Ok(out)
        }
        _ => single(service, attribute, |a| match a {
            1 => Some(vec![2]), // file loaded
            2 => Some(stringi("EDS and Icon Files")),
            3 => Some(1u16.to_le_bytes().to_vec()),
            4 => Some(stringi(&state.config.eds_name)),
            5 => {
                let (major, minor) = state.config.identity.revision;
                Some(vec![major, minor])
            }
            6 => Some((eds.len() as u32).to_le_bytes().to_vec()),
            7 => Some(checksum(eds).to_le_bytes().to_vec()),
            8 | 9 => Some(vec![0]),
            10 => Some(vec![1]), // read only
            11 => Some(vec![0]), // binary
            _ => None,
        }),
    }
}

/// The ciplink object's Get_Attributes_All: the signature, the ciplink version, the application's name,
/// version and status text, its assemblies and its connections.
fn ciplink(state: &State, service: u8, instance: u32) -> Result<Vec<u8>, u8> {
    if instance != 1 {
        return Err(NO_OBJECT);
    }
    if service != GET_ATTRIBUTES_ALL {
        return Err(NOT_SUPPORTED);
    }
    let mut out = short_string(CIPLINK_SIGNATURE);
    out.extend(short_string(env!("CARGO_PKG_VERSION")));
    out.extend(short_string(&state.config.app_name));
    out.extend(short_string(&state.config.app_version));
    out.extend(short_string(&state.detail));
    out.push(state.assemblies.len().min(255) as u8);
    for a in state.assemblies.iter().take(255) {
        out.extend((a.instance as u16).to_le_bytes());
        out.push(match a.kind {
            AssemblyKind::Input => 1,
            AssemblyKind::Output => 2,
            AssemblyKind::Config => 3,
        });
        out.extend((a.data.len() as u16).to_le_bytes());
    }
    let listed = state.conns.len().min(MAX_LISTED);
    out.push(listed as u8);
    for c in state.conns.iter().take(listed) {
        out.push(match c.kind {
            ConnectionKind::ExclusiveOwner => 1,
            ConnectionKind::InputOnly => 2,
            ConnectionKind::ListenOnly => 3,
        });
        out.extend(c.originator.octets());
        out.extend((c.o_t_rpi.as_micros() as u32).to_le_bytes());
        out.extend((c.t_o_rpi.as_micros() as u32).to_le_bytes());
        out.push(u8::from(c.multicast));
        out.extend((c.input as u16).to_le_bytes());
        out.extend((c.output.unwrap_or(0) as u16).to_le_bytes());
    }
    Ok(out)
}

/// Whether a request path names the Connection Manager.
pub(crate) fn is_connection_manager(path: &[Seg]) -> bool {
    wire::class_instance(path) == Some((0x06, 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::{AdapterConfig, AdapterIdentity, Assembly};

    fn state(eds: Option<Vec<u8>>) -> State {
        State::new(
            AdapterConfig {
                identity: AdapterIdentity {
                    vendor_id: 1234,
                    product_name: "Station".into(),
                    serial: 0xAABBCCDD,
                    ..AdapterIdentity::default()
                },
                assemblies: vec![Assembly::input(100, 4), Assembly::output(150, 2)],
                eds,
                eds_name: "station.eds".into(),
                app_name: "Station".into(),
                app_version: "2.1".into(),
                ..AdapterConfig::default()
            },
            1,
        )
    }

    fn ctx() -> Ctx {
        Ctx::new(
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::new(255, 255, 255, 0),
        )
    }

    fn ask(state: &mut State, ctx: &mut Ctx, service: u8, path: &[u8], data: &[u8]) -> Vec<u8> {
        let mut msg = vec![service, (path.len() / 2) as u8];
        msg.extend(path);
        msg.extend(data);
        message(state, ctx, &msg)
    }

    #[test]
    fn identity_answers_get_attributes_all_and_singles() {
        let (mut s, mut c) = (state(None), ctx());
        let all = ask(&mut s, &mut c, 0x01, &[0x20, 0x01, 0x24, 0x01], &[]);
        assert_eq!(all[..4], [0x81, 0, 0, 0]);
        assert_eq!(all[4..10], [0xD2, 0x04, 0x2B, 0, 1, 0]);
        assert_eq!(all[12..14], [0x30, 0]); // not owned, no I/O connections
        assert_eq!(all[14..18], [0xDD, 0xCC, 0xBB, 0xAA]);
        assert_eq!(all[18..], *b"\x07Station");
        let name = ask(
            &mut s,
            &mut c,
            0x0E,
            &[0x20, 0x01, 0x24, 0x01, 0x30, 0x07],
            &[],
        );
        assert_eq!(name[4..], *b"\x07Station");
        let missing = ask(
            &mut s,
            &mut c,
            0x0E,
            &[0x20, 0x01, 0x24, 0x01, 0x30, 0x63],
            &[],
        );
        assert_eq!(missing, [0x8E, 0, 0x14, 0]);
        assert_eq!(
            ask(&mut s, &mut c, 0x01, &[0x20, 0x01, 0x24, 0x02], &[])[2],
            0x16
        );
        assert_eq!(
            ask(&mut s, &mut c, 0x01, &[0x20, 0x99, 0x24, 0x01], &[])[2],
            0x05
        );
    }

    #[test]
    fn assemblies_are_readable() {
        let (mut s, mut c) = (state(None), ctx());
        s.set_input(100, &[1, 2, 3, 4]).expect("input");
        let data = ask(
            &mut s,
            &mut c,
            0x0E,
            &[0x20, 0x04, 0x24, 100, 0x30, 0x03],
            &[],
        );
        assert_eq!(data[4..], [1, 2, 3, 4]);
        let size = ask(
            &mut s,
            &mut c,
            0x0E,
            &[0x20, 0x04, 0x24, 150, 0x30, 0x04],
            &[],
        );
        assert_eq!(size[4..], [2, 0]);
    }

    #[test]
    fn port_and_tcp_ip_objects_describe_one_ethernet_port() {
        let (mut s, mut c) = (state(None), ctx());
        let get =
            |s: &mut State, c: &mut Ctx, path: &[u8]| ask(s, c, 0x0E, path, &[])[4..].to_vec();
        assert_eq!(
            get(&mut s, &mut c, &[0x20, 0xF4, 0x24, 0x00, 0x30, 0x02]),
            [1, 0]
        );
        assert_eq!(
            get(&mut s, &mut c, &[0x20, 0xF4, 0x24, 0x01, 0x30, 0x01]),
            [4, 0]
        );
        assert_eq!(
            get(&mut s, &mut c, &[0x20, 0xF4, 0x24, 0x01, 0x30, 0x02]),
            [2, 0]
        );
        let address = get(&mut s, &mut c, &[0x20, 0xF4, 0x24, 0x01, 0x30, 0x07]);
        assert_eq!(address, b"\x12\x0a192.0.2.10");
        let config = get(&mut s, &mut c, &[0x20, 0xF5, 0x24, 0x01, 0x30, 0x05]);
        // IP and mask as UDINTs in host order, as Logix reports them
        let mut expected = u32::from(Ipv4Addr::new(192, 0, 2, 10))
            .to_le_bytes()
            .to_vec();
        expected.extend(u32::from(Ipv4Addr::new(255, 255, 255, 0)).to_le_bytes());
        assert_eq!(config[..8], expected[..]);
    }

    #[test]
    fn the_eds_uploads_in_transfers_with_a_checksum() {
        let eds: Vec<u8> = (0..600u32).map(|i| (i % 251) as u8).collect();
        let (mut s, mut c) = (state(Some(eds.clone())), ctx());
        let path = [0x20, 0x37, 0x24, 0xC8];
        let started = ask(&mut s, &mut c, INITIATE_UPLOAD, &path, &[0xFF]);
        assert_eq!(started[4..], [88, 2, 0, 0, MAX_TRANSFER as u8]);
        let mut file: Vec<u8> = Vec::new();
        let mut types = Vec::new();
        for n in 0..=2u8 {
            let reply = ask(&mut s, &mut c, UPLOAD_TRANSFER, &path, &[n]);
            assert_eq!(reply[2], 0, "{reply:?}");
            assert_eq!(reply[4], n);
            types.push(reply[5]);
            file.extend(&reply[6..]);
        }
        assert_eq!(types, [0, 1, 2]);
        let sum = checksum(&eds);
        assert_eq!(file[600..], sum.to_le_bytes());
        assert_eq!(file[..600], eds[..]);
        // a retry of the last transfer gets it again; a jump is refused
        assert_eq!(ask(&mut s, &mut c, UPLOAD_TRANSFER, &path, &[2])[5], 2);
        assert_eq!(
            ask(&mut s, &mut c, UPLOAD_TRANSFER, &path, &[7])[2],
            STATE_CONFLICT
        );
        let name = ask(
            &mut s,
            &mut c,
            0x0E,
            &[0x20, 0x37, 0x24, 0xC8, 0x30, 0x04],
            &[],
        );
        assert_eq!(name[4..], *b"\x01eng\xDA\x04\x00\x0bstation.eds");
        let sum_attr = ask(
            &mut s,
            &mut c,
            0x0E,
            &[0x20, 0x37, 0x24, 0xC8, 0x30, 0x07],
            &[],
        );
        assert_eq!(sum_attr[4..], sum.to_le_bytes());
        assert_eq!(
            eds.iter()
                .fold(sum, |acc, b| acc.wrapping_add(u16::from(*b))),
            0
        );
    }

    #[test]
    fn without_an_eds_there_is_no_file_object() {
        let (mut s, mut c) = (state(None), ctx());
        let reply = ask(
            &mut s,
            &mut c,
            INITIATE_UPLOAD,
            &[0x20, 0x37, 0x24, 0xC8],
            &[0xFF],
        );
        assert_eq!(reply[2], PATH_UNKNOWN);
    }

    #[test]
    fn the_ciplink_object_starts_with_the_signature() {
        let (mut s, mut c) = (state(None), ctx());
        s.detail = "station 2".into();
        let reply = ask(&mut s, &mut c, 0x01, &[0x20, 0x64, 0x24, 0x01], &[]);
        assert_eq!(reply[..4], [0x81, 0, 0, 0]);
        assert_eq!(reply[4..12], *b"\x07ciplink");
        let rest = &reply[12..];
        let version = env!("CARGO_PKG_VERSION");
        let mut expected = short_string(version);
        expected.extend(b"\x07Station\x032.1\x09station 2");
        expected.extend([2, 100, 0, 1, 4, 0, 150, 0, 2, 2, 0, 0]);
        assert_eq!(rest, expected);
    }
}

//! Request builders and reply parsers for FC 1, 2, 3, 4, 5, 6, 8, 15, 16, 22 and 43/14, and exceptions. Pure.

use super::address::Area;
use crate::{Error, ErrorKind, TagError};

/// Most registers FC03/04 read.
pub(crate) const MAX_READ_REGISTERS: u16 = 125;
/// Most bits FC01/02 read.
pub(crate) const MAX_READ_BITS: u16 = 2000;
/// Most registers FC16 writes.
pub(crate) const MAX_WRITE_REGISTERS: u16 = 123;
/// Most coils FC15 writes.
pub(crate) const MAX_WRITE_BITS: u16 = 1968;

fn with_address(function: u8, address: u16, word: u16) -> Vec<u8> {
    let mut pdu = Vec::with_capacity(5);
    pdu.push(function);
    pdu.extend_from_slice(&address.to_be_bytes());
    pdu.extend_from_slice(&word.to_be_bytes());
    pdu
}

/// FC01-04: read `count` registers or bits of `area` from `start`.
pub(crate) fn read_request(area: Area, start: u16, count: u16) -> Vec<u8> {
    with_address(area.read_function(), start, count)
}

/// FC05 Write Single Coil.
pub(crate) fn write_coil(address: u16, on: bool) -> Vec<u8> {
    with_address(5, address, if on { 0xFF00 } else { 0x0000 })
}

/// FC06 Write Single Register.
pub(crate) fn write_register(address: u16, value: u16) -> Vec<u8> {
    with_address(6, address, value)
}

/// FC15 Write Multiple Coils, packed LSB first.
pub(crate) fn write_coils(address: u16, bits: &[bool]) -> Vec<u8> {
    // callers keep bits within MAX_WRITE_BITS
    let count = u16::try_from(bits.len()).unwrap_or(u16::MAX);
    let mut pdu = with_address(15, address, count);
    let bytes = bits.len().div_ceil(8);
    pdu.push(u8::try_from(bytes).unwrap_or(u8::MAX));
    let mut packed = vec![0u8; bytes];
    for (i, _) in bits.iter().enumerate().filter(|(_, b)| **b) {
        packed[i / 8] |= 1 << (i % 8);
    }
    pdu.extend(packed);
    pdu
}

/// FC16 Write Multiple Registers.
pub(crate) fn write_registers(address: u16, values: &[u16]) -> Vec<u8> {
    // callers keep values within MAX_WRITE_REGISTERS
    let count = u16::try_from(values.len()).unwrap_or(u16::MAX);
    let mut pdu = with_address(16, address, count);
    pdu.push(u8::try_from(values.len() * 2).unwrap_or(u8::MAX));
    for v in values {
        pdu.extend_from_slice(&v.to_be_bytes());
    }
    pdu
}

/// FC22 Mask Write Register: the register becomes `(reg & and) | (or & !and)`.
pub(crate) fn mask_write(address: u16, and: u16, or: u16) -> Vec<u8> {
    let mut pdu = with_address(22, address, and);
    pdu.extend_from_slice(&or.to_be_bytes());
    pdu
}

/// FC22 masks that set bit `bit` to `on`.
pub(crate) fn bit_masks(bit: u8, on: bool) -> (u16, u16) {
    (!(1u16 << bit), u16::from(on) << bit)
}

/// FC08 Diagnostics, sub-function 0000 Return Query Data, data 0000.
pub(crate) fn diagnostics_echo() -> Vec<u8> {
    vec![8, 0, 0, 0, 0]
}

/// FC43 / MEI 14 Read Device Identification: `code` 1 basic, 2 regular; from object `object`.
pub(crate) fn read_device_id(code: u8, object: u8) -> Vec<u8> {
    vec![0x2B, 0x0E, code, object]
}

/// Why a reply PDU could not be used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ReplyError {
    /// The device answered with this exception code.
    Exception(u8),
    /// The reply is short, long or inconsistent.
    Bad,
}

/// The data of `reply` after its function code, or the exception it carries.
pub(crate) fn reply_data(function: u8, reply: &[u8]) -> Result<&[u8], ReplyError> {
    match reply {
        [f, code, ..] if *f == function | 0x80 => Err(ReplyError::Exception(*code)),
        [f, data @ ..] if *f == function => Ok(data),
        _ => Err(ReplyError::Bad),
    }
}

/// The registers of an FC03/04 reply to a read of `count`.
pub(crate) fn parse_registers(
    function: u8,
    reply: &[u8],
    count: u16,
) -> Result<Vec<u16>, ReplyError> {
    let data = reply_data(function, reply)?;
    match data {
        [n, regs @ ..] if usize::from(*n) == regs.len() && regs.len() == usize::from(count) * 2 => {
            Ok(regs
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect())
        }
        _ => Err(ReplyError::Bad),
    }
}

/// The bits of an FC01/02 reply to a read of `count`, LSB of the first byte first.
pub(crate) fn parse_bits(function: u8, reply: &[u8], count: u16) -> Result<Vec<bool>, ReplyError> {
    let data = reply_data(function, reply)?;
    let count = usize::from(count);
    match data {
        [n, bytes @ ..] if usize::from(*n) == bytes.len() && bytes.len() == count.div_ceil(8) => {
            Ok((0..count)
                .map(|i| bytes[i / 8] >> (i % 8) & 1 == 1)
                .collect())
        }
        _ => Err(ReplyError::Bad),
    }
}

/// Checks a write reply against its request: FC05/06/15/16 echo address and value or quantity, FC22 echoes all.
pub(crate) fn check_write_reply(request: &[u8], reply: &[u8]) -> Result<(), ReplyError> {
    let function = request.first().copied().unwrap_or_default();
    reply_data(function, reply)?;
    let echo = if function == 22 { 7 } else { 5 };
    if reply.len() == echo && request.get(..echo) == Some(reply) {
        Ok(())
    } else {
        Err(ReplyError::Bad)
    }
}

/// One reply of Read Device Identification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DeviceIdPage {
    pub conformity: u8,
    /// Some(next object id) when more follow.
    pub next: Option<u8>,
    pub objects: Vec<(u8, Vec<u8>)>,
}

/// Parses an FC43 / MEI 14 reply.
pub(crate) fn parse_device_id(reply: &[u8]) -> Result<DeviceIdPage, ReplyError> {
    let data = reply_data(0x2B, reply)?;
    let [0x0E, _code, conformity, more, next, count, rest @ ..] = data else {
        return Err(ReplyError::Bad);
    };
    let mut objects = Vec::with_capacity(usize::from(*count));
    let mut at = rest;
    for _ in 0..*count {
        let [id, len, tail @ ..] = at else {
            return Err(ReplyError::Bad);
        };
        let len = usize::from(*len);
        if tail.len() < len {
            return Err(ReplyError::Bad);
        }
        objects.push((*id, tail[..len].to_vec()));
        at = &tail[len..];
    }
    if !at.is_empty() {
        return Err(ReplyError::Bad);
    }
    Ok(DeviceIdPage {
        conformity: *conformity,
        next: (*more == 0xFF).then_some(*next),
        objects,
    })
}

/// The name of an exception code.
pub(crate) fn exception_name(code: u8) -> &'static str {
    match code {
        1 => "illegal function",
        2 => "illegal data address",
        3 => "illegal data value",
        4 => "server device failure",
        5 => "acknowledge",
        6 => "server device busy",
        8 => "memory parity error",
        0x0A => "gateway path unavailable",
        0x0B => "gateway target device failed to respond",
        _ => "unknown exception",
    }
}

/// The kind of an exception code; 03 is a bad value on a write and a bad request otherwise.
pub(crate) fn exception_kind(code: u8, write: bool) -> ErrorKind {
    match code {
        1 => ErrorKind::BadRequest,
        2 => ErrorKind::NotFound,
        3 if write => ErrorKind::BadValue,
        3 => ErrorKind::BadRequest,
        5 | 6 => ErrorKind::Refused,
        0x0A | 0x0B => ErrorKind::Comm,
        _ => ErrorKind::Device,
    }
}

/// The per-tag error of exception `code` from `unit`.
pub(crate) fn exception_error(code: u8, unit: u8, write: bool) -> TagError {
    TagError {
        message: format!(
            "Modbus exception 0x{code:02X} ({}) from unit {unit}",
            exception_name(code)
        ),
        kind: exception_kind(code, write),
        status: Some(code),
        ext: None,
    }
}

/// The ResponseError of exception `code` (send_pdu, device_info).
pub(crate) fn exception_response(code: u8, unit: u8) -> Error {
    Error::response_tag(exception_error(code, unit, false))
}

/// The error of a reply that could not be used.
pub(crate) fn bad_reply(unit: u8) -> TagError {
    TagError::new(format!("bad reply from unit {unit}"), ErrorKind::Comm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modbus::frame::{mbap_frame, rtu_frame};

    #[test]
    fn golden_requests() {
        assert_eq!(
            mbap_frame(1, 1, &read_request(Area::Holding, 0, 2)),
            [
                0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x02
            ]
        );
        assert_eq!(
            read_request(Area::Coil, 0x13, 0x13),
            [0x01, 0x00, 0x13, 0x00, 0x13]
        );
        assert_eq!(
            read_request(Area::Discrete, 0xC4, 0x16),
            [0x02, 0x00, 0xC4, 0x00, 0x16]
        );
        assert_eq!(
            read_request(Area::Input, 0x08, 1),
            [0x04, 0x00, 0x08, 0x00, 0x01]
        );
        assert_eq!(write_coil(0xAC, true), [0x05, 0x00, 0xAC, 0xFF, 0x00]);
        assert_eq!(write_coil(0xAC, false), [0x05, 0x00, 0xAC, 0x00, 0x00]);
        assert_eq!(write_register(1, 3), [0x06, 0x00, 0x01, 0x00, 0x03]);
        // the spec's FC15 example: coils 20-29 = CD 01
        let bits = [
            true, false, true, true, false, false, true, true, true, false,
        ];
        assert_eq!(
            write_coils(0x13, &bits),
            [0x0F, 0x00, 0x13, 0x00, 0x0A, 0x02, 0xCD, 0x01]
        );
        assert_eq!(
            write_registers(1, &[0x000A, 0x0102]),
            [0x10, 0x00, 0x01, 0x00, 0x02, 0x04, 0x00, 0x0A, 0x01, 0x02]
        );
        assert_eq!(
            mask_write(4, 0x00F2, 0x0025),
            [0x16, 0x00, 0x04, 0x00, 0xF2, 0x00, 0x25]
        );
        assert_eq!(bit_masks(4, true), (0xFFEF, 0x0010));
        assert_eq!(bit_masks(15, false), (0x7FFF, 0));
        assert_eq!(diagnostics_echo(), [0x08, 0, 0, 0, 0]);
        assert_eq!(read_device_id(1, 0), [0x2B, 0x0E, 0x01, 0x00]);
        assert_eq!(
            rtu_frame(1, &read_request(Area::Holding, 0, 1)),
            [0x01, 0x03, 0x00, 0x00, 0x00, 0x01, 0x84, 0x0A]
        );
    }

    #[test]
    fn register_replies_short_long_and_exception() {
        assert_eq!(
            parse_registers(3, &[3, 4, 0x02, 0x2B, 0x00, 0x00], 2),
            Ok(vec![0x022B, 0])
        );
        assert_eq!(
            parse_registers(3, &[3, 4, 0x02, 0x2B, 0x00], 2),
            Err(ReplyError::Bad)
        );
        assert_eq!(
            parse_registers(3, &[3, 4, 0x02, 0x2B, 0x00, 0x00, 0x00], 2),
            Err(ReplyError::Bad)
        );
        assert_eq!(parse_registers(3, &[3, 2, 0, 1], 2), Err(ReplyError::Bad));
        assert_eq!(
            parse_registers(3, &[0x83, 2], 2),
            Err(ReplyError::Exception(2))
        );
        assert_eq!(parse_registers(3, &[4, 2, 0, 1], 1), Err(ReplyError::Bad));
        assert_eq!(parse_registers(3, &[], 1), Err(ReplyError::Bad));
        assert_eq!(parse_registers(3, &[0x83], 1), Err(ReplyError::Bad));
    }

    #[test]
    fn coil_bits_are_lsb_first() {
        // the spec's FC01 example: coils 20-38 = CD 6B 05
        let bits = parse_bits(1, &[1, 3, 0xCD, 0x6B, 0x05], 19).expect("bits");
        let expect: Vec<bool> = [1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1]
            .iter()
            .map(|&b| b == 1)
            .collect();
        assert_eq!(bits, expect);
        assert_eq!(parse_bits(1, &[1, 2, 0xCD, 0x6B], 19), Err(ReplyError::Bad));
        assert_eq!(parse_bits(2, &[0x82, 3], 1), Err(ReplyError::Exception(3)));
    }

    #[test]
    fn write_replies_echo_the_request() {
        let req = write_registers(1, &[1, 2]);
        assert_eq!(check_write_reply(&req, &[0x10, 0, 1, 0, 2]), Ok(()));
        assert_eq!(
            check_write_reply(&req, &[0x10, 0, 1, 0, 3]),
            Err(ReplyError::Bad)
        );
        assert_eq!(
            check_write_reply(&req, &[0x90, 4]),
            Err(ReplyError::Exception(4))
        );
        let req = write_coil(5, true);
        assert_eq!(check_write_reply(&req, &req), Ok(()));
        assert_eq!(
            check_write_reply(&req, &write_coil(5, false)),
            Err(ReplyError::Bad)
        );
        let req = mask_write(4, 0xF2, 0x25);
        assert_eq!(check_write_reply(&req, &req), Ok(()));
        assert_eq!(check_write_reply(&req, &req[..5]), Err(ReplyError::Bad));
    }

    #[test]
    fn device_id_pages() {
        let reply = [
            0x2B, 0x0E, 0x01, 0x01, 0xFF, 0x02, 0x02, 0x00, 0x03, b'a', b'b', b'c', 0x01, 0x01,
            b'x',
        ];
        assert_eq!(
            parse_device_id(&reply),
            Ok(DeviceIdPage {
                conformity: 1,
                next: Some(2),
                objects: vec![(0, b"abc".to_vec()), (1, b"x".to_vec())],
            })
        );
        let last = [0x2B, 0x0E, 0x01, 0x81, 0x00, 0x00, 0x01, 0x02, 0x00];
        assert_eq!(parse_device_id(&last).expect("last").next, None);
        assert_eq!(parse_device_id(&reply[..13]), Err(ReplyError::Bad));
        assert_eq!(parse_device_id(&[0x2B, 0x0E, 0x01]), Err(ReplyError::Bad));
        assert_eq!(
            parse_device_id(&[0xAB, 0x01]),
            Err(ReplyError::Exception(1))
        );
        let mut long = last.to_vec();
        long.push(0);
        assert_eq!(parse_device_id(&long), Err(ReplyError::Bad));
    }

    #[test]
    fn exceptions_map_to_kinds() {
        let kind = |code, write| exception_kind(code, write);
        assert_eq!(kind(1, false), ErrorKind::BadRequest);
        assert_eq!(kind(2, false), ErrorKind::NotFound);
        assert_eq!(kind(3, true), ErrorKind::BadValue);
        assert_eq!(kind(3, false), ErrorKind::BadRequest);
        assert_eq!(kind(4, false), ErrorKind::Device);
        assert_eq!(kind(5, false), ErrorKind::Refused);
        assert_eq!(kind(6, true), ErrorKind::Refused);
        assert_eq!(kind(8, false), ErrorKind::Device);
        assert_eq!(kind(0x0A, false), ErrorKind::Comm);
        assert_eq!(kind(0x0B, false), ErrorKind::Comm);
        assert_eq!(kind(0x42, false), ErrorKind::Device);
        let e = exception_error(2, 1, false);
        assert_eq!(
            e.message,
            "Modbus exception 0x02 (illegal data address) from unit 1"
        );
        assert_eq!((e.status, e.ext), (Some(2), None));
        match exception_response(0x0B, 3) {
            Error::Response { kind, status, .. } => {
                assert_eq!((kind, status), (Some(ErrorKind::Comm), Some(0x0B)));
            }
            other => panic!("{other:?}"),
        }
    }
}

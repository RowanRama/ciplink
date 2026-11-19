//! Framing: the MBAP header of Modbus TCP, RTU frames with CRC-16/MODBUS, and the length of an RTU reply
//! from its function code. Pure, no I/O.

use crate::{Error, Result};

/// MBAP header size: transaction id, protocol id, length, unit id.
pub(crate) const MBAP_HEADER: usize = 7;
/// Longest RTU frame (address, PDU of at most 253 bytes, CRC).
pub(crate) const RTU_MAX: usize = 256;

/// CRC-16/MODBUS of `data`: reflected polynomial 0xA001, initial 0xFFFF. Sent low byte first.
pub(crate) fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xA001
            } else {
                crc >> 1
            };
        }
    }
    crc
}

/// A Modbus TCP request: MBAP header then `pdu`.
pub(crate) fn mbap_frame(transaction: u16, unit: u8, pdu: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(MBAP_HEADER + pdu.len());
    out.extend_from_slice(&transaction.to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    // the PDU is at most 253 bytes (checked by the callers), so the length fits
    let length = u16::try_from(pdu.len() + 1).unwrap_or(u16::MAX);
    out.extend_from_slice(&length.to_be_bytes());
    out.push(unit);
    out.extend_from_slice(pdu);
    out
}

/// A parsed MBAP header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Mbap {
    pub transaction: u16,
    pub unit: u8,
    /// Bytes of PDU that follow the header.
    pub pdu_len: usize,
}

/// Parses an MBAP header; a protocol id other than 0 or a length outside 2..=254 means the stream is out of step.
pub(crate) fn parse_mbap(header: &[u8; MBAP_HEADER]) -> Result<Mbap> {
    let protocol = u16::from_be_bytes([header[2], header[3]]);
    let length = u16::from_be_bytes([header[4], header[5]]);
    if protocol != 0 {
        return Err(Error::comm(format!(
            "bad MBAP header: protocol id {protocol}"
        )));
    }
    if !(2..=254).contains(&length) {
        return Err(Error::comm(format!("bad MBAP header: length {length}")));
    }
    Ok(Mbap {
        transaction: u16::from_be_bytes([header[0], header[1]]),
        unit: header[6],
        pdu_len: usize::from(length) - 1,
    })
}

/// An RTU frame: unit, `pdu`, CRC low byte first.
pub(crate) fn rtu_frame(unit: u8, pdu: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(pdu.len() + 3);
    out.push(unit);
    out.extend_from_slice(pdu);
    let crc = crc16(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    out
}

/// True if the last two bytes of `frame` are the CRC of the rest.
pub(crate) fn rtu_crc_ok(frame: &[u8]) -> bool {
    match frame.len().checked_sub(2) {
        Some(n) if n > 0 => crc16(&frame[..n]).to_le_bytes() == frame[n..],
        _ => false,
    }
}

/// The length of the RTU reply that starts with `buf`: the whole frame's length when `buf` holds enough to know it,
/// else a lower bound above `buf.len()`. Read until `buf` is that long and ask again, until the answer is
/// `buf.len()`. Err for a function whose reply length is unknown or a frame longer than 256 bytes.
pub(crate) fn rtu_reply_len(buf: &[u8]) -> Result<usize> {
    if buf.len() < 2 {
        return Ok(2);
    }
    let function = buf[1];
    let total = if function & 0x80 != 0 {
        5
    } else {
        match function {
            // unit, function, byte count, data, CRC
            1..=4 | 12 | 17 | 20 | 21 | 23 => match buf.get(2) {
                Some(&count) => 5 + usize::from(count),
                None => 3,
            },
            7 => 5,
            5 | 6 | 8 | 11 | 15 | 16 => 8,
            22 => 10,
            24 => match buf.get(2..4) {
                Some(count) => 6 + usize::from(u16::from_be_bytes([count[0], count[1]])),
                None => 4,
            },
            43 => mei_len(buf)?,
            _ => {
                return Err(Error::comm(format!(
                    "cannot frame an RTU reply to function {function}"
                )));
            }
        }
    };
    if total > RTU_MAX {
        return Err(Error::comm(format!(
            "RTU reply of {total} bytes is too long"
        )));
    }
    Ok(total)
}

/// The length of an FC43 / MEI 14 reply: walk the objects' lengths.
fn mei_len(buf: &[u8]) -> Result<usize> {
    // unit, 0x2B, MEI type, read code, conformity, more follows, next id, object count
    const HEAD: usize = 8;
    match buf.get(2) {
        None => return Ok(3),
        Some(0x0E) => {}
        Some(other) => {
            return Err(Error::comm(format!(
                "cannot frame an RTU reply to MEI type {other}"
            )));
        }
    }
    let Some(&objects) = buf.get(HEAD - 1) else {
        return Ok(HEAD);
    };
    let mut at = HEAD;
    for _ in 0..objects {
        // object id, length, value
        let Some(&len) = buf.get(at + 1) else {
            return Ok(at + 2);
        };
        at += 2 + usize::from(len);
        if at > RTU_MAX {
            return Ok(at);
        }
    }
    Ok(at + 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_of_known_frames() {
        assert_eq!(
            crc16(&[0x01, 0x03, 0x00, 0x00, 0x00, 0x02]).to_le_bytes(),
            [0xC4, 0x0B]
        );
        assert_eq!(
            crc16(&[0x01, 0x03, 0x00, 0x00, 0x00, 0x01]).to_le_bytes(),
            [0x84, 0x0A]
        );
        assert_eq!(
            rtu_frame(1, &[0x03, 0x00, 0x00, 0x00, 0x02]),
            [0x01, 0x03, 0x00, 0x00, 0x00, 0x02, 0xC4, 0x0B]
        );
        assert!(rtu_crc_ok(&[
            0x01, 0x03, 0x00, 0x00, 0x00, 0x02, 0xC4, 0x0B
        ]));
        assert!(!rtu_crc_ok(&[
            0x01, 0x03, 0x00, 0x00, 0x00, 0x02, 0x0B, 0xC4
        ]));
        assert!(!rtu_crc_ok(&[0xFF, 0xFF]));
    }

    #[test]
    fn mbap_header_round_trip() {
        let frame = mbap_frame(1, 1, &[0x03, 0x00, 0x00, 0x00, 0x02]);
        assert_eq!(
            frame,
            [
                0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x02
            ]
        );
        let header: [u8; MBAP_HEADER] = frame[..MBAP_HEADER].try_into().expect("7 bytes");
        assert_eq!(
            parse_mbap(&header).expect("header"),
            Mbap {
                transaction: 1,
                unit: 1,
                pdu_len: 5
            }
        );
    }

    #[test]
    fn mbap_rejects_bad_protocol_and_length() {
        let bad = |h: [u8; 7]| matches!(parse_mbap(&h), Err(Error::Comm(_)));
        assert!(bad([0, 1, 0, 1, 0, 6, 1]));
        assert!(bad([0, 1, 0, 0, 0, 1, 1]));
        assert!(bad([0, 1, 0, 0, 0, 255, 1]));
        assert!(!bad([0, 1, 0, 0, 0, 2, 1]));
        assert!(!bad([0, 1, 0, 0, 0, 254, 1]));
    }

    /// Feeds `frame` to `rtu_reply_len` the way the link reader does and returns the length it settles on.
    fn settle(frame: &[u8]) -> usize {
        let mut have = 0;
        loop {
            let need = rtu_reply_len(&frame[..have]).expect("length");
            if need <= have {
                return need;
            }
            have = need.min(frame.len());
        }
    }

    #[test]
    fn rtu_reply_length_for_each_function() {
        // FC03, 2 registers
        assert_eq!(settle(&[1, 3, 4, 0, 1, 0, 2, 0xAA, 0xBB]), 9);
        // FC01, 1 byte of coils
        assert_eq!(settle(&[1, 1, 1, 5, 0, 0]), 6);
        assert_eq!(settle(&[1, 5, 0, 1, 0xFF, 0, 0, 0]), 8);
        assert_eq!(settle(&[1, 16, 0, 1, 0, 2, 0, 0]), 8);
        assert_eq!(settle(&[1, 22, 0, 1, 0, 2, 0, 3, 0, 0]), 10);
        assert_eq!(settle(&[1, 0x83, 2, 0, 0]), 5);
        assert_eq!(settle(&[1, 8, 0, 0, 0, 0, 0, 0]), 8);
        // FC43: two objects of 3 and 1 bytes
        let mei = [
            1, 0x2B, 0x0E, 1, 1, 0, 0, 2, 0, 3, b'a', b'b', b'c', 1, 1, b'x', 0, 0,
        ];
        assert_eq!(settle(&mei), mei.len());
        assert!(rtu_reply_len(&[1, 0x2B, 0x0D]).is_err());
        assert!(rtu_reply_len(&[1, 99]).is_err());
    }

    #[test]
    fn rtu_reply_length_rejects_counts_past_256() {
        assert_eq!(rtu_reply_len(&[1, 3, 251]).expect("fits"), 256);
        assert!(rtu_reply_len(&[1, 3, 252]).is_err());
        assert!(rtu_reply_len(&[1, 24, 1, 0]).is_err());
        let mut mei = vec![1, 0x2B, 0x0E, 1, 1, 0, 0, 3];
        for _ in 0..2 {
            mei.extend_from_slice(&[0, 200]);
            mei.extend(std::iter::repeat_n(b'x', 200));
        }
        assert!(rtu_reply_len(&mei).is_err());
    }
}

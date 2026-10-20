//! Decoding the request paths (padded EPATHs) and messages the simulator receives.

use ciplink::reader::Reader;

/// One segment of a padded EPATH.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Seg {
    /// Port segment: port number and link address bytes.
    Port {
        port: u16,
        link: Vec<u8>,
    },
    Class(u32),
    Instance(u32),
    Attribute(u32),
    /// Member ID, an array element in a tag path.
    Element(u32),
    /// ANSI extended symbol segment (0x91), a tag, member or program name.
    Symbol(String),
}

/// A CIP request: service, decoded path and request data.
#[derive(Debug)]
pub(crate) struct Request<'a> {
    pub service: u8,
    pub path: Vec<Seg>,
    pub data: &'a [u8],
}

/// Splits a message into service, path and data; None if the path is malformed.
pub(crate) fn parse_request(message: &[u8]) -> Option<Request<'_>> {
    let (&service, rest) = message.split_first()?;
    let (&words, rest) = rest.split_first()?;
    let size = usize::from(words) * 2;
    if rest.len() < size {
        return None;
    }
    let path = parse_path(&rest[..size])?;
    Some(Request {
        service,
        path,
        data: &rest[size..],
    })
}

/// Decodes a padded EPATH (without its size), None if a segment is malformed or unsupported.
pub(crate) fn parse_path(bytes: &[u8]) -> Option<Vec<Seg>> {
    let mut r = Reader::new(bytes);
    let mut segments = Vec::new();
    while !r.is_empty() {
        let kind = r.u8().ok()?;
        let segment = match kind {
            0x00..=0x1F => {
                let extended = kind & 0x10 != 0;
                let port = match kind & 0x0F {
                    0x0F => r.u16().ok()?,
                    p => u16::from(p),
                };
                if extended {
                    let size = usize::from(r.u8().ok()?);
                    let link = r.take(size).ok()?.to_vec();
                    if size % 2 == 1 {
                        r.take(1).ok()?;
                    }
                    Seg::Port { port, link }
                } else {
                    Seg::Port {
                        port,
                        link: vec![r.u8().ok()?],
                    }
                }
            }
            0x20..=0x3F => {
                let value = match kind & 0x03 {
                    0 => u32::from(r.u8().ok()?),
                    1 => {
                        r.take(1).ok()?;
                        u32::from(r.u16().ok()?)
                    }
                    2 => {
                        r.take(1).ok()?;
                        r.u32().ok()?
                    }
                    _ => return None,
                };
                match kind & 0x1C {
                    0x00 => Seg::Class(value),
                    0x04 => Seg::Instance(value),
                    0x08 => Seg::Element(value),
                    0x10 => Seg::Attribute(value),
                    _ => return None,
                }
            }
            0x91 => {
                let size = usize::from(r.u8().ok()?);
                let name = r.take(size).ok()?;
                if size % 2 == 1 {
                    r.take(1).ok()?;
                }
                Seg::Symbol(name.iter().map(|&b| char::from(b)).collect())
            }
            _ => return None,
        };
        segments.push(segment);
    }
    Some(segments)
}

/// The class and instance of a path addressing an object (class first), None otherwise.
pub(crate) fn class_instance(path: &[Seg]) -> Option<(u32, u32)> {
    match path {
        [Seg::Class(c), Seg::Instance(i), ..] => Some((*c, *i)),
        _ => None,
    }
}

/// The attribute of a class/instance/attribute path.
pub(crate) fn attribute(path: &[Seg]) -> Option<u32> {
    match path {
        [Seg::Class(_), Seg::Instance(_), Seg::Attribute(a)] => Some(*a),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_tag_paths_with_program_ids_and_elements() {
        let path = ciplink::epath::tag_request_path(
            "Program:Main.Tag[1,300].Member[70000]",
            Some(0x1234),
            true,
        )
        .expect("path");
        let message = [&[0x4C][..], &path, &[1, 0]].concat();
        let request = parse_request(&message).expect("request");
        assert_eq!(request.service, 0x4C);
        assert_eq!(request.data, &[1, 0]);
        assert_eq!(
            request.path,
            vec![
                Seg::Symbol("Program:Main".into()),
                Seg::Class(0x6B),
                Seg::Instance(0x1234),
                Seg::Element(1),
                Seg::Element(300),
                Seg::Symbol("Member".into()),
                Seg::Element(70000),
            ]
        );
    }

    #[test]
    fn decodes_port_segments_and_attributes() {
        assert_eq!(
            parse_path(&[
                0x01, 0x03, 0x12, 0x03, b'1', b'.', b'2', 0x00, 0x20, 0x02, 0x24, 0x01, 0x30, 0x06
            ]),
            Some(vec![
                Seg::Port {
                    port: 1,
                    link: vec![3]
                },
                Seg::Port {
                    port: 2,
                    link: b"1.2".to_vec()
                },
                Seg::Class(2),
                Seg::Instance(1),
                Seg::Attribute(6),
            ])
        );
    }

    #[test]
    fn rejects_truncated_and_unknown_segments() {
        assert_eq!(parse_path(&[0x91, 0x05, b'a']), None);
        assert_eq!(parse_path(&[0x25, 0x00, 0x01]), None);
        assert_eq!(parse_path(&[0x80, 0x00]), None);
        assert!(parse_request(&[0x4C, 0x02, 0x20]).is_none());
    }
}

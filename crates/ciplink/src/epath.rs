//! CIP path segments, EPATH encoding, connection path parsing and request paths.

use crate::{Error, Result};

/// Port of a port segment: a name (`"bp"`, `"enet"`, ...) or a port number.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortId {
    /// A named port: backplane/bp = 1, enet/dnet/cnet/dhrio-a/dh485-a = 2, dhrio-b/dh485-b = 3.
    Name(String),
    /// A port number, numbers above 14 use the extended port format.
    Number(i64),
}

/// Link address of a port segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Link {
    /// A slot or node number (one byte).
    Number(i64),
    /// A number written as text, or an IP address.
    Text(String),
    /// Raw link bytes.
    Raw(Vec<u8>),
}

/// Logical segment type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum LogicalType {
    ClassId,
    InstanceId,
    MemberId,
    ConnectionPoint,
    AttributeId,
    Special,
    ServiceId,
}

impl LogicalType {
    /// The type for a Python name such as `"class_id"`.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "class_id" => LogicalType::ClassId,
            "instance_id" => LogicalType::InstanceId,
            "member_id" => LogicalType::MemberId,
            "connection_point" => LogicalType::ConnectionPoint,
            "attribute_id" => LogicalType::AttributeId,
            "special" => LogicalType::Special,
            "service_id" => LogicalType::ServiceId,
            _ => return None,
        })
    }

    fn bits(self) -> u8 {
        (match self {
            LogicalType::ClassId => 0,
            LogicalType::InstanceId => 1,
            LogicalType::MemberId => 2,
            LogicalType::ConnectionPoint => 3,
            LogicalType::AttributeId => 4,
            LogicalType::Special => 5,
            LogicalType::ServiceId => 6,
        }) << 2
    }
}

/// Value of a logical segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogicalValue {
    /// Encoded in 1, 2 or 4 bytes, whichever is smallest.
    Int(i64),
    /// Raw value bytes (1, 2 or 4).
    Raw(Vec<u8>),
}

impl From<u32> for LogicalValue {
    fn from(v: u32) -> Self {
        LogicalValue::Int(v.into())
    }
}

impl LogicalValue {
    fn is_empty_or_zero(&self) -> bool {
        match self {
            LogicalValue::Int(v) => *v == 0,
            LogicalValue::Raw(b) => b.is_empty(),
        }
    }
}

/// Value of a data segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DataValue {
    /// An ANSI extended symbol (tag or member name).
    Symbol(String),
    /// A simple data segment.
    Raw(Vec<u8>),
}

/// A CIP path segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Segment {
    /// Port segment.
    Port {
        /// Port.
        port: PortId,
        /// Link address.
        link: Link,
    },
    /// Logical segment.
    Logical {
        /// Type.
        kind: LogicalType,
        /// Value.
        value: LogicalValue,
    },
    /// Data segment.
    Data(DataValue),
    /// Bytes already encoded.
    Raw(Vec<u8>),
}

impl Segment {
    /// A logical segment.
    pub fn logical(kind: LogicalType, value: impl Into<LogicalValue>) -> Self {
        Segment::Logical {
            kind,
            value: value.into(),
        }
    }

    /// A port segment on a named port with a numeric link.
    pub fn port(name: &str, link: i64) -> Self {
        Segment::Port {
            port: PortId::Name(name.into()),
            link: Link::Number(link),
        }
    }
}

fn port_number(name: &str) -> Option<i64> {
    Some(match name {
        "backplane" | "bp" => 1,
        "enet" | "dhrio-a" | "dnet" | "cnet" | "dh485-a" => 2,
        "dhrio-b" | "dh485-b" => 3,
        _ => return None,
    })
}

fn usint(v: i64) -> Option<u8> {
    u8::try_from(v).ok()
}

/// Encodes one segment; `padded` pads logical segments as in a padded EPATH.
pub fn encode_segment(segment: &Segment, padded: bool) -> Result<Vec<u8>> {
    let fail = || Error::Data(format!("Error packing {segment:?}"));
    match segment {
        Segment::Raw(bytes) => Ok(bytes.clone()),
        Segment::Port { port, link } => {
            let mut port = match port {
                PortId::Name(name) => port_number(name).ok_or_else(fail)?,
                PortId::Number(n) => *n,
            };
            let link = match link {
                Link::Number(n) => vec![usint(*n).ok_or_else(fail)?],
                Link::Text(text)
                    if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) =>
                {
                    vec![text.parse::<i64>().ok().and_then(usint).ok_or_else(fail)?]
                }
                Link::Text(text) => {
                    text.parse::<std::net::IpAddr>().map_err(|_| fail())?;
                    text.as_bytes().to_vec()
                }
                Link::Raw(bytes) => bytes.clone(),
            };
            let mut ext_port = Vec::new();
            if port > 14 {
                ext_port = u16::try_from(port)
                    .map_err(|_| fail())?
                    .to_le_bytes()
                    .to_vec();
                port = 0x0F;
            }
            let mut len = Vec::new();
            if link.len() > 1 {
                port |= 0x10;
                len.push(u8::try_from(link.len()).map_err(|_| fail())?);
            }
            let mut out = vec![usint(port).ok_or_else(fail)?];
            out.extend(len);
            out.extend(ext_port);
            out.extend(link);
            if out.len() % 2 == 1 {
                out.push(0);
            }
            Ok(out)
        }
        Segment::Logical { kind, value } => {
            let value = match value {
                LogicalValue::Int(v) if *v < 0 => return Err(fail()),
                LogicalValue::Int(v) if *v <= 0xFF => vec![*v as u8],
                LogicalValue::Int(v) if *v <= 0xFFFF => (*v as u16).to_le_bytes().to_vec(),
                LogicalValue::Int(v) if *v <= 0xFFFF_FFFF => (*v as u32).to_le_bytes().to_vec(),
                LogicalValue::Int(_) => return Err(fail()),
                LogicalValue::Raw(bytes) => bytes.clone(),
            };
            let format = match value.len() {
                1 => 0,
                2 => 1,
                4 => 2,
                _ => return Err(fail()),
            };
            let mut out = vec![0x20 | kind.bits() | format];
            if padded && (1 + value.len()) % 2 == 1 {
                out.push(0);
            }
            out.extend(value);
            Ok(out)
        }
        Segment::Data(DataValue::Symbol(name)) => {
            let mut data = name.as_bytes().to_vec();
            let len = u8::try_from(data.len()).map_err(|_| fail())?;
            if data.len() % 2 == 1 {
                data.push(0);
            }
            let mut out = vec![0x91, len];
            out.extend(data);
            Ok(out)
        }
        Segment::Data(DataValue::Raw(bytes)) => {
            let mut data = bytes.clone();
            if data.len() % 2 == 1 {
                data.push(0);
            }
            let mut out = vec![0x80, u8::try_from(data.len() / 2).map_err(|_| fail())?];
            out.extend(data);
            Ok(out)
        }
    }
}

/// Encodes segments as an EPATH; `length` prefixes the size in words (and a pad byte with `pad_length`).
pub fn encode_epath(
    segments: &[Segment],
    padded: bool,
    length: bool,
    pad_length: bool,
) -> Result<Vec<u8>> {
    let mut path = Vec::new();
    for segment in segments {
        path.extend(encode_segment(segment, padded)?);
    }
    if !length {
        return Ok(path);
    }
    let words = u8::try_from(path.len() / 2)
        .map_err(|_| Error::data("Error packing EPATH, path too long"))?;
    let mut out = vec![words];
    if pad_length {
        out.push(0);
    }
    out.extend(path);
    Ok(out)
}

/// The Message Router path, class 0x02 instance 1.
pub fn message_router_path() -> Vec<Segment> {
    vec![
        Segment::logical(LogicalType::ClassId, 0x02),
        Segment::logical(LogicalType::InstanceId, 0x01),
    ]
}

/// Parses a connection path (`ip`, `ip/slot`, `ip:port/route...`, `\` and `,` work as `/`) into the IP, the
/// port if given, and the route. `auto_slot` (Logix) makes no route mean `bp/0` and a single part a slot.
pub fn parse_connection_path(
    path: &str,
    auto_slot: bool,
) -> Result<(String, Option<u16>, Vec<Segment>)> {
    let normalized = path.replace(['\\', ','], "/");
    let mut parts = normalized.split('/');
    let first = parts.next().unwrap_or_default();
    let route: Vec<&str> = parts.collect();
    let (ip, port) = match first.split(':').collect::<Vec<_>>().as_slice() {
        [ip] => (ip.to_string(), None),
        [ip, port] => {
            let text = port.trim();
            let number = text.strip_prefix('+').unwrap_or(text).parse::<i64>();
            match number {
                Ok(n) if n > 0 && n < 65535 => (ip.to_string(), Some(n as u16)),
                _ => return Err(Error::request(format!("Invalid port: {port}"))),
            }
        }
        _ => {
            return Err(Error::request(format!(
                "Failed to parse connection path: {normalized}"
            )));
        }
    };
    Ok((ip, port, route_segments(&route, auto_slot)?))
}

/// Parses a route such as `bp/1/enet/10.1.1.1` into port segments.
pub fn parse_cip_route(route: &str, auto_slot: bool) -> Result<Vec<Segment>> {
    let normalized = route.replace('\\', "/");
    let parts: Vec<&str> = normalized.split('/').collect();
    route_segments(&parts, auto_slot)
}

fn route_segments(parts: &[&str], auto_slot: bool) -> Result<Vec<Segment>> {
    let bp = |link: Link| Segment::Port {
        port: PortId::Name("bp".into()),
        link,
    };
    if parts.is_empty() {
        return Ok(if auto_slot {
            vec![bp(Link::Number(0))]
        } else {
            vec![]
        });
    }
    if parts.len() == 1 && auto_slot {
        return Ok(vec![bp(Link::Text(parts[0].to_owned()))]);
    }
    if parts.len() % 2 == 1 {
        return Err(Error::request(format!(
            "Invalid connection path, must contain segment pairs(port/link), {} segments provided.",
            parts.len()
        )));
    }
    Ok(parts
        .chunks(2)
        .map(|pair| {
            let port = if !pair[0].is_empty() && pair[0].bytes().all(|b| b.is_ascii_digit()) {
                pair[0]
                    .parse()
                    .map(PortId::Number)
                    .unwrap_or_else(|_| PortId::Name(pair[0].to_owned()))
            } else {
                PortId::Name(pair[0].to_owned())
            };
            Segment::Port {
                port,
                link: Link::Text(pair[1].to_owned()),
            }
        })
        .collect())
}

/// The request path of a class, instance and optional attribute (a zero or empty attribute is omitted).
pub fn request_path(
    class_code: LogicalValue,
    instance: LogicalValue,
    attribute: Option<LogicalValue>,
) -> Result<Vec<u8>> {
    let mut segments = vec![
        Segment::Logical {
            kind: LogicalType::ClassId,
            value: class_code,
        },
        Segment::Logical {
            kind: LogicalType::InstanceId,
            value: instance,
        },
    ];
    if let Some(attribute) = attribute.filter(|a| !a.is_empty_or_zero()) {
        segments.push(Segment::Logical {
            kind: LogicalType::AttributeId,
            value: attribute,
        });
    }
    encode_epath(&segments, true, true, false)
}

fn split_index(part: &str) -> Result<(&str, Vec<LogicalValue>)> {
    let Some(open) = part.find('[') else {
        return Ok((part, Vec::new()));
    };
    let inner = &part[open + 1..part.len().saturating_sub(1).max(open + 1)];
    let mut index = Vec::new();
    for idx in inner.split(',') {
        let text = idx.trim();
        let n = text
            .strip_prefix('+')
            .unwrap_or(text)
            .parse::<i64>()
            .map_err(|_| {
                Error::request(format!("invalid literal for int() with base 10: '{idx}'"))
            })?;
        index.push(LogicalValue::Int(n));
    }
    Ok((&part[..open], index))
}

/// The padded request path of a Logix tag such as `Program:Main.Tag[1,2].Member`. With `use_ids` and a
/// non-zero `instance_id`, the base tag is addressed by its symbol instance ID, else by name.
pub fn tag_request_path(tag: &str, instance_id: Option<u32>, use_ids: bool) -> Result<Vec<u8>> {
    let mut parts: Vec<&str> = tag.split('.').collect();
    let mut segments = Vec::new();
    if parts[0].starts_with("Program:") && parts.len() > 1 {
        segments.push(Segment::Data(DataValue::Symbol(parts[0].to_owned())));
        parts.remove(0);
    }
    let (base, index) = split_index(parts[0])?;
    match instance_id.filter(|&id| use_ids && id != 0) {
        Some(id) => {
            segments.push(Segment::logical(LogicalType::ClassId, 0x6B));
            segments.push(Segment::logical(LogicalType::InstanceId, id));
        }
        None => segments.push(Segment::Data(DataValue::Symbol(base.to_owned()))),
    }
    let member = |value| Segment::Logical {
        kind: LogicalType::MemberId,
        value,
    };
    segments.extend(index.into_iter().map(member));
    for attr in &parts[1..] {
        let (name, index) = split_index(attr)?;
        segments.push(Segment::Data(DataValue::Symbol(name.to_owned())));
        segments.extend(index.into_iter().map(member));
    }
    encode_epath(&segments, true, true, false)
}

/// Wraps a message in an Unconnected Send to the Connection Manager, followed by its route path.
pub fn wrap_unconnected_send(message: &[u8], route_path: &[u8]) -> Vec<u8> {
    let mut out = vec![0x52, 0x02, 0x20, 0x06, 0x24, 0x01, 0x0A, 0x04];
    out.extend((message.len() as u16).to_le_bytes());
    out.extend(message);
    if message.len() % 2 == 1 {
        out.push(0);
    }
    out.extend(route_path);
    out
}

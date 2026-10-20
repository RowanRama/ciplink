//! CIP reply encoding and the faults the request handlers apply.

use std::time::Duration;

/// A CIP reply: reply service, reserved byte, general status, extended status size and words, then data.
pub(crate) fn reply(service: u8, general: u8, extended: &[u16], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 2 * extended.len() + data.len());
    out.extend([service | 0x80, 0, general, extended.len() as u8]);
    for word in extended {
        out.extend(word.to_le_bytes());
    }
    out.extend(data);
    out
}

/// The faults injected into a simulator (see [`crate::Fault`]).
#[derive(Clone, Debug, Default)]
pub(crate) struct Faults {
    pub drop_replies: u32,
    pub delay: Duration,
    pub refuse_connections: bool,
    /// (tag path, general status, extended status)
    pub tags: Vec<(String, u8, Vec<u16>)>,
    /// (service, class or any, general status, extended status)
    pub services: Vec<(u8, Option<u32>, u8, Vec<u16>)>,
}

impl Faults {
    /// The status injected for a service, if any.
    pub(crate) fn service_status(&self, service: u8, class: Option<u32>) -> Option<(u8, Vec<u16>)> {
        self.services
            .iter()
            .find(|(s, c, _, _)| *s == service && (c.is_none() || *c == class))
            .map(|(_, _, general, extended)| (*general, extended.clone()))
    }

    /// The status injected for a request of a tag: its whole path or its base tag.
    pub(crate) fn tag_status(&self, path: &str, base: &str) -> Option<(u8, Vec<u16>)> {
        self.tags
            .iter()
            .find(|(tag, _, _)| tag.eq_ignore_ascii_case(path) || tag.eq_ignore_ascii_case(base))
            .map(|(_, general, extended)| (*general, extended.clone()))
    }
}

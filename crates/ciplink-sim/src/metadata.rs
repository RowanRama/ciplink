//! Logix metadata: extended Descriptions (service 0x53 of class 0x349, answered in pages) and the metadata
//! authentication handshake (services 0x4B and 0x4C of class 0x64).

use ciplink::reader::Reader;

/// The language of configured Descriptions; another language has none.
pub(crate) const LANGUAGE: u16 = 0x007F;

/// What a Description request selects.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Selector {
    /// The Description of one tag, member, element or bit: class 0x6B (controller tag) or 0x68 (program tag),
    /// instance, owner context and the path below the tag (`[0]`, `.1`, `.!TTTTMMMM`).
    One {
        class: u16,
        instance: u32,
        owner: (u32, u16),
        path: String,
        language: u16,
    },
    /// Every Description record of a language (the index, with the members' default Descriptions).
    Index { language: u16 },
}

/// A Description request: the byte offset of the page asked for and the selector.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Request {
    pub offset: u32,
    pub selector: Selector,
}

/// Parses the request data of a Description read (after the request path), None if malformed.
pub(crate) fn parse_request(data: &[u8]) -> Option<Request> {
    let mut r = Reader::new(data);
    let (version, flags, reserved, offset) =
        (r.u8().ok()?, r.u8().ok()?, r.u16().ok()?, r.u32().ok()?);
    if version != 1 || flags != u8::from(offset == 0) || reserved != 0 {
        return None;
    }
    let (kind, all) = (r.u16().ok()?, r.u16().ok()?);
    let selector = match (kind, all) {
        (0x0F, 0xFF) => {
            let (class, instance) = (r.u16().ok()?, r.u32().ok()?);
            let owner = (r.u32().ok()?, r.u16().ok()?);
            let size = usize::from(r.u16().ok()?);
            let path = match size {
                0 => String::new(),
                _ => String::from_utf8(r.take(size).ok()?.to_vec()).ok()?,
            };
            Selector::One {
                class,
                instance,
                owner,
                path,
                language: r.u16().ok()?,
            }
        }
        (0x0C, 0xFF) => Selector::Index {
            language: r.u16().ok()?,
        },
        _ => return None,
    };
    (r.u16().ok()? == 1 && r.is_empty()).then_some(Request { offset, selector })
}

/// A text Description record.
pub(crate) fn record(
    class: u16,
    instance: u32,
    owner: (u32, u16),
    path: &str,
    language: u16,
    text: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(36 + path.len() + text.len());
    out.extend(class.to_le_bytes());
    out.extend(instance.to_le_bytes());
    out.extend(owner.0.to_le_bytes());
    out.extend(owner.1.to_le_bytes());
    // invariant: paths and texts come from the configuration, far below 64 KB
    out.extend((path.len() as u16).to_le_bytes());
    out.extend(path.as_bytes());
    out.extend(language.to_le_bytes());
    out.extend(1u16.to_le_bytes()); // property: Description
    out.extend(1u32.to_le_bytes()); // record ID
    out.extend([0; 12]);
    out.extend(1u16.to_le_bytes()); // kind: text
    out.extend((text.len() as u16).to_le_bytes());
    out.extend(text.as_bytes());
    out
}

/// The page of `payload` at `offset` that fits `room` bytes of reply data: the page header (version 1, flags
/// first 1 and last 2, the offset) then as much payload as fits. None if not even the header and one byte fit
/// (or the header of an empty payload), the caller answers 0x11.
pub(crate) fn page(payload: &[u8], offset: usize, room: usize) -> Option<Vec<u8>> {
    let remaining = payload.len().checked_sub(offset)?;
    let size = remaining.min(room.checked_sub(8)?);
    if size == 0 && remaining > 0 {
        return None;
    }
    let last = size == remaining;
    let flags = u8::from(offset == 0) | (u8::from(last) << 1);
    let mut out = vec![1, flags, 0, 0];
    // invariant: payloads are far below 4 GB
    out.extend((offset as u32).to_le_bytes());
    out.extend(&payload[offset..offset + size]);
    Some(out)
}

/// A metadata challenge (service 0x4B): the reply data and the proof and grants its completion expects.
///
/// The challenge is the RSA ciphertext n - 1, whose plaintext is n - 1 for any private key of the
/// certificate's modulus n (an odd private exponent), so the simulator needs no key. The proof is the SHA-1 of
/// the first 20 bytes of the little-endian plaintext; the grants are the certificate's claims.
pub(crate) fn challenge(certificate: &[u8]) -> Option<(Vec<u8>, [u8; 20], Vec<u8>)> {
    let claims = ciplink::logix::auth::validate_metadata_certificate(certificate).ok()?;
    let key_start = 8 + 4 * claims.len() + 13;
    let modulus = certificate.get(key_start..key_start + 128)?;
    let mut plain: Vec<u8> = modulus.iter().rev().copied().collect(); // little-endian
    for byte in plain.iter_mut() {
        let (value, borrow) = byte.overflowing_sub(1);
        *byte = value;
        if !borrow {
            break;
        }
    }
    let mut reply = vec![0x80, 0x00];
    reply.extend(&plain);
    let mut grants = (claims.len() as u16).to_le_bytes().to_vec();
    for (claim, level) in claims {
        grants.extend(claim.to_le_bytes());
        grants.extend(u32::from(level).to_le_bytes());
    }
    Some((reply, sha1(&plain[..20]), grants))
}

/// SHA-1 (FIPS 180-4), for the proof of the metadata authentication handshake.
pub(crate) fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend(((data.len() as u64) * 8).to_be_bytes());
    for block in message.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            (e, d, c, b, a) = (d, c, b.rotate_left(30), a, t);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 20];
    for (chunk, word) in out.chunks_exact_mut(4).zip(h) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciplink::logix::metadata::{build_description_index_request, build_description_request};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn sha1_matches_known_digests() {
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        let long = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(hex(&sha1(long)), "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
    }

    #[test]
    fn parses_the_requests_ciplink_builds() {
        let wire = build_description_request(0x006B_5ADA, 0x7F, 15, "[2].!0592EF20", 0x68, (8, 0))
            .expect("request");
        // service, path size and the 4-word path to class 0x349 instance 0 come first
        assert_eq!(&wire[..10], &[0x53, 4, 0x21, 0, 0x49, 3, 0x25, 0, 0, 0]);
        assert_eq!(
            parse_request(&wire[10..]),
            Some(Request {
                offset: 15,
                selector: Selector::One {
                    class: 0x68,
                    instance: 0x006B_5ADA,
                    owner: (8, 0),
                    path: "[2].!0592EF20".into(),
                    language: 0x7F
                }
            })
        );
        let index = build_description_index_request(0x0409, 0);
        assert_eq!(
            parse_request(&index[10..]),
            Some(Request {
                offset: 0,
                selector: Selector::Index { language: 0x0409 }
            })
        );
        assert_eq!(parse_request(&index[10..index.len() - 1]), None);
        let tag = build_description_request(425, 0x7F, 0, "", 0x6B, (0, 0)).expect("request");
        assert!(matches!(
            parse_request(&tag[10..]),
            Some(Request { selector: Selector::One { path, .. }, .. }) if path.is_empty()
        ));
    }

    #[test]
    fn pages_split_the_payload_and_mark_first_and_last() {
        let payload: Vec<u8> = (0..20).collect();
        let first = page(&payload, 0, 20).expect("page");
        assert_eq!(&first[..8], &[1, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&first[8..], &payload[..12]);
        let last = page(&payload, 12, 20).expect("page");
        assert_eq!(&last[..8], &[1, 2, 0, 0, 12, 0, 0, 0]);
        assert_eq!(&last[8..], &payload[12..]);
        assert_eq!(page(&[], 0, 8), Some(vec![1, 3, 0, 0, 0, 0, 0, 0]));
        assert_eq!(page(&payload, 0, 8), None);
        assert_eq!(page(&payload, 21, 100), None);
    }
}

//! Extended Descriptions (service 0x53 of class 0x349), the program reference they need, the member IDs of
//! templates, and the metadata authentication handshake, through ciplink's builders, decoders and credentials.
#![allow(clippy::unwrap_used)]

mod common;

use ciplink::logix::auth::LogixMetadataCredentials;
use ciplink::logix::metadata::{
    MetadataValue, TextEncoding, build_description_index_request, build_description_request,
    decode_description_records, decode_metadata_page,
};
use ciplink::packets::generic_message;
use ciplink_sim::{LogixConfig, MemberConfig, ProgramConfig, Simulator, TagConfig, TypeConfig};
use common::{Client, data};

fn config() -> LogixConfig {
    LogixConfig::default()
        .with_type(TypeConfig::udt(
            "Inner",
            [
                MemberConfig::new("Acked", "BOOL").description("Acked default"),
                MemberConfig::new("val", "DINT"),
            ],
        ))
        .with_type(TypeConfig::udt(
            "Outer",
            [MemberConfig::new("Inner", "Inner")],
        ))
        .with_tag(
            TagConfig::new("Array", "DINT")
                .dims(&[30])
                .instance_id(425)
                .description("", "Array text")
                .description("[0]", "Element text")
                .description("[0].1", "Bit text"),
        )
        .with_tag(
            TagConfig::new("Structs", "Inner")
                .dims(&[5])
                .instance_id(657)
                .description("[0].ACKED", "Member text"),
        )
        .with_tag(
            TagConfig::new("Outer", "Outer")
                .instance_id(100)
                .description(".Inner.val", "Nested text"),
        )
        .with_tag(
            TagConfig::new("Long", "DINT")
                .instance_id(5)
                .description("", &"x".repeat(1000)),
        )
        .with_program(ProgramConfig {
            instance_id: Some(155),
            ..ProgramConfig::new("Test").with_tag(
                TagConfig::new("Input", "BOOL")
                    .instance_id(8)
                    .description("", "Program text"),
            )
        })
}

fn sim(config: LogixConfig) -> Simulator {
    Simulator::new(config).unwrap()
}

/// Every page of a Description read from offset 0, as Python's `_pages` reads them.
fn pages(client: &mut Client, build: impl Fn(u32) -> Vec<u8>) -> Vec<Vec<u8>> {
    let mut pages = Vec::new();
    let mut offset = 0;
    loop {
        let reply = client.unit(&build(offset));
        assert_eq!(reply.service_status, Some(0), "{reply:?}");
        let page = data(&reply);
        let (last, size) = {
            let decoded = decode_metadata_page(&page).unwrap();
            assert_eq!(decoded.first, offset == 0);
            assert_eq!(decoded.offset, offset);
            (decoded.last, decoded.data.len())
        };
        pages.push(page);
        if last {
            return pages;
        }
        offset += size as u32;
    }
}

/// The text of the Description at `path` of the tag (class 0x6B, instance) or program tag, None if it has none.
fn text(
    client: &mut Client,
    class: u16,
    instance: u32,
    owner: (u32, u16),
    path: &str,
) -> Option<String> {
    let pages = pages(client, |offset| {
        build_description_request(instance, 0x7F, offset, path, class, owner).unwrap()
    });
    let records = decode_description_records(&pages, Some(TextEncoding::Utf8), None).unwrap();
    assert!(records.len() <= 1);
    records.into_iter().next().map(|record| {
        assert_eq!(
            (
                record.class_id,
                record.instance_id,
                record.owner_context,
                record.path.as_str()
            ),
            (class, instance, owner, path)
        );
        match record.value {
            MetadataValue::Text(text) => text,
            other => panic!("not text: {other:?}"),
        }
    })
}

#[test]
fn descriptions_of_tags_elements_bits_and_members() {
    let sim = sim(config());
    let mut client = Client::connected(&sim, 4000);
    let mut tag = |instance, path: &str| text(&mut client, 0x6B, instance, (0, 0), path);
    assert_eq!(tag(425, "").as_deref(), Some("Array text"));
    assert_eq!(tag(425, "[0]").as_deref(), Some("Element text"));
    assert_eq!(tag(425, "[0].1").as_deref(), Some("Bit text"));
    assert_eq!(tag(425, "[1]"), None); // the driver falls back to the tag's
    // members by template and member ID: Inner is the first user type (0x100), Acked member 1 after its host
    assert_eq!(tag(657, "[0].!0100E001").as_deref(), Some("Member text"));
    assert_eq!(tag(657, "[1].!0100E001"), None);
    assert_eq!(tag(657, "[0].!0101E001"), None); // not Inner's template
    assert_eq!(
        tag(100, ".!0101E000.!0100E002").as_deref(),
        Some("Nested text")
    );
    assert_eq!(tag(5, "").map(|t| t.len()), Some(1000));
}

#[test]
fn template_lists_member_ids_after_the_names() {
    let sim = sim(config());
    let mut client = Client::connected(&sim, 4000);
    // Read Tag of template 0x100 (Inner: a hidden BOOL host, Acked, val)
    let read = generic_message(
        0x4C,
        0x6Cu32.into(),
        0x100u32.into(),
        None,
        &[0, 0, 0, 0, 0xFF, 0],
    )
    .unwrap();
    let template = data(&client.unit(&read));
    let names = b"Inner;n\0ZZZZZZZZZZInner0\0Acked\0val\0";
    let mut expected = names.to_vec();
    expected.resize(expected.len().next_multiple_of(4), 0);
    expected.extend([0x00, 0xE0, 0x01, 0xE0, 0x02, 0xE0]);
    assert_eq!(&template[3 * 8..], &expected[..]);
}

#[test]
fn program_tags_are_described_through_the_program_reference() {
    let sim = sim(config());
    let mut client = Client::connected(&sim, 4000);
    // attribute 0x0D of the program's symbol: a path to its program object (class 0x68)
    let reference =
        generic_message(0x03, 0x6Bu32.into(), 155u32.into(), None, &[1, 0, 0x0D, 0]).unwrap();
    let reply = data(&client.unit(&reference));
    assert_eq!(&reply[..11], &[1, 0, 0x0D, 0, 0, 0, 3, 0x20, 0x68, 0x25, 0]);
    let program = u32::from(u16::from_le_bytes([reply[11], reply[12]]));
    let instance = (0x6B << 16) | program;
    assert_eq!(
        text(&mut client, 0x68, instance, (8, 0), "").as_deref(),
        Some("Program text")
    );
    // a controller tag of the same instance ID is another object
    let reply = client.unit(&build_description_request(8, 0x7F, 0, "", 0x6B, (0, 0)).unwrap());
    assert_eq!(reply.service_status, Some(0x05));
    // other attributes and other symbols have no reference
    let other =
        generic_message(0x03, 0x6Bu32.into(), 425u32.into(), None, &[1, 0, 0x0D, 0]).unwrap();
    assert_eq!(data(&client.unit(&other)), [1, 0, 0x0D, 0, 0x14, 0]);
}

#[test]
fn index_lists_member_defaults_of_the_language() {
    let sim = sim(config());
    let mut client = Client::connected(&sim, 4000);
    let pages = pages(&mut client, |offset| {
        build_description_index_request(0x7F, offset)
    });
    let records = decode_description_records(&pages, None, None).unwrap();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(
        (
            record.class_id,
            record.instance_id & 0xFFFF,
            record.owner_context,
            record.path.as_str()
        ),
        (0x6C, 0x100, (0xE001, 0), "")
    );
    assert_eq!(record.value, MetadataValue::Raw(b"Acked default".to_vec()));
    let other = pages_of_language(&mut client, 0x0409);
    assert!(
        decode_description_records(&other, None, None)
            .unwrap()
            .is_empty()
    );
}

fn pages_of_language(client: &mut Client, language: u16) -> Vec<Vec<u8>> {
    pages(client, |offset| {
        build_description_index_request(language, offset)
    })
}

#[test]
fn long_descriptions_are_paged_by_the_connection_size() {
    let sim = sim(config());
    let mut client = Client::connected(&sim, 504);
    let pages = pages(&mut client, |offset| {
        build_description_request(5, 0x7F, offset, "", 0x6B, (0, 0)).unwrap()
    });
    assert!(pages.len() > 2);
    assert!(pages.iter().all(|p| p.len() <= 504 - 2 - 4));
    // in a multi-service packet the first page fits the room the other replies leave
    let request = build_description_request(5, 0x7F, 0, "", 0x6B, (0, 0)).unwrap();
    let mut messages = vec![common::read("Array", 30); 3];
    messages.push(request);
    let reply = client.multi(&messages);
    let last = reply.replies.last().unwrap();
    assert_eq!(last.service_status, Some(0));
    let page = data(last);
    let page = decode_metadata_page(&page).unwrap();
    assert!(page.first && !page.last && !page.data.is_empty() && page.data.len() < 120);
}

#[test]
fn bad_requests_are_refused() {
    let sim = sim(config());
    let mut client = Client::connected(&sim, 4000);
    let mut request = build_description_request(425, 0x7F, 0, "", 0x6B, (0, 0)).unwrap();
    request.pop();
    assert_eq!(client.unit(&request).service_status, Some(0x13));
    let beyond = build_description_request(425, 0x7F, 1000, "", 0x6B, (0, 0)).unwrap();
    assert_eq!(client.unit(&beyond).service_status, Some(0xFF));
    let unknown = build_description_request(4242, 0x7F, 0, "", 0x6B, (0, 0)).unwrap();
    assert_eq!(client.unit(&unknown).service_status, Some(0x05));
    let micro = Simulator::new(
        LogixConfig::micro800().with_tag(TagConfig::new("Array", "DINT").instance_id(425)),
    )
    .unwrap();
    // a Micro800 has no metadata object
    let mut client = Client::connected(&micro, 500);
    let request = build_description_request(425, 0x7F, 0, "", 0x6B, (0, 0)).unwrap();
    assert_eq!(client.unit(&request).service_status, Some(0x05));
}

fn authenticated(sim: &Simulator, credentials: &LogixMetadataCredentials) -> Client {
    let mut client = Client::connected(sim, 4000);
    let challenge = client.unit(
        &generic_message(
            0x4B,
            0x64u32.into(),
            1u32.into(),
            None,
            credentials.certificate(),
        )
        .unwrap(),
    );
    assert_eq!(challenge.service_status, Some(0));
    let proof = credentials.answer_challenge(&data(&challenge)).unwrap();
    let completion = client.unit(
        &generic_message(
            0x4C,
            0x64u32.into(),
            1u32.into(),
            None,
            &[&[0x14, 0][..], &proof].concat(),
        )
        .unwrap(),
    );
    assert_eq!(completion.service_status, Some(0));
    credentials.validate_completion(&data(&completion)).unwrap();
    client
}

#[test]
fn metadata_authentication_unlocks_descriptions_per_connection() {
    let sim = sim(LogixConfig {
        metadata_auth: true,
        ..config()
    });
    let description = build_description_request(425, 0x7F, 0, "", 0x6B, (0, 0)).unwrap();
    let mut other = Client::connected(&sim, 4000);
    assert_eq!(other.unit(&description).service_status, Some(0x0F));
    let credentials = LogixMetadataCredentials::bundled().unwrap();
    let mut client = authenticated(&sim, &credentials);
    assert_eq!(
        text(&mut client, 0x6B, 425, (0, 0), "").as_deref(),
        Some("Array text")
    );
    // only the connection that authenticated
    assert_eq!(other.unit(&description).service_status, Some(0x0F));
    // unconnected: refused
    assert_eq!(other.rr(&description).service_status, Some(0x0F));
}

#[test]
fn metadata_authentication_rejects_a_wrong_proof_or_no_challenge() {
    let sim = sim(LogixConfig {
        metadata_auth: true,
        ..config()
    });
    let credentials = LogixMetadataCredentials::bundled().unwrap();
    let mut client = Client::connected(&sim, 4000);
    let complete = |proof: &[u8]| {
        generic_message(
            0x4C,
            0x64u32.into(),
            1u32.into(),
            None,
            &[&[0x14, 0][..], proof].concat(),
        )
        .unwrap()
    };
    assert_eq!(client.unit(&complete(&[0; 20])).service_status, Some(0x0C));
    let challenge = generic_message(
        0x4B,
        0x64u32.into(),
        1u32.into(),
        None,
        credentials.certificate(),
    )
    .unwrap();
    assert_eq!(client.unit(&challenge).service_status, Some(0));
    assert_eq!(client.unit(&complete(&[0; 20])).service_status, Some(0x0F));
    // the challenge is used up
    let proof = credentials
        .answer_challenge(&data(&client.unit(&challenge)))
        .unwrap();
    assert_eq!(client.unit(&complete(&proof)).service_status, Some(0));
    assert_eq!(client.unit(&complete(&proof)).service_status, Some(0x0C));
    // a certificate that is not one
    let bad = generic_message(0x4B, 0x64u32.into(), 1u32.into(), None, &[0; 10]).unwrap();
    assert_eq!(client.unit(&bad).service_status, Some(0x0F));
    // unconnected: not supported
    assert_eq!(client.rr(&challenge).service_status, Some(0x08));
}

//! Metadata, authentication and credential-bundle parity with the reference Python driver:
//! tools/fixtures/gen_metadata_auth.py writes fixtures/metadata_auth.json.
#![allow(clippy::unwrap_used)]

mod common;

use ciplink::Error;
use ciplink::logix::auth::{LogixMetadataCredentials, validate_metadata_certificate};
use ciplink::logix::bundle::{
    bundled_credentials, load_bundled, open_credentials, seal_credentials,
};
use ciplink::logix::metadata::{
    DefinitionField, DescriptionRecord, MetadataValue, TextEncoding, assemble_metadata_pages,
    build_description_index_request, build_description_request, decode_definition_response,
    decode_description_records, decode_description_response, decode_metadata_page,
};
use common::*;
use serde_json::Value as Json;
use sha1::{Digest, Sha1};

/// asserts an Err matches {"err": class, "msg": text}: ValueError is a RequestError here
fn assert_err(err: &Error, expected: &Json, ctx: &str) {
    let want = expected["err"]
        .as_str()
        .unwrap_or_else(|| panic!("{ctx}: unexpected error {err:?}"));
    let want = if want == "ValueError" {
        "RequestError"
    } else {
        want
    };
    assert_eq!(class(err), want, "{ctx}");
    assert_eq!(err.to_string(), expected["msg"].as_str().unwrap(), "{ctx}");
}

/// Ok values go to `ok`, errors must match class and message
fn verify<T: std::fmt::Debug>(
    result: Result<T, Error>,
    expected: &Json,
    ctx: &str,
    ok: impl FnOnce(&T, &Json),
) {
    match (&result, expected.get("ok")) {
        (Ok(value), Some(want)) => ok(value, want),
        (Err(err), None) => assert_err(err, expected, ctx),
        _ => panic!("{ctx}: got {result:?}, expected {expected}"),
    }
}

fn int(json: &Json) -> i128 {
    json["int"]
        .as_i64()
        .map(i128::from)
        .unwrap_or_else(|| json["int"].as_u64().unwrap().into())
}

fn plain_int(json: &Json) -> i128 {
    json.as_i64()
        .map(i128::from)
        .unwrap_or_else(|| json.as_u64().unwrap().into())
}

/// a tagged {"dict": [[k, v], ..]} as a lookup
fn dict(json: &Json) -> Vec<(String, Json)> {
    json["dict"]
        .as_array()
        .unwrap()
        .iter()
        .map(|kv| (kv[0].as_str().unwrap().to_owned(), kv[1].clone()))
        .collect()
}

fn get<'a>(map: &'a [(String, Json)], key: &str) -> &'a Json {
    &map.iter()
        .find(|(k, _)| k == key)
        .unwrap_or_else(|| panic!("no {key}"))
        .1
}

fn ints(json: &Json) -> Vec<i128> {
    json["list"].as_array().unwrap().iter().map(int).collect()
}

fn pages(case: &Json) -> Vec<Vec<u8>> {
    case["pages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| hex(p.as_str().unwrap()))
        .collect()
}

fn encoding(json: &Json) -> Option<TextEncoding> {
    Some(match json.as_str()? {
        "utf-8" => TextEncoding::Utf8,
        "ascii" => TextEncoding::Ascii,
        "latin-1" => TextEncoding::Latin1,
        "cp1252" => TextEncoding::Cp1252,
        other => panic!("encoding {other}"),
    })
}

fn assert_metadata_value(value: &MetadataValue, record: &[(String, Json)], ctx: &str) {
    let want = get(record, "value");
    match value {
        MetadataValue::Text(text) => assert_eq!(text, want["str"].as_str().unwrap(), "{ctx}"),
        MetadataValue::Raw(raw) => {
            assert_eq!(to_hex(raw), want["bytes"].as_str().unwrap(), "{ctx}")
        }
        MetadataValue::None => assert!(want.is_null(), "{ctx}"),
        MetadataValue::Atomic { type_code, values } => {
            assert_eq!(
                i128::from(*type_code),
                int(get(record, "type_code")),
                "{ctx}"
            );
            assert_value(&ciplink::Value::Array(values.clone()), want, ctx);
        }
    }
}

fn fixture() -> Json {
    load("metadata_auth.json")
}

#[test]
fn description_request_matches_python() {
    let fixture = fixture();
    for case in cases(&fixture, "description_request") {
        let ctx = case["args"].to_string();
        let args = &case["args"];
        let arg = |key: &str, default: i128| args.get(key).map_or(default, plain_int);
        let owner = args
            .get("owner_context")
            .map_or((0, 0), |o| (plain_int(&o[0]), plain_int(&o[1])));
        let path = match args.get("path_repeat") {
            Some(repeat) => repeat[0]
                .as_str()
                .unwrap()
                .repeat(repeat[1].as_u64().unwrap() as usize),
            None => args
                .get("path")
                .map_or("", |p| p.as_str().unwrap())
                .to_owned(),
        };
        let typed = (
            u32::try_from(arg("instance_id", 0)),
            u16::try_from(arg("language", 0x7F)),
            u32::try_from(arg("offset", 0)),
            u16::try_from(arg("class_id", 0x6B)),
            u32::try_from(owner.0),
            u16::try_from(owner.1),
        );
        let (Ok(instance), Ok(language), Ok(offset), Ok(class_id), Ok(o0), Ok(o1)) = typed else {
            assert_eq!(case["result"]["err"], "ValueError", "{ctx}"); // not representable in Rust's types
            continue;
        };
        let result =
            build_description_request(instance, language, offset, &path, class_id, (o0, o1));
        if let Some(digest) = case["result"].get("ok_sha1") {
            assert_eq!(
                to_hex(&Sha1::digest(result.unwrap())),
                digest.as_str().unwrap(),
                "{ctx}"
            );
            continue;
        }
        verify(result, &case["result"], &ctx, |bytes, want| {
            assert_eq!(to_hex(bytes), want["bytes"].as_str().unwrap(), "{ctx}")
        });
    }
}

#[test]
fn description_index_request_matches_python() {
    let fixture = fixture();
    for case in cases(&fixture, "index_request") {
        let ctx = case.to_string();
        let language = u16::try_from(plain_int(&case["language"]));
        let offset = u32::try_from(plain_int(&case["offset"]));
        let (Ok(language), Ok(offset)) = (language, offset) else {
            assert_eq!(case["result"]["err"], "ValueError", "{ctx}");
            continue;
        };
        let bytes = build_description_index_request(language, offset);
        assert_eq!(
            to_hex(&bytes),
            case["result"]["ok"]["bytes"].as_str().unwrap(),
            "{ctx}"
        );
    }
}

#[test]
fn metadata_page_matches_python() {
    let fixture = fixture();
    for case in cases(&fixture, "page") {
        let ctx = case.to_string();
        let raw = hex(case["raw"].as_str().unwrap());
        verify(
            decode_metadata_page(&raw),
            &case["result"],
            &ctx,
            |page, want| {
                let want = dict(want);
                assert_eq!(
                    page.first,
                    get(&want, "first")["bool"].as_bool().unwrap(),
                    "{ctx}"
                );
                assert_eq!(
                    page.last,
                    get(&want, "last")["bool"].as_bool().unwrap(),
                    "{ctx}"
                );
                assert_eq!(i128::from(page.offset), int(get(&want, "offset")), "{ctx}");
                assert_eq!(
                    to_hex(page.data),
                    get(&want, "data")["bytes"].as_str().unwrap(),
                    "{ctx}"
                );
            },
        );
    }
}

#[test]
fn assemble_pages_matches_python() {
    let fixture = fixture();
    for case in cases(&fixture, "assemble") {
        let ctx = case.to_string();
        verify(
            assemble_metadata_pages(&pages(case)),
            &case["result"],
            &ctx,
            |data, want| assert_eq!(to_hex(data), want["bytes"].as_str().unwrap(), "{ctx}"),
        );
    }
}

fn assert_field(field: &DefinitionField, want: &Json, ctx: &str) {
    let want = dict(want);
    assert_eq!(i128::from(field.kind), int(get(&want, "kind")), "{ctx}");
    assert_eq!(
        to_hex(&field.raw_value),
        get(&want, "raw_value_hex")["str"].as_str().unwrap(),
        "{ctx}"
    );
    let context: Vec<i128> = field.context.iter().map(|&c| c.into()).collect();
    assert_eq!(context, ints(get(&want, "context")), "{ctx}");
    assert_metadata_value(&field.value, &want, ctx);
}

#[test]
fn definition_response_matches_python() {
    let fixture = fixture();
    for case in cases(&fixture, "definition") {
        let ctx = format!("{} {}", case["encoding"], case["pages"]);
        let result = decode_definition_response(&pages(case), encoding(&case["encoding"]));
        verify(result, &case["result"], &ctx, |fields, want| {
            let want = dict(want);
            let keys: Vec<String> = fields.keys().map(u16::to_string).collect();
            let want_keys: Vec<String> = want.iter().map(|(k, _)| k.clone()).collect();
            assert_eq!(keys, want_keys, "{ctx}");
            for (id, field) in fields {
                assert_field(field, get(&want, &id.to_string()), &ctx);
            }
        });
    }
}

fn assert_record(record: &DescriptionRecord, want: &Json, ctx: &str) {
    let want = dict(want);
    let number = |key: &str| int(get(&want, key));
    assert_eq!(i128::from(record.kind), number("kind"), "{ctx}");
    assert_eq!(i128::from(record.class_id), number("class_id"), "{ctx}");
    assert_eq!(
        i128::from(record.instance_id),
        number("instance_id"),
        "{ctx}"
    );
    assert_eq!(i128::from(record.language), number("language"), "{ctx}");
    assert_eq!(
        i128::from(record.property_id),
        number("property_id"),
        "{ctx}"
    );
    assert_eq!(i128::from(record.record_id), number("record_id"), "{ctx}");
    let owner = vec![
        i128::from(record.owner_context.0),
        i128::from(record.owner_context.1),
    ];
    assert_eq!(owner, ints(get(&want, "owner_context")), "{ctx}");
    let context: Vec<i128> = record.context.iter().map(|&c| c.into()).collect();
    assert_eq!(context, ints(get(&want, "context")), "{ctx}");
    assert_eq!(
        record.path,
        get(&want, "path")["str"].as_str().unwrap(),
        "{ctx}"
    );
    assert_eq!(
        to_hex(&record.raw_value),
        get(&want, "raw_value_hex")["str"].as_str().unwrap(),
        "{ctx}"
    );
    assert_metadata_value(&record.value, &want, ctx);
}

#[test]
fn description_response_matches_python() {
    let fixture = fixture();
    for case in cases(&fixture, "description_response") {
        let ctx = format!("{} {}", case["encoding"], case["pages"]);
        let result = decode_description_response(&pages(case), encoding(&case["encoding"]));
        verify(result, &case["result"], &ctx, |record, want| match record {
            None => assert!(want.is_null(), "{ctx}"),
            Some(record) => assert_record(record, want, &ctx),
        });
    }
}

#[test]
fn description_records_match_python() {
    let fixture = fixture();
    for case in cases(&fixture, "description_records") {
        let ctx = format!(
            "{} {} {}",
            case["encoding"], case["max_records"], case["pages"]
        );
        let max = case["max_records"].as_u64().map(|m| m as usize);
        let result = decode_description_records(&pages(case), encoding(&case["encoding"]), max);
        verify(result, &case["result"], &ctx, |records, want| {
            let want = want["list"].as_array().unwrap();
            assert_eq!(records.len(), want.len(), "{ctx}");
            for (record, want) in records.iter().zip(want) {
                assert_record(record, want, &ctx);
            }
        });
    }
}

#[test]
fn certificate_validation_matches_python() {
    let fixture = fixture();
    for case in cases(&fixture, "certificate") {
        let ctx = case["certificate"].to_string();
        let certificate = hex(case["certificate"].as_str().unwrap());
        verify(
            validate_metadata_certificate(&certificate),
            &case["result"],
            &ctx,
            |claims, want| {
                let want: Vec<Vec<i128>> =
                    want["list"].as_array().unwrap().iter().map(ints).collect();
                let claims: Vec<Vec<i128>> = claims
                    .iter()
                    .map(|&(c, l)| vec![c.into(), l.into()])
                    .collect();
                assert_eq!(claims, want, "{ctx}");
            },
        );
    }
}

#[test]
fn credential_checks_match_python() {
    let fixture = fixture();
    for case in cases(&fixture, "credentials") {
        let ctx = format!("{} {}", case["certificate"], case["key"]);
        let certificate = hex(case["certificate"].as_str().unwrap());
        let key = hex(case["key"].as_str().unwrap());
        let result = LogixMetadataCredentials::new(&certificate, &key);
        verify(result, &case["result"], &ctx, |creds, _| {
            assert_eq!(creds.certificate(), certificate.as_slice(), "{ctx}")
        });
    }
}

fn synthetic(format: &str) -> LogixMetadataCredentials {
    let fixture = fixture();
    let certificate = hex(fixture["synthetic"]["certificate"].as_str().unwrap());
    let key = hex(fixture["synthetic"][format].as_str().unwrap());
    LogixMetadataCredentials::new(&certificate, &key).unwrap()
}

#[test]
fn challenge_proofs_match_python_for_both_key_formats() {
    let fixture = fixture();
    for format in ["pkcs1", "pkcs8"] {
        let creds = synthetic(format);
        for case in cases(&fixture, "challenge") {
            let ctx = format!("{format} {}", case["data"]);
            let data = hex(case["data"].as_str().unwrap());
            // blinding is random; the proof must not depend on it
            for _ in 0..2 {
                verify(
                    creds.answer_challenge(&data),
                    &case["result"],
                    &ctx,
                    |proof, want| {
                        assert_eq!(to_hex(proof), want["bytes"].as_str().unwrap(), "{ctx}")
                    },
                );
            }
        }
    }
}

#[test]
fn completion_checks_match_python() {
    let fixture = fixture();
    let creds = synthetic("pkcs1");
    for case in cases(&fixture, "completion") {
        let ctx = case["data"].to_string();
        let data = hex(case["data"].as_str().unwrap());
        verify(
            creds.validate_completion(&data),
            &case["result"],
            &ctx,
            |_, want| assert!(want.is_null(), "{ctx}"),
        );
    }
}

#[test]
fn debug_output_redacts_the_key() {
    let creds = synthetic("pkcs1");
    assert_eq!(format!("{creds:?}"), "LogixMetadataCredentials(<redacted>)");
    assert_eq!(
        format!("{:?}", bundled_credentials().unwrap()),
        "LogixMetadataCredentials(<redacted>)"
    );
}

#[test]
fn bundle_open_matches_python() {
    let fixture = fixture();
    for case in cases(&fixture, "bundle") {
        let bundle = match case.get("bundle_pad") {
            Some(pad) => {
                let mut bundle = hex(pad[0].as_str().unwrap());
                bundle.resize(pad[1].as_u64().unwrap() as usize, 0);
                bundle
            }
            None => hex(case["bundle"].as_str().unwrap()),
        };
        let ctx = format!("{} {}", to_hex(&bundle), case["key"]);
        let key: [u8; 32] = hex(case["key"].as_str().unwrap()).try_into().unwrap();
        verify(
            open_credentials(&bundle, &key),
            &case["result"],
            &ctx,
            |(cert, private), want| {
                let want = want["list"].as_array().unwrap();
                assert_eq!(to_hex(cert), want[0]["bytes"].as_str().unwrap(), "{ctx}");
                assert_eq!(to_hex(private), want[1]["bytes"].as_str().unwrap(), "{ctx}");
            },
        );
    }
}

#[test]
fn bundle_roundtrip_uses_a_fresh_nonce_and_hides_the_plaintext() {
    let fixture = fixture();
    let certificate = hex(fixture["synthetic"]["certificate"].as_str().unwrap());
    let private = hex(fixture["synthetic"]["pkcs1"].as_str().unwrap());
    let key: [u8; 32] = std::array::from_fn(|i| i as u8);
    let first = seal_credentials(&certificate, &private, &key).unwrap();
    let second = seal_credentials(&certificate, &private, &key).unwrap();
    assert_ne!(first, second);
    assert!(
        !first
            .windows(private.len())
            .any(|w| w == private.as_slice())
    );
    let (cert, opened) = open_credentials(&first, &key).unwrap();
    assert_eq!((cert, opened), (certificate.clone(), private.clone()));
    let wrong: [u8; 32] = std::array::from_fn(|i| 31 - i as u8);
    assert_eq!(
        open_credentials(&first, &wrong).unwrap_err().to_string(),
        "Credential bundle authentication failed"
    );
    for position in [0, 4, 16, first.len() - 1] {
        let mut tampered = first.clone();
        tampered[position] ^= 1;
        assert!(open_credentials(&tampered, &key).is_err(), "{position}");
    }
    assert!(seal_credentials(&certificate[..280], &private, &key).is_err());
}

#[test]
fn bundled_credentials_equal_python() {
    let fixture = fixture();
    let want = &fixture["bundled"];
    let (certificate, private) = load_bundled().unwrap();
    assert_eq!(
        to_hex(&Sha1::digest(&certificate)),
        want["certificate_sha1"].as_str().unwrap()
    );
    assert_eq!(
        to_hex(&Sha1::digest(&private)),
        want["key_sha1"].as_str().unwrap()
    );
    let creds = LogixMetadataCredentials::bundled().unwrap();
    assert_eq!(creds.certificate(), certificate.as_slice());
    let claims: Vec<Vec<i64>> = validate_metadata_certificate(&certificate)
        .unwrap()
        .iter()
        .map(|&(c, l)| vec![c.into(), l.into()])
        .collect();
    let want_claims: Vec<Vec<i64>> = serde_json::from_value(want["claims"].clone()).unwrap();
    assert_eq!(claims, want_claims);
}

#[test]
fn description_capture_decodes() {
    let capture: Json = serde_json::from_str(
        &std::fs::read_to_string(format!(
            "{}/../../tools/reference/tests/offline/logix_metadata_capture.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    let desc = &capture["description"];
    let request = build_description_request(1063, 0x7F, 0, "", 0x6B, (0, 0)).unwrap();
    assert_eq!(to_hex(&request), desc["request_cip_hex"].as_str().unwrap());
    let page = hex(desc["page_hex"].as_str().unwrap());
    let record = decode_description_response(&[page], Some(TextEncoding::Utf8))
        .unwrap()
        .unwrap();
    assert_eq!(record.value, MetadataValue::Text("HERE I AM WORLD".into()));
    assert_eq!(
        (record.instance_id, record.class_id, record.record_id),
        (1063, 0x6B, 4465)
    );
    for definition in capture["definitions"].as_array().unwrap() {
        let pages: Vec<Vec<u8>> = definition["pages_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| hex(p.as_str().unwrap()))
            .collect();
        let fields = decode_definition_response(&pages, Some(TextEncoding::Utf8)).unwrap();
        assert_eq!(
            fields[&9].value,
            MetadataValue::Text(definition["name"].as_str().unwrap().into())
        );
        let mut ids: Vec<u16> = fields.keys().copied().collect();
        ids.sort_unstable();
        assert_eq!(ids, (8..25).chain([43]).collect::<Vec<u16>>());
        assert!(
            matches!(&fields[&19].value, MetadataValue::Atomic { type_code: 0xC3, values } if values.len() == 2)
        );
    }
}

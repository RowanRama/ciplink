//! Tag Descriptions and metadata authentication parity with the Python LogixDriver (fixtures from
//! tools/fixtures/gen_logix_descriptions.py): the scenarios of tools/reference/tests/offline/test_logix_descriptions.py and the
//! driver parts of test_logix_metadata.py and test_logix_auth.py, replayed against the scripted fake transport:
//! the same frames (tag upload included), the same results, errors, kinds and statuses.
#![allow(clippy::unwrap_used)]

mod common;

use ciplink::cip::TagResult;
use ciplink::logix::auth::LogixMetadataCredentials;
use ciplink::logix::descriptions::DEFAULT_LANGUAGE;
use ciplink::logix::driver::{LogixDriver, LogixOptions};
use ciplink::logix::metadata::TextEncoding;
use ciplink::{Error, ErrorKind, Value};
use common::fake::Fake;
use common::{class, hex, to_hex};
use serde_json::{Value as Json, json};

/// zeroes the random connection triad of Forward Open / Forward Close requests
fn mask_triad(frame: &[u8]) -> Vec<u8> {
    let mut f = frame.to_vec();
    if f.first() == Some(&0x6F) && f.len() >= 56 {
        match f[40] {
            0x54 | 0x5B if f.len() >= 64 => {
                f[52..58].fill(0);
                f[60..64].fill(0);
            }
            0x4E => {
                f[48..50].fill(0);
                f[52..56].fill(0);
            }
            _ => {}
        }
    }
    f
}

fn encoding(name: &str) -> TextEncoding {
    match name {
        "utf-8" => TextEncoding::Utf8,
        "ascii" => TextEncoding::Ascii,
        "latin-1" => TextEncoding::Latin1,
        "cp1252" => TextEncoding::Cp1252,
        other => panic!("encoding {other}"),
    }
}

fn options(json: &Json) -> LogixOptions {
    let mut o = LogixOptions::default();
    for (k, v) in json.as_object().unwrap() {
        match k.as_str() {
            "init_program_tags" => o.init_program_tags = v.as_bool().unwrap(),
            "lazy_tags" => o.lazy_tags = v.as_bool().unwrap(),
            "connection_size" => o.cip.connection_size = v.as_u64().unwrap() as u16,
            other => panic!("option {other}"),
        }
    }
    o
}

/// a result as the fixture writes Python's Tag
fn tag_json(t: &TagResult) -> Json {
    let value = match &t.value {
        None => Json::Null,
        Some(Value::String(s)) => json!(s),
        Some(Value::Bool(b)) => json!(b),
        Some(other) => panic!("value {other:?}"),
    };
    let e = t.error.as_ref();
    json!({
        "tag": t.tag,
        "value": value,
        "type": t.data_type,
        "error": e.map(|e| e.message.clone()),
        "kind": e.map(|e| e.kind.as_str()),
        "status": e.and_then(|e| e.status),
        "ext": e.and_then(|e| e.ext),
    })
}

fn outcome(result: ciplink::Result<Json>) -> Json {
    match result {
        Ok(v) => json!({ "ok": v }),
        Err(err) => {
            let mut out = json!({ "err": class(&err), "msg": err.to_string() });
            if let Some(kind) = err.carried_kind() {
                out["kind"] = json!(kind.as_str());
            }
            out
        }
    }
}

fn run_scenario(case: &Json, credentials: &LogixMetadataCredentials) {
    let name = case["name"].as_str().unwrap();
    let fake = Fake::new();
    for reply in case["replies"].as_array().unwrap() {
        match reply.as_str() {
            Some(r) => fake.reply(hex(r)),
            None => fake.reply_err(Error::comm("connection lost")),
        };
    }
    let driver =
        LogixDriver::with_connector("1.2.3.4", options(&case["options"]), fake.connector())
            .unwrap();
    let steps = case["steps"].as_array().unwrap();
    let results = case["results"].as_array().unwrap();
    for (i, (step, want)) in steps.iter().zip(results).enumerate() {
        let ctx = format!("{name}[{i}] {step}");
        let got = match step["call"].as_str().unwrap() {
            "edit" | "fail_receive" => None, // in the recorded replies
            "open" => Some(outcome(driver.open().map(|b| json!({ "bool": b })))),
            "close" => Some(outcome(driver.close().map(|_| Json::Null))),
            "desc" => {
                let names: Vec<&str> = step["names"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|n| n.as_str().unwrap())
                    .collect();
                let language = step["language"].as_u64().unwrap() as u16;
                let encoding = encoding(step["encoding"].as_str().unwrap());
                let result = if names.len() == 1 {
                    driver
                        .get_tag_description(names[0], language, encoding)
                        .map(|t| vec![t])
                } else {
                    driver.get_tag_descriptions(&names, language, encoding)
                };
                Some(outcome(result.map(|tags| {
                    Json::Array(tags.iter().map(tag_json).collect())
                })))
            }
            "auth" => {
                let creds = match step["credentials"].as_str().unwrap() {
                    "synthetic" => Some(credentials),
                    "bundled" => None,
                    other => panic!("credentials {other}"),
                };
                Some(json!({ "ok": tag_json(&driver.authenticate_metadata(creds)) }))
            }
            other => panic!("step {other}"),
        };
        match (got, want.is_null()) {
            (None, true) => {}
            (Some(got), false) => assert_eq!(&got, want, "{ctx}"),
            (got, _) => panic!("{ctx}: step result {got:?}, expected {want}"),
        }
    }
    let sent: Vec<String> = fake.sent().iter().map(|f| to_hex(&mask_triad(f))).collect();
    let want: Vec<String> = case["sent"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| to_hex(&mask_triad(&hex(f.as_str().unwrap()))))
        .collect();
    for (i, (s, w)) in sent.iter().zip(&want).enumerate() {
        assert_eq!(s, w, "{name}: frame {i}");
    }
    assert_eq!(sent.len(), want.len(), "{name}: frame count");
    assert_eq!(fake.pending(), 0, "{name}: replies left");
}

fn fixture() -> Json {
    common::load("logix_descriptions.json")
}

fn synthetic(fixture: &Json) -> LogixMetadataCredentials {
    let creds = &fixture["credentials"];
    LogixMetadataCredentials::new(
        &hex(creds["certificate"].as_str().unwrap()),
        &hex(creds["key"].as_str().unwrap()),
    )
    .unwrap()
}

fn scenarios(names: &[&str]) {
    let fixture = fixture();
    let credentials = synthetic(&fixture);
    for name in names {
        let case = common::cases(&fixture, "scenarios")
            .iter()
            .find(|c| c["name"] == *name)
            .unwrap_or_else(|| panic!("no scenario {name}"));
        run_scenario(case, &credentials);
    }
}

const COVERED: &[&str] = &[
    "elements",
    "program_tag",
    "invalid_program_references",
    "udt_members",
    "duplicate_member_defaults",
    "member_index_failures",
    "short_template_identifiers",
    "wrong_targets",
    "paging",
    "invalid_addresses",
    "matrix",
    "statuses",
    "batch",
    "batch_own_texts",
    "no_room",
    "small_connection",
    "connection_drop_in_batch",
    "connection_drop_second_round",
    "connection_drop_in_fallback",
    "connection_drop_single",
    "languages",
    "member_default_encodings",
    "lazy_tags",
    "lazy_program_reference",
    "micro800",
    "lazy_reopen",
    "resolve_comm_failures",
    "member_identifier_continuation_failure",
    "auth",
    "auth_connection_drop",
];

#[test]
fn element_and_bit_descriptions_fall_back_like_python() {
    // test_array_element_has_its_own_description, ..._inherits_base_description, test_empty_element_description_
    // is_preserved, test_element_bit_description, test_multidimensional_bounds; test_logix_metadata.py's
    // test_reader_decodes_the_capture and ..._reports_missing_language
    scenarios(&["elements", "matrix"]);
}

#[test]
fn program_tags_read_their_program_reference_once_per_connection() {
    // test_program_tag_does_not_read_controller_symbol_with_same_id, ..._description_cache_is_connection_specific,
    // test_program_reference_cache_reuses_identical_scope, test_program_reference_formats,
    // test_invalid_program_reference_returns_an_error, plus the lazy tags lookups of the program symbol
    scenarios(&[
        "program_tag",
        "invalid_program_references",
        "lazy_tags",
        "lazy_program_reference",
    ]);
}

#[test]
fn udt_members_use_overrides_template_defaults_and_elements_like_python() {
    // test_udt_member_override, ..._default_and_index_cache, test_index_handles_other_binary_text_and_removed_
    // records, test_udt_member_falls_back_to_element_description, test_duplicate_member_defaults_return_an_error,
    // test_template_identifier_continuation, test_nested_udt_member, test_program_member_array
    scenarios(&[
        "udt_members",
        "duplicate_member_defaults",
        "member_index_failures",
        "short_template_identifiers",
    ]);
}

#[test]
fn replies_are_checked_and_paged_like_python() {
    // test_wrong_element_target_is_rejected, test_path_fragmentation, test_permission_denied_does_not_fall_back,
    // test_logix_metadata.py's test_reader_handles_continuations, ..._rejects_mismatched_target and
    // ..._preserves_permission_denied_and_does_not_retry
    scenarios(&[
        "wrong_targets",
        "paging",
        "statuses",
        "languages",
        "member_default_encodings",
    ]);
}

#[test]
fn invalid_addresses_send_nothing() {
    // test_invalid_addresses_do_not_send_requests, test_array_member_requires_an_element,
    // test_logix_metadata.py's test_reader_rejects_unsupported_tag_addresses_without_a_read
    scenarios(&["invalid_addresses"]);
}

#[test]
fn batches_pack_rounds_like_python() {
    // test_batch_equals_sequential_reads, test_identical_requests_are_sent_once, test_one_packet_per_round,
    // test_batch_continues_a_paged_reply_on_its_own, test_requests_without_room_in_the_packet_are_read_alone,
    // test_shared_less_specific_candidate_and_its_error
    scenarios(&["batch", "batch_own_texts", "no_room", "small_connection"]);
}

#[test]
fn connection_failures_end_the_unfinished_tags_like_python() {
    // test_connection_change_discards_reply, test_connection_change_discards_batch,
    // test_connection_change_keeps_the_tags_finished_in_earlier_rounds
    scenarios(&[
        "connection_drop_in_batch",
        "connection_drop_second_round",
        "connection_drop_in_fallback",
        "connection_drop_single",
    ]);
}

#[test]
fn metadata_authentication_like_python() {
    // test_logix_auth.py: test_driver_authenticates_the_same_connection, ..._stops_on_rejected_handshake,
    // ..._rejects_the_wrong_service_reply, ..._does_not_treat_authentication_as_metadata_permission, plus the
    // bundled credentials, malformed challenges and a dropped connection
    scenarios(&["auth", "auth_connection_drop", "micro800"]);
}

#[test]
fn reopening_a_lazy_driver_reads_program_references_and_member_ids_again() {
    // _reset_lazy_tags clears every _cache dict, the Descriptions' too, also on the same session and connection
    scenarios(&["lazy_reopen"]);
}

#[test]
fn a_failure_while_resolving_a_tag_is_that_tags_result() {
    // _resolve's exceptions (program reference, template and member identifier reads) are per tag
    scenarios(&[
        "resolve_comm_failures",
        "member_identifier_continuation_failure",
    ]);
}

#[test]
fn every_scenario_is_covered_by_a_test() {
    let fixture = fixture();
    let names: Vec<&str> = common::cases(&fixture, "scenarios")
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, COVERED);
}

#[test]
fn a_closed_driver_that_cannot_connect_returns_an_error() {
    // with_forward_open: get_tag_description raises when the connection cannot be opened
    let fake = Fake::new();
    let driver = LogixDriver::with_connector(
        "1.2.3.4",
        LogixOptions {
            init_tags: false,
            ..LogixOptions::default()
        },
        fake.connector(),
    )
    .unwrap();
    let err = driver
        .get_tag_description("Tag", DEFAULT_LANGUAGE, TextEncoding::Utf8)
        .unwrap_err();
    assert_eq!(class(&err), "CommError");
    assert!(fake.sent().is_empty());
    let result = driver.authenticate_metadata(None);
    assert_eq!(result.error_kind(), Some(ErrorKind::Comm));
    assert!(fake.sent().is_empty());
}

// ---- thread safety, on the simulator ----

/// A `ciplink-sim` process (built by `cargo test --workspace`), killed on drop.
struct SimProcess(std::process::Child);

impl Drop for SimProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Starts the simulator binary on a free port with `config`; None if it was not built (`cargo test -p ciplink`).
fn start_sim(config: &Json) -> Option<(SimProcess, String)> {
    use std::io::BufRead;
    use std::process::{Command, Stdio};
    let exe = std::env::current_exe().ok()?; // target/<profile>/deps/<test>
    let sim = exe
        .parent()?
        .parent()?
        .join(format!("ciplink-sim{}", std::env::consts::EXE_SUFFIX));
    if !sim.exists() {
        return None;
    }
    let dir = std::env::temp_dir().join(format!("ciplink-desc-sim-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("controller.json");
    std::fs::write(&path, config.to_string()).unwrap();
    let mut child = Command::new(sim)
        .arg("--config")
        .arg(&path)
        .args(["--port", "0", "--exit-on-eof"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let process = SimProcess(child);
    let mut line = String::new();
    std::io::BufReader::new(stdout)
        .read_line(&mut line)
        .unwrap();
    let address = line
        .trim()
        .strip_prefix("listening on ")
        .unwrap()
        .to_owned();
    Some((process, address))
}

#[test]
fn descriptions_reads_and_writes_from_several_threads_on_the_simulator() {
    let config = json!({
        "kind": "logix",
        "types": [{"name": "Inner", "members": [
            {"name": "Acked", "type": "BOOL", "description": "Acked default"},
            {"name": "val", "type": "DINT"},
        ]}],
        "tags": [
            {"name": "Array", "type": "DINT", "dims": [30],
             "descriptions": {"": "Array text", "[0]": "Element text", "[0].1": "Bit text"}},
            {"name": "Structs", "type": "Inner", "dims": [5], "descriptions": {"[0].ACKED": "Member text"}},
            {"name": "Counter", "type": "DINT"},
        ],
        "programs": [{"name": "Test", "tags": [
            {"name": "Input", "type": "BOOL", "descriptions": {"": "Program text"}},
        ]}],
    });
    let Some((_sim, address)) = start_sim(&config) else {
        eprintln!("ciplink-sim is not built; run cargo test --workspace");
        return;
    };
    let d = LogixDriver::new(&address, LogixOptions::default()).unwrap();
    assert_eq!(d.open(), Ok(true));
    let names = [
        "Array",
        "Array[0]",
        "Array[0].1",
        "Array[1]",
        "Structs[0].Acked",
        "Structs[1].Acked",
        "Program:Test.Input",
        "Counter",
    ];
    let expected = [
        Some("Array text"),
        Some("Element text"),
        Some("Bit text"),
        Some("Array text"),
        Some("Member text"),
        Some("Acked default"),
        Some("Program text"),
        None,
    ];
    let (done, finished) = std::sync::mpsc::channel();
    let d = std::sync::Arc::new(d);
    for thread in 0..4i32 {
        let (d, done) = (std::sync::Arc::clone(&d), done.clone());
        std::thread::spawn(move || {
            for i in 0..10 {
                let results = d
                    .get_tag_descriptions(&names, DEFAULT_LANGUAGE, TextEncoding::Utf8)
                    .unwrap();
                for (result, want) in results.iter().zip(expected) {
                    match want {
                        Some(text) => {
                            assert_eq!(result.value, Some(Value::String(text.into())), "{result:?}")
                        }
                        None => assert_eq!(
                            result.error.as_ref().map(|e| e.kind),
                            Some(ErrorKind::NotFound)
                        ),
                    }
                }
                let one = d
                    .get_tag_description(
                        names[thread as usize],
                        DEFAULT_LANGUAGE,
                        TextEncoding::Utf8,
                    )
                    .unwrap();
                assert_eq!(one.value, results[thread as usize].value);
                let value = thread * 100 + i;
                let wrote = d.write(&[("Counter", Value::DInt(value))]).unwrap();
                assert_eq!(wrote[0].error, None);
                let read = d.read(&["Counter", "Array[0]"]).unwrap();
                assert!(read.iter().all(|r| r.error.is_none()), "{read:?}");
            }
            done.send(()).unwrap();
        });
    }
    drop(done);
    for _ in 0..4 {
        finished
            .recv_timeout(std::time::Duration::from_secs(120))
            .expect("a thread panicked or the driver hung");
    }
    assert!(d.connected());
}

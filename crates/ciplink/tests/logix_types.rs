//! Logix tag and type model parity with the reference Python driver: tools/fixtures/gen_logix_types.py writes
//! fixtures/logix_types.json.
#![allow(clippy::unwrap_used)]

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use ciplink::logix::types::{
    DataType, PyObj, ScopeInfo, Symbol, TagDef, TagInfo, TemplateMakeup, TypeClass, encode_value,
    get_array_index, get_tag_info, is_aoi, isolate_scopes, nested_template_ids, parse_read_reply,
    parse_structure_makeup, parse_symbol_list, parse_template, read_reply_size, split_tag_name,
    strip_array, tag_key, tag_return_size, template_read_request,
};
use ciplink::reader::Reader;
use ciplink::{Error, ErrorKind, Value};
use common::*;
use indexmap::IndexMap;
use serde_json::{Value as Json, json};

/// a PyObj as the generator's tagged JSON (dict keys as str())
fn py_json(obj: &PyObj) -> Json {
    match obj {
        PyObj::None => Json::Null,
        PyObj::Bool(b) => json!({ "bool": b }),
        PyObj::Int(n) => match i64::try_from(*n) {
            Ok(n) => json!({ "int": n }),
            Err(_) => json!({ "int": u64::try_from(*n).unwrap() }),
        },
        PyObj::Str(s) => json!({ "str": s }),
        PyObj::List(items) => json!({ "list": items.iter().map(py_json).collect::<Vec<_>>() }),
        PyObj::Dict(items) => {
            let pairs: Vec<Json> = items
                .iter()
                .map(|(k, v)| {
                    let key = match k {
                        PyObj::Str(s) => s.clone(),
                        PyObj::Int(n) => n.to_string(),
                        other => panic!("key {other:?}"),
                    };
                    json!([key, py_json(v)])
                })
                .collect();
            json!({ "dict": pairs })
        }
    }
}

fn ok<'a>(result: &'a Json, ctx: &str) -> &'a Json {
    result
        .get("ok")
        .unwrap_or_else(|| panic!("{ctx}: expected an error {result}"))
}

/// checks an error's class and message against {"err", "msg"}; Python-only classes (TypeError, ...) only need
/// some error
fn check_err(err: &Error, expected: &Json, ctx: &str) {
    let class_name = expected["err"]
        .as_str()
        .unwrap_or_else(|| panic!("{ctx}: unexpected error {err:?}, expected {expected}"));
    if matches!(
        class_name,
        "DataError" | "BufferEmptyError" | "RequestError" | "ResponseError" | "CommError"
    ) {
        assert_eq!(class(err), class_name, "{ctx}: {err:?}");
        assert_eq!(err.to_string(), expected["msg"].as_str().unwrap(), "{ctx}");
    }
}

fn makeup_from(json: &Json) -> TemplateMakeup {
    TemplateMakeup {
        object_definition_size: json["object_definition_size"].as_u64().unwrap() as u32,
        structure_size: json["structure_size"].as_u64().unwrap() as u32,
        member_count: json["member_count"].as_u64().unwrap() as u16,
        structure_handle: json["structure_handle"].as_u64().unwrap() as u16,
    }
}

/// the driver's template cache (`_get_data_type`): parses a template once, nested ones first
#[derive(Default)]
struct Templates {
    raw: HashMap<u16, (TemplateMakeup, Vec<u8>)>,
    cache: HashMap<u16, Arc<DataType>>,
    data_types: IndexMap<String, Arc<DataType>>,
}

impl Templates {
    fn from_fixture(json: &Json) -> Self {
        let mut templates = Templates::default();
        for entry in json.as_array().unwrap() {
            let id = entry[0].as_u64().unwrap() as u16;
            templates.raw.insert(
                id,
                (makeup_from(&entry[1]), hex(entry[2].as_str().unwrap())),
            );
        }
        templates
    }

    fn get(&mut self, id: u16, symbol_type: u16) -> Result<Arc<DataType>, Error> {
        if let Some(dt) = self.cache.get(&id) {
            return Ok(Arc::clone(dt));
        }
        let parsed = match self.raw.get(&id).cloned() {
            Some((makeup, raw)) => {
                parse_template(&raw, &makeup, symbol_type, &mut |i, s| self.get(i, s))
            }
            None => Err(Error::response("template not available")),
        };
        let dt = Arc::new(parsed.map_err(|err| match err {
            Error::Comm(_) => err,
            _ => Error::response(format!("Failed to get data type information for {id}")),
        })?);
        self.cache.insert(id, Arc::clone(&dt));
        let name = dt.name.clone().unwrap_or_else(|| "None".into());
        self.data_types.insert(name, Arc::clone(&dt));
        Ok(dt)
    }

    fn data_types_py(&self) -> Json {
        let items = self
            .data_types
            .iter()
            .map(|(k, v)| (PyObj::Str(k.clone()), v.to_py()))
            .collect();
        py_json(&PyObj::Dict(items))
    }
}

fn parse_scopes(scopes: &Json, revision: u32) -> Vec<(Option<String>, Vec<Symbol>)> {
    scopes
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            let mut symbols = Vec::new();
            parse_symbol_list(&hex(s[1].as_str().unwrap()), 0, revision, &mut symbols).unwrap();
            (s[0].as_str().map(str::to_owned), symbols)
        })
        .collect()
}

/// the main fixture controller's tags
fn main_tags(fixture: &Json) -> (IndexMap<String, TagDef>, Templates) {
    let mut templates = Templates::from_fixture(&fixture["main_templates"]);
    let mut info = ScopeInfo::default();
    let tags = isolate_scopes(
        &mut info,
        &parse_scopes(&fixture["main_scopes"], 33),
        "",
        &mut |i, s| templates.get(i, s),
    )
    .unwrap();
    let tags = tags.into_iter().map(|t| (t.tag_name.clone(), t)).collect();
    (tags, templates)
}

#[test]
fn symbol_list_pages_match_python() {
    let fixture = load("logix_types.json");
    for case in cases(&fixture, "symbol_lists") {
        let ctx = format!("{} {}", case["revision"], case["status"]);
        let mut symbols = Vec::new();
        let result = parse_symbol_list(
            &hex(case["data"].as_str().unwrap()),
            case["status"].as_u64().unwrap() as u8,
            case["revision"].as_u64().unwrap() as u32,
            &mut symbols,
        );
        match result {
            Ok(next) => {
                let want = ok(&case["result"], &ctx);
                let next = next.map_or(PyObj::Int(-1), |n| PyObj::Int(n.into()));
                let got = PyObj::Dict(vec![
                    (PyObj::Str("next".into()), next),
                    (
                        PyObj::Str("tags".into()),
                        PyObj::List(symbols.iter().map(Symbol::to_py).collect()),
                    ),
                ]);
                assert_eq!(py_json(&got), *want, "{ctx}");
            }
            Err(err) => check_err(&err, &case["result"], &ctx),
        }
    }
}

#[test]
fn structure_makeups_match_python() {
    let fixture = load("logix_types.json");
    for case in cases(&fixture, "makeups") {
        let ctx = case["data"].to_string();
        match parse_structure_makeup(&hex(case["data"].as_str().unwrap())) {
            Ok(m) => assert_eq!(py_json(&m.to_py()), *ok(&case["result"], &ctx), "{ctx}"),
            Err(err) => check_err(&err, &case["result"], &ctx),
        }
    }
}

#[test]
fn template_read_requests_match_python() {
    let fixture = load("logix_types.json");
    for case in cases(&fixture, "template_reads") {
        let ctx = case.to_string();
        let result = template_read_request(
            case["ods"].as_u64().unwrap() as u32,
            case["offset"].as_u64().unwrap() as u32,
        );
        match result {
            Ok(bytes) => assert_eq!(
                to_hex(&bytes),
                ok(&case["result"], &ctx)["bytes"].as_str().unwrap(),
                "{ctx}"
            ),
            Err(err) => check_err(&err, &case["result"], &ctx),
        }
    }
}

#[test]
fn nested_template_ids_match_python() {
    let fixture = load("logix_types.json");
    for case in cases(&fixture, "nested_ids") {
        let ctx = case.to_string();
        let result = nested_template_ids(
            &hex(case["data"].as_str().unwrap()),
            &makeup_from(&case["makeup"]),
        );
        match result {
            Ok(ids) => {
                let got = PyObj::List(ids.iter().map(|i| PyObj::Int((*i).into())).collect());
                assert_eq!(py_json(&got), *ok(&case["result"], &ctx), "{ctx}");
            }
            Err(err) => check_err(&err, &case["result"], &ctx),
        }
    }
}

#[test]
fn templates_parse_like_python() {
    let fixture = load("logix_types.json");
    for case in cases(&fixture, "templates") {
        let ctx = case["name"].as_str().unwrap();
        let mut templates = Templates::from_fixture(&case["templates"]);
        let id = case["instance_id"].as_u64().unwrap() as u16;
        let (makeup, raw) = templates.raw[&id].clone();
        let result = parse_template(
            &raw,
            &makeup,
            case["symbol_type"].as_u64().unwrap() as u16,
            &mut |i, s| templates.get(i, s),
        );
        match result {
            Ok(dt) => {
                let want = ok(&case["result"], ctx);
                assert_eq!(py_json(&dt.to_py()), want["dict"][0][1], "{ctx}: data type");
                assert_eq!(
                    templates.data_types_py(),
                    want["dict"][1][1],
                    "{ctx}: data types"
                );
            }
            Err(err) => check_err(&err, &case["result"], ctx),
        }
    }
}

#[test]
fn tag_lists_match_python() {
    let fixture = load("logix_types.json");
    for case in cases(&fixture, "tag_lists") {
        let ctx = case["name"].as_str().unwrap();
        let revision = case["revision"].as_u64().unwrap() as u32;
        let mut templates = Templates::from_fixture(&case["templates"]);
        let mut info = ScopeInfo::default();
        if !case["info"].is_null() {
            // the program a single-program upload already knows
            info.programs.insert(
                "MainProgram".into(),
                ciplink::logix::types::ProgramInfo {
                    instance_id: 9,
                    routines: vec!["X".into()],
                },
            );
        }
        let result = isolate_scopes(
            &mut info,
            &parse_scopes(&case["scopes"], revision),
            case["filter"].as_str().unwrap(),
            &mut |i, s| templates.get(i, s),
        );
        match result {
            Ok(tags) => {
                let want = ok(&case["result"], ctx);
                let got = PyObj::List(tags.iter().map(TagDef::to_py).collect());
                assert_eq!(py_json(&got), want["dict"][0][1], "{ctx}: tags");
                assert_eq!(py_json(&info.to_py()), want["dict"][1][1], "{ctx}: info");
                assert_eq!(
                    templates.data_types_py(),
                    want["dict"][2][1],
                    "{ctx}: data types"
                );
            }
            Err(err) => check_err(&err, &case["result"], ctx),
        }
    }
}

#[test]
fn tag_info_lookups_match_python() {
    let fixture = load("logix_types.json");
    let (tags, _) = main_tags(&fixture);
    for case in cases(&fixture, "tag_info") {
        let ctx = case["tag"].as_str().unwrap();
        match get_tag_info(&tags, ctx) {
            Ok(info) => {
                let (name, offset) = match info {
                    TagInfo::Tag(t) => (PyObj::Str(t.tag_name.clone()), PyObj::None),
                    TagInfo::Member(m) => (PyObj::None, PyObj::Int(m.offset.into())),
                };
                let got = PyObj::Dict(vec![
                    (PyObj::Str("tag_name".into()), name),
                    (
                        PyObj::Str("data_type_name".into()),
                        PyObj::Str(info.data_type_name().unwrap().into()),
                    ),
                    (PyObj::Str("offset".into()), offset),
                ]);
                assert_eq!(py_json(&got), *ok(&case["result"], ctx), "{ctx}");
            }
            Err(err) => check_err(&err, &case["result"], ctx),
        }
    }
    let err = get_tag_info(&tags, "nope").unwrap_err();
    assert_eq!(err.carried_kind(), Some(ErrorKind::NotFound));
    let err = get_tag_info(&tags, "a.b").unwrap_err();
    assert_eq!(err.carried_kind(), Some(ErrorKind::BadRequest));
}

#[test]
fn read_replies_decode_like_python() {
    let fixture = load("logix_types.json");
    let (tags, _) = main_tags(&fixture);
    for case in cases(&fixture, "reads") {
        let ctx = format!("{} {}", case["tag"], case["data"]);
        let info = get_tag_info(&tags, case["tag"].as_str().unwrap()).unwrap();
        let data = hex(case["data"].as_str().unwrap());
        let elements = case["elements"].as_u64().unwrap() as usize;
        match parse_read_reply(&data, info, elements) {
            Ok((value, name)) => {
                let want = &ok(&case["result"], &ctx)["list"];
                assert_value(&value, &want[0], &ctx);
                assert_eq!(name.as_deref(), want[1]["str"].as_str(), "{ctx}");
            }
            Err(err) => check_err(&err, &case["result"], &ctx),
        }
    }
}

#[test]
fn write_values_encode_like_python() {
    let fixture = load("logix_types.json");
    let (tags, _) = main_tags(&fixture);
    for case in cases(&fixture, "encodes") {
        let ctx = format!("{} {}", case["tag"], case["value"]);
        let Some(value) = input(&case["value"]) else {
            assert!(case["result"].get("err").is_some(), "{ctx}");
            continue;
        };
        let info = get_tag_info(&tags, case["tag"].as_str().unwrap()).unwrap();
        let result = encode_value(
            &value,
            case["elements"].as_u64().unwrap() as usize,
            case["bool_elements"].as_u64().map(|n| n as usize),
            info.type_class(),
        );
        match result {
            Ok(bytes) => assert_eq!(
                to_hex(&bytes),
                ok(&case["result"], &ctx)["bytes"].as_str().unwrap(),
                "{ctx}"
            ),
            Err(err) => {
                check_err(&err, &case["result"], &ctx);
                assert_eq!(err.carried_kind(), Some(ErrorKind::BadValue), "{ctx}");
            }
        }
    }
}

#[test]
fn sizes_match_python() {
    let fixture = load("logix_types.json");
    let (tags, _) = main_tags(&fixture);
    for case in cases(&fixture, "sizes") {
        let ctx = case.to_string();
        let info = get_tag_info(&tags, case["tag"].as_str().unwrap()).unwrap();
        let elements = case["elements"].as_u64().unwrap() as usize;
        for (key, result) in [
            ("return_size", tag_return_size(info, elements)),
            ("reply_size", read_reply_size(info, elements)),
        ] {
            match result {
                Ok(n) => assert_eq!(
                    Some(n as u64),
                    ok(&case[key], &ctx)["int"].as_u64(),
                    "{ctx}"
                ),
                Err(err) => check_err(&err, &case[key], &ctx),
            }
        }
    }
}

#[test]
fn name_helpers_match_python() {
    let fixture = load("logix_types.json");
    for case in cases(&fixture, "split_tag_name") {
        let ctx = case["tag"].as_str().unwrap();
        match split_tag_name(ctx) {
            Ok((tag, base, attrs)) => {
                let attrs: Vec<PyObj> = attrs.into_iter().map(PyObj::Str).collect();
                let got = PyObj::List(vec![PyObj::Str(tag), PyObj::Str(base), PyObj::List(attrs)]);
                assert_eq!(py_json(&got), *ok(&case["result"], ctx), "{ctx}");
            }
            Err(err) => check_err(&err, &case["result"], ctx),
        }
    }
    let keys: IndexMap<String, i32> = [("Abc", 1), ("abc", 2), ("Def", 3), ("ÄB", 4)]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
    for case in cases(&fixture, "tag_key") {
        let name = case["name"].as_str().unwrap();
        assert_eq!(
            tag_key(&keys, name),
            ok(&case["result"], name)["str"].as_str().unwrap(),
            "{name}"
        );
    }
    for case in cases(&fixture, "get_array_index") {
        let ctx = case["tag"].as_str().unwrap();
        match get_array_index(ctx) {
            Ok((name, idx)) => {
                let idx = idx.map_or(PyObj::None, |i| PyObj::Int(i.into()));
                let got = PyObj::List(vec![PyObj::Str(name), idx]);
                assert_eq!(py_json(&got), *ok(&case["result"], ctx), "{ctx}");
            }
            Err(err) => {
                assert_eq!(case["result"]["err"], "ValueError", "{ctx}");
                assert_eq!(err.to_string(), case["result"]["msg"].as_str().unwrap());
            }
        }
    }
    for case in cases(&fixture, "strip_array") {
        let tag = case["tag"].as_str().unwrap();
        assert_eq!(
            strip_array(tag),
            ok(&case["result"], tag)["str"].as_str().unwrap()
        );
    }
}

#[test]
fn aoi_detection_matches_python() {
    let fixture = load("logix_types.json");
    let (_, templates) = main_tags(&fixture);
    for case in cases(&fixture, "is_aoi") {
        let name = case["name"].as_str().unwrap();
        let want = ok(&case["result"], name)["bool"].as_bool().unwrap();
        assert_eq!(is_aoi(&templates.data_types[name]), want, "{name}");
    }
}

// ------------------------------------------------------------------------------------------------ intent of the
// Python offline tests (test_strict_writes.py, test_data_types.py, test_logix_tag_list.py)

fn udt() -> Arc<DataType> {
    // DINT x at 0, private host SINT at 4 holding the bit member 'flag', 8 bytes
    let raw = [
        &[0u8, 0, 0xC4, 0, 0, 0, 0, 0][..],
        &[0, 0, 0xC2, 0, 4, 0, 0, 0],
        &[0, 0, 0xC1, 0, 4, 0, 0, 0],
        b"UDT;n\x00x\x00ZZZZZZZZZZhost\x00flag\x00",
    ]
    .concat();
    let makeup = TemplateMakeup {
        object_definition_size: 20,
        structure_size: 8,
        member_count: 3,
        structure_handle: 0x1234,
    };
    let mut none = |_, _| Err(Error::response("no nested types"));
    Arc::new(parse_template(&raw, &makeup, 0x8100, &mut none).unwrap())
}

fn dict(items: &[(&str, Value)]) -> Value {
    Value::Struct(
        items
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect(),
    )
}

#[test]
fn struct_read_value_round_trips() {
    let tc = TypeClass::Struct(udt());
    let value = dict(&[("x", Value::DInt(7)), ("flag", Value::Bool(true))]);
    let bytes = tc.encode(&value).unwrap();
    assert_eq!(bytes, [7, 0, 0, 0, 1, 0, 0, 0]);
    let decoded = tc.decode(&mut Reader::new(&bytes)).unwrap();
    assert_eq!(decoded, value);
    assert_eq!(tc.encode(&decoded).unwrap(), bytes);
}

#[test]
fn struct_writes_reject_unknown_missing_and_non_bool_members() {
    let tc = Some(TypeClass::Struct(udt()));
    for value in [
        dict(&[
            ("x", Value::LInt(1)),
            ("flag", Value::Bool(true)),
            ("y", Value::LInt(2)),
        ]),
        dict(&[("flag", Value::Bool(true))]),
        dict(&[("x", Value::LInt(1)), ("flag", Value::LInt(2))]),
        dict(&[
            ("x", Value::LInt(1)),
            ("flag", Value::String("True".into())),
        ]),
    ] {
        let err = encode_value(&value, 1, None, tc.as_ref()).unwrap_err();
        assert_eq!(err.carried_kind(), Some(ErrorKind::BadValue), "{value:?}");
    }
    // private members may be given, they are not written
    let value = dict(&[
        ("x", Value::LInt(1)),
        ("flag", Value::LInt(0)),
        ("ZZZZZZZZZZhost", Value::LInt(0)),
    ]);
    assert!(encode_value(&value, 1, None, tc.as_ref()).is_ok());
}

#[test]
fn array_writes_reject_wrong_element_counts() {
    let tc = TypeClass::Array(
        3,
        Box::new(TypeClass::Elementary(ciplink::types::Elementary::DInt)),
    );
    let list = |n: i64| Value::Array((1..=n).map(Value::LInt).collect());
    let err = encode_value(&list(4), 3, None, Some(&tc)).unwrap_err();
    assert!(err.to_string().contains("Too many values"), "{err}");
    let err = encode_value(&list(2), 1, None, Some(&tc)).unwrap_err();
    assert!(err.to_string().contains("Too many values"), "{err}");
    assert_eq!(
        encode_value(&list(3), 3, None, Some(&tc)).unwrap().len(),
        12
    );
    assert_eq!(
        encode_value(&Value::LInt(5), 1, None, Some(&tc)).unwrap(),
        [5, 0, 0, 0]
    );
}

#[test]
fn namespace_filter_only_filters_user_tags() {
    let symbol = |name: &str, id: u32| Symbol {
        instance_id: id,
        tag_name: name.into(),
        symbol_type: 0xC4,
        symbol_address: 0,
        symbol_object_address: 0,
        software_control: 0,
        external_access: "Read/Write".into(),
        dimensions: [0; 3],
    };
    let mut info = ScopeInfo::default();
    let controller = [
        symbol("Program:MainProgram", 1),
        symbol("Task:MainTask", 2),
        symbol("Local:1:I", 3),
        symbol("Line1_Speed", 4),
        symbol("Other", 5),
    ];
    let names: Vec<String> =
        ciplink::logix::types::user_symbols(&mut info, &controller, None, "Line1_")
            .into_iter()
            .map(|(n, _)| n)
            .collect();
    assert_eq!(names, ["Line1_Speed"]);
    let program = [symbol("Line1_X", 6), symbol("Other", 7)];
    let names: Vec<String> =
        ciplink::logix::types::user_symbols(&mut info, &program, Some("MainProgram"), "Line1_")
            .into_iter()
            .map(|(n, _)| n)
            .collect();
    assert_eq!(names, ["Program:MainProgram.Line1_X"]);
    assert!(info.programs.contains_key("MainProgram"));
    assert!(info.tasks.contains_key("MainTask"));
    assert_eq!(info.modules["Local"].slots[&1], ["I"]);
}

#[test]
fn symbol_list_page_cursor_follows_the_reply_status() {
    let mut out = Vec::new();
    assert_eq!(parse_symbol_list(&[], 0x06, 33, &mut out), Ok(Some(1)));
    assert_eq!(parse_symbol_list(&[], 0x00, 33, &mut out), Ok(None));
    assert!(matches!(
        parse_symbol_list(&[1, 2, 3], 0x00, 33, &mut out),
        Err(Error::Response { .. })
    ));
}

#[test]
fn hostile_wire_input_is_an_error_not_a_panic() {
    let fixture = load("logix_types.json");
    let mut none = |_, _| Err(Error::response("no nested types"));
    // every template cut at every length, with its own and with a huge member count
    for entry in fixture["main_templates"].as_array().unwrap() {
        let makeup = makeup_from(&entry[1]);
        let raw = hex(entry[2].as_str().unwrap());
        let huge = TemplateMakeup {
            member_count: u16::MAX,
            structure_size: u32::MAX,
            ..makeup
        };
        for cut in 0..=raw.len() {
            for m in [&makeup, &huge] {
                let _ = parse_template(&raw[..cut], m, 0x8100, &mut none);
                let _ = nested_template_ids(&raw[..cut], m);
            }
        }
    }
    // symbol pages and makeups cut at every length
    for case in cases(&fixture, "symbol_lists") {
        let data = hex(case["data"].as_str().unwrap());
        for cut in 0..=data.len() {
            let _ = parse_symbol_list(&data[..cut], 6, 33, &mut Vec::new());
        }
    }
    for cut in 0..30 {
        let _ = parse_structure_makeup(&vec![0xFF; cut]);
    }
    // read replies cut at every length, and with every element count up to 3
    let (tags, _) = main_tags(&fixture);
    for case in cases(&fixture, "reads") {
        let info = get_tag_info(&tags, case["tag"].as_str().unwrap()).unwrap();
        let data = hex(case["data"].as_str().unwrap());
        for cut in 0..=data.len() {
            for elements in 0..4 {
                let _ = parse_read_reply(&data[..cut], info, elements);
            }
        }
    }
    // a structure larger than its reply, and bit members past it
    for tag in ["udt", "outer", "deep", "bo", "ov", "t1", "aoi"] {
        let info = get_tag_info(&tags, tag).unwrap();
        for elements in [0, 1, 1000] {
            let _ = parse_read_reply(&[0xA0, 0x02, 0, 0, 1], info, elements);
        }
    }
}

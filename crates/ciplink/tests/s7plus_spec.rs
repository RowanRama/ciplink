//! Every hex example of the public S7comm-plus notes (`docs/dev/s7commplus-protocol.md`) decodes, and every
//! request example is rebuilt byte for byte, so the notes and the code cannot drift apart.

use ciplink::s7plus::wire::{
    Cursor, Object, build_request, parse_any_response, parse_request, parse_request_header,
};

fn spec() -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/dev/s7commplus-protocol.md"
    );
    std::fs::read_to_string(path).expect("read the protocol notes")
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn is_hex_line(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

/// (line, hex) of every example: `request` / `response` lines with their continuation lines, and blocks of
/// bare hex lines.
fn examples(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut in_block = false;
    let mut current = String::new();
    let mut start = 0;
    let mut flush = |current: &mut String, start: usize| {
        if !current.is_empty() {
            out.push((start, std::mem::take(current)));
        }
    };
    for (i, line) in text.lines().enumerate() {
        let n = i + 1;
        if line.starts_with("```") {
            flush(&mut current, start);
            in_block = !in_block;
            continue;
        }
        if !in_block {
            continue;
        }
        let s = line.trim();
        let labelled = s
            .strip_prefix("request")
            .or_else(|| s.strip_prefix("response"));
        if let Some(rest) = labelled {
            flush(&mut current, start);
            let rest = rest.trim();
            let rest = rest.split("->").next().unwrap_or("");
            let rest = rest.split("  ").next().unwrap_or("").trim();
            if is_hex_line(rest) {
                current.push_str(rest);
                start = n;
            }
        } else if s.is_empty() || s.starts_with('#') {
            flush(&mut current, start);
        } else if is_hex_line(s) {
            if current.is_empty() {
                start = n;
            }
            current.push_str(s);
        }
    }
    out
}

#[test]
fn every_spec_hex_example_decodes() {
    let text = spec();
    let examples = examples(&text);
    let mut requests = 0;
    let mut responses = 0;
    let mut objects = 0;
    for (line, hex) in &examples {
        let bytes = unhex(hex);
        if hex.starts_with("a1") {
            let mut c = Cursor::new(&bytes);
            let list = Object::decode_list(&mut c).unwrap_or_else(|e| panic!("line {line}: {e}"));
            assert_eq!(c.remaining(), 0, "line {line}: bytes after the object");
            assert!(!list.is_empty(), "line {line}");
            objects += 1;
            continue;
        }
        match bytes.get(1) {
            Some(0x31) => {
                let header =
                    parse_request_header(&bytes).unwrap_or_else(|e| panic!("line {line}: {e}"));
                let request = parse_request(&header).unwrap_or_else(|e| panic!("line {line}: {e}"));
                let rebuilt =
                    build_request(&header, &request).unwrap_or_else(|e| panic!("line {line}: {e}"));
                assert_eq!(
                    rebuilt, bytes,
                    "line {line}: request not rebuilt byte for byte"
                );
                requests += 1;
            }
            Some(0x32) => {
                parse_any_response(&bytes).unwrap_or_else(|e| panic!("line {line}: {e}"));
                responses += 1;
            }
            _ => panic!("line {line}: neither a request nor a response"),
        }
    }
    // the notes have 14 request and 9 response examples and the DTL type-info object
    assert_eq!((requests, responses), (14, 9));
    assert_eq!(objects, 1);
}

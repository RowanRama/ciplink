//! Replays the private captures of a real S7-1500 against the codec. Every test returns early when the
//! environment variable `S7PLUS_PRIVATE` (the private folder holding `captures/` and `spec/`) is unset, so the
//! public CI runs none of it.
//!
//! Nothing private may leave this test: assertion messages print counts and positions only, never names,
//! values or bytes.

use std::collections::HashMap;
use std::path::PathBuf;

use ciplink::s7plus::wire::{
    MAX_PDU, Request, Response, build_request, function, parse_any_response, parse_get_multi,
    parse_get_var, parse_request, parse_request_header, parse_response, parse_set_multi, read_pdu,
};

fn private_dir() -> Option<PathBuf> {
    std::env::var_os("S7PLUS_PRIVATE").map(PathBuf::from)
}

fn captures() -> Option<PathBuf> {
    let dir = private_dir()?.join("captures");
    assert!(dir.is_dir(), "S7PLUS_PRIVATE has no captures folder");
    Some(dir)
}

fn unhex(s: &str) -> Vec<u8> {
    let s: Vec<u8> = s.bytes().filter(u8::is_ascii_hexdigit).collect();
    s.chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).expect("ascii"), 16).expect("hex"))
        .collect()
}

/// One captured PDU: index, client-to-server, bytes.
struct Pdu {
    index: usize,
    to_plc: bool,
    bytes: Vec<u8>,
}

/// The PDUs of a `run*-pdus.txt` file.
fn pdu_file(path: &std::path::Path) -> Vec<Pdu> {
    let text = std::fs::read_to_string(path).expect("read PDU file");
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            Pdu {
                index: f[0].parse().expect("index"),
                to_plc: f[1] == "C>S",
                bytes: unhex(f[4]),
            }
        })
        .collect()
}

/// The PDUs of an app log (`app-*.tsv`): the plaintext chunks of each direction concatenated and cut into
/// PDUs with the frame reader.
fn app_log(path: &std::path::Path) -> Vec<Pdu> {
    let text = std::fs::read_to_string(path).expect("read app log");
    let mut out = Vec::new();
    let mut streams: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 5 || (f[2] != "tls" && f[2] != "clear") {
            continue;
        }
        let to_plc = f[1] == "C>S";
        streams[usize::from(to_plc)].extend(unhex(f[4]));
    }
    for (dir, stream) in streams.iter().enumerate() {
        let mut rest = stream.as_slice();
        while !rest.is_empty() {
            let bytes = read_pdu(&mut rest, MAX_PDU).expect("app log frames");
            out.push(Pdu {
                index: out.len() + 1,
                to_plc: dir == 1,
                bytes,
            });
        }
    }
    out
}

fn files_matching(dir: &std::path::Path, prefix: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("read dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(prefix))
        })
        .collect();
    out.sort();
    out
}

/// Parses every PDU; requests must be rebuilt byte for byte. Returns the counts.
fn check_pdus(name: &str, pdus: &[Pdu]) -> (usize, usize) {
    let (mut requests, mut responses) = (0, 0);
    for p in pdus {
        if p.to_plc {
            let header = parse_request_header(&p.bytes)
                .unwrap_or_else(|e| panic!("{name} #{}: request header: {e}", p.index));
            let request = parse_request(&header)
                .unwrap_or_else(|e| panic!("{name} #{}: request: {e}", p.index));
            let rebuilt = build_request(&header, &request)
                .unwrap_or_else(|e| panic!("{name} #{}: rebuild: {e}", p.index));
            assert!(
                rebuilt == p.bytes,
                "{name} #{}: request not rebuilt byte for byte",
                p.index
            );
            requests += 1;
        } else {
            parse_any_response(&p.bytes)
                .unwrap_or_else(|e| panic!("{name} #{}: response: {e}", p.index));
            responses += 1;
        }
    }
    (requests, responses)
}

/// The integrity rule of spec 6.6 on every request / response pair (by sequence number).
fn check_integrity(name: &str, pdus: &[Pdu]) -> usize {
    let mut sent: HashMap<u16, (u16, Option<u32>, bool)> = HashMap::new();
    let mut checked = 0;
    for p in pdus.iter().filter(|p| p.to_plc) {
        let header = parse_request_header(&p.bytes).expect("header");
        let request = parse_request(&header).expect("request");
        let setup = matches!(
            request,
            Request::SetMulti {
                integrity: None,
                ..
            }
        );
        sent.insert(
            header.sequence,
            (header.function, request.integrity(), setup),
        );
    }
    for p in pdus.iter().filter(|p| !p.to_plc) {
        let r: Response<'_> = parse_response(&p.bytes).expect("response");
        let Some(&(function, integrity, setup)) = sent.get(&r.sequence) else {
            panic!("{name} #{}: response without request", p.index);
        };
        assert_eq!(function, r.function, "{name} #{}: function", p.index);
        let got = match r.function {
            function::GET_MULTI_VARIABLES => parse_get_multi(&r).expect("get").integrity,
            function::GET_VAR_SUB_STREAMED => parse_get_var(&r).expect("var").1,
            function::EXPLORE => {
                ciplink::s7plus::wire::parse_explore(&r)
                    .expect("explore")
                    .integrity
            }
            function::SET_MULTI_VARIABLES => parse_set_multi(&r).expect("set").integrity,
            _ => continue,
        };
        let want = if setup {
            0
        } else {
            u32::from(r.sequence).wrapping_add(integrity.expect("integrity"))
        };
        assert_eq!(got, want, "{name} #{}: response integrity", p.index);
        checked += 1;
    }
    checked
}

#[test]
fn every_captured_pdu_parses_and_every_request_is_rebuilt() {
    let Some(dir) = captures() else { return };
    let mut total = 0;
    for path in files_matching(&dir, "run") {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with("-pdus.txt") {
            continue;
        }
        let pdus = pdu_file(&path);
        let (requests, responses) = check_pdus(name, &pdus);
        assert!(requests > 0 && responses > 0, "{name}");
        check_integrity(name, &pdus);
        total += requests + responses;
    }
    assert!(total >= 181, "{total} PDUs");
}

/// The app log of the write session (the one `run4` folder).
fn write_session_log(dir: &std::path::Path) -> Vec<PathBuf> {
    let runs: Vec<PathBuf> = files_matching(dir, "run4")
        .into_iter()
        .filter(|p| p.is_dir())
        .collect();
    assert_eq!(runs.len(), 1, "one write session folder");
    files_matching(&runs[0], "app-")
}

#[test]
fn the_write_session_is_rebuilt_byte_for_byte() {
    let Some(dir) = captures() else { return };
    let logs = write_session_log(&dir);
    assert_eq!(logs.len(), 1);
    let pdus = app_log(&logs[0]);
    check_pdus("run4", &pdus);
    assert!(check_integrity("run4", &pdus) > 0);
    // the two tag writes: SetMultiVariables with an integrity ID from the "set" counter, 1 then 2
    let writes: Vec<u32> = pdus
        .iter()
        .filter(|p| p.to_plc)
        .filter_map(|p| {
            let header = parse_request_header(&p.bytes).ok()?;
            match parse_request(&header).ok()? {
                Request::SetMulti {
                    integrity: Some(i), ..
                } => Some(i),
                _ => None,
            }
        })
        .collect();
    assert_eq!(writes, vec![1, 2]);
    // DeleteObject takes the next "set" value
    let delete = pdus
        .iter()
        .filter(|p| p.to_plc)
        .find_map(|p| {
            let header = parse_request_header(&p.bytes).ok()?;
            match parse_request(&header).ok()? {
                Request::DeleteObject { integrity, .. } => Some(integrity),
                _ => None,
            }
        })
        .expect("DeleteObject");
    assert_eq!(delete, 3);
}

#[test]
fn every_app_log_cuts_into_parsable_pdus() {
    let Some(dir) = captures() else { return };
    let mut runs = 0;
    for run in files_matching(&dir, "run")
        .into_iter()
        .filter(|p| p.is_dir())
    {
        for log in files_matching(&run, "app-") {
            let pdus = app_log(&log);
            check_pdus("app log", &pdus);
            runs += 1;
        }
    }
    assert_eq!(runs, 5);
}

// ------------------------------------------------------------------------------------------------ browse

use ciplink::s7plus::wire::{Object, Scalar, Tree, WireValue, parse_explore};
use ciplink::{Value, s7plus::S7Symbol};

/// Requests and responses of one PDU file paired by sequence number.
fn pairs(pdus: &[Pdu]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut requests: HashMap<u16, Vec<u8>> = HashMap::new();
    let mut out = Vec::new();
    for p in pdus {
        if p.to_plc {
            let header = parse_request_header(&p.bytes).expect("header");
            requests.insert(header.sequence, p.bytes.clone());
        } else if let Ok(r) = parse_response(&p.bytes)
            && let Some(q) = requests.remove(&r.sequence)
        {
            out.push((q, p.bytes.clone()));
        }
    }
    out
}

/// The symbol tree of run1: every explored object and the LID-1 reads of the DBs.
fn run1_tree(dir: &std::path::Path) -> (Tree, Vec<Pdu>) {
    let pdus = pdu_file(&dir.join("run1-pdus.txt"));
    let mut explored: Vec<Object> = Vec::new();
    let mut db_types = HashMap::new();
    for (q, a) in pairs(&pdus) {
        let r = parse_response(&a).expect("response");
        match r.function {
            function::EXPLORE => explored.extend(parse_explore(&r).expect("explore").objects),
            function::GET_MULTI_VARIABLES => {
                let header = parse_request_header(&q).expect("header");
                let Request::GetMulti { items, .. } = parse_request(&header).expect("request")
                else {
                    continue;
                };
                if !items
                    .iter()
                    .all(|i| i.lids == [1] && i.area >> 16 == 0x8A0E)
                {
                    continue;
                }
                for (n, v) in parse_get_multi(&r).expect("values").values {
                    if let Some(Scalar::Rid(rid)) = v.as_scalar() {
                        db_types.insert(items[n as usize - 1].area & 0xFFFF, *rid);
                    }
                }
            }
            _ => {}
        }
    }
    (Tree::new(&explored, &db_types), pdus)
}

fn file_rows(dir: &std::path::Path, prefix: &str) -> Vec<Vec<String>> {
    let files = files_matching(dir, prefix);
    assert_eq!(files.len(), 1, "{prefix}");
    std::fs::read_to_string(&files[0])
        .expect("read")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.split('\t').map(str::to_string).collect())
        .collect()
}

/// The resolver's name of a reference row: PLC tags are listed as `<area name>.<tag>`.
fn plain_name(tree: &Tree, name: &str) -> String {
    for area in [80, 81, 82] {
        if let Some(prefix) = tree.area_name(area)
            && !prefix.is_empty()
            && let Some(rest) = name.strip_prefix(&format!("{prefix}."))
        {
            return rest.to_string();
        }
    }
    name.to_string()
}

#[test]
fn the_browse_rebuilds_the_captured_symbol_table() {
    let Some(dir) = captures() else { return };
    let (tree, _) = run1_tree(&dir);
    let rows = file_rows(&dir.join("run1"), "browse-");
    let (mut checked, mut skipped, mut multi_dim) = (0, 0, 0);
    let mut reference: HashMap<String, (String, u32)> = HashMap::new();
    for (i, row) in rows.iter().enumerate() {
        let access = &row[2];
        if access.starts_with("53.") || access.starts_with("54.") {
            skipped += 1; // S7 counters and timers: not part of the driver's table
            continue;
        }
        let name = plain_name(&tree, &row[0]);
        let crc = u32::from_str_radix(row[3].trim_start_matches("0x"), 16).expect("crc");
        let sym = tree
            .resolve(&name)
            .unwrap_or_else(|e| panic!("row {i}: not resolved ({:?})", e.kind));
        let (sdt, kind) = tree.leaf(&name).expect("leaf");
        assert_eq!(sym.access, *access, "row {i}: access");
        assert_eq!(sdt.to_string(), row[1], "row {i}: softdatatype");
        assert_eq!(
            sym.hmi_accessible.to_string(),
            row[4].to_lowercase(),
            "row {i}: HMI accessible"
        );
        assert_eq!(
            sym.hmi_visible.to_string(),
            row[5].to_lowercase(),
            "row {i}: HMI visible"
        );
        if sym.crc != crc {
            // the capture client used the one-dimensional CRC rule for multi-dimensional arrays, which the CPU
            // rejects (spec 11.7); the driver uses the vartype CRC
            assert_eq!(kind, 11, "row {i}: crc");
            multi_dim += 1;
        }
        reference.insert(name, (sym.access.clone(), sym.crc));
        checked += 1;
    }
    assert!(checked > 10_000, "{checked} rows");
    assert!(
        multi_dim <= 13,
        "{multi_dim} multi-dimensional CRC differences"
    );
    // the flat list: every symbol is a reference row, or a system structure listed whole whose members are rows
    let symbols: Vec<S7Symbol> = tree.symbols();
    let mut wholes = 0;
    for (i, s) in symbols.iter().enumerate() {
        match reference.get(&s.name) {
            Some((access, crc)) => {
                assert_eq!(&s.access, access, "symbol {i}: access");
                assert_eq!(s.crc, *crc, "symbol {i}: crc");
            }
            None => {
                let prefix = format!("{}.", s.name);
                assert!(
                    reference.keys().any(|k| k.starts_with(&prefix)),
                    "symbol {i}: not in the reference"
                );
                wholes += 1;
            }
        }
    }
    assert!(symbols.len() - wholes <= checked);
    eprintln!(
        "browse parity: {checked} rows, {skipped} skipped, {multi_dim} multi-dim CRCs, {} symbols, {wholes} listed whole",
        symbols.len()
    );
}

/// The text inside the first `<Value ...>` of a log column, or the column itself.
fn logged_scalar(text: &str) -> String {
    if text.starts_with("<Value") {
        let start = text.find('>').map_or(0, |i| i + 1);
        let end = text[start..].find('<').map_or(text.len(), |i| start + i);
        return text[start..end].to_string();
    }
    text.to_string()
}

/// The numbers of a logged list: `[1,2]` or `<Value>1</Value><Value>2</Value>` (possibly cut short).
fn logged_list(text: &str) -> Vec<String> {
    if let Some(inner) = text.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
        return inner
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
    }
    text.split("<Value>")
        .skip(1)
        .filter_map(|p| p.split_once("</Value>").map(|(v, _)| v.to_string()))
        .collect()
}

fn scalar_text(v: &Value) -> String {
    match v {
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::String(s) => s.clone(),
        other => other
            .as_i128()
            .map_or_else(|| format!("{other:?}"), |i| i.to_string()),
    }
}

/// `2026-11-18T16:34:46...` as the capture tool printed dates: `11/18/2026 4:34:46 PM`.
fn us_date(iso: &str) -> Option<String> {
    let (date, time) = iso.split_once('T')?;
    let d: Vec<u32> = date
        .split('-')
        .map(|p| p.parse().ok())
        .collect::<Option<_>>()?;
    let t: Vec<u32> = time
        .split('.')
        .next()?
        .split(':')
        .map(|p| p.parse().ok())
        .collect::<Option<_>>()?;
    let (h, pm) = (t[0] % 12, t[0] >= 12);
    let h = if h == 0 { 12 } else { h };
    Some(format!(
        "{}/{}/{} {}:{:02}:{:02} {}",
        d[1],
        d[2],
        d[0],
        h,
        t[1],
        t[2],
        if pm { "PM" } else { "AM" }
    ))
}

fn same(value: &Value, sdt: u8, logged: &str) -> bool {
    match value {
        Value::Real(f) => logged_scalar(logged).parse::<f32>().is_ok_and(|l| l == *f),
        Value::LReal(f) => logged_scalar(logged).parse::<f64>().is_ok_and(|l| l == *f),
        Value::Array(items) => {
            let list = logged_list(logged);
            !list.is_empty()
                && list.len() <= items.len()
                && list.iter().zip(items).all(|(l, v)| *l == scalar_text(v))
        }
        Value::Bytes(bytes) => {
            let list = logged_list(logged);
            !list.is_empty() && list.iter().zip(bytes).all(|(l, b)| *l == b.to_string())
        }
        Value::String(s) if matches!(sdt, 14 | 66 | 67) => {
            let l = logged_scalar(logged);
            if let Ok(ns) = l.parse::<u64>() {
                // a raw timestamp: the capture tool printed nanoseconds since 1970
                return ns == 0 && s.starts_with("1970-01-01T00:00:00");
            }
            us_date(s).is_some_and(|d| d == l)
        }
        other => scalar_text(other) == logged_scalar(logged),
    }
}

#[test]
fn captured_read_values_decode_to_the_logged_values() {
    let Some(dir) = captures() else { return };
    let (tree, run1) = run1_tree(&dir);
    let mut checked = 0;
    // run1: the read of the readmap rows, matched by access sequence and CRC
    let rows = file_rows(&dir.join("run1"), "readmap-");
    let reads: Vec<(Vec<u8>, Vec<u8>)> = pairs(&run1)
        .into_iter()
        .filter(|(q, _)| {
            parse_request_header(q).is_ok_and(|h| h.function == function::GET_MULTI_VARIABLES)
        })
        .collect();
    for (i, row) in rows.iter().enumerate() {
        let (name, access) = (plain_name(&tree, &row[1]), &row[3]);
        let crc = u32::from_str_radix(row[4].trim_start_matches("0x"), 16).expect("crc");
        let found = reads.iter().find_map(|(q, a)| {
            let header = parse_request_header(q).ok()?;
            let Request::GetMulti { items, .. } = parse_request(&header).ok()? else {
                return None;
            };
            let n = items
                .iter()
                .position(|it| it.access() == *access && it.crc == crc)?
                + 1;
            let r = parse_response(a).ok()?;
            let reply = parse_get_multi(&r).ok()?;
            reply
                .values
                .into_iter()
                .find(|(k, _)| *k as usize == n)
                .map(|(_, v)| v)
        });
        let Some(wire) = found else { continue };
        let sdt: u8 = row[2].parse().expect("sdt");
        let (value, _) = tree
            .decode(&name, &wire)
            .unwrap_or_else(|e| panic!("readmap row {i}: {:?}", e.kind));
        assert!(
            same(&value, sdt, &row[7]),
            "readmap row {i}: value differs (softdatatype {sdt})"
        );
        checked += 1;
    }
    // run2: the many-tag reads, in request order
    let run2 = pdu_file(&dir.join("run2-pdus.txt"));
    let rows = file_rows(&dir.join("run2"), "readmany-");
    let mut values: Vec<(String, Option<WireValue>)> = Vec::new();
    for (q, a) in pairs(&run2) {
        let header = parse_request_header(&q).expect("header");
        let Request::GetMulti { items, .. } = parse_request(&header).expect("request") else {
            continue;
        };
        let reply = parse_get_multi(&parse_response(&a).expect("response")).expect("values");
        for (n, item) in items.iter().enumerate() {
            let v = reply
                .values
                .iter()
                .find(|(k, _)| *k as usize == n + 1)
                .map(|(_, v)| v.clone());
            values.push((item.access(), v));
        }
    }
    let mut many = 0;
    for (i, row) in rows.iter().enumerate() {
        let Some((_, Some(wire))) = values.iter().find(|(acc, _)| *acc == row[3]) else {
            continue;
        };
        let sdt: u8 = row[2].parse().expect("sdt");
        let name = plain_name(&tree, &row[1]);
        let (value, _) = tree
            .decode(&name, wire)
            .unwrap_or_else(|e| panic!("readmany row {i}: {:?}", e.kind));
        assert!(
            same(&value, sdt, &row[6]),
            "readmany row {i}: value differs (softdatatype {sdt})"
        );
        many += 1;
    }
    assert!(checked > 10 && many > 10, "{checked} / {many} values");
    eprintln!("value parity: {checked} readmap and {many} readmany values");
}

#[test]
fn the_captured_write_is_rebuilt_from_its_name_and_value() {
    let Some(dir) = captures() else { return };
    let (tree, _) = run1_tree(&dir);
    let symbols = tree.symbols();
    let logs = write_session_log(&dir);
    let pdus = app_log(&logs[0]);
    let mut rebuilt = 0;
    for p in pdus.iter().filter(|p| p.to_plc) {
        let header = parse_request_header(&p.bytes).expect("header");
        let Ok(Request::SetMulti {
            integrity: Some(integrity),
            fields,
            values,
            ..
        }) = parse_request(&header)
        else {
            continue;
        };
        let address = ciplink::s7plus::wire::split_addresses(&fields, 1).expect("address");
        // find the symbol with this address in the browsed table, then encode the value from its name
        let symbol = symbols
            .iter()
            .find(|s| s.access == address[0].access() && s.crc == address[0].crc)
            .expect("the written symbol is in the table");
        let Some(Scalar::Bool(b)) = values[0].1.as_scalar() else {
            panic!("a BOOL write");
        };
        let (item, wire) = tree.encode(&symbol.name, &Value::Bool(*b)).expect("encode");
        let pdu = ciplink::s7plus::wire::set_multi(
            header.sequence,
            header.session,
            &[(item, wire)],
            integrity,
        );
        assert!(pdu == p.bytes, "write request not rebuilt byte for byte");
        rebuilt += 1;
    }
    assert_eq!(rebuilt, 2);
}

#[test]
fn the_certificate_fingerprint_formats_as_the_private_notes_say() {
    let Some(dir) = captures() else { return };
    let der = std::fs::read(dir.join("run1").join("server-cert-0.der")).expect("certificate");
    let fp = ciplink::s7plus::wire::fingerprint(&der);
    let got = ciplink::s7plus::wire::format_fingerprint(&fp);
    let spec = std::fs::read_to_string(dir.join("..").join("spec").join("s7commplus-spec.md"))
        .expect("spec");
    let marker = "SHA-256 fingerprint `";
    let start = spec.find(marker).expect("fingerprint in the private notes") + marker.len();
    let want = spec.get(start..start + 95).expect("fingerprint text");
    assert!(got == want, "fingerprint differs");
    assert!(ciplink::s7plus::wire::parse_fingerprint(want).is_ok_and(|p| p == fp));
}

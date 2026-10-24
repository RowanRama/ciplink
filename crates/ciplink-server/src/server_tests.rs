//! Ports of ciplink-tagserver's tests through a running server: tests/test_ws.py, tests/test_http.py, the server
//! parts of test_worker.py, test_tiers.py, test_groups.py and test_decorators.py, and the two conformance tests
//! that need control of the mock (tests/conformance/test_protocol.py).
#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ciplink::Value;
use serde_json::{Value as Json, json};

use crate::config::load_config;
use crate::server::ServerHandle;
use crate::testing::{
    Closed, Make, TempDir, Ws, atomic, audit_lines, other, plant, st, strct, string, udt, vq,
};

fn make() -> Make<'static> {
    Make::default()
}

/// Waits (polling) until `cond` holds; panics after 5 s.
async fn wait_for(mut cond: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(5);
    while !cond() {
        assert!(Instant::now() < end, "condition not met");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn is_values(m: &Json) -> bool {
    m["op"] == "values"
}

fn is_ack(m: &Json) -> bool {
    m["op"] == "ack"
}

fn sorted_tiers(tiers: indexmap::IndexMap<String, u8>) -> Vec<(String, u8)> {
    let mut t: Vec<(String, u8)> = tiers.into_iter().collect();
    t.sort();
    t
}

fn tiers(pairs: &[(&str, u8)]) -> Vec<(String, u8)> {
    let mut t: Vec<(String, u8)> = pairs.iter().map(|(k, v)| ((*k).to_owned(), *v)).collect();
    t.sort();
    t
}

// ------------------------------------------------------------------------------------------------ test_worker.py

#[tokio::test(flavor = "multi_thread")]
async fn always_tags_are_polled_without_subscribers() {
    let server = Make {
        extra: "[[plc.PLC1.rule]]\nmatch = \"Count\"\nalways = true\n",
        ..make()
    }
    .start(|f| f["PLC1"].lock().set("Count", Value::DInt(9)));
    let worker = server.worker("PLC1");
    wait_for(|| sorted_tiers(worker.tiers()) == tiers(&[("Count", 1)])).await;
    wait_for(|| {
        worker
            .snapshot("Count")
            .is_some_and(|e| vq(&e.to_json()) == json!([9, "good"]))
    })
    .await;
    let mut ws = server.ws().await;
    ws.hello("s3cret").await;
    ws.send(json!({"op": "sub", "id": 1, "tags": ["Count"]}))
        .await;
    assert_eq!(
        vq(&ws.until(is_values).await["d"]["Count"]),
        json!([9, "good"])
    );
}

// ------------------------------------------------------------------------------------------------ test_tiers.py

#[tokio::test(flavor = "multi_thread")]
async fn hub_tiers_and_grace() {
    let server = Make {
        server: "grace_s = 0.3",
        ..make()
    }
    .start(|_| {});
    {
        let mut f = server.fake();
        f.set("A", Value::DInt(1));
        f.set("B", Value::DInt(2));
    }
    let worker = server.worker("PLC1");
    let mut ws = server.ws().await;
    ws.hello("s3cret").await;
    ws.send(json!({"op": "sub", "id": 1, "tags": ["A", "B"]}))
        .await;
    ws.send(json!({"op": "sub", "id": 2, "tags": ["B"], "tier": 3}))
        .await;
    ws.send(json!({"op": "sub", "id": 3, "tags": ["A"], "tier": 2}))
        .await;
    ws.until(|m| is_ack(m) && m["id"] == 3).await;
    assert_eq!(sorted_tiers(worker.tiers()), tiers(&[("A", 1), ("B", 1)])); // the lowest tier wins
    ws.send(json!({"op": "unsub", "id": 1})).await;
    ws.until(is_ack).await;
    assert_eq!(sorted_tiers(worker.tiers()), tiers(&[("A", 2), ("B", 2)])); // B in its grace
    wait_for(|| sorted_tiers(worker.tiers()) == tiers(&[("A", 2), ("B", 3)])).await;
    let stats = server.get("/stats").await;
    let plc = &stats["plcs"]["PLC1"];
    assert_eq!(
        (&plc["tier1"], &plc["tier2"], &plc["tier3"]),
        (&json!(0), &json!(1), &json!(1))
    );
    ws.send(json!({"op": "sub", "id": 4, "tags": ["X"], "tier": 4}))
        .await;
    let error = ws.until_op("error").await;
    assert!(error["error"].as_str().unwrap().contains("tier"));
}

#[tokio::test(flavor = "multi_thread")]
async fn page_learning_and_page_subscriptions() {
    let dir = Arc::new(TempDir::new());
    let server = make().start_in(Arc::clone(&dir), |_| {});
    {
        let mut f = server.fake();
        for (k, v) in [("A", 1), ("B", 2), ("C", 3)] {
            f.set(k, Value::DInt(v));
        }
    }
    let worker = server.worker("PLC1");
    let mut nav = server.ws().await;
    let mut page = server.ws().await;
    nav.hello("s3cret").await;
    page.hello("s3cret").await;
    // not learned yet: empty
    nav.send(json!({"op": "sub", "id": 1, "page": "/line1", "tier": 2}))
        .await;
    assert_eq!(nav.until(is_ack).await["ok"], true);
    assert!(worker.tiers().is_empty());

    page.send(json!({"op": "sub", "id": 1, "tags": ["A", "PLC1/B"], "page": "/line1"}))
        .await;
    page.until(is_values).await;
    // tier 2 doesn't teach
    page.send(json!({"op": "sub", "id": 2, "tags": ["C"], "page": "/line1", "tier": 2}))
        .await;
    page.until(|m| is_ack(m) && m["id"] == 2).await;
    page.send(json!({"op": "unsub", "id": 1})).await;
    page.until(|m| is_ack(m) && m["id"] == 1).await;
    // the page subscription followed what /line1 learned, so A and B stay polled at tier 2
    assert_eq!(
        sorted_tiers(worker.tiers()),
        tiers(&[("A", 2), ("B", 2), ("C", 2)])
    );
    let mut d = serde_json::Map::new();
    while d.len() < 2 {
        // its values are keyed by the plain names (one PLC)
        d.extend(nav.until(is_values).await["d"].as_object().unwrap().clone());
    }
    assert_eq!(
        (vq(&d["A"]), vq(&d["B"])),
        (json!([1, "good"]), json!([2, "good"]))
    );

    nav.send(json!({"op": "sub", "id": 5})).await;
    assert_eq!(nav.until_op("error").await["error"], "missing field 'tags'");
    nav.close().await;
    page.close().await;

    let pages = dir.path().join("pages.json");
    wait_for(|| pages.exists()).await;
    let learned: Json = serde_json::from_str(&std::fs::read_to_string(&pages).unwrap()).unwrap();
    assert_eq!(learned, json!({"/line1": ["PLC1/A", "PLC1/B"]}));
    server.handle.stop().unwrap();

    // a restart loads what was learned
    let server = make().start_in(dir, |_| {});
    let mut nav = server.ws().await;
    nav.hello("s3cret").await;
    nav.send(json!({"op": "sub", "id": 1, "page": "/line1", "tier": 2}))
        .await;
    nav.until(is_ack).await;
    assert_eq!(
        sorted_tiers(server.worker("PLC1").tiers()),
        tiers(&[("A", 2), ("B", 2)])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stats_counts_after_planning() {
    let server = make().start(|f| plant(&mut f["PLC1"].lock()));
    let mut ws = server.ws().await;
    ws.hello("s3cret").await;
    ws.send(json!({"op": "sub", "id": 1, "tags": ["Line1.Motor.Speed", "Line1.Motor.Current", "Speed"]}))
        .await;
    ws.send(json!({"op": "sub", "id": 2, "tags": ["Count"], "tier": 2}))
        .await;
    ws.until(|m| is_ack(m) && m["id"] == 2).await;
    server
        .wait_get("/stats", |s| s["plcs"]["PLC1"]["tags_per_cycle"] == 3)
        .await;
    let stats = server.get("/stats").await;
    let plc = &stats["plcs"]["PLC1"];
    assert_eq!(
        json!([
            plc["tier1"],
            plc["tier2"],
            plc["reads_per_cycle"],
            plc["subscriptions"]
        ]),
        json!([3, 1, 2, 4])
    );
}

// ------------------------------------------------------------------------------------------------ test_groups.py

#[tokio::test(flavor = "multi_thread")]
async fn hub_groups_in_stats_and_info() {
    let server = Make {
        extra: "[[plc.PLC1.group]]\nname = \"fast\"\nrate_ms = 10\nmatch = \"Speed\"\n",
        ..make()
    }
    .start(|_| {});
    {
        let mut f = server.fake();
        f.set("Speed", Value::LReal(1.5));
        f.set("Count", Value::DInt(2));
    }
    let mut ws = server.ws().await;
    ws.hello("s3cret").await;
    ws.send(json!({"op": "sub", "id": 1, "tags": ["Speed", "Count"]}))
        .await;
    let info = ws.until_op("info").await;
    assert_eq!(info["d"]["Speed"]["group"], "fast");
    assert_eq!(info["d"]["Speed"]["rate_ms"], 10);
    let stats = server
        .wait_get("/stats", |s| {
            !s["plcs"]["PLC1"]["groups"]["fast"]["last_period_ms"].is_null()
        })
        .await;
    let fast = &stats["plcs"]["PLC1"]["groups"]["fast"];
    assert_eq!((&fast["tags"], &fast["rate_ms"]), (&json!(1), &json!(10)));
}

// ------------------------------------------------------------------------------------------------ test_ws.py

/// The 0.2 write tests' tags made writable (writes need a writable rule and a token pattern).
const WRITABLE: &str = r#"
[[plc.PLC1.rule]]
match = "SpeedSP"
min = 0
max = 1800
units = "rpm"

[[plc.PLC1.rule]]
match = ["Speed*", "Program:Main.Door*"]
writable = true

[[plc.PLC1.rule]]
match = "Word"
bits = { EStop = 0, Door = 1 }
"#;

#[tokio::test(flavor = "multi_thread")]
async fn welcome() {
    let server = make().start(|_| {});
    let mut ws = server.ws().await;
    let welcome = ws.hello("s3cret").await;
    assert_eq!(
        (&welcome["v"], &welcome["write"]),
        (&json!(1), &json!(true))
    );
    let plcs: Vec<&String> = welcome["plcs"].as_object().unwrap().keys().collect();
    assert_eq!(plcs, ["PLC1"]);
    assert_eq!(
        welcome["features"],
        json!(["info", "momentary", "readback", "errors"])
    );
    let mut ws = server.ws().await;
    assert_eq!(ws.hello("view").await["write"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_failure_closes_4401() {
    let server = make().start(|_| {});
    for first in [
        json!({"op": "hello", "v": 1, "token": "wrong"}),
        json!({"op": "sub", "id": 1, "tags": ["Speed"]}),
        json!({"op": "hello", "v": 2, "token": "s3cret"}),
    ] {
        let mut ws = server.ws().await;
        ws.send(first).await;
        assert_eq!(ws.recv().await, Err(Closed::Code(4401)));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn subscribe_snapshot_and_changes_only() {
    let server = make().start(|_| {});
    {
        let mut f = server.fake();
        f.set("Speed", Value::DInt(10));
        f.set("Count", Value::DInt(1));
    }
    let mut ws = server.ws().await;
    ws.hello("s3cret").await;
    ws.send(json!({"op": "sub", "id": 1, "tags": ["Speed", "PLC1/Count", "Nope"], "tier": 1}))
        .await;
    assert_eq!(
        ws.until(is_ack).await,
        json!({"op": "ack", "id": 1, "ok": true, "error": null})
    );
    let first = ws.until(is_values).await["d"].clone();
    assert_eq!(vq(&first["Speed"]), json!([10, "good"]));
    assert_eq!(vq(&first["PLC1/Count"]), json!([1, "good"])); // keyed by the name as subscribed
    assert_eq!(vq(&first["Nope"]), json!([null, "missing"]));
    assert_eq!(first["Nope"][3]["kind"], "not_found");
    assert_eq!(first["Speed"][3], Json::Null);
    assert!(first["Speed"][2].is_i64());

    server.fake().set("Speed", Value::DInt(11));
    let changed = ws.until(is_values).await;
    let keys: Vec<&String> = changed["d"].as_object().unwrap().keys().collect();
    assert_eq!(keys, ["Speed"]);
    ws.close().await;

    // a new session gets the cached values at once
    let mut ws = server.ws().await;
    ws.hello("s3cret").await;
    ws.send(json!({"op": "sub", "id": 7, "tags": ["Speed"]}))
        .await;
    ws.until(is_ack).await;
    assert_eq!(
        vq(&ws.until(is_values).await["d"]["Speed"]),
        json!([11, "good"])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn two_sessions_share_a_tag_and_unsub_stops_polling() {
    let server = make().start(|_| {});
    server.fake().set("Speed", Value::DInt(5));
    let mut a = server.ws().await;
    let mut b = server.ws().await;
    a.hello("s3cret").await;
    b.hello("s3cret").await;
    a.send(json!({"op": "sub", "id": 1, "tags": ["Speed"]}))
        .await;
    a.until(is_values).await;
    b.send(json!({"op": "sub", "id": 1, "tags": ["Speed"]}))
        .await;
    assert_eq!(b.until(is_ack).await["ok"], true);
    assert_eq!(
        vq(&b.until(is_values).await["d"]["Speed"]),
        json!([5, "good"])
    ); // snapshot

    server.fake().set("Speed", Value::DInt(6));
    assert_eq!(a.until(is_values).await["d"]["Speed"][0], 6);
    assert_eq!(b.until(is_values).await["d"]["Speed"][0], 6);

    a.send(json!({"op": "unsub", "id": 1})).await;
    assert_eq!(a.until(is_ack).await["ok"], true);
    tokio::time::sleep(Duration::from_millis(100)).await;
    server.fake().reads.clear();
    wait_for(|| server.fake().reads.len() >= 2).await;
    // b still subscribes
    assert!(
        server
            .fake()
            .reads
            .iter()
            .all(|r| r.contains(&"Speed".to_owned()))
    );

    b.send(json!({"op": "unsub", "id": 1})).await;
    b.until(is_ack).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    server.fake().reads.clear();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(server.fake().reads.is_empty()); // refcount 0: no longer polled
    assert_eq!(
        server.get("/stats").await["plcs"]["PLC1"]["subscriptions"],
        0
    );

    b.send(json!({"op": "unsub", "id": 99})).await;
    assert_eq!(
        b.until(is_ack).await,
        json!({"op": "ack", "id": 99, "ok": false, "error": "unknown id"})
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn closing_a_session_drops_its_subscriptions() {
    let server = make().start(|_| {});
    let mut ws = server.ws().await;
    ws.hello("s3cret").await;
    ws.send(json!({"op": "sub", "id": 1, "tags": ["A", "B"]}))
        .await;
    ws.until(is_values).await;
    assert_eq!(server.get("/stats").await["sessions"], 1);
    ws.close().await;
    server.wait_get("/stats", |s| s["sessions"] == 0).await;
    assert!(server.worker("PLC1").tiers().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_requests() {
    let server = Make {
        names: &["A", "B"],
        ..make()
    }
    .start(|_| {});
    let mut ws = server.ws().await;
    ws.hello("s3cret").await;
    ws.send_text("not json").await;
    assert_eq!(ws.until_op("error").await["id"], Json::Null);
    ws.send(json!({"op": "frobnicate", "id": 3})).await;
    assert_eq!(
        ws.until_op("error").await,
        json!({"op": "error", "id": 3, "error": "unknown op 'frobnicate'"})
    );
    // two PLCs: must be qualified
    ws.send(json!({"op": "sub", "id": 4, "tags": ["Speed"]}))
        .await;
    let msg = ws.until_op("error").await;
    assert_eq!(msg["id"], 4);
    assert!(msg["error"].as_str().unwrap().contains("qualified"));
    ws.send(json!({"op": "sub", "id": 5})).await;
    assert_eq!(ws.until_op("error").await["error"], "missing field 'tags'");
}

#[tokio::test(flavor = "multi_thread")]
async fn write_checks_readback_and_audit() {
    let server = Make {
        extra: WRITABLE,
        ..make()
    }
    .start(|_| {});
    let mut ws = server.ws().await;
    ws.hello("s3cret").await;
    server.connected("PLC1").await;
    assert_eq!(
        ws.write(1, "SpeedSP", json!(42)).await,
        json!({"op": "ack", "id": 1, "ok": true, "error": null, "kind": null, "value": 42}) // the read-back
    );
    assert_eq!(server.fake().written(), [("SpeedSP".to_owned(), json!(42))]);
    // patterns match case-insensitively
    assert_eq!(
        ws.write(2, "PLC1/program:main.DoorOpen", json!(true)).await["ok"],
        true
    );
    assert_eq!(
        ws.write(3, "Other", json!(1)).await,
        json!({"op": "ack", "id": 3, "ok": false, "error": "not allowed", "kind": "not_allowed", "value": null})
    );
    assert_eq!(
        ws.write(4, "SpeedSP", json!(1801)).await["kind"],
        "out_of_range"
    );
    assert_eq!(
        ws.write(5, "B/SpeedSP", json!(1)).await["kind"],
        "bad_request"
    );
    ws.close().await;
    assert_eq!(server.fake().writes.len(), 2);

    let mut ws = server.ws().await;
    ws.hello("view").await;
    assert_eq!(
        ws.write(1, "SpeedSP", json!(1)).await["error"],
        "not allowed"
    );

    let lines = audit_lines(&server.audit_log(), 6);
    let got: Vec<Json> = lines
        .iter()
        .map(|l| {
            json!([
                l["token"], l["tag"], l["old"], l["value"], l["ok"], l["error"], l["kind"]
            ])
        })
        .collect();
    assert_eq!(
        got,
        [
            json!(["hmi1", "PLC1/SpeedSP", null, 42, true, null, null]),
            json!([
                "hmi1",
                "PLC1/program:main.DoorOpen",
                null,
                true,
                true,
                null,
                null
            ]),
            json!([
                "hmi1",
                "PLC1/Other",
                null,
                1,
                false,
                "not allowed",
                "not_allowed"
            ]),
            json!([
                "hmi1",
                "PLC1/SpeedSP",
                null,
                1801,
                false,
                "out of range",
                "out_of_range"
            ]),
            json!([
                "hmi1",
                "B/SpeedSP",
                null,
                1,
                false,
                "unknown PLC 'B'",
                "bad_request"
            ]),
            json!([
                "viewer",
                "PLC1/SpeedSP",
                null,
                1,
                false,
                "not allowed",
                "not_allowed"
            ]),
        ]
    );
    assert!(
        lines
            .iter()
            .all(|l| l.get("time").is_some() && l.get("momentary").is_none())
    );
    let stats = server.get("/stats").await;
    assert_eq!(
        json!([
            stats["writes"],
            stats["write_rejects"],
            stats["momentary_timeouts"]
        ]),
        json!([2, 4, 0])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn write_needs_a_writable_rule() {
    let server = Make {
        extra: "[[plc.PLC1.rule]]\nmatch = \"Speed*\"\nunits = \"rpm\"\n",
        ..make()
    }
    .start(|_| {});
    // the token pattern alone no longer allows a write
    let mut ws = server.ws().await;
    ws.hello("s3cret").await;
    server.connected("PLC1").await;
    assert_eq!(
        ws.write(1, "SpeedSP", json!(42)).await["kind"],
        "not_writable"
    );
    assert!(server.fake().writes.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn audit_old_value_from_the_cache() {
    let server = Make {
        extra: WRITABLE,
        ..make()
    }
    .start(|_| {});
    server.fake().set("SpeedSP", Value::DInt(7));
    let mut ws = server.ws().await;
    ws.hello("s3cret").await;
    ws.send(json!({"op": "sub", "id": 1, "tags": ["SpeedSP"]}))
        .await;
    ws.until(is_values).await;
    assert_eq!(ws.write(2, "SpeedSP", json!(8)).await["value"], 8);
    assert_eq!(audit_lines(&server.audit_log(), 1)[0]["old"], 7);
}

#[tokio::test(flavor = "multi_thread")]
async fn write_ack_with_driver_error() {
    let server = Make {
        extra: WRITABLE,
        ..make()
    }
    .start(|_| {});
    server.fake().write_error = Some(other("Privilege violation"));
    let mut ws = server.ws().await;
    ws.hello("s3cret").await;
    server.connected("PLC1").await;
    let ack = ws.write(9, "SpeedSP", json!(1)).await;
    assert_eq!(
        json!([ack["ok"], ack["error"], ack["value"]]),
        json!([false, "Privilege violation", null])
    );
    assert!(!ack["kind"].is_null());
    let lines = audit_lines(&server.audit_log(), 1);
    let line = lines.last().unwrap();
    assert_eq!(
        (&line["ok"], &line["error"]),
        (&json!(false), &json!("Privilege violation"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn write_while_disconnected() {
    let server = Make {
        extra: WRITABLE,
        ..make()
    }
    .start(|f| f["PLC1"].lock().fail = true);
    let mut ws = server.ws().await;
    ws.hello("s3cret").await;
    let ack = ws.write(1, "SpeedSP", json!(1)).await;
    assert_eq!(
        (&ack["error"], &ack["kind"]),
        (&json!("PLC not connected"), &json!("refused"))
    );
    assert!(server.fake().writes.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn info_before_the_snapshot_and_bit_names() {
    let server = Make {
        extra: WRITABLE,
        ..make()
    }
    .start(|f| {
        let mut f = f["PLC1"].lock();
        f.tags.insert("SpeedSP".into(), atomic("REAL", &[]));
        f.tags.insert("Word".into(), atomic("DINT", &[]));
        f.set("SpeedSP", Value::LReal(1.5));
        f.set("Word", Value::DInt(0b10));
    });
    let mut ws = server.ws().await;
    ws.hello("s3cret").await;
    server.connected("PLC1").await;
    ws.send(json!({"op": "sub", "id": 1, "tags": ["SpeedSP", "Word.Door", "Word.1"]}))
        .await;
    let info = ws.until_op("info").await["d"].clone();
    assert_eq!(
        info["SpeedSP"],
        json!({"type": "REAL", "writable": true, "rate_ms": 20, "group": null, "min": 0, "max": 1800,
               "units": "rpm"})
    );
    let bit = json!({"type": "BOOL", "writable": false, "rate_ms": 20, "group": null});
    assert_eq!((&info["Word.Door"], &info["Word.1"]), (&bit, &bit));
    let mut d = serde_json::Map::new();
    while d.len() < 3 {
        d.extend(ws.until(is_values).await["d"].as_object().unwrap().clone());
    }
    // an alias and its bit, both as sent
    assert_eq!(
        (vq(&d["Word.Door"]), vq(&d["Word.1"])),
        (json!([true, "good"]), json!([true, "good"]))
    );
    // resolved by the server
    assert!(
        !server
            .fake()
            .reads
            .iter()
            .flatten()
            .any(|t| t == "Word.Door")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn momentary_over_the_socket() {
    let server = Make {
        extra: WRITABLE,
        server: "grace_s = 0\nmomentary_timeout_ms = 300",
        ..make()
    }
    .start(|_| {});
    server.fake().set("SpeedStart", Value::Bool(false));
    let mut ws = server.ws().await;
    ws.hello("s3cret").await;
    server.connected("PLC1").await;
    ws.send(json!({"op": "momentary", "id": 1, "tag": "SpeedStart", "action": "press"}))
        .await;
    assert_eq!(
        ws.until(is_ack).await,
        json!({"op": "ack", "id": 1, "ok": true, "error": null, "kind": null, "value": true})
    );
    for _ in 0..4 {
        // holds keep it pressed past the timeout
        ws.send(json!({"op": "momentary", "tag": "SpeedStart", "action": "hold"}))
            .await;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        server.fake().written(),
        [("SpeedStart".to_owned(), json!(true))]
    );
    // no hold: released by the watchdog
    wait_for(|| server.fake().written().last() == Some(&("SpeedStart".to_owned(), json!(false))))
        .await;
    ws.send(json!({"op": "momentary", "id": 2, "tag": "SpeedStart", "action": "press"}))
        .await;
    assert_eq!(ws.until(is_ack).await["ok"], true);
    ws.send(json!({"op": "momentary", "id": 3, "tag": "SpeedStart", "action": "release"}))
        .await;
    assert_eq!(ws.until(is_ack).await["value"], false);
    ws.send(json!({"op": "momentary", "id": 4, "tag": "SpeedStart", "action": "push"}))
        .await;
    assert_eq!(
        ws.until_op("error").await,
        json!({"op": "error", "id": 4, "error": "unknown action 'push'"})
    );
    ws.send(json!({"op": "momentary", "id": 5, "tag": "SpeedStart", "action": "press"}))
        .await;
    assert_eq!(ws.until(is_ack).await["ok"], true);
    ws.close().await;
    wait_for(|| server.fake().writes.len() == 6).await; // the closed session's press is released
    assert_eq!(
        server.fake().written().last(),
        Some(&("SpeedStart".to_owned(), json!(false)))
    );
    let lines = audit_lines(&server.audit_log(), 6);
    let got: Vec<&Json> = lines.iter().map(|l| &l["momentary"]).collect();
    assert_eq!(
        got,
        [
            &json!("press"),
            &json!("timeout"),
            &json!("press"),
            &json!("release"),
            &json!("press"),
            &json!("disconnect")
        ]
    );
    assert_eq!(server.get("/stats").await["momentary_timeouts"], 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn disconnect_marks_stale_then_reconnects() {
    let server = make().start(|_| {});
    server.fake().set("Speed", Value::DInt(3));
    let mut ws = server.ws().await;
    ws.hello("s3cret").await;
    ws.send(json!({"op": "sub", "id": 1, "tags": ["Speed"]}))
        .await;
    assert_eq!(
        vq(&ws.until(is_values).await["d"]["Speed"]),
        json!([3, "good"])
    );

    server.fake().fail = true;
    // status (a control message) may go out before the stale values
    let mut seen: HashMap<String, Json> = HashMap::new();
    while seen.len() < 2 {
        let msg = ws
            .until(|m| m["op"] == "values" || m["op"] == "status")
            .await;
        let op = msg["op"].as_str().unwrap().to_owned();
        seen.entry(op).or_insert(msg);
    }
    let speed = &seen["values"]["d"]["Speed"];
    assert_eq!(*speed, json!([3, "stale", speed[2], null])); // value kept
    assert_eq!(seen["status"]["plcs"], json!({"PLC1": "disconnected"}));

    server.fake().fail = false;
    ws.until(|m| m["op"] == "status" && m["plcs"]["PLC1"] == "connected")
        .await;
    assert_eq!(
        vq(&ws.until(is_values).await["d"]["Speed"]),
        json!([3, "good"])
    );
    let health = server.get("/health").await;
    assert!(health["plcs"]["PLC1"]["reconnects"].as_u64().unwrap() >= 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn reload_sends_meta() {
    let server = make().start(|_| {});
    server.fake().set("Speed", Value::DInt(1));
    let mut ws = server.ws().await;
    ws.hello("s3cret").await;
    ws.send(json!({"op": "sub", "id": 1, "tags": ["Speed"]}))
        .await;
    ws.until(is_values).await;
    {
        let mut f = server.fake();
        f.tags.insert("Speed".into(), atomic("DINT", &[]));
        f.version = 2; // as if ciplink reloaded the tag table during a read
    }
    assert_eq!(
        ws.until_op("meta").await,
        json!({"op": "meta", "plc": "PLC1"})
    );
    assert_eq!(server.get("/health").await["plcs"]["PLC1"]["reloads"], 1);
    let (_, _, body) = crate::testing::http(
        server.handle.addr(),
        "GET",
        "/tags",
        &[("Authorization", "Bearer view")],
    )
    .await;
    // tag list rebuilt after the reload
    assert_eq!(body["tags"], json!([{"name": "Speed", "type": "DINT"}]));
}

#[tokio::test(flavor = "multi_thread")]
async fn several_plcs() {
    let server = Make {
        names: &["A", "B"],
        ..make()
    }
    .start(|_| {});
    server.fakes["A"].lock().set("X", Value::DInt(1));
    server.fakes["B"].lock().set("X", Value::DInt(2));
    let mut ws = server.ws().await;
    ws.hello("s3cret").await;
    ws.send(json!({"op": "sub", "id": 1, "tags": ["A/X", "B/X"]}))
        .await;
    let mut d = serde_json::Map::new();
    while d.len() < 2 {
        d.extend(ws.until(is_values).await["d"].as_object().unwrap().clone());
    }
    assert_eq!((&d["A/X"][0], &d["B/X"][0]), (&json!(1), &json!(2)));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_write_with_a_missing_field_gets_a_bad_request_ack() {
    let server = Make {
        extra: WRITABLE,
        ..make()
    }
    .start(|_| {});
    let mut ws = server.ws().await;
    ws.hello("s3cret").await;
    server.connected("PLC1").await;
    ws.send(json!({"op": "write", "id": 5, "tag": "SpeedSP"}))
        .await;
    assert_eq!(
        ws.until(|m| is_ack(m) && m["id"] == 5).await,
        json!({"op": "ack", "id": 5, "ok": false, "error": "missing value", "kind": "bad_request", "value": null})
    );
    ws.send(json!({"op": "momentary", "id": 6, "action": "press"}))
        .await;
    assert_eq!(
        ws.until(|m| is_ack(m) && m["id"] == 6).await["kind"],
        "bad_request"
    );
    let kinds: Vec<Json> = audit_lines(&server.audit_log(), 2)
        .iter()
        .map(|l| l["kind"].clone())
        .collect();
    assert_eq!(kinds, [json!("bad_request"), json!("bad_request")]);
    assert_eq!(server.get("/stats").await["write_rejects"], 2);
}

// ------------------------------------------------------------------------------------------------ test_http.py

#[tokio::test(flavor = "multi_thread")]
async fn health() {
    let server = Make {
        names: &["A", "B"],
        ..make()
    }
    .start(|f| f["B"].lock().fail = true);
    let health = server
        .wait_get("/health", |h| !h["plcs"]["A"]["last_ok_ts"].is_null())
        .await;
    let plcs = &health["plcs"];
    assert_eq!(plcs["A"]["state"], "connected");
    assert!(["connecting", "disconnected"].contains(&plcs["B"]["state"].as_str().unwrap()));
    let mut keys: Vec<&String> = plcs["A"].as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "last_cycle_ms",
            "last_ok_ts",
            "reconnects",
            "reloads",
            "state"
        ]
    );
    assert_eq!(plcs["A"]["reloads"], 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn stats() {
    let server = make().start(|_| {});
    {
        let mut f = server.fake();
        f.set("A", Value::DInt(1));
        f.set("B", Value::DInt(2));
    }
    let mut ws = server.ws().await;
    ws.hello("s3cret").await;
    ws.send(json!({"op": "sub", "id": 1, "tags": ["A", "B"]}))
        .await;
    ws.until(is_values).await;
    let stats = server
        .wait_get("/stats", |s| s["plcs"]["PLC1"]["reads_per_cycle"] == 2)
        .await;
    assert_eq!(stats["sessions"], 1);
    let plc = &stats["plcs"]["PLC1"];
    assert_eq!(
        (&plc["subscriptions"], &plc["cycle_ms"]),
        (&json!(2), &json!(20))
    );
    assert!(plc.get("overruns").is_some() && !plc["last_cycle_ms"].is_null());
    assert_eq!(
        json!([
            plc["tier1"],
            plc["tier2"],
            plc["tags_per_cycle"],
            plc["group_fallbacks"]
        ]),
        json!([2, 0, 2, 0])
    );
    assert_eq!(plc["groups"], json!({}));
}

#[tokio::test(flavor = "multi_thread")]
async fn tags() {
    let server = make().start(|f| {
        let mut f = f["PLC1"].lock();
        f.tags.insert("Speed".into(), atomic("REAL", &[]));
        f.tags.insert("Valve1".into(), strct("MyAOI", 4, &[]));
        f.types.insert(
            "MyAOI".into(),
            udt(
                4,
                vec![
                    ("Open", atomic("BOOL", &[])),
                    ("Local1", atomic("BOOL", &[])),
                ],
                Some((false, &["Open"])),
            ),
        );
    });
    let addr = server.handle.addr();
    assert_eq!(crate::testing::http(addr, "GET", "/tags", &[]).await.0, 401);
    let nope = [("Authorization", "Bearer nope")];
    assert_eq!(
        crate::testing::http(addr, "GET", "/tags", &nope).await.0,
        401
    );
    server.connected("PLC1").await;
    let view = [("Authorization", "Bearer view")];
    let body = crate::testing::http(addr, "GET", "/tags?plc=PLC1", &view)
        .await
        .2;
    assert_eq!(
        body["tags"],
        json!([{"name": "Speed", "type": "REAL"}, {"name": "Valve1", "type": "MyAOI", "aoi_readable": ["Open"]}])
    );
    assert_eq!(
        crate::testing::http(addr, "GET", "/tags?plc=Nope", &view)
            .await
            .0,
        404
    );
}

const GROUPS: &str = r#"
[[plc.PLC1.rule]]
match = "Tank[*].Level"
units = "%"

[[plc.PLC1.group]]
name = "fast"
rate_ms = 10
match = ["Fast*"]
"#;

#[tokio::test(flavor = "multi_thread")]
async fn tags_types_rules_groups_and_cors() {
    let server = Make {
        extra: GROUPS,
        ..make()
    }
    .start(|f| {
        let mut f = f["PLC1"].lock();
        f.tags.insert("Tank".into(), strct("Tank", 12, &[4]));
        f.tags.insert("Name".into(), string());
        f.types.insert(
            "Tank".into(),
            udt(
                12,
                vec![
                    ("Level", atomic("REAL", &[])),
                    ("Hist", atomic("REAL", &[2])),
                ],
                None,
            ),
        );
    });
    server.connected("PLC1").await;
    let addr = server.handle.addr();
    let (_, headers, body) = crate::testing::http(
        addr,
        "GET",
        "/tags",
        &[("Authorization", "Bearer view"), ("Origin", "http://hmi")],
    )
    .await;
    assert_eq!(headers["access-control-allow-origin"], "*");
    assert_eq!(
        json!([body["plc"], body["state"], body["version"]]),
        json!(["PLC1", "connected", 1])
    );
    assert_eq!(
        body["tags"],
        json!([{"name": "Tank", "type": "Tank", "dims": [4]}, {"name": "Name", "type": "STRING"}])
    );
    assert_eq!(
        body["types"],
        json!({"Tank": {"members": {"Level": {"type": "REAL"}, "Hist": {"type": "REAL", "dims": [2]}}}})
    );
    assert_eq!(
        body["rules"],
        json!([{"match": "Tank[*].Level", "units": "%"}])
    );
    assert_eq!(
        body["groups"],
        json!([{"name": "fast", "rate_ms": 10, "match": ["Fast*"]}])
    );
    let preflight = crate::testing::http(
        addr,
        "OPTIONS",
        "/tags",
        &[
            ("Origin", "http://hmi"),
            ("Access-Control-Request-Method", "GET"),
            ("Access-Control-Request-Headers", "Authorization"),
        ],
    )
    .await;
    assert_eq!(preflight.0, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn stats_groups_and_write_counters() {
    let server = Make {
        extra: GROUPS,
        ..make()
    }
    .start(|_| {});
    {
        let mut f = server.fake();
        f.set("FastA", Value::DInt(1));
        f.set("Slow", Value::DInt(2));
    }
    let stats = server.get("/stats").await;
    assert_eq!(
        json!([
            stats["writes"],
            stats["write_rejects"],
            stats["momentary_timeouts"]
        ]),
        json!([0, 0, 0])
    );
    let mut ws = server.ws().await;
    ws.hello("s3cret").await;
    ws.send(json!({"op": "sub", "id": 1, "tags": ["FastA", "Slow"]}))
        .await;
    ws.until(is_values).await;
    let stats = server
        .wait_get("/stats", |s| {
            s["plcs"]["PLC1"]["groups"]["fast"]["tags"] == 1
        })
        .await;
    let group = &stats["plcs"]["PLC1"]["groups"]["fast"];
    assert_eq!(group["rate_ms"], 10);
    assert!(group.get("last_period_ms").is_some());
}

// ------------------------------------------------------------------------------------------------ test_decorators.py

const MOCK_TAGS: &str = r#"{"types": {"Pump": {"SpeedSP": "REAL", "Running": "BOOL", "Temp": "REAL", "Alarm": "BOOL"}},
 "tags": {"SpeedPumps": "Pump[2]", "SpeedLimit": "REAL"}}"#;

const EXTRA: &str = r#"
[plc.PLC1.udt.Pump]
SpeedSP = { use = "sp", max = 50 }
Temp = "warm"
Alarm = "alarm"

[decorator.sp]
writable = true
min = 0
max = 100
units = "rpm"

[decorator.warm]
units = "C"
rate_ms = 30

[decorator.alarm]
always = true
"#;

async fn mock_server() -> crate::testing::TestServer {
    let dir = Arc::new(TempDir::new());
    let path = dir.path().join("mock_tags.json");
    std::fs::write(&path, MOCK_TAGS).unwrap();
    let extra = format!(
        "mock_tags = \"{}\"\n{EXTRA}",
        path.display().to_string().replace('\\', "/")
    );
    let server = Make {
        mock: true,
        extra: &extra,
        ..make()
    }
    .start_in(dir, |_| {});
    server.connected("PLC1").await;
    server
}

#[tokio::test(flavor = "multi_thread")]
async fn ws_writes_info_rate_and_always() {
    let server = mock_server().await;
    let worker = server.worker("PLC1");
    // always via udt, added on connect
    wait_for(|| worker.tiers().get("SpeedPumps[1].Alarm") == Some(&1)).await;
    assert_eq!(worker.tiers().get("SpeedPumps[0].Alarm"), Some(&1));
    let mut ws = server.ws().await;
    ws.hello("s3cret").await;
    ws.send(json!({"op": "sub", "id": 1, "tags": ["SpeedPumps[1].SpeedSP", "SpeedPumps[0].Temp"]}))
        .await;
    let info = ws.until_op("info").await["d"].clone();
    assert_eq!(
        info["SpeedPumps[1].SpeedSP"],
        json!({"type": "REAL", "writable": true, "rate_ms": 20, "group": null, "min": 0, "max": 50,
               "units": "rpm"})
    );
    assert_eq!(
        info["SpeedPumps[0].Temp"],
        json!({"type": "REAL", "writable": false, "rate_ms": 30, "group": "warm", "units": "C"})
    );
    let mut acks = Vec::new();
    for (i, (tag, value)) in [
        ("SpeedPumps[1].SpeedSP", json!(40.0)),
        ("SpeedPumps[1].SpeedSP", json!(60.0)),
        ("SpeedPumps[0].Running", json!(true)),
        ("SpeedLimit", json!(1.0)),
    ]
    .into_iter()
    .enumerate()
    {
        acks.push(ws.write(10 + i as u64, tag, value).await);
    }
    let got: Vec<Json> = acks.iter().map(|a| json!([a["ok"], a["kind"]])).collect();
    assert_eq!(
        got,
        [
            json!([true, null]),
            json!([false, "out_of_range"]),
            json!([false, "not_writable"]),
            json!([false, "not_writable"])
        ]
    );
    assert_eq!(acks[0]["value"], json!(40.0));
    let stats = server
        .wait_get("/stats", |s| {
            let warm = &s["plcs"]["PLC1"]["groups"]["warm"];
            !warm.is_null() && !warm["last_period_ms"].is_null()
        })
        .await;
    let warm = &stats["plcs"]["PLC1"]["groups"]["warm"];
    assert_eq!((&warm["rate_ms"], &warm["tags"]), (&json!(30), &json!(1)));
}

#[tokio::test(flavor = "multi_thread")]
async fn tags_payload_and_codegen_from_the_server() {
    let server = mock_server().await;
    let addr = server.handle.addr();
    let body = crate::testing::http(addr, "GET", "/tags", &[("Authorization", "Bearer view")])
        .await
        .2;
    assert_eq!(body["udt"]["Pump"]["Temp"], "warm");
    assert_eq!(
        body["decorators"]["warm"],
        json!({"units": "C", "rate_ms": 30})
    );
    assert_eq!(body["tag_settings"], json!({}));
    let out = server.dir.path().join("plc.ts");
    let args: Vec<std::ffi::OsString> = [
        "ciplink-server",
        "types",
        "--url",
        &format!("http://{addr}"),
        "--token",
        "view",
        "--out",
        out.to_str().unwrap(),
    ]
    .iter()
    .map(Into::into)
    .collect();
    let code = tokio::task::spawn_blocking(move || crate::cli::main_as(args, &[]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(code, 0);
    let text = std::fs::read_to_string(&out).unwrap();
    assert!(
        text.contains("    SpeedSP: TagRef<number, true>;\n    Running: TagRef<boolean, false>;\n")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn reload_clears_the_memo_and_updates_always() {
    let tank = || udt(8, vec![("Level", atomic("REAL", &[]))], None);
    let extra =
        "[decorator.watch]\nalways = true\nunits = \"%\"\n[plc.PLC1.udt.Tank]\nLevel = \"watch\"\n";
    let server = Make { extra, ..make() }.start(|f| {
        let mut f = f["PLC1"].lock();
        f.tags.insert("Tanks".into(), strct("Tank", 8, &[2]));
        f.types.insert("Tank".into(), tank());
        f.set(
            "Tanks",
            Value::Array(vec![
                st(vec![("Level", Value::LReal(1.0))]),
                st(vec![("Level", Value::LReal(2.0))]),
            ]),
        );
    });
    let shared = Arc::clone(server.handle.shared());
    let worker = server.worker("PLC1");
    wait_for(|| worker.tiers().get("Tanks[1].Level") == Some(&1)).await;
    assert_eq!(
        shared.rules.effective("PLC1", "Tanks[0].Level")["units"],
        "%"
    );
    {
        // a download changed the type
        let mut f = server.fake();
        f.types.insert("Tank2".into(), tank());
        f.tags.insert("Tanks".into(), strct("Tank2", 8, &[2]));
        f.version = 2;
    }
    wait_for(|| !worker.tiers().contains_key("Tanks[1].Level")).await;
    assert!(shared.rules.effective("PLC1", "Tanks[0].Level").is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn udt_bit_alias_subscribed_before_connect_resolves_on_connect() {
    let extra = "[decorator.stbits]\nbits = { Ready = 3 }\n[plc.PLC1.udt.Axis]\nSt = \"stbits\"\n";
    let server = Make { extra, ..make() }.start(|f| {
        let mut f = f["PLC1"].lock();
        f.fail = true; // the HMI is up before the PLC
        f.tags.insert("Ax".into(), strct("Axis", 8, &[]));
        f.types.insert(
            "Axis".into(),
            udt(8, vec![("St", atomic("DINT", &[]))], None),
        );
        f.set("Ax", st(vec![("St", Value::DInt(8))]));
    });
    let worker = server.worker("PLC1");
    let mut ws = server.ws().await;
    ws.hello("s3cret").await;
    ws.send(json!({"op": "sub", "id": 1, "tags": ["Ax.St.Ready"]}))
        .await;
    assert_eq!(
        ws.until_op("info").await["d"]["Ax.St.Ready"]["type"],
        Json::Null
    );
    server.fake().fail = false;
    let info = ws
        .until(|m| m["op"] == "info" && !m["d"]["Ax.St.Ready"]["type"].is_null())
        .await;
    assert_eq!(info["d"]["Ax.St.Ready"]["type"], "BOOL");
    let values = ws
        .until(|m| is_values(m) && m["d"].get("Ax.St.Ready").is_some())
        .await;
    assert_eq!(values["d"]["Ax.St.Ready"][0], true);
    assert_eq!(sorted_tiers(worker.tiers()), tiers(&[("Ax.St.3", 1)]));
}

#[tokio::test(flavor = "multi_thread")]
async fn example_config_in_mock_mode() {
    let dir = TempDir::new();
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/decorators_example.toml");
    let mut config = load_config(&fixture).unwrap();
    config.port = 0;
    config.audit_log = Some(dir.path().join("audit.log"));
    config.pages_file = None;
    let handle = ServerHandle::start(config.clone(), crate::mock::factory().0).unwrap();
    let addr = handle.addr();
    let shared = Arc::clone(handle.shared());
    let end = Instant::now() + Duration::from_secs(5);
    while shared.workers["PLC1"].state() != "connected" {
        assert!(Instant::now() < end, "mock PLC did not connect");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let eff = |tag: &str| shared.rules.effective("PLC1", tag);
    let rate = |tag: &str| {
        shared
            .rules
            .group("PLC1", tag)
            .map_or(config.cycle_ms, |g| g.rate_ms)
    };
    assert_eq!(eff("Spindle.RPM")["units"], "rpm");
    assert_eq!(eff("Spindle.RPM")["deadband"], 0.5);
    assert_eq!(rate("Spindle.RPM"), 100);
    let sp = eff("Spindle.SpeedSP");
    assert_eq!(
        json!([sp["writable"], sp["min"], sp["max"], sp["units"]]),
        json!([true, 0, 3000, "rpm"])
    );
    assert_eq!(sp["description"], "Spindle speed setpoint");
    assert_eq!(rate("Spindle.Running"), 250);
    assert!(!crate::rules::truthy(
        eff("Spindle.Running").get("writable")
    ));
    assert_eq!(eff("Axes[1].Drive.Motor.Temp")["units"], "°C");
    assert_eq!(rate("Axes[1].Drive.Motor.Temp"), 1000);
    assert_eq!(eff("Axes[0].Drive.Motor.Current")["units"], "A");
    assert_eq!(rate("Axes[0].Drive.Motor.Current"), 250);
    assert_eq!(rate("Axes[0].Drive.Faults[2]"), 250);
    assert_eq!(eff("Axes[1].JogCmd")["writable"], true);
    assert_eq!(eff("ZoneTemp[3]")["units"], "°C");
    assert_eq!(rate("ZoneTemp[3]"), 1000);
    assert_eq!(rate("RecipeName"), 2000);
    assert_eq!(
        shared.rules.group("PLC1", "RecipeName").unwrap().name,
        "tag"
    );
    assert_eq!(
        shared
            .rules
            .resolve("PLC1", "Program:Main.StatusWord.EStop"),
        "Program:Main.StatusWord.0"
    );
    assert_eq!(eff("Program:Main.CmdWord.0")["writable"], true);
    assert_eq!(rate("Grid[3]"), 500);
    assert!(eff("Grid[3]").is_empty());

    let mut ws = Ws::connect(addr).await;
    ws.hello("hmi-secret").await;
    ws.send(
        json!({"op": "sub", "id": 1, "tags": ["Spindle.SpeedSP", "Program:Main.StatusWord.EStop"]}),
    )
    .await;
    let info = ws.until_op("info").await["d"].clone();
    assert_eq!(info["Spindle.SpeedSP"]["writable"], true);
    assert_eq!(info["Spindle.SpeedSP"]["group"], "fast");
    assert_eq!(info["Program:Main.StatusWord.EStop"]["type"], "BOOL");
    ws.send(json!({"op": "momentary", "id": 2, "tag": "Axes[1].JogCmd", "action": "press"}))
        .await;
    assert_eq!(ws.until(|m| is_ack(m) && m["id"] == 2).await["ok"], true);
    ws.send(json!({"op": "momentary", "id": 3, "tag": "Axes[1].JogCmd", "action": "release"}))
        .await;
    assert_eq!(ws.until(|m| is_ack(m) && m["id"] == 3).await["ok"], true);
    assert_eq!(
        ws.write(4, "Program:Main.CmdWord.0", json!(true)).await["ok"],
        true
    );
    assert_eq!(
        ws.write(5, "Spindle.SpeedSP", json!(3500.0)).await["kind"],
        "out_of_range"
    );
    ws.close().await;
    handle.stop().unwrap();
}

// ------------------------------------------------------------------------------------------------ conformance

/// The conformance suite's in-process server: the Test Bench config on the mock.
async fn bench() -> (ServerHandle, Arc<crate::mock::MockState>, TempDir) {
    let dir = TempDir::new();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bench.toml");
    let mut config = load_config(&fixture).unwrap();
    config.port = 0;
    config.audit_log = Some(dir.path().join("audit.log"));
    config.pages_file = None;
    let (factory, states) = crate::mock::factory();
    let handle = ServerHandle::start(config, factory).unwrap();
    let end = Instant::now() + Duration::from_secs(10);
    while handle.shared().workers["PLC1"].state() != "connected" {
        assert!(Instant::now() < end, "mock PLC did not connect");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mock = Arc::clone(&states.lock().unwrap()["PLC1"]);
    (handle, mock, dir)
}

/// test_protocol.py's Client.until: receives until `pred(msg)`, keeping the latest values of every message seen.
async fn until_tracking(
    ws: &mut Ws,
    values: &mut serde_json::Map<String, Json>,
    mut pred: impl FnMut(&Json) -> bool,
) -> Json {
    loop {
        let msg = ws.recv().await.unwrap();
        if is_values(&msg) {
            values.extend(msg["d"].as_object().unwrap().clone());
        }
        if pred(&msg) {
            return msg;
        }
    }
}

/// test_protocol.py's Client.wait: receives until `cond(values seen)` holds.
async fn wait_values(
    ws: &mut Ws,
    values: &mut serde_json::Map<String, Json>,
    mut cond: impl FnMut(&serde_json::Map<String, Json>) -> bool,
) {
    let end = Instant::now() + Duration::from_secs(10);
    while !cond(values) {
        assert!(Instant::now() < end, "condition not met");
        until_tracking(ws, values, |_| true).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn conformance_stale_on_disconnect() {
    use std::sync::atomic::Ordering;
    let (handle, mock, _dir) = bench().await;
    let mut ws = Ws::connect(handle.addr()).await;
    ws.hello("bench-hmi").await;
    ws.send(json!({"op": "sub", "id": 1, "tags": ["Bench.Count"], "tier": 1}))
        .await;
    let mut values = serde_json::Map::new();
    wait_values(&mut ws, &mut values, |v| {
        v.get("Bench.Count").is_some_and(|e| e[1] == "good")
    })
    .await;
    let kept = values["Bench.Count"][0].as_f64().unwrap();
    mock.fail.store(true, Ordering::SeqCst);
    until_tracking(&mut ws, &mut values, |m| {
        m["op"] == "status" && m["plcs"]["PLC1"] == "disconnected"
    })
    .await;
    wait_values(&mut ws, &mut values, |v| v["Bench.Count"][1] == "stale").await;
    let entry = values["Bench.Count"].clone();
    assert!(entry[3].is_null());
    assert!((entry[0].as_f64().unwrap() - kept).abs() < 5.0);
    ws.send(json!({"op": "write", "id": 101, "tag": "Bench.SpeedSP", "value": 1.0}))
        .await;
    let ack = until_tracking(&mut ws, &mut values, |m| is_ack(m) && m["id"] == 101).await;
    assert_eq!(ack["ok"], false);
    assert!(["refused", "comm"].contains(&ack["kind"].as_str().unwrap()));
    mock.fail.store(false, Ordering::SeqCst);
    until_tracking(&mut ws, &mut values, |m| {
        m["op"] == "status" && m["plcs"]["PLC1"] == "connected"
    })
    .await;
    wait_values(&mut ws, &mut values, |v| v["Bench.Count"][1] == "good").await;
    ws.close().await;
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn conformance_meta_on_reload() {
    use std::sync::atomic::Ordering;
    let (handle, mock, _dir) = bench().await;
    let addr = handle.addr();
    let mut ws = Ws::connect(addr).await;
    ws.hello("bench-hmi").await;
    ws.send(json!({"op": "sub", "id": 1, "tags": ["Bench.SpeedSP"], "tier": 1}))
        .await;
    ws.until(|m| m["op"] == "info" && m["d"].get("Bench.SpeedSP").is_some())
        .await;
    let token = [("Authorization", "Bearer bench-hmi")];
    let version = crate::testing::http(addr, "GET", "/tags", &token).await.2["version"]
        .as_u64()
        .unwrap();
    mock.version.fetch_add(1, Ordering::SeqCst);
    ws.until(|m| m["op"] == "meta" && m["plc"] == "PLC1").await;
    // info is sent again after a reload
    ws.until(|m| m["op"] == "info" && m["d"].get("Bench.SpeedSP").is_some())
        .await;
    assert_eq!(
        crate::testing::http(addr, "GET", "/tags", &token).await.2["version"],
        version + 1
    );
    ws.close().await;
    handle.stop().unwrap();
}

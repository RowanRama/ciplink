//! Controller-side trends: the driver's trend against the simulated trend object (class 0xB2).
#![allow(clippy::unwrap_used)]

mod common;

use std::time::{Duration, Instant};

use ciplink::Value;
use ciplink::cip::CipOptions;
use ciplink::logix::driver::{LogixDriver, LogixOptions};
use ciplink::logix::trend::{Trend, TrendOptions, TrendSample};
use ciplink::packets::generic_message;
use ciplink_sim::{Fault, Simulator, TagConfig};
use common::{Client, controller};
use serde_json::json;

fn sim() -> Simulator {
    let config = controller()
        .with_tag(TagConfig::new("sint", "SINT").value(json!(-5)))
        .with_tag(TagConfig::new("usint", "USINT").value(json!(250)))
        .with_tag(TagConfig::new("udint", "UDINT").value(json!(4_000_000_000u32)))
        .with_tag(TagConfig::new("real", "REAL").value(json!(45.5)))
        .with_tag(TagConfig::new("flag", "BOOL").value(json!(true)))
        .with_tag(TagConfig::new("big", "LINT").value(json!(1)));
    Simulator::new(config).unwrap()
}

fn driver(sim: &Simulator, lazy_tags: bool) -> LogixDriver {
    let options = LogixOptions {
        lazy_tags,
        cip: CipOptions {
            socket_timeout: Some(Duration::from_millis(300)),
            ..CipOptions::default()
        },
        ..LogixOptions::default()
    };
    let plc = LogixDriver::with_connector("192.0.2.1", options, sim.connector()).unwrap();
    plc.open().unwrap();
    plc
}

fn options(period_ms: u64) -> TrendOptions {
    TrendOptions {
        period: Duration::from_millis(period_ms),
        ..TrendOptions::default()
    }
}

/// The trend instances in the controller (class attribute 3).
fn instances(sim: &Simulator) -> u16 {
    let mut client = Client::new(sim);
    let request = [3, 0, 1, 0, 2, 0, 3, 0];
    let reply =
        client.rr(&generic_message(0x03, 0xB2u32.into(), 0u32.into(), None, &request).unwrap());
    let data = reply.data.unwrap();
    u16::from_le_bytes([data[data.len() - 2], data[data.len() - 1]])
}

/// Reads until at least `n` samples arrived (or two seconds passed).
fn collect(trend: &Trend, n: usize) -> Vec<TrendSample> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut out = Vec::new();
    while out.len() < n && Instant::now() < deadline {
        out.extend(trend.read().unwrap());
        std::thread::sleep(Duration::from_millis(5));
    }
    out
}

#[test]
fn trends_every_type_up_to_32_bits_and_bits() {
    let sim = sim();
    let plc = driver(&sim, false);
    let tags = [
        "dint",
        "int",
        "sint",
        "usint",
        "udint",
        "real",
        "flag",
        "tmr.ACC",
        "tmr.DN",
        "pt.on",
        "pt.x",
        "ary[3]",
        "bits[2]",
        "bits[1]",
        "dint.4",
        "dint.0",
        "Program:Main.local",
    ];
    let trend = plc.trend(&tags, options(5)).unwrap();
    let types: Vec<&str> = trend.pens().iter().map(|p| p.data_type).collect();
    assert_eq!(
        types,
        [
            "DINT", "INT", "SINT", "USINT", "UDINT", "REAL", "BOOL", "DINT", "BOOL", "BOOL",
            "DINT", "DINT", "BOOL", "BOOL", "BOOL", "BOOL", "DINT"
        ]
    );
    assert_eq!(instances(&sim), 1);
    let samples = collect(&trend, 3);
    assert!(samples.len() >= 3);
    use Value::*;
    assert_eq!(
        samples[0].values,
        [
            DInt(1234),
            Int(-2),
            SInt(-5),
            USInt(250),
            UDInt(4_000_000_000),
            Real(45.5),
            Bool(true),
            DInt(0),
            Bool(true),
            Bool(true),
            DInt(7),
            DInt(3),
            Bool(true),
            Bool(false),
            Bool(true),
            Bool(false),
            DInt(42)
        ]
    );
    // samples are 5 ms apart on the controller clock, from the start time on
    let first = &samples[0];
    assert_eq!(first.timestamp_us, trend.start_time_us() + first.elapsed_us);
    for pair in samples.windows(2) {
        assert!(pair[1].elapsed_us.abs_diff(pair[0].elapsed_us + 5000) < 128);
    }
    trend.close().unwrap();
    assert!(!trend.running());
    assert_eq!(instances(&sim), 0);
}

#[test]
fn samples_follow_the_tag_values() {
    let sim = sim();
    let plc = driver(&sim, true);
    let trend = plc.trend(&["dint", "real"], options(2)).unwrap();
    collect(&trend, 1);
    sim.set_value("dint", &json!(-7)).unwrap();
    sim.set_value("real", &json!(0.25)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut last = None;
    while Instant::now() < deadline {
        if let Some(s) = trend.read().unwrap().pop() {
            last = Some(s.values.clone());
            if s.values[0] == Value::DInt(-7) {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(last.unwrap(), [Value::DInt(-7), Value::Real(0.25)]);
    trend.close().unwrap();
}

#[test]
fn a_backlog_larger_than_a_reply_is_uploaded_without_gaps() {
    let sim = sim();
    let plc = driver(&sim, false);
    let tags = [
        "dint", "int", "sint", "real", "flag", "pt.x", "ary[1]", "ary[2]",
    ];
    let trend = plc.trend(&tags, options(1)).unwrap();
    // each upload now waits 150 ms: 150 samples of 38 bytes, more than one 4000 byte reply
    sim.inject(Fault::Delay(Duration::from_millis(150)));
    std::thread::sleep(Duration::from_millis(400));
    sim.clear_faults();
    let samples = collect(&trend, 500);
    trend.close().unwrap();
    let mut samples = samples;
    samples.extend(trend.read().unwrap());
    assert!(samples.len() >= 500, "{}", samples.len());
    for pair in samples.windows(2) {
        assert!(pair[1].elapsed_us.abs_diff(pair[0].elapsed_us + 1000) < 128);
    }
}

#[test]
fn a_full_host_buffer_drops_the_oldest_samples() {
    let sim = sim();
    let plc = driver(&sim, false);
    let trend = plc
        .trend(
            &["dint"],
            TrendOptions {
                period: Duration::from_millis(1),
                capacity: 10,
                duration: None,
            },
        )
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while trend.received() < 50 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let samples = trend.read().unwrap();
    assert_eq!(samples.len(), 10);
    assert!(trend.dropped() >= 40);
    trend.close().unwrap();
}

#[test]
fn a_trend_stops_after_its_duration_and_keeps_its_samples() {
    let sim = sim();
    let plc = driver(&sim, false);
    let trend = plc
        .trend(
            &["dint"],
            TrendOptions {
                duration: Some(Duration::from_millis(60)),
                ..options(5)
            },
        )
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while trend.running() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(!trend.running());
    assert_eq!(instances(&sim), 0);
    let samples = trend.read().unwrap();
    assert!(samples.len() >= 10, "{}", samples.len());
    assert_eq!(trend.received(), samples.len() as u64);
    trend.close().unwrap();
}

#[test]
fn unsupported_pens_fail_before_a_trend_is_created() {
    let sim = sim();
    let plc = driver(&sim, false);
    for tags in [
        &["big"][..],
        &["s"],
        &["pt"],
        &["ary{2}"],
        &["dint", "nope"],
        &[],
    ] {
        assert!(plc.trend(tags, options(10)).is_err(), "{tags:?}");
    }
    assert_eq!(instances(&sim), 0);
}

#[test]
fn a_refused_period_deletes_the_new_trend() {
    let sim = sim();
    let plc = driver(&sim, false);
    let refused = TrendOptions {
        period: Duration::from_micros(500),
        ..TrendOptions::default()
    };
    assert!(plc.trend(&["dint"], refused).is_err());
    assert_eq!(instances(&sim), 0);
}

#[test]
fn a_lost_connection_fails_the_trend_after_its_samples() {
    let sim = sim();
    let plc = driver(&sim, false);
    let trend = plc.trend(&["dint"], options(5)).unwrap();
    collect(&trend, 1);
    sim.inject(Fault::DropReplies(1000));
    let deadline = Instant::now() + Duration::from_secs(3);
    while trend.running() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!trend.running());
    assert!(trend.error().is_some());
    // the samples before the failure are still read, then the error
    let _ = trend.read();
    assert!(trend.read().is_err());
    assert!(trend.close().is_err());
}

#[test]
fn the_parent_driver_keeps_working_while_a_trend_runs() {
    let sim = sim();
    let plc = driver(&sim, false);
    let trend = plc.trend(&["dint"], options(5)).unwrap();
    plc.close().unwrap();
    collect(&trend, 3);
    assert!(trend.running());
    plc.open().unwrap();
    assert_eq!(plc.read(&["int"]).unwrap()[0].value, Some(Value::Int(-2)));
    drop(trend);
    let deadline = Instant::now() + Duration::from_secs(2);
    while instances(&sim) != 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(instances(&sim), 0);
}

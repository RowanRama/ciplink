//! The SLC 500 / MicroLogix simulator over PCCC, checked with ciplink's PCCC request builders and parsers.
#![allow(clippy::unwrap_used)]

mod common;

use ciplink::Value;
use ciplink::slc::pccc::{
    Requestor, datalog_request, file_directory_size_request, parse_datalog,
    parse_file_directory_size, parse_processor_type, parse_read_reply, processor_type_request,
    read_request, request_status, sys0_info, write_request,
};
use ciplink_sim::{FileConfig, Simulator, SlcConfig};
use common::Client;
use serde_json::json;

fn slc() -> Simulator {
    Simulator::new(SlcConfig {
        files: vec![
            FileConfig {
                values: vec![json!(10), json!(-1)],
                ..FileConfig::new(7, "N", 300)
            },
            FileConfig {
                values: vec![json!(1.5)],
                ..FileConfig::new(8, "F", 4)
            },
            FileConfig {
                values: vec![json!({"PRE": 100, "ACC": 25, "EN": true})],
                ..FileConfig::new(4, "T", 2)
            },
            FileConfig {
                values: vec![json!("Hi")],
                ..FileConfig::new(9, "ST", 2)
            },
            FileConfig::new(3, "B", 4),
        ],
        datalog: vec!["entry 1".into()],
        ..SlcConfig::default()
    })
    .unwrap()
}

fn read(client: &mut Client, tag: &str) -> Result<Value, String> {
    let (addr, message) = read_request(tag, &Requestor::default(), 1).unwrap();
    let raw = client.unit(&message).raw.unwrap();
    match request_status(&raw) {
        Some(error) => Err(error),
        None => Ok(parse_read_reply(&addr, &raw[61..]).unwrap()),
    }
}

fn write(client: &mut Client, tag: &str, value: Value) -> Option<String> {
    let (_, message) = write_request(tag, &value, &Requestor::default(), 1).unwrap();
    request_status(&client.unit(&message).raw.unwrap())
}

#[test]
fn reads_data_files_by_element_and_bit() {
    let sim = slc();
    let mut client = Client::connected(&sim, 500);
    assert_eq!(read(&mut client, "N7:0"), Ok(Value::Int(10)));
    assert_eq!(
        read(&mut client, "N7:0{2}"),
        Ok(Value::Array(vec![Value::Int(10), Value::Int(-1)]))
    );
    assert_eq!(read(&mut client, "N7:255"), Ok(Value::Int(0))); // 255 is escaped as 0xFF and a 16-bit value
    assert_eq!(read(&mut client, "N7:1/15"), Ok(Value::Bool(true)));
    assert_eq!(read(&mut client, "F8:0"), Ok(Value::Real(1.5)));
    assert_eq!(read(&mut client, "T4:0.ACC"), Ok(Value::Int(25)));
    assert_eq!(read(&mut client, "T4:0.EN"), Ok(Value::Bool(true)));
    assert_eq!(read(&mut client, "ST9:0"), Ok(Value::String("Hi".into())));
    let missing = read(&mut client, "N10:0").unwrap_err();
    assert!(missing.contains("EXT STS 0x06"), "{missing}");
    assert!(read(&mut client, "F8:4").is_err()); // past the end of the file
}

#[test]
fn masked_writes_change_only_the_masked_bits() {
    let sim = slc();
    let mut client = Client::connected(&sim, 500);
    assert_eq!(write(&mut client, "N7:5", Value::Int(-7)), None);
    assert_eq!(write(&mut client, "B3:1/3", Value::Bool(true)), None);
    assert_eq!(write(&mut client, "B3/17", Value::Bool(true)), None);
    assert_eq!(write(&mut client, "T4:0.PRE", Value::Int(500)), None);
    assert_eq!(write(&mut client, "T4:0.DN", Value::Bool(true)), None);
    assert_eq!(
        write(&mut client, "ST9:1", Value::String("written".into())),
        None
    );
    assert_eq!(write(&mut client, "F8:1", Value::Real(-0.5)), None);
    assert_eq!(sim.value("N7:5").unwrap(), json!(-7));
    assert_eq!(sim.value("B3:1").unwrap(), json!(0b1010));
    assert_eq!(
        sim.value("T4:0").unwrap(),
        json!({"PRE": 500, "ACC": 25, "EN": true, "TT": false, "DN": true})
    );
    assert_eq!(sim.value("ST9:1").unwrap(), json!("written"));
    assert_eq!(read(&mut client, "F8:1"), Ok(Value::Real(-0.5)));
}

#[test]
fn processor_type_file_directory_and_datalog() {
    let sim = slc();
    let mut client = Client::connected(&sim, 500);
    let raw = client
        .unit(&processor_type_request(&Requestor::default(), 1))
        .raw
        .unwrap();
    assert_eq!(parse_processor_type(&raw).as_deref(), Some("1747-L552"));

    let info = sys0_info("1747-L552");
    let raw = client
        .unit(&file_directory_size_request(
            &info,
            &Requestor::default(),
            2,
        ))
        .raw
        .unwrap();
    let size = parse_file_directory_size(&raw, &info).unwrap();
    assert_eq!(size, 79 + 10 * 10); // rows for files 0 to 9

    let raw = client.unit(&datalog_request(1)).raw.unwrap();
    assert_eq!(parse_datalog(&raw), Value::String("entry 1".into()));
    let raw = client.unit(&datalog_request(1)).raw.unwrap();
    assert!(request_status(&raw).is_some()); // the queue is empty
}

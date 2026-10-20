//! A minimal EtherNet/IP client for the simulator tests, built from ciplink's request builders and reply parsers.
#![allow(dead_code, clippy::unwrap_used)]

use ciplink::epath::{Segment, tag_request_path};
use ciplink::packets::{
    Encap, ForwardOpen, MultiServiceReply, Reply, ReplyKind, forward_open_data, generic_message,
    multi_service_message, parse_multi_service_reply, register_session_request,
    send_rr_data_request, send_unit_data_request,
};
use ciplink::transport::Transport;
use ciplink_sim::{
    LogixConfig, MemberConfig, ProgramConfig, SimTransport, Simulator, TagConfig, TypeConfig,
};
use serde_json::json;

pub struct Client {
    pub transport: SimTransport,
    pub encap: Encap,
    pub cid: [u8; 4],
    pub sequence: u16,
}

impl Client {
    /// A connection with a registered session.
    pub fn new(sim: &Simulator) -> Self {
        let mut client = Client {
            transport: sim.transport(),
            encap: Encap {
                session: 0,
                context: *b"_pycomm_",
                option: 0,
            },
            cid: [0; 4],
            sequence: 0,
        };
        let reply = client.exchange(
            &register_session_request(&client.encap, 1, 0),
            ReplyKind::RegisterSession,
        );
        client.encap.session = reply.session.unwrap();
        client
    }

    pub fn exchange(&mut self, frame: &[u8], kind: ReplyKind) -> Reply {
        self.transport.send(frame).unwrap();
        Reply::parse(kind, &self.transport.receive().unwrap())
    }

    /// An unconnected message (SendRRData).
    pub fn rr(&mut self, message: &[u8]) -> Reply {
        let frame = send_rr_data_request(&self.encap, message).unwrap();
        self.exchange(&frame, ReplyKind::SendRRData)
    }

    /// A (Large) Forward Open to the controller in slot 0; keeps the connection ID.
    pub fn forward_open(&mut self, size: u32, large: bool) -> Reply {
        let params = ForwardOpen {
            cid: [1, 2, 3, 4],
            csn: [5, 6],
            vid: [7, 8],
            vsn: [9, 10, 11, 12],
            connection_size: size,
            large,
        };
        let data = forward_open_data(&params, &[Segment::port("bp", 0)]).unwrap();
        let reply = self.rr(&generic_message(
            if large { 0x5B } else { 0x54 },
            6u32.into(),
            1u32.into(),
            None,
            &data,
        )
        .unwrap());
        if reply.is_valid() {
            self.cid.copy_from_slice(&reply.data.as_ref().unwrap()[..4]);
        }
        reply
    }

    /// A connected message (SendUnitData).
    pub fn unit(&mut self, message: &[u8]) -> Reply {
        self.sequence = self.sequence.wrapping_add(1);
        let frame = send_unit_data_request(&self.encap, &self.cid, self.sequence, message).unwrap();
        self.exchange(&frame, ReplyKind::SendUnitData)
    }

    /// A Multiple Service Packet of these messages, connected.
    pub fn multi(&mut self, messages: &[Vec<u8>]) -> MultiServiceReply {
        self.sequence = self.sequence.wrapping_add(1);
        let message = multi_service_message(messages).unwrap();
        let frame =
            send_unit_data_request(&self.encap, &self.cid, self.sequence, &message).unwrap();
        self.transport.send(&frame).unwrap();
        parse_multi_service_reply(&self.transport.receive().unwrap(), messages.len())
    }

    /// A connected client: a session and a connection of `size` bytes.
    pub fn connected(sim: &Simulator, size: u32) -> Self {
        let mut client = Client::new(sim);
        assert!(client.forward_open(size, size > 511).is_valid());
        client
    }
}

/// A tag path by name, or by symbol instance ID.
pub fn path(tag: &str, id: Option<u32>) -> Vec<u8> {
    tag_request_path(tag, id, id.is_some()).unwrap()
}

pub fn message(service: u8, path: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = vec![service];
    out.extend(path);
    out.extend(data);
    out
}

pub fn read(tag: &str, elements: u16) -> Vec<u8> {
    message(0x4C, &path(tag, None), &elements.to_le_bytes())
}

pub fn write(tag: &str, type_code: &[u8], elements: u16, value: &[u8]) -> Vec<u8> {
    message(
        0x4D,
        &path(tag, None),
        &[type_code, &elements.to_le_bytes(), value].concat(),
    )
}

pub fn data(reply: &Reply) -> Vec<u8> {
    reply.data.clone().unwrap_or_default()
}

/// A controller with every kind of tag the tests use.
pub fn controller() -> LogixConfig {
    LogixConfig::default()
        .with_type(TypeConfig::udt(
            "Point",
            [
                MemberConfig::new("on", "BOOL"),
                MemberConfig::new("x", "DINT"),
                MemberConfig::array("r", "REAL", 2),
            ],
        ))
        .with_type(TypeConfig::aoi(
            "Valve",
            [
                MemberConfig::new("Cmd", "BOOL"),
                MemberConfig::new("Mode", "DINT"),
                MemberConfig::new("Count", "DINT").local(),
            ],
        ))
        .with_type(TypeConfig::string("STRING8", 8))
        .with_tag(TagConfig::new("dint", "DINT").value(json!(1234)))
        .with_tag(TagConfig::new("int", "INT").value(json!(-2)))
        .with_tag(
            TagConfig::new("ary", "DINT")
                .dims(&[100])
                .value(json!((0..100).collect::<Vec<_>>())),
        )
        .with_tag(
            TagConfig::new("grid", "INT")
                .dims(&[2, 3])
                .value(json!([[1, 2, 3], [4, 5, 6]])),
        )
        .with_tag(
            TagConfig::new("bits", "BOOL")
                .dims(&[64])
                .value(json!([true, false, true])),
        )
        .with_tag(TagConfig::new("pt", "Point").value(json!({"on": true, "x": 7, "r": [0.5, 1.5]})))
        .with_tag(TagConfig::new("pts", "Point").dims(&[3]))
        .with_tag(TagConfig::new("s", "STRING8").value(json!("abc")))
        .with_tag(TagConfig::new("tmr", "TIMER").value(json!({"PRE": 10, "DN": true})))
        .with_tag(TagConfig::new("valve", "Valve").value(json!({"Mode": 2, "Count": 5})))
        .with_tag(
            TagConfig::new("ro", "DINT")
                .access("Read Only")
                .value(json!(9)),
        )
        .with_tag(
            TagConfig::new("far", "DINT")
                .instance_id(70000)
                .value(json!(-1)),
        )
        .with_program(
            ProgramConfig::new("Main").with_tag(TagConfig::new("local", "DINT").value(json!(42))),
        )
}

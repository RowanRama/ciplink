//! A minimal S7comm-plus PLC on 127.0.0.1 for the driver's own tests: COTP, InitSsl, TLS 1.3 with a fresh
//! self-signed certificate, the session, browse of the sample tree, reads, writes, keep-alive and close, with
//! the sequence and integrity counters checked. (The full simulator is `ciplink-sim`.)

use std::collections::HashMap;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use super::browse::tests::{element, type_object};
use super::browse::{SymbolTree, type_infos};
use super::codec::{Blob, Payload, Scalar, Struct, WireValue, dt};
use super::cotp::{self, CotpStream};
use super::pdu::{
    self, ExploreReply, GetMultiReply, MAX_PDU, Object, Request, SetMultiReply, function, ids,
};
use super::tls::{Fingerprint, fingerprint};

/// Item error codes the fake answers with.
pub(crate) const LID_MISSING: u64 = 0x814E_8800_0962_FF01;
pub(crate) const CRC_MISMATCH: u64 = 0x8009_8900_12C9_FFEF;

/// What the fake holds and records; tests change it between requests.
#[derive(Default)]
pub(crate) struct State {
    /// Type-info objects and the DBs (name, number, type RID).
    pub types: Vec<Object>,
    pub dbs: Vec<(String, u32, u32)>,
    /// Values by access sequence (`8A0E0005.C`).
    pub values: HashMap<String, WireValue>,
    /// CRCs a non-zero item CRC must match, by access sequence.
    pub crcs: HashMap<String, u32>,
    /// Function codes received, in order.
    pub functions: Vec<u16>,
    /// Refuse the next connections (COTP DR).
    pub refuse: bool,
    /// Close the connection after this many more requests.
    pub drop_after: Option<usize>,
    /// Item count of each GetMultiVariables received.
    pub read_sizes: Vec<usize>,
    pub max_read: i32,
    pub connections: usize,
    /// Answer the system-limits read with a negative return value and no items.
    pub refuse_limits: bool,
}

pub(crate) struct FakePlc {
    pub port: u16,
    pub state: Arc<Mutex<State>>,
    pub fingerprint: Fingerprint,
    stop: Arc<AtomicBool>,
}

impl Drop for FakePlc {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

const HMI: u16 = 0x0A00;

/// The sample program: DB 5 "Line1" with the members of the spec examples, a DTL type, an I-area tag.
fn sample(state: &mut State) {
    let conveyor = type_object(
        0x9201_0005,
        "",
        11,
        vec![
            element("Running", 9, 1, 1, HMI, &[0, 0]),
            element("Speed", 0xB, 8, 1, HMI, &[2, 2]),
        ],
    );
    let dtl = type_object(
        0x0200_0043,
        "",
        1_224_779_910_406_829_900,
        vec![
            element("YEAR", 9, 53, 1, HMI, &[0, 0]),
            element("MONTH", 0xA, 52, 1, HMI, &[2, 2]),
            element("DAY", 0xB, 52, 1, HMI, &[3, 3]),
            element("WEEKDAY", 0xC, 52, 1, HMI, &[4, 4]),
            element("HOUR", 0xD, 52, 1, HMI, &[5, 5]),
            element("MINUTE", 0xE, 52, 1, HMI, &[6, 6]),
            element("SECOND", 0xF, 52, 1, HMI, &[7, 7]),
            element("NANOSECOND", 0x10, 54, 1, HMI, &[8, 8]),
        ],
    );
    let db = type_object(
        0x9200_0005,
        "",
        13,
        vec![
            element("Conveyor", 0xA, 17, 12, HMI, &[0, 0, 0, 0x9201_0005]),
            element("Count", 0xC, 7, 8, HMI, &[4, 4]),
            element("Recipe", 0xE, 19, 9, HMI, &[0x000A_000C, 16, 16]),
            element("Stamp", 0x10, 67, 12, HMI, &[0, 40, 40, 0x0200_0043]),
            element("Items", 0x11, 53, 10, HMI, &[0, 52, 52, 0, 300]),
            element("Big", 0x12, 48, 10, HMI, &[0, 700, 700, 0, 10_000]),
        ],
    );
    let i_area = type_object(
        0x9001_0000,
        "IArea",
        0,
        vec![element("StartButton", 0xC, 1, 8, HMI, &[0, 0])],
    );
    state.types = vec![conveyor, dtl, db, i_area];
    state.dbs = vec![("Line1".into(), 5, 0x9200_0005)];
    state.max_read = 100;
    let s = |v| WireValue::scalar(v);
    state
        .values
        .insert("8A0E0005.A.B".into(), s(Scalar::Real(1.5)));
    state
        .values
        .insert("8A0E0005.A.9".into(), s(Scalar::Bool(true)));
    state
        .values
        .insert("8A0E0005.C".into(), s(Scalar::DInt(-300)));
    state.values.insert("50.C".into(), s(Scalar::Bool(false)));
    for i in 0..300u32 {
        state
            .values
            .insert(format!("8A0E0005.11.{i:X}"), s(Scalar::UInt(i as u16)));
    }
    state.recompute_crcs();
}

impl State {
    /// The CRCs of every non-indexed path of the current types.
    pub fn recompute_crcs(&mut self) {
        let tree = self.tree();
        self.crcs = tree
            .symbols()
            .into_iter()
            .filter(|s| s.crc != 0)
            .map(|s| (s.access, s.crc))
            .collect();
    }

    fn tree(&self) -> SymbolTree {
        let db_types = self.dbs.iter().map(|(_, n, rid)| (*n, *rid)).collect();
        let dbs = self
            .dbs
            .iter()
            .map(|(name, n, _)| (name.clone(), *n))
            .collect();
        SymbolTree::new(dbs, &db_types, type_infos(&self.types))
    }

    /// Renames the CRC of `member` in DB type 0x92000005 (a "download" that changes the program).
    pub fn change_crc(&mut self, member: &str) {
        for o in &mut self.types {
            if o.rid != 0x9200_0005 {
                continue;
            }
            let names = o.varnames.clone().unwrap_or_default();
            if let Some(list) = o.vartypes.as_mut() {
                for (e, n) in list.elements.iter_mut().zip(&names) {
                    if n == member {
                        e.crc ^= 0x0101_0101;
                    }
                }
            }
            if let Some(Scalar::ULInt(ts)) =
                o.attrs
                    .iter_mut()
                    .find(|(id, _)| *id == 529)
                    .and_then(|(_, v)| match &mut v.payload {
                        Payload::Scalar(s) => Some(s),
                        _ => None,
                    })
            {
                *ts += 1;
            }
        }
        self.recompute_crcs();
    }
}

fn server_config() -> (Arc<ServerConfig>, Fingerprint) {
    let key =
        rcgen::generate_simple_self_signed(vec!["192.0.2.10".to_string()]).expect("certificate");
    let der: CertificateDer<'static> = key.cert.der().clone();
    let fp = fingerprint(der.as_ref());
    let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.key_pair.serialize_der()));
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(vec![der], private)
            .expect("server config");
    (Arc::new(config), fp)
}

impl FakePlc {
    pub fn start() -> FakePlc {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let mut state = State::default();
        sample(&mut state);
        let state = Arc::new(Mutex::new(state));
        let (config, fp) = server_config();
        let stop = Arc::new(AtomicBool::new(false));
        let (s, st) = (Arc::clone(&state), Arc::clone(&stop));
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                if st.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(conn) = conn else { continue };
                let (s, config) = (Arc::clone(&s), Arc::clone(&config));
                std::thread::spawn(move || {
                    let _ = serve(conn, &s, config);
                });
            }
        });
        FakePlc {
            port,
            state,
            fingerprint: fp,
            stop,
        }
    }

    pub fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

type Failure = Box<dyn std::error::Error>;

fn serve(
    mut tcp: TcpStream,
    state: &Mutex<State>,
    config: Arc<ServerConfig>,
) -> Result<(), Failure> {
    tcp.set_read_timeout(Some(Duration::from_secs(20)))?;
    let request = cotp::read_tpkt(&mut tcp)?;
    if request.get(5) != Some(&0xE0) {
        return Err("not a CR".into());
    }
    let refuse = {
        let mut s = state.lock().unwrap_or_else(PoisonError::into_inner);
        s.connections += 1;
        s.refuse
    };
    if refuse {
        tcp.write_all(&cotp::disconnect_request())?;
        return Ok(());
    }
    tcp.write_all(&cotp::connect_confirm(4))?;
    let mut cotp = CotpStream::new(tcp);
    let init = pdu::read_pdu(&mut cotp, MAX_PDU)?;
    let header = pdu::parse_request_header(&init)?;
    if header.function != function::INIT_SSL {
        return Err("expected InitSsl".into());
    }
    let reply = pdu::response(1, function::INIT_SSL, 1, 0x70, 0, &pdu::init_ssl_body());
    cotp.write_all(&pdu::frame(&reply)?)?;
    let conn = ServerConnection::new(config)?;
    let mut tls = StreamOwned::new(conn, cotp);
    let session = 0x7000_0A10u32;
    let (mut sequence, mut get, mut set) = (1u16, 0u32, 0u32);
    loop {
        let request = match pdu::read_pdu(&mut tls, MAX_PDU) {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };
        let header = pdu::parse_request_header(&request)?;
        let body = pdu::parse_request(&header)?;
        sequence = if sequence == u16::MAX {
            1
        } else {
            sequence + 1
        };
        if header.sequence != sequence {
            return Err("sequence mismatch".into());
        }
        let counter = match header.function {
            function::SET_MULTI_VARIABLES | function::DELETE_OBJECT => &mut set,
            _ => &mut get,
        };
        if let Some(i) = body.integrity() {
            *counter = counter.wrapping_add(1);
            if i != *counter {
                return Err("integrity mismatch".into());
            }
        }
        let integrity = body
            .integrity()
            .map_or(0, |i| u32::from(header.sequence).wrapping_add(i));
        let mut s = state.lock().unwrap_or_else(PoisonError::into_inner);
        s.functions.push(header.function);
        if let Some(n) = s.drop_after.as_mut() {
            if *n == 0 {
                s.drop_after = None;
                return Ok(());
            }
            *n -= 1;
        }
        let (version, flags, rv, body) = answer(&mut s, session, &body, integrity);
        drop(s);
        let reply = pdu::response(version, header.function, header.sequence, flags, rv, &body);
        tls.write_all(&pdu::frame_split(&reply, pdu::PLC_FRAME_DATA))?;
        tls.flush()?;
        if header.function == function::DELETE_OBJECT {
            return Ok(());
        }
    }
}

/// (version, transport flags, return value, body) of the response to one request.
fn answer(
    s: &mut State,
    session: u32,
    request: &Request,
    integrity: u32,
) -> (u8, u8, u64, Vec<u8>) {
    match request {
        Request::CreateObject { .. } => {
            let version = Struct::Normal {
                id: 314,
                elements: vec![
                    (315, WireValue::scalar(Scalar::UDInt(1))),
                    (
                        319,
                        WireValue::scalar(Scalar::WString("1;6ES7 5XX-XXXXX-XAB0;V3.1".into())),
                    ),
                ],
            };
            let object = Object {
                rid: 0x120,
                class: 287,
                flags: 1,
                attrs: vec![(306, WireValue::scalar(Scalar::Struct(Box::new(version))))],
                ..Object::default()
            };
            let body = pdu::create_object_body(&[session, session + 1], &[object]);
            (1, 0x36, 0x6022_8000_012D_0011, body)
        }
        Request::SetMulti {
            integrity: None, ..
        } => (
            2,
            0x34,
            0,
            pdu::set_multi_body(&SetMultiReply {
                errors: vec![],
                integrity: 0,
            }),
        ),
        Request::SetMulti { fields, values, .. } => {
            let addresses = pdu::split_addresses(fields, values.len()).unwrap_or_default();
            let mut errors = Vec::new();
            for (i, (a, (_, v))) in addresses.iter().zip(values).enumerate() {
                let access = a.access();
                if a.crc != 0 && s.crcs.get(&access) != Some(&a.crc) {
                    errors.push((i as u32 + 1, CRC_MISMATCH));
                } else if let Some(slot) = s.values.get_mut(&access) {
                    *slot = v.clone();
                } else {
                    errors.push((i as u32 + 1, LID_MISSING));
                }
            }
            let rv = if errors.is_empty() {
                0
            } else {
                0x2027_8000_00A1_0013
            };
            (
                2,
                0x34,
                rv,
                pdu::set_multi_body(&SetMultiReply { errors, integrity }),
            )
        }
        Request::GetMulti { items, .. }
            if s.refuse_limits && items.iter().any(|a| a.area == ids::OBJECT_ROOT) =>
        {
            let reply = GetMultiReply {
                values: vec![],
                errors: vec![],
                integrity,
            };
            (2, 0x34, 0x8027_8000_0000_FF01, pdu::get_multi_body(&reply))
        }
        Request::GetMulti { items, .. } => {
            s.read_sizes.push(items.len());
            let mut reply = GetMultiReply {
                values: vec![],
                errors: vec![],
                integrity,
            };
            for (i, a) in items.iter().enumerate() {
                let n = i as u32 + 1;
                let access = a.access();
                if a.area == ids::OBJECT_ROOT {
                    let v = match a.lids.first() {
                        Some(1000 | 1001) => s.max_read,
                        _ => 7,
                    };
                    reply.values.push((n, WireValue::scalar(Scalar::DInt(v))));
                } else if a.lids == [1] && a.area >> 16 == 0x8A0E {
                    match s
                        .dbs
                        .iter()
                        .find(|(_, db, _)| ids::DB_AREA_BASE + db == a.area)
                    {
                        Some((_, _, rid)) => {
                            reply.values.push((n, WireValue::scalar(Scalar::Rid(*rid))))
                        }
                        None => reply.errors.push((n, LID_MISSING)),
                    }
                } else if a.crc != 0 && s.crcs.get(&access) != Some(&a.crc) {
                    reply.errors.push((n, CRC_MISMATCH));
                } else if let Some(v) = s.values.get(&access) {
                    reply.values.push((n, v.clone()));
                } else {
                    reply.errors.push((n, LID_MISSING));
                }
            }
            let rv = if reply.errors.is_empty() {
                0
            } else {
                0x2027_8000_00A1_0013
            };
            (2, 0x34, rv, pdu::get_multi_body(&reply))
        }
        Request::Explore { request, .. } => {
            let objects = if request.rid == ids::PLC_PROGRAM {
                s.dbs
                    .iter()
                    .map(|(name, n, _)| Object {
                        rid: ids::DB_AREA_BASE + n,
                        class: ids::CLASS_DB,
                        flags: 0x20,
                        attrs: vec![(233, WireValue::scalar(Scalar::WString(name.clone())))],
                        ..Object::default()
                    })
                    .collect()
            } else {
                vec![Object {
                    rid: ids::TYPE_INFO_CONTAINER,
                    class: 534,
                    flags: 0x30,
                    children: s.types.clone(),
                    ..Object::default()
                }]
            };
            let reply = ExploreReply {
                parent: 1,
                integrity,
                objects,
            };
            (2, 0x34, 0, pdu::explore_body(&reply))
        }
        Request::GetVar {
            object, attribute, ..
        } => {
            let value = match (*object, *attribute) {
                (ids::CPU_COMMON, ids::ATTR_NAME) => {
                    WireValue::scalar(Scalar::WString("PLC_Line1".into()))
                }
                (ids::CPU_PROXY, ids::ATTR_IDENTIFICATION) => {
                    let mut blob = vec![0x00, 0x20, 0x00, 0x38, 0x01, 0x00, 0x00, 0x2a];
                    blob.extend_from_slice(b"6ES7 5XX-XXXXX-XAB0 SVPX0000000000AB");
                    blob.extend_from_slice(&[0, 4, b'V', 3, 1, 3]);
                    blob.resize(60, 0);
                    WireValue::scalar(Scalar::Blob(Blob {
                        root: 0,
                        extra: None,
                        data: blob,
                    }))
                }
                (ids::AS_ROOT, ids::ATTR_ENGINEERING_VERSION) => WireValue::array(
                    dt::USINT,
                    [19, 0, 0, 0, 19, 0, 0, 0]
                        .into_iter()
                        .map(Scalar::USInt)
                        .collect(),
                ),
                (ids::RELEASE_MANAGEMENT_ROOT, ids::ATTR_PROJECT) => WireValue {
                    flags: 0x20,
                    datatype: dt::WSTRING,
                    payload: Payload::Array(
                        ["V19", "19.0", "Demo line"]
                            .into_iter()
                            .map(|t| Scalar::WString(t.into()))
                            .collect(),
                    ),
                },
                _ => WireValue::scalar(Scalar::UDInt(0)),
            };
            (2, 0x34, 0, pdu::get_var_body(&value, integrity))
        }
        Request::DeleteObject { object, .. } => (
            2,
            0x34,
            0x2023_8000_0087_002D,
            pdu::delete_object_body(*object),
        ),
        Request::InitSsl => (1, 0x70, 0, pdu::init_ssl_body()),
    }
}

//! Device browsing like RSWho in FactoryTalk Linx: the ports of a device (Port Object, class 0xF4) and the
//! devices on each port (Identity Object of every slot or node).
//!
//! A route is relative to the device at the driver's IP address, as text like a connection path: `""` is that
//! device, `bp/3` the module in slot 3 of its backplane, `bp/2/enet/192.168.1.10` a device behind the module
//! in slot 2. The driver's own connection path (e.g. a Logix `bp/0`) is not used.
//!
//! An empty slot or missing device costs a reply from the bridge, which may wait for its Unconnected Send
//! timeout (about 4 s), so a [`Scan`] probes the addresses of a port from several connections of its own.

use crate::adapter::{Assembly, AssemblyKind, CIPLINK_OBJECT, CIPLINK_SIGNATURE, ConnectionKind};
use crate::cip::{CipConnection, CipOptions, GenericMessage, RoutePath};
use crate::epath::{LogicalValue, encode_epath, parse_cip_route};
use crate::identity::ModuleIdentity;
use crate::reader::Reader;
use crate::transport::Connector;
use crate::types::Elementary;
use crate::{Error, Result, Value};
use indexmap::IndexMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};

/// Class code of the Port Object.
pub const PORT_OBJECT: u16 = 0xF4;
const TCP_IP_INTERFACE: u16 = 0xF5;
const ETHERNET_LINK: u16 = 0xF6;
const GET_ATTRIBUTES_ALL: u8 = 0x01;
const GET_ATTRIBUTE_SINGLE: u8 = 0x0E;

/// One port of a device (an instance of its Port Object).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortInfo {
    /// Port number, the port of a route segment through it (1 is the backplane).
    pub number: u16,
    /// Port type (attribute 1), e.g. 1 backplane, 2 ControlNet, 4 EtherNet/IP, 5 DeviceNet.
    pub port_type: u16,
    /// Port name (attribute 4), e.g. `"Backplane"` or `"A"`; empty if the device does not have one.
    pub name: String,
    /// This device's own address on the port (attribute 7), e.g. its slot; None if not reported.
    pub address: Option<String>,
    /// Node addresses on the port (attribute 8), None if not reported.
    pub node_range: Option<(u16, u16)>,
    /// EtherNet/IP ports: the IP address and subnet mask of the port (its TCP/IP Interface Object).
    pub ip: Option<(Ipv4Addr, Ipv4Addr)>,
}

impl PortInfo {
    /// The name of the port type.
    pub fn type_name(&self) -> String {
        port_type_name(self.port_type)
    }

    /// The addresses [`browse_port`](CipConnection::browse_port) probes: the reported node range, else the
    /// usual range of the port type; on an EtherNet/IP port every host of its subnet, at most the /24 around
    /// its own address. None if they are not known (an EtherNet/IP port without an IP address).
    pub fn nodes(&self) -> Option<Vec<String>> {
        let range = |first: u16, last: u16| Some((first..=last).map(|n| n.to_string()).collect());
        if let Some((first, last)) = self.node_range {
            return range(first, last);
        }
        match (self.port_type, self.ip) {
            (4, Some((ip, mask))) => Some(subnet_hosts(ip, mask)),
            (1, _) => range(0, 16),     // a 17-slot chassis
            (2 | 3, _) => range(1, 99), // ControlNet
            (5, _) => range(0, 63),     // DeviceNet
            _ => None,
        }
    }
}

/// The host addresses of the subnet of `ip`, at most the /24 around it.
fn subnet_hosts(ip: Ipv4Addr, mask: Ipv4Addr) -> Vec<String> {
    let mask = u32::from(mask).max(0xFFFF_FF00);
    let network = u32::from(ip) & mask;
    let broadcast = network | !mask;
    (network.saturating_add(1)..broadcast)
        .map(|a| Ipv4Addr::from(a).to_string())
        .collect()
}

/// The instance of the Ethernet Link Object in a port's Link Object path (attribute 3: its size in words,
/// then the path), None if the path names another object.
fn link_instance(data: &[u8]) -> Option<u16> {
    let mut r = Reader::new(data);
    r.u16().ok()?;
    let (mut class, mut instance) = (None, None);
    while let Ok(segment) = r.u8() {
        match segment {
            0x20 => class = Some(u16::from(r.u8().ok()?)),
            0x21 => class = r.u8().and_then(|_| r.u16()).ok(),
            0x24 => instance = Some(u16::from(r.u8().ok()?)),
            0x25 => instance = r.u8().and_then(|_| r.u16()).ok(),
            _ => break,
        }
    }
    (class? == ETHERNET_LINK).then_some(instance?)
}

/// The name of a CIP port type.
pub fn port_type_name(port_type: u16) -> String {
    match port_type {
        0 => "None".into(),
        1 => "Backplane".into(),
        2 => "ControlNet".into(),
        3 => "ControlNet (redundant)".into(),
        4 => "EtherNet/IP".into(),
        5 => "DeviceNet".into(),
        200 => "CompoNet".into(),
        201 => "Modbus/TCP".into(),
        202 => "Modbus/SL".into(),
        203 => "SERCOS III".into(),
        65535 => "No active link".into(),
        n @ 100..=199 => format!("Vendor specific ({n})"),
        n => format!("Type {n}"),
    }
}

/// One slot or node found by [`browse_port`](CipConnection::browse_port).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    /// Route to the node, to browse it further.
    pub route: String,
    /// Slot, node or IP address on the port.
    pub address: String,
    /// The node's identity, None if it did not answer.
    pub identity: Option<ModuleIdentity>,
    /// Why there is no identity (e.g. an empty slot).
    pub error: Option<String>,
    /// What a ciplink device runs (see [`AppInfo`]); probed only at IP addresses, since a ciplink adapter is
    /// a PC on a network, never a module in a slot.
    pub app: Option<AppInfo>,
}

/// What a ciplink [adapter](crate::adapter) runs, read from its ciplink object: the badge and application
/// line of a device browser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppInfo {
    /// The ciplink version of the device.
    pub ciplink_version: String,
    /// The application's name, e.g. `"Station"`.
    pub name: String,
    /// The application's version.
    pub version: String,
    /// The application's status text, e.g. `"station 2"`.
    pub detail: String,
    /// Its assemblies.
    pub assemblies: Vec<Assembly>,
    /// Its open class 1 connections (at most 16 are listed).
    pub connections: Vec<AppConnection>,
}

/// A class 1 connection of a ciplink device, as its ciplink object lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppConnection {
    /// Exclusive owner, input only or listen only.
    pub kind: ConnectionKind,
    /// The scanner's IP address.
    pub originator: Ipv4Addr,
    /// O->T RPI in microseconds.
    pub o_t_rpi_us: u32,
    /// T->O RPI in microseconds.
    pub t_o_rpi_us: u32,
    /// T->O data is multicast.
    pub multicast: bool,
    /// The input assembly.
    pub input: u16,
    /// The output assembly, None without one.
    pub output: Option<u16>,
}

impl AppInfo {
    /// Decodes the ciplink object's Get_Attributes_All reply; None unless it carries the ciplink signature (other
    /// devices may answer the class differently: a Logix controller with its program name).
    pub fn decode(data: &[u8]) -> Option<AppInfo> {
        let mut r = Reader::new(data);
        let mut text = || -> Option<String> {
            match r.u8().ok()? {
                0 => Some(String::new()), // take(0) is an error, an empty string is not
                len => Some(String::from_utf8_lossy(r.take(len.into()).ok()?).into_owned()),
            }
        };
        if text()? != CIPLINK_SIGNATURE {
            return None;
        }
        let (ciplink_version, name, version, detail) = (text()?, text()?, text()?, text()?);
        let mut assemblies = Vec::new();
        for _ in 0..r.u8().ok()? {
            let instance = r.u16().ok()?;
            let kind = AssemblyKind::from_code(r.u8().ok()?)?;
            let size = r.u16().ok()?;
            assemblies.push(Assembly {
                instance: instance.into(),
                kind,
                size: size.into(),
            });
        }
        let mut connections = Vec::new();
        for _ in 0..r.u8().ok()? {
            let kind = ConnectionKind::from_code(r.u8().ok()?)?;
            let originator = Ipv4Addr::from(<[u8; 4]>::try_from(r.take(4).ok()?).ok()?);
            let (o_t_rpi_us, t_o_rpi_us) = (r.u32().ok()?, r.u32().ok()?);
            let multicast = r.u8().ok()? != 0;
            let (input, output) = (r.u16().ok()?, r.u16().ok()?);
            connections.push(AppConnection {
                kind,
                originator,
                o_t_rpi_us,
                t_o_rpi_us,
                multicast,
                input,
                output: (output != 0).then_some(output),
            });
        }
        Some(AppInfo {
            ciplink_version,
            name,
            version,
            detail,
            assemblies,
            connections,
        })
    }

    /// The application line of a device browser, e.g. `"Station · station 2 · owned by 10.0.0.5, RPI 20 ms"`.
    pub fn summary(&self) -> String {
        let rpi = |us: u32| match us % 1000 {
            0 => format!("RPI {} ms", us / 1000),
            _ => format!("RPI {} ms", f64::from(us) / 1000.0),
        };
        let owners: Vec<_> = (self.connections.iter())
            .filter(|c| c.kind == ConnectionKind::ExclusiveOwner)
            .map(|c| format!("{}, {}", c.originator, rpi(c.t_o_rpi_us)))
            .collect();
        let state = match (owners.is_empty(), self.connections.first()) {
            (false, _) => format!("owned by {}", owners.join("; ")),
            (true, Some(c)) => format!("read by {}, {}", c.originator, rpi(c.t_o_rpi_us)),
            (true, None) => "no connection".to_owned(),
        };
        let name = if self.name.is_empty() {
            CIPLINK_SIGNATURE
        } else {
            &self.name
        };
        [name, &self.detail, &state]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" · ")
    }

    /// The application as the Python driver's dict (`summary` included).
    pub fn to_value(&self) -> Value {
        let s = |text: &str| Value::String(text.to_owned());
        let assemblies = (self.assemblies.iter())
            .map(|a| {
                Value::Struct(IndexMap::from([
                    ("instance".to_owned(), Value::UDInt(a.instance)),
                    ("kind".to_owned(), s(a.kind.as_str())),
                    ("size".to_owned(), Value::UDInt(a.size as u32)),
                ]))
            })
            .collect();
        let connections = (self.connections.iter())
            .map(|c| {
                let mut conn = IndexMap::from([
                    ("kind".to_owned(), s(c.kind.as_str())),
                    ("originator".to_owned(), s(&c.originator.to_string())),
                    ("o_t_rpi_us".to_owned(), Value::UDInt(c.o_t_rpi_us)),
                    ("t_o_rpi_us".to_owned(), Value::UDInt(c.t_o_rpi_us)),
                    ("multicast".to_owned(), Value::Bool(c.multicast)),
                    ("input".to_owned(), Value::UInt(c.input)),
                ]);
                // only an exclusive owner has an output assembly
                if let Some(output) = c.output {
                    conn.insert("output".to_owned(), Value::UInt(output));
                }
                Value::Struct(conn)
            })
            .collect();
        Value::Struct(IndexMap::from([
            ("ciplink_version".to_owned(), s(&self.ciplink_version)),
            ("name".to_owned(), s(&self.name)),
            ("version".to_owned(), s(&self.version)),
            ("detail".to_owned(), s(&self.detail)),
            ("summary".to_owned(), s(&self.summary())),
            ("assemblies".to_owned(), Value::Array(assemblies)),
            ("connections".to_owned(), Value::Array(connections)),
        ]))
    }
}

/// The route one hop past `route` on `port`.
pub fn child_route(route: &str, port: u16, address: &str) -> String {
    let route = route.trim_matches('/');
    if route.is_empty() {
        format!("{port}/{address}")
    } else {
        format!("{route}/{port}/{address}")
    }
}

/// The port and link of the port segment at the start of a padded EPATH, the link as text (e.g. `"3"`).
fn port_segment(data: &[u8]) -> Option<(u16, String)> {
    let first = *data.first()?;
    if first & 0xE0 != 0 {
        return None; // not a port segment
    }
    let mut at = 1;
    let link_size = if first & 0x10 != 0 {
        at += 1;
        usize::from(*data.get(1)?)
    } else {
        1
    };
    let port = if first & 0x0F == 0x0F {
        at += 2;
        u16::from_le_bytes([*data.get(at - 2)?, *data.get(at - 1)?])
    } else {
        u16::from(first & 0x0F)
    };
    let link = data.get(at..at + link_size)?;
    let link = match link {
        [n] => n.to_string(),
        text => String::from_utf8_lossy(text).into_owned(),
    };
    Some((port, link))
}

impl CipConnection {
    /// Sends a request to the device at `route`: directly for `""`, else by Unconnected Send. The reply data,
    /// or in the inner Err the error the device (or a bridge on the way) answered with.
    fn request_at(
        &mut self,
        route: &str,
        service: u8,
        class: u16,
        instance: u16,
        attribute: Option<u16>,
        name: &str,
    ) -> Result<std::result::Result<Vec<u8>, String>> {
        let route = route.trim_matches('/');
        let route_path = if route.is_empty() {
            RoutePath::None
        } else {
            RoutePath::Encoded(encode_epath(
                &parse_cip_route(route, false)?,
                true,
                true,
                true,
            )?)
        };
        let msg = GenericMessage {
            service,
            class_code: LogicalValue::Int(class.into()),
            instance: LogicalValue::Int(instance.into()),
            attribute: attribute.map(|a| LogicalValue::Int(a.into())),
            name: name.into(),
            connected: false,
            unconnected_send: !route.is_empty(),
            route_path,
            ..GenericMessage::default()
        };
        let reply = self.generic_message(&msg)?;
        Ok(match reply.tag.error {
            Some(err) => Err(err.message),
            None => Ok(reply.data().unwrap_or_default().to_vec()),
        })
    }

    /// The identity of the device at `route`. CommErrors pass through, a device that answers with an error
    /// is a ResponseError.
    pub fn identity_at(&mut self, route: &str) -> Result<ModuleIdentity> {
        let data = self
            .request_at(route, GET_ATTRIBUTES_ALL, 0x01, 1, None, "identity")?
            .map_err(Error::response)?;
        ModuleIdentity::decode(&mut Reader::new(&data))
    }

    /// What the ciplink device at `route` runs (its ciplink object), None for any other device. CommErrors pass
    /// through.
    pub fn app_at(&mut self, route: &str) -> Result<Option<AppInfo>> {
        let reply = self.request_at(
            route,
            GET_ATTRIBUTES_ALL,
            CIPLINK_OBJECT,
            1,
            None,
            "ciplink",
        )?;
        Ok(reply.ok().and_then(|data| AppInfo::decode(&data)))
    }

    /// The ports of the device at `route`, none if it has no Port Object.
    pub fn ports_at(&mut self, route: &str) -> Result<Vec<PortInfo>> {
        let get = |conn: &mut Self, instance: u16, attribute: u16| {
            conn.request_at(
                route,
                GET_ATTRIBUTE_SINGLE,
                PORT_OBJECT,
                instance,
                Some(attribute),
                "port",
            )
            .map(|r| r.ok())
        };
        // class attribute 2: the highest instance
        let Some(max) = get(self, 0, 2)? else {
            return Ok(Vec::new());
        };
        let max = Reader::new(&max).u16().unwrap_or(0);
        let mut ports = Vec::new();
        for instance in 1..=max {
            let Some(port_type) = get(self, instance, 1)? else {
                continue;
            };
            let Ok(port_type) = Reader::new(&port_type).u16() else {
                continue;
            };
            let number = get(self, instance, 2)?
                .and_then(|d| Reader::new(&d).u16().ok())
                .unwrap_or(instance);
            let name = match get(self, instance, 4)? {
                Some(d) => match Elementary::ShortString.decode(&mut Reader::new(&d)) {
                    Ok(Value::String(s)) => s,
                    _ => String::new(),
                },
                None => String::new(),
            };
            let address = get(self, instance, 7)?
                .and_then(|d| port_segment(&d))
                .map(|(_, link)| link);
            let node_range = get(self, instance, 8)?.and_then(|d| {
                let mut r = Reader::new(&d);
                Some((r.u16().ok()?, r.u16().ok()?))
            });
            let ip = if port_type == 4 {
                let link = get(self, instance, 3)?.and_then(|d| link_instance(&d));
                self.port_ip(route, link.unwrap_or(1))?
            } else {
                None
            };
            ports.push(PortInfo {
                number,
                port_type,
                name,
                address,
                node_range,
                ip,
            });
        }
        Ok(ports)
    }

    /// The IP address and subnet mask of instance `instance` of the TCP/IP Interface Object (attribute 5,
    /// the interface configuration), None if not readable or not set.
    fn port_ip(&mut self, route: &str, instance: u16) -> Result<Option<(Ipv4Addr, Ipv4Addr)>> {
        let reply = self.request_at(
            route,
            GET_ATTRIBUTE_SINGLE,
            TCP_IP_INTERFACE,
            instance,
            Some(5),
            "tcp/ip",
        )?;
        Ok(reply.ok().and_then(|d| {
            let mut r = Reader::new(&d);
            let (ip, mask) = (Ipv4Addr::from(r.u32().ok()?), Ipv4Addr::from(r.u32().ok()?));
            (!ip.is_unspecified()).then_some((ip, mask))
        }))
    }

    /// A scan of `port` of the device at `route`: the addresses in `nodes`, by default (None) the port's own
    /// [`nodes`](PortInfo::nodes) (none if the device has no such port).
    pub fn scan(&mut self, route: &str, port: u16, nodes: Option<&[String]>) -> Result<Scan> {
        let nodes = match nodes {
            Some(nodes) => nodes.to_vec(),
            None => self
                .ports_at(route)?
                .into_iter()
                .find(|p| p.number == port)
                .and_then(|p| p.nodes())
                .unwrap_or_default(),
        };
        Ok(Scan {
            host: format!("{}:{}", self.host(), self.port()),
            socket_timeout: self.socket_timeout(),
            connector: Arc::new(self.share_connector()),
            route: route.to_owned(),
            port,
            nodes,
        })
    }
}

/// The probes of every address on a port, made by [`CipConnection::scan`] (or a driver's `scan_port` and
/// `browse_port`), which run on connections of their own to the device.
pub struct Scan {
    host: String,
    socket_timeout: Option<std::time::Duration>,
    connector: Arc<Connector>,
    route: String,
    port: u16,
    nodes: Vec<String>,
}

impl Scan {
    /// The addresses probed.
    pub fn nodes(&self) -> &[String] {
        &self.nodes
    }

    /// Probes every address from `workers` connections at once (at least 1), calling `found` with each node as
    /// it answers, in any order. Stops early when `found` returns false (probes under way finish first).
    pub fn run(self, workers: usize, found: &mut dyn FnMut(Node) -> bool) {
        let (next, stop) = (AtomicUsize::new(0), AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let scan = &self;
        std::thread::scope(|threads| {
            for _ in 0..workers.clamp(1, self.nodes.len().max(1)) {
                let (tx, next, stop) = (tx.clone(), &next, &stop);
                threads.spawn(move || {
                    let mut conn = None;
                    while !stop.load(Ordering::Relaxed) {
                        let Some(address) = scan.nodes.get(next.fetch_add(1, Ordering::Relaxed))
                        else {
                            break;
                        };
                        if tx.send(scan.probe(&mut conn, address)).is_err() {
                            break;
                        }
                    }
                    if let Some(mut conn) = conn {
                        let _ = conn.close();
                    }
                });
            }
            drop(tx);
            for node in rx.iter() {
                if !found(node) {
                    stop.store(true, Ordering::Relaxed);
                    break;
                }
            }
            drop(rx); // workers sending after a stop see the channel closed
        });
    }

    /// Probes every address from `workers` connections at once; the nodes in the order of the addresses.
    pub fn collect(self, workers: usize) -> Vec<Node> {
        let order: std::collections::HashMap<String, usize> = (self.nodes.iter().cloned())
            .enumerate()
            .map(|(i, a)| (a, i))
            .collect();
        let mut nodes = Vec::with_capacity(self.nodes.len());
        self.run(workers, &mut |node| {
            nodes.push(node);
            true
        });
        nodes.sort_by_key(|n| order.get(&n.address).copied());
        nodes
    }

    /// The identity at one address, on this worker's connection (opened when needed, dropped after a
    /// connection error so the next address opens a new one).
    fn probe(&self, conn: &mut Option<CipConnection>, address: &str) -> Node {
        let route = child_route(&self.route, self.port, address);
        let result = (|| {
            if conn.is_none() {
                let options = CipOptions {
                    socket_timeout: self.socket_timeout,
                    ..CipOptions::default()
                };
                let connector = Arc::clone(&self.connector);
                let connector: Connector = Box::new(move |h, p, t| connector(h, p, t));
                let mut c = CipConnection::new(&self.host, options, connector, false)?;
                if !c.open()? {
                    return Err(Error::comm("failed to register a session"));
                }
                *conn = Some(c);
            }
            let c = conn.as_mut().ok_or_else(|| Error::comm("no connection"))?;
            let identity = c.identity_at(&route)?;
            // a ciplink adapter is a PC: only a node at an IP address can be one, so slots cost nothing extra
            let app = match address.parse::<Ipv4Addr>().map(|_| c.app_at(&route)) {
                Ok(Ok(app)) => app,
                Ok(Err(err)) => {
                    // the identity stands; a lost connection is opened again for the next address
                    if matches!(err, Error::Comm(_)) {
                        *conn = None;
                    }
                    None
                }
                Err(_) => None,
            };
            Ok((identity, app))
        })();
        let (identity, app, error) = match result {
            Ok((identity, app)) => (Some(identity), app, None),
            Err(err) => {
                if matches!(err, Error::Comm(_)) {
                    *conn = None;
                }
                (None, None, Some(err.to_string()))
            }
        };
        Node {
            route,
            address: address.to_owned(),
            identity,
            error,
            app,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_segments_format_as_port_and_link() {
        let seg = |data: &[u8]| port_segment(data).map(|(p, l)| format!("{p}/{l}"));
        assert_eq!(seg(&[0x01, 0x03]).as_deref(), Some("1/3"));
        let mut ip = vec![0x12, 8];
        ip.extend(b"10.0.0.1");
        assert_eq!(seg(&ip).as_deref(), Some("2/10.0.0.1"));
        assert_eq!(seg(&[0x0F, 0x12, 0x00, 0x05]).as_deref(), Some("18/5"));
        assert_eq!(seg(&[0x20, 0x01]), None);
        assert_eq!(seg(&[]), None);
    }

    fn ciplink_object(connections: &[[u8; 18]]) -> Vec<u8> {
        let mut data = b"ciplink0.3.4Station1.0	station 2".to_vec();
        data.extend([1, 100, 0, 1, 148, 0]); // input 100 of 148 bytes
        data.push(connections.len() as u8);
        connections.iter().for_each(|c| data.extend(c));
        data
    }

    // kind, originator, O->T and T->O RPI (us), multicast, input, output
    const OWNER: [u8; 18] = [
        1, 192, 0, 2, 5, 0x20, 0x4E, 0, 0, 0x20, 0x4E, 0, 0, 1, 100, 0, 150, 0,
    ];
    const LISTENER: [u8; 18] = [
        3, 192, 0, 2, 6, 0x20, 0x4E, 0, 0, 0xC4, 0x09, 0, 0, 1, 100, 0, 0, 0,
    ];

    #[test]
    fn the_ciplink_object_decodes_into_the_app_line() {
        let app = AppInfo::decode(&ciplink_object(&[OWNER, LISTENER])).expect("a ciplink device");
        assert_eq!(app.assemblies, [Assembly::input(100, 148)]);
        assert_eq!(app.connections[0].kind, ConnectionKind::ExclusiveOwner);
        assert_eq!(app.connections[0].output, Some(150));
        assert_eq!(app.connections[1].output, None);
        assert_eq!(
            app.summary(),
            "Station · station 2 · owned by 192.0.2.5, RPI 20 ms"
        );
        let only_listener = AppInfo::decode(&ciplink_object(&[LISTENER])).expect("app");
        assert_eq!(
            only_listener.summary(),
            "Station · station 2 · read by 192.0.2.6, RPI 2.5 ms"
        );
    }

    #[test]
    fn empty_names_and_no_connections_decode() {
        let mut data = b"ciplink0.3.5   ".to_vec();
        data.extend([0, 0]); // no assemblies, no connections
        let app = AppInfo::decode(&data).expect("a ciplink device");
        assert_eq!(
            (app.name.as_str(), app.version.as_str(), app.detail.as_str()),
            ("", "", "")
        );
        assert_eq!(app.summary(), "ciplink · no connection");
    }

    #[test]
    fn other_answers_of_the_class_are_not_ciplink_devices() {
        // a Logix controller answers class 0x64 with its program name, a STRING with a 2-byte length
        assert_eq!(AppInfo::decode(b" ciplink"), None);
        assert_eq!(AppInfo::decode(b""), None);
        let full = ciplink_object(&[OWNER]);
        for cut in 0..full.len() {
            assert_eq!(AppInfo::decode(&full[..cut]), None, "cut at {cut}");
        }
        let mut bad_kind = full.clone();
        let at = full.len() - 18;
        bad_kind[at] = 9;
        assert_eq!(AppInfo::decode(&bad_kind), None);
    }

    #[test]
    fn child_routes_extend_the_route() {
        assert_eq!(child_route("", 1, "3"), "1/3");
        assert_eq!(child_route("1/2/", 2, "10.0.0.5"), "1/2/2/10.0.0.5");
    }

    #[test]
    fn ports_without_a_node_range_use_their_type_default() {
        let port = |port_type, node_range, ip| PortInfo {
            number: 1,
            port_type,
            name: String::new(),
            address: None,
            node_range,
            ip,
        };
        let span = |nodes: Option<Vec<String>>| {
            nodes.map(|n| (n.len(), n[0].clone(), n[n.len() - 1].clone()))
        };
        let s = |t: &str| t.to_owned();
        assert_eq!(
            span(port(1, None, None).nodes()),
            Some((17, s("0"), s("16")))
        );
        assert_eq!(
            span(port(1, Some((0, 9)), None).nodes()),
            Some((10, s("0"), s("9")))
        );
        assert_eq!(
            span(port(5, None, None).nodes()),
            Some((64, s("0"), s("63")))
        );
        assert_eq!(port(4, None, None).nodes(), None);
        let ip = |a: &str, m: &str| Some((a.parse().expect("ip"), m.parse().expect("mask")));
        let enet = port(4, None, ip("192.168.1.5", "255.255.255.0")).nodes();
        assert_eq!(
            span(enet),
            Some((254, s("192.168.1.1"), s("192.168.1.254")))
        );
        // a bigger subnet is cut to the /24 around the port, a smaller one is kept
        let wide = port(4, None, ip("10.20.30.40", "255.255.0.0")).nodes();
        assert_eq!(span(wide), Some((254, s("10.20.30.1"), s("10.20.30.254"))));
        let small = port(4, None, ip("10.0.0.70", "255.255.255.192")).nodes();
        assert_eq!(span(small), Some((62, s("10.0.0.65"), s("10.0.0.126"))));
    }

    #[test]
    fn link_object_paths_name_the_ethernet_link_instance() {
        assert_eq!(link_instance(&[2, 0, 0x20, 0xF6, 0x24, 0x02]), Some(2));
        assert_eq!(
            link_instance(&[3, 0, 0x20, 0xF6, 0x25, 0, 0x01, 0x01]),
            Some(0x101)
        );
        assert_eq!(link_instance(&[2, 0, 0x20, 0xF5, 0x24, 0x01]), None);
        assert_eq!(link_instance(&[]), None);
    }
}

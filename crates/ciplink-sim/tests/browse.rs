//! Browsing a simulated chassis like RSWho: the controller's ports, the slots of its backplane and the devices
//! on its EtherNet/IP network.
#![allow(clippy::unwrap_used)]

use ciplink::cip::{CipDriver, CipOptions};
use ciplink_sim::{IdentityConfig, LogixConfig, ModuleConfig, NetworkDeviceConfig, Simulator};

fn identity(product_name: &str) -> IdentityConfig {
    IdentityConfig {
        product_name: product_name.into(),
        ..IdentityConfig::default()
    }
}

fn chassis() -> Simulator {
    Simulator::new(LogixConfig {
        slot: 1,
        chassis_size: 4,
        modules: vec![ModuleConfig {
            slot: 3,
            identity: identity("1756-EN2T/D"),
        }],
        ip: "10.1.2.3".into(),
        netmask: "255.255.255.0".into(),
        network: vec![NetworkDeviceConfig {
            ip: "10.1.2.40".into(),
            identity: identity("2198-H008-ERS2"),
        }],
        ..LogixConfig::default()
    })
    .unwrap()
}

fn driver(sim: &Simulator) -> CipDriver {
    let driver =
        CipDriver::with_connector("192.0.2.1", CipOptions::default(), sim.connector()).unwrap();
    assert!(driver.open().unwrap());
    driver
}

fn addresses(range: std::ops::RangeInclusive<u16>) -> Vec<String> {
    range.map(|n| n.to_string()).collect()
}

#[test]
fn the_ports_of_the_device_name_its_slot_chassis_and_subnet() {
    let sim = chassis();
    let driver = driver(&sim);
    let ports = driver.ports_at("").unwrap();
    assert_eq!(ports.len(), 2);
    let (bp, enet) = (&ports[0], &ports[1]);
    assert_eq!(
        (bp.number, bp.type_name().as_str(), bp.name.as_str()),
        (1, "Backplane", "Backplane")
    );
    assert_eq!(bp.address.as_deref(), Some("1"));
    assert_eq!(bp.nodes(), Some(addresses(0..=3)));
    assert_eq!((enet.number, enet.type_name().as_str()), (2, "EtherNet/IP"));
    assert_eq!(enet.address.as_deref(), Some("10.1.2.3"));
    assert_eq!(
        enet.ip,
        Some((
            "10.1.2.3".parse().unwrap(),
            "255.255.255.0".parse().unwrap()
        ))
    );
    let hosts = enet.nodes().unwrap();
    assert_eq!(
        (hosts.len(), hosts[0].as_str(), hosts[253].as_str()),
        (254, "10.1.2.1", "10.1.2.254")
    );
    // the controller answers through its own slot too
    assert_eq!(driver.ports_at("bp/1").unwrap(), ports);
}

#[test]
fn browsing_the_backplane_finds_every_module_and_the_empty_slots() {
    let sim = chassis();
    let driver = driver(&sim);
    let nodes = driver
        .browse_port("", 1, Some(&addresses(0..=3)), 1)
        .unwrap();
    let found: Vec<_> = nodes
        .iter()
        .map(|n| {
            (
                n.route.as_str(),
                n.identity.as_ref().map(|i| i.product_name.as_str()),
            )
        })
        .collect();
    assert_eq!(
        found,
        [
            ("1/0", None),
            ("1/1", Some("1756-SIM/A")),
            ("1/2", None),
            ("1/3", Some("1756-EN2T/D")),
        ]
    );
    assert!(nodes[0].error.is_some());
    // a module without a Port Object has no ports to browse
    assert!(driver.ports_at("1/3").unwrap().is_empty());
    assert_eq!(driver.identity_at("").unwrap().product_name, "1756-SIM/A");
}

#[test]
fn browsing_the_ethernet_port_finds_the_devices_on_its_network() {
    let sim = chassis();
    let driver = driver(&sim);
    let hosts = ["10.1.2.39", "10.1.2.40"].map(String::from);
    let nodes = driver.browse_port("", 2, Some(&hosts), 2).unwrap();
    assert_eq!(nodes[0].identity, None);
    assert!(
        nodes[0]
            .error
            .as_deref()
            .unwrap()
            .contains("Unconnected message timeout"),
        "{nodes:?}"
    );
    assert_eq!(nodes[1].route, "2/10.1.2.40");
    assert_eq!(
        nodes[1].identity.as_ref().unwrap().product_name,
        "2198-H008-ERS2"
    );
}

#[test]
fn a_scan_probes_the_port_from_several_connections_and_can_stop_early() {
    let sim = chassis();
    let driver = driver(&sim);
    // by default the port's own addresses: the whole subnet, in address order
    let nodes = driver.browse_port("", 2, None, 8).unwrap();
    assert_eq!(nodes.len(), 254);
    assert_eq!(nodes[0].address, "10.1.2.1");
    let found: Vec<_> = nodes.iter().filter(|n| n.identity.is_some()).collect();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].route, "2/10.1.2.40");

    // streamed as they answer, stopping at the first device
    let mut seen = 0;
    let mut first = None;
    driver
        .scan_port("", 2, None, 8, &mut |node| {
            seen += 1;
            first = node.identity.map(|i| i.product_name);
            first.is_none()
        })
        .unwrap();
    assert_eq!(first.as_deref(), Some("2198-H008-ERS2"));
    assert!(seen < 254, "the scan went on after the stop: {seen}");

    // the driver's own connection is free meanwhile and after
    assert_eq!(driver.identity_at("").unwrap().product_name, "1756-SIM/A");
    // a port the device does not have has nothing to scan
    assert!(driver.browse_port("", 9, None, 4).unwrap().is_empty());
}

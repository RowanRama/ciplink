# Discovering and browsing devices

## Discover devices on the network

`discover` broadcasts a ListIdentity request, like the RSLinx EtherNet/IP driver, on every network adapter that is
up, and returns the identity of every device that answers within a second or so. `list_identity` asks a single
device. Neither needs an open driver.

=== "Python"

    ```python
    from ciplink import CIPDriver

    for device in CIPDriver.discover():
        print(device["ip_address"], device["product_name"], device["revision"])
    print(CIPDriver.list_identity("192.0.2.10"))
    # {'encap_protocol_version': 1, 'ip_address': '192.0.2.10', 'vendor': 'Rockwell Automation/Allen-Bradley',
    #  'product_type': 'Communications Adapter', 'product_code': 166, 'revision': {'major': 11, 'minor': 2},
    #  'status': b'0\x00', 'serial': '00e2c0de', 'product_name': '1756-EN2T/D', 'state': 3}
    ```

=== "Rust"

    ```rust
    use ciplink::cip::CipDriver;

    for device in CipDriver::discover("255.255.255.255") {
        println!("{} {}", device.ip_address, device.identity.product_name);
    }
    if let Some(device) = CipDriver::list_identity("192.0.2.10")? {
        println!("{:?}", device.identity);
    }
    ```

=== "C#"

    ```csharp
    using Ciplink;

    foreach (var device in CipDriver.Discover())
        Console.WriteLine($"{device!["ip_address"]} {device["product_name"]}");
    Console.WriteLine(CipDriver.ListIdentity("192.0.2.10"));
    ```

=== "C++"

    ```cpp
    #include <iostream>
    #include "ciplink.hpp"

    ciplink::Value devices = ciplink::discover();     // keep it: a loop over discover().as_array() would dangle
    for (const ciplink::Value& device : devices.as_array())
        std::cout << device["ip_address"].as_string() << " " << device["product_name"].as_string() << "\n";
    std::cout << ciplink::to_json(ciplink::list_identity("192.0.2.10")) << "\n";
    ```

=== "C"

    ```c
    char *json = NULL;
    if (ciplink_discover(NULL, &json) == CIPLINK_STATUS_OK) {        /* NULL: 255.255.255.255 */
        printf("%s\n", json);
        ciplink_string_free(json);
    }
    if (ciplink_list_identity("192.0.2.10", &json) == CIPLINK_STATUS_OK) {
        printf("%s\n", json);
        ciplink_string_free(json);
    }
    ```

## Browse like RSWho

A driver can walk through a device the way RSWho expands a tree:

- `get_ports(route)` lists the ports of the device at `route` (its Port object): the backplane, Ethernet ports and
  so on, with the addresses on each.
- `browse_port(route, port)` asks every address on one port for its identity: each slot of a backplane, each node
  of a ControlNet or DeviceNet network, or every host of an EtherNet/IP port's subnet (at most the /24 around it),
  each through the module.
- `get_identity(route)` reads the identity at any route.

A route is relative to the device at the driver's IP address (the driver's own path isn't used): `""` is that
device, `"bp/3"` (or `"1/3"`) the module in slot 3 of its backplane, `"bp/2/enet/192.0.2.30"` a device behind the
module in slot 2. Every node found carries its `route`, to browse further.

An empty slot or a missing device costs a timeout at the bridge (about 4 s), so `browse_port` probes from several
connections of its own at once (`workers`, 16 by default). `scan_port` (Python: `iter_port`) hands over each node as
it answers instead of waiting for all of them.

=== "Python"

    ```python
    from ciplink import CIPDriver

    with CIPDriver("192.0.2.10") as drv:
        for port in drv.get_ports():
            print(port["number"], port["type_name"], port["ip"], len(port["nodes"] or []))
            for node in drv.browse_port("", port):
                if node["identity"]:
                    print("  ", node["route"], node["identity"]["product_name"])
    # 1 Backplane None 10
    #    1/0 1756-L83E/B
    #    1/1 1756-EN2T/D
    # 2 EtherNet/IP 192.0.2.10 254
    #    2/192.0.2.30 1734-AENTR/C
    ```

=== "Rust"

    ```rust
    use ciplink::cip::{CipDriver, CipOptions};

    let drv = CipDriver::new("192.0.2.10", CipOptions::default())?;
    drv.open()?;
    for port in drv.ports_at("")? {
        println!("{} {}", port.number, port.type_name());
        for node in drv.browse_port("", port.number, None, 16)? {
            if let Some(identity) = node.identity {
                println!("   {} {}", node.route, identity.product_name);
            }
        }
    }
    ```

=== "C#"

    ```csharp
    using Ciplink;

    using var drv = new CipDriver("192.0.2.10");
    drv.Open();
    foreach (var port in drv.GetPorts())
    {
        Console.WriteLine($"{port!["number"]} {port["type_name"]}");
        foreach (var node in drv.BrowsePort("", (int)port["number"]!))
            if (node!["identity"] is { } identity)
                Console.WriteLine($"   {node["route"]} {identity["product_name"]}");
    }
    ```

=== "C++"

    ```cpp
    #include <iostream>
    #include "ciplink.hpp"

    ciplink::Cip drv("192.0.2.10");
    drv.open();
    ciplink::Value ports = drv.get_ports();
    for (const ciplink::Value& port : ports.as_array()) {
        std::cout << port["number"].as_int() << " " << port["type_name"].as_string() << "\n";
        drv.scan_port("", uint16_t(port["number"].as_int()), [](const ciplink::Value& node) {
            if (!node["identity"].is_null())
                std::cout << "   " << node["route"].as_string() << " "
                          << node["identity"]["product_name"].as_string() << "\n";
            return true;     // false stops the scan
        });
    }
    ```

=== "C"

    ```c
    static bool on_node(void *user, const char *node_json) {
        (void)user;
        printf("%s\n", node_json);   /* {"route": ..., "address": ..., "identity": {...}|null, "error": ...} */
        return true;                 /* false stops the scan */
    }

    /* in main: */
    CiplinkDriver *drv = NULL;
    ciplink_cip_new("192.0.2.10", NULL, &drv);
    if (ciplink_open(drv) == CIPLINK_STATUS_OK) {
        char *ports = NULL;
        if (ciplink_get_ports(drv, "", &ports) == CIPLINK_STATUS_OK) {
            printf("%s\n", ports);
            ciplink_string_free(ports);
        }
        ciplink_scan_port(drv, "", 1, NULL, 16, on_node, NULL);    /* port 1: the backplane */
    }
    ciplink_driver_free(drv);
    ```

`get_module_info(slot)` is a shortcut for the identity of a slot in the driver's own backplane.

## ciplink devices

A ciplink [adapter](adapter.md) answers like any other EtherNet/IP device, and it also says what it runs. Every node
that `browse_port` or `scan_port` finds at an IP address carries an `app` field: null for other devices, else the
application's `name`, `version` and `detail` (status text), its `assemblies` and `connections`, the `ciplink_version`,
and a `summary` for a device browser, such as `Station · station 2 · owned by 192.0.2.5, RPI 20 ms`. Reading it costs
one request per device found, and none for the slots of a backplane, since an adapter is a PC on a network.

`get_app(route)` reads it for a single device: Python `drv.get_app("")`, Rust `drv.app_at("")`, C# `drv.GetApp()`,
C++ `drv.get_app()`, C `ciplink_get_app(drv, "", &json)`. `examples/device_browser.py` shows ciplink devices with
their app line.

`python -m examples.device_browser` in the repository is a small RSWho-style tree browser built on these calls.

# Getting started

## Pick a driver

| Driver | For | Python | Rust | C# | C++ | C |
|---|---|---|---|---|---|---|
| Logix | ControlLogix, CompactLogix, GuardLogix, Micro800 | `LogixDriver` | `logix::driver::LogixDriver` | `LogixDriver` | `ciplink::Logix` | `ciplink_logix_new` |
| SLC | SLC 500, MicroLogix | `SLCDriver` | `slc::driver::SlcDriver` | `SlcDriver` | `ciplink::Slc` | `ciplink_slc_new` |
| CIP | any EtherNet/IP device: generic messages, identity, browsing | `CIPDriver` | `cip::CipDriver` | `CipDriver` | `ciplink::Cip` | `ciplink_cip_new` |

Each driver holds one connection to one device. Create more drivers for more connections.

## Connect

Opening a driver connects and registers a session. A Logix driver also reads the controller info and uploads the
tag list (see [Tag list and controller info](tag-list.md) to make that faster or lazy). Close the driver when you're
done; every binding also closes it when the driver is released.

=== "Python"

    ```python
    from ciplink import LogixDriver

    # a with block opens the driver and closes it at the end
    with LogixDriver("192.0.2.10") as plc:
        print(plc.info["product_name"], plc.info["name"])

    # or open and close it yourself, e.g. for a long-lived connection
    plc = LogixDriver("192.0.2.10")
    plc.open()
    try:
        print(plc.read("Counter"))
    finally:
        plc.close()
    ```

=== "Rust"

    ```rust
    use ciplink::logix::driver::{LogixDriver, LogixOptions};

    let plc = LogixDriver::new("192.0.2.10", LogixOptions::default())?;
    plc.open()?;
    println!("{:?}", plc.get_plc_name()?);
    plc.close()?; // dropping the driver also closes it
    ```

=== "C#"

    ```csharp
    using Ciplink;

    using var plc = new LogixDriver("192.0.2.10");   // Dispose closes it
    plc.Open();
    Console.WriteLine($"{plc.Info()["product_name"]} running {plc.GetPlcName()}");
    ```

=== "C++"

    ```cpp
    #include <iostream>
    #include "ciplink.hpp"

    ciplink::Logix plc("192.0.2.10");   // the destructor closes it
    plc.open();
    std::cout << plc.get_plc_name() << "\n";
    ```

=== "C"

    ```c
    #include <stdio.h>
    #include "ciplink.h"

    CiplinkDriver *plc = NULL;
    if (ciplink_logix_new("192.0.2.10", NULL, &plc) == CIPLINK_STATUS_OK && ciplink_open(plc) == CIPLINK_STATUS_OK) {
        char *name = NULL;
        if (ciplink_get_plc_name(plc, &name) == CIPLINK_STATUS_OK) {
            printf("%s\n", name);   /* a JSON string, e.g. "SimPLC" */
            ciplink_string_free(name);
        }
    }
    ciplink_driver_free(plc);   /* closes the connection; NULL is ignored */
    ```

Requests on one driver are sent one at a time, so one driver can be shared between threads. For requests in
parallel, use one driver per thread. The drivers don't send keep-alives: a controller may close a connection that
is idle for about a minute, so a long-lived connection should make a request at least that often. If a request
fails with a connection error (timeout, reset), the driver drops the connection; open it again to reconnect.

## Paths

The path names the device, the same way Logix shows a route.

| Form | Example | Use for |
|---|---|---|
| IP address | `192.0.2.10` | devices without a backplane (drives, Micro800), or a controller in slot 0 |
| IP address and slot | `192.0.2.10/2` | a controller in another slot of the backplane |
| CIP route | `192.0.2.10/bp/2/enet/192.0.2.20/bp/0` | a device reached through other modules |

- In a route, `backplane` or `bp` is the backplane port and `enet` the Ethernet port. Segments can be separated by
  `/`, `\` or `,`.
- A non-standard TCP port follows the IP address: `192.0.2.10:44819`.
- The Logix and SLC drivers turn the first two forms into a route to the controller (adding `bp/0` when no slot is
  given). The CIP driver uses the path as it is, so `192.0.2.10` addresses the Ethernet module itself.

## Options

| Option | Default | What it does |
|---|---|---|
| `socket_timeout` | 5 s | timeout of connecting, sends and receives; none blocks forever |
| `connection_size` | 4000 (500 for SLC) | largest connected message; above 511 bytes uses a Large Forward Open, with a fallback to 500 if the module refuses it |
| `init_tags` (Logix) | true | upload the tag list on open |
| `init_program_tags` (Logix) | true | include program-scoped tags in that upload |
| `tag_namespace_filter` (Logix) | `""` | keep only tags whose name (without `Program:X.`) starts with this |
| `lazy_tags` (Logix) | false | skip the upload and look tags up on first use |
| `tag_cache_file` (Logix) | none | keep the tag list in a file, so a reconnect to an unchanged controller uploads nothing |

=== "Python"

    ```python
    from ciplink import LogixDriver

    plc = LogixDriver("192.0.2.10", socket_timeout=2.0, connection_size=500,
                      lazy_tags=True, tag_cache_file="plc.cache")
    ```

=== "Rust"

    ```rust
    use ciplink::cip::CipOptions;
    use ciplink::logix::driver::{LogixDriver, LogixOptions};
    use std::time::Duration;

    let plc = LogixDriver::new("192.0.2.10", LogixOptions {
        lazy_tags: true,
        tag_cache_file: Some("plc.cache".into()),
        cip: CipOptions { socket_timeout: Some(Duration::from_secs(2)), connection_size: 500 },
        ..LogixOptions::default()
    })?;
    ```

=== "C#"

    ```csharp
    using Ciplink;

    using var plc = new LogixDriver("192.0.2.10", new LogixOptions
    {
        SocketTimeout = TimeSpan.FromSeconds(2),
        ConnectionSize = 500,
        LazyTags = true,
        TagCacheFile = "plc.cache",
    });
    ```

=== "C++"

    ```cpp
    #include "ciplink.hpp"

    ciplink::Logix plc("192.0.2.10",
        R"({"socket_timeout": 2, "connection_size": 500, "lazy_tags": true, "tag_cache_file": "plc.cache"})");
    ```

=== "C"

    ```c
    #include "ciplink.h"

    CiplinkDriver *plc = NULL;
    ciplink_logix_new("192.0.2.10",
        "{\"socket_timeout\": 2, \"connection_size\": 500, \"lazy_tags\": true, \"tag_cache_file\": \"plc.cache\"}",
        &plc);
    ```

The connection size and timeout can also be changed on a driver: set the connection size before opening (or close
first), and a new timeout applies to an open connection at once.

## Check the results

Reads and writes return one result per tag, in order. A result has the tag name, the value, the data type and an
error. A failed tag has an error message and an [error kind](errors.md) (`not_found`, `bad_value`, `access` and so
on) instead of a value, and the other tags of the call are not affected. Only connection failures and bad arguments
raise an exception (Python, C#, C++), return `Err` (Rust) or return a status code (C).

=== "Python"

    ```python
    from ciplink import ErrorKind

    for tag in plc.read("Counter", "NoSuchTag"):
        if tag:                                   # a value and no error
            print(tag.tag, tag.value, tag.type)
        elif tag.error_kind == ErrorKind.NOT_FOUND:
            print(f"{tag.tag} is not in the controller")
        else:
            print(f"{tag.tag} failed: {tag.error}")

    if all(plc.write(("Counter", 0), ("Tank.Setpoint", 75.5))):
        print("both written")
    ```

=== "Rust"

    ```rust
    use ciplink::ErrorKind;

    for tag in plc.read(&["Counter", "NoSuchTag"])? {
        match (&tag.value, &tag.error) {
            (Some(value), None) => println!("{} = {value:?} ({:?})", tag.tag, tag.data_type),
            (_, Some(error)) if error.kind == ErrorKind::NotFound => println!("{} is not in the controller", tag.tag),
            (_, error) => println!("{} failed: {error:?}", tag.tag),
        }
    }
    ```

=== "C#"

    ```csharp
    foreach (Tag tag in plc.Read("Counter", "NoSuchTag"))
    {
        if (tag.IsOk)
            Console.WriteLine($"{tag.Name} = {tag.Value} ({tag.DataType})");
        else if (tag.ErrorKind == "not_found")
            Console.WriteLine($"{tag.Name} is not in the controller");
        else
            Console.WriteLine($"{tag.Name} failed: {tag.Error}");
    }
    ```

=== "C++"

    ```cpp
    for (const ciplink::Tag& tag : plc.read({"Counter", "NoSuchTag"})) {
        if (tag)
            std::cout << tag.tag << " = " << ciplink::to_json(tag.value) << " (" << *tag.type << ")\n";
        else if (tag.error->kind == "not_found")
            std::cout << tag.tag << " is not in the controller\n";
        else
            std::cout << tag.tag << " failed: " << tag.error->message << "\n";
    }
    ```

=== "C"

    ```c
    /* results are JSON: [{"tag": str, "value": ..., "type": str|null,
       "error": null | {"message": str, "kind": str, "status": int|null, "ext": int|null}}, ...] */
    const char *tags[] = {"Counter", "NoSuchTag"};
    char *json = NULL;
    if (ciplink_read(plc, tags, 2, &json) == CIPLINK_STATUS_OK) {
        printf("%s\n", json);
        ciplink_string_free(json);
    } else {
        char *err = ciplink_last_error(plc);
        fprintf(stderr, "read failed: %s\n", err);
        ciplink_string_free(err);
    }
    ```

See [Values and results](values.md) for how each PLC type appears in each language.

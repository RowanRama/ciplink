# Tag list and controller info

## The tag list

On open, the Logix driver uploads the controller's tag list and the definition of every UDT and AOI used. Reads and
writes need these definitions to encode requests and decode replies. The upload takes from well under a second to
10–15 seconds for a very large program on a busy older controller. Three options shorten it:

- **`lazy_tags`** skips the upload. The first request in a scope uploads that scope's symbol list and resolves only
  the tags asked for and the structures they need. Use it when a program reads a few tags.
- **`tag_cache_file`** keeps the tag list in a file. A reconnect to a controller whose tag table hasn't changed
  uploads nothing, and the structures of an unchanged symbol list aren't read again.
- **`init_program_tags=False`** uploads the controller-scoped tags only.

`init_tags=False` skips the upload without lazy lookups; then call `get_tag_list` yourself (or load a cache file)
before reading.

=== "Python"

    ```python
    from ciplink import LogixDriver

    with LogixDriver("192.0.2.10") as plc:
        for name, tag in plc.tags.items():                 # {tag name: definition}
            print(name, tag["data_type_name"], tag["dimensions"], tag["external_access"])
        print(plc.data_types["TankData"]["attributes"])   # ['Level', 'Setpoint']
        print(plc.get_tag_info("Tank.Level"))             # the definition of a member
        program_tags = plc.get_tag_list(program="MainProgram", cache=False)
    ```

=== "Rust"

    ```rust
    use ciplink::logix::driver::{LogixDriver, LogixOptions};

    let plc = LogixDriver::new("192.0.2.10", LogixOptions::default())?;
    plc.open()?;
    for (name, tag) in plc.tags() {
        println!("{name}: {:?} {:?} {}", tag.data_type.name(), tag.dimensions, tag.external_access);
    }
    let program_tags = plc.get_tag_list(Some("MainProgram"), false, "")?;
    println!("{} tags in MainProgram", program_tags.len());
    ```

=== "C#"

    ```csharp
    using System.Text.Json.Nodes;
    using Ciplink;

    using var plc = new LogixDriver("192.0.2.10");
    plc.Open();
    foreach (var (name, tag) in plc.Tags())
        Console.WriteLine($"{name}: {tag!["data_type_name"]} {tag["external_access"]}");
    Console.WriteLine(plc.DataTypes()["TankData"]!["attributes"]);
    Console.WriteLine(plc.TagInfo("Tank.Level"));
    JsonArray programTags = plc.TagList("MainProgram", cache: false);
    ```

=== "C++"

    ```cpp
    #include <iostream>
    #include "ciplink.hpp"

    ciplink::Logix plc("192.0.2.10");
    plc.open();
    ciplink::Value tags = ciplink::parse_json(plc.tags_json());     // {tag name: definition}
    for (const auto& [name, tag] : tags.as_struct())
        std::cout << name << ": " << tag["data_type_name"].as_string() << "\n";
    std::cout << plc.tag_info_json("Tank.Level") << "\n";
    std::string program_tags = plc.tag_list_json("MainProgram", false);
    ```

=== "C"

    ```c
    char *json = NULL;
    if (ciplink_tags(plc, &json) == CIPLINK_STATUS_OK) {          /* {tag name: definition} */
        printf("%s\n", json);
        ciplink_string_free(json);
    }
    if (ciplink_tag_info(plc, "Tank.Level", &json) == CIPLINK_STATUS_OK) {
        printf("%s\n", json);
        ciplink_string_free(json);
    }
    if (ciplink_tag_list(plc, "MainProgram", false, NULL, &json) == CIPLINK_STATUS_OK) {
        printf("%s\n", json);
        ciplink_string_free(json);
    }
    ```

`get_tag_list(program)` takes `None`/null for the controller tags, `"*"` for all tags, or a program name. With
`cache` (the default) the result replaces the driver's tag list.

### Tag definitions

| Key | Meaning |
|---|---|
| `tag_name` | the name; program tags are `Program:<program>.<tag>` |
| `instance_id` | the controller's ID of the tag, used to address it on firmware v21 and later |
| `tag_type` | `atomic` (BOOL, DINT, REAL ...) or `struct` (STRING, TIMER, UDTs, AOIs) |
| `data_type_name` | the type name, e.g. `DINT`, `TIMER`, `TankData` |
| `data_type` | the type name for atomic tags; the structure definition for structures |
| `string` | the string length of a string type |
| `external_access` | `Read/Write`, `Read Only` or `None` |
| `dim` | number of dimensions, 0 for a scalar |
| `dimensions` | length of each dimension, e.g. `[5, 10, 0]` for `DINT[5,10]` |
| `alias` | true for an alias tag |

A structure definition (`data_types[name]`) has the `name`, the visible member names in `attributes`, every member
with its type and byte offset in `internal_tags` (including hidden ones, such as the host integer of BOOL members),
and the `template` used to read it whole. InOut parameters of AOIs are not included.

## Online edits

Tags are addressed by instance ID, which an online edit can change. Every read and write checks the controller's
tag table version, and when it has changed the driver reloads the tag list before going on; a result is never
silently the wrong tag. A request caught in the middle of a change fails with the `table_changed` error kind rather
than returning data. `check_tag_table()` checks and reloads on demand and returns whether it did.

## Sharing a tag list

Several drivers to the same controller can share one upload: open the second with `init_tags=False` and give it the
first driver's tags. A tag list is only valid for the controller it came from, since instance IDs differ between
controllers even when their programs match.

=== "Python"

    ```python
    first = LogixDriver("192.0.2.10")
    first.open()                                      # uploads the tag list
    second = LogixDriver("192.0.2.10", init_tags=False)
    second._tags = first.tags
    second.open()                                     # uploads nothing
    ```

=== "Rust"

    ```rust
    let first = LogixDriver::new("192.0.2.10", LogixOptions::default())?;
    first.open()?;
    let second = LogixDriver::new("192.0.2.10", LogixOptions { init_tags: false, ..LogixOptions::default() })?;
    second.share_tags_from(&first);
    second.open()?;
    ```

In C, C++ and C#, give each driver the same `tag_cache_file` instead.

## Controller info, name and clock

| | Python | Rust | C# | C++ | C |
|---|---|---|---|---|---|
| Info read on open (product, revision, serial, keyswitch, program name) | `plc.info` | `get_plc_info()`, `name()` | `Info()` | `info_json()` | `ciplink_info` |
| Program name | `get_plc_name()` | `get_plc_name()` | `GetPlcName()` | `get_plc_name()` | `ciplink_get_plc_name` |
| Identity and keyswitch, read now | `get_plc_info()` | `get_plc_info()` | `GetPlcInfo()` | `get_plc_info()` | `ciplink_get_plc_info` |
| Read the clock | `get_plc_time()` | `get_plc_time()` | `GetPlcTime()` | `get_plc_time()` | `ciplink_get_plc_time` |
| Set the clock (to this computer's by default) | `set_plc_time()` | `set_plc_time(None)` | `SetPlcTime()` | `set_plc_time()` | `ciplink_set_plc_time(plc, -1, &json)` |

=== "Python"

    ```python
    print(plc.info["product_name"], plc.info["revision"], plc.info["keyswitch"])
    clock = plc.get_plc_time()
    print(clock.value["string"])                 # 'Monday, October 26, 2026 02:15:04PM' in local time
    plc.set_plc_time()                           # set it to this computer's clock
    ```

=== "Rust"

    ```rust
    use ciplink::logix::driver::format_plc_time_utc;
    use ciplink::Value;

    let info = plc.get_plc_info()?;
    println!("{} {}", info.identity.product_name, info.keyswitch);
    let clock = plc.get_plc_time()?;
    if let Some(Value::Struct(time)) = &clock.value {
        if let Some(Value::ULInt(us)) = time.get("microseconds") {
            println!("{}", format_plc_time_utc(*us));
        }
    }
    plc.set_plc_time(None)?;
    ```

=== "C#"

    ```csharp
    Console.WriteLine($"{plc.Info()["product_name"]} {plc.GetPlcInfo()["keyswitch"]}");
    DateTime clock = (DateTime)plc.GetPlcTime().Value!;   // UTC
    plc.SetPlcTime();
    ```

=== "C++"

    ```cpp
    std::cout << plc.get_plc_info()["keyswitch"].as_string() << "\n";
    uint64_t us = plc.get_plc_time();      // microseconds since 1970 UTC
    plc.set_plc_time();
    ```

=== "C"

    ```c
    char *json = NULL;
    if (ciplink_get_plc_time(plc, &json) == CIPLINK_STATUS_OK) {
        printf("%s\n", json);   /* {"tag":"get_plc_time","value":{"microseconds":...},...} */
        ciplink_string_free(json);
    }
    if (ciplink_set_plc_time(plc, -1, &json) == CIPLINK_STATUS_OK)
        ciplink_string_free(json);
    ```

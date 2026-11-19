# Modbus TCP and RTU

`ModbusDriver` reads and writes Modbus devices over Modbus TCP, RTU on a serial port, and RTU frames over TCP
(serial-to-Ethernet gateways). It runs on the same session as the Logix driver: reads queued together are merged into
the fewest Modbus requests, it reconnects in the background, and async calls, subscriptions and connection events work
as described in [Async, subscriptions and reconnect](sessions.md).

Modbus has no tag names. A **map file** gives them, with their types and descriptions; anything not in the map can be
read by its **plain address**.

## Paths

| Path | Means |
|---|---|
| `tcp://host[:port][?unit=N]` | Modbus TCP (MBAP), port 502 |
| `rtu://PORT[?baud=B&parity=N\|E\|O&data=7\|8&stop=1\|2&unit=N]` | RTU on a serial port: `rtu://COM3`, `rtu:///dev/ttyUSB0` |
| `rtu+tcp://host[:port][?unit=N]` | RTU frames over a TCP socket, for gateways in transparent (raw) mode, port 502 |

- The scheme is required; a bare IP address is a `RequestError`, so a Logix path passed by mistake fails clearly.
- `unit` is the default unit (slave) id, 0 to 255, used by every tag without one of its own. Default 1.
- **RTU settings** default to the Modbus spec's: 19200 baud, even parity, 8 data bits, 1 stop bit
  (`rtu://COM3?baud=9600&parity=N&stop=2`). Keys are case-insensitive; an unknown key is an error. No flow control.
- Unit 0 on `rtu://` and `rtu+tcp://` is broadcast: writes are sent and succeed without a reply, reads are refused.
  On `tcp://` unit 0 is an ordinary unit id.
- RS-485 adapters that echo the bytes they send are not supported.

## Map file

CSV, UTF-8, one row per tag. The first line that is not a comment is the header; columns are found by name, so their
order is free, optional columns may be left out and extra columns are ignored. Lines starting with `#` and blank lines
are skipped. A header with semicolons and no commas makes a semicolon-separated file (Excel in many locales). Quote a
field with `"` to hold a comma or line break.

```csv
# Pump skid. Addresses are 0-based: holding register 40001 is "holding,0".
name,area,address,type,count,order,unit,scale,offset,units,description,writable
Pump1_Speed,holding,0,float32,,CDAB,,,,rpm,Pump 1 speed setpoint,
Pump1_Run,coil,0,bool,,,,,,,Pump 1 run command,
Pump1_Fault,discrete,3,bool,,,,,,,"Pump 1 fault, any cause",
Tank_Level,input,10,int16,,,,0.1,,%,Tank level (0.1 % per count),
Tank_Temp,input,11,int16,,,,0.1,-40,degC,Tank temperature,
Totals,holding,100,uint32,4,,,,,m3,Daily totals of the last 4 days,
Recipe,holding,200,string,16,,,,,,Active recipe name,
Drive_Status,holding,300,uint16,,,,,,,Drive status word,false
Horn,holding,301.4,bool,,,,,,,Horn bit in the control word,
Valve2_Open,coil,10,bool,,,2,,,,Valve on gateway unit 2,
```

This is `tools/sim/example_modbus_map.csv`; the [simulator](simulator.md#modbus) serves it with
`tools/sim/example_modbus.json`.

| Column | Required | Values | Default |
|---|---|---|---|
| `name` | yes | letters, digits, `_`, dot-separated parts (`Pump1.Speed`); unique ignoring case; must not look like a plain address | |
| `area` | yes | `coil`, `discrete`, `holding`, `input` (or `co`, `di`, `hr`, `ir`) | |
| `address` | yes | **0-based** protocol address 0 to 65535; for a `bool` in a register `register.bit` (`301.4`) | |
| `type` | yes | `bool`, `int16`, `uint16`, `int32`, `uint32`, `int64`, `uint64`, `float32`, `float64`, `string` | |
| `count` | no | array elements; for `string` the length in characters (required) | 1 |
| `order` | no | `ABCD`, `CDAB`, `BADC`, `DCBA` (see [word order](#word-and-byte-order)) | the driver's `word_order` |
| `unit` | no | 0 to 255 | the path's unit |
| `scale`, `offset` | no | read value = raw x scale + offset (the tag reads as `LREAL`; writes are converted back) | none |
| `units` | no | engineering units text | empty |
| `description` | no | text, served as the tag's description | empty |
| `writable` | no | `true`/`false`, `yes`/`no`, `1`/`0` | true for coils and holding registers; discrete inputs and input registers are always read-only |

`bool` works in every area (in `holding`/`input` it needs a bit). Every other type is for `holding` and `input` only.
Rows may overlap (an `int32` and its two `uint16` halves). Loading stops at the first error, which names the file,
line and column: `pumps.csv line 7: type 'flaot32' is not one of bool, int16, ...`.

Names a caller can use, ignoring case:

| Name | Means |
|---|---|
| `Totals` | the whole map row (an array when `count` > 1) |
| `Totals[2]` | element 2 (0-based) |
| `Drive_Status.5` | bit 5 of a 16-bit integer row in `holding`/`input` (written with FC22) |
| anything else | a plain address |

## Plain addresses

Without a map, or for anything not in it:

```text
area offset ["." bit] [":" type [":" order]] ["{" count "}"] ["@" unit]
```

`area` is `co` (coils), `di` (discrete inputs), `hr` (holding registers) or `ir` (input registers); `co`/`di` default
to `bool`, `hr`/`ir` to `uint16`. Case does not matter; no spaces.

| Address | Means |
|---|---|
| `hr0` | holding register 0 (Modicon 40001) as `UINT` |
| `hr100:float32` | holding registers 100-101 as `REAL`, driver word order |
| `hr100:float32:cdab` | the same, word-swapped |
| `hr200:int16{10}` | holding registers 200-209, an array of 10 `INT` |
| `hr300:string{20}` | holding registers 300-309 as a 20-character string |
| `hr10.4` | bit 4 of holding register 10 (`BOOL`) |
| `ir5:int32` | input registers 5-6 as `DINT` |
| `co0{16}` | coils 0-15, an array of 16 `BOOL` |
| `di7@3` | discrete input 7 of unit 3 |

**Addresses are 0-based protocol addresses**, what goes on the wire. Modicon reference numbers are not parsed (a
5- or 6-digit `40001` is ambiguous); convert them by their first digit and subtract 1:

| Modicon | Area | Example |
|---|---|---|
| `0xxxx` / `0xxxxx` | `co` | `00001` -> `co0` |
| `1xxxx` / `1xxxxx` | `di` | `10008` -> `di7` |
| `3xxxx` / `3xxxxx` | `ir` | `30011` -> `ir10` |
| `4xxxx` / `4xxxxx` | `hr` | `40001` -> `hr0`, `400101` -> `hr100` |

## Values

| Type | Registers | Reads as |
|---|---|---|
| `bool` | 1 bit | `BOOL` |
| `int16`, `uint16` | 1 | `INT`, `UINT` |
| `int32`, `uint32` | 2 | `DINT`, `UDINT` |
| `int64`, `uint64` | 4 | `LINT`, `ULINT` |
| `float32`, `float64` | 2, 4 | `REAL`, `LREAL` |
| `string` | count / 2, rounded up | `STRING` (two characters per register, cut at the first NUL) |
| any number with `scale` or `offset` | as its type | `LREAL` |

A write that does not fit the type (70000 into an `int16`, 1.5 into an integer, a string longer than `count`) is
`bad_value` and nothing is sent.

### Word and byte order

`ABCD` is the Modbus standard: each register big-endian, most significant register first. The others are two
independent swaps, shown for the `float32` 123.456 (`0x42F6E979`):

| Order | Bytes in each register | Register order | Registers |
|---|---|---|---|
| `ABCD` | high byte first | most significant first | `42F6 E979` |
| `CDAB` | high byte first | least significant first | `E979 42F6` |
| `BADC` | low byte first | most significant first | `F642 79E9` |
| `DCBA` | low byte first | least significant first | `79E9 F642` |

For 64-bit types "least significant first" reverses all four registers. 16-bit types only see the byte swap
(`BADC`, `DCBA`). Strings only see the byte swap too. Set the order per map row, per plain address
(`hr100:float32:cdab`), or for the whole driver (`word_order`). If a float reads as a tiny or huge number, try `CDAB`.

## Reads, writes and options

**Reads** are merged: tags of the same unit and area whose gap is at most `max_gap` registers (or bits) go into one
request, up to `max_registers` (125, the protocol limit) or `max_bits` (2000). This holds across callers too, so two
subscriptions on neighbouring registers make one request. A tag longer than the limit is read in several requests,
split between elements. If a merged request gets exception 02 or 03 (some tag in it is not there), each of its tags
is read again on its own, so one bad row never fails its neighbours. For a device whose register map has holes, set
`max_gap = 0` to avoid the retry; for a device that refuses long reads, lower `max_registers`.

**Writes** are sent one request per tag, in order, never merged:

| Target | Function |
|---|---|
| one coil | FC05 Write Single Coil |
| several coils | FC15 Write Multiple Coils |
| one register | FC06 Write Single Register |
| several registers (32/64-bit, floats, arrays, strings) | FC16 Write Multiple Registers |
| a bit of a holding register (`hr10.4`, `Horn`, `Drive_Status.5`) | FC22 Mask Write Register only |
| a discrete input, an input register, a `writable = false` row | refused (`access`), nothing sent |

`write_multiple` sends FC15/FC16 for a single coil or register too, for devices without FC05/FC06. A device without
FC22 answers exception 01 and the bit write fails; there is deliberately no read-modify-write fallback, which would
race the device's own logic.

| Option | Default | Meaning |
|---|---|---|
| `map_file` | none | the map file; none: plain addresses only |
| `socket_timeout` | 1 s | reply timeout |
| `max_registers` | 125 | most registers in one read (1 to 125) |
| `max_bits` | 2000 | most coils or discrete inputs in one read (1 to 2000) |
| `max_gap` | 8 | most unrequested registers or bits between two tags read in one request |
| `word_order` | `ABCD` | for rows and addresses without an order |
| `write_multiple` | false | always FC15/FC16 |
| `keep_alive_address` | none | the keep-alive reads this plain address instead of sending FC08 |
| `keep_alive` | 30 s over `tcp://` and `rtu+tcp://`, off for `rtu://` | idle time before a keep-alive request |
| `reconnect` | on | reconnect in the background after the link is lost |

The keep-alive sends FC08 (Diagnostics, Return Query Data) to the default unit. Any reply counts, an exception too
(most TCP devices answer 01). For a device that ignores unknown functions, set `keep_alive_address` (e.g. `hr0`).

**Device info.** `device_info(unit)` reads Read Device Identification (FC43 / MEI 14): `vendor_name`,
`product_code`, `revision` and, if the device has them, `vendor_url`, `product_name`, `model_name`,
`user_application_name`. A device without FC43 gives the exception as the error. `send_pdu(pdu, unit)` sends one raw
PDU (function code and data) for functions the driver does not wrap, and returns the reply PDU.

## Examples

=== "Python"

    ```python
    from ciplink import ModbusDriver

    with ModbusDriver("tcp://192.0.2.30?unit=1", "skid.csv", max_gap=0) as plc:
        speed, level = plc.read("Pump1_Speed", "Tank_Level")    # Tag objects, as for Logix
        print(plc.read("Totals[2]", "Drive_Status.5", "hr400:int32", "di7@3"))
        plc.write(("Pump1_Speed", 1450.0), ("Horn", True))      # FC16, then FC22
        print(plc.tags["Tank_Level"]["description"], plc.device_info())
        with plc.subscribe("Tank_Level", "Pump1_Fault", interval=0.5) as sub:
            for tags in sub:
                print([(t.tag, t.value, t.error) for t in tags])

    # RTU on a serial port, and RTU over a TCP gateway
    rtu = ModbusDriver("rtu://COM3?baud=9600&parity=N&unit=5", "skid.csv")
    gateway = ModbusDriver("rtu+tcp://192.0.2.40:4001?unit=3", word_order="CDAB")
    ```

=== "Rust"

    ```rust
    use ciplink::Value;
    use ciplink::modbus::{ModbusDriver, ModbusOptions, TagMap};

    let options = ModbusOptions { map: Some(TagMap::load("skid.csv")?), max_gap: 0, ..ModbusOptions::default() };
    let plc = ModbusDriver::new("tcp://192.0.2.30?unit=1", options)?;
    plc.open()?;
    for tag in plc.read(&["Pump1_Speed", "Tank_Level", "hr400:int32"])? {
        println!("{} = {:?} {:?}", tag.tag, tag.value, tag.error);
    }
    plc.write(&[("Pump1_Speed", Value::Real(1450.0)), ("Horn", Value::Bool(true))])?;
    println!("{:?}", plc.device_info(None)?);
    for row in plc.map().tags() {
        println!("{} ({}): {}", row.name, row.units, row.description);
    }
    ```

=== "C#"

    ```csharp
    using Ciplink;

    using var plc = new ModbusDriver("tcp://192.0.2.30?unit=1", new ModbusOptions { MapFile = "skid.csv", MaxGap = 0 });
    plc.Open();
    foreach (Tag tag in plc.Read("Pump1_Speed", "Tank_Level", "hr400:int32"))
        Console.WriteLine($"{tag.Name} = {tag.Value}");
    plc.Write(("Pump1_Speed", 1450.0f), ("Horn", true));
    Console.WriteLine(plc.DeviceInfo());
    foreach (var row in plc.Tags)
        Console.WriteLine($"{row!["name"]} ({row["units"]}): {row["description"]}");
    ```

=== "C++"

    ```cpp
    #include <iostream>
    #include "ciplink.hpp"

    ciplink::Modbus plc("tcp://192.0.2.30?unit=1", R"({"map_file": "skid.csv", "max_gap": 0})");
    plc.open();
    for (const ciplink::Tag& tag : plc.read({"Pump1_Speed", "Tank_Level", "hr400:int32"}))
        std::cout << tag.tag << " = " << ciplink::to_json(tag.value) << "\n";
    plc.write({{"Pump1_Speed", 1450.0}, {"Horn", true}});
    std::cout << ciplink::to_json(plc.device_info()) << "\n";
    ```

=== "C"

    ```c
    #include <stdio.h>
    #include "ciplink.h"

    CiplinkDriver *plc = NULL;
    ciplink_modbus_new("tcp://192.0.2.30?unit=1", "{\"map_file\": \"skid.csv\", \"max_gap\": 0}", &plc);
    if (ciplink_open(plc) == CIPLINK_STATUS_OK) {
        const char *tags[] = {"Pump1_Speed", "Tank_Level", "hr400:int32"};
        char *json = NULL;
        if (ciplink_read(plc, tags, 3, &json) == CIPLINK_STATUS_OK) {
            printf("%s\n", json);
            ciplink_string_free(json);
        }
        if (ciplink_write(plc, "[[\"Pump1_Speed\", 1450.0], [\"Horn\", true]]", &json) == CIPLINK_STATUS_OK)
            ciplink_string_free(json);
        if (ciplink_modbus_device_info(plc, -1, &json) == CIPLINK_STATUS_OK) {
            printf("%s\n", json);
            ciplink_string_free(json);
        }
    }
    ciplink_driver_free(plc);
    ```

The options in C and C++ are a JSON object with the keys of the options table (`socket_timeout` and `keep_alive` in
seconds, `keep_alive` `null` for off); C# uses `ModbusOptions` (`MapFile`, `MaxGap`, `WordOrder`, ...). See
[Other languages](api.md#modbus-c-c-and-c) and the [Python API](api-python.md#modbus) for every call. The
[tag server](server.md) serves a Modbus device with `protocol = "modbus"` and a `map_file`.

## Errors

A Modbus exception is the tag's error, with the exception code as its status:

| Code | Name | Error kind |
|---|---|---|
| 01 | Illegal Function | `bad_request` |
| 02 | Illegal Data Address | `not_found` |
| 03 | Illegal Data Value | `bad_value` on a write, `bad_request` on a read |
| 04 | Server Device Failure | `device` |
| 05 | Acknowledge | `refused` |
| 06 | Server Device Busy | `refused` |
| 08 | Memory Parity Error | `device` |
| 0A | Gateway Path Unavailable | `comm` |
| 0B | Gateway Target Device Failed to Respond | `comm` |
| other | | `device` |

**Timeouts** differ by scheme:

- `tcp://`: no reply within `socket_timeout` fails the whole call (`CommError`) and drops the link; the session
  reconnects. A gateway that stays silent for a dead unit (instead of sending 0B) therefore makes every read of that
  unit reconnect; use `rtu+tcp://` if the gateway passes RTU frames, or one driver per unit.
- `rtu://` and `rtu+tcp://`: a timeout, a bad CRC or a reply that does not match fails only that request's tags
  (`comm`); the link stays, so one dead unit does not take down the others on the bus. A write that times out says
  `(the write may have been applied)` and is never sent again.

A read or write before `open()` is a `CommError`. An unknown name is `not_found`, a malformed address `bad_request`.

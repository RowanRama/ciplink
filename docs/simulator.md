# Testing with the simulator

`ciplink-sim` is a simulated Logix, Micro800 or SLC 500 controller that speaks real EtherNet/IP over TCP. Point any
driver, in any language, at it to test without a PLC. It answers reads and writes (packed, fragmented and by
instance ID), the tag list upload, online edits, descriptions, the clock, trends, ListIdentity, the Port object and
a backplane of modules. All of ciplink's own tests run against it.

It is built from the repository (it isn't published as a package):

```sh
git clone https://github.com/RowanRama/ciplink
cd ciplink
cargo run -p ciplink-sim -- --config tools/sim/wiki_controller.json --port 44818
```

It prints `listening on 127.0.0.1:44818` once ready. Then connect to `127.0.0.1`:

```python
from ciplink import LogixDriver

with LogixDriver("127.0.0.1") as plc:
    print(plc.read("Counter", "Tank", "Recipe{10}"))
```

`tools/sim/wiki_controller.json` holds the tags used in this wiki's examples (`Counter`, `Tank`, `Recipe`, `Motor`,
`Message`, `Flags`, `Status` and `Program:MainProgram.Step`), so every example runs against it once the IP address
is changed to `127.0.0.1`.

## Options

```text
ciplink-sim [--config FILE] [--host HOST] [--port PORT] [--udp ADDR] [--exit-on-eof]
```

| Option | Meaning |
|---|---|
| `--config FILE` | the controller to simulate (JSON); without it, a Logix controller with no tags |
| `--host`, `--port` | where to listen (default `127.0.0.1:44818`); port 0 picks a free port, printed on start |
| `--udp ADDR` | also answer ListIdentity over UDP, e.g. `127.0.0.1:44818` |
| `--exit-on-eof` | exit when standard input closes (for test harnesses) |

Port 44818 may already be taken by FactoryTalk Linx or RSLinx. Then use another port and add it to the path:
`LogixDriver("127.0.0.1:44819")`.

## Controller files

A controller file lists the data types, the controller and program tags with their values, the identity, and
optionally the modules in the chassis and the devices on its network. `tools/sim/` has examples:
`example_controller.json` (every data type), `example_micro800.json` and `example_slc.json` (data files).

```json
{
  "kind": "logix",
  "program_name": "Line2",
  "types": [
    {"name": "TankData", "members": [{"name": "Level", "type": "REAL"}, {"name": "Setpoint", "type": "REAL"}]}
  ],
  "tags": [
    {"name": "Counter", "type": "DINT", "value": 42, "descriptions": {"": "Parts made this shift"}},
    {"name": "Tank", "type": "TankData", "value": {"Level": 50.0, "Setpoint": 75.5}},
    {"name": "Recipe", "type": "DINT", "dims": [10], "value": [1, 2, 3]}
  ],
  "programs": [
    {"name": "MainProgram", "tags": [{"name": "Step", "type": "DINT", "value": 3}]}
  ]
}
```

To simulate a real project, convert a Studio 5000 L5X export:

```sh
python tools/sim/l5x_to_config.py project.L5X -o controller.json
```

It takes the data types (UDTs, string types, AOIs), the controller and program tags with their values, the programs
and the tasks.

## Changing it during a test

Standard input takes one JSON command per line and answers each with one JSON line, `{"ok": result}` or
`{"error": message}`, so a test can change the controller between requests:

| Command | Does |
|---|---|
| `{"cmd": "value", "path": "Tank.Level"}` | returns a tag's value (SLC: `"N7:0"`) |
| `{"cmd": "set", "path": "Counter", "value": 5}` | sets it |
| `{"cmd": "add_tag", "program": null, "tag": {...}}` | an online edit adding a tag |
| `{"cmd": "remove_tag", "program": null, "name": "Counter"}` | an online edit removing one |
| `{"cmd": "bump"}` | bumps the tag table version |
| `{"cmd": "fault", "fault": {"drop_replies": 1}}` | injects a fault: `drop_replies`, `delay_ms`, `refuse_connections`, `tag_status`, `service_status` |
| `{"cmd": "clear_faults"}` | clears them |
| `{"cmd": "requests"}` | the requests received so far |

## Modbus

A config whose `"kind"` is `"modbus"` makes the simulator a Modbus device (port 502 unless `--port` is given):
units with coils, discrete inputs, holding and input registers, optional holes (ranges that answer exception 02),
functions 1-6, 8, 15, 16, 22 and 43/14 (device identification), and exception 01 for anything else.

```sh
cargo run -p ciplink-sim -- --config tools/sim/example_modbus.json --port 5020                  # Modbus TCP
cargo run -p ciplink-sim -- --config tools/sim/example_modbus.json --port 5021 --framing rtu    # RTU over TCP
```

Connect with `ModbusDriver("tcp://127.0.0.1:5020", "tools/sim/example_modbus_map.csv")` or
`rtu+tcp://127.0.0.1:5021`. See [Modbus TCP and RTU](modbus.md). Its standard input commands:

| Command | Does |
|---|---|
| `{"cmd": "registers", "unit": 1, "area": "holding", "address": 0, "count": 2}` | returns registers (`holding` or `input`) |
| `{"cmd": "set_registers", "unit": 1, "area": "holding", "address": 0, "values": [1, 2]}` | sets them |
| `{"cmd": "bits", "unit": 1, "area": "coil", "address": 0, "count": 3}` | returns coils or discrete inputs (`coil`, `discrete`) |
| `{"cmd": "set_bits", "unit": 1, "area": "coil", "address": 0, "values": [true]}` | sets them |
| `{"cmd": "fault", "fault": {"no_reply": 2}}` | injects a fault: `drop_replies`, `delay_ms`, `refuse_connections`, `close_connections`, `no_reply` (a silent unit), `exception` (`{"unit", "function", "code"}`), `bad_crc` |
| `{"cmd": "clear_faults"}` | clears them |
| `{"cmd": "requests"}` | the requests received so far |

## S7comm-plus

A config whose top-level key is `"s7plus"` makes the simulator a Siemens S7-1500 over S7comm-plus with TLS (port 102
unless `--port` is given). It makes a self-signed certificate at start and prints its SHA-256 as
`fingerprint XX:XX:...` after `listening on`, so a test can pin it.

```sh
cargo run -p ciplink-sim -- --config tools/sim/example_s7plus.json --port 1102
```

Connect with `S7PlusDriver("127.0.0.1:1102")`. See [Siemens S7-1500 and S7-1200](s7plus.md). Its standard input
commands:

| Command | Does |
|---|---|
| `{"cmd": "value", "path": "Line1.Conveyor.Speed"}` | returns a tag's value |
| `{"cmd": "set", "path": "Line1.Count", "value": 5}` | sets it |
| `{"cmd": "fault", "fault": {"drop_replies": 1}}` | injects a fault: `delay_ms`, `drop_replies`, `close_connections`, `refuse_connections`, `item_error` (`{"tag", "code"}`), `error_pdu`, `system_event`, `negative_item_errors` |
| `{"cmd": "clear_faults"}` | clears them |
| `{"cmd": "change_program"}` | changes the program, as a download would |
| `{"cmd": "requests"}` | the requests received so far |
| `{"cmd": "fingerprint"}` | the certificate's SHA-256 |

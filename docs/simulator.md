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

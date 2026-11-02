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

## Testing a driver from Rust

In a Rust test the simulator runs in the same process: `Simulator::new(config)` (or `Simulator::from_json`) and
`LogixDriver::with_connector(path, options, sim.connector())` connect a driver without sockets, and
`sim.serve("127.0.0.1:0")` serves it over TCP. Besides values and faults, it has hooks that let a test see and
control what the driver does to the controller. `crates/ciplink-sim/tests/driver_hooks.rs` uses each one to test
ciplink's driver.

| Hook | For |
|---|---|
| `LogixConfig::memory_len`, `TagConfig::at`, `TagConfig::bit` | tags at known offsets of one controller memory; overlapping tags and bit aliases |
| `TypeConfig::explicit`, `MemberConfig::at`, `bit`, `hidden` | a data type with an exact layout, such as a predefined type |
| `Logix::type_layout` | the layout the simulator stores, to compare with what a driver decoded |
| `Logix::swap_memory`, `Logix::memory_len` | lend the test's own bytes as the controller memory, or take a copy |
| `Simulator::set_deferred`, `pending`, `service` | hold requests until the test answers them, and report the bytes each write changed |
| `Logix::set_clock_us` | a fixed controller clock |
| `Simulator::set_identity_status` | the identity status word (mode, key and fault bits) and the ListIdentity state |
| `LogixConfig::trends` | `false` answers every trend request with 0x08 (service not supported) |

### Placed tags

With `memory_len`, tags placed with `at` lie at that byte offset of one memory (tags without `at` come after it).
Placed tags may overlap, so a tag at the offset of another is an alias that shares its bytes, and a BOOL with `bit`
is one bit of the byte at its offset:

```rust
let config = LogixConfig { memory_len: Some(16), ..LogixConfig::default() }
    .with_tag(TagConfig::new("word", "DINT").at(0))
    .with_tag(TagConfig::new("low", "SINT").at(0))          // the low byte of word
    .with_tag(TagConfig::new("flag", "BOOL").at(1).bit(5)); // bit 13 of word
```

A placed BOOL stores 0 or 1 whatever byte is written, as a controller does. In JSON these are `"memory_len"` on the
controller and `"at"` and `"bit"` on a tag.

### Explicit layouts

`TypeConfig::explicit(name, size, members)` uses each member's offset (and a BOOL's bit) as given, instead of the
Logix layout rules, and may take a template ID up to 0xFFF. Above 0xEFF the type reports as predefined, like TIMER
or MESSAGE. A hidden member is in the template but cannot be read by name and is left out of values. The simulator
does not tell a driver which members are hidden, so name them as a controller does: `CTL` or `Control` in a
predefined type, or a name starting with `ZZZZZZZZZZ` or `__`.

```rust
let timer_like = TypeConfig {
    template_id: Some(0xF40),
    ..TypeConfig::explicit("TMRLIKE", 12, [
        MemberConfig::new("CTL", "DINT").at(0).hidden(),
        MemberConfig::new("PRE", "DINT").at(4),
        MemberConfig::new("ACC", "DINT").at(8),
        MemberConfig::new("EN", "BOOL").at(3).bit(7),
        MemberConfig::new("DN", "BOOL").at(3).bit(5),
    ])
};
let layout = sim.with_logix(|l| l.type_layout("TMRLIKE")).unwrap().unwrap();
assert_eq!(plc.data_types()[&Some("TMRLIKE".into())].template.structure_size, layout.size);
```

In JSON a type takes `"size"` and `"template_id"`, a member `"offset"`, `"bit"` and `"hidden"`.

### Deferred requests

`sim.set_deferred(true)` holds every request until the test calls `sim.service(&mut memory, max_frames)`, which
answers up to `max_frames` of them, oldest first, with `memory` lent as the controller memory (it must be
`memory_len()` long). It returns a `Serviced`: the number of requests answered, the `(offset, len)` ranges that
writes changed, and the value of any clock set. So a test can check exactly which bytes a write touched, hold a
request past the driver's timeout, or answer a driver's packets one at a time. A deferred driver waits for its
answer, so run it on a thread of its own:

```rust
let plc = LogixDriver::with_connector("192.0.2.1", options, sim.connector())?;
plc.open()?;                                   // answered at once
sim.set_deferred(true);
let client = std::thread::spawn(move || plc.write(&[("word.3", Value::Bool(true))]));
let mut memory = vec![0xA5; 16];
let mut writes = Vec::new();
while !client.is_finished() {
    writes.extend(sim.service(&mut memory, usize::MAX)?.writes);
    std::thread::sleep(Duration::from_millis(1));
}
assert_eq!(writes, [(0, 4)]);                  // a read-modify-write of the DINT
assert_eq!(memory[0], 0xAD);                   // only bit 3 changed
```

`sim.pending()` says whether a request is waiting, and `set_deferred(false)` answers every waiting request from
the simulator's own memory. TCP connections are deferred too; UDP ListIdentity is answered at once.

### Clock and identity

`sim.with_logix(|l| l.set_clock_us(Some(us)))` fixes the controller clock, so `get_plc_time` returns exactly `us`
and a `set_plc_time` moves it to the value set; `None` goes back to the host clock.
`sim.set_identity_status(status, state)` sets the identity status word, whose bytes the driver decodes into the
keyswitch position (`0x3060` is REMOTE RUN, `0x2070` PROG), and the state byte of ListIdentity.

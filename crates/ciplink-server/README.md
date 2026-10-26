# ciplink-server

One server per site that owns all the PLC connections and serves tag values to web apps over a WebSocket. Apps
never talk to the PLCs: each PLC gets one connection and one poll loop, however many screens are open. It runs on
the [ciplink](https://crates.io/crates/ciplink) Rust core and speaks the protocol of
[`@ciplink/react`](https://www.npmjs.com/package/@ciplink/react). It replaces the Python ciplink-tagserver and reads
the same config files.

## Get it

| From | How |
|---|---|
| Python | `pip install ciplink`, then `ciplink-server ...` (or `python -m ciplink.server`) |
| Rust | `cargo install ciplink-server`, or `cargo add ciplink-server` to embed it |
| C / C++ / C# | `ciplink_server_start` in `ciplink.h`, `ciplink::Server`, `Ciplink.TagServer` |
| Anything else | the `ciplink-server` executable on the [releases page](https://github.com/RowanRama/ciplink/releases) |

## Run

```
ciplink-server run --config tagserver.toml          # real PLCs
ciplink-server run --config tagserver.toml --mock   # simulated values from each PLC's mock_tags file
ciplink-server dump-tags --config tagserver.toml --plc PLC1 --out PLC1_tags.json
ciplink-server types --url http://127.0.0.1:8765 --token T --out src/plc.ts
ciplink-server service install --config C:\TagServer\tagserver.toml   # Windows: start at boot (administrator)
```

`--log-file FILE` on `run` logs to a file (rotated at 10 MB, 5 kept) instead of the console.

## Config

```toml
[server]
host = "127.0.0.1"      # localhost only by default
port = 8765
cycle_ms = 250          # poll period per PLC
audit_log = "audit.log" # JSON lines of every write attempt ("" for none)

[plc.PLC1]
path = "192.168.1.10"
mock_tags = "PLC1_tags.json"         # optional: used only with --mock

[decorator.setpoint]
writable = true

[plc.PLC1.udt.MotorData]
SpeedSP = "setpoint"                 # every MotorData.SpeedSP in the controller is writable

[token.hmi1]
secret = "change-me"
write = ["PLC1/Line1.*.SpeedSP"]
```

Tags are named `<plc>/<tag>` (unqualified with one PLC). Structure comes from the controller; intent (writable,
min/max, units, deadband, bit names, poll rates) comes from decorators, rules and poll groups in the config. The
full reference (decorators, rules, poll groups, tiers and pages, the read planner, writes and momentary buttons,
the protocol and the HTTP endpoints) is the [Tag server page of the ciplink wiki](https://rowanrama.github.io/ciplink/server/).

## Safety

- Writes are off unless a token has `write` patterns and the tag's settings make it writable.
- Every write attempt, allowed or not, goes to the audit log.
- Momentary buttons are released by the server when the client stops holding them.
- The server binds to `127.0.0.1` by default. Put it behind a TLS proxy before opening it to a network: tokens
  travel in clear text over plain `ws://` and `http://`.

## Embed it

```rust
let config = ciplink_server::load_config("tagserver.toml".as_ref())?;
let server = ciplink_server::ServerHandle::start(config, ciplink_server::factory(false))?;
println!("listening on {}", server.addr());
server.stop()?;
```

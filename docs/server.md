# The tag server

`ciplink-server` owns the PLC connections of a site and serves tag values to web apps over a WebSocket: each PLC
gets one connection and one poll loop, however many screens are open. It is the Rust port of the Python
ciplink-tagserver 0.4: the same config files, protocol and HTTP API, so `@ciplink/react` apps and existing configs
work unchanged.

One thing differs from the Python server: BYTE, WORD, DWORD and LWORD values are lists of bools (as ciplink reads
them), typed `boolean[]` with `.bit(n)` by `types`.

## Run it

The `ciplink-server` command comes with the Python package (`pip install ciplink`), with `cargo install
ciplink-server`, and as an executable per platform on the [releases page](https://github.com/RowanRama/ciplink/releases).

```sh
ciplink-server run --config tagserver.toml          # real PLCs
ciplink-server run --config tagserver.toml --mock   # simulated values from each PLC's mock_tags file
ciplink-server dump-tags --config tagserver.toml --plc PLC1 --out PLC1_tags.json
ciplink-server types --url http://127.0.0.1:8765 --token T --out src/plc.ts
ciplink-server service install --config C:\TagServer\tagserver.toml   # Windows: start at boot (administrator)
```

`--log-file FILE` on `run` logs to a file (rotated at 10 MB, 5 kept) instead of the console.

It also runs inside a program, on threads of its own, until it is stopped. `host` and `port` override the config
file's (port 0 picks a free port); stopping it releases pressed momentary buttons, closes the PLC connections and
flushes the audit log.

=== "Python"

    ```python
    from ciplink.server import TagServer

    with TagServer("tagserver.toml", mock=True, port=0) as server:
        print("listening on", server.address)       # ('127.0.0.1', 51234)
        input("Enter stops the server")
    ```

=== "Rust"

    ```rust
    let config = ciplink_server::load_config("tagserver.toml".as_ref())?;
    let server = ciplink_server::ServerHandle::start(config, ciplink_server::factory(false))?;
    println!("listening on {}", server.addr());
    server.stop()?;
    ```

    Add the `ciplink-server` crate (`cargo add ciplink-server`); `factory(true)` serves mock values.

=== "C#"

    ```csharp
    using Ciplink;

    using var server = new TagServer("tagserver.toml", mock: true, port: 0);
    Console.WriteLine($"listening on {server.Address}");
    Console.ReadLine();
    server.Stop();
    ```

=== "C++"

    ```cpp
    #include <iostream>
    #include "ciplink.hpp"

    ciplink::Server server("tagserver.toml", /*mock*/ true, std::nullopt, /*port*/ 0);
    std::cout << "listening on " << server.address() << "\n";
    std::cin.get();
    server.stop();
    ```

=== "C"

    ```c
    #include <stdio.h>
    #include "ciplink.h"

    CiplinkServer *server = NULL;
    if (ciplink_server_start("tagserver.toml", "{\"mock\": true, \"port\": 0}", &server) == CIPLINK_STATUS_OK) {
        char *address = NULL;
        ciplink_server_address(server, &address);
        printf("listening on %s\n", address);
        ciplink_string_free(address);
        getchar();
        ciplink_server_stop(server);     /* stops and frees it */
    } else {
        char *err = ciplink_last_error(NULL);
        fprintf(stderr, "%s\n", err);
        ciplink_string_free(err);
    }
    ```

Web apps connect with the [`@ciplink/react`](https://www.npmjs.com/package/@ciplink/react) client. The rest of this
page is the config and protocol reference.

## Config

```toml
[server]
host = "127.0.0.1"      # localhost only by default
port = 8765
cycle_ms = 250          # poll period per PLC
audit_log = "audit.log" # JSON lines of every write attempt ("" for none)
tier2_period_s = 3      # each tier-2 tag is read about this often
grace_s = 10            # a tag leaving tier 1 stays at tier 2 this long
pages_file = "pages.json" # what each page showed, learned from the clients ("" to keep it in memory)
planner = true          # read structs whole when that saves reads (false to troubleshoot)
whole_max_bytes = 1500  # largest struct the planner reads whole
momentary_timeout_ms = 1000 # a pressed momentary tag with no hold this long is released

[plc.PLC1]
path = "192.168.1.10"                # a ciplink/pycomm3 path, e.g. "10.0.0.5/1/3"
tag_cache_file = "cache/PLC1.json"   # optional: fast restarts
mock_tags = "PLC1_tags.json"         # optional: used only with --mock

[decorator.setpoint]                 # see Decorators
writable = true

[plc.PLC1.udt.MotorData]
SpeedSP = "setpoint"

[token.viewer]
secret = "change-me-too"             # no write patterns: read-only

[token.hmi1]
secret = "change-me"
write = ["PLC1/Line1.*.SpeedSP", "PLC1/Program:Station1.Door*"]
```

Relative file paths are relative to the config file. A complete example is
the Test Bench example of [ciplink-tagserver](https://github.com/RowanRama/ciplink-tagserver/tree/main/examples/bench).

**Tag names** are qualified as `<plc>/<tag>`, e.g. `PLC1/Program:Main.Speed` (a slash cannot appear
in a Logix tag name). With exactly one PLC configured, unqualified names mean that PLC.

**Patterns** (token write patterns, and the fallback rules and poll groups) ignore case; `*` matches any run
of characters (dots and brackets too), `?` one character, everything else is literal: `Tank[*].Level` matches
`Tank[3].Level`. Rule and group patterns match the tag inside its PLC (`Tank[3].Level`); token write patterns
match the qualified name (`PLC1/Tank[3].Level`). `match` may be one pattern or a list.

## Decorators

The recommended way to give tags their settings. A decorator is a named bundle of settings, defined once and
attached to UDT members (every instance in the controller) or to tag paths:

```toml
[decorator.temperature]
units   = "°C"
rate_ms = 1000

[decorator.speed]
units = "rpm"
min   = 0
max   = 3000

[decorator.setpoint]
writable = true

[decorator.fast]
rate_ms = 250

[plc.PLC1.udt.MotorData]              # every MotorData member Temp and SpeedSP, wherever the UDT is used
Temp    = "temperature"
SpeedSP = { use = ["speed", "setpoint"], description = "Motor speed setpoint" }

[plc.PLC1.udt.PumpData]
Motor = "fast"                        # everything under Motor polled at 250 ms, except Temp (1000 ms)

[plc.PLC1.tags]
Pump1 = "fast"                        # a base tag
TankLevel = "temperature"             # an array: every element too
"Pumps[2].Motor.SpeedSP" = { max = 1500 }   # one element; "Pumps.Motor.SpeedSP" would be every element
"Program:Main.StatusWord" = { bits = { EStop = 0, DoorOpen = 1 } }
```

- **Fields**: `units`, `min`, `max`, `deadband`, `writable`, `rate_ms`, `description`, `bits`, `together`,
  `always` (see Rules for what each does). Unknown keys are logged and ignored.
- **An entry** is `"name"`, `["name", ...]` or `{ use = "name" | [...], <fields> }`. Decorators apply in list
  order (a later one wins), then the entry's own fields win over its decorators. A decorator name that is not
  defined is an error at startup, naming the place in the file.
- **`[plc.P.udt.UDT]`** applies to that member in every instance of the UDT: any tag, any array element, nested
  at any depth, program scopes too. UDT and member names ignore case. UDT types come from the controller, so
  these apply once the PLC is connected (and again after every tag table reload); until then only
  `[plc.P.tags]` entries and rules apply.
- **`[plc.P.tags]`** keys are tag paths: `Pump1`, `Program:Main.StatusWord`, `Pumps[2].Motor.SpeedSP`. Case and
  index spelling are ignored. A key with indexes applies to that element; the same key without them
  (`Pumps.Motor.SpeedSP`) applies to every element.
- **Closest wins.** `rate_ms` and `together` pass down from a struct or array to everything under it, and the
  setting closest to the tag wins. The other fields describe one value and never pass down to members, so a
  writable struct does not make its members writable. An array element does take its array's fields
  (`TankLevel[3]` is in °C).
- **At one node**, a `[tags]` key with indexes wins over one without, which wins over the `[udt]` entry.
- **Bits**: `X.3` takes `writable` from `X` unless set for the bit itself; bit names come from `X`'s `bits`.
  Names set by a `[udt]` entry resolve once the PLC connects; subscriptions made before then move to the bit.
- **`rate_ms`** works like a poll group (tier 1 only); `/stats` and info name it after the decorator that set
  it, or `"tag"` when set in the entry itself. Tags with the same name share the stats entry.
- **`always`** on a `[tags]` key reads that tag (every element for a key without indexes, such as
  `Pumps.Motor.Alarm`); on a `[udt]` member it reads every instance. Both expand once the controller's types
  are known.
- Fields still unset after the decorators come from the rules below, then the rate from the poll groups.


## Rules

The fallback to decorators, and how 0.3 configs set things: match patterns, read after the decorators.

```toml
[[plc.PLC1.rule]]
match    = "Bench.SpeedSP"
writable = true        # a setpoint: writes also need a token write pattern
min      = 0
max      = 1800
units    = "rpm"
description = "Spindle speed setpoint"   # else the controller's description, when ciplink can read it

[[plc.PLC1.rule]]
match    = "Bench.Speed"
deadband = 0.5         # changes smaller than this (vs the last value sent) are not sent

[[plc.PLC1.rule]]
match    = "Bench.StatusWord"
always   = true        # read at tier 1 even with no subscribers (alarms, logging); literal names only
bits     = { EStop = 0, DoorOpen = 1, Fault = 2 }   # Bench.StatusWord.EStop is Bench.StatusWord.0

[[plc.PLC1.rule]]
match    = "Bench.Recipe"
together = true        # members of this struct are always read in one read: no torn values across scans
```

- Several rules can match a tag. For each field, the first rule in the file that sets it wins, so put
  specific rules first. A decorator setting wins over any rule.
- A bit `X.<n>` takes only `writable` from `X`'s rules; `min`, `max`, `units`, `deadband`, `bits` never
  apply to a bit.
- Bit names (`X.EStop`) work wherever a tag name does (sub, write, momentary). Values and acks are keyed by
  the name exactly as the client sent it. An unknown name reads as `missing`.
- Unknown keys are ignored.

## Poll groups

The fallback to `rate_ms` in decorators: a tag with a decorator rate ignores the groups.

```toml
[[plc.PLC1.group]]
name    = "fast"
rate_ms = 50
match   = ["Bench.Axis.Position", "Bench.Axis.Velocity"]

[[plc.PLC1.group]]
name    = "slow"
rate_ms = 2000
match   = ["Tank[*].Temp"]
```

A group sets the poll rate of a tag **only while it is at tier 1** (on a loaded page, or `always`): polling a
tag nobody looks at faster is wasted. At tier 2 or 3 the group is ignored. The first matching group wins;
tags in no group are read every `cycle_ms`. The loop ticks at the smallest rate among `cycle_ms` and the
groups that have tier-1 tags, and each tick plans what is due together (a group tag due with the cycle's tags
shares their packets). `/stats`
shows `groups: {name: {rate_ms, tags, last_period_ms}}` per PLC: `tags` is 0 while no page shows them.

## Writes

Checked in this order, before anything is sent to the PLC; a rejected write's ack carries `kind`:

| check | kind |
|---|---|
| the name qualifies (no `{n}` element count, not a whole array: write `X[0]`) and the message is well formed (a `value`) | `bad_request` |
| a token write pattern matches (as sent, or after bit-name resolution) | `not_allowed` |
| the tag's settings (decorators, else rules) say `writable = true` | `not_writable` |
| numbers (also inside lists and dicts) are within the written path's own `min`/`max` | `out_of_range` |
| type and size, checked by ciplink per tag, nothing sent | `bad_value` |

The PLC thread runs queued writes between the packets of a cycle (a write waits about one packet, not a
whole cycle), then reads the written tag back (a bit: its word) and publishes it. The ack is
`{"op":"ack","id":N,"ok":true,"error":null,"kind":null,"value":<read-back>}`. A write while the PLC is not
connected fails at once with `refused`; a connection lost during the write gives `comm`. Writes are never
retried. Every attempt, allowed or not, is one JSON line in `audit_log` (`time`, `token`, `tag`, `old`,
`value`, `ok`, `error`, `kind`, and `momentary` for buttons), written by a background thread.

## Momentary buttons

`{"op":"momentary","id":N,"tag":"Bench.StartPB","action":"press"|"hold"|"release"}`, for BOOL tags and bits,
with the same checks as a write. `press` writes true and `release` false, each acked like a write. While the
button is held the client sends `hold` every 300 ms (no ack). With no `press` or `hold` for
`momentary_timeout_ms`, the server writes false itself (`/stats` `momentary_timeouts`), and a closed
connection releases everything it held, also when the server shuts down. A release that fails because the
PLC is not reachable is written again when the PLC connects, and one refused while it stays connected (a
tag table reload, a busy controller) is written again every half second until it goes through. So a lost tab, a crashed browser or a cut cable
never leaves a jog button pressed.

## Tag info

The first time a connection subscribes a name, the server sends its info before the values:

```json
{"op":"info","d":{"Bench.SpeedSP":{"type":"REAL","writable":true,"rate_ms":250,"group":null,
 "min":0,"max":1800,"units":"rpm","description":"Spindle speed setpoint"}}}
```

`type` comes from the controller (null until the PLC is connected), `writable` is true only when the settings
say so and this connection's token may write it, `dims` is set for a whole array, `bits` on a word with bit
names. Bits and bit names are `BOOL`. Info is sent again after a tag table reload and when a PLC connects.

## Codegen: the typed tag tree

```
ciplink-server types --url http://127.0.0.1:8765 --token T --out src/plc.ts
```

reads `GET /tags` from a running server (real or `--mock`) and writes a TypeScript module: one interface per
UDT, a `PLC1Tags` interface of the controller and `Program:` scopes, and `export const PLC1 = tagTree<PLC1Tags>(...)`.

```ts
import { PLC1 } from "./plc";
<TagValue name={PLC1.Tank[2].Level} />          // "Tank[2].Level"
<NumericInput name={PLC1.Bench.SpeedSP} />       // compiles only if its settings make it writable
<TagLamp name={PLC1.Bench.StatusWord.EStop} />   // bit names from the settings; .bit(3) for any bit
```

Leaves are `TagRef<number|boolean|string, W>`, with `W` true where the settings make the path writable (the
server's own resolution of decorators and rules, from `/tags`), so
`useWriteTag`, `NumericInput` and `MomentaryButton` reject read-only tags at compile time. Arrays are
`TagArray<T, N>` with a literal `length`, not refs: a bare array name reads and writes only its first
element, so use `Trend[0]`. The header gives the tag table version: run it again after a
download and let `tsc` show what changed. With one `--plc` (or none) names are unqualified; with several,
one tree per PLC with qualified names. `--format names` writes the 0.2 union `type TagName = "..." | ...`.

## Protocol (v1)

JSON messages over `ws://host:port/ws`. Every 0.3 addition is optional, so 0.2 clients keep working.

| op | dir | fields |
|---|---|---|
| `hello` | c→s | `v: 1`, `token`; must be first |
| `welcome` | s→c | `v`, `plcs: {PLC: state}`, `write` (the token has write patterns), `features: ["info","momentary","readback","errors"]` |
| `sub` | c→s | `id`, `tags: [...]`, `tier` (1-3, default 1), `page`; with `page` and no `tags`: that page's learned tags. Reusing an id replaces it |
| `unsub` | c→s | `id` |
| `info` | s→c | `d: {name: info}` (see Tag info) |
| `values` | s→c | `d: {name: [value, quality, t, error]}`: changes only; after a `sub`, the cached values |
| `write` | c→s | `id`, `tag`, `value` |
| `momentary` | c→s | `id`, `tag`, `action: press / hold / release` |
| `ack` | s→c | `id`, `ok`, `error`; for write and momentary also `kind` and `value` (the read-back) |
| `status` | s→c | `plcs: {PLC: "connecting" / "connected" / "disconnected"}` |
| `meta` | s→c | `plc`: its tag table was reloaded (online edit, download): fetch `/tags` again |
| `error` | s→c | `id`, `error`: a bad request (`id` null when unknown) |

- A bad token, a first message that is not `hello`, or another protocol version: closed with code **4401**.
- `quality`: `good`; `missing` (no such tag, or not readable from outside: value null); `bad` (the read
  failed: the **last value is kept**); `stale` (PLC disconnected: last value kept). `error` is null when good,
  else `{"kind": "...", "message": "..."}` with ciplink's kinds (`not_found`, `access`, `comm`, ...).
- Values: structs are objects, arrays lists, bytes hex strings, NaN and infinities the strings `"NaN"`,
  `"Infinity"`, `"-Infinity"`. `t` is ms since the epoch. A numeric change below the tag's `deadband` is not sent.
- Writes and reconnects: see Writes. Reconnects back off 1, 2, 5, then every 10 s.

The conformance suite of ciplink-tagserver (`tests/conformance/`) checks a server against this table over a real
WebSocket: `pytest tests/conformance --url http://host:8765 --token T --viewer-token V` against
`ciplink-server run --config examples/bench/tagserver.toml --mock`.

## Tiers and pages

A poll costs about 12 ms per packet plus 1.35 ms per read, so the server reads only what is on screen
every cycle:

| tier | read |
|---|---|
| 1 | every cycle (or its poll group's rate): what is on screen |
| 2 | round robin, each tag about every `tier2_period_s`: what is likely next |
| 3 | never: accepted and kept, not polled |

A tag's tier is the lowest among its subscriptions. A tag new at tier 2 is read at the next tick, then in its
slice. When its last tier-1 subscription ends it is read at tier 2 for `grace_s` more, so going back to a page
finds fresh values, then it drops out (or to tier 3).

**Pages.** A tier-1 `sub` carrying `"page": "/line1"` (the client's current route) teaches the server that
page's tags; it keeps the union per page in `pages_file` (saved a moment after a change, by an atomic
rename, and loaded at startup). A `sub` with a `page` and no `tags` subscribes the tags learned for that
page, at its `tier` (2 for a link to it); it is empty until the page has been visited, and follows what the
page learns. Its values are keyed by the plain tag names with one PLC, else by qualified names.

Known limits: a page's learned list only grows (a tag removed from a page, or deleted from the PLC, stays
listed until you edit or delete `pages_file`), and a tier-1 subscription re-sent after the route changed
(say, a component that stays mounted across pages) teaches the new page its tags too.

**Read planner.** Members of one struct can be read through one read of that struct and sliced out:
for `Line1.Motor.Speed` and `Line1.Motor.Current`, `Line1.Motor` is read once. Two or more elements of a
1-D atomic array (`Trend[3]`, `Trend[4]`, `Trend[7]`) can become one ranged read `Trend[3]{5}`. An extra
packet costs far more than a few reads, so the planner estimates each read's request and reply bytes and
takes groups best first, each only if it adds at most 450 reply bytes per read saved and the cycle's
estimated packet count stays what plain reads would take. A `together` rule forces its struct whole
whatever the cost (if it fits a packet). Never grouped: bit access, element counts, whole arrays, strings,
BOOL arrays, and AOIs that cannot be read whole. If a struct read fails, its members are read one by one
in the same cycle, and the struct is tried whole again after 60 s or a reload (`group_fallbacks`).
`planner = false` turns it off.

## HTTP

- `GET /health`: per PLC `state`, `last_cycle_ms`, `last_ok_ts`, `reconnects`, `reloads`.
- `GET /stats`: `sessions`, `writes`, `write_rejects`, `momentary_timeouts`, and per PLC `reads_per_cycle`,
  `tags_per_cycle`, `last_cycle_ms`, `cycle_ms`, `overruns`, `subscriptions`, `tier1`, `tier2`, `tier3`,
  `group_fallbacks` and `groups`.
- `GET /tags?plc=NAME` with `Authorization: Bearer <secret>`: `{plc, state, version, tags: [{name, type,
  dims?, aoi_readable?}], types: {UDT: {members: {m: {type, dims?}}}}, rules, groups, decorators, udt,
  tag_settings}` (`tag_settings` is the PLC's `[plc.P.tags]` table). Strings show as type
  `STRING`. `plc` may be left out with one PLC. CORS allows GET from any origin (the TagBrowser fetches it).

## Mock mode

`--mock` replaces every PLC driver with a simulation of the tags in that PLC's `mock_tags` file, either the
0.2 flat `{"Line1.Speed": "REAL"}` or structured:

```json
{"types": {"TankData": {"Level": "REAL", "Temp": "REAL", "Valve": "BOOL"}},
 "tags":  {"Tank": "TankData[4]", "Trend": "REAL[16]", "Bench": "BenchData", "Program:Bench.Mode": "DINT"}}
```

Types are `NAME` or `NAME[n]`. Reads support members, elements, ranges, bits and whole structs, so the planner
runs as on a PLC. Values are shaped by the name: `temp` 20-90, `level` 0-100, `position` ramps, `count`
counts, words carry a few toggling bits, `speed` follows its `SpeedSP` while a sibling `Running` is true,
`StartPB`/`StopPB` set `Running`, and written values hold. Writes are type-checked like ciplink's. Unknown
names are `missing`. `dump-tags` writes a flat file from a real PLC's tag list.

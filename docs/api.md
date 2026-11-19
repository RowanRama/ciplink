# Other languages

Every binding calls the same Rust core, so the guides apply to all of them. This page says where each binding's full
API is documented and how its calls map to the others.

| Language | Package | API documentation |
|---|---|---|
| Rust | [`ciplink`](https://crates.io/crates/ciplink), [`ciplink-server`](https://crates.io/crates/ciplink-server) | [docs.rs/ciplink](https://docs.rs/ciplink), [docs.rs/ciplink-server](https://docs.rs/ciplink-server) |
| C# | [`Ciplink`](https://www.nuget.org/packages/Ciplink) on NuGet | XML documentation in the package (shown by IntelliSense) |
| C++ | `ciplink.hpp`, header-only C++17 | the comments in [`ciplink.hpp`](https://github.com/RowanRama/ciplink/blob/main/bindings/cpp/include/ciplink.hpp) |
| C | `ciplink.h` and the libraries in the `ciplink-ffi` archives of each [release](https://github.com/RowanRama/ciplink/releases) | the comments in [`ciplink.h`](https://github.com/RowanRama/ciplink/blob/main/crates/ciplink-ffi/include/ciplink.h) |
| Python | [`ciplink`](https://pypi.org/project/ciplink/) on PyPI | [Python API](api-python.md) |

## Names across languages

| Python | Rust | C# | C++ | C |
|---|---|---|---|---|
| `LogixDriver(path, **options)` | `LogixDriver::new(path, LogixOptions)` | `new LogixDriver(path, LogixOptions)` | `ciplink::Logix(path, options_json)` | `ciplink_logix_new` |
| `SLCDriver` | `SlcDriver` | `SlcDriver` | `ciplink::Slc` | `ciplink_slc_new` |
| `CIPDriver` | `CipDriver` | `CipDriver` | `ciplink::Cip` | `ciplink_cip_new` |
| `ModbusDriver(path, map_file)` | `ModbusDriver::new(path, ModbusOptions)` | `new ModbusDriver(path, ModbusOptions)` | `ciplink::Modbus(path, options_json)` | `ciplink_modbus_new` (see [Modbus](#modbus-c-c-and-c)) |
| `S7PlusDriver(path, **options)` | `S7PlusDriver::new(path, S7PlusOptions)` | `new S7PlusDriver(path, S7PlusOptions)` | `ciplink::S7Plus(path, options_json)` | `ciplink_s7plus_new` (see [S7comm-plus](#s7comm-plus-c-c-and-c)) |
| `open()`, `close()` | `open()`, `close()` | `Open()`, `Close()` | `open()`, `close()` | `ciplink_open`, `ciplink_close` |
| `read(*tags)` | `read(&[tags])` | `Read(params tags)` | `read({tags})`, `read_tag` | `ciplink_read` |
| `write(*(tag, value))` | `write(&[(tag, Value)])` | `Write(params (tag, value))` | `write({{tag, value}})`, `write_tag` | `ciplink_write` |
| `tags`, `data_types`, `info` | `tags()`, `data_types()`, `get_plc_info()` | `Tags()`, `DataTypes()`, `Info()` | `tags_json()`, `data_types_json()`, `info_json()` | `ciplink_tags`, `ciplink_data_types`, `ciplink_info` |
| `get_tag_list(program)` | `get_tag_list(program, cache, filter)` | `TagList(program)` | `tag_list_json(program)` | `ciplink_tag_list` |
| `get_tag_info(name)` | `get_tag_info(name)` | `TagInfo(name)` | `tag_info_json(name)` | `ciplink_tag_info` |
| `get_tag_descriptions(*tags)` | `get_tag_descriptions(&[tags], language, encoding)` | `GetTagDescriptions(tags)` | `get_tag_descriptions({tags})` | `ciplink_get_tag_descriptions` |
| `trend(*tags, period_ms=)` | `trend(&[tags], TrendOptions)` | `Trend(tags, TrendOptions)` | `trend({tags}, period_ms)` | `ciplink_trend_start` |
| `generic_message(...)` | `generic_message(&GenericMessage)` | `GenericMessage(Message)` | `generic_message(Message)` | `ciplink_generic_message` |
| `CIPDriver.discover()` | `CipDriver::discover(broadcast)` | `CipDriver.Discover()` | `ciplink::discover()` | `ciplink_discover` |
| `get_ports(route)` | `ports_at(route)` | `GetPorts(route)` | `get_ports(route)` | `ciplink_get_ports` |
| `browse_port(route, port)`, `iter_port` | `browse_port(...)`, `scan_port(...)` | `BrowsePort`, `ScanPort` | `browse_port`, `scan_port` | `ciplink_browse_port`, `ciplink_scan_port` |
| `get_app(route)` | `app_at(route)` | `GetApp(route)` | `get_app(route)` | `ciplink_get_app` |
| `ciplink.server.TagServer` | `ciplink_server::ServerHandle` | `TagServer` | `ciplink::Server` | `ciplink_server_start` |
| `ciplink.Adapter(inputs=..., ...)` | `adapter::Adapter::start(AdapterConfig)` | `new Adapter(AdapterConfig)` | `ciplink::Adapter(AdapterConfig)` | `ciplink_adapter_start(config_json)` |
| `next_event(timeout)` | `next_event(Some(timeout))` | `NextEvent(timeout)` | `next_event(timeout)` | `ciplink_adapter_next_event` |

In C# every driver is thread-safe and `IDisposable`; `ReadAsync` and `WriteAsync` queue a read or write and return a
task that the driver completes, without a thread waiting (see [below](#async-subscriptions-and-connection-events-c)). In C++ the classes are movable RAII wrappers that throw `ciplink::Error`; `handle()` gives the raw C handle for
calls the wrapper doesn't cover.

## Using the C library

Link against the shared library (`ciplink.dll` with its import library `ciplink.dll.lib` on Windows,
`libciplink.so` on Linux, `libciplink.dylib` on macOS) or the static one (`ciplink.lib`, `libciplink.a`), and
include `ciplink.h`; for C++ also add `ciplink.hpp`. A CMake project can follow
[`bindings/cpp/CMakeLists.txt`](https://github.com/RowanRama/ciplink/blob/main/bindings/cpp/CMakeLists.txt).

Rules of the C ABI:

- Every function returns a `CiplinkStatus`; 0 (`CIPLINK_STATUS_OK`) is success.
- Handles (`CiplinkDriver`, `CiplinkRequest`, `CiplinkSubscription`, `CiplinkTrend`, `CiplinkServer`,
  `CiplinkAdapter`) are opaque. Free each with its own function: `ciplink_driver_free`, `ciplink_request_free`,
  `ciplink_subscription_free`, `ciplink_trend_free`, `ciplink_server_stop`, `ciplink_adapter_free`.
- A driver handle can be used from several threads at once. A Logix or SLC driver queues every call for its own
  session thread, which does all of its I/O and sends the reads queued together as one read.
- Values cross as UTF-8 JSON (see [Values and results](values.md)), and every returned string is freed with
  `ciplink_string_free`.
- Per-tag failures are data in the result JSON, not a failed status.

## Async calls, subscriptions and connection events (C and C++)

A Logix or SLC driver keeps its link up by itself. After an open link is lost it reconnects in the background,
first after 100 ms, then doubling the wait up to 10 s, until it is back or `ciplink_close` is called. The request
that saw the loss returns its error, and a write is never sent again. While the driver reconnects, reads, writes and
subscription polls fail at once with a `CIPLINK_STATUS_COMM` error `not connected, reconnecting: <cause>`. An idle
link gets a small keep-alive request every 30 s. The options JSON of `ciplink_logix_new` and `ciplink_slc_new` sets
this up:

| Key | Default | Meaning |
|---|---|---|
| `reconnect` | `true` | reconnect in the background after an open link is lost |
| `reconnect_min` | `0.1` | seconds before the first attempt, doubled after each failed one |
| `reconnect_max` | `10` | longest wait between attempts, in seconds |
| `keep_alive` | `30` | seconds without traffic before a keep-alive request; `null` for never |

| C | C++ | What it does |
|---|---|---|
| `ciplink_read_async`, `ciplink_write_async` | `read_async({tags})`, `write_async({{tag, value}})` | queue a read or write and return at once; C calls `done(user, status, json)` once, C++ returns a `std::future<std::vector<Tag>>` |
| `ciplink_request_done`, `ciplink_request_wait`, `ciplink_request_free` | `std::future` | poll, wait (with a timeout in ms, negative for none; `CIPLINK_STATUS_TIMEOUT` leaves it pending) and free a request |
| `ciplink_subscribe`, `ciplink_subscription_free` | `subscribe({tags}, on_changes, interval_s, deadband)` returning a `ciplink::Subscription` | read tags every interval and pass the ones that changed |
| `ciplink_set_connection_callback` | `on_connection(f)` | be told `connected`, `disconnected` (with the error) and `reconnecting` (attempt, delay) |
| `ciplink_connection_state` | `connection_state()` | closed, connected or reconnecting; never blocks |

**Where callbacks run.** Every callback of a driver (`done`, `on_changes`, the connection callback, and the C++
functions behind them) runs on that driver's own callback thread. They run one at a time, in order, never on the
thread that made the call and never on the thread that does the I/O. A callback may call ciplink, blocking calls on
the same driver included. It must not block for long, because the driver's other callbacks wait for it. In C it must
not unwind. In C++ an exception thrown from it is caught and dropped. A C++ future can be waited on from any thread,
inside a callback too.

**Requests.** `done` and `out_request` may each be NULL. If the call returns an error, nothing was queued and `done`
is never called. Otherwise `done` is called exactly once, and it can run before `ciplink_read_async` returns (a
request that fails at once), so set up `user` first. A request handle can be freed at any time: the request still
runs and `done` still fires.

```c
static void on_done(void *user, CiplinkStatus status, const char *json) {
    /* status OK: json is the result array; else json is the error message. Valid only during the call. */
}

const char *tags[] = {"Counter", "Setpoint"};
CiplinkRequest *req = NULL;
ciplink_read_async(plc, tags, 2, on_done, my_state, &req);
char *json = NULL;
if (ciplink_request_wait(req, 1000, &json) == CIPLINK_STATUS_OK) {
    /* ... */
    ciplink_string_free(json);
}
ciplink_request_free(req);
```

**Subscriptions.** The options JSON is `{"interval": seconds, "deadband": number | null}`, with an interval of 1 s
by default. The first call has every tag. Later calls have the tags whose value or error changed. A failed read, or
a lost link, shows up as each tag's error with kind `comm`. Subscriptions are read in the same queue as everything
else, so their reads are packed with other callers' reads. Once `ciplink_subscription_free` returns (or a C++
`Subscription` is destroyed or closed), the callback is not running and will not run again, so `user` can be freed.

```cpp
ciplink::Logix plc("192.168.1.10/0");
plc.on_connection([](const ciplink::ConnectionEvent& e) { std::cerr << e.event << " " << e.error << "\n"; });
plc.open();
auto sub = plc.subscribe({"Counter", "Level"}, [](const std::vector<ciplink::Tag>& changed) {
    for (auto& t : changed) std::cout << t.tag << "\n";
}, 0.5);
std::future<std::vector<ciplink::Tag>> f = plc.read_async({"Setpoint"});
double setpoint = f.get().at(0).value.as_double();
```

**Shutdown.** `ciplink_close` stops reconnecting and ends the subscriptions. Requests still queued fail with
`driver closed` and their `done` fires. The request in flight finishes first. `ciplink_driver_free` (C++: the
destructor) does the same. Once it returns, no callback of that driver runs again.

## Async, subscriptions and connection events (C#)

The C# driver works the same way as the C one. Reconnecting and the keep-alive are set on `DriverOptions` (and so on
`LogixOptions`):

| Property | Default | C key |
|---|---|---|
| `Reconnect` | `true` | `reconnect` |
| `ReconnectMin` | 100 ms | `reconnect_min` |
| `ReconnectMax` | 10 s | `reconnect_max` |
| `KeepAlive` | 30 s, `null` for never | `keep_alive` |

| C# | What it does |
|---|---|
| `ReadAsync(params tags)`, `ReadAsync(tags, CancellationToken)` | queue a read; reads queued together, from any thread or subscription, go out as one read |
| `WriteAsync(params (tag, value))`, `WriteAsync(items, CancellationToken)` | queue a write; writes run in the order queued and are never sent twice |
| `Subscribe(tags, interval, deadband, changed)` | returns a `Subscription`: the `Changed` event and `await foreach` give the tags that changed |
| `ConnectionChanged` event | `ConnectionEventArgs` with `Event` ("connected", "disconnected", "reconnecting"), `Error`, `Attempt`, `Delay` |
| `ConnectionState` | `Closed`, `Connected` or `Reconnecting`; never blocks |

**Tasks.** `ReadAsync` and `WriteAsync` hold no thread while they wait. The native callback completes a
`TaskCompletionSource` created with `RunContinuationsAsynchronously`, so your `await` continues on the thread pool and
never on the driver's callback thread. A failed call is a faulted task with a `CiplinkException`, such as
`Comm` "not connected, reconnecting: ..." while the driver reconnects, or "driver closed" when `Close` or `Dispose`
ran while it was queued. A `CancellationToken` cancels the task only. The request is already queued and still runs,
so a cancelled write may still be written.

**Subscriptions.** The first delivery has every tag. After that you get only the tags whose value or error changed.
A failed read, or a lost link, shows up as each tag's `Error` with `ErrorKind` "comm". Pass `changed:` to attach a
handler before the first poll, because a handler added to `Changed` later may miss the first values. `await foreach`
gives every tag that changed since the previous item, with the latest result of each, so a slow consumer never
falls behind. It ends when the subscription is disposed or the driver is closed or disposed. Dispose the
subscription to unsubscribe. Once `Dispose` returns, `Changed` is not running and will not be raised again.

**Callbacks.** `Changed` and `ConnectionChanged` run on the driver's callback thread, one at a time. Keep them short.
They may call the driver, blocking calls included. An exception a handler throws is written to
`System.Diagnostics.Trace` and dropped.

```csharp
using var plc = new LogixDriver("192.168.1.10/0", new LogixOptions { KeepAlive = TimeSpan.FromSeconds(15) });
plc.ConnectionChanged += (_, e) => Console.WriteLine(e);   // connected, disconnected: ..., reconnecting (attempt 1, ...)
plc.Open();

IReadOnlyList<Tag>[] results = await Task.WhenAll(plc.ReadAsync("Counter"), plc.ReadAsync("Level", "Setpoint"));
await plc.WriteAsync(("Setpoint", 75.5));

using Subscription sub = plc.Subscribe(new[] { "Counter", "Level" }, TimeSpan.FromMilliseconds(500), deadband: 0.1);
await foreach (IReadOnlyList<Tag> changed in sub)
    foreach (Tag t in changed)
        Console.WriteLine(t.IsOk ? $"{t.Name} = {t.Value}" : $"{t.Name}: {t.Error}");
```

## Modbus (C, C++ and C#)

A Modbus driver is one more driver handle. It takes the same read, write, async, subscription and connection calls
as a Logix driver, with the same queue, reconnect and callback rules as above. The CIP calls (generic messages,
identity, browsing, connection size, ...) return `CIPLINK_STATUS_UNSUPPORTED` (C++ `ciplink::Error`, C#
`CiplinkException` with `Unsupported`).

**Paths.** `tcp://host[:port][?unit=N]` is Modbus TCP. `rtu://PORT[?baud=..&parity=..&data=..&stop=..&unit=N]` is
RTU on a serial port, e.g. `rtu://COM3?baud=19200&parity=E` or `rtu:///dev/ttyUSB0?baud=9600`.
`rtu+tcp://host[:port][?unit=N]` is RTU frames over TCP, for serial-to-Ethernet gateways in transparent mode. The
port is 502 and the unit 1 unless given.

**Names.** A map file gives the tags their names, types and descriptions. Anything not in it is a plain address,
`area offset ["." bit] [":" type [":" order]] ["{" count "}"] ["@" unit]`, with the area `co` (coils), `di`
(discrete inputs), `hr` (holding registers) or `ir` (input registers). Addresses are **0-based protocol
addresses**: Modicon holding register 40001 is `hr0`. Examples: `hr100:float32`, `hr100:float32:cdab`,
`hr200:int16{10}`, `hr300:string{20}`, `hr10.4` (bit 4 of holding register 10), `co0{16}`, `di7@3` (unit 3).

**Map file.** CSV with a header row, one row per tag. Only `name`, `area`, `address` and `type` are required; an
empty cell takes the default.

```text
# Pump skid. Addresses are 0-based: holding register 40001 is "holding,0".
name,area,address,type,count,order,unit,scale,offset,units,description,writable
Pump1_Speed,holding,0,float32,,CDAB,,,,rpm,Pump 1 speed setpoint,
Pump1_Run,coil,0,bool,,,,,,,Pump 1 run command,
Pump1_Fault,discrete,3,bool,,,,,,,"Pump 1 fault, any cause",
Tank_Level,input,10,int16,,,,0.1,,%,Tank level (0.1 % per count),
Totals,holding,100,uint32,4,,,,,m3,Daily totals of the last 4 days,
Recipe,holding,200,string,16,,,,,,Active recipe name,
Drive_Status,holding,300,uint16,,,,,,,Drive status word,false
Horn,holding,301.4,bool,,,,,,,Horn bit in the control word,
Valve2_Open,coil,10,bool,,,2,,,,Valve on gateway unit 2,
```

| Column | Meaning |
|---|---|
| `area` | `coil`, `discrete`, `holding` or `input` |
| `address` | 0-based; `301.4` is bit 4 of a holding or input register |
| `type` | `bool`, `int16`, `uint16`, `int32`, `uint32`, `int64`, `uint64`, `float32`, `float64`, `string` |
| `count` | array elements, or a string's length in characters |
| `order` | `ABCD` (Modbus standard, big-endian), `CDAB` (word swap), `BADC` (byte swap), `DCBA`; empty: the driver's `word_order` |
| `unit` | unit id of this tag; empty: the path's |
| `scale`, `offset` | read value = raw x scale + offset (reported as LREAL); writes divide it back out |
| `writable` | `false` makes the tag read-only (discrete inputs and input registers always are) |

Reads queued together are merged into the fewest requests: tags of the same unit and area whose gap is at most
`max_gap` registers or bits go in one request, up to `max_registers` (125) or `max_bits` (2000). Writes use FC05 and
FC06 for one coil or register, FC15 and FC16 for more (always with `write_multiple`), and FC22 (mask write) for a
bit of a holding register. A Modbus exception is the tag's error; the reply timeout is 1 s by default. The keep-alive
(30 s over TCP, off on a serial port) sends FC08, or reads `keep_alive_address` for devices that ignore FC08.

| Option (C key) | C# `ModbusOptions` | Default |
|---|---|---|
| `map_file` (or `map_csv`, the CSV text) | `MapFile` | none: plain addresses only |
| `socket_timeout` | `SocketTimeout` | 1 s |
| `max_registers`, `max_bits` | `MaxRegisters`, `MaxBits` | 125, 2000 |
| `max_gap` | `MaxGap` | 8 |
| `word_order` | `WordOrder` | `"ABCD"` |
| `write_multiple` | `WriteMultiple` | false |
| `keep_alive_address` | `KeepAliveAddress` | none (FC08) |
| `keep_alive` | `KeepAlive` (null: the scheme's default, `TimeSpan.Zero`: off) | 30 s over TCP, off for `rtu://` |
| `reconnect`, `reconnect_min`, `reconnect_max` | `Reconnect`, `ReconnectMin`, `ReconnectMax` | as above |

| C | C++ `ciplink::Modbus` | C# `ModbusDriver` | What it does |
|---|---|---|---|
| `ciplink_modbus_device_info(h, unit, &json)` | `device_info(unit)` | `DeviceInfo(unit)` | Read Device Identification (FC43/14): vendor_name, product_code, revision, ... |
| `ciplink_modbus_tags(h, &json)` | `tags()` | `Tags` | the map's rows: name, area, address, bit, type, cip_type, count, order, unit, scale, offset, units, description, writable |
| `ciplink_modbus_send_pdu(h, unit, pdu, len, &out, &out_len)` | `send_pdu(pdu, unit)` | `SendPdu(pdu, unit)` | one raw PDU (function code and data) for functions the driver does not wrap |

A negative `unit` in C (C++ and C#: no unit) means the path's unit.

```c
CiplinkDriver *mb = NULL;
ciplink_modbus_new("tcp://10.0.0.9?unit=1", "{\"map_file\": \"skid.csv\"}", &mb);
ciplink_open(mb);
const char *tags[] = {"Pump1_Speed", "Tank_Level", "hr40:uint16"};
char *json = NULL;
if (ciplink_read(mb, tags, 3, &json) == CIPLINK_STATUS_OK) {
    /* [{"tag":"Pump1_Speed","value":123.456,"type":"REAL","error":null}, ...] */
    ciplink_string_free(json);
}
ciplink_write(mb, "[[\"Pump1_Run\", true], [\"Horn\", true]]", &json);
ciplink_string_free(json);
ciplink_driver_free(mb);
```

```cpp
ciplink::Modbus mb("rtu+tcp://10.0.0.20:4001?unit=3", R"({"map_file": "skid.csv", "word_order": "CDAB"})");
mb.open();
ciplink::Tag speed = mb.read_tag("Pump1_Speed");
mb.write_tag("Pump1_Run", true);
ciplink::Value info = mb.device_info();          // {"vendor_name": ..., "product_code": ..., ...}
for (auto& row : mb.tags().as_array())
    std::cout << row["name"].as_string() << ": " << row["description"].as_string() << "\n";
auto sub = mb.subscribe({"Tank_Level", "Pump1_Fault"}, [](const std::vector<ciplink::Tag>& changed) { /* ... */ }, 0.5);
```

```csharp
using var mb = new ModbusDriver("tcp://10.0.0.9", new ModbusOptions { MapFile = "skid.csv", MaxGap = 0 });
mb.ConnectionChanged += (_, e) => Console.WriteLine(e);
mb.Open();
IReadOnlyList<Tag> r = await mb.ReadAsync("Pump1_Speed", "Totals", "ir0:int16{4}");
await mb.WriteAsync(("Pump1_Speed", 1450.0f), ("Valve2_Open", true));
JsonObject info = mb.DeviceInfo();
foreach (JsonNode? row in mb.Tags)
    Console.WriteLine($"{row!["name"]} ({row["units"]}): {row["description"]}");
```

## S7comm-plus (C, C++ and C#)

Siemens S7-1500 and S7-1200 CPUs with secure PG/HMI communication (TLS, firmware 2.9 and later) have a driver of
their own: `ciplink_s7plus_new` in C, `ciplink::S7Plus` in C++ and `S7PlusDriver` in C#. It runs on the same
session core as the Logix driver, so everything above applies: one handle shared by threads, merged reads (at most
the PLC's limit, usually 100 items, per request), async calls, subscriptions, connection events, reconnect and
keep-alive (every 15 s by default). Tag names are TIA style: `Line1.Conveyor.Speed`, `Line1.Items[3]`, and PLC
tags of the I, Q and M areas by their bare name (`StartButton`). Tag comments are not read, and the CIP-only calls
(generic messages, device browsing, trends, PLC time, connection size) return `CIPLINK_STATUS_UNSUPPORTED`.

Options (C keys; C# properties of `S7PlusOptions` in brackets):

| Key | Default | Meaning |
|---|---|---|
| `socket_timeout` (`SocketTimeout`) | `10` | seconds per connect, read and write; `null` blocks forever |
| `init_tags` (`InitTags`) | `true` | browse the symbol table on open; else on the first request that needs it |
| `tls_fingerprint` (`TlsFingerprint`) | `null` | SHA-256 of the PLC certificate to require, hex with or without `:`; a mismatch fails open with `CIPLINK_STATUS_COMM` |
| `keep_alive` (`KeepAlive`) | `15` | seconds without traffic before a keep-alive request; `null` for never |
| `reconnect`, `reconnect_min`, `reconnect_max` | as Logix | see the table above |

The certificate is not checked by default. To pin it, connect once, read the fingerprint, and pass it as
`tls_fingerprint` from then on.

| C | C++ | C# | What it does |
|---|---|---|---|
| `ciplink_tags` | `tags()` | `Tags()` | data blocks and I/Q/M tags by name (type, kind, dims, HMI flags); no I/O |
| `ciplink_data_types` | `data_types()` | `DataTypes()` | structure types by name, with their members |
| `ciplink_tag_list` (other arguments ignored) | `tag_list()` | `TagList()` | every symbol, flat: name, type, dims, access, crc, HMI flags |
| `ciplink_tag_info` | `tag_info(name)` | `TagInfo(name)` | one name resolved; an unknown name is `CIPLINK_STATUS_REQUEST` |
| `ciplink_get_plc_info` | `plc_info()` | `GetPlcInfo()` | name, order and serial number, firmware, TIA version, project, protection level, read/write limits |
| `ciplink_info` | | | `ciplink_get_plc_info` plus `fingerprint` |
| `ciplink_s7plus_fingerprint` | `fingerprint()` | `CertificateFingerprint` | `"AB:CD:..."` of the latest handshake, null before one |
| `ciplink_s7plus_refresh_tags` | `refresh_tags()` | `RefreshTags()` | browse again; true if the tags or types changed |

Values follow [Values and results](values.md): BYTE, WORD, DWORD and LWORD are unsigned integers, TIME and S5TIME
milliseconds, LTIME nanoseconds, the date and time types (DATE, TOD, DT, DTL, LDT) ISO 8601 strings, structures
objects and arrays arrays. A result's `type` is the S7 type name (`"WORD"`, `"DTL"`, `"REAL[50]"`).

```cpp
ciplink::S7Plus plc("192.168.0.10", "{\"tls_fingerprint\": \"AB:CD:...\"}");
plc.open();
auto r = plc.read({"Line1.Conveyor.Speed", "Line1.Items[3]", "StartButton"});
plc.write_tag("Line1.Recipe.Name", "Batch7");
auto sub = plc.subscribe({"Line1.Count"}, [](const std::vector<ciplink::Tag>& changed) {
    for (auto& t : changed) std::cout << t.tag << " = " << ciplink::to_json(t.value) << "\n";
}, 0.5);
```

```csharp
using var plc = new S7PlusDriver("192.168.0.10", new S7PlusOptions { InitTags = true });
plc.Open();
Console.WriteLine(plc.CertificateFingerprint);   // pin it with TlsFingerprint next time
IReadOnlyList<Tag> r = await plc.ReadAsync("Line1.Conveyor.Speed", "Line1.Stamp");
plc.Write(("Line1.Count", 42), ("Line1.Recipe.Speed", 2.5));
foreach (JsonNode? s in plc.TagList())
    Console.WriteLine($"{s!["name"]} {s["type"]}");
```

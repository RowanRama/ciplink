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

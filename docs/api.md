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

In C# every driver is thread-safe and `IDisposable`; `ReadAsync` and `WriteAsync` run a read or write on the thread
pool. In C++ the classes are movable RAII wrappers that throw `ciplink::Error`; `handle()` gives the raw C handle for
calls the wrapper doesn't cover.

## Using the C library

Link against the shared library (`ciplink.dll` with its import library `ciplink.dll.lib` on Windows,
`libciplink.so` on Linux, `libciplink.dylib` on macOS) or the static one (`ciplink.lib`, `libciplink.a`), and
include `ciplink.h`; for C++ also add `ciplink.hpp`. A CMake project can follow
[`bindings/cpp/CMakeLists.txt`](https://github.com/RowanRama/ciplink/blob/main/bindings/cpp/CMakeLists.txt).

Rules of the C ABI:

- Every function returns a `CiplinkStatus`; 0 (`CIPLINK_STATUS_OK`) is success.
- Handles (`CiplinkDriver`, `CiplinkTrend`, `CiplinkServer`, `CiplinkAdapter`) are opaque. Free each with its own
  function: `ciplink_driver_free`, `ciplink_trend_free`, `ciplink_server_stop`, `ciplink_adapter_free`.
- A driver handle can be used from several threads at once; calls are serialized inside the driver.
- Values cross as UTF-8 JSON (see [Values and results](values.md)), and every returned string is freed with
  `ciplink_string_free`.
- Per-tag failures are data in the result JSON, not a failed status.

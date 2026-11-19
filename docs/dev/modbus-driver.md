# Modbus driver: TCP, RTU and RTU over TCP on the session core

Status: phase 2 of adding Siemens, Modbus and OPC UA to ciplink. Branch `feature/modbus`, on top of
`feature/session-core`. Every step of the [checklist](#implementation-checklist) is implemented: the Rust core,
the simulator, the server, every binding and the user guide (`docs/modbus.md`). Where the implementation differs
from the first draft, *Changes made while implementing* says how and why. Not yet tried on a real Modbus device.

This page is for the engineers who build it. It is not part of the published wiki (`mkdocs.yml` excludes
`docs/dev/`). Read [session-core.md](session-core.md) first: the queue, the session thread, reconnect, keep-alive,
subscriptions and the callback rules are reused as they are and not repeated here.

## Decisions at a glance

| Topic | Decision |
|---|---|
| Shape | `ModbusDriver` is a thin struct around `Session<Modbus>`, as `LogixDriver` is around `Session<Logix>`. `Modbus` (crate-private) implements `Protocol`. Nothing in `session/` changes. |
| Paths | One scheme, required: `tcp://host[:port][?unit=N]`, `rtu://PORT[?baud=..&parity=..&data=..&stop=..&unit=N]`, `rtu+tcp://host[:port][?unit=N]`. Port 502 by default, unit 1 by default. |
| Tag names | From a **map file** (CSV, one row per tag, header row names the columns). Without a map, or for anything not in it, **plain addresses**: `hr100:float32`, `co5`, `ir10{4}`, `hr20.3`, `di7@2`. Addresses are **0-based** protocol addresses everywhere. |
| Values | Results use the existing `Value` variants and CIP type names (`INT`, `UINT`, `DINT`, `UDINT`, `LINT`, `ULINT`, `REAL`, `LREAL`, `BOOL`, `STRING`), so Python `Tag`, the server and every HMI client work unchanged. A tag with `scale` or `offset` reads as `LREAL`. |
| Word order | `ABCD` (Modbus standard, big-endian), `CDAB`, `BADC`, `DCBA`: two flags, swap bytes in each register and least significant register first. Per row in the map, per address after the type, driver default `word_order` (default `ABCD`). |
| Read merging | `merges_reads()` is true. One `Protocol::read` (one caller, or several merged by the session) is planned into the fewest requests: per unit and area, sorted by address, joined when the gap is at most `max_gap` (default 8) and the span fits `max_registers` (default 125) or `max_bits` (default 2000). |
| Bad address in a merged request | Exception 02 or 03 on a request that serves more than one tag: each of its tags is read again on its own, so one bad row never fails its neighbours. This is what makes merging across callers safe. |
| Writes | One request per item, in order, never merged. Coil: FC05 (one) / FC15 (several). Holding: FC06 (one register) / FC16 (several). A bit in a holding register: FC22 mask write **only**, never read-modify-write. `write_multiple` forces FC15/16. Discrete inputs, input registers and `writable = false` rows are refused locally, also by a plain address that overlaps such a row on the same unit and area. |
| Errors | Modbus exceptions become per-tag `TagError`s with `status = Some(code)`. Transport failures are `Error::Comm`. See [Errors](#errors). |
| Timeouts | `tcp`: a timeout fails the call (`Err(Comm)`) and drops the link, as Logix does, so the session reconnects. `rtu` and `rtu+tcp` (a bus behind a port): a timeout fails only that request's tags (kind `Comm`), the link stays, input already received is discarded before every request and drained after a failed one. |
| Keep-alive | FC08 sub-function 0000 (Return Query Data) to the default unit; **any** reply, exception included, proves the link. `keep_alive_address` reads that address instead. Default 30 s for `tcp://` and `rtu+tcp://`, off for `rtu://`. |
| Device info | `device_info(unit)`: FC43 / MEI 14 (Read Device Identification), basic then regular objects. A device without it gives the exception as an error. |
| Serial | `serialport` 4.x with `default-features = false` (no libudev). Always compiled, no cargo feature. RTU frames are found by length (from the function code), not by measuring 3.5-character silences; t3.5 is only kept as a minimum gap before each send. |
| Simulator | A separate `ModbusSim` in `crates/ciplink-sim/src/modbus.rs` (MBAP and RTU framing, four tables per unit, holes, faults, FC 1-6, 8, 15, 16, 22, 43/14), served over TCP or in memory; the binary takes `"kind": "modbus"` configs. |
| Bindings | Python `ciplink.ModbusDriver`, C `ciplink_modbus_new` plus the generic `ciplink_*` calls, C++ `ciplink::Modbus`, .NET `ModbusDriver` / `ModbusOptions`. |
| Server | `[plc.X] protocol = "modbus"`, `map_file = "pumps.csv"`, `[plc.X.modbus]` options. `ModbusPlc` serves the map's tags with their descriptions. |

## Module layout

```text
crates/ciplink/src/modbus/
  mod.rs        docs, pub use of the public types
  address.rs    Area, DataType, WordOrder, Address; the plain-address parser; resolving a name
                (map row, row[i], row.N, row[i].N, or a plain address) to a Target
  map.rs        TagMap, MapTag; the CSV reader (hand written, RFC 4180 quoting, no dependency)
  value.rs      registers/bits <-> Value: word order, scale/offset, strings, range checks (pure)
  pdu.rs        request builders and reply parsers for FC 1, 2, 3, 4, 5, 6, 8, 15, 16, 22, 43/14; exceptions (pure)
  frame.rs      MBAP header, RTU framing and CRC-16/MODBUS, reply length from the function code (pure)
  link.rs       Endpoint (the path parser), Link trait, ModbusConnector, the TCP and serial connectors
  plan.rs       the read planner: targets -> blocks (pure)
  driver.rs     Modbus (the state, impl Protocol), ModbusOptions, DeviceInfo, ModbusDriver
```

`lib.rs` gets `pub mod modbus;`. Everything is in new files except that line and one small refactor in
`transport.rs`: the TCP connect plus socket2 keep-alive moves into `pub(crate) fn tcp_stream(host, port, timeout) ->
Result<TcpStream>`, which `TcpTransport::connect` and the Modbus TCP connector both call (no behaviour change).

Pure modules (`address`, `map`, `value`, `pdu`, `frame`, `plan`) have no I/O and carry their unit tests with golden
bytes. Only `link.rs` and `driver.rs` touch a socket or a port.

## Paths

```text
tcp://host[:port][?unit=N]                                   Modbus TCP (MBAP), port 502
rtu://PORT[?baud=B&parity=N|E|O&data=7|8&stop=1|2&unit=N]   RTU on a serial port
rtu+tcp://host[:port][?unit=N]                               RTU frames over a TCP socket (serial device servers), port 502
```

- The scheme is required. A bare `host` is an error (`RequestError: modbus path needs tcp://, rtu:// or
  rtu+tcp://`), so a Logix path passed by mistake fails clearly.
- `PORT` is everything between `rtu://` and `?`: `rtu://COM3`, `rtu:///dev/ttyUSB0` (port `/dev/ttyUSB0`). `serialport`
  adds the `\\.\` prefix Windows needs for COM10 and up.
- Serial defaults are the Modbus spec's: 19200 baud, even parity, 8 data bits, 1 stop bit. Keys are
  case-insensitive; values: `parity` N, E or O; `data` 7 or 8; `stop` 1 or 2.
- `unit` (0 to 255) is the default unit (slave) id, used by every tag without a unit of its own. Default 1.
- Unit 0 on `rtu://` and `rtu+tcp://` is broadcast: writes are sent and succeed without a reply, reads are refused
  (`BadRequest`). On `tcp://` unit 0 is an ordinary unit id (many devices answer it).
- An unknown query key is an error. Host may be an IPv4 address or a name (resolved as `TcpTransport` does, IPv4).

```rust
/// Where a Modbus driver connects, parsed from its path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// Modbus TCP.
    Tcp { host: String, port: u16 },
    /// RTU on a serial port.
    Rtu { port: String, baud: u32, parity: Parity, data_bits: u8, stop_bits: u8 },
    /// RTU frames over TCP.
    RtuOverTcp { host: String, port: u16 },
}
pub enum Parity { None, Even, Odd }

impl Endpoint {
    /// The endpoint and the default unit of `path`.
    pub fn parse(path: &str) -> Result<(Endpoint, u8)>;
}
```

## Map file

CSV, UTF-8 (a BOM is skipped). The first non-comment line is the header. Columns are found by their header name
(case-insensitive, surrounding spaces trimmed), so their order is free, optional columns may be left out, and extra
columns (notes, PLC cross-references) are ignored.

| Column | Required | Values | Default |
|---|---|---|---|
| `name` | yes | `[A-Za-z_][A-Za-z0-9_]*`, dot-separated parts allowed (`Pump1.Speed`); no part may be all digits (`.3` is the bit syntax); unique ignoring case; must not parse as a plain address (`hr100` is refused) | |
| `area` | yes | `coil`, `discrete`, `holding`, `input` (or `co`, `di`, `hr`, `ir`) | |
| `address` | yes | 0-based protocol address `0`..`65535`; for a `bool` in `holding` or `input`: `register.bit`, bit `0`..`15` (`300.4`) | |
| `type` | yes | `bool`, `int16`, `uint16`, `int32`, `uint32`, `int64`, `uint64`, `float32`, `float64`, `string` | |
| `count` | no | array elements; for `string` the length in characters (bytes) | 1 (string: required) |
| `order` | no | `ABCD`, `CDAB`, `BADC`, `DCBA` | the driver's `word_order` |
| `unit` | no | `0`..`255` | the path's unit |
| `scale` | no | number; read value = raw x scale + offset | none |
| `offset` | no | number | none (0 when scale is set) |
| `units` | no | text (engineering units, `rpm`, `degC`) | empty |
| `description` | no | text | empty |
| `writable` | no | `true`/`false`, `yes`/`no`, `1`/`0` | true for `coil` and `holding`, false otherwise; `true` on `discrete`/`input` is an error |

Rules:

- Comma separated. If the header line has no comma but has a semicolon, the file is semicolon separated (Excel in
  many European locales). Fields may be quoted with `"`; `""` inside quotes is a quote. Quoted fields may hold the
  separator and line breaks.
- Lines whose first character is `#`, and blank lines, are skipped.
- `bool` is valid in every area; in `coil`/`discrete` the address has no bit, in `holding`/`input` it must have one,
  and a bit-in-register `bool` must have `count` 1. Every other type is valid in `holding` and `input` only.
- `scale`/`offset` are valid on numeric types only (not `bool`, not `string`).
- The tag must fit: `address + registers - 1 <= 65535` (bits: `address + count - 1`).
- Overlapping rows are allowed (an `int32` and the two `uint16` halves of it, a word and its bits).
- Every error names the file, the line and the column: `RequestError: pumps.csv line 7: type 'flaot32' is not one of
  bool, int16, ...`. Loading stops at the first error.

Example (`tools/sim/example_modbus_map.csv`, used by the tests and the docs):

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

```rust
/// The tags of a map file, in file order.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TagMap { /* IndexMap<lowercase name, MapTag> */ }

impl TagMap {
    /// Reads a map file; errors name the file and line.
    pub fn load(path: impl AsRef<Path>) -> Result<Self>;
    /// Parses map CSV text (errors name the line).
    pub fn from_csv(text: &str) -> Result<Self>;
    /// The tag of `name`, ignoring case.
    pub fn get(&self, name: &str) -> Option<&MapTag>;
    /// Every tag, in file order.
    pub fn tags(&self) -> impl Iterator<Item = &MapTag>;
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
}

/// One row of a map file.
#[derive(Clone, Debug, PartialEq)]
pub struct MapTag {
    pub name: String,
    pub area: Area,
    pub address: u16,
    /// The bit of a `bool` in a holding or input register.
    pub bit: Option<u8>,
    pub data_type: DataType,
    /// Elements; a string's length in characters.
    pub count: u16,
    /// None: the driver's word order.
    pub order: Option<WordOrder>,
    /// None: the path's unit.
    pub unit: Option<u8>,
    pub scale: Option<f64>,
    pub offset: Option<f64>,
    pub units: String,
    pub description: String,
    pub writable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Area { Coil, Discrete, Holding, Input }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataType { Bool, Int16, UInt16, Int32, UInt32, Int64, UInt64, Float32, Float64, String }

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WordOrder { #[default] Abcd, Cdab, Badc, Dcba }
```

## Tag names a caller can use

Resolution order, ignoring case:

1. A map row: `Totals` (the whole tag: an array when `count > 1`).
2. An element of a map array: `Totals[2]` (0-based; out of range is `NotFound`).
3. A bit of a 16-bit integer map tag or element in `holding`/`input`: `Drive_Status.5`, `Words[3].15` (bits 0..15;
   on any other type `BadRequest`). This is the `tag.N` form the server's `split_bit` already knows. `N` is a bit
   of the tag's value: on a `BADC` or `DCBA` row (bytes swapped) that is register bit `N ^ 8`. A plain `hrX.N`
   and a map `address` of `301.4` name register bits.
4. A plain address.

Plain address grammar (case-insensitive, no spaces):

```text
address = area offset ["." bit] [":" type [":" order]] ["{" count "}"] ["@" unit]
area    = "co" | "di" | "hr" | "ir"          coil, discrete input, holding register, input register
offset  = 0..65535                            0-based protocol address
bit     = 0..15                               hr/ir only; the type is then bool (omit it, or write :bool)
type    = bool | int16 | uint16 | int32 | uint32 | int64 | uint64 | float32 | float64 | string
order   = abcd | cdab | badc | dcba           default: the driver's word_order
count   = 1..                                 elements; for string the length in characters (required)
unit    = 0..255                              default: the path's unit
```

Defaults: `co`/`di` are `bool`, `hr`/`ir` are `uint16`. Examples:

| Address | Means |
|---|---|
| `hr0` | holding register 0 (Modicon 40001) as `UINT` |
| `hr100:float32` | holding registers 100-101 as `REAL`, driver word order |
| `hr100:float32:cdab` | the same, word-swapped |
| `hr200:int16{10}` | holding registers 200-209, an array of 10 `INT` |
| `hr300:string{20}` | holding registers 300-309 as a 20-character string |
| `hr10.4` | bit 4 of holding register 10 (`BOOL`; written with FC22) |
| `ir5:int32` | input registers 5-6 as `DINT` |
| `co0{16}` | coils 0-15, an array of 16 `BOOL` |
| `di7@3` | discrete input 7 of unit 3 |

Counts use `{n}` as SLC addresses do (`N7:0{3}`), so `[i]` always means an element. Modicon references are not
parsed (a 5- or 6-digit `40001` is ambiguous); the user guide has the table: `0xxxx` -> `co`, `1xxxx` -> `di`, `3xxxx`
-> `ir`, `4xxxx` -> `hr`, and subtract 1 (40001 -> `hr0`, 400101 -> `hr100`).

The result's `tag` is the caller's string unchanged, as for Logix.

## Values

| Map type | Registers | `Value` read | `data_type` |
|---|---|---|---|
| `bool` (coil, discrete, or bit of a register) | 1 bit | `Bool` | `BOOL` |
| `int16` | 1 | `Int(i16)` | `INT` |
| `uint16` | 1 | `UInt(u16)` | `UINT` |
| `int32` | 2 | `DInt` | `DINT` |
| `uint32` | 2 | `UDInt` | `UDINT` |
| `int64` | 4 | `LInt` | `LINT` |
| `uint64` | 4 | `ULInt` | `ULINT` |
| `float32` | 2 | `Real` | `REAL` |
| `float64` | 4 | `LReal` | `LREAL` |
| `string` | ceil(count / 2) | `String` (cut at the first NUL, Latin-1 bytes above 0x7F mapped to chars) | `STRING` |
| any numeric with `scale` or `offset` | as its type | `LReal(raw as f64 * scale + offset)` | `LREAL` |

Arrays (`count > 1`, not strings) read as `Value::Array` of the element values; `data_type` is the element's name, as
SLC reports file types.

**Word and byte order.** `ABCD` is the Modbus standard: each register big-endian, most significant register first.
The other orders are two independent swaps:

| Order | Bytes in each register | Register order | float32 123.456 (0x42F6E979) as registers |
|---|---|---|---|
| `ABCD` | high byte first | most significant first | `42F6 E979` |
| `CDAB` | high byte first | least significant first | `E979 42F6` |
| `BADC` | low byte first | most significant first | `F642 79E9` |
| `DCBA` | low byte first | least significant first | `79E9 F642` |

For 64-bit types "least significant first" reverses all four registers (`CDAB` on 0x0102030405060708 is
`0708 0506 0304 0102`). For 16-bit types only the byte swap applies (`BADC` and `DCBA` swap the two bytes). For
strings, characters are packed two per register, high byte first; `BADC`/`DCBA` put the first character in the low
byte; the register order flag does not apply.

**Writes** take any `Value` that fits:

- `bool`: `Bool`, or an integer 0/1.
- Integer types: any integer variant, or a float with no fractional part, in the type's range; else `BadValue`
  (nothing sent).
- `float32`/`float64`: any number (`f64` to `f32` may round; out of `f32` range is `BadValue`).
- Scaled tags: `raw = (value - offset) / scale`, rounded to the nearest integer for integer types, then the range
  check above.
- `string`: `String` of at most `count` bytes (Latin-1; other characters are `BadValue`), padded with NUL.
- Arrays: `Value::Array` of exactly `count` elements for the whole tag; an element (`Totals[2]`) takes one value.

## Read planning

```rust
/// One request to send: a span of one area of one unit, and the targets it serves.
pub(crate) struct Block { pub unit: u8, pub area: Area, pub start: u16, pub count: u16, pub targets: Vec<usize> }

/// Plans the reads of `targets` (resolved tags) into blocks. Pure.
pub(crate) fn plan(targets: &[Span], limits: Limits) -> Vec<Block>;
pub(crate) struct Span { pub unit: u8, pub area: Area, pub start: u16, pub count: u16 }   // count in registers or bits
pub(crate) struct Limits { pub max_registers: u16, pub max_bits: u16, pub max_gap: u16 }
```

1. Resolve every tag. A name that resolves to nothing is that tag's `NotFound` result
   (`no tag or address 'x'`); a malformed address is its `BadRequest`. Neither is sent.
2. A bit of a register reads its register; a bit-in-register `bool` and a `uint16` at the same register share it.
3. Group by `(unit, area)`, in the order unit, then area (coil, discrete, holding, input). Sort each group by start
   (then by end, descending).
4. Walk the group: the next span joins the current block when `next.start <= block.end + 1 + max_gap` and the joined
   block's count is at most the limit (`max_registers` for registers, `max_bits` for bits). Overlapping and duplicate
   spans always join when the size allows.
5. A single target bigger than the limit (a long array or string) becomes several consecutive blocks of the limit;
   its value is put together from them.
6. Send the blocks in plan order (FC01 coil, FC02 discrete, FC03 holding, FC04 input); decode each target from its
   block(s); return the results in the callers' order.

Limits: `max_registers` 1..=125 (default 125, the FC03/04 maximum; also the RTU frame limit: 5 + 250 bytes), `max_bits`
1..=2000 (default 2000), `max_gap` 0.. (default 8, in the area's own unit: registers or bits). A value above the
protocol maximum is a `RequestError` at construction. `max_gap = 0` joins only touching or overlapping tags.

**Fallback.** When a block that serves more than one target gets exception 02 (illegal data address) or 03 (illegal
data value; some devices send it for a quantity they dislike), each of its targets is read again alone (its own span,
split by the limits). Each target then gets its own result or exception. The fallback is logged at debug level and is
not remembered: a device whose map has holes inside the gap should be given `max_gap = 0`, which the user guide says.
A block of one target gets its exception as that target's error, with no retry.

Why the driver merges reads across callers (`merges_reads() == true`): `Protocol::read` returns a per-tag result for
every address problem, thanks to the fallback; its `Err` is only a lost link, which fails every caller anyway. So one
merged read gives each caller what its own read would, and Modbus gains a lot from it: two subscriptions on
neighbouring registers become one FC03.

## Writes

Each item of `Protocol::write` is resolved and sent on its own, in order, and gets its own result. Writes are never
merged (session rule) and never split across requests: a value that needs more registers than one request carries
(FC16: 123 registers, FC15: 1968 coils, or `max_registers`/`max_bits` if lower) is a `BadRequest`, nothing sent.

| Target | Function |
|---|---|
| one coil | FC05 Write Single Coil (`FF00` / `0000`) |
| several coils (array, `co0{16}`) | FC15 Write Multiple Coils |
| one register (`int16`, `uint16`, one element, scaled 16-bit) | FC06 Write Single Register |
| several registers (32/64-bit, float, arrays, strings) | FC16 Write Multiple Registers |
| a bit of a holding register (`hr10.4`, `Horn`, `Drive_Status.5`) | FC22 Mask Write Register: AND = `!(1 << bit)`, OR = `value << bit` |
| `discrete`, `input`, a `writable = false` row | refused: `Access` (`'x' is read-only`), nothing sent |

`write_multiple: true` sends FC15/FC16 for one coil or register too, for devices that only implement those. A device
without FC22 answers exception 01, which is the result (`BadRequest`, message names FC22); there is deliberately no
read-modify-write fallback, because it would race the device's own logic.

A write's echo reply is checked (address and quantity, or value for FC05/06) and a mismatch is a `Comm` result.

## Errors

**Modbus exceptions** become the target's `TagError { kind, status: Some(code), ext: None, message }`, message
`Modbus exception 0x02 (illegal data address) from unit 1`:

| Code | Name | `ErrorKind` |
|---|---|---|
| 01 | Illegal Function | `BadRequest` |
| 02 | Illegal Data Address | `NotFound` |
| 03 | Illegal Data Value | `BadValue` on a write, `BadRequest` on a read |
| 04 | Server Device Failure | `Device` |
| 05 | Acknowledge | `Refused` |
| 06 | Server Device Busy | `Refused` |
| 08 | Memory Parity Error | `Device` |
| 0A | Gateway Path Unavailable | `Comm` |
| 0B | Gateway Target Device Failed to Respond | `Comm` |
| other | | `Device` |

For `send_pdu` and `device_info` an exception is `Error::Response { kind, status: Some(code), .. }` with the same
kind.

**Transport failures:**

| What happened | `tcp://` | `rtu://`, `rtu+tcp://` |
|---|---|---|
| No reply within `socket_timeout` | `Err(Comm("no reply from unit 1 within 1 s"))` for the whole call; link dropped; the session reconnects | that request's targets get `TagError` kind `Comm`, same message; link kept; the rest of the call goes on |
| Socket or port error, peer closed | `Err(Comm)`, link dropped | same |
| Bad MBAP header (protocol id not 0, length < 2 or > 254) | `Err(Comm)`, link dropped (the stream is out of step) | n/a |
| Reply with an older transaction id | discarded, keep reading (a reply late from an earlier request) | n/a |
| Bad CRC, or a reply whose unit, function or byte count does not match the request (or a write echo that does not) | n/a | targets get `Comm` (`bad CRC from unit 1`, `bad reply from unit 1`; a write adds `(the write may have been applied)`), link kept, input drained |
| Reply PDU too short or inconsistent | targets get `Comm` (`bad reply`), link kept (MBAP framing is intact) | same |

Why `tcp://` drops the link on a timeout: it matches Logix and the session's reconnect, and on Linux a dead peer under
unacknowledged sends is otherwise found only after the kernel's retransmission timeout (minutes). The cost: a Modbus
TCP gateway that stays silent for a dead RTU unit (instead of exception 0B, which the spec defines for this) makes
every read of that unit reconnect the link. Users with such a gateway use `rtu+tcp://` if the gateway can pass RTU
frames, or one driver per unit. Listed under [Risks](#risks-to-watch).

Why RTU keeps the link: a serial port has no connection to lose, and one dead unit must not take down the others on
the bus. RTU replies carry no transaction id, so before **every** request the driver discards the input already
received (serial: clear the input buffer; TCP: non-blocking reads); a late reply sitting there then cannot shift every
later reply by one. After an RTU timeout, a bad frame or a reply that does not answer the request, the next request
first also **drains**: it reads and discards until the line has been silent for `max(t3.5, socket_timeout / 4)`, so
the usual slightly late reply is gone. The residual risk (a reply arriving after the request went out that matches
its unit, function and byte count) is listed under risks; it costs one wrong reply, not a permanent shift.

Write timeouts on RTU: the item's result is `Comm` with `(the write may have been applied)` appended; it is never sent
again. Over `tcp://` a timeout drops the link: on the first item the call is `Err(Comm)`; on a later item the call is
`Ok` so the items already applied show as good, the failing item is `Comm` with `(the write may have been applied)`
and the rest are `Comm` (`not sent`).

Local errors: unknown name `NotFound`; malformed address `BadRequest`; read-only `Access`; value does not fit
`BadValue`; reading unit 0 on RTU `BadRequest`.

## Keep-alive and reconnect

- `open()` connects the socket or opens the port. It sends nothing; it does not probe the device (a Modbus server has
  no session to register). Ok(true) on success, `Err(Comm("Failed to open socket to host:502"))` /
  `Err(Comm("Failed to open serial port COM3: ..."))` on failure.
- `reopen()` is `open()`. `close()` and `drop_link()` drop the socket or port (no closing request exists).
  `connected()` is true while a socket or port is held.
- **Keep-alive request** (`Protocol::keep_alive`): FC08 Diagnostics, sub-function 0000 Return Query Data, data `0000`,
  to the default unit. Any reply, the echo or an exception (most Modbus TCP devices answer 01, FC08 being a serial
  line function), proves the link. With `keep_alive_address` set (a plain address, e.g. `"hr0"`), it reads that
  instead; a reply with an exception still counts. A timeout or I/O error of the keep-alive drops the link on every
  scheme, so the session sees a lost link and reconnects (on `rtu://` this reopens the port).
- Default `SessionOptions` from `ModbusDriver::new`: reconnect on, keep-alive `Some(30 s)` for `tcp://` and
  `rtu+tcp://` (it also keeps NAT and firewall state alive), `None` for `rtu://` (a bus needs no keep-alive and a
  missing default unit would reopen the port every 30 s). `with_session` takes explicit options;
  `with_connector` uses `SessionOptions::off()` as the other drivers do.
- TCP keep-alive on the socket comes from the shared `tcp_stream` helper (idle 10 s, probe every 5 s).

## RTU framing and timing

- **CRC-16/MODBUS**: polynomial 0xA001 (reflected 0x8005), initial 0xFFFF, appended low byte first. Bitwise loop, no
  table (frames are at most 256 bytes). Golden vector: `01 03 00 00 00 02` -> `C4 0B`.
- **Reply length** is known from the request, so frames are read by length, not by detecting a 3.5-character
  silence (Windows serial timing cannot see a 1.75 ms gap). Read 2 bytes (unit, function), then:
  function with bit 0x80: 3 more (code, CRC); FC01-04: 1 byte count + count + 2; FC05, 06, 08, 15, 16: 6 more;
  FC22: 8 more; FC43: parse the MEI header and each object's length, then 2. Every count is bounds-checked (frame
  <= 256 bytes) before reading on.
- **Timing**: before each send, wait until t3.5 has passed since the last byte sent or received. t3.5 is
  `3.5 * 11 bits / baud` up to 19200 baud and a fixed 1.75 ms above (the spec's values); t1.5 is not checked. The
  reply timeout starts after the send and adds the request's and the longest reply's time on the wire
  (`bytes * 11 / baud`). `rtu+tcp://` has no t3.5 (the converter makes the gaps).
- The reply must come from the unit asked and carry the function asked (or it with 0x80); anything else is a bad frame
  (drain, `Comm`).
- `serialport` setup: baud, parity, data bits, stop bits, no flow control, `timeout` per read; `clear(ClearBuffer::All)`
  on open. RS-485 adapters that echo the sent bytes are not supported (no `echo` option); see risks.

MBAP (`tcp://`): transaction id (u16, wrapping, one per request), protocol id 0, length = unit + PDU, unit id. One
request in flight at a time (the session thread does all I/O), so a reply with an older transaction id is a late one
and is skipped.

## Link and connector

```rust
/// A byte stream to a Modbus device: a TCP socket, a serial port, or a test fake. A read that times out returns an
/// io::Error of kind TimedOut or WouldBlock.
pub trait Link: std::io::Read + std::io::Write + Send {
    /// Timeout of later reads and writes.
    fn set_timeout(&mut self, timeout: Duration) -> std::io::Result<()>;
}

/// Opens a link to an endpoint; the driver calls it on every open.
pub type ModbusConnector = Box<dyn Fn(&Endpoint, Duration) -> Result<Box<dyn Link>> + Send + Sync>;

/// TCP for `tcp://` and `rtu+tcp://`, `serialport` for `rtu://`.
pub fn modbus_connector() -> ModbusConnector;
```

`impl Link for TcpStream` and for `Box<dyn serialport::SerialPort>`. The simulator supplies an in-memory `Link`. A
separate trait from `transport::Transport` because that one moves whole EtherNet/IP encapsulation frames; Modbus
framing lives in `frame.rs` above a plain byte stream, and that is what lets the same RTU code run over a serial port
and over TCP.

## The protocol state and the trait impl

```rust
pub(crate) struct Modbus {
    endpoint: Endpoint,
    unit: u8,                       // default unit
    options: ModbusOptions,         // map, limits, word order, ...
    connector: ModbusConnector,
    link: Option<Box<dyn Link>>,
    opened: Arc<AtomicBool>,        // mirrors link.is_some() for ModbusDriver::connected without the lock
    transaction: u16,
    last_io: Instant,               // for t3.5
    drain: bool,                    // RTU: drain before the next request
}

impl Protocol for Modbus {
    fn open(&mut self) -> Result<bool>;                 // connect; Ok(true)
    fn close(&mut self) -> Result<()>;                  // drop the link
    fn drop_link(&mut self);                            // drop the link
    fn connected(&self) -> bool;                        // link.is_some()
    fn read(&mut self, tags: &[&str]) -> Result<Vec<TagResult>>;              // resolve, plan, send, fallback, decode
    fn write(&mut self, items: &[(&str, Value)]) -> Result<Vec<TagResult>>;  // one request per item
    fn keep_alive(&mut self) -> Result<()>;             // FC08 0000, or a read of keep_alive_address
    // reopen: default (open); merges_reads: default (true)
}

impl Modbus {
    /// One request/reply: frames `pdu` for `unit`, sends it, reads the reply, returns the reply PDU (an exception
    /// PDU included). Err on a timeout (tcp) or a transport failure; on rtu a timeout is
    /// Err(Comm) too and `read`/`write` turn it into per-target results.
    fn transact(&mut self, unit: u8, pdu: &[u8]) -> Result<Vec<u8>>;
}
```

`read` and `write` decide per scheme whether an `Err(Comm)` from `transact` is a per-target result (rtu, timeout or
bad frame, link still held) or the whole call's error (anything else). The session's lost-link detection needs
nothing new: it reads `connected()` after the job.

## Public Rust API

```rust
/// How a Modbus driver reads and writes.
#[derive(Clone, Debug, PartialEq)]
pub struct ModbusOptions {
    /// Tag names, types and descriptions; None: plain addresses only.
    pub map: Option<TagMap>,
    /// Reply timeout. Default 1 s (Modbus devices answer in milliseconds; a dead RTU unit holds the bus this long).
    pub socket_timeout: Duration,
    /// Most registers in one read, 1..=125. Default 125.
    pub max_registers: u16,
    /// Most coils or discrete inputs in one read, 1..=2000. Default 2000.
    pub max_bits: u16,
    /// Most unrequested registers or bits between two tags read in one request. Default 8.
    pub max_gap: u16,
    /// Word order of tags without one. Default ABCD.
    pub word_order: WordOrder,
    /// Always FC15/FC16, never FC05/FC06. Default false.
    pub write_multiple: bool,
    /// The keep-alive reads this plain address instead of sending FC08. Default None.
    pub keep_alive_address: Option<String>,
}
impl Default for ModbusOptions { /* None, 1 s, 125, 2000, 8, Abcd, false, None */ }

/// Read Device Identification (FC43 / MEI 14) objects; None where the device has none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceInfo {
    pub vendor_name: String,
    pub product_code: String,
    pub revision: String,
    pub vendor_url: Option<String>,
    pub product_name: Option<String>,
    pub model_name: Option<String>,
    pub user_application_name: Option<String>,
}

/// A Modbus TCP, RTU or RTU-over-TCP driver, on a session (see LogixDriver for the threading contract).
pub struct ModbusDriver { session: Session<Modbus>, map: Arc<TagMap>, opened: Arc<AtomicBool> }

impl ModbusDriver {
    /// A driver for `path` (tcp://, rtu:// or rtu+tcp://); not connected until open. Reconnects; keep-alive 30 s
    /// over TCP, off on a serial port.
    pub fn new(path: &str, options: ModbusOptions) -> Result<Self>;
    /// With `connector`, no reconnect and no keep-alive (SessionOptions::off()).
    pub fn with_connector(path: &str, options: ModbusOptions, connector: ModbusConnector) -> Result<Self>;
    /// With explicit session options.
    pub fn with_session(path: &str, options: ModbusOptions, session: SessionOptions, connector: ModbusConnector)
        -> Result<Self>;
    /// The session options `new` uses for `path`.
    pub fn default_session(path: &str) -> Result<SessionOptions>;

    // as LogixDriver
    pub fn open(&self) -> Result<bool>;
    pub fn close(&self) -> Result<()>;
    pub fn stop(&self);
    pub fn connected(&self) -> bool;                       // never waits
    pub fn connection_state(&self) -> ConnectionState;    // never waits
    pub fn set_connection_callback(&self, callback: Option<ConnectionCallback>);
    pub fn read(&self, tags: &[&str]) -> Result<Vec<TagResult>>;
    pub fn write(&self, items: &[(&str, Value)]) -> Result<Vec<TagResult>>;
    pub fn read_async(&self, tags: &[&str]) -> Handle<Vec<TagResult>>;
    pub fn write_async(&self, items: &[(&str, Value)]) -> Handle<Vec<TagResult>>;
    pub fn subscribe(&self, tags: &[&str], options: SubscribeOptions) -> Result<Subscription>;
    pub fn socket_timeout(&self) -> Duration;
    pub fn set_socket_timeout(&self, timeout: Duration) -> Result<()>;

    // Modbus
    /// The map (empty without one). No lock, no I/O.
    pub fn map(&self) -> &TagMap;
    /// Read Device Identification of `unit` (None: the path's unit), through the session.
    pub fn device_info(&self, unit: Option<u8>) -> Result<DeviceInfo>;
    /// Sends one raw PDU (function code + data) to `unit` and returns the reply PDU; an exception reply is
    /// Error::Response with its code. For functions the driver does not wrap (FC23, file records, ...).
    pub fn send_pdu(&self, unit: Option<u8>, pdu: &[u8]) -> Result<Vec<u8>>;
}
impl fmt::Display for ModbusDriver { /* "ModbusDriver(tcp://10.0.0.9:502?unit=1)" */ }
```

Mapping onto the session, as [the closure table](session-core.md#closures-how-every-existing-method-maps):
`open` -> `session.open()`; `close` -> `session.close()`; `read`/`write` -> `session.read`/`write` then `wait`;
`device_info`, `send_pdu` -> `session.call`; `socket_timeout`, `set_socket_timeout` -> `session.lock()` (no I/O);
`map`, `connected`, `connection_state` -> no lock.

`device_info`: FC43, MEI 0x0E, read code 01 (basic), object 0; follow "more follows" with the next object id (stop
with `Comm("bad reply")` if the next id does not increase, and after 256 objects); if the conformity level allows
regular objects (0x02, 0x03, 0x82, 0x83), read code 02 the same way. Object bytes are decoded as UTF-8, lossy.
Missing mandatory basic objects become empty strings.

Not mirrored from `LogixDriver` (CIP only): generic messages, tag table versions, trends, browsing, PLC time, tag
upload. `get_tag_list` has no equivalent; `map()` is the tag list.

## Simulator

New file `crates/ciplink-sim/src/modbus.rs`, exported from `lib.rs` (`mod modbus; pub use modbus::{...}`), and a
dispatch in `main.rs`. The CIP `Simulator` and `Config` are untouched: Modbus has nothing in common with the
encapsulation layer, and keeping it apart keeps merges with the S7 work small. The simulator codes its frames itself
(it does not call `ciplink::modbus`), so it is an independent check of the driver's bytes.

```rust
pub struct ModbusSim { /* Arc<Mutex<State>> */ }
pub enum Framing { Mbap, Rtu }
pub enum ModbusFault {
    DropReplies(u32),                                   // the next n requests get no reply
    Delay(Duration),                                    // every reply this late
    RefuseConnections,                                  // new connections closed at once / connector error
    CloseConnections,                                   // open connections closed at their next request
    NoReply { unit: u8 },                               // unit is dead: no reply (a silent gateway)
    Exception { unit: u8, function: Option<u8>, code: u8 }, // answer with this exception
    BadCrc(u32),                                        // RTU: the next n replies carry a wrong CRC
}

impl ModbusSim {
    pub fn new(config: ModbusSimConfig) -> Result<Self, ConfigError>;
    pub fn from_json(text: &str) -> Result<Self, ConfigError>;
    pub fn connector(&self, framing: Framing) -> ciplink::modbus::ModbusConnector; // in memory, no sockets
    pub fn serve(&self, addr: &str, framing: Framing) -> std::io::Result<ModbusServer>;
    pub fn registers(&self, unit: u8, area: &str, address: u16, count: u16) -> Vec<u16>;
    pub fn set_registers(&self, unit: u8, area: &str, address: u16, values: &[u16]);
    pub fn bits(&self, unit: u8, area: &str, address: u16, count: u16) -> Vec<bool>;
    pub fn set_bits(&self, unit: u8, area: &str, address: u16, values: &[bool]);
    pub fn inject(&self, fault: ModbusFault);
    pub fn clear_faults(&self);                         // not CloseConnections, as the CIP sim
    pub fn requests(&self) -> u64;
    pub fn record(&self, on: bool);
    pub fn take_received(&self) -> Vec<Vec<u8>>;        // whole ADUs as received
    pub fn on_request(&self, hook: impl FnMut(&mut ModbusData, u64) + Send + 'static); // may block: holds the driver
    pub fn clear_hook(&self);
}
```

It must implement:

- Per unit, four tables sized by the config (`coils`, `discrete`, `holding`, `input`, default 10000 each) and
  `holes`: ranges that answer exception 02 when a request touches them.
- FC01, 02, 03, 04 (exception 03 above `max_registers`/`max_bits` of the config, default 125/2000; exception 02 past
  the table or into a hole), FC05, 06, 15, 16 (echo replies), FC22 (mask write: `(reg & and) | (or & !and)`), FC08
  sub-function 0000 (echo), FC43/14 when `identity` is configured (basic and regular objects, with "more follows"
  when `identity_page` objects per reply is set, to test paging); exception 01 for any function in `unsupported` and
  any other function.
- MBAP framing (echo the transaction id) and RTU framing (CRC checked; a bad CRC in a request gets no reply, as a
  real device).
- Units not in the config get no reply (RTU) or exception 0B (MBAP, as a well-behaved gateway; `NoReply` simulates a
  silent one).
- RTU broadcast: unit 0 writes apply to every unit and get no reply.
- The in-memory link is synchronous, like `SimTransport`: a complete written frame is handled at once and its reply
  queued for reading; a read with nothing queued returns `TimedOut` at once (no real wait), so timeout tests are fast.
  `Delay` sleeps in the read and times out when it is longer than the link's timeout.

Config (`tools/sim/example_modbus.json`):

```json
{
  "kind": "modbus",
  "max_registers": 125,
  "max_bits": 2000,
  "units": [
    {"unit": 1, "holding": 1000, "input": 1000, "coils": 2000, "discrete": 2000,
     "holes": [{"area": "holding", "start": 500, "count": 10}],
     "identity": {"vendor_name": "ciplink", "product_code": "SIM-MB", "revision": "1.0",
                  "product_name": "ciplink-sim Modbus", "model_name": "MB-1"},
     "values": {"holding": {"0": [59769, 17142]}, "coil": {"0": [true, false, true]}}},
    {"unit": 2, "holding": 100, "coils": 100, "unsupported": [22, 43]}
  ]
}
```

Binary: `ciplink-sim --config example_modbus.json --port 0 [--framing mbap|rtu]` (default `mbap`; `rtu` serves RTU
frames over TCP for `rtu+tcp://`), prints `listening on 127.0.0.1:PORT`. `main.rs` reads the config's `kind` first and
builds a `ModbusSim` for `"modbus"`. Stdin commands for Modbus:

```text
{"cmd": "registers", "unit": 1, "area": "holding", "address": 0, "count": 2}   [59769, 17142]
{"cmd": "set_registers", "unit": 1, "area": "holding", "address": 0, "values": [1, 2]}
{"cmd": "bits", "unit": 1, "area": "coil", "address": 0, "count": 3}           [true, false, true]
{"cmd": "set_bits", "unit": 1, "area": "coil", "address": 0, "values": [true]}
{"cmd": "fault", "fault": {...}}   {"drop_replies": n}, {"delay_ms": n}, {"refuse_connections": true},
                                   {"close_connections": true}, {"no_reply": unit},
                                   {"exception": {"unit", "function", "code"}}, {"bad_crc": n}
{"cmd": "clear_faults"}
{"cmd": "requests"}
```

No serial port is ever opened by a test: RTU is tested through the in-memory link and through `--framing rtu` over
TCP on 127.0.0.1. The serial connector's own code (port settings from the path) is tested by parsing only.

## Bindings

### C ABI

New file `crates/ciplink-ffi/src/modbus.rs`; `lib.rs` gets `Driver::Modbus(Box<ModbusDriver>)` and arms in the
generic functions; `session.rs` gets arms in the async, subscribe and connection functions. Header regenerated with
cbindgen.

```c
/* path: tcp://, rtu:// or rtu+tcp://. options_json (NULL or {}), all optional:
   map_file (path), map_csv (CSV text; not with map_file), socket_timeout (seconds, default 1),
   max_registers (125), max_bits (2000), max_gap (8), word_order ("ABCD"), write_multiple (false),
   keep_alive_address (null), reconnect (true), reconnect_min (0.1), reconnect_max (10),
   keep_alive (seconds or null; absent: 30 over TCP, off for rtu://) */
CiplinkStatus ciplink_modbus_new(const char *path, const char *options_json, CiplinkDriver **out);
/* {"vendor_name": ..., "product_code": ..., "revision": ..., "vendor_url": null, ...}; unit < 0: the path's unit */
CiplinkStatus ciplink_modbus_device_info(const CiplinkDriver *handle, int32_t unit, char **out_json);
/* the map as a JSON array of rows: {"name","area","address","bit","type","count","order","unit","scale",
   "offset","units","description","writable"} */
CiplinkStatus ciplink_modbus_tags(const CiplinkDriver *handle, char **out_json);
/* raw PDU in, reply PDU out (free with ciplink_bytes_free); an exception is CIPLINK_STATUS_RESPONSE */
CiplinkStatus ciplink_modbus_send_pdu(const CiplinkDriver *handle, int32_t unit, const uint8_t *pdu, size_t len,
                                      uint8_t **out, size_t *out_len);
```

Generic calls that work on a Modbus handle: `ciplink_open`, `ciplink_close`, `ciplink_connected`, `ciplink_read`,
`ciplink_write`, `ciplink_read_async`, `ciplink_write_async`, `ciplink_request_*`, `ciplink_subscribe`,
`ciplink_subscription_free`, `ciplink_set_connection_callback`, `ciplink_connection_state`,
`ciplink_socket_timeout`, `ciplink_set_socket_timeout` (null is `INVALID_ARGUMENT` for Modbus), `ciplink_last_error`,
`ciplink_driver_free`. Every other driver call returns `CIPLINK_STATUS_UNSUPPORTED`. Results use the existing result
JSON, so `results_json` and every binding's parser need no change. The FFI's `session_options` parser gets the
scheme's keep-alive default passed in instead of `SessionOptions::default()`.

### Python

`_core`: new file `crates/ciplink-py/src/modbus.rs`, `PyModbusDriver` (`ciplink._core.ModbusDriver`) registered in
`lib.rs`, with `Drop` releasing the GIL around `stop()` (session-core rule 6), every blocking call in `py.detach`,
results converted as Logix results are. Package: new `python/ciplink/modbus_driver.py`, exported from
`__init__.py`.

```python
class ModbusDriver(_Session):
    def __init__(self, path: str, map_file: Optional[str] = None, *, socket_timeout: float = 1.0,
                 max_registers: int = 125, max_bits: int = 2000, max_gap: int = 8, word_order: str = "ABCD",
                 write_multiple: bool = False, keep_alive_address: Optional[str] = None,
                 reconnect: bool = True, keep_alive: Union[float, None, str] = "auto"): ...
    def open(self) -> bool
    def close(self)                                   # also ends subscriptions, as SLCDriver.close
    def __enter__(self) / __exit__(self, *exc)        # open / close
    @property connected -> bool
    def read(self, *tags: str) -> ReadWriteReturnType                  # Tag, or a list of Tag
    def write(self, *tags_values: Tuple[str, TagValueType]) -> ReadWriteReturnType
    async def read_async(self, *tags) / write_async(self, *tags_values)
    # subscribe, on_connection, connection_state: from _Session
    def device_info(self, unit: Optional[int] = None) -> dict
    def send_pdu(self, pdu: bytes, unit: Optional[int] = None) -> bytes
    @property tags -> Dict[str, dict]                 # the map rows by name, keys as ciplink_modbus_tags
```

`keep_alive="auto"` means the scheme's default. Errors raise the package's existing classes (`CommError`,
`RequestError`, `ResponseError`); per-tag errors are in `Tag.error` as for Logix.

### C++

`bindings/cpp/include/ciplink.hpp`:

```cpp
class Modbus : public Driver {
public:
    /// `path` like "tcp://10.0.0.9?unit=1"; `options_json` see ciplink_modbus_new.
    explicit Modbus(const std::string& path, const std::string& options_json = "");
    std::vector<Tag> read(const std::vector<std::string>& tags);
    Tag read_tag(const std::string& tag);
    std::vector<Tag> write(const std::vector<std::pair<std::string, Value>>& items);
    Tag write_tag(const std::string& tag, const Value& value);
    std::future<std::vector<Tag>> read_async(const std::vector<std::string>& tags);
    std::future<std::vector<Tag>> write_async(const std::vector<std::pair<std::string, Value>>& items);
    Subscription subscribe(const std::vector<std::string>& tags, double interval_s = 1.0,
                           std::optional<double> deadband = std::nullopt,
                           std::function<void(const std::vector<Tag>&)> on_changes = {});
    Value device_info(std::optional<uint8_t> unit = std::nullopt);
    Value tags();
    std::vector<uint8_t> send_pdu(const std::vector<uint8_t>& pdu, std::optional<uint8_t> unit = std::nullopt);
};
```

The inherited CIP calls (`generic_message`, `get_identity`, ...) throw `ciplink::Error` with status Unsupported.

### .NET

New file `bindings/dotnet/Ciplink/Modbus.cs`; `Native.cs` gets the four imports.

```csharp
public sealed class ModbusOptions : DriverOptions
{
    public string? MapFile { get; init; }
    public int MaxRegisters { get; init; } = 125;
    public int MaxBits { get; init; } = 2000;
    public int MaxGap { get; init; } = 8;
    public string WordOrder { get; init; } = "ABCD";
    public bool WriteMultiple { get; init; }
    public string? KeepAliveAddress { get; init; }
    /// null: the scheme's default (30 s over TCP, off for rtu://); TimeSpan.Zero: off.
    public new TimeSpan? KeepAlive { get; init; }
    // SocketTimeout: base property; ModbusOptions sets it to 1 s in its constructor
}

public sealed class ModbusDriver : Driver
{
    public ModbusDriver(string path, ModbusOptions? options = null);
    // Open, Close, Read, Write, ReadAsync, WriteAsync, Subscribe, ConnectionChanged, ConnectionState: from Driver
    public JsonObject DeviceInfo(byte? unit = null);
    public JsonArray Tags { get; }
    public byte[] SendPdu(byte[] pdu, byte? unit = null);
}
```

`ModbusOptions.AddTo` calls the base, then writes the Modbus keys and replaces `keep_alive` (removes it for null, null
for zero). `ConnectionSize` is ignored for Modbus.

### ciplink-server

Config (`config.rs`, `PlcConfig` gets three fields):

```toml
[plc.Skid]
protocol = "modbus"                 # "logix" (default) or "modbus"
path = "tcp://10.0.0.9?unit=1"
map_file = "maps/skid.csv"          # relative to the config file
[plc.Skid.modbus]                   # optional; the keys of ciplink_modbus_new
max_gap = 0
word_order = "CDAB"
socket_timeout = 2.0
```

- `protocol: String`, `map_file: Option<PathBuf>`, `modbus: Map<String, Json>`. `protocol = "modbus"` without
  `map_file` is a config error (the server serves named tags). An unknown protocol is a config error.
- New file `crates/ciplink-server/src/modbus.rs`: `ModbusPlc { driver: ModbusDriver }` implementing `Plc`, built
  with `reconnect: false` and the scheme's keep-alive (as `LogixPlc`: the worker reconnects).
  - `read`, `write`: through the driver; `Err` is the driver's `Err`.
  - `catalog()`: one `Node` per map row: `type_name` the CIP name (`REAL`, `INT`, ... ; `LREAL` for scaled rows),
    `kind` `Atomic` (or `String` with `structure_size = Some(count)`), `dims` `[count]` for arrays, no instance id.
    No types.
  - `version()`: `Json::Null` (a map does not change while serving).
  - `describes()`: true; `descriptions(tags)`: the rows' `description` (None when empty), no I/O.
  - `connection_size()`: 0 (the planner's default budget). The planner sees only atomic tags and string tags, so it
    plans one read per tag in budget-sized chunks; the driver merges each chunk into the fewest Modbus requests.
- `lib.rs::factory(false)` dispatches on `cfg.protocol`: `"modbus"` -> `ModbusPlc::new`, else `LogixPlc::new`.
  `--mock` is unchanged (it serves `mock_tags` whatever the protocol). `dump-tags` goes through the same factory, so
  it writes a Modbus PLC's map tags; `types` reads a running server and needs nothing new.
- Bits: a client writing `Horn` or `Drive_Status.5` goes through `split_bit` as for Logix; the driver sends FC22.
- The S7 work adds a `protocol` too. Whoever merges second keeps one `protocol` field and one dispatch.

## User documentation

- New guide `docs/modbus.md` ("Modbus TCP and RTU"), in the nav under Guides after SLC: paths, the map file with the
  example, plain addresses with the Modicon table, word orders with the 123.456 example, merging and `max_gap`,
  write functions, exceptions table, timeouts per scheme, keep-alive defaults, device info, language tabs like the
  other guides.
- `docs/server.md`: the `protocol`, `map_file` and `[plc.X.modbus]` keys.
- `docs/simulator.md`: `"kind": "modbus"`, `--framing`, the Modbus commands.
- `docs/errors.md`: the exception table. `docs/api.md`, `docs/api-python.md`: the new classes.
- `docs/releases.md`: one line under `## Unreleased`. No version bump.

The guide also has the RTU settings and examples in every language tab; the C/C++/C# reference is in `docs/api.md`
(*Modbus (C, C++ and C#)*) and the Python one in `docs/api-python.md` (*Modbus*).

## Test plan

Existing suites run unchanged; no fixture or parity test is edited. New tests:

| Where | Tests | Proves |
|---|---|---|
| `modbus/frame.rs` | `crc_of_known_frames` (`01 03 00 00 00 02` -> `C4 0B`, `01 03 00 00 00 01` -> `84 0A`), `mbap_header_round_trip`, `mbap_rejects_bad_protocol_and_length`, `rtu_reply_length_for_each_function`, `rtu_reply_length_rejects_counts_past_256` | framing |
| `modbus/pdu.rs` | golden request bytes for FC 1-6, 8, 15, 16, 22, 43 (e.g. MBAP `00 01 00 00 00 06 01 03 00 00 00 02`); reply parsers with short, long and exception PDUs; `coil_bits_are_lsb_first`; `fc43_pages_follow_more_follows_and_stop_without_progress` | codec |
| `modbus/value.rs` | `float32_in_every_word_order` (123.456 table above), `int64_and_float64_word_orders`, `int16_byte_swap`, `string_packing_and_byte_swap`, `scale_and_offset_round_trip`, `write_range_checks` (int16 70000, 1.5 to int, NaN to int, bad Latin-1), `scaled_write_rounds` | value mapping |
| `modbus/address.rs` | every example of the address table; `rejects` (bit on co, bit 16, string without count, type on a bit, offset + size past 65535, unit 256); `name_then_element_then_bit_then_address` resolution order | names and addresses |
| `modbus/map.rs` | `example_map_parses` (the example file), `quoted_fields_with_commas_quotes_and_newlines`, `semicolon_files`, `bom_comments_blank_lines_and_extra_columns`, `errors_name_line_and_column` (one per rule), `name_that_is_an_address_is_refused`, `duplicate_names_ignoring_case` | map file |
| `modbus/plan.rs` | `contiguous_tags_are_one_block`, `gap_at_max_gap_joins_and_one_more_splits`, `limit_splits_blocks`, `long_array_spans_several_blocks`, `units_and_areas_never_join`, `duplicates_and_overlaps_share_a_block`, `bit_and_word_share_a_register` | planning |
| `modbus/link.rs` | `endpoint_parse` for every path form and defaults; `bad_paths` (no scheme, unknown key, parity X, port 0) | paths |
| `crates/ciplink-sim/tests/modbus.rs` (driver on `ModbusSim` in memory, `with_connector`) | `reads_every_type_from_the_map`, `plain_addresses_without_a_map`, `writes_use_fc05_06_15_16_22` (recorded function codes), `write_multiple_forces_fc15_16`, `bit_write_without_fc22_is_bad_request_and_sends_nothing_else`, `read_only_rows_are_refused_locally` (requests unchanged), `exceptions_map_to_kinds` (each code via `Exception` fault), `hole_in_a_merged_block_falls_back_per_tag` (good neighbours read, the hole's tag `NotFound`), `max_gap_zero_never_reads_unrequested_registers`, `picky_device_max_registers` (sim limit 10, driver `max_registers = 10`), `device_info_basic_and_regular_with_paging`, `device_info_unsupported_is_bad_request`, `send_pdu_round_trip_and_exception`, `rtu_broadcast_write_gets_no_reply_and_succeeds` | driver behaviour, both framings (each test runs for `Framing::Mbap` and `Framing::Rtu`) |
| same | `rtu_timeout_fails_only_that_units_tags` (`NoReply { unit: 2 }`: unit 1 tags good, link still open), `rtu_bad_crc_is_a_comm_result_and_the_next_read_is_good`, `rtu_late_reply_is_drained` (`Delay` past the timeout once), `tcp_timeout_drops_the_link_and_reconnects` (`with_session`, events), `tcp_late_reply_with_old_transaction_id_is_skipped` | timeouts per scheme |
| same (`with_session`) | `reads_from_three_callers_are_one_request` (hook holds one request, three `read_async` of neighbouring registers, one FC03 recorded, each result equals its solo read), `subscriptions_on_neighbouring_tags_share_a_request`, `write_then_read_from_two_callers_reads_the_write`, `idle_tcp_sends_fc08_and_any_reply_counts` (sim answers 01 via `unsupported: [8]`), `keep_alive_address_reads_instead`, `rtu_has_no_keep_alive_by_default`, `close_connections_while_idle_is_found_by_keep_alive` | session integration |
| same, over TCP | `serve_mbap_and_rtu_over_tcp_on_localhost` (`ModbusDriver::new` on `tcp://127.0.0.1:PORT` and `rtu+tcp://127.0.0.1:PORT`) | the real connectors (no serial) |
| `crates/ciplink-sim/tests/faults_and_servers.rs` stays as is; new `ModbusSim` unit tests in `modbus.rs` | `holes_and_limits_answer_exceptions`, `fc22_mask_math`, `unknown_unit_is_0b_over_mbap_and_silent_over_rtu`, `binary_commands` | the simulator |
| `crates/ciplink-server/src/modbus_tests.rs` (or in `modbus.rs`) | `config_protocol_map_file_and_options`, `modbus_without_map_file_is_an_error`, `unknown_protocol_is_an_error`, `catalog_from_the_map` (types, dims, strings, scaled LREAL), `descriptions_from_the_map`, `serves_and_writes_through_the_hub` (server on a `ModbusSim`, read `Tank_Level`, write `Horn` -> FC22) | server |
| `crates/ciplink-ffi/src/modbus_tests.rs` | `modbus_new_checks_path_and_options`, `read_write_async_subscribe_on_a_modbus_handle`, `device_info_tags_and_send_pdu`, `cip_calls_are_unsupported`, `keep_alive_default_depends_on_scheme` | C ABI |
| `crates/ciplink-py/tests/test_modbus.py` (sim binary over TCP, both framings) | `test_read_write_map_and_addresses`, `test_tags_property`, `test_device_info`, `test_send_pdu`, `test_read_async_and_subscribe`, `test_exceptions_are_tag_errors`, `test_bad_path_is_request_error`, `test_keep_alive_auto` | Python |
| `bindings/cpp/tests/test_ciplink.cpp` (`build_and_test.sh` also starts `example_modbus.json`) | `modbus_read_write_and_device_info`, `modbus_async_and_subscription` | C++ |
| `bindings/dotnet/Ciplink.Tests/ModbusTests.cs` | `Read_write_map_tags`, `Async_and_subscribe`, `DeviceInfo_and_SendPdu`, `Options_keep_alive_auto_and_zero` | .NET |
| `tools/sim/run_online_tests.py` | runs the Python Modbus tests against `ciplink-sim --config example_modbus.json` in both framings | online suite |

Golden bytes in the codec tests are written from the Modbus Application Protocol spec v1.1b3 and the serial line
guide v1.02 by hand, not from the driver's output.

## Implementation checklist

Each step leaves every suite green and is its own commit (`git add <paths>`, short subject).

1. `transport.rs`: factor `tcp_stream` (no behaviour change).
2. `modbus/frame.rs`, `modbus/pdu.rs` with their tests.
3. `modbus/address.rs`, `modbus/value.rs` with their tests.
4. `modbus/map.rs` and `tools/sim/example_modbus_map.csv` with tests.
5. `modbus/plan.rs` with tests.
6. `modbus/link.rs` (`Endpoint`, `Link`, connectors; `serialport` dependency with `default-features = false`).
7. `modbus/driver.rs`: `Modbus`, `impl Protocol`, `ModbusOptions`, `DeviceInfo`, `ModbusDriver`; `pub mod modbus`.
8. Simulator: `ciplink-sim/src/modbus.rs`, `main.rs` dispatch and commands, `tools/sim/example_modbus.json`, its unit
   tests.
9. `crates/ciplink-sim/tests/modbus.rs`: the driver and session integration tests.
10. ciplink-server: config fields, `ModbusPlc`, factory dispatch, tests.
11. C ABI: `Driver::Modbus`, `ciplink_modbus_*`, generic arms, header, tests.
12. Python: `_core` class, `python/ciplink/modbus_driver.py`, `test_modbus.py`, `run_online_tests.py`.
13. C++: `Modbus` class, tests, `build_and_test.sh` starts the Modbus sim.
14. .NET: `Modbus.cs`, `Native.cs`, `ModbusTests.cs`.
15. User docs (list above).
16. Full CI run: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
    `cargo test --workspace`, `maturin develop --release` + the three Python suites, `bash bindings/cpp/build_and_test.sh`,
    `cargo build --release -p ciplink-ffi` + `dotnet test bindings/dotnet`, `mkdocs build --strict`.

## Changes made while implementing

What the code does differently from the first draft of this page, and why:

- **Driver unit tests in the crate.** `modbus/driver_tests.rs` runs `ModbusDriver` against a small in-memory device
  (both framings): merging, fallback, write functions, exceptions, RTU timeouts and bad CRCs, MBAP stale replies,
  device info paging, broadcast, keep-alive, and one test of the real TCP connector on 127.0.0.1. The simulator
  integration tests in `crates/ciplink-sim/tests/modbus.rs` still come with step 9; these cover the driver without
  waiting for the simulator.
- **A read or write before `open()`** fails the call with `CommError("not connected: call open() first")`; the
  driver never connects on its own (the session's reconnect does that).
- **RTU reply lengths** also know FC07, 11, 12, 17, 20, 21, 23 and 24, so `send_pdu` works over RTU for the common
  functions the driver does not wrap; any other function over RTU is a `CommError` (its reply cannot be framed).
- **A span longer than the limit** gets blocks of its own and never shares one with a neighbour (simpler
  assembly; the cost is at most one extra request). It is cut between elements (124 registers per block for 32- and
  64-bit types), as many devices refuse a read that starts or ends inside a value, and a value read in two halves
  could be torn.
- **`MapTag::type_name()`** gives the CIP type name a row reads as (`LREAL` when scaled), for the server catalog
  and the bindings' `tags`.
- **End-to-end tests over real sockets.** `crates/ciplink-sim/tests/modbus.rs` runs `ModbusDriver::new`'s
  connector against `ModbusSim::serve` on 127.0.0.1 in both framings (`tcp://` and `rtu+tcp://`), so every test
  also covers the real TCP connector; one test uses the in-memory `ModbusSim::connector`. The simulator exposes
  `link(framing)` (a raw in-memory `ModbusLink`, which implements `Link`) beside `connector(framing)`.
- **`CloseConnections` over TCP** closes the connections whose server thread has started; a test injects it only
  after one answered request, or a connection accepted a moment earlier counts as new.
- **`Display`** of an `rtu://` driver appends `&unit=N` to the serial options:
  `ModbusDriver(rtu://COM3?baud=19200&parity=E&data=8&stop=1&unit=1)`.
- **Bindings' `tags` rows carry `cip_type`** beside `type`: `type` is the map file's type (`float32`), `cip_type`
  the name reads report (`REAL`, `LREAL` when scaled), so a binding can show both without a table of its own.
- **C++ `Modbus::subscribe`** takes `(tags, on_changes, interval_s, deadband)`, the order of `Logix::subscribe`,
  not the draft's.
- **.NET**: the four imports sit in `Modbus.cs` (`partial class Native`), not `Native.cs`, to keep merges with the
  S7 work small; `ModbusDriver.Tags` is a property; `ModbusOptions` drops `connection_size` from its JSON. The .NET
  tests start their own two Modbus simulators (`ModbusSimulators`, collection `modbus`) instead of growing
  `Simulator.cs`.
- **C ABI**: `ciplink_set_socket_timeout` with a negative value (block forever) is `INVALID_ARGUMENT` for Modbus;
  `ciplink_modbus_send_pdu` with an empty PDU is `INVALID_ARGUMENT`.

## Out of scope

Modbus server/slave mode in the driver (the simulator is the only server), ASCII framing, FC23 (read/write
multiple) and file records except through `send_pdu`, writes split across requests, learning which gaps a device
refuses, Modicon 4xxxx references, reloading a map while running, units in the server's tag info (they are in
`map()` and the bindings' `tags`), serial port enumeration, RS-485 echo cancellation, a mock built from a map file.

## Risks to watch

- **Silent TCP gateways.** `tcp://` drops the link on a timeout; a gateway that does not send exception 0B for a dead
  unit makes each read of that unit reconnect, briefly failing the other units' reads (fail fast while
  reconnecting). Workarounds: `rtu+tcp://`, or one driver per unit. If it bites in the field, the next step is a
  per-unit timeout rule, not more options now.
- **Late RTU replies.** Discarding the input before every request and draining after a failure cover the usual
  cases; a late reply that arrives after the next request went out and matches its unit, function and byte count
  would be taken as its reply (once: the request after it discards the real one). Only real hardware shows whether
  this happens.
- **Serial timing on Windows.** t3.5 waits use `thread::sleep`, which is coarse (about 1-15 ms) on Windows; it only
  ever waits longer than needed. Not verified on a real bus; no RS-485 adapter in the lab.
- **FC08 on TCP devices.** Most answer exception 01, which counts as alive. A device that ignores unknown functions
  would time out and reconnect every 30 s idle; `keep_alive_address` is the fix, and the user guide says so.
- **Merge conflicts with the S7 work**: `lib.rs` module lines, the FFI `Driver` enum and match arms, `_core`
  registration, the server's `protocol` field and factory, `mkdocs.yml` nav. All new logic is in new files.
- **`serialport` on the GNU toolchain**: builds with `default-features = false`; confirm it builds on the CI's MSVC and
  Linux runners before step 6 is merged.

# Python API

Generated from the docstrings of the `ciplink` package. The other languages are described in
[Other languages](api.md).

## Drivers

::: ciplink.LogixDriver

::: ciplink.SLCDriver

::: ciplink.CIPDriver

## Modbus

`ModbusDriver` talks Modbus TCP (`tcp://host[:port][?unit=N]`), RTU on a serial port
(`rtu://COM3?baud=19200&parity=E&data=8&stop=1&unit=N`) and RTU frames over TCP for serial gateways
(`rtu+tcp://host[:port][?unit=N]`). It runs on the same session as `LogixDriver`: `read_async`, `write_async`,
`subscribe`, `on_connection`, `connection_state` and `reconnect` work as described below, and reads queued
together (from several tasks, threads or subscriptions) are merged into the fewest Modbus requests.

Modbus has no tag names, so a **map file** gives them, one CSV row per tag:

```csv
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

- `area`: `coil`, `discrete`, `holding`, `input`. `address`: the 0-based protocol address (`301.4` is bit 4 of
  holding register 301). `type`: `bool`, `int16`, `uint16`, `int32`, `uint32`, `int64`, `uint64`, `float32`,
  `float64`, `string` (`count` is its length in characters).
- `order`: `ABCD` (Modbus standard), `CDAB`, `BADC`, `DCBA`; empty: the driver's `word_order`. `unit`: empty for the
  path's unit. A row with `scale`/`offset` reads as `LREAL` (raw x scale + offset) and is written back unscaled.
- `writable` defaults to true for coils and holding registers; discrete and input rows are always read-only.

Anything not in the map is a **plain address**: `area offset[.bit][:type[:order]][{count}][@unit]` with area `co`,
`di`, `hr` or `ir`, e.g. `hr0`, `hr100:float32:cdab`, `hr200:int16{10}`, `hr300:string{20}`, `hr10.4`, `co0{16}`,
`di7@3`. Addresses are 0-based: Modicon `40001` is `hr0`, `30011` is `ir10`.

```python
from ciplink import ModbusDriver

with ModbusDriver("tcp://10.0.0.9?unit=1", "skid.csv") as plc:
    speed, level = plc.read("Pump1_Speed", "Tank_Level")        # Tag objects, as for Logix
    plc.read("Totals[2]", "Drive_Status.5", "hr400:int32")      # elements, bits and plain addresses
    plc.write(("Pump1_Speed", 1450.0), ("Horn", True))          # FC16, then FC22 (mask write)
    print(plc.tags["Tank_Level"]["description"], plc.device_info())
    with plc.subscribe("Tank_Level", "Pump1_Fault", interval=0.5) as sub:
        for tags in sub:
            print([(t.tag, t.value, t.error) for t in tags])
```

A Modbus exception is the tag's `error` (a `TagError` whose `status` is the exception code, e.g. `NOT_FOUND`
for 02 illegal data address); a device that refuses one tag of a merged read gets each of its tags read again
alone, so one bad row never fails its neighbours (for devices with holes in their register map, `max_gap=0`
avoids the retry). `keep_alive="auto"` (the default) sends FC08 after 30 s idle over TCP and nothing on a serial
port; `keep_alive_address="hr0"` reads that address instead, for devices that do not answer FC08.

::: ciplink.ModbusDriver

## Siemens S7-1500 / S7-1200 (S7comm-plus)

`S7PlusDriver` talks S7comm-plus over TLS to CPUs with secure PG/HMI communication (firmware 2.9 and later). It
runs on the same session as `LogixDriver`: `read_async`, `write_async`, `subscribe`, `on_connection`,
`reconnect` and `keep_alive` (15 s by default) work as described below.

```python
from ciplink import S7PlusDriver

with S7PlusDriver("10.20.30.40") as plc:
    print(plc.name, plc.certificate_fingerprint)      # "AB:CD:..." of the PLC certificate
    speed = plc.read("Line1.Conveyor.Speed")         # TIA names: DB.member, arrays by index
    tags = plc.read("Line1.Items[3]", '"Line1".Count', "StartButton")   # PLC tags (I/Q/M) by bare name
    plc.write("Line1.Conveyor.Speed", 2.5)
    plc.write(("Line1.Recipe.Name", "Mix2"), ("Mode", 3))
    print(plc.read("Line1.Stamp").value)              # DTL: "2026-11-18T16:34:46.100000000"
    symbols = plc.tag_list()                          # flat list: name, type, dims, access, crc, HMI flags
    print(plc.get_tag_info("Line1.Items"), plc.get_plc_info())
```

- Reads are batched by the PLC's item limit (100 items per request on most CPUs); a tag that fails has its
  `error` set and the others are unaffected.
- `tags` holds the data blocks and the I, Q and M PLC tags; `data_types` the structure types they use.
  Descriptions (tag comments) are not read.
- The certificate is not verified by default. To pin it, pass the fingerprint seen once:
  `S7PlusDriver("10.20.30.40", tls_fingerprint="AB:CD:...")`; another certificate fails `open` with a
  `CommError`.
- Whole structures (except DTL) and whole BOOL arrays cannot be written; write their members. Elements of
  multi-dimensional arrays are refused (read or write the whole array).

::: ciplink.S7PlusDriver

## Async, subscriptions and connection events

`LogixDriver` and `SLCDriver` do all their I/O on one session thread per driver. The sync methods (`read`,
`write`, ...) are unchanged; they queue their request and wait for it with the GIL released, so threads can share
a driver. On top of them:

```python
import asyncio
from ciplink import LogixDriver

async def main(plc):
    # reads queued while the driver is busy, from any task or thread, go out as one read
    a, b = await asyncio.gather(plc.read_async("Tag1"), plc.read_async("Tag2", "Tag3"))
    await plc.write_async("Tag1", 5)          # writes run in the order they were made, never sent twice

with LogixDriver("10.20.30.100") as plc:
    plc.on_connection(lambda e: print(e.event, e.error, e.attempt, e.delay))
    asyncio.run(main(plc))

    with plc.subscribe("Tag1", "Tag2", interval=0.5, deadband=0.1) as sub:
        for tags in sub:                       # or: async for tags in sub, or callback=f
            print([(t.tag, t.value, t.error) for t in tags])
```

- `read_async` and `write_async` take the arguments of `read` and `write` and give the same results. Cancelling
  the awaiting task does not cancel the request.
- `subscribe` delivers only the tags that changed (the first delivery has every tag). A tag that fails is
  delivered with its `error` set, and again once it reads fine. Keep the `Subscription`: dropping it
  unsubscribes. Closing the driver ends every subscription.
- Callbacks (`callback=`, `on_connection`) run on the driver's callback thread, never on the thread doing I/O, so
  they may call the driver. An exception in a callback is reported as unraisable and dropped.
- `reconnect=True` (default): after an open connection is lost the driver reconnects in the background, waiting
  0.1 s, then doubling up to 10 s between attempts. The request that found the link lost raises its
  `CommError`; while reconnecting, reads, writes and subscription polls raise `CommError("not connected,
  reconnecting: ...")` at once. `close()` stops reconnecting and fails queued requests with
  `CommError("driver closed")`.
- `keep_alive=30.0` (seconds, None for never): after this long without a request the driver sends a small one,
  so an idle connection is not dropped.
- `connection_state` is `'closed'`, `'connected'` or `'reconnecting'`.

::: ciplink.Subscription

::: ciplink.ConnectionEvent

## Results

::: ciplink.Tag

::: ciplink.ErrorKind

::: ciplink.TagError

## Trends

::: ciplink.Trend

::: ciplink.TrendSample

::: ciplink.TrendPen

## Adapter

::: ciplink.adapter.Adapter

## Tag server

::: ciplink.server.TagServer

## Metadata credentials

::: ciplink.LogixMetadataCredentials

## Exceptions

::: ciplink.exceptions
    options:
      show_root_heading: false
      members: [PycommError, CommError, DataError, BufferEmptyError, ResponseError, RequestError]

## Data types

The CIP types used to decode generic message replies (`data_type=`) and to encode request data.

::: ciplink.cip.data_types
    options:
      show_root_heading: false

::: ciplink.custom_types
    options:
      show_root_heading: false

# Python API

Generated from the docstrings of the `ciplink` package. The other languages are described in
[Other languages](api.md).

## Drivers

::: ciplink.LogixDriver

::: ciplink.SLCDriver

::: ciplink.CIPDriver

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

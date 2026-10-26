# Errors

ciplink tells two kinds of failure apart:

- **A failed tag** is data in that tag's result: an error message, an error kind and, for a controller error, the
  CIP status. The other tags of the same call are unaffected.
- **A failed call** (no connection, a broken session, a bad argument) is an exception in Python, C# and C++, an
  `Err` in Rust and a status code in C. Python's exceptions derive from `ciplink.PycommError`; C# throws
  `CiplinkException` and C++ `ciplink::Error`, both carrying the status below.

## Error kinds

| Kind | Meaning |
|---|---|
| `not_found` | no such tag, member, element or bit |
| `bad_value` | the value doesn't fit the type (rejected locally or by the controller) |
| `bad_request` | a malformed request: syntax, element count, a bit of a REAL, path size |
| `access` | the tag exists but isn't accessible: External Access, AOI local tag, keyswitch or password |
| `refused` | nothing was done and it may work later: reload backoff, a state conflict, busy |
| `table_changed` | the tag table changed during the request, so the result was discarded |
| `comm` | the request or reply was lost or couldn't be parsed |
| `device` | any other controller status |
| `other` | not classified |

In Python it's `tag.error_kind` (`ciplink.ErrorKind`, a `str` enum), in Rust `error.kind` (`ciplink::ErrorKind`),
and in C#, C++ and C the lowercase name.

## Call failures

| Failure | Python | Rust (`ciplink::Error`) | C# (`CiplinkException.Status`) | C++ (`ciplink::Error::status()`) | C (`CiplinkStatus`) |
|---|---|---|---|---|---|
| connection: refused, timed out, reset | `CommError` | `Error::Comm` | `Comm` | `CIPLINK_STATUS_COMM` | `CIPLINK_STATUS_COMM` |
| a value couldn't be encoded or decoded | `DataError` | `Error::Data` | `Data` | `CIPLINK_STATUS_DATA` | `CIPLINK_STATUS_DATA` |
| the reply couldn't be used | `ResponseError` | `Error::Response { .. }` | `Response` | `CIPLINK_STATUS_RESPONSE` | `CIPLINK_STATUS_RESPONSE` |
| the request couldn't be built | `RequestError` | `Error::Request { .. }` | `Request` | `CIPLINK_STATUS_REQUEST` | `CIPLINK_STATUS_REQUEST` |
| bad argument | `ValueError` | – (the types prevent it) | `InvalidArgument` | `CIPLINK_STATUS_INVALID_ARGUMENT` | `CIPLINK_STATUS_INVALID_ARGUMENT` |
| the driver kind doesn't support the call | – (no such method) | – (no such method) | `Unsupported` | `CIPLINK_STATUS_UNSUPPORTED` | `CIPLINK_STATUS_UNSUPPORTED` |

In C, `ciplink_last_error(handle)` returns the message of the handle's latest failure, and `ciplink_last_error(NULL)`
the calling thread's latest failure (use it after a constructor, a handle-less call, or with a handle shared by
threads). Free the message with `ciplink_string_free`.

After a connection failure the driver has dropped its connection; open it again to reconnect. Failed requests are
not replayed.

## CIP status codes

A controller error carries the CIP general status (`status`) and the first extended status word (`ext`). Common
general statuses:

| Status | Meaning |
|---|---|
| 0x04 | path segment error (often: tag not found) |
| 0x05 | path destination unknown |
| 0x06 | partial transfer (the driver continues with fragments) |
| 0x08 | service not supported |
| 0x0F | privilege violation |
| 0x10 | device state conflict (e.g. the keyswitch) |
| 0x13 | not enough data |
| 0x1E | embedded service error (one service of a multiple service packet failed) |
| 0xFF | general error; see `ext` (e.g. 0x2105 out of range, 0x2107 type mismatch) |

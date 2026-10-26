# Values and results

## Values by language

| PLC type | Python | Rust (`ciplink::Value`) | C# | C++ (`ciplink::Value`) | C (JSON) |
|---|---|---|---|---|---|
| BOOL | `bool` | `Bool` | `bool` | `bool` | `true` / `false` |
| SINT, INT, DINT, LINT, USINT, UINT, UDINT | `int` | `SInt` … `UDInt` | `long` | `int64_t` | number |
| ULINT | `int` | `ULInt` | `long`, or `ulong` above `long.MaxValue` | `int64_t`, or `uint64_t` above `INT64_MAX` | number |
| REAL, LREAL | `float` | `Real`, `LReal` | `double` | `double` | number with `.` or `e`; `{"$float": "NaN"}` for non-finite values |
| STRING and custom strings | `str` | `String` | `string` | `std::string` | string |
| array, BOOL array | `list` | `Array` | `object?[]` | `ciplink::Array` | array |
| UDT, AOI, built-in structure | `dict` | `Struct` (an `IndexMap`, members in order) | `Dictionary<string, object?>` | `ciplink::Struct` | object, members in order |
| BYTE, WORD, DWORD, LWORD | `list` of `bool`, least significant bit first | `Array` of `Bool` | `object?[]` of `bool` | `ciplink::Array` of `bool` | array of booleans |
| raw bytes (generic message replies) | `bytes` | `Bytes` | `byte[]` | `ciplink::Bytes` | `{"$bytes": "<hex>"}` |

Writes accept the same forms. Any number is accepted for a REAL and any integer for an integer type; the driver
checks the range against the tag's type before sending. In C#, any `IEnumerable` works for an array and any
`IDictionary` for a structure.

## Results

Every read, write, description and generic message returns one result per item:

| Field | Python `Tag` | Rust `TagResult` | C# `Tag` | C++ `ciplink::Tag` | C JSON |
|---|---|---|---|---|---|
| name | `tag` | `tag` | `Name` | `tag` | `"tag"` |
| value (none on error) | `value` | `value: Option<Value>` | `Value` | `value` (null) | `"value"` |
| data type | `type` | `data_type` | `DataType` | `type` | `"type"` |
| error message | `error` | `error: Option<TagError>` | `Error` | `error->message` | `"error"."message"` |
| error kind | `error_kind` | `error.kind` | `ErrorKind` | `error->kind` | `"error"."kind"` |
| CIP status, extended status | `error.status`, `error.ext` | `error.status`, `error.ext` | `Status`, `ExtendedStatus` | `error->status`, `error->ext` | `"error"."status"`, `"error"."ext"` |
| success | `bool(tag)` | `is_ok()` | `IsOk` | `bool(tag)` | `"error"` is null |

In Python, reading or writing one tag returns one `Tag` and several return a list. In the other languages the calls
taking several tags return a list, and single-tag shortcuts (C# `Read(string)`, C++ `read_tag`, `write_tag`) return
one result.

## The C ABI's JSON

The C functions take and return UTF-8 JSON text. Every `char*` the library returns belongs to the caller and is freed
with `ciplink_string_free`; byte buffers from `ciplink_send_connected` and `ciplink_send_unconnected` are freed
with `ciplink_bytes_free`. A tag result is:

```json
{"tag": "Counter", "value": 42, "type": "DINT", "error": null}
{"tag": "NoSuchTag", "value": null, "type": null,
 "error": {"message": "...", "kind": "not_found", "status": 4, "ext": 0}}
```

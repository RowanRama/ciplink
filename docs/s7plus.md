# Siemens S7-1500 and S7-1200

`S7PlusDriver` reads and writes the symbolic tags of Siemens S7-1500 and S7-1200 CPUs over S7comm-plus, the
protocol TIA Portal and Siemens HMIs use. It needs **secure PG/HMI communication** (TLS 1.3, CPU firmware 2.9 or
later; port 102). It runs on the same session as `LogixDriver`, so async calls, subscriptions, connection events,
reconnect and keep-alive work as described in [Async, subscriptions and reconnect](sessions.md).

All names below are invented.

=== "Python"

    ```python
    from ciplink import S7PlusDriver

    with S7PlusDriver("192.0.2.30") as plc:
        print(plc.name, plc.certificate_fingerprint)     # "PLC_Line1" "AB:CD:..." (pin it, see below)
        print(plc.read("Line1.Conveyor.Speed"))          # Tag(tag='Line1.Conveyor.Speed', value=1.5, type='REAL', ...)
        tags = plc.read("Line1.Items[3]", "Line1.Stamp", "StartButton")
        plc.write(("Line1.Conveyor.Speed", 2.5), ("Line1.Label", "Mix2"))
        print(plc.get_plc_info())                        # name, order number, firmware, TIA version, limits
    ```

=== "Rust"

    ```rust
    use ciplink::s7plus::{S7PlusDriver, S7PlusOptions};
    use ciplink::Value;

    let plc = S7PlusDriver::new("192.0.2.30", S7PlusOptions::default())?;
    plc.open()?;
    println!("{:?}", plc.certificate_fingerprint());
    for tag in plc.read(&["Line1.Conveyor.Speed", "Line1.Items[3]", "StartButton"])? {
        println!("{} = {:?} ({:?})", tag.tag, tag.value, tag.data_type);
    }
    plc.write(&[("Line1.Conveyor.Speed", Value::Real(2.5))])?;
    ```

=== "C#"

    ```csharp
    using Ciplink;

    using var plc = new S7PlusDriver("192.0.2.30", new S7PlusOptions());
    plc.Open();
    Console.WriteLine(plc.CertificateFingerprint);
    foreach (Tag tag in plc.Read("Line1.Conveyor.Speed", "Line1.Items[3]", "StartButton"))
        Console.WriteLine($"{tag.Name} = {tag.Value}");
    plc.Write(("Line1.Conveyor.Speed", 2.5), ("Line1.Label", "Mix2"));
    ```

=== "C++"

    ```cpp
    #include <iostream>
    #include "ciplink.hpp"

    ciplink::S7Plus plc("192.0.2.30");
    plc.open();
    for (const ciplink::Tag& tag : plc.read({"Line1.Conveyor.Speed", "Line1.Items[3]", "StartButton"}))
        std::cout << tag.tag << " = " << ciplink::to_json(tag.value) << "\n";
    plc.write_tag("Line1.Conveyor.Speed", 2.5);
    ```

=== "C"

    ```c
    #include <stdio.h>
    #include "ciplink.h"

    CiplinkDriver *plc = NULL;
    ciplink_s7plus_new("192.0.2.30", NULL, &plc);
    if (ciplink_open(plc) == CIPLINK_STATUS_OK) {
        const char *tags[] = {"Line1.Conveyor.Speed", "Line1.Items[3]", "StartButton"};
        char *json = NULL;
        if (ciplink_read(plc, tags, 3, &json) == CIPLINK_STATUS_OK) {
            printf("%s\n", json);
            ciplink_string_free(json);
        }
    }
    ciplink_driver_free(plc);
    ```

## Tag names

Names are the ones TIA Portal shows:

| Name | Means |
|---|---|
| `Line1.Count` | member `Count` of data block `Line1` |
| `Line1.Conveyor.Speed` | a member of a structure, UDT or FB instance, any depth |
| `"Line1".Conveyor` | double quotes around a segment are accepted and stripped |
| `Line1.Items[3]` | an array element, by its declared index (`ARRAY[1..50]` starts at 1) |
| `Line1.Recipes[2].Speed` | a member of an element of an array of structures |
| `Line1.Conveyor`, `Line1.Recipes` | a whole structure or array of structures: a dict / list of dicts |
| `StartButton` | a PLC tag of the I, Q or M area, by its bare name |

An exact match is tried first, then one that ignores case. A whole data block is not a tag: read its members.

## Tag list and CPU information

`open` browses the symbol table (a few seconds for a large program; `init_tags=False` defers it to the first
request that needs it). Then, without further I/O:

- `tags` holds the data blocks and the I, Q and M PLC tags, `data_types` the structure types they use (UDT names
  are not sent by the PLC: a UDT is named by its type ID, `0x91000005`);
- `tag_list()` is the flat list an HMI tag browser shows: every member of every structure, elementary arrays as
  one entry, with type, dimensions, access path, CRC and the HMI flags (visible, accessible, read-only);
- `get_tag_info(name)` resolves one name the same way.

`refresh_tags()` browses again and says whether anything changed. A program download is noticed on its own: the
PLC refuses a stale address (symbol CRC), the driver browses once and the read is retried.

`get_plc_info()` returns the CPU name, order number, serial number, hardware and firmware version, the TIA Portal
version and project name, the protection level and the read / write item limits.

## Values

| S7 type | Value |
|---|---|
| BOOL | bool |
| BYTE, WORD, DWORD, LWORD | unsigned integer (USInt, UInt, UDInt, ULInt) |
| SINT, INT, DINT, LINT, USINT, UINT, UDINT, ULINT | integer of that size |
| REAL, LREAL | float |
| CHAR, WCHAR, STRING, WSTRING | string |
| TIME, S5TIME | milliseconds (DInt) |
| LTIME | nanoseconds (LInt) |
| DATE, TIME_OF_DAY, LTOD, DATE_AND_TIME, LDT, DTL | ISO 8601 string in the PLC's clock: `"2026-11-18T16:34:46.100000000"` |
| ANY | bytes |
| HW_ANY, HW_IO, ..., DB_ANY | unsigned integer |
| structure, UDT, IEC_TIMER, system types | dict of the members |
| arrays | list (a BOOL array as one bool per element) |

A result's type is the S7 type name: `"WORD"`, `"DTL"`, `"REAL[50]"`, `"DINT[4,16]"`.

Writes take the same forms. Not writable: whole structures (except DTL), whole arrays of structures, STRING,
WSTRING, DATE_AND_TIME or DTL, and whole BOOL arrays; write their members or elements instead. A value that does
not fit the type is that tag's `BadValue` error; the other tags of the call are still written.

## Batching and limits

- Reads and writes are split by the PLC's item limit (100 items per request on the CPUs seen), and reads queued
  while one is in flight go out together.
- A tag that fails has its own error (unknown name, index out of range, refused by the PLC); the other tags are
  unaffected.
- Elements of multi-dimensional arrays (`Line1.Grid[2,5]`) are refused: read or write the whole array.
- A CPU may refuse a whole array of structures (seen for a large one in an optimized block) with an item error;
  read its elements instead.

## TLS and certificate pinning

The PLC's certificate is not verified by default (CPUs use self-signed certificates). The driver exposes the
SHA-256 fingerprint of the certificate it was shown, so you can pin it: connect once, check the fingerprint
against the one in TIA Portal or the CPU's web server, and pass it from then on.

```python
plc = S7PlusDriver("192.0.2.30", tls_fingerprint="AB:CD:EF:...")   # hex, with or without ':'
```

With a pin, a different certificate fails `open` with a `CommError` before anything is sent.

## Not supported

The legacy non-TLS login (firmware before 2.9), password-protected access (legitimation), tag comments
(descriptions are always empty), Siemens trends and traces, alarms, and CPU start / stop or downloads.

## Testing without a PLC

The [simulator](simulator.md) plays an S7-1500 when its configuration's top-level key is `s7plus`:

```bash
ciplink-sim --config tools/sim/example_s7plus.json --port 1102
```

and `S7PlusDriver("127.0.0.1:1102")` talks to it like to a CPU.

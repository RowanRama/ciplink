# Ciplink

Read and write tags on Allen-Bradley PLCs over EtherNet/IP from .NET.

Ciplink is the .NET binding of [ciplink](https://github.com/RowanRama/ciplink), a fork of pycomm3 rebuilt on a
shared Rust core. The native library ships inside this package for Windows x64, Linux x64 and macOS (Apple
Silicon and Intel), so there is nothing else to install.

- **Controllers:** ControlLogix, CompactLogix, GuardLogix and Micro800 (`LogixDriver`); SLC 500 and MicroLogix
  (`SlcDriver`); generic CIP messaging with any EtherNet/IP device (`CipDriver`).
- **Tags:** atomic types, arrays, strings, UDTs (whole or by member), AOIs, bits and BOOL arrays. Many tags
  share each packet, and large values are fragmented automatically.
- **Online-edit safe:** tags are addressed by instance ID and checked against the controller's tag-table version,
  so an online edit never silently returns the wrong tag.
- **Thread-safe** drivers, released with `Dispose` (`using`).

## Install

```sh
dotnet add package Ciplink
```

Requires .NET 8 or later.

## Quick start

```csharp
using Ciplink;

using var plc = new LogixDriver("192.0.2.10");   // IP, IP/slot, or a full route such as 192.0.2.10/bp/2
plc.Open();

Tag counter = plc.Read("Counter");
Console.WriteLine(counter.IsOk ? $"{counter.Name} = {counter.Value}" : $"{counter.ErrorKind}: {counter.Error}");

foreach (Tag tag in plc.Read("Tank.Level", "Recipe{10}", "Motor.Running"))
    Console.WriteLine($"{tag.Name} ({tag.DataType}) = {tag.Value}");

plc.Write("Counter", 0);
plc.Write(("Tank.Setpoint", 75.5), ("Motor.Start", true));
```

Every read and write returns one `Tag` per request. A failure is reported on that tag through `Error` and
`ErrorKind` (NotFound, BadValue, Access and so on) instead of being thrown, so one bad tag never fails a whole
batch.

Values map to .NET types as `long` / `ulong` / `double` / `bool` / `string` for atomic types, `object?[]` for
arrays, and `Dictionary<string, object?>` for UDTs. `ReadAsync` and `WriteAsync` are also available.

## More

- Documentation, with examples in C# and every other language: https://rowanrama.github.io/ciplink/
- Source and issues: https://github.com/RowanRama/ciplink
- License: MIT

# ciplink

EtherNet/IP (CIP) client driver for Allen-Bradley Logix, Micro800 and SLC/MicroLogix PLCs: the Rust core of the
[ciplink](https://github.com/RowanRama/ciplink) Python package (a pycomm3 fork), also bound to C, C++ and C#.
The [documentation](https://rowanrama.github.io/ciplink/) has guides with Rust examples next to the other languages'.

```rust
use ciplink::logix::driver::{LogixDriver, LogixOptions};
use ciplink::Value;

fn main() -> ciplink::Result<()> {
    let plc = LogixDriver::new("192.0.2.100/1", LogixOptions::default())?;
    plc.open()?;
    for t in plc.read(&["Counter", "Recipe.Speed"])? {
        match (&t.value, &t.error) {
            (Some(value), None) => println!("{} = {value:?}", t.tag),
            (_, error) => println!("{}: {error:?}", t.tag),
        }
    }
    plc.write(&[("Setpoint", Value::Real(12.5))])?;
    plc.close()
}
```

- Explicit messaging over TCP 44818: unconnected and class 3 connected (Forward Open and Large Forward Open).
- Logix: tag list upload (or lazy lookups), reads and writes of any tag with request packing and fragmentation,
  symbol instance addressing, tag table change detection, a tag cache file, descriptions, PLC time.
- SLC 500 / MicroLogix data files through PCCC; generic CIP messages to any device.
- Blocking I/O on std threads; a driver can be shared between threads (one request at a time). Logs through `log`.
- A failure on one tag is data in that tag's result (`TagResult::error`, with an `ErrorKind`), not an `Err` for the
  whole call.

The `ciplink-sim` crate of the same repository serves a simulated controller for tests.

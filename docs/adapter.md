# The adapter: ciplink as an I/O device

By default ciplink is a client: it connects to PLCs and reads and writes their tags, and it listens on no
EtherNet/IP port. The adapter is the opposite role, and it is opt-in. An application that starts one becomes an
EtherNet/IP device that a Logix controller can find in RSWho and own in its I/O tree, like a camera or an I/O
module. Nothing listens until the application calls `Adapter::start`, so programs that only use the client never
see it.

Use it when a ciplink application is a service host the PLC should talk to directly, e.g. a vision station that
takes a trigger from the PLC and returns results every RPI.

!!! note "Rust and Python for now"
    The adapter is in the Rust core (`ciplink::adapter`) and in Python (`ciplink.adapter`); the C, C++ and C#
    bindings follow.

## What it does

- **Class 1 I/O.** Answers Forward Open from a scanner. It produces input assemblies to the PLC every RPI
  (T→O) and consumes output assemblies from it (O→T, with run/idle). The adapter accepts exclusive-owner,
  input-only and listen-only connections, with multicast or point-to-point T→O. The I/O runs on its own threads,
  so a slow application never makes a packet late.
- **Explicit messages.** Get/Set of assembly data, and the Identity, Port, TCP/IP Interface and Ethernet Link
  objects that RSWho and Studio 5000 read.
- **Discovery.** Answers ListIdentity, so the device shows up when RSWho, Linx or ciplink's `browse_port` and
  `scan_port` browse its subnet.
- **EDS upload.** The File object serves the EDS, if the application gives one, so "Upload EDS from device"
  works.
- **The ciplink object** (class 0x64). It marks the device as ciplink and describes the application, so
  ciplink's own browser can show it as a ciplink device.

The application reads and writes assembly data and takes events from a queue (`next_event`): connection opened,
closed or timed out, new output data, and new config data.

=== "Rust"

    ```rust
    use ciplink::adapter::{Adapter, AdapterConfig, Assembly, Event};
    use std::time::Duration;

    let adapter = Adapter::start(AdapterConfig {
        assemblies: vec![Assembly::input(100, 148), Assembly::output(150, 32), Assembly::config(199, 0)],
        app_name: "Station".into(),
        ..AdapterConfig::default()
    })?;
    adapter.set_input(100, &[1, 2, 3])?;
    while let Some(event) = adapter.next_event(Some(Duration::from_secs(1))) {
        match event {
            Event::Opened(conn) => println!("{:?} opened by {}", conn.kind, conn.originator),
            Event::Output { instance } => {
                let output = adapter.output(instance)?;
                println!("trigger {} (run {})", output.data[0] & 1, output.run);
            }
            Event::TimedOut(conn) => println!("{} stopped talking", conn.originator),
            _ => {}
        }
    }
    ```

=== "Python"

    ```python
    from ciplink.adapter import Adapter

    with Adapter(inputs={100: 148}, outputs={150: 32}, configs={199: 0}, app_name="Station") as adapter:
        adapter.set_input(100, bytes([1, 2, 3]))
        while True:
            event = adapter.next_event(1.0)  # a dict, or None after 1 s
            if event and event["event"] == "opened":
                c = event["connection"]
                print(c["kind"], "opened by", c["originator"])
            elif event and event["event"] == "output":
                data, run = adapter.output(event["instance"])
                print("trigger", data[0] & 1, "run", run)
    ```

    The I/O runs on the core's threads, so a slow Python loop never makes a packet late. `identity={...}` sets
    the Identity object, RPIs are in seconds, and the other keywords are those of `AdapterConfig`.

## Adding it to a Logix project

You can add the adapter to the I/O tree in either of two ways:

1. **Generic Ethernet Module (no EDS).** Add an ETHERNET-MODULE and enter the instance numbers and sizes:
   input 100, output 150, configuration 199 (size 0 if there is no config data). Sizes are in the module's data
   format. Size the connection to the assembly sizes in `AdapterConfig`; the adapter refuses the connection when
   they differ.
2. **With an EDS.** Register the EDS in Studio 5000 (EDS Hardware Installation Tool, or upload it from the device
   in RSWho). It then appears as a named module with its connections listed. An EDS must use its vendor's own
   ODVA vendor ID; the default `vendor_id` 0 is a placeholder.

Input-only and listen-only connections use the heartbeat instances 238 and 237 as their O→T point (configurable
as `input_only_heartbeat` and `listen_only_heartbeat`). An EDS has to name the same numbers.

Each output assembly has one owner at a time, so two controllers can each own a different output assembly. If a
second controller opens the same output, it is refused with 0x0106 (ownership conflict). A controller that
reconnects before its old connection has timed out also gets this refusal, until the old connection times out.

## One EtherNet/IP device per IP address

**The adapter cannot run on the same IP address as another program that listens on the EtherNet/IP ports.**
On a typical PC, this rules out:

| Program | Why it clashes |
|---|---|
| FactoryTalk Linx, RSLinx Classic | listen on TCP/UDP 44818 (and often UDP 2222) on every network card |
| `ciplink-sim` | a simulated controller, listening on 44818 |
| a second adapter | each adapter is one device |

The ports are fixed by the protocol, not chosen by ciplink:

- A controller always opens its session to **TCP 44818** of the module's IP address, and sends class 1 output
  data to **UDP 2222**. A Logix module definition has an IP address but no port number, so there is no way to
  point the PLC at "the adapter on port 44819".
- RSWho and ListIdentity broadcast to **UDP 44818**, so only one program per address can answer them.
- Only one program can listen on a given address and port. If two could, the operating system would hand each
  incoming connection or packet to just one of them, and the PLC would reach Linx when it wanted the adapter.

If a port is taken, `Adapter::start` fails with an error that names the address and suggests Linx as the likely
holder. Windows reports this as "access denied" when the other program holds the port exclusively.

What still works on the same PC:

- the ciplink client (drivers, browsing, trends) and `ciplink-server`. They connect out to PLCs from temporary
  ports and do not listen on 44818.
- Studio 5000 and Linx on **another** PC, browsing to and going online with the controller that owns the adapter.

If a PC needs both Linx and the adapter, give the adapter its own IP address: a second network card, or a second
address on the plant card. Set `bind` to that address. Whether Linx leaves that address free depends on how it
binds its sockets (it may take every address), so test it on the target PC before relying on it. Running the
adapter on its own PC or VM avoids the question.

## Network notes

- `bind` picks the network card, which is also the card multicast T→O data leaves from. Set it on PCs with more
  than one card. `0.0.0.0` listens on all of them, but multicast then leaves from whichever card the OS picks.
- The firewall must allow TCP 44818 and UDP 44818 and 2222 inbound, plus multicast to 239.192.x.x if the
  connection uses multicast T→O.
- The adapter accepts RPIs from 2 ms to 3200 ms by default (`rpi_min` and `rpi_max`).

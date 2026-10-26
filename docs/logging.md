# Logging

The driver core logs connections, sessions, Forward Opens, tag list uploads and every generic message, and at its
most verbose level the bytes of every packet sent and received. A verbose log is the most useful thing to attach to
a bug report.

=== "Python"

    The records go to Python's standard `logging`, under the same logger names as the Python driver's
    (`ciplink.cip_driver.CIPDriver`, `ciplink.logix_driver.LogixDriver` ...). `configure_default_logger` sets up the
    `ciplink` logger (pass `logger=""` to configure the root logger instead):

    ```python
    from ciplink.logger import configure_default_logger, LOG_VERBOSE

    configure_default_logger(filename="ciplink.log")                     # INFO, to the console and a file
    configure_default_logger(level=LOG_VERBOSE, filename="ciplink.log")  # also every packet
    ```

    ```text
    2026-10-26 14:37:41,389 [DEBUG] ciplink.cip_driver.CIPDriver.open(): Opening connection to 192.0.2.10
    2026-10-26 14:37:41,398 [INFO] ciplink.cip_driver.CIPDriver.open(): Session=184719106 has been registered.
    2026-10-26 14:37:41,398 [INFO] ciplink.logix_driver.LogixDriver.open(): Initializing driver...
    ```

=== "Rust"

    The core logs through the [`log`](https://docs.rs/log) facade and never installs a logger itself. Add one, such
    as `env_logger`:

    ```rust
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("ciplink=info")).init();
    ```

    `RUST_LOG=ciplink=trace` includes every packet.

=== "C#"

    The native library doesn't log through .NET. Use the Python package or a Rust program with a logger to capture
    a packet log of the same requests.

=== "C++"

    The native library doesn't log through C++ streams. Use the Python package or a Rust program with a logger to
    capture a packet log of the same requests.

=== "C"

    The native library doesn't write a log. Use the Python package or a Rust program with a logger to capture a
    packet log of the same requests.

Every binding sends the same requests in the same order, so a log taken from Python shows what a C# or C program
sends too.

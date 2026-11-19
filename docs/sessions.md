# Async, subscriptions and reconnect

A Logix or SLC driver does all of its I/O on one session thread of its own. Every call, from any thread, queues a
request for it:

- **Sync calls** (`read`, `write`, `get_tag_list`, ...) are unchanged: they queue their request and wait for it.
- **Async calls** (`read_async`, `write_async`) queue a read or write and return at once: a handle, a future, a
  task or an awaitable, depending on the language.
- **Packing.** Reads waiting in the queue together, from any thread, async call or subscription, go out as one
  read, and a tag asked for twice is read once. Each caller gets its own results. A caller alone sends exactly what
  it sent before. SLC drivers keep each caller's addresses in a request of their own, because one bad address fails
  a whole SLC read.
- **Order.** A write is never merged and never moved past anything queued before it. Every other call (tag list,
  descriptions, trends, generic messages, ...) also runs alone, in queue order.

The plain CIP driver has none of this: it has no async calls, subscriptions or reconnect.

## Reconnect

On by default. After an open connection is lost, the driver reconnects in the background: first after 100 ms,
then doubling the wait up to 10 s, until it is back or the driver is closed. When the controller's tag table did not
change, the tag list uploaded before is kept, so a reconnect uploads nothing.

- The request that found the link lost fails with its connection error. A write is **never sent again**: check
  the value and write it again yourself if you need to.
- **While reconnecting, requests fail fast.** Reads, writes and subscription polls fail at once with a connection
  error `not connected, reconnecting: <cause>`. They do not wait for the link.
- `close()` stops reconnecting. Requests still queued fail with `driver closed`; the request in flight finishes
  first.
- Connection events tell you what happens: `connected` (opened, or reconnected), `disconnected` with the error,
  and `reconnecting` with the attempt number and the wait before it. A failed `open()` and `close()` send none.
- `connection_state` is closed, connected or reconnecting, and never waits.

Turn it off with `reconnect=False` (Python), `"reconnect": false` (C, C++), `Reconnect = false` (C#) or
`SessionOptions { reconnect: false, .. }` (Rust); a lost link then leaves the driver closed, as before.

## Keep-alive

Every TCP connection has TCP keep-alive on (first probe after 10 s idle, then every 5 s). On top of that, after 30 s
without a request the driver sends a small request (Identity Get Attribute Single, vendor ID) on its connection,
so a controller, firewall or NAT doesn't drop an idle connection, and a link lost while idle is found (and
reconnected) before your next request. Set the time with `keep_alive` (seconds; `None`/`null` for never).

## Subscriptions

`subscribe(tags, interval, deadband)` reads the tags every interval and delivers the ones that changed:

- The first delivery has every tag. Later ones have the tags whose value or error changed.
- `deadband` (optional): a numeric tag that moved less than this since its last delivered value is not delivered.
- Quality is each tag's error: none is good. A failed read or a lost link is delivered as each tag's error (kind
  `comm`), once, and the tag again when it reads fine.
- A slow consumer never falls behind: it gets the latest result of each tag that changed.
- Subscriptions start at a random point of their interval, so they don't all poll at once, and their reads join
  the same queue as everything else, so they pack with other callers' reads.
- Drop, close or dispose the subscription to stop it. Closing the driver ends every subscription.

## Where callbacks run

Every callback of a driver (subscription changes, connection events, completion callbacks) runs on that driver's
own callback thread: one at a time, in order, never on the thread that does the I/O and never on the thread that
made the call. A callback may call the driver, blocking calls included, and may close it. Keep callbacks short:
the driver's other callbacks wait for them. An error raised by a callback is reported and dropped.

=== "Python"

    ```python
    import asyncio
    from ciplink import LogixDriver

    with LogixDriver("192.0.2.10", keep_alive=15.0) as plc:      # reconnect=True by default
        plc.on_connection(lambda e: print(e.event, e.error, e.attempt, e.delay))
        print(plc.connection_state)                            # 'connected'

        async def main():
            a, b = await asyncio.gather(plc.read_async("Counter"), plc.read_async("Level", "Setpoint"))
            await plc.write_async(("Setpoint", 75.5))
            with plc.subscribe("Counter", "Level", interval=0.5) as sub:
                async for tags in sub:                         # the tags that changed
                    print([(t.tag, t.value, t.error) for t in tags])

        asyncio.run(main())

        # blocking iterator, or a callback on the callback thread
        with plc.subscribe("Counter", interval=0.5, deadband=1, callback=print):
            ...
    ```

    `read_async` and `write_async` take the arguments of `read` and `write` and give the same results.
    Cancelling the awaiting task does not cancel the request. Every blocking call (`read`, iterating a
    subscription, `close`) waits with the GIL released, and callbacks take the GIL on the callback thread, so a
    callback can't deadlock with a thread that holds the GIL.

=== "Rust"

    ```rust
    use std::time::Duration;
    use ciplink::logix::driver::{LogixDriver, LogixOptions};
    use ciplink::session::{ConnectionEvent, SessionOptions, SubscribeOptions};
    use ciplink::transport::tcp_connector;
    use ciplink::Value;

    // new() reconnects and keeps alive with SessionOptions::default(); with_session sets them
    let session = SessionOptions { keep_alive: Some(Duration::from_secs(15)), ..SessionOptions::default() };
    let plc = LogixDriver::with_session("192.0.2.10", LogixOptions::default(), session, tcp_connector())?;
    plc.set_connection_callback(Some(Box::new(|e: &ConnectionEvent| eprintln!("{e:?}"))));
    plc.open()?;

    // Handle<T>: wait(), wait_timeout(), try_take(), on_complete(), or .await in any async runtime
    let a = plc.read_async(&["Counter"]);
    let b = plc.read_async(&["Level", "Setpoint"]);
    let (a, b) = (a.wait()?, b.wait()?);
    plc.write_async(&[("Setpoint", Value::Real(75.5))]).wait()?;

    let sub = plc.subscribe(
        &["Counter", "Level"],
        SubscribeOptions { interval: Duration::from_millis(500), deadband: Some(0.1) },
    )?;
    while let Some(changes) = sub.recv() {             // or recv_timeout, try_recv, on_changes(callback)
        for t in &changes.results {
            println!("{} {:?} {:?}", t.tag, t.value, t.error);
        }
    }
    ```

    The session types are in `ciplink::session`; `SlcDriver` has the same methods. `with_connector` builds a
    driver without reconnect or keep-alive (`SessionOptions::off()`). The crate has no async runtime dependency:
    a `Handle` is a plain `Future` that stores its waker.

=== "C#"

    ```csharp
    using var plc = new LogixDriver("192.0.2.10", new LogixOptions { KeepAlive = TimeSpan.FromSeconds(15) });
    plc.ConnectionChanged += (_, e) => Console.WriteLine(e);   // Event, Error, Attempt, Delay
    plc.Open();

    IReadOnlyList<Tag>[] both = await Task.WhenAll(plc.ReadAsync("Counter"), plc.ReadAsync("Level", "Setpoint"));
    await plc.WriteAsync(("Setpoint", 75.5));

    using Subscription sub = plc.Subscribe(new[] { "Counter", "Level" }, TimeSpan.FromMilliseconds(500), deadband: 0.1);
    await foreach (IReadOnlyList<Tag> changed in sub)            // or the Changed event (pass changed: to get the first values)
        foreach (Tag t in changed)
            Console.WriteLine(t.IsOk ? $"{t.Name} = {t.Value}" : $"{t.Name}: {t.Error}");
    ```

    `ReadAsync` and `WriteAsync` hold no thread while they wait: the native callback completes the task, and
    `await` continues on the thread pool, never on the driver's callback thread. A `CancellationToken` cancels
    the task only; the request still runs. `Reconnect`, `ReconnectMin`, `ReconnectMax` and `KeepAlive` are on
    `DriverOptions`.

=== "C++"

    ```cpp
    ciplink::Logix plc("192.0.2.10", R"({"keep_alive": 15})");
    plc.on_connection([](const ciplink::ConnectionEvent& e) { std::cerr << e.event << " " << e.error << "\n"; });
    plc.open();

    std::future<std::vector<ciplink::Tag>> a = plc.read_async({"Counter"});
    std::future<std::vector<ciplink::Tag>> b = plc.read_async({"Level", "Setpoint"});
    auto counter = a.get(), rest = b.get();
    plc.write_async({{"Setpoint", 75.5}}).get();

    ciplink::Subscription sub = plc.subscribe({"Counter", "Level"}, [](const std::vector<ciplink::Tag>& changed) {
        for (auto& t : changed) std::cout << t.tag << "\n";
    }, 0.5);
    // destroying `sub` unsubscribes; once that returns, the function is not running and won't run again
    ```

=== "C"

    ```c
    static void on_done(void *user, CiplinkStatus status, const char *json) { /* result array, or the error */ }
    static void on_changes(void *user, const char *results_json) { /* the tags that changed */ }
    static void on_connection(void *user, const char *event_json) { /* {"event":"reconnecting","attempt":1,...} */ }

    CiplinkDriver *plc = NULL;
    ciplink_logix_new("192.0.2.10", "{\"keep_alive\": 15}", &plc);
    ciplink_set_connection_callback(plc, on_connection, NULL);
    ciplink_open(plc);

    const char *tags[] = {"Counter", "Level"};
    CiplinkRequest *req = NULL;
    ciplink_read_async(plc, tags, 2, on_done, NULL, &req);    /* done fires once, on the callback thread */
    char *json = NULL;
    if (ciplink_request_wait(req, 1000, &json) == CIPLINK_STATUS_OK)   /* or poll ciplink_request_done */
        ciplink_string_free(json);
    ciplink_request_free(req);

    CiplinkSubscription *sub = NULL;
    ciplink_subscribe(plc, tags, 2, "{\"interval\": 0.5, \"deadband\": null}", on_changes, NULL, &sub);
    /* ... */
    ciplink_subscription_free(sub);   /* once it returns, on_changes won't run again */
    ciplink_driver_free(plc);         /* closes; pending requests' done fires with "driver closed" */
    ```

    `ciplink_request_wait` takes a timeout in ms (negative waits forever); `CIPLINK_STATUS_TIMEOUT` leaves the
    request pending. A request handle can be freed at any time: the request still runs and `done` still fires.
    `done` can run before `ciplink_read_async` returns, so set up `user` first. Callbacks must not unwind.

The full call lists are in [Python API](api-python.md#async-subscriptions-and-connection-events) and
[Other languages](api.md#async-calls-subscriptions-and-connection-events-c-and-c).

## What a real controller still has to confirm

These are tested against the simulator only:

- that a real controller, switch and firewall keep a 30 s idle connection open with the keep-alive request, and
  how long a pulled cable takes to show up as `disconnected` while idle (TCP keep-alive plus the socket timeout);
- reconnect after a real cable pull or controller restart, including a reconnect with the tag table unchanged
  uploading nothing;
- the SLC keep-alive request on a real SLC or MicroLogix (any reply, an error status included, counts as alive).

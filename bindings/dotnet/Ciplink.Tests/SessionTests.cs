using System.Collections.Concurrent;

namespace Ciplink.Tests;

/// <summary>The session API: real async requests, packing across callers, subscriptions, connection events, close.</summary>
[Collection("sim")]
public sealed class SessionTests
{
    private static readonly TimeSpan Long = TimeSpan.FromSeconds(10);

    private readonly Simulators _sim;

    public SessionTests(Simulators sim) => _sim = sim;

    private LogixDriver OpenPlc(LogixOptions? options = null)
    {
        var plc = new LogixDriver(_sim.LogixPath, options);
        plc.Open();
        return plc;
    }

    /// <summary>Runs <paramref name="body"/> with every reply of the Logix simulator delayed, then clears the fault.</summary>
    private async Task WithDelay(int ms, Func<Task> body)
    {
        _sim.Command($"{{\"cmd\": \"fault\", \"fault\": {{\"delay_ms\": {ms}}}}}");
        try
        {
            await body();
        }
        finally
        {
            _sim.Command("{\"cmd\": \"clear_faults\"}");
        }
    }

    private static void WaitFor(Func<bool> condition, string what)
    {
        DateTime end = DateTime.UtcNow + Long;
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < end, "timed out waiting for " + what);
            Thread.Sleep(10);
        }
    }

    [Fact]
    public async Task ReadAsync_returns_at_once_and_concurrent_reads_are_packed()
    {
        using var plc = OpenPlc();
        plc.Write(("uint1", 11), ("usint1", (short)22));
        await WithDelay(50, async () =>
        {
            long before = _sim.Requests();
            var tasks = new List<Task<IReadOnlyList<Tag>>>();
            for (int i = 0; i < 40; i++)
            {
                tasks.Add(i % 2 == 0 ? plc.ReadAsync("uint1") : plc.ReadAsync("usint1", "uint1"));
            }
            // queued, not run on a pool thread: nothing can be back before the 50 ms delay
            Assert.False(tasks[0].IsCompleted);
            IReadOnlyList<Tag>[] results = await Task.WhenAll(tasks).WaitAsync(Long);
            for (int i = 0; i < results.Length; i++)
            {
                Assert.All(results[i], t => Assert.True(t.IsOk, t.Error));
                if (i % 2 == 0)
                {
                    Assert.Equal(new object?[] { 11L }, results[i].Select(t => t.Value));
                }
                else
                {
                    Assert.Equal(new object?[] { 22L, 11L }, results[i].Select(t => t.Value));
                }
            }
            long sent = _sim.Requests() - before;
            Assert.True(sent < 40, $"40 reads queued together took {sent} requests");
        });
    }

    [Fact]
    public async Task WriteAsync_then_ReadAsync_reads_the_write()
    {
        using var plc = OpenPlc();
        for (int value = 1; value <= 3; value++)
        {
            // queued back to back without awaiting: the read runs after the write
            Task<IReadOnlyList<Tag>> write = plc.WriteAsync(("uint1", value), ("usint1", value + 10));
            Task<IReadOnlyList<Tag>> read = plc.ReadAsync("uint1", "usint1");
            Assert.All(await write, t => Assert.True(t.IsOk, t.Error));
            Assert.Equal(new object?[] { (long)value, (long)(value + 10) }, (await read).Select(t => t.Value));
        }
    }

    [Fact]
    public async Task Async_failures_are_faulted_tasks()
    {
        using var plc = OpenPlc();
        Tag missing = (await plc.ReadAsync("no_such_tag"))[0];
        Assert.False(missing.IsOk);

        using var cip = new CipDriver(_sim.LogixPath);
        var e = await Assert.ThrowsAsync<CiplinkException>(() => cip.ReadAsync("uint1"));
        Assert.Equal(CiplinkStatus.Unsupported, e.Status);

        var closed = new LogixDriver(_sim.LogixPath);
        closed.Dispose();
        await Assert.ThrowsAsync<ObjectDisposedException>(() => closed.ReadAsync("uint1"));
        await Assert.ThrowsAsync<ObjectDisposedException>(() => closed.WriteAsync(("uint1", 1)));
    }

    [Fact]
    public async Task Cancelling_cancels_the_task()
    {
        using var plc = OpenPlc();
        await WithDelay(300, async () =>
        {
            using var cts = new CancellationTokenSource();
            Task<IReadOnlyList<Tag>> read = plc.ReadAsync(new[] { "uint1" }, cts.Token);
            cts.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => read);
            Assert.True(read.IsCanceled);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => plc.ReadAsync(new[] { "uint1" }, cts.Token));
        });
        Assert.True(plc.Read("uint1").IsOk);
    }

    [Fact]
    public void Sync_callers_on_many_threads_share_one_driver()
    {
        using var plc = OpenPlc();
        plc.Write(("uint1", 5), ("usint1", (short)6));
        Parallel.For(0, 32, new ParallelOptions { MaxDegreeOfParallelism = 8 }, i =>
        {
            IReadOnlyList<Tag> r = i % 2 == 0 ? plc.Read("uint1", "usint1") : plc.Read(new[] { "usint1" });
            Assert.All(r, t => Assert.True(t.IsOk, t.Error));
            Assert.Equal(i % 2 == 0 ? new object?[] { 5L, 6L } : new object?[] { 6L }, r.Select(t => t.Value));
        });
    }

    [Fact]
    public void Subscribe_raises_Changed_with_only_the_changed_tags()
    {
        using var plc = OpenPlc();
        plc.Write(("uint1", 100), ("usint1", (short)200));
        var batches = new BlockingCollection<IReadOnlyList<Tag>>();
        using Subscription sub = plc.Subscribe(new[] { "uint1", "usint1" }, TimeSpan.FromMilliseconds(50), changed: batches.Add);
        Assert.Equal(new[] { "uint1", "usint1" }, sub.Tags);

        Assert.True(batches.TryTake(out IReadOnlyList<Tag>? first, Long));
        Assert.Equal(new object?[] { 100L, 200L }, first!.Select(t => t.Value));

        plc.Write("uint1", 101);
        Assert.True(batches.TryTake(out IReadOnlyList<Tag>? next, Long));
        Tag changed = Assert.Single(next!);
        Assert.Equal(("uint1", (object?)101L), (changed.Name, changed.Value));

        sub.Dispose();
        Assert.True(sub.IsClosed);
        while (batches.TryTake(out _)) { }
        plc.Write("uint1", 102);
        Assert.False(batches.TryTake(out _, TimeSpan.FromMilliseconds(300)), "Changed raised after Dispose");
    }

    [Fact]
    public async Task Subscribe_as_IAsyncEnumerable_ends_when_the_driver_closes()
    {
        using var plc = OpenPlc();
        plc.Write("uint1", 1);
        Subscription sub = plc.Subscribe(new[] { "uint1" }, TimeSpan.FromMilliseconds(50));
        var seen = new List<long>();
        await foreach (IReadOnlyList<Tag> batch in sub.WithCancellation(new CancellationTokenSource(Long).Token))
        {
            Tag t = Assert.Single(batch);
            Assert.True(t.IsOk, t.Error);
            seen.Add((long)t.Value!);
            if (seen.Count == 1)
            {
                await plc.WriteAsync(("uint1", 2));
            }
            else
            {
                // ends the subscription: the enumeration completes instead of waiting forever
                plc.Close();
            }
        }
        Assert.Equal(new[] { 1L, 2L }, seen);
        Assert.True(sub.IsClosed);
    }

    [Fact]
    public void A_Changed_handler_can_call_the_driver()
    {
        using var plc = OpenPlc();
        plc.Write("usint1", (short)9);
        var reads = new BlockingCollection<Tag>();
        using Subscription sub = plc.Subscribe(new[] { "uint1" }, TimeSpan.FromMilliseconds(50),
            changed: _ => reads.Add(plc.Read("usint1")));
        Assert.True(reads.TryTake(out Tag? tag, Long));
        Assert.Equal(9L, tag!.Value);
    }

    [Fact]
    public void ConnectionChanged_reports_a_lost_link_and_the_reconnect()
    {
        var events = new BlockingCollection<ConnectionEventArgs>();
        using var plc = new LogixDriver(_sim.LogixPath, new LogixOptions { ReconnectMin = TimeSpan.FromMilliseconds(20) });
        object? sender = null;
        plc.ConnectionChanged += (s, e) =>
        {
            sender = s;
            events.Add(e);
        };
        Assert.Equal(ConnectionState.Closed, plc.ConnectionState);
        plc.Open();
        Assert.True(events.TryTake(out ConnectionEventArgs? e, Long));
        Assert.Equal("connected", e!.Event);
        Assert.Same(plc, sender);
        Assert.Equal(ConnectionState.Connected, plc.ConnectionState);

        _sim.Command("{\"cmd\": \"fault\", \"fault\": {\"close_connections\": true}}");
        var lost = Assert.Throws<CiplinkException>(() => plc.Read("uint1"));
        Assert.Equal(CiplinkStatus.Comm, lost.Status);

        Assert.True(events.TryTake(out e, Long));
        Assert.Equal("disconnected", e!.Event);
        Assert.False(string.IsNullOrEmpty(e.Error));
        Assert.True(events.TryTake(out e, Long));
        Assert.Equal(("reconnecting", (int?)1, (TimeSpan?)TimeSpan.FromMilliseconds(20)), (e!.Event, e.Attempt, e.Delay));
        Assert.True(events.TryTake(out e, Long));
        Assert.Equal("connected", e!.Event);

        WaitFor(() => plc.ConnectionState == ConnectionState.Connected, "Connected state");
        Assert.True(plc.Read("uint1").IsOk);

        plc.Close();
        Assert.Equal(ConnectionState.Closed, plc.ConnectionState);
        Assert.False(events.TryTake(out _, TimeSpan.FromMilliseconds(200)), "Close raised an event");
    }

    [Fact]
    public void Requests_fail_fast_while_reconnecting()
    {
        // a refused reconnect keeps the driver reconnecting
        using var plc = OpenPlc(new LogixOptions { ReconnectMin = TimeSpan.FromSeconds(5), ReconnectMax = TimeSpan.FromSeconds(5) });
        _sim.Command("{\"cmd\": \"fault\", \"fault\": {\"close_connections\": true}}");
        Assert.Throws<CiplinkException>(() => plc.Read("uint1"));
        WaitFor(() => plc.ConnectionState == ConnectionState.Reconnecting, "Reconnecting state");
        var e = Assert.Throws<CiplinkException>(() => plc.Read("uint1"));
        Assert.Equal(CiplinkStatus.Comm, e.Status);
        Assert.StartsWith("not connected, reconnecting", e.Message);
        plc.Close(); // stops reconnecting
        Assert.Equal(ConnectionState.Closed, plc.ConnectionState);
    }

    [Fact]
    public async Task Close_with_pending_work_fails_the_queued_requests()
    {
        using var plc = OpenPlc();
        Subscription sub = null!;
        await WithDelay(300, async () =>
        {
            long before = _sim.Requests();
            Task<IReadOnlyList<Tag>> inFlight = plc.ReadAsync("uint1");
            // only a request the simulator has received is in flight; until then close may fail it as queued
            WaitFor(() => _sim.Requests() > before, "the read to reach the simulator");
            // subscribed now, so its first poll queues behind the read instead of delaying it
            sub = plc.Subscribe(new[] { "usint1" }, TimeSpan.FromSeconds(10));
            Task<IReadOnlyList<Tag>> queuedWrite = plc.WriteAsync(("uint1", 1));
            Task<IReadOnlyList<Tag>> queuedRead = plc.ReadAsync("uint1");
            plc.Close();

            Assert.True((await inFlight.WaitAsync(Long))[0].IsOk);
            foreach (Task<IReadOnlyList<Tag>> queued in new[] { queuedWrite, queuedRead })
            {
                var e = await Assert.ThrowsAsync<CiplinkException>(() => queued.WaitAsync(Long));
                Assert.Equal(CiplinkStatus.Comm, e.Status);
                Assert.Contains("driver closed", e.Message);
            }
        });
        Assert.True(sub.IsClosed);
        await foreach (IReadOnlyList<Tag> _ in sub.WithCancellation(new CancellationTokenSource(Long).Token))
        {
            // at most what was delivered before the close; then it ends
        }

        plc.Open(); // the driver can be opened again
        Assert.True((await plc.ReadAsync("uint1"))[0].IsOk);
    }

    [Fact]
    public async Task Dispose_with_pending_work_completes_every_task()
    {
        var plc = OpenPlc();
        var tasks = new List<Task<IReadOnlyList<Tag>>>();
        await WithDelay(200, async () =>
        {
            for (int i = 0; i < 5; i++)
            {
                tasks.Add(plc.ReadAsync("uint1"));
                tasks.Add(plc.WriteAsync(("uint1", i)));
            }
            plc.Dispose();
            foreach (Task<IReadOnlyList<Tag>> t in tasks)
            {
                try
                {
                    await t.WaitAsync(Long);
                }
                catch (CiplinkException e)
                {
                    Assert.Equal(CiplinkStatus.Comm, e.Status);
                }
            }
        });
        Assert.Contains(tasks, t => t.IsFaulted);
    }

    [Fact]
    public async Task Slc_async_and_subscriptions_work()
    {
        using var slc = new SlcDriver(_sim.SlcPath);
        slc.Open();
        Assert.True((await slc.WriteAsync(("N7:0", 42)))[0].IsOk);
        Task<IReadOnlyList<Tag>> a = slc.ReadAsync("N7:0");
        Task<IReadOnlyList<Tag>> b = slc.ReadAsync("N7:0", "N7:1");
        Assert.Equal(42L, (await a)[0].Value);
        Assert.Equal(42L, (await b)[0].Value);

        var batches = new BlockingCollection<IReadOnlyList<Tag>>();
        using Subscription sub = slc.Subscribe(new[] { "N7:0" }, TimeSpan.FromMilliseconds(50), changed: batches.Add);
        Assert.True(batches.TryTake(out IReadOnlyList<Tag>? first, Long));
        Assert.Equal(42L, first![0].Value);
        Assert.Equal(ConnectionState.Connected, slc.ConnectionState);
    }

    [Fact]
    public void CipDriver_has_no_session_features()
    {
        using var cip = new CipDriver(_sim.LogixPath);
        Assert.Equal(CiplinkStatus.Unsupported, Assert.Throws<CiplinkException>(() => cip.Subscribe(new[] { "uint1" }, TimeSpan.FromSeconds(1))).Status);
        Assert.Equal(CiplinkStatus.Unsupported, Assert.Throws<CiplinkException>(() => cip.ConnectionChanged += (_, _) => { }).Status);
    }
}

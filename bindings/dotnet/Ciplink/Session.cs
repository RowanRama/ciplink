using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Ciplink;

/// <summary>Where a driver's link is (<see cref="Driver.ConnectionState"/>).</summary>
public enum ConnectionState
{
    /// <summary>Never opened, closed, or lost with <see cref="DriverOptions.Reconnect"/> off.</summary>
    Closed = 0,
    /// <summary>Opened and not lost since.</summary>
    Connected = 1,
    /// <summary>Lost; reconnecting in the background. Reads, writes and subscription polls fail at once meanwhile.</summary>
    Reconnecting = 2,
}

/// <summary>A change of a driver's link, raised by <see cref="Driver.ConnectionChanged"/>.</summary>
public sealed class ConnectionEventArgs : EventArgs
{
    internal ConnectionEventArgs(string @event, string? error, int? attempt, TimeSpan? delay)
    {
        Event = @event;
        Error = error;
        Attempt = attempt;
        Delay = delay;
    }

    /// <summary>"connected", "disconnected" or "reconnecting".</summary>
    public string Event { get; }

    /// <summary>For "disconnected": the error that lost the link.</summary>
    public string? Error { get; }

    /// <summary>For "reconnecting": the attempt number, from 1.</summary>
    public int? Attempt { get; }

    /// <summary>For "reconnecting": the wait before this attempt.</summary>
    public TimeSpan? Delay { get; }

    /// <inheritdoc/>
    public override string ToString() => Event switch
    {
        "disconnected" => $"disconnected: {Error}",
        "reconnecting" => $"reconnecting (attempt {Attempt}, after {Delay?.TotalMilliseconds} ms)",
        _ => Event,
    };

    internal static ConnectionEventArgs Parse(string json)
    {
        JsonNode node = JsonNode.Parse(json)!;
        double? delay = (double?)node["delay"];
        return new ConnectionEventArgs(
            (string?)node["event"] ?? "",
            (string?)node["error"],
            (int?)node["attempt"],
            delay is double s ? TimeSpan.FromSeconds(s) : null);
    }
}

/// <summary>
/// A running subscription from <see cref="Driver.Subscribe"/>: its tags are read every interval, in the driver's
/// request queue (packed with other callers' reads), and the tags whose value or error changed are delivered
/// through <see cref="Changed"/> and the async enumerator. The first delivery has every tag. A failed read or a lost
/// link is a change to each tag's <see cref="Tag.Error"/> (kind "comm").
/// </summary>
/// <remarks>
/// <see cref="Dispose"/> unsubscribes; once it returns <see cref="Changed"/> is not running and will not be raised
/// again (unless it is called from a <see cref="Changed"/> handler). <see cref="Driver.Close"/> and
/// <see cref="Driver.Dispose"/> end every subscription of that driver.
/// </remarks>
public sealed class Subscription : IDisposable, IAsyncEnumerable<IReadOnlyList<Tag>>
{
    private readonly object _lock = new();
    // changes not yet taken by an enumerator, the latest result per tag, so memory stays bounded by the tag count
    private readonly List<Tag> _pending = new();
    private readonly Dictionary<string, int> _pendingIndex = new();
    private readonly Channel<bool> _signal =
        Channel.CreateBounded<bool>(new BoundedChannelOptions(1) { FullMode = BoundedChannelFullMode.DropWrite });
    private readonly Driver _driver;
    private GCHandle _self;
    private IntPtr _native;
    private bool _closed;

    internal Subscription(Driver driver, IReadOnlyList<string> tags)
    {
        _driver = driver;
        Tags = tags;
        _self = GCHandle.Alloc(this);
    }

    internal IntPtr Self => GCHandle.ToIntPtr(_self);

    internal void Attach(IntPtr native)
    {
        lock (_lock)
        {
            _native = native;
        }
    }

    /// <summary>The subscribed tags, in order.</summary>
    public IReadOnlyList<string> Tags { get; }

    /// <summary>True once disposed, or the driver was closed or disposed.</summary>
    public bool IsClosed
    {
        get
        {
            lock (_lock)
            {
                return _closed;
            }
        }
    }

    /// <summary>
    /// Raised with the changed tags, on the driver's callback thread, one call at a time. Keep handlers short:
    /// the driver's other callbacks wait for them. A handler may call the driver (blocking calls included). An
    /// exception thrown by a handler is written to <see cref="Trace"/> and dropped.
    /// </summary>
    public event Action<IReadOnlyList<Tag>>? Changed;

    /// <summary>
    /// The changes as they come, until the subscription ends. Each item is every tag that changed since the
    /// previous item (the latest result of each), so a slow consumer never falls behind. Use one enumerator at a
    /// time.
    /// </summary>
    public async IAsyncEnumerator<IReadOnlyList<Tag>> GetAsyncEnumerator(CancellationToken cancellationToken = default)
    {
        while (true)
        {
            Tag[]? batch = null;
            lock (_lock)
            {
                if (_pending.Count > 0)
                {
                    batch = _pending.ToArray();
                    _pending.Clear();
                    _pendingIndex.Clear();
                }
                else if (_closed)
                {
                    yield break;
                }
            }
            if (batch is not null)
            {
                yield return batch;
                continue;
            }
            try
            {
                await _signal.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (ChannelClosedException)
            {
                // closed: the loop takes what is still pending, then ends
            }
        }
    }

    /// <summary>Unsubscribes. Idempotent.</summary>
    public void Dispose()
    {
        IntPtr native;
        lock (_lock)
        {
            native = _native;
            _native = IntPtr.Zero;
            _closed = true;
        }
        if (native != IntPtr.Zero)
        {
            // waits for an on_changes call in progress, so the GCHandle can be freed after it
            Native.ciplink_subscription_free(native);
        }
        lock (_lock)
        {
            if (_self.IsAllocated)
            {
                _self.Free();
            }
        }
        _signal.Writer.TryComplete();
        _driver.Forget(this);
    }

    private void Deliver(Tag[] changed)
    {
        lock (_lock)
        {
            if (_closed)
            {
                return;
            }
            foreach (Tag tag in changed)
            {
                if (_pendingIndex.TryGetValue(tag.Name, out int i))
                {
                    _pending[i] = tag;
                }
                else
                {
                    _pendingIndex[tag.Name] = _pending.Count;
                    _pending.Add(tag);
                }
            }
        }
        _signal.Writer.TryWrite(true);
        try
        {
            Changed?.Invoke(changed);
        }
        catch (Exception e)
        {
            Trace.TraceError($"ciplink: a Subscription.Changed handler threw: {e}");
        }
    }

    [UnmanagedCallersOnly]
    internal static void OnChanges(IntPtr user, IntPtr resultsJson)
    {
        try
        {
            if (GCHandle.FromIntPtr(user).Target is Subscription s)
            {
                s.Deliver(Values.ParseTags(Marshal.PtrToStringUTF8(resultsJson) ?? "[]"));
            }
        }
        catch (Exception e)
        {
            Trace.TraceError($"ciplink: subscription delivery failed: {e}");
        }
    }
}

/// <summary>A read or write queued with the native library: its task, completed from the native callback.</summary>
internal sealed class PendingRequest
{
    private readonly TaskCompletionSource<IReadOnlyList<Tag>> _tcs =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private CancellationTokenRegistration _registration;

    /// <summary>
    /// Queues a request: <paramref name="submit"/> gets the user data for the done callback and returns the native
    /// status. Any failure to queue is a faulted task, as the thread-pool versions of ReadAsync/WriteAsync gave.
    /// </summary>
    internal static Task<IReadOnlyList<Tag>> Start(Func<IntPtr, int> submit, CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return Task.FromCanceled<IReadOnlyList<Tag>>(cancellationToken);
        }
        var pending = new PendingRequest();
        // a strong handle keeps the request alive until the native side calls done, which it does exactly once
        GCHandle handle = GCHandle.Alloc(pending);
        if (cancellationToken.CanBeCanceled)
        {
            pending._registration = cancellationToken.Register(
                static (state, token) => ((TaskCompletionSource<IReadOnlyList<Tag>>)state!).TrySetCanceled(token),
                pending._tcs);
        }
        try
        {
            Native.Check(submit(GCHandle.ToIntPtr(handle)));
        }
        catch (Exception e)
        {
            // nothing was queued: done will never be called
            handle.Free();
            pending._registration.Dispose();
            return Task.FromException<IReadOnlyList<Tag>>(e);
        }
        return pending._tcs.Task;
    }

    [UnmanagedCallersOnly]
    internal static void OnDone(IntPtr user, int status, IntPtr json)
    {
        GCHandle handle = GCHandle.FromIntPtr(user);
        var pending = (PendingRequest)handle.Target!;
        handle.Free();
        try
        {
            string text = Marshal.PtrToStringUTF8(json) ?? "";
            if (status == 0)
            {
                pending._tcs.TrySetResult(Values.ParseTags(text));
            }
            else
            {
                pending._tcs.TrySetException(new CiplinkException((CiplinkStatus)status, text));
            }
        }
        catch (Exception e)
        {
            pending._tcs.TrySetException(e);
        }
        pending._registration.Dispose();
    }
}

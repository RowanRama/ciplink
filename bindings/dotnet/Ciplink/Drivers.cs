using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Ciplink;

/// <summary>
/// The calls every driver kind shares. Drivers are thread-safe: one instance can serve several threads, and
/// <see cref="Dispose"/> waits for calls in progress before it frees the native driver.
/// </summary>
/// <remarks>
/// A Logix or SLC driver queues every call for its own session thread, which does all of its I/O: reads queued
/// together (by any thread, <see cref="ReadAsync(string[])"/> call or <see cref="Subscription"/>) go out as one
/// read, and writes run in the order queued. After an open link is lost it reconnects in the background (see
/// <see cref="DriverOptions.Reconnect"/> and <see cref="ConnectionChanged"/>). Callbacks
/// (<see cref="ConnectionChanged"/>, <see cref="Subscription.Changed"/>) run on the driver's callback thread, one
/// at a time; async results complete their tasks there and continue on the thread pool.
/// </remarks>
public abstract class Driver : IDisposable
{
    private protected delegate int Create(string path, string? optionsJson, out DriverHandle handle);

    private readonly DriverHandle _handle;
    private readonly object _sessionLock = new();
    private readonly List<Subscription> _subscriptions = new();
    private EventHandler<ConnectionEventArgs>? _connectionChanged;

    private protected Driver(string path, DriverOptions options, Create create)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(options);
        int status = create(path, options.ToJson(), out DriverHandle handle);
        _handle = handle;
        if (status != 0)
        {
            handle.Dispose();
            Native.Check(status);
        }
        Path = path;
    }

    private protected DriverHandle Handle => _handle;

    /// <summary>The path the driver was created with, such as "192.168.1.10/0".</summary>
    public string Path { get; }

    /// <summary>The native library version.</summary>
    public static string Version => Marshal.PtrToStringUTF8(Native.ciplink_version()) ?? "";

    /// <summary>True while the session is open. False after <see cref="Dispose"/>.</summary>
    public bool Connected => !_handle.IsClosed && Native.ciplink_connected(_handle);

    /// <summary>Opens the session (a Logix driver also uploads its tag list, unless told not to).</summary>
    /// <exception cref="CiplinkException">The connection failed.</exception>
    /// <exception cref="ObjectDisposedException">The driver was disposed.</exception>
    public void Open() => Native.Check(Native.ciplink_open(_handle));

    /// <summary>
    /// Closes the session and stops reconnecting. The request in flight finishes; requests still queued fail with
    /// a <see cref="CiplinkStatus.Comm"/> error "driver closed", and every <see cref="Subscription"/> ends. The
    /// driver can be opened again.
    /// </summary>
    public void Close()
    {
        try
        {
            Native.Check(Native.ciplink_close(_handle));
        }
        finally
        {
            EndSubscriptions();
        }
    }

    /// <summary>Where the link is: closed, connected or reconnecting. Never waits for I/O.</summary>
    public ConnectionState ConnectionState =>
        _handle.IsClosed ? ConnectionState.Closed : (ConnectionState)Native.ciplink_connection_state(_handle);

    /// <summary>
    /// Raised when the link changes: "connected" (<see cref="Open"/> or a reconnect succeeded), "disconnected"
    /// (an open link was lost, with the error) and "reconnecting" (before each attempt, with its number and
    /// wait). <see cref="Close"/> and a failed <see cref="Open"/> raise nothing. Raised on the driver's callback
    /// thread; an exception thrown by a handler is written to <see cref="Trace"/> and dropped.
    /// </summary>
    /// <exception cref="CiplinkException">Adding a handler to a <see cref="CipDriver"/> (<see cref="CiplinkStatus.Unsupported"/>).</exception>
    public event EventHandler<ConnectionEventArgs>? ConnectionChanged
    {
        add
        {
            lock (_sessionLock)
            {
                if (_handle.Owner == IntPtr.Zero)
                {
                    RegisterConnectionCallback();
                }
                _connectionChanged += value;
            }
        }
        remove
        {
            lock (_sessionLock)
            {
                _connectionChanged -= value;
            }
        }
    }

    private unsafe void RegisterConnectionCallback()
    {
        // weak: an undisposed driver can still be collected (its handle's finalizer frees the native driver)
        GCHandle owner = GCHandle.Alloc(this, GCHandleType.Weak);
        int status = Native.ciplink_set_connection_callback(_handle, &OnConnection, GCHandle.ToIntPtr(owner));
        if (status != 0)
        {
            owner.Free();
            Native.Check(status);
        }
        _handle.Owner = GCHandle.ToIntPtr(owner);
    }

    [UnmanagedCallersOnly]
    private static void OnConnection(IntPtr user, IntPtr eventJson)
    {
        try
        {
            if (GCHandle.FromIntPtr(user).Target is Driver driver)
            {
                EventHandler<ConnectionEventArgs>? handler;
                lock (driver._sessionLock)
                {
                    handler = driver._connectionChanged;
                }
                handler?.Invoke(driver, ConnectionEventArgs.Parse(Marshal.PtrToStringUTF8(eventJson) ?? "{}"));
            }
        }
        catch (Exception e)
        {
            Trace.TraceError($"ciplink: a ConnectionChanged handler threw: {e}");
        }
    }

    /// <summary>
    /// Subscribes to <paramref name="tags"/>: they are read every <paramref name="interval"/> (packed with the
    /// driver's other reads) and the ones whose value or error changed are delivered by the returned
    /// <see cref="Subscription"/>, as an event and as an async enumerable. With <paramref name="deadband"/>, a
    /// numeric tag that moved less than it since the last value delivered is not delivered. Dispose it to
    /// unsubscribe.
    /// </summary>
    /// <param name="tags">The tags to read.</param>
    /// <param name="interval">The poll period (more than zero).</param>
    /// <param name="deadband">Numeric tags: the smallest change delivered, or null for every change.</param>
    /// <param name="changed">
    /// A <see cref="Subscription.Changed"/> handler attached before the first poll, so it gets the first values
    /// too (a handler attached later may miss them).
    /// </param>
    /// <exception cref="CiplinkException">No tags or a zero interval (<see cref="CiplinkStatus.InvalidArgument"/>
    /// or <see cref="CiplinkStatus.Request"/>), or a <see cref="CipDriver"/> (<see cref="CiplinkStatus.Unsupported"/>).</exception>
    public unsafe Subscription Subscribe(IEnumerable<string> tags, TimeSpan interval, double? deadband = null,
        Action<IReadOnlyList<Tag>>? changed = null)
    {
        ArgumentNullException.ThrowIfNull(tags);
        string[] names = tags.ToArray();
        string options = Values.ToJson(new Dictionary<string, object?>
        {
            ["interval"] = interval.TotalSeconds,
            ["deadband"] = deadband,
        });
        var subscription = new Subscription(this, names);
        subscription.Changed += changed;
        try
        {
            IntPtr native = WithNames(names, ptrs =>
            {
                Native.Check(Native.ciplink_subscribe(_handle, ptrs, (nuint)ptrs.Length, options, &Subscription.OnChanges,
                    subscription.Self, out IntPtr raw));
                return raw;
            });
            subscription.Attach(native);
        }
        catch
        {
            subscription.Dispose();
            throw;
        }
        lock (_sessionLock)
        {
            _subscriptions.Add(subscription);
        }
        return subscription;
    }

    internal void Forget(Subscription subscription)
    {
        lock (_sessionLock)
        {
            _subscriptions.Remove(subscription);
        }
    }

    private void EndSubscriptions()
    {
        Subscription[] all;
        lock (_sessionLock)
        {
            all = _subscriptions.ToArray();
        }
        foreach (Subscription s in all)
        {
            s.Dispose();
        }
    }

    /// <summary>Reads one tag, e.g. "dint1", "ary[2]{3}" or "N7:0".</summary>
    public Tag Read(string tag) => Read(new[] { tag })[0];

    /// <summary>Reads several tags in as few requests as possible; one result per tag, in order.</summary>
    public IReadOnlyList<Tag> Read(params string[] tags) =>
        WithNames(tags, ptrs => Values.ParseTags(Native.CallJson((out IntPtr j) => Native.ciplink_read(_handle, ptrs, (nuint)ptrs.Length, out j))));

    /// <summary>Reads the identity of the module in backplane <paramref name="slot"/> (product_name, serial, ...).</summary>
    public JsonObject GetModuleInfo(long slot) =>
        (JsonObject)CallNode((out IntPtr j) => Native.ciplink_get_module_info(_handle, slot, out j))!;

    // Device browsing like RSWho. A route is relative to the device at the driver's IP address: "" is that device,
    // "bp/3" the module in slot 3 of its backplane, "bp/2/enet/192.168.1.10" a device behind the module in slot 2.

    /// <summary>Reads the identity of the device at <paramref name="route"/> (product_name, serial, ...).</summary>
    public JsonObject GetIdentity(string route = "") =>
        (JsonObject)CallNode((out IntPtr j) => Native.ciplink_get_identity(_handle, route, out j))!;

    /// <summary>
    /// What the ciplink device at <paramref name="route"/> runs (name, version, detail, summary, ciplink_version,
    /// assemblies, connections), or null for any other device. <c>summary</c> is the line a device browser shows,
    /// e.g. "Station · station 2 · owned by 10.0.0.5, RPI 20 ms".
    /// </summary>
    public JsonObject? GetApp(string route = "") =>
        CallNode((out IntPtr j) => Native.ciplink_get_app(_handle, route, out j)) as JsonObject;

    /// <summary>
    /// The ports of the device at <paramref name="route"/>: objects with number, type, type_name, name, address,
    /// ip, netmask and nodes, the addresses <see cref="BrowsePort"/> probes (the slots, or every host of an
    /// EtherNet/IP port's subnet, at most a /24).
    /// </summary>
    public JsonArray GetPorts(string route = "") =>
        (JsonArray)CallNode((out IntPtr j) => Native.ciplink_get_ports(_handle, route, out j))!;

    /// <summary>
    /// Probes every address on <paramref name="port"/> of the device at <paramref name="route"/>
    /// (<paramref name="nodes"/>, by default the port's own) from <paramref name="workers"/> connections at once:
    /// objects with route, address, identity (null if nothing answered) and error, in address order. Each
    /// missing device may cost the bridge's ~4 s timeout.
    /// </summary>
    public JsonArray BrowsePort(string route, int port, IEnumerable<string>? nodes = null, int workers = 16) =>
        (JsonArray)CallNode((out IntPtr j) =>
            Native.ciplink_browse_port(_handle, route, checked((ushort)port), NodesJson(nodes), (nuint)Math.Max(workers, 1), out j))!;

    /// <summary>
    /// <see cref="BrowsePort"/>, calling <paramref name="found"/> on this thread with each node as it answers (in
    /// any order) until it returns false. An exception thrown by <paramref name="found"/> stops the scan and is
    /// rethrown.
    /// </summary>
    public unsafe void ScanPort(string route, int port, Func<JsonObject, bool> found, IEnumerable<string>? nodes = null, int workers = 16)
    {
        var scan = new Scan(found);
        GCHandle user = GCHandle.Alloc(scan);
        try
        {
            Native.Check(Native.ciplink_scan_port(_handle, route, checked((ushort)port), NodesJson(nodes),
                (nuint)Math.Max(workers, 1), &OnNode, GCHandle.ToIntPtr(user)));
        }
        finally
        {
            user.Free();
        }
        if (scan.Error is not null) ExceptionDispatchInfo.Capture(scan.Error).Throw();
    }

    private sealed class Scan(Func<JsonObject, bool> found)
    {
        public Func<JsonObject, bool> Found { get; } = found;
        public Exception? Error { get; set; }
    }

    [UnmanagedCallersOnly]
    private static byte OnNode(IntPtr user, IntPtr nodeJson)
    {
        var scan = (Scan)GCHandle.FromIntPtr(user).Target!;
        try
        {
            return scan.Found((JsonObject)JsonNode.Parse(Marshal.PtrToStringUTF8(nodeJson)!)!) ? (byte)1 : (byte)0;
        }
        catch (Exception e)
        {
            scan.Error = e;
            return 0;
        }
    }

    private static string? NodesJson(IEnumerable<string>? nodes) => nodes is null ? null : JsonSerializer.Serialize(nodes);

    /// <summary>
    /// The connection size of the next Forward Open (1 to 65535; above 511 uses a Large Forward Open). Set it
    /// only while the CIP connection is closed: setting it while open throws <see cref="CiplinkException"/>
    /// (<see cref="CiplinkStatus.Request"/>).
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The size is outside 1 to 65535.</exception>
    public int ConnectionSize
    {
        get
        {
            Native.Check(Native.ciplink_connection_size(_handle, out ushort size));
            return size;
        }
        set
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 1);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(value, ushort.MaxValue);
            Native.Check(Native.ciplink_set_connection_size(_handle, (ushort)value));
        }
    }

    /// <summary>
    /// The socket timeout; <see cref="System.Threading.Timeout.InfiniteTimeSpan"/> blocks forever. Setting it
    /// applies to an open connection at once.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The timeout is zero or negative (other than infinite).</exception>
    public TimeSpan SocketTimeout
    {
        get
        {
            Native.Check(Native.ciplink_socket_timeout(_handle, out double seconds));
            return seconds < 0 ? System.Threading.Timeout.InfiniteTimeSpan : TimeSpan.FromSeconds(seconds);
        }
        set
        {
            if (value != System.Threading.Timeout.InfiniteTimeSpan && value <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(value), "the socket timeout must be positive, or infinite");
            }
            double seconds = value == System.Threading.Timeout.InfiniteTimeSpan ? -1.0 : value.TotalSeconds;
            Native.Check(Native.ciplink_set_socket_timeout(_handle, seconds));
        }
    }

    /// <summary>
    /// Sends a raw connected CIP message (service, request path and data, without the sequence count) over the
    /// current CIP connection and returns the raw reply frame, encapsulation header included. It does not make
    /// the Forward Open: a Logix <see cref="Open"/> does, or send a connected <see cref="GenericMessage"/> first.
    /// </summary>
    public byte[] SendConnected(byte[] message) => RawSend(message, connected: true);

    /// <summary>Sends a raw unconnected CIP message (SendRRData) and returns the raw reply frame.</summary>
    public byte[] SendUnconnected(byte[] message) => RawSend(message, connected: false);

    private unsafe byte[] RawSend(byte[] message, bool connected)
    {
        ArgumentNullException.ThrowIfNull(message);
        fixed (byte* p = message)
        {
            IntPtr reply;
            nuint len;
            int status = connected
                ? Native.ciplink_send_connected(_handle, p, (nuint)message.Length, out reply, out len)
                : Native.ciplink_send_unconnected(_handle, p, (nuint)message.Length, out reply, out len);
            byte[] bytes = Native.TakeBytes(reply, len);
            Native.Check(status);
            return bytes;
        }
    }

    /// <summary>Runs <paramref name="call"/> with the names as native UTF-8 strings, freed afterwards.</summary>
    private protected static T WithNames<T>(string[] names, Func<IntPtr[], T> call)
    {
        ArgumentNullException.ThrowIfNull(names);
        var ptrs = new IntPtr[names.Length];
        try
        {
            for (int i = 0; i < names.Length; i++)
            {
                ptrs[i] = Marshal.StringToCoTaskMemUTF8(names[i] ?? throw new ArgumentNullException(nameof(names)));
            }
            return call(ptrs);
        }
        finally
        {
            foreach (IntPtr p in ptrs)
            {
                Marshal.FreeCoTaskMem(p);
            }
        }
    }

    /// <summary>Writes one tag. The value types are those of <see cref="Tag.Value"/> (any integer or float type works).</summary>
    public Tag Write(string tag, object? value) => Write(new[] { (tag, value) })[0];

    /// <summary>Writes several tags; one result per tag, in order.</summary>
    public IReadOnlyList<Tag> Write(params (string Tag, object? Value)[] items)
    {
        ArgumentNullException.ThrowIfNull(items);
        string json = Values.WriteItems(items);
        return Values.ParseTags(Native.CallJson((out IntPtr j) => Native.ciplink_write(_handle, json, out j)));
    }

    /// <summary>
    /// Queues a read of <paramref name="tags"/> (as <see cref="Read(string[])"/>) and returns at once, without
    /// using a thread while it waits. Reads queued together go out as one read.
    /// </summary>
    public Task<IReadOnlyList<Tag>> ReadAsync(params string[] tags) => ReadAsync(tags, CancellationToken.None);

    /// <summary>
    /// <see cref="ReadAsync(string[])"/>. Cancelling <paramref name="cancellationToken"/> cancels the task only:
    /// the queued read still runs and its result is dropped.
    /// </summary>
    public unsafe Task<IReadOnlyList<Tag>> ReadAsync(string[] tags, CancellationToken cancellationToken)
    {
        try
        {
            return WithNames(tags, ptrs => PendingRequest.Start(
                user => Native.ciplink_read_async(_handle, ptrs, (nuint)ptrs.Length, &PendingRequest.OnDone, user, IntPtr.Zero),
                cancellationToken));
        }
        catch (Exception e)
        {
            return Task.FromException<IReadOnlyList<Tag>>(e);
        }
    }

    /// <summary>
    /// Queues a write (as <see cref="Write(ValueTuple{string, object}[])"/>) and returns at once. Writes run in
    /// the order queued, after everything queued before them, and are never sent twice: a write whose link is lost
    /// fails with that error.
    /// </summary>
    public Task<IReadOnlyList<Tag>> WriteAsync(params (string Tag, object? Value)[] items) => WriteAsync(items, CancellationToken.None);

    /// <summary>
    /// <see cref="WriteAsync(ValueTuple{string, object}[])"/>. Cancelling <paramref name="cancellationToken"/>
    /// cancels the task only: the queued write still runs.
    /// </summary>
    public unsafe Task<IReadOnlyList<Tag>> WriteAsync((string Tag, object? Value)[] items, CancellationToken cancellationToken)
    {
        try
        {
            ArgumentNullException.ThrowIfNull(items);
            string json = Values.WriteItems(items);
            return PendingRequest.Start(
                user => Native.ciplink_write_async(_handle, json, &PendingRequest.OnDone, user, IntPtr.Zero),
                cancellationToken);
        }
        catch (Exception e)
        {
            return Task.FromException<IReadOnlyList<Tag>>(e);
        }
    }

    /// <summary>Sends a CIP generic message. The reply data is the result's value, as <see cref="byte"/>[].</summary>
    public unsafe Tag GenericMessage(Message message)
    {
        ArgumentNullException.ThrowIfNull(message);
        byte[] data = message.RequestData ?? Array.Empty<byte>();
        IntPtr route = message.RoutePath is null ? IntPtr.Zero : Marshal.StringToCoTaskMemUTF8(message.RoutePath);
        IntPtr name = message.Name is null ? IntPtr.Zero : Marshal.StringToCoTaskMemUTF8(message.Name);
        try
        {
            fixed (byte* p = data)
            {
                var m = new NativeMessage
                {
                    Service = message.Service,
                    ClassCode = message.ClassCode,
                    Instance = message.Instance,
                    Attribute = message.Attribute ?? -1,
                    RequestData = (IntPtr)p,
                    RequestDataLen = (nuint)data.Length,
                    Connected = message.Connected ? (byte)1 : (byte)0,
                    UnconnectedSend = message.UnconnectedSend ? (byte)1 : (byte)0,
                    RoutePath = route,
                    Name = name,
                };
                return Values.ParseOneTag(Native.CallJson((out IntPtr j) => Native.ciplink_generic_message(_handle, m, out j)));
            }
        }
        finally
        {
            Marshal.FreeCoTaskMem(route);
            Marshal.FreeCoTaskMem(name);
        }
    }

    /// <summary>
    /// Closes the connection and frees the native driver. Pending async requests fail and every
    /// <see cref="Subscription"/> ends; once the native driver is freed no callback of it runs again. Later calls
    /// throw <see cref="ObjectDisposedException"/>.
    /// </summary>
    public void Dispose()
    {
        _handle.Dispose();
        EndSubscriptions();
        GC.SuppressFinalize(this);
    }

    private protected JsonNode? CallNode(Native.JsonCall call) => JsonNode.Parse(Native.CallJson(call));
}

/// <summary>A ControlLogix / CompactLogix / Micro800 driver (pycomm3's LogixDriver).</summary>
public sealed class LogixDriver : Driver
{
    /// <summary>Creates the driver; it connects on <see cref="Driver.Open"/>.</summary>
    /// <param name="path">"ip", "ip/slot", "ip:port" or a CIP route.</param>
    /// <param name="options">Options, or null for the defaults.</param>
    /// <exception cref="CiplinkException">The path or options are invalid.</exception>
    public LogixDriver(string path, LogixOptions? options = null)
        : base(path, options ?? new LogixOptions(), Native.ciplink_logix_new) { }

    /// <summary>
    /// Starts a controller-side trend: the controller samples <paramref name="tags"/> (atomic tags, members or
    /// elements of up to 32 bits, or bits such as "Tag.3") every period and the trend uploads them on a connection
    /// of its own. Close or dispose the trend to stop it.
    /// </summary>
    /// <exception cref="CiplinkException">A tag cannot be trended (<see cref="CiplinkStatus.Request"/>), or the
    /// controller refused the trend.</exception>
    public Trend Trend(string[] tags, TrendOptions? options = null)
    {
        string json = (options ?? new TrendOptions()).ToJson();
        return WithNames(tags, ptrs =>
        {
            int status = Native.ciplink_trend_start(Handle, ptrs, (nuint)ptrs.Length, json, out TrendHandle trend);
            if (status != 0)
            {
                trend.Dispose();
                Native.Check(status);
            }
            return new Trend(trend);
        });
    }

    /// <summary>Starts a controller-side trend of <paramref name="tags"/> sampled every 10 ms.</summary>
    public Trend Trend(params string[] tags) => Trend(tags, null);

    /// <summary>The uploaded tag definitions, by tag name.</summary>
    public JsonObject Tags() => (JsonObject)CallNode((out IntPtr j) => Native.ciplink_tags(Handle, out j))!;

    /// <summary>
    /// Uploads the tag list: controller tags (null), all programs ("*") or one program. With
    /// <paramref name="cache"/> the result replaces <see cref="Tags"/>; <paramref name="tagNamespaceFilter"/>
    /// keeps only the tags whose name (without "Program:X.") starts with it.
    /// </summary>
    public JsonArray TagList(string? program = null, bool cache = true, string tagNamespaceFilter = "") =>
        (JsonArray)CallNode((out IntPtr j) => Native.ciplink_tag_list(Handle, program, cache, tagNamespaceFilter, out j))!;

    /// <summary>The definition of a tag or member, such as "udt1.dint".</summary>
    public JsonNode? TagInfo(string tagName) => CallNode((out IntPtr j) => Native.ciplink_tag_info(Handle, tagName, out j));

    /// <summary>The uploaded data type (UDT and AOI) definitions, by name.</summary>
    public JsonObject DataTypes() => (JsonObject)CallNode((out IntPtr j) => Native.ciplink_data_types(Handle, out j))!;

    /// <summary>Controller information (product name, revision, serial, ...).</summary>
    public JsonObject Info() => (JsonObject)CallNode((out IntPtr j) => Native.ciplink_info(Handle, out j))!;

    /// <summary>Reads the PLC clock. The result's value is a UTC <see cref="DateTime"/>.</summary>
    public Tag GetPlcTime() => WithTime(Values.ParseOneTag(Native.CallJson((out IntPtr j) => Native.ciplink_get_plc_time(Handle, out j))));

    /// <summary>Sets the PLC clock to <paramref name="time"/>, or to this computer's clock when null.</summary>
    public Tag SetPlcTime(DateTime? time = null)
    {
        long us = time is DateTime t ? (t.ToUniversalTime() - DateTime.UnixEpoch).Ticks / 10 : -1;
        if (us < -1)
        {
            throw new ArgumentOutOfRangeException(nameof(time), "the PLC clock starts in 1970");
        }
        return WithTime(Values.ParseOneTag(Native.CallJson((out IntPtr j) => Native.ciplink_set_plc_time(Handle, us, out j))));
    }

    /// <summary>Reads the controller program name.</summary>
    public string GetPlcName() => CallNode((out IntPtr j) => Native.ciplink_get_plc_name(Handle, out j))!.GetValue<string>();

    /// <summary>Reads the controller identity plus "keyswitch".</summary>
    public JsonObject GetPlcInfo() => (JsonObject)CallNode((out IntPtr j) => Native.ciplink_get_plc_info(Handle, out j))!;

    /// <summary>Reloads the tag list if the controller's tag table changed; true if it did.</summary>
    public bool CheckTagTable()
    {
        Native.Check(Native.ciplink_check_tag_table(Handle, out byte changed));
        return changed != 0;
    }

    /// <summary>The tag table version the tags were loaded at (5 numbers), or null if unknown.</summary>
    public JsonArray? TagTableVersion() => CallNode((out IntPtr j) => Native.ciplink_tag_table_version(Handle, out j)) as JsonArray;

    /// <summary>Authenticates this connection for Description reads with the bundled credentials; the value is true on success.</summary>
    public unsafe Tag AuthenticateMetadata() =>
        Values.ParseOneTag(Native.CallJson((out IntPtr j) => Native.ciplink_authenticate_metadata(Handle, null, 0, null, 0, out j)));

    /// <summary>
    /// Authenticates this connection for Description reads with caller-supplied credentials: the signed
    /// certificate and its unencrypted PKCS #1 or PKCS #8 DER RSA private key. The value is true on success.
    /// </summary>
    /// <exception cref="CiplinkException">The credentials do not parse or do not match (<see cref="CiplinkStatus.Request"/>).</exception>
    public unsafe Tag AuthenticateMetadata(byte[] certificate, byte[] privateKeyDer)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(privateKeyDer);
        // `fixed` gives NULL for an empty array, which would mean "bundled": pin a placeholder byte instead
        byte[] cert = certificate.Length == 0 ? new byte[1] : certificate;
        byte[] key = privateKeyDer.Length == 0 ? new byte[1] : privateKeyDer;
        fixed (byte* c = cert)
        fixed (byte* k = key)
        {
            byte* cp = c;
            byte* kp = k;
            return Values.ParseOneTag(Native.CallJson((out IntPtr j) => Native.ciplink_authenticate_metadata(
                Handle, cp, (nuint)certificate.Length, kp, (nuint)privateKeyDer.Length, out j)));
        }
    }

    /// <summary>Reads the Description of one tag; the value is the text.</summary>
    public Tag GetTagDescription(string tag, ushort language = 0x7F, string encoding = "utf-8") =>
        GetTagDescriptions(new[] { tag }, language, encoding)[0];

    /// <summary>Reads the Descriptions of several tags (0x7F is the project's default language).</summary>
    public IReadOnlyList<Tag> GetTagDescriptions(string[] tags, ushort language = 0x7F, string encoding = "utf-8") =>
        WithNames(tags, ptrs => Values.ParseTags(Native.CallJson((out IntPtr j) =>
            Native.ciplink_get_tag_descriptions(Handle, ptrs, (nuint)ptrs.Length, language, encoding, out j))));

    private static Tag WithTime(Tag tag) =>
        tag.Value is Dictionary<string, object?> v && v.TryGetValue("microseconds", out object? us) && us is long or ulong
            ? tag with { Value = DateTime.UnixEpoch.AddTicks(Convert.ToInt64(us) * 10) }
            : tag;
}

/// <summary>An SLC 500 / MicroLogix driver (PCCC), with addresses like "N7:0", "F8:1{4}" or "B3:0/2".</summary>
public sealed class SlcDriver : Driver
{
    /// <summary>Creates the driver; it connects on <see cref="Driver.Open"/>.</summary>
    /// <param name="path">"ip", "ip:port" or a CIP route.</param>
    /// <param name="options">Options, or null for the defaults.</param>
    public SlcDriver(string path, DriverOptions? options = null)
        : base(path, options ?? new DriverOptions(), Native.ciplink_slc_new) { }

    /// <summary>Reads the processor type, e.g. "1747-L552"; null if unknown.</summary>
    public string? GetProcessorType() => CallNode((out IntPtr j) => Native.ciplink_slc_processor_type(Handle, out j))?.GetValue<string>();

    /// <summary>Reads the data file directory: {"N7": {"elements": n, "length": bytes}, ...}.</summary>
    public JsonObject GetFileDirectory() => (JsonObject)CallNode((out IntPtr j) => Native.ciplink_slc_file_directory(Handle, out j))!;

    /// <summary>Reads <paramref name="numDataLogs"/> records of data log queue <paramref name="queueNum"/> (null where none was read).</summary>
    public JsonArray GetDatalogQueue(int numDataLogs, byte queueNum) =>
        (JsonArray)CallNode((out IntPtr j) => Native.ciplink_slc_datalog_queue(Handle, (nuint)numDataLogs, queueNum, out j))!;
}

/// <summary>A plain CIP driver: generic messages only. Read and write throw <see cref="CiplinkException"/> (Unsupported).</summary>
public sealed class CipDriver : Driver
{
    /// <summary>Creates the driver; it connects on <see cref="Driver.Open"/>.</summary>
    public CipDriver(string path, DriverOptions? options = null)
        : base(path, options ?? new DriverOptions(), Native.ciplink_cip_new) { }

    /// <summary>Asks one device for its identity, without a session. Null when it does not answer.</summary>
    public static JsonObject? ListIdentity(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        return JsonNode.Parse(Native.CallJson((out IntPtr j) => Native.ciplink_list_identity(path, out j))) as JsonObject;
    }

    /// <summary>Broadcasts List Identity (UDP) and returns every device that answers.</summary>
    public static JsonArray Discover(string? broadcast = null) =>
        (JsonArray)JsonNode.Parse(Native.CallJson((out IntPtr j) => Native.ciplink_discover(broadcast, out j)))!;
}

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace Ciplink;

/// <summary>
/// The calls every driver kind shares. Drivers are thread-safe: one instance can serve several threads, and
/// <see cref="Dispose"/> waits for calls in progress before it frees the native driver.
/// </summary>
public abstract class Driver : IDisposable
{
    private protected delegate int Create(string path, string? optionsJson, out DriverHandle handle);

    private readonly DriverHandle _handle;

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

    /// <summary>Closes the session. The driver can be opened again.</summary>
    public void Close() => Native.Check(Native.ciplink_close(_handle));

    /// <summary>Reads one tag, e.g. "dint1", "ary[2]{3}" or "N7:0".</summary>
    public Tag Read(string tag) => Read(new[] { tag })[0];

    /// <summary>Reads several tags in as few requests as possible; one result per tag, in order.</summary>
    public IReadOnlyList<Tag> Read(params string[] tags) =>
        WithNames(tags, ptrs => Values.ParseTags(Native.CallJson((out IntPtr j) => Native.ciplink_read(_handle, ptrs, (nuint)ptrs.Length, out j))));

    /// <summary>Reads the identity of the module in backplane <paramref name="slot"/> (product_name, serial, ...).</summary>
    public JsonObject GetModuleInfo(long slot) =>
        (JsonObject)CallNode((out IntPtr j) => Native.ciplink_get_module_info(_handle, slot, out j))!;

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

    /// <summary><see cref="Read(string[])"/> on the thread pool.</summary>
    public Task<IReadOnlyList<Tag>> ReadAsync(params string[] tags) => Task.Run(() => Read(tags));

    /// <summary><see cref="Write(ValueTuple{string, object}[])"/> on the thread pool.</summary>
    public Task<IReadOnlyList<Tag>> WriteAsync(params (string Tag, object? Value)[] items) => Task.Run(() => Write(items));

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

    /// <summary>Closes the connection and frees the native driver. Later calls throw <see cref="ObjectDisposedException"/>.</summary>
    public void Dispose()
    {
        _handle.Dispose();
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

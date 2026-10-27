using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;

namespace Ciplink;

/// <summary>
/// The setup of an <see cref="Adapter"/>: ciplink as an EtherNet/IP I/O device that a Logix controller owns.
/// Assemblies map instance numbers to sizes in bytes.
/// </summary>
public sealed class AdapterConfig
{
    /// <summary>Input assemblies (T->O, produced to the controller): instance to size in bytes.</summary>
    public IReadOnlyDictionary<uint, int> Inputs { get; init; } = new Dictionary<uint, int>();

    /// <summary>Output assemblies (O->T, consumed from the controller): instance to size in bytes.</summary>
    public IReadOnlyDictionary<uint, int> Outputs { get; init; } = new Dictionary<uint, int>();

    /// <summary>Configuration assemblies, sent by the controller with the Forward Open: instance to size in bytes.</summary>
    public IReadOnlyDictionary<uint, int> Configs { get; init; } = new Dictionary<uint, int>();

    /// <summary>ODVA vendor ID. 0 is a placeholder: a device shipped with an EDS needs its vendor's own ID.</summary>
    public ushort VendorId { get; init; }

    /// <summary>Device type, by default 0x2B (generic device, keyable).</summary>
    public ushort DeviceType { get; init; } = 0x2B;

    /// <summary>Product code.</summary>
    public ushort ProductCode { get; init; } = 1;

    /// <summary>Major and minor revision.</summary>
    public (byte Major, byte Minor) Revision { get; init; } = (1, 1);

    /// <summary>Serial number.</summary>
    public uint Serial { get; init; }

    /// <summary>Product name: ASCII, at most 32 characters.</summary>
    public string ProductName { get; init; } = "ciplink adapter";

    /// <summary>The application's name, shown by device browsers next to the ciplink badge.</summary>
    public string AppName { get; init; } = "";

    /// <summary>The application's version.</summary>
    public string AppVersion { get; init; } = "";

    /// <summary>The EDS served by the File object, so "Upload EDS from device" works; null for none.</summary>
    public byte[]? Eds { get; init; }

    /// <summary>The EDS file name the File object reports.</summary>
    public string EdsName { get; init; } = "ciplink.eds";

    /// <summary>The local IPv4 address to listen on (the network card multicast leaves from), 0.0.0.0 for all.</summary>
    public string Bind { get; init; } = "0.0.0.0";

    /// <summary>TCP and UDP port of explicit messages and ListIdentity; 0 picks a free one.</summary>
    public int Port { get; init; } = 44818;

    /// <summary>UDP port of class 1 I/O; 0 picks a free one.</summary>
    public int IoPort { get; init; } = 2222;

    /// <summary>The shortest RPI accepted.</summary>
    public TimeSpan RpiMin { get; init; } = TimeSpan.FromMilliseconds(2);

    /// <summary>The longest RPI accepted.</summary>
    public TimeSpan RpiMax { get; init; } = TimeSpan.FromMilliseconds(3200);

    /// <summary>The O->T connection point of input-only connections.</summary>
    public uint InputOnlyHeartbeat { get; init; } = 238;

    /// <summary>The O->T connection point of listen-only connections.</summary>
    public uint ListenOnlyHeartbeat { get; init; } = 237;

    internal string ToJson()
    {
        static Dictionary<string, object?> Sizes(IReadOnlyDictionary<uint, int> sizes) =>
            sizes.ToDictionary(kv => kv.Key.ToString(System.Globalization.CultureInfo.InvariantCulture), kv => (object?)kv.Value);
        var json = new Dictionary<string, object?>
        {
            ["inputs"] = Sizes(Inputs),
            ["outputs"] = Sizes(Outputs),
            ["configs"] = Sizes(Configs),
            ["identity"] = new Dictionary<string, object?>
            {
                ["vendor_id"] = VendorId,
                ["device_type"] = DeviceType,
                ["product_code"] = ProductCode,
                // ints, not a byte[]: that would serialize as raw bytes
                ["revision"] = new[] { (int)Revision.Major, (int)Revision.Minor },
                ["serial"] = Serial,
                ["product_name"] = ProductName,
            },
            ["app_name"] = AppName,
            ["app_version"] = AppVersion,
            ["eds_name"] = EdsName,
            ["bind"] = Bind,
            ["port"] = Port,
            ["io_port"] = IoPort,
            ["rpi_min"] = RpiMin.TotalSeconds,
            ["rpi_max"] = RpiMax.TotalSeconds,
            ["input_only_heartbeat"] = InputOnlyHeartbeat,
            ["listen_only_heartbeat"] = ListenOnlyHeartbeat,
        };
        if (Eds is not null)
        {
            json["eds"] = Eds;
        }
        return Values.ToJson(json);
    }
}

/// <summary>An output assembly's latest data and the controller's run bit.</summary>
/// <param name="Data">The data.</param>
/// <param name="Run">The run bit: false before the first packet and after the owner closed or timed out.</param>
public sealed record AdapterOutput(byte[] Data, bool Run);

/// <summary>
/// A running adapter: ciplink as an EtherNet/IP I/O device that a Logix controller finds in RSWho and owns in its
/// I/O tree. The I/O runs on the library's threads, so a slow application never makes a packet late. Nothing
/// listens until one is created; it needs TCP/UDP 44818 and UDP 2222 of its address to itself, so it cannot run
/// beside FactoryTalk Linx or RSLinx on the same IP address. Thread-safe: one thread can wait in
/// <see cref="NextEvent"/> while others set inputs. <see cref="Dispose"/> stops it.
/// </summary>
public sealed class Adapter : IDisposable
{
    private readonly AdapterHandle _handle;

    /// <summary>Starts the adapter: binds its ports and starts its I/O threads.</summary>
    /// <exception cref="CiplinkException">The config was refused (Request) or a port is taken (Comm).</exception>
    public Adapter(AdapterConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        int status = Native.ciplink_adapter_start(config.ToJson(), out AdapterHandle handle);
        if (status != 0)
        {
            handle.Dispose();
            Native.Check(status);
        }
        _handle = handle;
        JsonNode addresses = JsonNode.Parse(Native.CallJson((out IntPtr j) => Native.ciplink_adapter_addresses(_handle, out j)))!;
        Address = (string)addresses["address"]!;
        IoAddress = (string)addresses["io_address"]!;
    }

    /// <summary>"ip:port" of explicit messages and ListIdentity.</summary>
    public string Address { get; }

    /// <summary>"ip:port" of class 1 I/O.</summary>
    public string IoAddress { get; }

    /// <summary>Sets an input assembly's data, sent in the next T->O packets; shorter data leaves the rest zero.</summary>
    public unsafe void SetInput(uint instance, byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        fixed (byte* p = data)
        {
            Native.Check(Native.ciplink_adapter_set_input(_handle, instance, p, (nuint)data.Length));
        }
    }

    /// <summary>An input assembly's current data.</summary>
    public byte[] Input(uint instance)
    {
        int status = Native.ciplink_adapter_input(_handle, instance, out IntPtr data, out nuint len);
        byte[] bytes = Native.TakeBytes(data, len);
        Native.Check(status);
        return bytes;
    }

    /// <summary>An output assembly's latest data and the controller's run bit.</summary>
    public AdapterOutput Output(uint instance)
    {
        int status = Native.ciplink_adapter_output(_handle, instance, out IntPtr data, out nuint len, out byte run);
        byte[] bytes = Native.TakeBytes(data, len);
        Native.Check(status);
        return new AdapterOutput(bytes, run != 0);
    }

    /// <summary>A configuration assembly's data, as the last Forward Open with data sent it.</summary>
    public byte[] Config(uint instance)
    {
        int status = Native.ciplink_adapter_config(_handle, instance, out IntPtr data, out nuint len);
        byte[] bytes = Native.TakeBytes(data, len);
        Native.Check(status);
        return bytes;
    }

    /// <summary>
    /// The next event, waiting up to <paramref name="timeout"/> (null: until one comes or the adapter stops); null
    /// if none came. An event has <c>event</c>: <c>opened</c>, <c>closed</c> or <c>timed_out</c> with
    /// <c>connection</c>, <c>output</c> with <c>instance</c> (sent once until <see cref="Output"/> reads it), or
    /// <c>config</c> with <c>instance</c> and <c>data</c>.
    /// </summary>
    public JsonObject? NextEvent(TimeSpan? timeout = null)
    {
        double seconds = timeout is TimeSpan t ? t.TotalSeconds : -1;
        return JsonNode.Parse(Native.CallJson((out IntPtr j) => Native.ciplink_adapter_next_event(_handle, seconds, out j))) as JsonObject;
    }

    /// <summary>
    /// The open class 1 connections: kind, originator, o_t_rpi and t_o_rpi (seconds), input, input_size, output
    /// (null unless an owner), output_size, multicast, o_t_id and t_o_id.
    /// </summary>
    public JsonArray Connections() =>
        (JsonArray)JsonNode.Parse(Native.CallJson((out IntPtr j) => Native.ciplink_adapter_connections(_handle, out j)))!;

    /// <summary>Sets the application's status text that device browsers show, e.g. "station 2".</summary>
    public void SetDetail(string detail)
    {
        ArgumentNullException.ThrowIfNull(detail);
        Native.Check(Native.ciplink_adapter_set_detail(_handle, detail));
    }

    /// <summary>I/O timing counters: produced packets, late ones (1 ms or more) and max_late (seconds).</summary>
    public JsonObject Stats() =>
        (JsonObject)JsonNode.Parse(Native.CallJson((out IntPtr j) => Native.ciplink_adapter_stats(_handle, out j)))!;

    /// <summary>Stops the adapter: a thread waiting in <see cref="NextEvent"/> returns null; later calls throw.</summary>
    public void Stop() => Native.Check(Native.ciplink_adapter_stop(_handle));

    /// <summary>Stops and frees the adapter.</summary>
    public void Dispose() => _handle.Dispose();
}

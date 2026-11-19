using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using System.Text.Json.Nodes;

namespace Ciplink;

/// <summary>Options for <see cref="ModbusDriver"/>. <see cref="DriverOptions.ConnectionSize"/> is ignored.</summary>
public sealed class ModbusOptions : DriverOptions
{
    /// <summary>Default options: a 1 s reply timeout (Modbus devices answer in milliseconds).</summary>
    public ModbusOptions() => SocketTimeout = TimeSpan.FromSeconds(1);

    /// <summary>
    /// The map file (CSV, one row per tag: name, area, address, type, count, order, unit, scale, offset, units,
    /// description, writable) that gives tag names, types and descriptions; null for plain addresses only.
    /// </summary>
    public string? MapFile { get; init; }

    /// <summary>Most registers in one read, 1 to 125. Default 125.</summary>
    public int MaxRegisters { get; init; } = 125;

    /// <summary>Most coils or discrete inputs in one read, 1 to 2000. Default 2000.</summary>
    public int MaxBits { get; init; } = 2000;

    /// <summary>Most unrequested registers or bits between two tags merged into one read. Default 8.</summary>
    public int MaxGap { get; init; } = 8;

    /// <summary>Word order of tags without one: "ABCD" (default), "CDAB", "BADC" or "DCBA".</summary>
    public string WordOrder { get; init; } = "ABCD";

    /// <summary>Always write with FC15/FC16, never FC05/FC06. Default false.</summary>
    public bool WriteMultiple { get; init; }

    /// <summary>A plain address the keep-alive reads instead of sending FC08, or null. Default null.</summary>
    public string? KeepAliveAddress { get; init; }

    /// <summary>
    /// Keep-alive after this long without traffic. Null: the scheme's default (30 s over TCP, off for rtu://);
    /// <see cref="TimeSpan.Zero"/>: off.
    /// </summary>
    public new TimeSpan? KeepAlive { get; init; }

    internal override void AddTo(IDictionary<string, object?> json)
    {
        base.AddTo(json);
        json.Remove("connection_size");
        json["map_file"] = MapFile;
        json["max_registers"] = MaxRegisters;
        json["max_bits"] = MaxBits;
        json["max_gap"] = MaxGap;
        json["word_order"] = WordOrder;
        json["write_multiple"] = WriteMultiple;
        json["keep_alive_address"] = KeepAliveAddress;
        if (KeepAlive is not TimeSpan keepAlive)
        {
            json.Remove("keep_alive");
        }
        else
        {
            json["keep_alive"] = keepAlive == TimeSpan.Zero ? null : keepAlive.TotalSeconds;
        }
    }
}

/// <summary>
/// A Modbus TCP, RTU (serial) or RTU-over-TCP driver. Tag names come from the map file
/// (<see cref="ModbusOptions.MapFile"/>); anything else is a plain address such as "hr100:float32", "co5" or
/// "ir10{4}" (0-based protocol addresses: holding register 40001 is "hr0"). Reads queued together are merged into
/// the fewest Modbus requests. The CIP calls inherited from <see cref="Driver"/> (<see cref="Driver.GenericMessage"/>,
/// <see cref="Driver.GetIdentity"/>, <see cref="Driver.ConnectionSize"/>, ...) throw <see cref="CiplinkException"/>
/// (<see cref="CiplinkStatus.Unsupported"/>).
/// </summary>
public sealed class ModbusDriver : Driver
{
    /// <summary>Creates the driver; it connects on <see cref="Driver.Open"/>.</summary>
    /// <param name="path">
    /// "tcp://host[:port][?unit=N]", "rtu://PORT[?baud=..&amp;parity=..&amp;data=..&amp;stop=..&amp;unit=N]" or
    /// "rtu+tcp://host[:port][?unit=N]" (port 502 and unit 1 by default).
    /// </param>
    /// <param name="options">Options, or null for the defaults.</param>
    /// <exception cref="CiplinkException">The path, options or map file are invalid.</exception>
    public ModbusDriver(string path, ModbusOptions? options = null)
        : base(path, options ?? new ModbusOptions(), Native.ciplink_modbus_new) { }

    /// <summary>
    /// Reads Device Identification (FC43 / MEI 14) of <paramref name="unit"/> (null: the path's unit):
    /// vendor_name, product_code, revision, vendor_url, product_name, model_name, user_application_name (null
    /// where the device has none). A device without it throws <see cref="CiplinkStatus.Response"/>.
    /// </summary>
    public JsonObject DeviceInfo(byte? unit = null) =>
        (JsonObject)CallNode((out IntPtr j) => Native.ciplink_modbus_device_info(Handle, unit ?? -1, out j))!;

    /// <summary>
    /// The map file's rows in file order (empty without a map): name, area, address, bit, type, cip_type, count,
    /// order, unit, scale, offset, units, description, writable. No I/O.
    /// </summary>
    public JsonArray Tags => (JsonArray)CallNode((out IntPtr j) => Native.ciplink_modbus_tags(Handle, out j))!;

    /// <summary>
    /// Sends one raw PDU (function code and data) to <paramref name="unit"/> (null: the path's unit) and returns
    /// the reply PDU. An exception reply throws <see cref="CiplinkStatus.Response"/>.
    /// </summary>
    public unsafe byte[] SendPdu(byte[] pdu, byte? unit = null)
    {
        ArgumentNullException.ThrowIfNull(pdu);
        fixed (byte* p = pdu)
        {
            int status = Native.ciplink_modbus_send_pdu(Handle, unit ?? -1, p, (nuint)pdu.Length, out IntPtr reply, out nuint len);
            byte[] bytes = Native.TakeBytes(reply, len);
            Native.Check(status);
            return bytes;
        }
    }
}

internal static partial class Native
{
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ciplink_modbus_new(string path, string? optionsJson, out DriverHandle handle);

    [LibraryImport(Lib)]
    internal static partial int ciplink_modbus_device_info(DriverHandle handle, int unit, out IntPtr json);

    [LibraryImport(Lib)]
    internal static partial int ciplink_modbus_tags(DriverHandle handle, out IntPtr json);

    [LibraryImport(Lib)]
    internal static unsafe partial int ciplink_modbus_send_pdu(DriverHandle handle, int unit, byte* pdu, nuint len, out IntPtr reply, out nuint replyLen);
}

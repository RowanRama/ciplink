using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using System.Text.Json.Nodes;

namespace Ciplink;

/// <summary>Options for <see cref="S7PlusDriver"/>. <see cref="DriverOptions.ConnectionSize"/> is ignored.</summary>
public sealed class S7PlusOptions : DriverOptions
{
    /// <summary>Default options: a 10 s socket timeout and a keep-alive after 15 s without traffic.</summary>
    public S7PlusOptions()
    {
        SocketTimeout = TimeSpan.FromSeconds(10);
        KeepAlive = TimeSpan.FromSeconds(15);
    }

    /// <summary>Browse the PLC's symbol table on <see cref="Driver.Open"/>. Default true.</summary>
    public bool InitTags { get; init; } = true;

    /// <summary>
    /// The SHA-256 fingerprint of the PLC certificate to require, hex with or without ':'; null accepts any
    /// certificate (the default). A mismatch makes <see cref="Driver.Open"/> throw
    /// (<see cref="CiplinkStatus.Comm"/>); see <see cref="S7PlusDriver.CertificateFingerprint"/>.
    /// </summary>
    public string? TlsFingerprint { get; init; }

    internal override void AddTo(IDictionary<string, object?> json)
    {
        base.AddTo(json);
        json.Remove("connection_size");
        json["init_tags"] = InitTags;
        json["tls_fingerprint"] = TlsFingerprint;
    }
}

/// <summary>
/// A Siemens S7-1500 / S7-1200 driver over S7comm-plus with TLS (secure PG/HMI communication, firmware 2.9 and
/// later). Tag names are TIA style: "Line1.Conveyor.Speed", "Line1.Items[3]", PLC tags of the I, Q and M areas by
/// their bare name. Reads queued together are merged, at most the PLC's limit (usually 100) items per request.
/// Tag comments are not read. The CIP calls inherited from <see cref="Driver"/>
/// (<see cref="Driver.GenericMessage"/>, <see cref="Driver.GetIdentity"/>, <see cref="Driver.ConnectionSize"/>, ...)
/// throw <see cref="CiplinkException"/> (<see cref="CiplinkStatus.Unsupported"/>).
/// </summary>
public sealed class S7PlusDriver : Driver
{
    /// <summary>Creates the driver; it connects on <see cref="Driver.Open"/>.</summary>
    /// <param name="path">"host" or "host:port" (port 102 by default).</param>
    /// <param name="options">Options, or null for the defaults.</param>
    /// <exception cref="CiplinkException">The path or options are invalid (a malformed fingerprint is
    /// <see cref="CiplinkStatus.Request"/>).</exception>
    public S7PlusDriver(string path, S7PlusOptions? options = null)
        : base(path, options ?? new S7PlusOptions(), Native.ciplink_s7plus_new) { }

    /// <summary>
    /// Top-level tags (data blocks and I/Q/M PLC tags) by name: name, type, kind, softdatatype, dims,
    /// lower_bounds, string_length, lid, member_crc, hmi_visible, hmi_accessible, hmi_read_only. Empty before the
    /// first browse; no I/O.
    /// </summary>
    public JsonObject Tags() => (JsonObject)CallNode((out IntPtr j) => Native.ciplink_tags(Handle, out j))!;

    /// <summary>The structure types the tags use, by name: name, rid, interface_timestamp, members. No I/O.</summary>
    public JsonObject DataTypes() => (JsonObject)CallNode((out IntPtr j) => Native.ciplink_data_types(Handle, out j))!;

    /// <summary>
    /// Every symbol as a flat list (members of structures expanded): name, type, dims, access, crc, hmi_visible,
    /// hmi_accessible, hmi_read_only. Browses first if needed.
    /// </summary>
    public JsonArray TagList() =>
        (JsonArray)CallNode((out IntPtr j) => Native.ciplink_tag_list(Handle, null, false, null, out j))!;

    /// <summary>One name resolved, as a <see cref="TagList"/> entry. An unknown name throws (<see cref="CiplinkStatus.Request"/>).</summary>
    public JsonObject TagInfo(string name) =>
        (JsonObject)CallNode((out IntPtr j) => Native.ciplink_tag_info(Handle, name, out j))!;

    /// <summary>
    /// CPU information: name, order_number, serial_number, hardware_version, firmware, engineering_version,
    /// project, protection_level, max_read, max_write.
    /// </summary>
    public JsonObject GetPlcInfo() => (JsonObject)CallNode((out IntPtr j) => Native.ciplink_get_plc_info(Handle, out j))!;

    /// <summary>
    /// "AB:CD:..." (SHA-256) of the certificate the PLC presented at the latest TLS handshake, null before one. A
    /// certificate refused by <see cref="S7PlusOptions.TlsFingerprint"/> still sets it.
    /// </summary>
    public string? CertificateFingerprint =>
        CallNode((out IntPtr j) => Native.ciplink_s7plus_fingerprint(Handle, out j))?.GetValue<string>();

    /// <summary>Browses the symbol table again; true if the tags or types changed.</summary>
    public bool RefreshTags()
    {
        Native.Check(Native.ciplink_s7plus_refresh_tags(Handle, out byte changed));
        return changed != 0;
    }
}

internal static partial class Native
{
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ciplink_s7plus_new(string path, string? optionsJson, out DriverHandle handle);

    [LibraryImport(Lib)]
    internal static partial int ciplink_s7plus_fingerprint(DriverHandle handle, out IntPtr json);

    [LibraryImport(Lib)]
    internal static partial int ciplink_s7plus_refresh_tags(DriverHandle handle, out byte changed);
}

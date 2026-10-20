using System;
using System.Collections.Generic;

namespace Ciplink;

/// <summary>The status a failed ciplink call returns (<c>CiplinkStatus</c> in ciplink.h).</summary>
public enum CiplinkStatus
{
    /// <summary>Success.</summary>
    Ok = 0,
    /// <summary>Connection or socket failure.</summary>
    Comm = 1,
    /// <summary>Bad data, such as a value that cannot be encoded or a reply that cannot be decoded.</summary>
    Data = 2,
    /// <summary>The device returned an error reply.</summary>
    Response = 3,
    /// <summary>The request could not be built.</summary>
    Request = 4,
    /// <summary>A bad argument, such as malformed options or a value the binding cannot convert.</summary>
    InvalidArgument = 5,
    /// <summary>The driver kind does not support this call.</summary>
    Unsupported = 6,
    /// <summary>An internal error inside the native library.</summary>
    Panic = 7,
}

/// <summary>A whole call failed. Per-tag failures are reported in <see cref="Tag.Error"/> instead.</summary>
public sealed class CiplinkException : Exception
{
    /// <summary>Creates the exception.</summary>
    public CiplinkException(CiplinkStatus status, string message) : base(message) => Status = status;

    /// <summary>The native status code.</summary>
    public CiplinkStatus Status { get; }
}

/// <summary>
/// The result for one tag of a read or write (or one generic message). A failure here is data, not an exception.
/// </summary>
/// <param name="Name">The tag as requested.</param>
/// <param name="Value">
/// The value: null, <see cref="bool"/>, <see cref="long"/> (or <see cref="ulong"/> above long.MaxValue),
/// <see cref="double"/>, <see cref="string"/>, <see cref="byte"/>[], <c>object?[]</c> for arrays and
/// <c>Dictionary&lt;string, object?&gt;</c> for structures (members in order).
/// </param>
/// <param name="DataType">The data type name, such as DINT, or null.</param>
/// <param name="Error">The error message, or null on success.</param>
/// <param name="ErrorKind">
/// The error class: not_found, bad_value, bad_request, access, refused, table_changed, comm, device or other.
/// </param>
/// <param name="Status">The CIP general status of the failure, when there is one.</param>
/// <param name="ExtendedStatus">The CIP extended status of the failure, when there is one.</param>
public sealed record Tag(
    string Name,
    object? Value,
    string? DataType,
    string? Error,
    string? ErrorKind,
    int? Status = null,
    int? ExtendedStatus = null)
{
    /// <summary>True when the tag succeeded.</summary>
    public bool IsOk => Error is null;
}

/// <summary>Connection options shared by every driver kind.</summary>
public class DriverOptions
{
    /// <summary>Socket timeout; <see cref="System.Threading.Timeout.InfiniteTimeSpan"/> blocks forever. Default 5 s.</summary>
    public TimeSpan SocketTimeout { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Connection size in bytes; null uses the driver default (4000, or 500 for SLC).</summary>
    public int? ConnectionSize { get; init; }

    internal virtual void AddTo(IDictionary<string, object?> json)
    {
        json["socket_timeout"] = SocketTimeout == System.Threading.Timeout.InfiniteTimeSpan ? null : SocketTimeout.TotalSeconds;
        if (ConnectionSize is int size)
        {
            json["connection_size"] = size;
        }
    }

    internal string ToJson()
    {
        var json = new Dictionary<string, object?>();
        AddTo(json);
        return Values.ToJson(json);
    }
}

/// <summary>Options for <see cref="LogixDriver"/>.</summary>
public sealed class LogixOptions : DriverOptions
{
    /// <summary>Upload the tag list and data types on <see cref="Driver.Open"/>. Default true.</summary>
    public bool InitTags { get; init; } = true;

    /// <summary>Also upload program-scoped tags. Default true.</summary>
    public bool InitProgramTags { get; init; } = true;

    /// <summary>Only upload tags in this namespace (empty means all).</summary>
    public string TagNamespaceFilter { get; init; } = "";

    /// <summary>Look tags up on first use instead of uploading the whole list. Default false.</summary>
    public bool LazyTags { get; init; }

    /// <summary>A file to cache the uploaded tag list in, or null.</summary>
    public string? TagCacheFile { get; init; }

    internal override void AddTo(IDictionary<string, object?> json)
    {
        base.AddTo(json);
        json["init_tags"] = InitTags;
        json["init_program_tags"] = InitProgramTags;
        json["tag_namespace_filter"] = TagNamespaceFilter;
        json["lazy_tags"] = LazyTags;
        json["tag_cache_file"] = TagCacheFile;
    }
}

/// <summary>A CIP generic message (explicit messaging), as in pycomm3's <c>generic_message</c>.</summary>
public sealed record Message
{
    /// <summary>The service code, such as 0x0E (Get Attribute Single).</summary>
    public byte Service { get; init; }

    /// <summary>The class code.</summary>
    public uint ClassCode { get; init; }

    /// <summary>The instance.</summary>
    public uint Instance { get; init; }

    /// <summary>The attribute, or null for none.</summary>
    public int? Attribute { get; init; }

    /// <summary>The request data, or null for none.</summary>
    public byte[]? RequestData { get; init; }

    /// <summary>Send over the connected session. Default true.</summary>
    public bool Connected { get; init; } = true;

    /// <summary>Wrap an unconnected request in Unconnected Send. Default false.</summary>
    public bool UnconnectedSend { get; init; }

    /// <summary>The route: null uses the driver's path, "" means none, otherwise a CIP route such as "bp/2".</summary>
    public string? RoutePath { get; init; }

    /// <summary>The name used for the result's <see cref="Tag.Name"/>. Default "generic".</summary>
    public string? Name { get; init; }
}

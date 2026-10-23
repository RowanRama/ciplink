using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using Microsoft.Win32.SafeHandles;

namespace Ciplink;

/// <summary>Owns a <c>CiplinkDriver*</c>; releasing it closes the connection and frees the driver.</summary>
internal sealed class DriverHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public DriverHandle() : base(ownsHandle: true) { }

    protected override bool ReleaseHandle()
    {
        Native.ciplink_driver_free(handle);
        return true;
    }
}

/// <summary>Owns a <c>CiplinkTrend*</c>; releasing it stops the trend (without waiting) and frees it.</summary>
internal sealed class TrendHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public TrendHandle() : base(ownsHandle: true) { }

    protected override bool ReleaseHandle()
    {
        Native.ciplink_trend_free(handle);
        return true;
    }
}

/// <summary>Owns a <c>CiplinkServer*</c>; releasing it stops the tag server and frees it.</summary>
internal sealed class ServerHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public ServerHandle() : base(ownsHandle: true) { }

    protected override bool ReleaseHandle()
    {
        Native.ciplink_server_stop(handle);
        return true;
    }
}

/// <summary>The <c>CiplinkMessage</c> struct of ciplink.h (x64 size 56).</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct NativeMessage
{
    public byte Service;
    public uint ClassCode;
    public uint Instance;
    public int Attribute;
    public IntPtr RequestData;
    public nuint RequestDataLen;
    public byte Connected;
    public byte UnconnectedSend;
    public IntPtr RoutePath;
    public IntPtr Name;
}

/// <summary>P/Invoke declarations for crates/ciplink-ffi/include/ciplink.h. Every status is a C int.</summary>
internal static partial class Native
{
    private const string Lib = "ciplink";

    internal delegate int JsonCall(out IntPtr json);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ciplink_logix_new(string path, string? optionsJson, out DriverHandle handle);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ciplink_slc_new(string path, string? optionsJson, out DriverHandle handle);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ciplink_cip_new(string path, string? optionsJson, out DriverHandle handle);

    [LibraryImport(Lib)]
    internal static partial void ciplink_driver_free(IntPtr handle);

    [LibraryImport(Lib)]
    internal static partial int ciplink_open(DriverHandle handle);

    [LibraryImport(Lib)]
    internal static partial int ciplink_close(DriverHandle handle);

    [LibraryImport(Lib)]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static partial bool ciplink_connected(DriverHandle handle);

    [LibraryImport(Lib)]
    internal static partial int ciplink_read(DriverHandle handle, IntPtr[] tags, nuint count, out IntPtr json);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ciplink_write(DriverHandle handle, string itemsJson, out IntPtr json);

    [LibraryImport(Lib)]
    internal static partial int ciplink_tags(DriverHandle handle, out IntPtr json);

    [LibraryImport(Lib)]
    internal static partial int ciplink_connection_size(DriverHandle handle, out ushort size);

    [LibraryImport(Lib)]
    internal static partial int ciplink_set_connection_size(DriverHandle handle, ushort size);

    [LibraryImport(Lib)]
    internal static partial int ciplink_socket_timeout(DriverHandle handle, out double seconds);

    [LibraryImport(Lib)]
    internal static partial int ciplink_set_socket_timeout(DriverHandle handle, double seconds);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ciplink_tag_list(DriverHandle handle, string? program, [MarshalAs(UnmanagedType.U1)] bool cache, string? tagNamespaceFilter, out IntPtr json);

    [LibraryImport(Lib)]
    internal static unsafe partial int ciplink_send_connected(DriverHandle handle, byte* message, nuint messageLen, out IntPtr reply, out nuint replyLen);

    [LibraryImport(Lib)]
    internal static unsafe partial int ciplink_send_unconnected(DriverHandle handle, byte* message, nuint messageLen, out IntPtr reply, out nuint replyLen);

    [LibraryImport(Lib)]
    internal static partial void ciplink_bytes_free(IntPtr data, nuint len);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ciplink_tag_info(DriverHandle handle, string tagName, out IntPtr json);

    [LibraryImport(Lib)]
    internal static partial int ciplink_data_types(DriverHandle handle, out IntPtr json);

    [LibraryImport(Lib)]
    internal static partial int ciplink_info(DriverHandle handle, out IntPtr json);

    [LibraryImport(Lib)]
    internal static partial int ciplink_get_plc_time(DriverHandle handle, out IntPtr json);

    [LibraryImport(Lib)]
    internal static partial int ciplink_set_plc_time(DriverHandle handle, long microseconds, out IntPtr json);

    [LibraryImport(Lib)]
    internal static partial int ciplink_generic_message(DriverHandle handle, in NativeMessage message, out IntPtr json);

    [LibraryImport(Lib)]
    internal static partial int ciplink_get_plc_name(DriverHandle handle, out IntPtr json);

    [LibraryImport(Lib)]
    internal static partial int ciplink_get_plc_info(DriverHandle handle, out IntPtr json);

    [LibraryImport(Lib)]
    internal static partial int ciplink_get_module_info(DriverHandle handle, long slot, out IntPtr json);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ciplink_get_identity(DriverHandle handle, string? route, out IntPtr json);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ciplink_get_ports(DriverHandle handle, string? route, out IntPtr json);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ciplink_browse_port(DriverHandle handle, string? route, ushort port, string? nodesJson, nuint workers, out IntPtr json);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static unsafe partial int ciplink_scan_port(DriverHandle handle, string? route, ushort port, string? nodesJson, nuint workers, delegate* unmanaged<IntPtr, IntPtr, byte> callback, IntPtr user);

    [LibraryImport(Lib)]
    internal static partial int ciplink_check_tag_table(DriverHandle handle, out byte changed);

    [LibraryImport(Lib)]
    internal static partial int ciplink_tag_table_version(DriverHandle handle, out IntPtr json);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ciplink_get_tag_descriptions(DriverHandle handle, IntPtr[] tags, nuint count, ushort language, string? encoding, out IntPtr json);

    [LibraryImport(Lib)]
    internal static unsafe partial int ciplink_authenticate_metadata(DriverHandle handle, byte* certificate, nuint certificateLen, byte* privateKeyDer, nuint privateKeyDerLen, out IntPtr json);

    [LibraryImport(Lib)]
    internal static partial int ciplink_slc_processor_type(DriverHandle handle, out IntPtr json);

    [LibraryImport(Lib)]
    internal static partial int ciplink_slc_datalog_queue(DriverHandle handle, nuint numDataLogs, byte queueNum, out IntPtr json);

    [LibraryImport(Lib)]
    internal static partial int ciplink_slc_file_directory(DriverHandle handle, out IntPtr json);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ciplink_list_identity(string path, out IntPtr json);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ciplink_discover(string? broadcast, out IntPtr json);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ciplink_trend_start(DriverHandle handle, IntPtr[] tags, nuint count, string? optionsJson, out TrendHandle trend);

    [LibraryImport(Lib)]
    internal static partial int ciplink_trend_read(TrendHandle trend, out IntPtr json);

    [LibraryImport(Lib)]
    internal static partial int ciplink_trend_info(TrendHandle trend, out IntPtr json);

    [LibraryImport(Lib)]
    internal static partial int ciplink_trend_close(TrendHandle trend);

    [LibraryImport(Lib)]
    internal static partial void ciplink_trend_free(IntPtr trend);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int ciplink_server_start(string configPath, string? optionsJson, out ServerHandle server);

    [LibraryImport(Lib)]
    internal static partial int ciplink_server_address(ServerHandle server, out IntPtr text);

    [LibraryImport(Lib)]
    internal static partial int ciplink_server_stop(IntPtr server);

    /// <summary>Always called with NULL: the calling thread's latest error, which every failing call sets.</summary>
    [LibraryImport(Lib)]
    internal static partial IntPtr ciplink_last_error(IntPtr handle);

    [LibraryImport(Lib)]
    internal static partial void ciplink_string_free(IntPtr s);

    [LibraryImport(Lib)]
    internal static partial IntPtr ciplink_version();

    /// <summary>Copies and frees a string the library returned.</summary>
    internal static string? TakeString(IntPtr p)
    {
        if (p == IntPtr.Zero)
        {
            return null;
        }
        try
        {
            return Marshal.PtrToStringUTF8(p);
        }
        finally
        {
            ciplink_string_free(p);
        }
    }

    /// <summary>Throws <see cref="CiplinkException"/> for a non-OK status, with this thread's last error.</summary>
    internal static void Check(int status)
    {
        if (status != 0)
        {
            string message = TakeString(ciplink_last_error(IntPtr.Zero)) ?? $"ciplink call failed with status {status}";
            throw new CiplinkException((CiplinkStatus)status, message);
        }
    }

    /// <summary>Copies and frees a byte buffer the library returned (NULL is an empty array).</summary>
    internal static byte[] TakeBytes(IntPtr data, nuint len)
    {
        if (data == IntPtr.Zero)
        {
            return Array.Empty<byte>();
        }
        try
        {
            var bytes = new byte[checked((int)len)];
            Marshal.Copy(data, bytes, 0, bytes.Length);
            return bytes;
        }
        finally
        {
            ciplink_bytes_free(data, len);
        }
    }

    /// <summary>Runs a call that returns a JSON string and takes ownership of that string.</summary>
    internal static string CallJson(JsonCall call)
    {
        int status = call(out IntPtr json);
        string? text = TakeString(json);
        Check(status);
        return text ?? "null";
    }
}

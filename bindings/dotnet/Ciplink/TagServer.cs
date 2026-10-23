using System;
using System.Collections.Generic;

namespace Ciplink;

/// <summary>
/// A tag server (see <c>ciplink-server</c>) running in this process on threads of its own: it owns the PLC
/// connections of a config file and serves tag values to web apps over a WebSocket. <see cref="Stop"/> or
/// <see cref="Dispose"/> stops it: pressed momentary buttons are released, the PLC connections closed and the audit
/// log flushed.
/// </summary>
public sealed class TagServer : IDisposable
{
    private readonly ServerHandle _handle;

    /// <summary>
    /// Starts the server of a config file (the TOML file of <c>ciplink-server run --config</c>) and returns once it
    /// listens. <paramref name="mock"/> serves simulated values from each PLC's <c>mock_tags</c> file;
    /// <paramref name="host"/> and <paramref name="port"/> override the config's (port 0 picks a free port).
    /// </summary>
    public TagServer(string configPath, bool mock = false, string? host = null, int? port = null)
    {
        var options = new Dictionary<string, object?> { ["mock"] = mock };
        if (host is not null)
        {
            options["host"] = host;
        }
        if (port is not null)
        {
            options["port"] = port.Value;
        }
        int status = Native.ciplink_server_start(configPath, Values.ToJson(options), out ServerHandle handle);
        if (status != 0)
        {
            handle.Dispose();
            Native.Check(status);
        }
        _handle = handle;
        Address = Native.CallJson((out IntPtr text) => Native.ciplink_server_address(_handle, out text));
    }

    /// <summary>The address the server listens on, e.g. <c>127.0.0.1:8765</c>.</summary>
    public string Address { get; }

    /// <summary>Stops the server and waits for it; throws <see cref="CiplinkException"/> if the shutdown failed.</summary>
    public void Stop()
    {
        if (_handle.IsInvalid || _handle.IsClosed)
        {
            return;
        }
        IntPtr raw = _handle.DangerousGetHandle();
        _handle.SetHandleAsInvalid();
        Native.Check(Native.ciplink_server_stop(raw));
    }

    /// <summary>Stops the server (see <see cref="Stop"/>), ignoring a failed shutdown.</summary>
    public void Dispose() => _handle.Dispose();
}

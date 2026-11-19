using System.Diagnostics;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Ciplink.Tests;

/// <summary>
/// Runs tools/sim/example_modbus.json twice for the whole test run: as Modbus TCP and as RTU over TCP (the way a
/// serial gateway frames it), so RTU is tested without a serial port.
/// </summary>
public sealed class ModbusSimulators : IDisposable
{
    private readonly List<Process> _processes = new();

    public ModbusSimulators()
    {
        string repo = AppContext.BaseDirectory;
        while (!File.Exists(Path.Combine(repo, "tools", "sim", "example_modbus.json")))
        {
            repo = Path.GetDirectoryName(repo) ?? throw new InvalidOperationException("repository root not found");
        }
        Run(repo, "cargo", "build -p ciplink-sim");
        string exe = Path.Combine(repo, "target", "debug", OperatingSystem.IsWindows() ? "ciplink-sim.exe" : "ciplink-sim");
        string config = Path.Combine(repo, "tools", "sim", "example_modbus.json");
        TcpPath = "tcp://" + Start(exe, config, "mbap");
        RtuPath = "rtu+tcp://" + Start(exe, config, "rtu");
        MapFile = Path.Combine(repo, "tools", "sim", "example_modbus_map.csv");
    }

    /// <summary>"tcp://127.0.0.1:PORT" of the Modbus TCP simulator.</summary>
    public string TcpPath { get; }

    /// <summary>"rtu+tcp://127.0.0.1:PORT" of the RTU-over-TCP simulator.</summary>
    public string RtuPath { get; }

    /// <summary>tools/sim/example_modbus_map.csv.</summary>
    public string MapFile { get; }

    public void Dispose()
    {
        foreach (Process p in _processes)
        {
            try
            {
                p.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
                // already exited
            }
            p.Dispose();
        }
    }

    private static void Run(string dir, string file, string args)
    {
        using var p = Process.Start(new ProcessStartInfo(file, args) { WorkingDirectory = dir, UseShellExecute = false })!;
        p.WaitForExit();
        if (p.ExitCode != 0)
        {
            throw new InvalidOperationException($"{file} {args} failed with exit code {p.ExitCode}");
        }
    }

    private string Start(string exe, string config, string framing)
    {
        var p = Process.Start(new ProcessStartInfo(exe, $"--config \"{config}\" --port 0 --framing {framing}")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardInput = true,
        })!;
        _processes.Add(p);
        string? line = p.StandardOutput.ReadLine();
        Match m = Regex.Match(line ?? "", @"listening on (\S+)");
        if (!m.Success)
        {
            throw new InvalidOperationException($"simulator did not start: '{line}'");
        }
        return m.Groups[1].Value;
    }
}

[CollectionDefinition("modbus")]
public sealed class ModbusCollection : ICollectionFixture<ModbusSimulators> { }

/// <summary>ModbusDriver against the Modbus simulator: map tags, plain addresses, writes, device info, raw PDUs, sessions.</summary>
[Collection("modbus")]
public sealed class ModbusTests
{
    private static readonly TimeSpan Long = TimeSpan.FromSeconds(10);

    private readonly ModbusSimulators _sim;

    public ModbusTests(ModbusSimulators sim) => _sim = sim;

    private ModbusDriver Open(string path)
    {
        var mb = new ModbusDriver(path, new ModbusOptions { MapFile = _sim.MapFile, SocketTimeout = TimeSpan.FromSeconds(0.5) });
        mb.Open();
        return mb;
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
    public void Reads_map_tags_and_plain_addresses_in_both_framings()
    {
        foreach (string path in new[] { _sim.TcpPath, _sim.RtuPath })
        {
            using var mb = Open(path);
            Assert.True(mb.Connected);
            var r = mb.Read("Pump1_Speed", "Totals", "Recipe", "Tank_Level", "Pump1_Fault", "hr0", "Nope");
            Assert.Equal(123.456, (double)r[0].Value!, 4);
            Assert.Equal("REAL", r[0].DataType);
            // Totals[3] is the write test's
            Assert.Equal(new object?[] { 120L, 135L, 99L }, ((object?[])r[1].Value!)[..3]);
            Assert.Equal("MIX-A", r[2].Value);
            Assert.Equal(52.3, (double)r[3].Value!, 9);
            Assert.Equal(true, r[4].Value);
            Assert.Equal(59769L, r[5].Value);
            Assert.False(r[6].IsOk);
            Assert.Equal("not_found", r[6].ErrorKind);
        }
    }

    [Fact]
    public void Writes_coils_registers_and_a_register_bit()
    {
        using var mb = Open(_sim.TcpPath);
        var w = mb.Write(("Totals[3]", 9), ("Horn", true), ("hr710:float32:badc", 3.5f), ("co60", true));
        Assert.All(w, t => Assert.True(t.IsOk, t.Error));
        Assert.Equal("access", mb.Write("Drive_Status", 1).ErrorKind);
        Assert.False(mb.Write("Pump1_Fault", true).IsOk);
        var r = mb.Read("Totals[3]", "Horn", "hr710:float32:badc", "co60", "hr301");
        Assert.Equal(9L, r[0].Value);
        Assert.Equal(true, r[1].Value);
        Assert.Equal(3.5, r[2].Value);
        Assert.Equal(true, r[3].Value);
        Assert.Equal(0x10L, (long)r[4].Value! & 0x10);
    }

    [Fact]
    public void Tags_device_info_and_send_pdu()
    {
        using var mb = Open(_sim.RtuPath);
        JsonArray tags = mb.Tags;
        Assert.Equal(10, tags.Count);
        Assert.Equal("Pump1_Speed", (string)tags[0]!["name"]!);
        Assert.Equal("Pump 1 speed setpoint", (string)tags[0]!["description"]!);
        Assert.Equal("float32", (string)tags[0]!["type"]!);
        Assert.Equal("CDAB", (string)tags[0]!["order"]!);
        Assert.Equal("LREAL", (string)tags[3]!["cip_type"]!);
        Assert.Equal(4, (int)tags[8]!["bit"]!);

        JsonObject info = mb.DeviceInfo();
        Assert.Equal("ciplink", (string)info["vendor_name"]!);
        Assert.Equal("SIM-MB", (string)info["product_code"]!);
        Assert.Null(info["vendor_url"]);
        Assert.Equal(CiplinkStatus.Response, Assert.Throws<CiplinkException>(() => mb.DeviceInfo(2)).Status);

        Assert.Equal(new byte[] { 3, 2, 0xE9, 0x79 }, mb.SendPdu(new byte[] { 3, 0, 0, 0, 1 }));
        // holding 500 is a hole: exception 02
        Assert.Equal(CiplinkStatus.Response, Assert.Throws<CiplinkException>(() => mb.SendPdu(new byte[] { 3, 0x01, 0xF4, 0, 1 })).Status);
        Assert.Throws<ArgumentNullException>(() => mb.SendPdu(null!));
    }

    [Fact]
    public async Task Async_calls_subscriptions_and_connection_events()
    {
        using var mb = new ModbusDriver(_sim.TcpPath, new ModbusOptions { MapFile = _sim.MapFile });
        var events = new List<string>();
        mb.ConnectionChanged += (_, e) =>
        {
            lock (events)
            {
                events.Add(e.Event);
            }
        };
        mb.Open();
        Assert.True((await mb.WriteAsync(("co70", false)))[0].IsOk);
        var r = await mb.ReadAsync("co70", "Pump1_Speed");
        Assert.Equal(false, r[0].Value);

        var seen = new List<object?>();
        using (Subscription sub = mb.Subscribe(new[] { "co70" }, TimeSpan.FromMilliseconds(20), changed: tags =>
        {
            lock (seen)
            {
                seen.AddRange(tags.Select(t => t.Value));
            }
        }))
        {
            WaitFor(() => { lock (seen) { return seen.Contains(false); } }, "the first value");
            mb.Write("co70", true);
            WaitFor(() => { lock (seen) { return seen.Contains(true); } }, "the change");
        }

        WaitFor(() => { lock (events) { return events.Contains("connected"); } }, "the connected event");
        Assert.Equal(ConnectionState.Connected, mb.ConnectionState);
        mb.Close();
        Assert.Equal(ConnectionState.Closed, mb.ConnectionState);
    }

    [Fact]
    public void Cip_calls_are_unsupported_and_options_are_checked()
    {
        using var mb = new ModbusDriver(_sim.TcpPath);
        Assert.Equal(CiplinkStatus.Unsupported, Assert.Throws<CiplinkException>(() => mb.GetIdentity()).Status);
        Assert.Equal(CiplinkStatus.Unsupported, Assert.Throws<CiplinkException>(() => mb.ConnectionSize).Status);
        Assert.Equal(TimeSpan.FromSeconds(1), mb.SocketTimeout);
        mb.SocketTimeout = TimeSpan.FromSeconds(2);
        Assert.Equal(TimeSpan.FromSeconds(2), mb.SocketTimeout);
        Assert.Equal(CiplinkStatus.InvalidArgument,
            Assert.Throws<CiplinkException>(() => mb.SocketTimeout = Timeout.InfiniteTimeSpan).Status);
        Assert.Empty(mb.Tags);

        Assert.Equal(CiplinkStatus.InvalidArgument,
            Assert.Throws<CiplinkException>(() => new ModbusDriver(_sim.TcpPath, new ModbusOptions { WordOrder = "XYZW" })).Status);
        Assert.Equal(CiplinkStatus.Request,
            Assert.Throws<CiplinkException>(() => new ModbusDriver(_sim.TcpPath, new ModbusOptions { MaxRegisters = 126 })).Status);
        Assert.Equal(CiplinkStatus.Request, Assert.Throws<CiplinkException>(() => new ModbusDriver("udp://127.0.0.1")).Status);
        // keep-alive off on a serial port is the default; setting it is allowed (the port is not opened here)
        using var serial = new ModbusDriver("rtu://COM9?baud=19200&parity=E", new ModbusOptions { KeepAlive = TimeSpan.Zero });
    }

    [Fact]
    public void Options_json_has_modbus_keys_and_scheme_keep_alive()
    {
        JsonObject o = JsonNode.Parse(new ModbusOptions { MapFile = "m.csv", WordOrder = "CDAB" }.ToJson())!.AsObject();
        Assert.Equal("m.csv", (string)o["map_file"]!);
        Assert.Equal("CDAB", (string)o["word_order"]!);
        Assert.Equal(1.0, (double)o["socket_timeout"]!);
        Assert.False(o.ContainsKey("keep_alive"));
        Assert.False(o.ContainsKey("connection_size"));
        Assert.True(JsonNode.Parse(new ModbusOptions { KeepAlive = TimeSpan.Zero }.ToJson())!.AsObject().ContainsKey("keep_alive"));
        Assert.Null(JsonNode.Parse(new ModbusOptions { KeepAlive = TimeSpan.Zero }.ToJson())!["keep_alive"]);
        Assert.Equal(5.0, (double)JsonNode.Parse(new ModbusOptions { KeepAlive = TimeSpan.FromSeconds(5) }.ToJson())!["keep_alive"]!);
    }
}

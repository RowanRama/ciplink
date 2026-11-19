using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Ciplink.Tests;

/// <summary>Runs tools/sim/example_s7plus.json (an S7comm-plus CPU over TLS) for the whole test run.</summary>
public sealed class S7PlusSimulator : IDisposable
{
    private readonly Process _process;
    private readonly object _commandLock = new();

    public S7PlusSimulator()
    {
        string repo = AppContext.BaseDirectory;
        while (!File.Exists(Path.Combine(repo, "tools", "sim", "example_s7plus.json")))
        {
            repo = Path.GetDirectoryName(repo) ?? throw new InvalidOperationException("repository root not found");
        }
        using (var build = Process.Start(new ProcessStartInfo("cargo", "build -p ciplink-sim") { WorkingDirectory = repo, UseShellExecute = false })!)
        {
            build.WaitForExit();
            if (build.ExitCode != 0) throw new InvalidOperationException("cargo build -p ciplink-sim failed");
        }
        string exe = Path.Combine(repo, "target", "debug", OperatingSystem.IsWindows() ? "ciplink-sim.exe" : "ciplink-sim");
        string config = Path.Combine(repo, "tools", "sim", "example_s7plus.json");
        _process = Process.Start(new ProcessStartInfo(exe, $"--config \"{config}\" --port 0")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardInput = true,
        })!;
        string? line = _process.StandardOutput.ReadLine();
        Match m = Regex.Match(line ?? "", @"listening on (\S+)");
        if (!m.Success) throw new InvalidOperationException($"simulator did not start: '{line}'");
        Path_ = m.Groups[1].Value;
        Fingerprint = Regex.Match(_process.StandardOutput.ReadLine() ?? "", @"fingerprint (\S+)").Groups[1].Value;
    }

    /// <summary>"127.0.0.1:PORT" of the simulator.</summary>
    public string Path_ { get; }

    /// <summary>The fingerprint of the simulator's certificate, as it printed it.</summary>
    public string Fingerprint { get; }

    /// <summary>Sends one command on the simulator's standard input and returns its "ok" result.</summary>
    public JsonNode? Command(string json)
    {
        lock (_commandLock)
        {
            _process.StandardInput.WriteLine(json);
            _process.StandardInput.Flush();
            string answer = _process.StandardOutput.ReadLine() ?? throw new InvalidOperationException("simulator exited");
            JsonObject o = JsonNode.Parse(answer)!.AsObject();
            if (o.TryGetPropertyValue("error", out JsonNode? error)) throw new InvalidOperationException($"simulator {json}: {error}");
            return o["ok"];
        }
    }

    public void Dispose()
    {
        try
        {
            _process.Kill(entireProcessTree: true);
        }
        catch (InvalidOperationException)
        {
            // already exited
        }
        _process.Dispose();
    }
}

[CollectionDefinition("s7plus")]
public sealed class S7PlusCollection : ICollectionFixture<S7PlusSimulator> { }

/// <summary>S7PlusDriver against the S7comm-plus simulator: reads, writes, browse, CPU info, pinning, sessions.</summary>
[Collection("s7plus")]
public sealed class S7PlusTests
{
    private static readonly TimeSpan Long = TimeSpan.FromSeconds(10);

    private readonly S7PlusSimulator _sim;

    public S7PlusTests(S7PlusSimulator sim) => _sim = sim;

    private S7PlusDriver OpenPlc(S7PlusOptions? options = null)
    {
        var plc = new S7PlusDriver(_sim.Path_, options);
        plc.Open();
        return plc;
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
    public void Reads_and_writes_with_S7_types()
    {
        using S7PlusDriver plc = OpenPlc();
        Assert.True(plc.Connected);
        IReadOnlyList<Tag> r = plc.Read("Line1.Conveyor.Speed", "Line1.Status", "Mode", "Line1.Nope");
        Assert.Equal(1.5, Convert.ToDouble(r[0].Value));
        Assert.Equal("REAL", r[0].DataType);
        Assert.Equal(4660L, Convert.ToInt64(r[1].Value));
        Assert.Equal("WORD", r[1].DataType);
        Assert.Equal(3L, Convert.ToInt64(r[2].Value));
        Assert.Equal("not_found", r[3].ErrorKind);

        Assert.Null(plc.Write("Line1.Label", "Batch7").Error);
        Assert.Equal("Batch7", plc.Read("Line1.Label").Value);
        IReadOnlyList<Tag> w = plc.Write(("Line1.Count", 42), ("Line1.Count", "x"));
        Assert.Null(w[0].Error);
        Assert.Equal("bad_value", w[1].ErrorKind);
        Assert.Equal(42L, Convert.ToInt64(plc.Read("Line1.Count").Value));
        Assert.Equal(42L, (long)_sim.Command("{\"cmd\": \"value\", \"path\": \"Line1.Count\"}")!);
    }

    [Fact]
    public void Reads_past_the_PLC_limit_are_split()
    {
        using S7PlusDriver plc = OpenPlc(new S7PlusOptions { KeepAlive = null });
        string[] names = Enumerable.Range(1, 250).Select(i => $"Line1.Items[{i}]").ToArray();
        long before = (long)_sim.Command("{\"cmd\": \"requests\"}")!;
        IReadOnlyList<Tag> r = plc.Read(names);
        Assert.Equal(250, r.Count);
        Assert.All(r, t => Assert.Null(t.Error));
        Assert.Equal(3, (long)_sim.Command("{\"cmd\": \"requests\"}")! - before);
    }

    [Fact]
    public void Browse_and_cpu_info()
    {
        using S7PlusDriver plc = OpenPlc();
        JsonObject tags = plc.Tags();
        Assert.Equal("data_block", (string)tags["Line1"]!["kind"]!);
        Assert.Equal("BOOL", (string)tags["StartButton"]!["type"]!);
        Assert.NotEmpty(plc.DataTypes());
        Assert.Contains(plc.TagList(), s => (string)s!["name"]! == "Line1.Conveyor.Speed");
        JsonObject info = plc.TagInfo("Line1.Hidden");
        Assert.Equal("INT", (string)info["type"]!);
        Assert.False((bool)info["hmi_accessible"]!);
        Assert.Equal(CiplinkStatus.Request, Assert.Throws<CiplinkException>(() => plc.TagInfo("Line1.Nope")).Status);

        JsonObject cpu = plc.GetPlcInfo();
        Assert.Equal("PLC_Line1", (string)cpu["name"]!);
        Assert.Equal(100, (int)cpu["max_read"]!);
        Assert.False(plc.RefreshTags());
        Assert.Equal(TimeSpan.FromSeconds(10), plc.SocketTimeout);

        Assert.Equal(CiplinkStatus.Unsupported, Assert.Throws<CiplinkException>(() => plc.GetIdentity()).Status);
        Assert.Equal(CiplinkStatus.Unsupported, Assert.Throws<CiplinkException>(() => plc.ConnectionSize).Status);
    }

    [Fact]
    public void Fingerprint_is_exposed_and_can_be_pinned()
    {
        using var plc = new S7PlusDriver(_sim.Path_);
        Assert.Null(plc.CertificateFingerprint);
        plc.Open();
        Assert.Equal(_sim.Fingerprint, plc.CertificateFingerprint);

        using S7PlusDriver pinned = OpenPlc(new S7PlusOptions { TlsFingerprint = _sim.Fingerprint.Replace(":", "").ToLowerInvariant() });
        Assert.True(pinned.Connected);

        using var wrong = new S7PlusDriver(_sim.Path_, new S7PlusOptions { TlsFingerprint = new string('0', 64) });
        Assert.Equal(CiplinkStatus.Comm, Assert.Throws<CiplinkException>(wrong.Open).Status);
        Assert.Equal(_sim.Fingerprint, wrong.CertificateFingerprint);

        Assert.Equal(CiplinkStatus.Request,
            Assert.Throws<CiplinkException>(() => new S7PlusDriver(_sim.Path_, new S7PlusOptions { TlsFingerprint = "zz" })).Status);
    }

    [Fact]
    public async Task Async_subscriptions_and_reconnect_events()
    {
        var events = new ConcurrentQueue<ConnectionEventArgs>();
        using var plc = new S7PlusDriver(_sim.Path_, new S7PlusOptions { ReconnectMin = TimeSpan.FromMilliseconds(50) });
        plc.ConnectionChanged += (_, e) => events.Enqueue(e);
        plc.Open();

        Task<IReadOnlyList<Tag>> read = plc.ReadAsync("Line1.Status");
        Task<IReadOnlyList<Tag>> write = plc.WriteAsync(("Line1.Count", 5));
        Assert.Equal(4660L, Convert.ToInt64((await read)[0].Value));
        Assert.Null((await write)[0].Error);

        var seen = new ConcurrentQueue<long>();
        using (Subscription sub = plc.Subscribe(new[] { "Line1.Count" }, TimeSpan.FromMilliseconds(50),
            changed: changes => { foreach (Tag t in changes) if (t.Error is null) seen.Enqueue(Convert.ToInt64(t.Value)); }))
        {
            WaitFor(() => seen.Contains(5), "the first value");
            plc.Write("Line1.Count", 6);
            WaitFor(() => seen.Contains(6), "the change");
        }

        _sim.Command("{\"cmd\": \"fault\", \"fault\": {\"close_connections\": true}}");
        // the next request finds the link gone; the driver reconnects in the background
        try
        {
            plc.Read("Line1.Count");
        }
        catch (CiplinkException)
        {
        }
        WaitFor(() => events.Count(e => e.Event == "connected") >= 2, "the reconnect");
        Assert.Contains(events, e => e.Event == "disconnected");
        Assert.Contains(events, e => e.Event == "reconnecting");
        Assert.Equal(ConnectionState.Connected, plc.ConnectionState);
        Assert.Equal(6L, Convert.ToInt64(plc.Read("Line1.Count").Value));
    }
}

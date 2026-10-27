namespace Ciplink.Tests;

/// <summary>The adapter on 127.0.0.1 with free ports. Class 1 I/O is tested in Rust (crates/ciplink-sim/tests).</summary>
public sealed class AdapterTests
{
    private static Adapter Station() => new(new AdapterConfig
    {
        Inputs = new Dictionary<uint, int> { [100] = 8 },
        Outputs = new Dictionary<uint, int> { [150] = 4 },
        Configs = new Dictionary<uint, int> { [199] = 0 },
        ProductName = "Station",
        ProductCode = 7,
        Revision = (2, 3),
        AppName = "Station",
        Bind = "127.0.0.1",
        Port = 0,
        IoPort = 0,
    });

    [Fact]
    public void Adapter_serves_its_assemblies()
    {
        using var adapter = Station();
        adapter.SetInput(100, new byte[] { 1, 2 });
        Assert.Equal(new byte[] { 1, 2, 0, 0, 0, 0, 0, 0 }, adapter.Input(100));
        AdapterOutput output = adapter.Output(150);
        Assert.False(output.Run); // nothing from a controller yet
        Assert.Equal(new byte[4], output.Data);
        Assert.Empty(adapter.Config(199));
        Assert.Null(adapter.NextEvent(TimeSpan.FromMilliseconds(50)));
        Assert.Empty(adapter.Connections());
        Assert.Equal(0, (long)adapter.Stats()["produced"]!);
        var e = Assert.Throws<CiplinkException>(() => adapter.SetInput(101, Array.Empty<byte>()));
        Assert.Equal(CiplinkStatus.Request, e.Status);
    }

    [Fact]
    public void Browsers_read_its_identity_and_app_line()
    {
        using var adapter = Station();
        adapter.SetDetail("station 2");
        using var browser = new CipDriver(adapter.Address);
        browser.Open();
        var identity = browser.GetIdentity();
        Assert.Equal("Station", (string)identity["product_name"]!);
        Assert.Equal(2, (int)identity["revision"]!["major"]!);
        Assert.Equal("Station · station 2 · no connection", (string)browser.GetApp()!["summary"]!);
    }

    [Fact]
    public async Task Stop_wakes_a_waiting_thread_and_later_calls_throw()
    {
        using var adapter = Station();
        var waiting = Task.Run(() => adapter.NextEvent());
        await Task.Delay(200);
        adapter.Stop();
        Assert.Null(await waiting.WaitAsync(TimeSpan.FromSeconds(2)));
        var e = Assert.Throws<CiplinkException>(() => adapter.Input(100));
        Assert.Equal(CiplinkStatus.InvalidArgument, e.Status);
        adapter.Stop(); // twice is fine
    }

    [Fact]
    public void A_bad_config_is_refused()
    {
        var e = Assert.Throws<CiplinkException>(() => new Adapter(new AdapterConfig
        {
            Inputs = new Dictionary<uint, int> { [100] = 8 },
            Outputs = new Dictionary<uint, int> { [100] = 4 },
            Port = 0,
            IoPort = 0,
        }));
        Assert.Equal(CiplinkStatus.Request, e.Status);
    }
}

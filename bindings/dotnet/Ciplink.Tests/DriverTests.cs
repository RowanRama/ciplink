using System.Text.Json.Nodes;

namespace Ciplink.Tests;

[Collection("sim")]
public sealed class LogixTests
{
    private readonly Simulators _sim;

    public LogixTests(Simulators sim) => _sim = sim;

    private LogixDriver OpenPlc()
    {
        var plc = new LogixDriver(_sim.LogixPath);
        plc.Open();
        return plc;
    }

    [Fact]
    public void Open_connects_and_close_disconnects()
    {
        using var plc = new LogixDriver(_sim.LogixPath);
        Assert.False(plc.Connected);
        plc.Open();
        Assert.True(plc.Connected);
        plc.Close();
        Assert.False(plc.Connected);
        plc.Open();
        Assert.True(plc.Connected);
    }

    [Fact]
    public void Read_atomic_tags_returns_typed_values()
    {
        using var plc = OpenPlc();
        IReadOnlyList<Tag> r = plc.Read("dint1", "sint1", "lint1", "ulint1", "real1", "lreal1");
        Assert.Equal(6, r.Count);
        Assert.All(r, t => Assert.True(t.IsOk, t.Error));
        Assert.Equal(new Tag("dint1", 2147483647L, "DINT", null, null), r[0]);
        Assert.IsType<long>(r[1].Value);
        Assert.IsType<long>(r[2].Value);
        Assert.Equal("ULINT", r[3].DataType);
        Assert.IsType<double>(r[4].Value);
        Assert.IsType<double>(r[5].Value);
    }

    [Fact]
    public void Write_atomic_then_read_back()
    {
        using var plc = OpenPlc();
        Assert.True(plc.Write("dint1", 1234).IsOk);
        Assert.True(plc.Write("real1", 0.5).IsOk);
        Assert.True(plc.Write("lint1", -9000000000L).IsOk);
        Assert.True(plc.Write("lreal1", 2.0).IsOk); // a whole double still goes out as a float
        Assert.Equal(1234L, plc.Read("dint1").Value);
        Assert.Equal(0.5, plc.Read("real1").Value);
        Assert.Equal(-9000000000L, plc.Read("lint1").Value);
        Assert.Equal(2.0, plc.Read("lreal1").Value);

        IReadOnlyList<Tag> batch = plc.Write(("dint1", 7), ("int1", (short)-1234));
        Assert.All(batch, t => Assert.True(t.IsOk, t.Error));
        Assert.Equal(new[] { "dint1", "int1" }, batch.Select(t => t.Name));
    }

    [Fact]
    public void Arrays_read_and_write_as_object_arrays()
    {
        using var plc = OpenPlc();
        Tag t = plc.Read("dint_ary[1]{3}");
        Assert.True(t.IsOk, t.Error);
        Assert.Equal(3, Assert.IsType<object?[]>(t.Value).Length);
        Assert.True(plc.Write("dint_ary[0]{2}", new[] { 7, 8 }).IsOk);
        Assert.Equal(new object?[] { 7L, 8L }, plc.Read("dint_ary[0]{2}").Value);
        Assert.Equal(5, ((object?[])plc.Read("real_ary{5}").Value!).Length);
    }

    [Fact]
    public void Structs_read_as_ordered_dictionaries_and_write_from_dictionaries()
    {
        using var plc = OpenPlc();
        Tag t = plc.Read("udt1");
        Assert.Equal("AtomicUDT", t.DataType);
        var udt = Assert.IsType<Dictionary<string, object?>>(t.Value);
        Assert.Equal(new[] { "bool", "sint", "int", "dint", "lint", "real" }, udt.Keys);

        var s = new Dictionary<string, object?> { ["bool"] = false, ["sint"] = 1, ["int"] = 2, ["dint"] = 3, ["lint"] = 4, ["real"] = 0.25 };
        Assert.True(plc.Write("udt1", s).IsOk);
        Assert.Equal(0.25, plc.Read("udt1.real").Value);
        Assert.Equal(3L, plc.Read("udt1.dint").Value);
        Assert.Equal(5000L, plc.Read("timer1.PRE").Value);
    }

    [Fact]
    public void Strings_read_and_write()
    {
        using var plc = OpenPlc();
        Assert.Equal("Hello Logix", plc.Read("str1").Value);
        Assert.True(plc.Write("str20", "hi there").IsOk);
        Assert.Equal("hi there", plc.Read("str20").Value);
        Tag tooLong = plc.Write("str20", new string('x', 30));
        Assert.False(tooLong.IsOk);
        Assert.Equal("bad_value", tooLong.ErrorKind);
    }

    [Fact]
    public void Bits_read_and_write()
    {
        using var plc = OpenPlc();
        Assert.Equal(true, plc.Read("bool1").Value);
        Assert.True(plc.Write("bool2", true).IsOk);
        Assert.Equal(true, plc.Read("bool2").Value);
        Assert.True(plc.Write("dint_ary[5].3", true).IsOk);
        Assert.Equal(true, plc.Read("dint_ary[5].3").Value);
        Assert.True(plc.Write("dint_ary[5].3", false).IsOk);
        Assert.Equal(false, plc.Read("dint_ary[5].3").Value);
    }

    [Fact]
    public void Per_tag_errors_are_data_with_an_error_kind()
    {
        using var plc = OpenPlc();
        IReadOnlyList<Tag> r = plc.Read("no_such_tag", "int1");
        Assert.False(r[0].IsOk);
        Assert.Equal("not_found", r[0].ErrorKind);
        Assert.False(string.IsNullOrEmpty(r[0].Error));
        Assert.Null(r[0].Value);
        Assert.True(r[1].IsOk);

        Tag w = plc.Write("sint1", 1000);
        Assert.Equal("bad_value", w.ErrorKind);
    }

    [Fact]
    public void Whole_call_failures_throw_with_a_status()
    {
        var e = Assert.Throws<CiplinkException>(() => new LogixDriver("127.0.0.1", new LogixOptions { ConnectionSize = -5 }));
        Assert.Equal(CiplinkStatus.InvalidArgument, e.Status);

        using var refused = new LogixDriver("127.0.0.1:1", new LogixOptions { SocketTimeout = TimeSpan.FromSeconds(1) });
        e = Assert.Throws<CiplinkException>(refused.Open);
        Assert.Equal(CiplinkStatus.Comm, e.Status);
        Assert.False(string.IsNullOrEmpty(e.Message));

        using var plc = new LogixDriver(_sim.LogixPath);
        Assert.Throws<ArgumentException>(() => plc.Write("dint1", new object()));
    }

    [Fact]
    public void Tags_tag_list_info_and_data_types()
    {
        using var plc = OpenPlc();
        Assert.Equal("DINT", (string?)plc.Tags()["dint1"]!["data_type"]);
        Assert.NotEmpty(plc.TagList());
        Assert.Equal("1756-SIM/A", (string?)plc.Info()["product_name"]);
        Assert.Equal("DINT", (string?)plc.TagInfo("udt1.dint")!["data_type"]);
        Assert.True(plc.DataTypes().ContainsKey("AtomicUDT"));
    }

    [Fact]
    public void Plc_time_round_trips_as_utc_datetime()
    {
        using var plc = OpenPlc();
        var when = new DateTime(2023, 11, 14, 22, 13, 20, DateTimeKind.Utc);
        Assert.True(plc.SetPlcTime(when).IsOk);
        Tag t = plc.GetPlcTime();
        Assert.True(t.IsOk, t.Error);
        Assert.True(Assert.IsType<DateTime>(t.Value) >= when);
    }

    [Fact]
    public void Generic_message_returns_reply_bytes()
    {
        using var plc = OpenPlc();
        Tag t = plc.GenericMessage(new Message
        {
            Service = 0x0e, // Get Attribute Single
            ClassCode = 1,  // Identity
            Instance = 1,
            Attribute = 3,  // product code
            Connected = false,
            Name = "product_code",
        });
        Assert.True(t.IsOk, t.Error);
        Assert.Equal("product_code", t.Name);
        Assert.Equal(new byte[] { 0xa6, 0x00 }, t.Value);
        Assert.Equal("1756-SIM/A", (string?)CipDriver.ListIdentity(_sim.LogixPath)!["product_name"]);
    }

    [Fact]
    public void Cip_driver_does_not_support_tag_reads()
    {
        using var cip = new CipDriver(_sim.LogixPath);
        cip.Open();
        Assert.Equal(CiplinkStatus.Unsupported, Assert.Throws<CiplinkException>(() => cip.Read("dint1")).Status);
    }

    [Fact]
    public async Task One_driver_serves_several_threads()
    {
        using var plc = OpenPlc();
        Task<bool>[] workers = Enumerable.Range(0, 4)
            .Select(_ => Task.Run(() => Enumerable.Range(0, 20).All(_ => Equals(plc.Read("int1").Value, -1234L))))
            .ToArray();
        Assert.All(await Task.WhenAll(workers), Assert.True);
        IReadOnlyList<Tag> r = await plc.ReadAsync("int1", "dint1");
        Assert.Equal(2, r.Count);
    }

    [Fact]
    public void Dispose_closes_and_later_calls_throw_object_disposed()
    {
        var plc = OpenPlc();
        plc.Dispose();
        Assert.False(plc.Connected);
        Assert.Throws<ObjectDisposedException>(() => plc.Read("dint1"));
        Assert.Throws<ObjectDisposedException>(plc.Open);
        plc.Dispose(); // twice is fine
        Assert.False(string.IsNullOrEmpty(Driver.Version));
    }
}

[Collection("sim")]
public sealed class SlcTests
{
    private readonly Simulators _sim;

    public SlcTests(Simulators sim) => _sim = sim;

    [Fact]
    public void Slc_reads_and_writes_files()
    {
        using var slc = new SlcDriver(_sim.SlcPath);
        slc.Open();
        Assert.True(slc.Write("N7:1", 42).IsOk);
        Assert.Equal(42L, slc.Read("N7:1").Value);
        Assert.Equal(2, ((object?[])slc.Read("N7:0{2}").Value!).Length);
        Assert.False(slc.Read("N99:0").IsOk);
    }

    [Fact]
    public void Slc_processor_type_file_directory_and_datalog()
    {
        using var slc = new SlcDriver(_sim.SlcPath);
        slc.Open();
        Assert.Equal("1747-L552", slc.GetProcessorType());
        Assert.True(slc.GetFileDirectory()["N7"]!["elements"]!.GetValue<long>() > 0);
        Assert.Equal(2, slc.GetDatalogQueue(2, 1).Count);
        Assert.NotNull(slc.GetModuleInfo(0));
    }
}

[Collection("sim")]
public sealed class BrowseTests
{
    private readonly Simulators _sim;

    public BrowseTests(Simulators sim) => _sim = sim;

    [Fact]
    public void Browsing_lists_ports_slots_and_the_devices_on_the_network()
    {
        using var cip = new CipDriver(_sim.LogixPath);
        cip.Open();
        Assert.Equal("1756-SIM/A", cip.GetIdentity()["product_name"]!.GetValue<string>());
        Assert.Equal("1756-EN2T/D", cip.GetIdentity("bp/1")["product_name"]!.GetValue<string>());
        JsonArray ports = cip.GetPorts();
        Assert.Equal("Backplane", ports[0]!["type_name"]!.GetValue<string>());
        Assert.Equal(10, ports[0]!["nodes"]!.AsArray().Count);
        Assert.Equal("EtherNet/IP", ports[1]!["type_name"]!.GetValue<string>());
        Assert.Equal("192.168.1.10", ports[1]!["ip"]!.GetValue<string>());

        JsonArray slots = cip.BrowsePort("", 1, new[] { "1", "2", "3" }, workers: 2);
        Assert.Equal("1/1", slots[0]!["route"]!.GetValue<string>());
        Assert.Equal("1756-IB16/A", slots[1]!["identity"]!["product_name"]!.GetValue<string>());
        Assert.Null(slots[2]!["identity"]);
        Assert.NotNull(slots[2]!["error"]);

        JsonArray subnet = cip.BrowsePort("", 2);  // the port's own addresses: its subnet
        Assert.Equal(254, subnet.Count);
        Assert.Equal(new[] { "2/192.168.1.20" },
            subnet.Where(n => n!["identity"] is not null).Select(n => n!["route"]!.GetValue<string>()));
    }

    [Fact]
    public void A_scan_calls_back_until_told_to_stop_and_rethrows()
    {
        using var plc = new LogixDriver(_sim.LogixPath);
        plc.Open();
        int seen = 0;
        string? first = null;
        plc.ScanPort("", 2, node =>
        {
            seen++;
            first = node["identity"]?["product_name"]?.GetValue<string>();
            return first is null;
        }, workers: 4);
        Assert.Equal("1734-AENTR/C", first);
        Assert.True(seen < 254);
        var e = Assert.Throws<InvalidOperationException>(() => plc.ScanPort("", 1, _ => throw new InvalidOperationException("stop")));
        Assert.Equal("stop", e.Message);
    }
}

[Collection("sim")]
public sealed class LogixInfoTests
{
    private readonly Simulators _sim;

    public LogixInfoTests(Simulators sim) => _sim = sim;

    [Fact]
    public void Plc_name_info_module_and_tag_table()
    {
        using var plc = new LogixDriver(_sim.LogixPath);
        plc.Open();
        Assert.Equal("SimPLC", plc.GetPlcName());
        Assert.Equal("REMOTE RUN", plc.GetPlcInfo()["keyswitch"]!.GetValue<string>());
        Assert.Equal("1756-EN2T/D", plc.GetModuleInfo(1)["product_name"]!.GetValue<string>());
        Assert.Equal(5, plc.TagTableVersion()!.Count);
        Assert.False(plc.CheckTagTable());
        Assert.Equal("dint1.@Description", plc.GetTagDescription("dint1").Name);
        Assert.Equal(2, plc.GetTagDescriptions(new[] { "dint1", "int1" }).Count);
        Assert.NotNull(plc.AuthenticateMetadata());
    }
}

public sealed class ValuesTests
{
    [Fact]
    public void Json_round_trips_every_value_form()
    {
        var v = new Dictionary<string, object?>
        {
            ["a"] = -5L,
            ["b"] = new object?[] { true, 1.5, "x\"\n", null },
            ["c"] = new byte[] { 0x00, 0xab },
            ["d"] = ulong.MaxValue,
            ["e"] = double.NaN,
            ["f"] = double.NegativeInfinity,
            ["g"] = long.MinValue,
            ["h"] = 2.0,
        };
        string json = Values.ToJson(v);
        Assert.Contains("{\"$bytes\":\"00ab\"}", json);
        Assert.Contains("\"h\":2.0", json);
        var back = Assert.IsType<Dictionary<string, object?>>(Values.FromJson(json));
        Assert.Equal(v.Keys, back.Keys);
        Assert.Equal(-5L, back["a"]);
        Assert.Equal(new object?[] { true, 1.5, "x\"\n", null }, back["b"]);
        Assert.Equal(new byte[] { 0x00, 0xab }, back["c"]);
        Assert.Equal(ulong.MaxValue, back["d"]);
        Assert.True(double.IsNaN((double)back["e"]!));
        Assert.Equal(double.NegativeInfinity, back["f"]);
        Assert.Equal(long.MinValue, back["g"]);
        Assert.Equal(2.0, back["h"]);
    }

    [Fact]
    public void Numbers_with_a_point_or_exponent_are_doubles()
    {
        Assert.IsType<double>(Values.FromJson("2.0"));
        Assert.IsType<double>(Values.FromJson("1e3"));
        Assert.IsType<long>(Values.FromJson("2"));
        Assert.Equal("1E+20", Values.ToJson(1e20));
        Assert.Equal("0.1", Values.ToJson(0.1f));
        Assert.Equal("\"é\"", Values.ToJson("é").Replace("\\u00E9", "é"));
    }

    [Fact]
    public void Unsupported_types_are_rejected()
    {
        Assert.Throws<ArgumentException>(() => Values.ToJson(new object()));
        Assert.Throws<ArgumentException>(() => Values.ToJson(new Dictionary<int, int> { [1] = 2 }));
    }
}

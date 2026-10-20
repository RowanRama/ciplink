using System.Text.Json.Nodes;

namespace Ciplink.Tests;

/// <summary>Raw CIP passthrough, connection settings, tag list arguments and caller-supplied credentials.</summary>
[Collection("sim")]
public sealed class ConnectionTests
{
    // Get Attribute Single of the identity's product code; its reply frame ends with 8e 00 00 00 a6 00
    private static readonly byte[] ProductCodeRequest = { 0x0e, 0x03, 0x20, 0x01, 0x24, 0x01, 0x30, 0x03 };
    private static readonly byte[] ProductCodeReply = { 0x8e, 0x00, 0x00, 0x00, 0xa6, 0x00 };

    private readonly Simulators _sim;

    public ConnectionTests(Simulators sim) => _sim = sim;

    private static bool EndsWithReply(byte[] frame) => frame.AsSpan().EndsWith(ProductCodeReply);

    [Fact]
    public void Raw_sends_return_reply_frames()
    {
        using var plc = new LogixDriver(_sim.LogixPath);
        plc.Open();
        byte[] u = plc.SendUnconnected(ProductCodeRequest);
        Assert.Equal(0x6f, u[0]); // SendRRData
        Assert.True(EndsWithReply(u), Convert.ToHexString(u));
        byte[] c = plc.SendConnected(ProductCodeRequest);
        Assert.Equal(0x70, c[0]); // SendUnitData
        Assert.True(EndsWithReply(c), Convert.ToHexString(c));

        using var slc = new SlcDriver(_sim.SlcPath);
        slc.Open();
        Assert.Equal(0x6f, slc.SendUnconnected(ProductCodeRequest)[0]);

        plc.Close();
        Assert.Equal(CiplinkStatus.Comm, Assert.Throws<CiplinkException>(() => plc.SendUnconnected(ProductCodeRequest)).Status);
        Assert.Throws<ArgumentNullException>(() => plc.SendUnconnected(null!));
    }

    [Fact]
    public void Connection_size_changes_only_while_closed()
    {
        using var plc = new LogixDriver(_sim.LogixPath);
        Assert.Equal(4000, plc.ConnectionSize);
        plc.ConnectionSize = 500;
        Assert.Equal(500, plc.ConnectionSize);
        Assert.Throws<ArgumentOutOfRangeException>(() => plc.ConnectionSize = 0);
        Assert.Throws<ArgumentOutOfRangeException>(() => plc.ConnectionSize = 65536);
        plc.Open();
        Assert.Equal(2000, ((object?[])plc.Read("big_ary{2000}").Value!).Length);
        Assert.Equal(CiplinkStatus.Request, Assert.Throws<CiplinkException>(() => plc.ConnectionSize = 4000).Status);
        plc.Close();
        plc.ConnectionSize = 4000;
        Assert.Equal(4000, plc.ConnectionSize);
    }

    [Fact]
    public void Socket_timeout_is_set_on_open_and_closed_drivers()
    {
        using var slc = new SlcDriver(_sim.SlcPath, new DriverOptions { SocketTimeout = TimeSpan.FromSeconds(3) });
        Assert.Equal(TimeSpan.FromSeconds(3), slc.SocketTimeout);
        slc.SocketTimeout = Timeout.InfiniteTimeSpan;
        Assert.Equal(Timeout.InfiniteTimeSpan, slc.SocketTimeout);
        Assert.Throws<ArgumentOutOfRangeException>(() => slc.SocketTimeout = TimeSpan.Zero);
        slc.Open();
        slc.SocketTimeout = TimeSpan.FromMilliseconds(2500);
        Assert.Equal(TimeSpan.FromMilliseconds(2500), slc.SocketTimeout);
        Assert.True(slc.Read("N7:0").IsOk);
    }

    [Fact]
    public void Tag_list_takes_program_cache_and_namespace_filter()
    {
        using var plc = new LogixDriver(_sim.LogixPath);
        plc.Open();
        JsonArray program = plc.TagList("MainProgram", cache: false);
        Assert.NotEmpty(program);
        Assert.All(program, t => Assert.StartsWith("Program:MainProgram.", (string?)t!["tag_name"]));
        Assert.True(plc.Tags().ContainsKey("dint1"));

        JsonArray filtered = plc.TagList(cache: false, tagNamespaceFilter: "dint");
        Assert.NotEmpty(filtered);
        Assert.All(filtered, t => Assert.StartsWith("dint", (string?)t!["tag_name"]));

        plc.TagList("MainProgram");
        JsonObject cached = plc.Tags();
        Assert.NotEmpty(cached);
        Assert.All(cached, kv => Assert.StartsWith("Program:MainProgram.", kv.Key));
    }

    [Fact]
    public void Authenticate_metadata_with_caller_credentials()
    {
        (byte[] cert, byte[] key) = SyntheticCredentials();
        using var plc = new LogixDriver(_sim.LogixPath);
        plc.Open();
        Tag t = plc.AuthenticateMetadata(cert, key);
        Assert.True(t.IsOk, t.Error);
        Assert.Equal("metadata_authentication", t.Name);
        Assert.Equal(true, t.Value);
        Assert.True(plc.AuthenticateMetadata().IsOk);
        Assert.Equal(CiplinkStatus.Request, Assert.Throws<CiplinkException>(() => plc.AuthenticateMetadata(cert, key[..10])).Status);
        Assert.Equal(CiplinkStatus.Request, Assert.Throws<CiplinkException>(() => plc.AuthenticateMetadata(Array.Empty<byte>(), Array.Empty<byte>())).Status);
    }

    /// <summary>The synthetic test credentials of the reference fixtures (not the bundled ones).</summary>
    private (byte[] Certificate, byte[] Key) SyntheticCredentials()
    {
        string path = Path.Combine(_sim.RepoPath, "crates", "ciplink", "tests", "fixtures", "logix_descriptions.json");
        JsonNode creds = JsonNode.Parse(File.ReadAllText(path))!["credentials"]!;
        return (Convert.FromHexString((string)creds["certificate"]!), Convert.FromHexString((string)creds["key"]!));
    }
}

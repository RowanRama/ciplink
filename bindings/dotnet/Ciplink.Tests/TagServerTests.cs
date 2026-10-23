using System.Net.Http;

namespace Ciplink.Tests;

/// <summary>The tag server, serving a mock PLC.</summary>
public sealed class TagServerTests
{
    private static string WriteConfig()
    {
        string dir = Path.Combine(Path.GetTempPath(), $"ciplink-dotnet-server-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "tags.json"), "{\"Speed\": \"REAL\"}");
        string config = Path.Combine(dir, "tagserver.toml");
        File.WriteAllText(config,
            "[server]\naudit_log = \"\"\npages_file = \"\"\n" +
            "[plc.P]\npath = \"192.0.2.1\"\nmock_tags = \"tags.json\"\n[token.t]\nsecret = \"s\"\n");
        return config;
    }

    [Fact]
    public async Task Tag_server_serves_until_stopped()
    {
        using var server = new TagServer(WriteConfig(), mock: true, port: 0);
        Assert.StartsWith("127.0.0.1:", server.Address);
        using var http = new HttpClient();
        string health = "";
        for (int i = 0; i < 50 && !health.Contains("\"connected\""); i++)
        {
            health = await http.GetStringAsync($"http://{server.Address}/health");
            await Task.Delay(50);
        }
        Assert.Contains("\"P\":{\"state\":\"connected\"", health);
        server.Stop();
        server.Stop(); // stopping twice is fine
    }

    [Fact]
    public void Tag_server_reports_a_bad_config()
    {
        var e = Assert.Throws<CiplinkException>(() => new TagServer("no/such/tagserver.toml"));
        Assert.Equal(CiplinkStatus.InvalidArgument, e.Status);
    }
}

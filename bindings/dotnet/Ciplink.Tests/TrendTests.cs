namespace Ciplink.Tests;

/// <summary>Controller-side trends against the simulator's trend object.</summary>
[Collection("sim")]
public sealed class TrendTests
{
    private readonly Simulators _sim;

    public TrendTests(Simulators sim) => _sim = sim;

    private LogixDriver OpenPlc()
    {
        var plc = new LogixDriver(_sim.LogixPath);
        plc.Open();
        return plc;
    }

    private static List<TrendSample> Collect(Trend trend, int count)
    {
        var samples = new List<TrendSample>();
        var deadline = DateTime.UtcNow.AddSeconds(2);
        while (samples.Count < count && DateTime.UtcNow < deadline)
        {
            samples.AddRange(trend.Read());
            Thread.Sleep(5);
        }
        return samples;
    }

    [Fact]
    public void Trend_samples_typed_values_until_closed()
    {
        using var plc = OpenPlc();
        string[] tags = { "sint1", "udint1", "timer1.ACC", "timer1.TT", "dint_ary[2]", "bool_ary[5]" };
        using Trend trend = plc.Trend(tags, new TrendOptions { PeriodMs = 5 });
        Assert.Equal(new TrendPen("timer1.TT", "BOOL"), trend.Pens[3]);
        Assert.True(trend.Running);
        List<TrendSample> samples = Collect(trend, 2);
        Assert.True(samples.Count >= 2);
        IReadOnlyList<Tag> reads = plc.Read(tags);
        Assert.Equal(reads.Select(t => t.Value), samples[0].Values);
        Assert.Equal(trend.StartTimeMicroseconds + samples[0].ElapsedMicroseconds, samples[0].TimestampMicroseconds);
        Assert.Equal(DateTimeKind.Utc, samples[0].Timestamp.Kind);
        Assert.InRange(samples[1].ElapsedMicroseconds - samples[0].ElapsedMicroseconds, 5000 - 128, 5000 + 128);
        trend.Close();
        Assert.False(trend.Running);
        Assert.Null(trend.Error);
    }

    [Fact]
    public void Trend_with_a_duration_stops_by_itself()
    {
        using var plc = OpenPlc();
        using Trend trend = plc.Trend(new[] { "dint1" }, new TrendOptions { PeriodMs = 5, Duration = TimeSpan.FromMilliseconds(50) });
        var deadline = DateTime.UtcNow.AddSeconds(2);
        while (trend.Running && DateTime.UtcNow < deadline)
        {
            Thread.Sleep(5);
        }
        Assert.False(trend.Running);
        Assert.Equal(trend.Received, trend.Read().Count);
    }

    [Fact]
    public void Untrendable_tags_throw_request_errors()
    {
        using var plc = OpenPlc();
        var e = Assert.Throws<CiplinkException>(() => plc.Trend("lreal1"));
        Assert.Equal(CiplinkStatus.Request, e.Status);
        Assert.Throws<CiplinkException>(() => plc.Trend("str1"));
    }
}

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Ciplink;

/// <summary>Options for <see cref="LogixDriver.Trend(string[], TrendOptions?)"/>.</summary>
public sealed class TrendOptions
{
    /// <summary>Sample period in milliseconds (whole microseconds); controllers accept 1 ms or more. Default 10.</summary>
    public double PeriodMs { get; init; } = 10;

    /// <summary>Samples kept until <see cref="Trend.Read"/>; when full the oldest are dropped. Default 4096.</summary>
    public int Capacity { get; init; } = 4096;

    /// <summary>Stop sampling after this long; null runs until the trend is closed. Default null.</summary>
    public TimeSpan? Duration { get; init; }

    internal string ToJson() => Values.ToJson(new Dictionary<string, object?>
    {
        ["period_ms"] = PeriodMs,
        ["capacity"] = Capacity,
        ["duration"] = Duration?.TotalSeconds,
    });
}

/// <summary>A pen of a trend: the tag and the type sampled ("BOOL" for a bit or a BOOL array element).</summary>
public sealed record TrendPen(string Tag, string DataType);

/// <summary>One sample of every pen of a trend.</summary>
/// <param name="Timestamp">Controller time of the sample, UTC.</param>
/// <param name="TimestampMicroseconds">Controller time of the sample, microseconds since 1970 UTC.</param>
/// <param name="ElapsedMicroseconds">Time since the trend started, microseconds.</param>
/// <param name="Values">One value per pen, in pen order (the types of <see cref="Tag.Value"/>).</param>
public sealed record TrendSample(
    DateTime Timestamp,
    long TimestampMicroseconds,
    long ElapsedMicroseconds,
    IReadOnlyList<object?> Values);

/// <summary>
/// A running controller-side trend, from <see cref="LogixDriver.Trend(string[], TrendOptions?)"/>: the controller
/// samples the pens every period into its trend buffer and a worker thread uploads them on a connection of its
/// own. <see cref="Close"/> stops it and waits for the cleanup; <see cref="Dispose"/> stops it without waiting.
/// </summary>
public sealed class Trend : IDisposable
{
    private readonly TrendHandle _handle;

    internal Trend(TrendHandle handle)
    {
        _handle = handle;
        JsonObject info = Info();
        var pens = new List<TrendPen>();
        foreach (JsonNode? pen in info["pens"]!.AsArray())
        {
            pens.Add(new TrendPen((string)pen!["tag"]!, (string)pen["type"]!));
        }
        Pens = pens;
        StartTimeMicroseconds = (long)info["start_time_us"]!;
    }

    /// <summary>The pens, in the order of the sample values.</summary>
    public IReadOnlyList<TrendPen> Pens { get; }

    /// <summary>Controller time the trend started, microseconds since 1970 UTC.</summary>
    public long StartTimeMicroseconds { get; }

    /// <summary>True until the trend is closed, its duration is over, or it failed.</summary>
    public bool Running => (bool)Info()["running"]!;

    /// <summary>Samples uploaded so far, including dropped ones.</summary>
    public long Received => (long)Info()["received"]!;

    /// <summary>Samples dropped because <see cref="TrendOptions.Capacity"/> samples were waiting to be read.</summary>
    public long Dropped => (long)Info()["dropped"]!;

    /// <summary>Why the trend failed, null if it has not.</summary>
    public string? Error => (string?)Info()["error"];

    /// <summary>
    /// Takes the samples uploaded since the last read, oldest first. Once the trend failed and every sample was
    /// taken, throws its error.
    /// </summary>
    /// <exception cref="CiplinkException">The trend failed and no samples are left.</exception>
    public IReadOnlyList<TrendSample> Read()
    {
        using var doc = JsonDocument.Parse(Native.CallJson((out IntPtr j) => Native.ciplink_trend_read(_handle, out j)));
        var samples = new List<TrendSample>(doc.RootElement.GetArrayLength());
        foreach (JsonElement s in doc.RootElement.EnumerateArray())
        {
            long timestamp = s.GetProperty("timestamp_us").GetInt64();
            var values = new List<object?>();
            foreach (JsonElement v in s.GetProperty("values").EnumerateArray())
            {
                values.Add(Values.FromElement(v));
            }
            samples.Add(new TrendSample(
                DateTime.UnixEpoch.AddTicks(timestamp * 10), timestamp, s.GetProperty("elapsed_us").GetInt64(), values));
        }
        return samples;
    }

    /// <summary>Stops the trend and waits for its cleanup; the samples uploaded until then can still be read.</summary>
    /// <exception cref="CiplinkException">The trend failed.</exception>
    public void Close() => Native.Check(Native.ciplink_trend_close(_handle));

    /// <summary>Stops the trend without waiting (the cleanup finishes in the background) and frees it.</summary>
    public void Dispose()
    {
        _handle.Dispose();
        GC.SuppressFinalize(this);
    }

    private JsonObject Info() =>
        (JsonObject)JsonNode.Parse(Native.CallJson((out IntPtr j) => Native.ciplink_trend_info(_handle, out j)))!;
}

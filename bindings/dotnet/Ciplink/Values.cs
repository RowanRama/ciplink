using System;
using System.Buffers;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Ciplink;

/// <summary>Converts between .NET values and the value JSON of the C ABI.</summary>
/// <remarks>
/// Integers are plain numbers (full i64/u64 range); REAL/LREAL always contain '.' or 'e'; non-finite floats are
/// <c>{"$float":"NaN"}</c>; bytes are <c>{"$bytes":"hex"}</c>; structures are objects in member order.
/// </remarks>
public static class Values
{
    /// <summary>Parses value JSON into a .NET value (see <see cref="Tag.Value"/> for the types).</summary>
    public static object? FromJson(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return FromElement(doc.RootElement);
    }

    /// <summary>Serializes a .NET value into value JSON.</summary>
    /// <exception cref="ArgumentException">The value has a type that has no PLC equivalent.</exception>
    public static string ToJson(object? value)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            Write(writer, value);
        }
        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    internal static object? FromElement(JsonElement e)
    {
        switch (e.ValueKind)
        {
            case JsonValueKind.Null:
            case JsonValueKind.Undefined:
                return null;
            case JsonValueKind.True:
                return true;
            case JsonValueKind.False:
                return false;
            case JsonValueKind.String:
                return e.GetString();
            case JsonValueKind.Number:
                string raw = e.GetRawText();
                if (raw.AsSpan().IndexOfAny(".eE") < 0)
                {
                    if (e.TryGetInt64(out long l))
                    {
                        return l;
                    }
                    if (e.TryGetUInt64(out ulong u))
                    {
                        return u;
                    }
                }
                return e.GetDouble();
            case JsonValueKind.Array:
                var items = new object?[e.GetArrayLength()];
                int i = 0;
                foreach (JsonElement item in e.EnumerateArray())
                {
                    items[i++] = FromElement(item);
                }
                return items;
            default:
                if (TryOnly(e, "$bytes", out string? hex))
                {
                    return Convert.FromHexString(hex);
                }
                if (TryOnly(e, "$float", out string? f))
                {
                    return f switch
                    {
                        "NaN" => double.NaN,
                        "Infinity" => double.PositiveInfinity,
                        "-Infinity" => double.NegativeInfinity,
                        _ => throw new FormatException($"bad $float value '{f}'"),
                    };
                }
                var members = new Dictionary<string, object?>();
                foreach (JsonProperty p in e.EnumerateObject())
                {
                    members[p.Name] = FromElement(p.Value);
                }
                return members;
        }
    }

    // An object with exactly one string member named `key`.
    private static bool TryOnly(JsonElement e, string key, out string value)
    {
        value = "";
        using var it = e.EnumerateObject();
        if (!it.MoveNext() || it.Current.Name != key || it.Current.Value.ValueKind != JsonValueKind.String)
        {
            return false;
        }
        value = it.Current.Value.GetString()!;
        return !it.MoveNext();
    }

    internal static void Write(Utf8JsonWriter w, object? value)
    {
        switch (value)
        {
            case null:
                w.WriteNullValue();
                break;
            case bool b:
                w.WriteBooleanValue(b);
                break;
            case sbyte or byte or short or ushort or int or uint or long:
                w.WriteNumberValue(Convert.ToInt64(value, CultureInfo.InvariantCulture));
                break;
            case ulong ul:
                w.WriteNumberValue(ul);
                break;
            case float f:
                WriteFloat(w, f, f.ToString("R", CultureInfo.InvariantCulture));
                break;
            case double d:
                WriteFloat(w, d, d.ToString("R", CultureInfo.InvariantCulture));
                break;
            case decimal m:
                double md = (double)m;
                WriteFloat(w, md, md.ToString("R", CultureInfo.InvariantCulture));
                break;
            case string s:
                w.WriteStringValue(s);
                break;
            case char c:
                w.WriteStringValue(c.ToString());
                break;
            case byte[] bytes:
                w.WriteStartObject();
                w.WriteString("$bytes", Convert.ToHexString(bytes).ToLowerInvariant());
                w.WriteEndObject();
                break;
            case JsonNode node:
                node.WriteTo(w);
                break;
            case JsonElement element:
                element.WriteTo(w);
                break;
            case IDictionary dict:
                w.WriteStartObject();
                foreach (DictionaryEntry entry in dict)
                {
                    w.WritePropertyName(entry.Key as string ?? throw new ArgumentException("structure member names must be strings"));
                    Write(w, entry.Value);
                }
                w.WriteEndObject();
                break;
            case IEnumerable seq:
                w.WriteStartArray();
                foreach (object? item in seq)
                {
                    Write(w, item);
                }
                w.WriteEndArray();
                break;
            default:
                throw new ArgumentException($"cannot write a value of type {value.GetType()} to a PLC");
        }
    }

    private static void WriteFloat(Utf8JsonWriter w, double value, string text)
    {
        if (!double.IsFinite(value))
        {
            w.WriteStartObject();
            w.WriteString("$float", double.IsNaN(value) ? "NaN" : value > 0 ? "Infinity" : "-Infinity");
            w.WriteEndObject();
            return;
        }
        // keep it a float on the wire: 1.0 must not turn into the integer 1
        if (text.AsSpan().IndexOfAny(".eE") < 0)
        {
            text += ".0";
        }
        w.WriteRawValue(text, skipInputValidation: true);
    }

    internal static Tag ParseTag(JsonElement e)
    {
        string name = e.GetProperty("tag").GetString() ?? "";
        object? value = e.TryGetProperty("value", out JsonElement v) ? FromElement(v) : null;
        string? type = e.TryGetProperty("type", out JsonElement t) && t.ValueKind == JsonValueKind.String ? t.GetString() : null;
        if (e.TryGetProperty("error", out JsonElement err) && err.ValueKind == JsonValueKind.Object)
        {
            return new Tag(
                name,
                value,
                type,
                err.TryGetProperty("message", out JsonElement m) ? m.GetString() ?? "" : "",
                err.TryGetProperty("kind", out JsonElement k) ? k.GetString() : "other",
                OptionalInt(err, "status"),
                OptionalInt(err, "ext"));
        }
        return new Tag(name, value, type, null, null);
    }

    private static int? OptionalInt(JsonElement e, string key) =>
        e.TryGetProperty(key, out JsonElement v) && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : null;

    internal static Tag[] ParseTags(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var tags = new Tag[doc.RootElement.GetArrayLength()];
        int i = 0;
        foreach (JsonElement e in doc.RootElement.EnumerateArray())
        {
            tags[i++] = ParseTag(e);
        }
        return tags;
    }

    internal static Tag ParseOneTag(string json)
    {
        using var doc = JsonDocument.Parse(json);
        JsonElement root = doc.RootElement;
        return root.ValueKind == JsonValueKind.Array ? ParseTag(root[0]) : ParseTag(root);
    }

    internal static string WriteItems(IReadOnlyList<(string Tag, object? Value)> items)
    {
        using var stream = new MemoryStream();
        using (var w = new Utf8JsonWriter(stream))
        {
            w.WriteStartArray();
            foreach ((string tag, object? value) in items)
            {
                w.WriteStartArray();
                w.WriteStringValue(tag);
                Write(w, value);
                w.WriteEndArray();
            }
            w.WriteEndArray();
        }
        return Encoding.UTF8.GetString(stream.ToArray());
    }
}

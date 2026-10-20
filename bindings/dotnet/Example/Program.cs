// Reads and writes a few tags. Usage: dotnet run --project Example -- <path>   e.g. 127.0.0.1:44818 or 192.168.1.10/0
using Ciplink;

string path = args.Length > 0 ? args[0] : "127.0.0.1";

using var plc = new LogixDriver(path, new LogixOptions { SocketTimeout = TimeSpan.FromSeconds(3) });
plc.Open();
Console.WriteLine($"ciplink {Driver.Version}, connected to {plc.Info()["product_name"]}");

foreach (Tag tag in plc.Read("dint1", "real1", "str1", "udt1", "no_such_tag"))
{
    Console.WriteLine(tag.IsOk
        ? $"{tag.Name} ({tag.DataType}) = {Show(tag.Value)}"
        : $"{tag.Name}: {tag.ErrorKind}: {tag.Error}");
}

Tag written = plc.Write("dint1", 42);
Console.WriteLine($"write {written.Name}: {(written.IsOk ? "ok" : written.Error)}, now {plc.Read("dint1").Value}");

static string Show(object? v) => v switch
{
    null => "null",
    byte[] b => Convert.ToHexString(b),
    object?[] a => "[" + string.Join(", ", a.Select(Show)) + "]",
    Dictionary<string, object?> d => "{" + string.Join(", ", d.Select(kv => $"{kv.Key}: {Show(kv.Value)}")) + "}",
    _ => Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture) ?? "",
};

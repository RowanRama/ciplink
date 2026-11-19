using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Ciplink.Tests;

/// <summary>Builds ciplink-sim once and runs a Logix and an SLC simulator on free ports for the whole test run.</summary>
public sealed class Simulators : IDisposable
{
    private readonly List<Process> _processes = new();
    private readonly object _commandLock = new();
    private Process _logix = null!;

    public Simulators()
    {
        string repo = FindRepo();
        RepoPath = repo;
        Run(repo, "cargo", "build -p ciplink-sim");
        string exe = Path.Combine(repo, "target", "debug", OperatingSystem.IsWindows() ? "ciplink-sim.exe" : "ciplink-sim");
        LogixPath = Start(exe, Path.Combine(repo, "tools", "sim", "example_controller.json"));
        _logix = _processes[^1];
        SlcPath = Start(exe, Path.Combine(repo, "tools", "sim", "example_slc.json"));
    }

    /// <summary>The repository root.</summary>
    public string RepoPath { get; }

    /// <summary>"127.0.0.1:PORT" of the Logix simulator.</summary>
    public string LogixPath { get; }

    /// <summary>"127.0.0.1:PORT" of the SLC simulator.</summary>
    public string SlcPath { get; }

    /// <summary>
    /// Sends one command to the Logix simulator on its standard input (see crates/ciplink-sim/src/main.rs), e.g.
    /// <c>{"cmd": "requests"}</c>, and returns its "ok" result; throws on an "error" answer.
    /// </summary>
    public System.Text.Json.Nodes.JsonNode? Command(string json)
    {
        lock (_commandLock)
        {
            _logix.StandardInput.WriteLine(json);
            _logix.StandardInput.Flush();
            string line = _logix.StandardOutput.ReadLine() ?? throw new InvalidOperationException("simulator exited");
            var answer = System.Text.Json.Nodes.JsonNode.Parse(line)!.AsObject();
            if (answer.TryGetPropertyValue("error", out var error))
            {
                throw new InvalidOperationException($"simulator {json}: {error}");
            }
            return answer["ok"];
        }
    }

    /// <summary>The number of requests the Logix simulator has received.</summary>
    public long Requests() => (long)Command("{\"cmd\": \"requests\"}")!;

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

    private static string FindRepo()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Cargo.toml")) && Directory.Exists(Path.Combine(dir.FullName, "tools", "sim")))
            {
                return dir.FullName;
            }
        }
        throw new InvalidOperationException("repository root (Cargo.toml + tools/sim) not found above " + AppContext.BaseDirectory);
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

    private string Start(string exe, string config)
    {
        var p = Process.Start(new ProcessStartInfo(exe, $"--config \"{config}\" --port 0")
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
        // after this line the simulator writes to stdout only to answer Command, which reads each answer
        return m.Groups[1].Value;
    }
}

[CollectionDefinition("sim")]
public sealed class SimCollection : ICollectionFixture<Simulators> { }

using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Ciplink.Tests;

/// <summary>Builds ciplink-sim once and runs a Logix and an SLC simulator on free ports for the whole test run.</summary>
public sealed class Simulators : IDisposable
{
    private readonly List<Process> _processes = new();

    public Simulators()
    {
        string repo = FindRepo();
        RepoPath = repo;
        Run(repo, "cargo", "build -p ciplink-sim");
        string exe = Path.Combine(repo, "target", "debug", OperatingSystem.IsWindows() ? "ciplink-sim.exe" : "ciplink-sim");
        LogixPath = Start(exe, Path.Combine(repo, "tools", "sim", "example_controller.json"));
        SlcPath = Start(exe, Path.Combine(repo, "tools", "sim", "example_slc.json"));
    }

    /// <summary>The repository root.</summary>
    public string RepoPath { get; }

    /// <summary>"127.0.0.1:PORT" of the Logix simulator.</summary>
    public string LogixPath { get; }

    /// <summary>"127.0.0.1:PORT" of the SLC simulator.</summary>
    public string SlcPath { get; }

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
        })!;
        _processes.Add(p);
        string? line = p.StandardOutput.ReadLine();
        Match m = Regex.Match(line ?? "", @"listening on (\S+)");
        if (!m.Success)
        {
            throw new InvalidOperationException($"simulator did not start: '{line}'");
        }
        // keep draining stdout so the simulator never blocks on a full pipe
        _ = p.StandardOutput.ReadToEndAsync();
        return m.Groups[1].Value;
    }
}

[CollectionDefinition("sim")]
public sealed class SimCollection : ICollectionFixture<Simulators> { }

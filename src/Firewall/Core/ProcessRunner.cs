using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace TheKrystalShip.KGSM.Firewall.Core;

/// <summary>Result of a shelled command. <see cref="ExitCode"/> == <see cref="NoExitCode"/> means the
/// process produced no usable exit code (it could not be launched, or it was killed on timeout).</summary>
internal readonly record struct ProcessResult(int ExitCode, string Stdout, string Stderr)
{
    /// <summary>Sentinel for "no usable exit code" (launch failure or timeout).</summary>
    public const int NoExitCode = -1;

    public bool HasExitCode => ExitCode != NoExitCode;
    public bool Ok => ExitCode == 0;
}

/// <summary>Shells out to an external command. The single seam through which the authority touches the
/// system (the ufw/firewall-cmd/nft probes and writes), so drivers stay unit-testable behind a fake.</summary>
internal interface IProcessRunner
{
    Task<ProcessResult> RunAsync(
        string fileName, IReadOnlyList<string> args, CancellationToken ct = default);
}

/// <summary>
/// AOT-safe process runner, mirroring kgsm-watchdog's UpnpService shell-out: <see cref="Process"/> only
/// (no reflection), <see cref="ProcessStartInfo.ArgumentList"/> (no shell, no quoting games), time-boxed,
/// and both pipes drained concurrently so a chatty child cannot fill a pipe buffer and deadlock
/// <c>WaitForExit</c>. A launch failure or timeout surfaces as <see cref="ProcessResult.NoExitCode"/>
/// rather than throwing — the caller decides whether that is fatal.
/// </summary>
internal sealed class ProcessRunner(ILogger<ProcessRunner> logger) : IProcessRunner
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);

    public async Task<ProcessResult> RunAsync(
        string fileName, IReadOnlyList<string> args, CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (string a in args)
            psi.ArgumentList.Add(a);

        Process proc;
        try
        {
            proc = Process.Start(psi)
                ?? throw new InvalidOperationException("Process.Start returned null");
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Could not launch '{File}' (is it installed and on PATH?)", fileName);
            return new ProcessResult(ProcessResult.NoExitCode, "", ex.Message);
        }

        using (proc)
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(Timeout);

            Task<string> stdoutTask = proc.StandardOutput.ReadToEndAsync(timeoutCts.Token);
            Task<string> stderrTask = proc.StandardError.ReadToEndAsync(timeoutCts.Token);

            try
            {
                await proc.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
                string stdout = (await stdoutTask.ConfigureAwait(false)).Trim();
                string stderr = (await stderrTask.ConfigureAwait(false)).Trim();
                return new ProcessResult(proc.ExitCode, stdout, stderr);
            }
            catch (OperationCanceledException)
            {
                logger.LogWarning(
                    "'{File}' timed out after {Timeout}s; killed", fileName, Timeout.TotalSeconds);
                try { proc.Kill(entireProcessTree: true); } catch { /* already gone */ }
                await ObserveQuietly(stdoutTask).ConfigureAwait(false);
                await ObserveQuietly(stderrTask).ConfigureAwait(false);
                return new ProcessResult(ProcessResult.NoExitCode, "", "timed out");
            }
        }
    }

    private static async Task ObserveQuietly(Task task)
    {
        try { await task.ConfigureAwait(false); }
        catch { /* timeout / teardown — already accounted for */ }
    }
}

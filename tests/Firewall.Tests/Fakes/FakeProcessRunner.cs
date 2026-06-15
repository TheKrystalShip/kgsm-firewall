using TheKrystalShip.KGSM.Firewall.Core;

namespace TheKrystalShip.KGSM.Firewall.Tests.Fakes;

/// <summary>An <see cref="IProcessRunner"/> that records every invocation and returns scripted results
/// from a handler keyed on (file, args). Defaults to a clean exit-0 with empty output.</summary>
internal sealed class FakeProcessRunner : IProcessRunner
{
    public List<(string File, string[] Args)> Calls { get; } = [];

    public Func<string, IReadOnlyList<string>, ProcessResult> Handler { get; set; }
        = (_, _) => new ProcessResult(0, "", "");

    public Task<ProcessResult> RunAsync(
        string fileName, IReadOnlyList<string> args, CancellationToken ct = default)
    {
        Calls.Add((fileName, [.. args]));
        return Task.FromResult(Handler(fileName, args));
    }

    public bool WasCalledWith(string file, params string[] args)
        => Calls.Any(c => c.File == file && c.Args.SequenceEqual(args));
}

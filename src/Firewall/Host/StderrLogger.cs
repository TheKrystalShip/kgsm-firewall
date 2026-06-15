using Microsoft.Extensions.Logging;

namespace TheKrystalShip.KGSM.Firewall.Host;

/// <summary>
/// A minimal <see cref="ILoggerFactory"/> that writes single-line records to stderr — captured by
/// journald when run under systemd, visible directly in a dev terminal. Deliberately tiny: the authority
/// carries only <c>Logging.Abstractions</c> (no full logging/hosting stack), in keeping with the
/// footprint-tuned, Native-AOT helper design. <c>ILogger&lt;T&gt;</c> flows through the Abstractions
/// <c>CreateLogger&lt;T&gt;()</c> wrapper, so only <see cref="CreateLogger(string)"/> needs implementing.
/// </summary>
internal sealed class StderrLoggerFactory(LogLevel minimum) : ILoggerFactory
{
    public ILogger CreateLogger(string categoryName) => new StderrLogger(categoryName, minimum);
    public void AddProvider(ILoggerProvider provider) { /* single fixed sink */ }
    public void Dispose() { }
}

internal sealed class StderrLogger(string category, LogLevel minimum) : ILogger
{
    // Last dotted segment — "UfwDriver" reads better in a log line than the full namespace.
    private readonly string _shortCategory =
        category.LastIndexOf('.') is var i && i >= 0 ? category[(i + 1)..] : category;

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => logLevel >= minimum && logLevel != LogLevel.None;

    public void Log<TState>(
        LogLevel logLevel, EventId eventId, TState state, Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        if (!IsEnabled(logLevel)) return;
        Console.Error.WriteLine($"[{Abbrev(logLevel)}] {_shortCategory}: {formatter(state, exception)}");
        if (exception is not null)
            Console.Error.WriteLine(exception);
    }

    private static string Abbrev(LogLevel level) => level switch
    {
        LogLevel.Trace => "trce",
        LogLevel.Debug => "dbug",
        LogLevel.Information => "info",
        LogLevel.Warning => "warn",
        LogLevel.Error => "fail",
        LogLevel.Critical => "crit",
        _ => "info",
    };
}

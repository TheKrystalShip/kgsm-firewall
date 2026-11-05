namespace TheKrystalShip.KGSM.Firewall.Contracts;

/// <summary>
/// Thrown when the kgsm-firewall authority is unreachable — the socket cannot be connected, the request
/// times out, or the daemon sends no/garbled reply. This is the C# analog of the authority's "unreachable"
/// exit code (the abort-the-install signal): it is distinct from a normal operation outcome
/// (unsupported / op-failed / honest-unknown), which the client returns as a typed result, not an
/// exception. A caller can therefore catch this to mean "the firewall door is down" and react
/// accordingly, while still inspecting the result of a reachable-but-unsuccessful operation.
/// </summary>
public class FirewallException : Exception
{
    /// <summary>The control-socket path the client was dialing when the failure occurred.</summary>
    public string? SocketPath { get; }

    /// <summary>Initializes a new instance of the <see cref="FirewallException"/> class.</summary>
    public FirewallException() { }

    /// <summary>Initializes a new instance with a specified error message.</summary>
    /// <param name="message">The message that describes the error.</param>
    public FirewallException(string message) : base(message) { }

    /// <summary>Initializes a new instance with a specified error message and socket path.</summary>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="socketPath">The control-socket path being dialed.</param>
    public FirewallException(string message, string socketPath) : base(message)
    {
        SocketPath = socketPath;
    }

    /// <summary>Initializes a new instance with a message, socket path, and the underlying cause.</summary>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="socketPath">The control-socket path being dialed.</param>
    /// <param name="innerException">The exception that is the cause of this exception.</param>
    public FirewallException(string message, string socketPath, Exception innerException) : base(message, innerException)
    {
        SocketPath = socketPath;
    }
}

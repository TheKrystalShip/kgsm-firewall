namespace TheKrystalShip.KGSM.Firewall.Host;

/// <summary>
/// The CLI client's exit-code contract — the seam Increment 3's hard-fail install logic is built on.
/// Hard-fail (B) means the kgsm bash wrapper MUST be able to tell "the firewall authority is down →
/// abort the install" from "the authority ran but ufw rejected this rule". Collapsing those into one
/// "failure" would defeat the install semantics the user deliberately chose over best-effort. So the
/// four cases get four distinct codes:
/// <list type="bullet">
/// <item><see cref="Success"/> (0) — applied / removed / noop / a successful read.</item>
/// <item><see cref="Usage"/> (2) — bad CLI arguments; never left the client.</item>
/// <item><see cref="Unreachable"/> (3) — could not reach the authority (socket missing / refused /
///   activation failed). THE one Inc 3 treats as a hard install failure.</item>
/// <item><see cref="Unsupported"/> (4) — reached, but no usable backend (None / not-yet-driveable).</item>
/// <item><see cref="OpFailed"/> (5) — reached, the op was attempted and failed (ufw errored / validation).</item>
/// <item><see cref="Unknown"/> (6) — list only: the backend genuinely cannot answer (honest unknown,
///   never fabricated as "nothing open").</item>
/// </list>
/// </summary>
internal static class ExitCodes
{
    public const int Success = 0;
    public const int Usage = 2;
    public const int Unreachable = 3;
    public const int Unsupported = 4;
    public const int OpFailed = 5;
    public const int Unknown = 6;
}

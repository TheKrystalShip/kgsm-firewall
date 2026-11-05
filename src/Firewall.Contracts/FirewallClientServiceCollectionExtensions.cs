using Microsoft.Extensions.DependencyInjection;

namespace TheKrystalShip.KGSM.Firewall.Contracts;

public static class FirewallClientServiceCollectionExtensions
{
    /// <summary>Adds the firewall authority's control client (<see cref="IFirewallService"/>) for a control socket.</summary>
    public static IServiceCollection AddKgsmFirewallClient(this IServiceCollection services, string socketPath)
    {
        ArgumentNullException.ThrowIfNull(services, nameof(services));

        if (string.IsNullOrWhiteSpace(socketPath))
            throw new ArgumentException("Firewall socket path cannot be null, empty, or whitespace.", nameof(socketPath));

        return AddKgsmFirewallClient(services, options => options.SocketPath = socketPath);
    }

    /// <summary>Adds the firewall authority's control client with a configuration action.</summary>
    public static IServiceCollection AddKgsmFirewallClient(this IServiceCollection services, Action<FirewallClientOptions> configureOptions)
    {
        ArgumentNullException.ThrowIfNull(services, nameof(services));
        ArgumentNullException.ThrowIfNull(configureOptions, nameof(configureOptions));

        var options = new FirewallClientOptions();
        configureOptions(options);

        // A socket is opened per request, so the client holds no connection and one registration serves everyone.
        services.AddSingleton(options);
        services.AddSingleton<IFirewallService, FirewallClient>();

        return services;
    }
}

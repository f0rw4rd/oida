// SPDX-License-Identifier: MIT
//
// OIDA TwinCAT ADS/AMS mock - entry point.
//
// Generic-host application that runs, in one process:
//   * an AmsTcpIpRouter (usermode AMS/TCP router) on TCP 48898
//   * the routing-infrastructure servers (AmsPort 1 + 10000)
//   * an OidaSymbolServer (AdsSymbolicServer) on the PLC AMS port (851)
//
// Configuration comes from appsettings.json overlaid with AmsRouter__* /
// OIDA_* environment variables, so a single image serves multiple profiles.
//
// Uses the official Beckhoff TwinCAT.Ads packages (MIT, (c)Beckhoff Automation
// 2024). Architecture derived from the 0BSD Beckhoff TF6000_ADS_DOTNET_V5_Samples.

using System.Net.Sockets;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OidaTwinCatMock;

// Lightweight healthcheck mode: TCP-connect to the AMS/TCP port (48898).
// Used by the Docker HEALTHCHECK since the runtime:8.0 image has no
// python3/bash/nc/curl. The AmsTcpIpRouter binds 48898 to the container's
// external interface (NOT 127.0.0.1), so we probe the container's own
// resolved IPs. Exit 0 = healthy, 1 = unhealthy.
if (args.Length > 0 && args[0] == "--healthcheck")
{
    try
    {
        var candidates = new List<System.Net.IPAddress> { System.Net.IPAddress.Loopback };
        try
        {
            candidates.AddRange(System.Net.Dns.GetHostAddresses(System.Net.Dns.GetHostName())
                .Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork));
        }
        catch { /* fall back to loopback only */ }

        foreach (var ip in candidates)
        {
            try
            {
                using var sock = new TcpClient();
                var connect = sock.ConnectAsync(ip, 48898);
                if (connect.Wait(TimeSpan.FromSeconds(3)) && sock.Connected)
                    return 0;
            }
            catch { /* try next candidate */ }
        }
        return 1;
    }
    catch
    {
        return 1;
    }
}

IHost host = Host.CreateDefaultBuilder(args)
    .ConfigureAppConfiguration((ctx, config) =>
    {
        config.Sources.Clear();
        config.AddJsonFile("appsettings.json", optional: false, reloadOnChange: false);
        // AmsRouter__NetId, AmsRouter__LoopbackExternalSubnet, OIDA_* etc.
        config.AddEnvironmentVariables();

        // Dynamic self-configuration from the container's own interface.
        // Rather than pinning the container IP + subnet in compose and
        // hardcoding matching AmsRouter__* values, resolve the container's
        // own IPv4 (and its subnet) at startup and derive:
        //   * AmsRouter:NetId               = <ip>.1.1   (pyads default scheme)
        //   * AmsRouter:LoopbackExternalSubnet = <network>/<prefix>
        // This keeps both correct under any IP/subnet Docker assigns, so the
        // compose network needs neither a static ipv4_address nor a pinned
        // subnet. An explicit env var still wins (env source is added above,
        // and we only inject a key when its env var is unset).
        var iface = ResolveOwnInterface();
        var overrides = new Dictionary<string, string?>();
        if (iface is not null)
        {
            if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("AmsRouter__NetId")))
                overrides["AmsRouter:NetId"] = $"{iface.Value.Address}.1.1";
            if (string.IsNullOrWhiteSpace(
                    Environment.GetEnvironmentVariable("AmsRouter__LoopbackExternalSubnet")))
                overrides["AmsRouter:LoopbackExternalSubnet"] = iface.Value.Subnet;
        }
        if (overrides.Count > 0)
            config.AddInMemoryCollection(overrides);
    })
    .ConfigureServices((ctx, services) =>
    {
        services.AddSingleton<RouterReadySignal>();
        services.AddHostedService<RouterService>();
        services.AddHostedService<SymbolServerService>();
    })
    .ConfigureLogging((ctx, logging) =>
    {
        logging.ClearProviders();
        logging.AddSimpleConsole(o => { o.SingleLine = true; o.TimestampFormat = "HH:mm:ss "; });
        logging.SetMinimumLevel(LogLevel.Information);
    })
    .Build();

await host.RunAsync();
return 0;

// Resolve the container's primary non-loopback IPv4 together with the CIDR
// of the subnet it sits on (e.g. Address="172.18.0.7", Subnet="172.18.0.0/16").
// Returns null if no suitable interface is found, in which case the caller
// falls back to the appsettings.json defaults.
static (string Address, string Subnet)? ResolveOwnInterface()
{
    try
    {
        foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up)
                continue;
            foreach (var ua in nic.GetIPProperties().UnicastAddresses)
            {
                var ip = ua.Address;
                if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork
                    || System.Net.IPAddress.IsLoopback(ip))
                    continue;
                int prefix = ua.PrefixLength;
                // PrefixLength can be 0 on some platforms; fall back to /16
                // (the conventional bridge size) so the subnet stays sane.
                if (prefix is <= 0 or > 32)
                    prefix = 16;
                return ($"{ip}", $"{NetworkAddress(ip, prefix)}/{prefix}");
            }
        }
    }
    catch
    {
        // fall through to null
    }
    return null;
}

// Mask an IPv4 address down to its network address for the given prefix.
static System.Net.IPAddress NetworkAddress(System.Net.IPAddress ip, int prefix)
{
    byte[] addr = ip.GetAddressBytes();
    uint value = ((uint)addr[0] << 24) | ((uint)addr[1] << 16) | ((uint)addr[2] << 8) | addr[3];
    uint mask = prefix == 0 ? 0u : 0xFFFFFFFFu << (32 - prefix);
    uint net = value & mask;
    return new System.Net.IPAddress(new[]
    {
        (byte)(net >> 24), (byte)(net >> 16), (byte)(net >> 8), (byte)net,
    });
}

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

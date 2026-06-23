// SPDX-License-Identifier: MIT
//
// OIDA TwinCAT ADS/AMS mock - symbol server host.
//
// Waits for the in-process AmsTcpIpRouter to start, then registers the
// OidaSymbolServer on the configured PLC AMS port (851 by default) using
// AmsNetId.Local (resolved from AmsRouter:NetId via the shared IConfiguration).

using System.Globalization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using TwinCAT.Ads;

namespace OidaTwinCatMock
{
    public sealed class SymbolServerService : BackgroundService
    {
        private readonly ILoggerFactory _loggerFactory;
        private readonly ILogger<SymbolServerService> _logger;
        private readonly IConfiguration _configuration;
        private readonly RouterReadySignal _routerReady;

        public SymbolServerService(IConfiguration configuration, ILoggerFactory loggerFactory,
            RouterReadySignal routerReady)
        {
            _loggerFactory = loggerFactory;
            _logger = loggerFactory.CreateLogger<SymbolServerService>();
            _configuration = configuration;
            _routerReady = routerReady;
        }

        protected override async Task ExecuteAsync(CancellationToken cancel)
        {
            // Don't register symbols until the router is listening.
            await _routerReady.Ready.WaitAsync(cancel);
            await Task.Delay(TimeSpan.FromMilliseconds(500), cancel); // small settle margin

            ushort port = ushort.Parse(
                Environment.GetEnvironmentVariable("OIDA_PLC_PORT") ?? "851",
                CultureInfo.InvariantCulture);
            string deviceName = Environment.GetEnvironmentVariable("OIDA_DEVICE_NAME") ?? "OIDA-TwinCAT";
            Version version = ParseVersion(Environment.GetEnvironmentVariable("OIDA_DEVICE_VERSION") ?? "3.1.4024");
            AdsState adsState = ParseAdsState(Environment.GetEnvironmentVariable("OIDA_ADS_STATE") ?? "Run");
            ushort deviceState = ushort.Parse(
                Environment.GetEnvironmentVariable("OIDA_DEVICE_STATE") ?? "0",
                CultureInfo.InvariantCulture);
            string symbolSpec = Environment.GetEnvironmentVariable("OIDA_SYMBOLS")
                ?? "GVL.Value:REAL:0";

            var symbols = OidaSymbolServer.ParseSymbols(symbolSpec);

            _logger.LogInformation("Registering OidaSymbolServer on local NetId {NetId} port {Port}",
                AmsNetId.Local, port);

            using var server = new OidaSymbolServer(
                port, deviceName, version, adsState, deviceState, symbols, _configuration, _loggerFactory);

            AdsErrorCode code = await server.ConnectServerAndWaitAsync(cancel);

            if (code.Succeeded())
                _logger.LogInformation("Symbol server stopped cleanly.");
            else
                _logger.LogError("Symbol server stopped with AdsErrorCode {Code}", code);
        }

        private static Version ParseVersion(string s)
        {
            // Accept "3", "3.1", "3.1.4024".
            string[] p = s.Split('.', StringSplitOptions.RemoveEmptyEntries);
            int major = p.Length > 0 ? int.Parse(p[0], CultureInfo.InvariantCulture) : 0;
            int minor = p.Length > 1 ? int.Parse(p[1], CultureInfo.InvariantCulture) : 0;
            int build = p.Length > 2 ? int.Parse(p[2], CultureInfo.InvariantCulture) : 0;
            return new Version(major, minor, build);
        }

        private static AdsState ParseAdsState(string s) =>
            Enum.TryParse<AdsState>(s, ignoreCase: true, out var st) ? st : AdsState.Run;
    }
}

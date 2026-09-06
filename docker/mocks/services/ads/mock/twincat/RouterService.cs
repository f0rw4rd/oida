// SPDX-License-Identifier: MIT
//
// OIDA TwinCAT ADS/AMS mock - usermode AMS/TCP router host.
//
// Runs Beckhoff's AmsTcpIpRouter (Beckhoff.TwinCAT.Ads.TcpRouter, MIT) plus the
// routing-infrastructure servers (AdsRouterServer on AmsPort 1, SystemServiceServer
// on AmsPort 10000) entirely in usermode - no TwinCAT install required.
// Derived from the 0BSD DockerSamples/AdsRouterConsole in
// Beckhoff/TF6000_ADS_DOTNET_V5_Samples.

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using TwinCAT.Ads.TcpRouter;
using TwinCAT.Ads.SystemService;
using TwinCAT.Router;

namespace OidaTwinCatMock
{
    /// <summary>
    /// Hosts the AMS/TCP router. Exposes a TaskCompletionSource that completes
    /// once the router reaches <see cref="RouterStatus.Started"/> so the symbol
    /// server can wait for the router before registering.
    /// </summary>
    public sealed class RouterService : BackgroundService
    {
        private readonly ILoggerFactory _loggerFactory;
        private readonly ILogger<RouterService> _logger;
        private readonly IConfiguration _configuration;
        private readonly RouterReadySignal _ready;

        public RouterService(IConfiguration configuration, ILoggerFactory loggerFactory,
            RouterReadySignal ready)
        {
            _loggerFactory = loggerFactory;
            _logger = loggerFactory.CreateLogger<RouterService>();
            _configuration = configuration;
            _ready = ready;
        }

        protected override async Task ExecuteAsync(CancellationToken cancel)
        {
            _logger.LogInformation("Router NetId={NetId} TcpPort={Port} LoopbackIP={Lo} ExternalSubnet={Sub}",
                _configuration["AmsRouter:NetId"], _configuration["AmsRouter:TcpPort"],
                _configuration["AmsRouter:LoopbackIP"], _configuration["AmsRouter:LoopbackExternalSubnet"]);

            var router = new AmsTcpIpRouter(_configuration, _loggerFactory);
            router.RouterStatusChanged += (_, e) =>
            {
                _logger.LogInformation("Router status: {Status}", e.RouterStatus);
                if (e.RouterStatus == RouterStatus.Started)
                    _ready.MarkReady();
            };

            // Router task (AMS/TCP listener on TcpPort).
            Task routerTask = router.StartAsync(cancel);

            // Routing infrastructure servers required for a complete AMS endpoint:
            //   AmsPort 10000 -> SystemServiceServer, AmsPort 1 -> AdsRouterServer
            var systemService = new SystemServiceServer(router, _configuration, _loggerFactory);
            var adsRouterServer = new AdsRouterServer(router, _configuration, _loggerFactory);

            Task systemTask = systemService.ConnectServerAndWaitAsync(cancel);
            Task routerServerTask = adsRouterServer.ConnectServerAndWaitAsync(cancel);

            await Task.WhenAll(routerTask, systemTask, routerServerTask);
        }
    }

    /// <summary>Cross-service signal: completes when the router is started.</summary>
    public sealed class RouterReadySignal
    {
        private readonly TaskCompletionSource _tcs =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task Ready => _tcs.Task;
        public void MarkReady() => _tcs.TrySetResult();
    }
}

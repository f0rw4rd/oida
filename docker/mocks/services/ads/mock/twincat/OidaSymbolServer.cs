// SPDX-License-Identifier: MIT
//
// OIDA TwinCAT ADS/AMS mock - symbolic ADS server.
//
// Subclasses Beckhoff's AdsSymbolicServer (Beckhoff.TwinCAT.Ads.SymbolicServer,
// MIT, (c)Beckhoff Automation 2024). The symbol-upload / handle-acquire /
// read-by-name ADS protocol is implemented by the base class once the symbol
// factory is populated. Derived from the 0BSD AdsSymbolicServerSample in
// Beckhoff/TF6000_ADS_DOTNET_V5_Samples.
//
// Everything that distinguishes one profile from another (device name,
// version, ADS state, symbol set + initial values) is driven by environment
// variables so the SAME image can serve the "motor" and "HVAC" profiles.

using System.Globalization;
using System.Text;
using TwinCAT.Ads;
using TwinCAT.Ads.Server;
using TwinCAT.Ads.Server.TypeSystem;
using TwinCAT.Ads.TypeSystem;
using TwinCAT.TypeSystem;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace OidaTwinCatMock
{
    /// <summary>
    /// A minimal but genuine symbolic ADS server exposing an in-memory GVL
    /// symbol table on a TC3 PLC runtime AMS port (851 by default).
    /// </summary>
    public sealed class OidaSymbolServer : AdsSymbolicServer
    {
        private readonly Dictionary<ISymbol, object> _symbolValues = new();
        private readonly SymbolicAnyTypeMarshaler _marshaler = new(Encoding.UTF8);
        private readonly ILogger? _logger;
        private readonly AdsState _adsState;
        private readonly ushort _deviceState;

        // Parsed symbol descriptors from the OIDA_SYMBOLS env var.
        private readonly List<SymbolDef> _symbolDefs;

        public OidaSymbolServer(ushort port, string deviceName, Version deviceVersion,
            AdsState adsState, ushort deviceState, IEnumerable<SymbolDef> symbols,
            IConfiguration configuration, ILoggerFactory? loggerFactory)
            : base(port, deviceName, configuration, loggerFactory)
        {
            // Device version reported by ADS ReadDeviceInfo (auto-served by base).
            base.serverVersion = deviceVersion;

            _adsState = adsState;
            _deviceState = deviceState;
            _symbolDefs = symbols.ToList();
            _logger = loggerFactory?.CreateLogger<OidaSymbolServer>();
            _logger?.LogInformation(
                "OidaSymbolServer '{Name}' v{Version} state={State} port={Port} symbols={Count}",
                deviceName, deviceVersion, adsState, port, _symbolDefs.Count);
        }

        /// <summary>Builds the symbol table once the server is connected to the router.</summary>
        protected override void OnConnected()
        {
            AddSymbols();
            base.OnConnected();
        }

        private void AddSymbols()
        {
            // Primitive PLC types. .NET CLR type drives marshalling width.
            var dtBool = new PrimitiveType("BOOL", typeof(bool));    // 1 byte
            var dtInt = new PrimitiveType("INT", typeof(short));     // 2 bytes
            var dtDInt = new PrimitiveType("DINT", typeof(int));     // 4 bytes
            var dtReal = new PrimitiveType("REAL", typeof(float));   // 4-byte float
            var dtLReal = new PrimitiveType("LREAL", typeof(double));// 8-byte float

            base.symbolFactory!
                .AddType(dtBool)
                .AddType(dtInt)
                .AddType(dtDInt)
                .AddType(dtReal)
                .AddType(dtLReal);

            // Virtual process-image data area used for IndexGroup/IndexOffset layout.
            var gvl = new DataArea("GVL", 0x02, 0x1000, 0x1000);
            base.symbolFactory.AddDataArea(gvl);

            foreach (var def in _symbolDefs)
            {
                PrimitiveType dt = def.Type switch
                {
                    "BOOL" => dtBool,
                    "INT" => dtInt,
                    "DINT" => dtDInt,
                    "REAL" => dtReal,
                    "LREAL" => dtLReal,
                    _ => throw new InvalidOperationException($"Unsupported symbol type '{def.Type}'"),
                };
                base.symbolFactory.AddSymbol(def.Name, dt, gvl);

                object value = def.Type switch
                {
                    "BOOL" => def.InitialValue != 0.0,
                    "INT" => (short)def.InitialValue,
                    "DINT" => (int)def.InitialValue,
                    "REAL" => (float)def.InitialValue,
                    "LREAL" => def.InitialValue,
                    _ => throw new InvalidOperationException($"Unsupported symbol type '{def.Type}'"),
                };
                _symbolValues.Add(Symbols[def.Name], value);
            }
        }

        /// <summary>Answers ADS ReadState with the configured ADS/device state.</summary>
        protected override Task<ResultReadDeviceState> OnReadDeviceStateAsync(
            AmsAddress sender, uint invokeId, CancellationToken cancel)
        {
            var state = new StateInfo(_adsState, _deviceState);
            return Task.FromResult(ResultReadDeviceState.CreateSuccess(state));
        }

        /// <summary>Marshals the stored value into the response span (raw read).</summary>
        protected override AdsErrorCode OnReadRawValue(ISymbol symbol, Span<byte> span)
        {
            AdsErrorCode ret = OnGetValue(symbol, out object? value);
            if (value != null)
            {
                ret = _marshaler.TryMarshal(symbol, value, span, out _)
                    ? AdsErrorCode.NoError
                    : AdsErrorCode.DeviceInvalidSize;
            }
            return ret;
        }

        /// <summary>Unmarshals an incoming raw write into the stored value.</summary>
        protected override AdsErrorCode OnWriteRawValue(ISymbol symbol, ReadOnlySpan<byte> span)
        {
            _marshaler.Unmarshal(symbol, span, null, out object value);
            return SetValue(symbol, value);
        }

        protected override AdsErrorCode OnGetValue(ISymbol symbol, out object? value)
        {
            if (_symbolValues.TryGetValue(symbol, out value))
                return AdsErrorCode.NoError;
            value = null;
            return AdsErrorCode.DeviceSymbolNotFound;
        }

        protected override AdsErrorCode OnSetValue(ISymbol symbol, object value, out bool valueChanged)
        {
            valueChanged = false;
            if (!_symbolValues.TryGetValue(symbol, out object? oldValue))
                return AdsErrorCode.DeviceSymbolNotFound;

            if (oldValue != null && !oldValue.Equals(value))
            {
                _symbolValues[symbol] = value;
                valueChanged = true;
            }
            return AdsErrorCode.NoError;
        }

        /// <summary>One symbol descriptor parsed from configuration.</summary>
        public readonly record struct SymbolDef(string Name, string Type, double InitialValue);

        /// <summary>
        /// Parses the OIDA_SYMBOLS env-var format:
        ///   "GVL.MotorSpeed:REAL:1480.5,GVL.Running:BOOL:1,GVL.Temperature:INT:42"
        /// (name:type:initialValue, comma separated). Initial value optional (default 0).
        /// </summary>
        public static IReadOnlyList<SymbolDef> ParseSymbols(string spec)
        {
            var result = new List<SymbolDef>();
            foreach (var raw in spec.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                string[] parts = raw.Split(':', StringSplitOptions.TrimEntries);
                if (parts.Length < 2)
                    throw new FormatException($"Bad symbol spec '{raw}' (expected name:type[:value])");
                string name = parts[0];
                string type = parts[1].ToUpperInvariant();
                double initial = 0.0;
                if (parts.Length >= 3 && parts[2].Length > 0)
                    initial = double.Parse(parts[2], CultureInfo.InvariantCulture);
                result.Add(new SymbolDef(name, type, initial));
            }
            if (result.Count == 0)
                throw new FormatException("OIDA_SYMBOLS produced no symbols");
            return result;
        }
    }
}

# FreeTASE2 Mock Server

IEC 60870-6-503 compliant TASE.2/ICCP mock server for testing MSF-ICS scanner.

## Features

- **Full MMS/ISO stack** via [libiec61850](https://github.com/mz-automation/libiec61850)
- **Block 1**: Basic data exchange (Get/Set Data Value, Data Sets)
- **Block 2**: Report-by-Exception (Transfer Sets, InformationReport)
- **Block 5**: Device control (SBO, Direct, Tagging)
- **Bilateral tables** with configurable IDs
- **Value simulation** (frequency, power, voltage)

## Quick Start

```bash
# Build and run
cd docker/mocks/tase2
docker-compose up -d

# Check logs
docker logs msf-ics-tase2

# Test with scanner
msf-ics tase2 localhost --port 102 -v
```

## Protocol Stack

```
TASE.2 Application (IEC 60870-6-503)
        |
       MMS (ISO 9506)
        |
      ACSE (Association Control)
        |
   ISO 8823 Presentation
        |
   ISO 8327 Session
        |
      COTP (RFC 1006)
        |
     TCP/IP (Port 102)
```

## Data Model

### VCC-Scope Variables (System-wide)

| Variable | Type | Description |
|----------|------|-------------|
| Supported_Features | BitString | Blocks 1,2,5 enabled |
| TASE2_Version | Structure | 2000.8 |
| Bilateral_Table_ID | String | BLT_UTILITY_001 |
| System_Status | StateQ | System operational status |
| Total_Generation_MW | RealQTimeTag | Total generation |
| System_Frequency_Hz | RealQTimeTag | System frequency |
| ACE_MW | RealQ | Area Control Error |

### ICC1 Domain (Substation North - 132kV)

| Variable | Type | Description |
|----------|------|-------------|
| Bus_Voltage_kV | RealQTimeTag | Bus voltage |
| Feeder1_MW/MVAr | RealQTimeTag | Feeder 1 power |
| Feeder2_MW/MVAr | RealQTimeTag | Feeder 2 power |
| Breaker1_Status | StateQTimeTag | CB1 status |
| Breaker2_Status | StateQTimeTag | CB2 status |
| Transformer_Tap | DiscreteQ | Tap position |

### ICC2 Domain (Substation South - 33kV)

| Variable | Type | Description |
|----------|------|-------------|
| Bus_Voltage_kV | RealQTimeTag | Bus voltage |
| Load_MW/MVAr | RealQTimeTag | Load power |
| Power_Factor | RealQ | Power factor |
| Capacitor_Status | StateQTimeTag | Cap bank status |

## Control Points (Block 5)

| Point | Type | Class | Tag | Reason |
|-------|------|-------|-----|--------|
| ICC1/Breaker1_Control | Command | SBO | CLOSE_ONLY_INHIBIT | Scheduled maintenance |
| ICC1/Breaker2_Control | Command | SBO | NO_TAG | - |
| ICC1/Tap_Setpoint | Setpoint | Direct | NO_TAG | - |
| ICC2/Capacitor_Control | Command | SBO | OPEN_AND_CLOSE_INHIBIT | Equipment fault |
| ICC2/Voltage_Setpoint | Setpoint | Direct | NO_TAG | - |

### Tag Values

- `NO_TAG` (0): Select and Operate allowed
- `OPEN_AND_CLOSE_INHIBIT` (1): No operations allowed
- `CLOSE_ONLY_INHIBIT` (2): Only Open/Trip allowed

### SBO Sequence

```
Client                          Server
   |                               |
   |-- Read <device>_SBO --------->|  Select
   |<-------- CheckBackID ---------|
   |                               |  (30s timeout starts)
   |-- Write <device> + cmd ------>|  Operate
   |<-------- Success -------------|
   |                               |  (Device executes)
```

## Data Sets

| Name | Scope | Members |
|------|-------|---------|
| VCC/DS_System | VCC | System_Status, Total_Generation_MW, etc |
| ICC1/DS_Voltages | ICC | Bus_Voltage_kV |
| ICC1/DS_Feeders | ICC | Feeder1/2 MW/MVAr |
| ICC1/DS_Status | ICC | Breaker1/2_Status, Transformer_Tap |
| ICC2/DS_Load | ICC | Bus_Voltage, Load_MW/MVAr, PF |

## Transfer Sets (Block 2)

Each domain has 5 pre-allocated transfer sets (TS_01 to TS_05).

### DSConditions

- `INTERVAL_TIMEOUT`: Periodic reporting
- `INTEGRITY_TIMEOUT`: Full data refresh
- `OBJECT_CHANGE`: Report on change
- `OPERATOR_REQUEST`: Manual trigger

## Configuration

```bash
# Custom port
docker run -p 10102:102 msf-ics-tase2 --port 102

# Debug mode
docker run -p 102:102 msf-ics-tase2 --debug

# Custom vendor/model
docker run -p 102:102 msf-ics-tase2 --vendor "MyUtility" --model "SCADA-GW"
```

## Files

| File | Description |
|------|-------------|
| `tase2_server_spec.py` | Main server (Block 1,2,5) |
| `tase2_types.py` | IEC 60870-6-802 data types |
| `Dockerfile` | Builds libiec61850 + server |
| `docker-compose.yml` | Service definition |

## Building libiec61850

The Dockerfile builds libiec61850 with Python bindings automatically. For manual builds:

```bash
git clone https://github.com/mz-automation/libiec61850.git
cd libiec61850
mkdir build && cd build
cmake .. -DBUILD_PYTHON_BINDINGS=ON -DBUILD_EXAMPLES=OFF
make -j$(nproc)
sudo make install
sudo ldconfig
```

## Testing

```bash
# Build container
docker build -t msf-ics-tase2 .

# Run with debug
docker run --rm -p 102:102 msf-ics-tase2 --debug

# Test with scanner
msf-ics tase2 localhost --port 102 -vv

# Expected output:
#   Bilateral Table ID: BLT_UTILITY_001
#   TASE.2 Version: 2000.8
#   Supported Features: Block 1, Block 2, Block 5
#   Domains: VCC, ICC1, ICC2
#   Data Points: 20
#   Control Points: 5
```

## References

- [IEC 60870-6-503](https://webstore.iec.ch/publication/3749) - TASE.2 Services and Protocol
- [IEC 60870-6-802](https://webstore.iec.ch/publication/3757) - TASE.2 Object Models
- [libiec61850](https://github.com/mz-automation/libiec61850)
- [FreeTase2](https://github.com/aklira/FreeTase2)
- [MZ Automation libtase2](https://www.mz-automation.de/iccp-protocol-library-tase-2-iec60870-6/)

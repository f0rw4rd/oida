# OIDA Mock Services Docker Container

This Docker container provides mock implementations of various Industrial Control System (ICS) protocols for testing the OIDA security testing framework.

## Supported Protocols

The container includes mock servers for the following network-based ICS protocols:

| Protocol | Port | Service | Description |
|----------|------|---------|-------------|
| **Modbus TCP** | 502 | Mock PLC | Industrial automation protocol with realistic register data |
| **OPC UA** | 4840 | Mock OPC Server | Industrial communication with hierarchical data model |
| **IEC 60870-5-104** | 2404 | Mock RTU | Telecontrol protocol with 100+ data points |
| **Beckhoff ADS** | 48898 | Mock TwinCAT PLC | Automation protocol with PLC variables |
| **MMS/IEC 61850** | 102 | Mock Substation | Power system communication protocol |
| **EtherNet/IP** | 44818 | Mock Industrial Device | Industrial Ethernet protocol |

## Features

- **Realistic Industrial Data**: Each service simulates realistic industrial process values
- **Dynamic Behavior**: Values change over time to simulate real equipment
- **Framework-Based**: Uses existing libraries (pymodbus, asyncua, cpppo, etc.) where possible
- **Comprehensive Coverage**: Supports discovery, read, and write operations
- **Security Testing Ready**: Designed specifically for OIDA scanner testing

## Quick Start

### Using Docker Compose (Recommended)

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Pre-built images (`$OIDA_REGISTRY`)

Every buildable service carries an `image: ${OIDA_REGISTRY}/oida-mock-*:latest`
tag in addition to its `build:` section, so the heavy compiled mocks
(libiec61850, lib60870, dnp3-rs, OpENer, hipserver, …) can be **pulled**
instead of compiled locally.

`OIDA_REGISTRY` is **required** — compose/bake fail hard if it is unset (no
default, so nothing pushes/pulls the wrong registry by accident). Set it once in
a gitignored `.env`; the real URL never lands in git:

```bash
cp .env.example .env          # then edit OIDA_REGISTRY (host[:port]/namespace, no trailing slash)
docker login <your-registry>  # if private
```

**Publishing / keeping the registry in sync** — one command builds every
buildable mock and pushes it:

```bash
python ../../services.py push        # reads OIDA_REGISTRY from .env
python ../../services.py push --batch 6   # smaller batches if buildkit drops jobs under load
```

Re-run it after editing `docker/mocks/**`; bake's content-addressed cache only
rebuilds and re-pushes what actually changed. It batches the work (buildkit
chokes on 100+ concurrent compiles + remote pushes) and skips targets whose
build context is missing on disk.

```bash
# Default: pull pre-built images, build only what isn't published yet
python ../../services.py up            # core
python ../../services.py up all        # core + CVE

# Force a local rebuild (after editing a Dockerfile)
python ../../services.py up --build

# Skip the registry entirely and build missing images locally
python ../../services.py up --no-pull
```

Images are (re)published by the `.github/workflows/mocks-publish.yml` workflow
on pushes that touch `docker/mocks/**`. The CVE/vulnerable images are published
too — they are deliberately-vulnerable **targets** for authorized testing, in
the same spirit as [vulhub](https://github.com/vulhub/vulhub); see
`VULNERABLE_SERVICES.md`.

### Using Docker directly

```bash
# Build the container
docker build -t oida-mock .

# Run the container
docker run -d \
  --name oida-mock \
  -p 502:502 \
  -p 4840:4840 \
  -p 2404:2404 \
  -p 48898:48898 \
  -p 102:102 \
  -p 44818:44818 \
  oida-mock

# View logs
docker logs -f oida-mock
```

## Testing with OIDA

Once the container is running, you can test each protocol with the OIDA scanners:

```bash
# Test Modbus
python -c "from oida.protocols.modbus import ModbusScanner; scanner = ModbusScanner({'rhost': 'localhost', 'rport': 502}); print(scanner.run_scan())"

# Test OPC UA
python -c "from oida.protocols.opcua import OPCUAScanner; scanner = OPCUAScanner({'rhost': 'localhost', 'rport': 4840}); print(scanner.run_scan())"

# Test IEC 104
python -c "from oida.protocols.iec104 import IEC104Scanner; scanner = IEC104Scanner({'rhost': 'localhost', 'rport': 2404}); print(scanner.run_scan())"

# Test ADS
python -c "from oida.protocols.ads import ADSScanner; scanner = ADSScanner({'rhost': 'localhost', 'rport': 48898}); print(scanner.run_scan())"

# Test MMS
python -c "from oida.protocols.mms import MMSScanner; scanner = MMSScanner({'rhost': 'localhost', 'rport': 102}); print(scanner.run_scan())"

# Test EtherNet/IP
python -c "from oida.protocols.ethernetip import EtherNetIPScanner; scanner = EtherNetIPScanner({'rhost': 'localhost', 'rport': 44818}); print(scanner.run_scan())"
```

## Mock Data Details

### Modbus TCP (Port 502)
- **Device**: Mock Industrial PLC
- **Registers**: 100 each of coils, discrete inputs, holding registers, input registers
- **Data**: Temperature, pressure, flow sensors; motor controls; valve positions
- **Vendor**: OIDA Mock

### OPC UA (Port 4840)
- **Device**: Industrial Controller
- **Namespace**: Industrial simulation with sensors, actuators, alarms, configuration
- **Nodes**: 20+ variables including temperatures, pressures, motor controls
- **Security**: Anonymous access enabled

### IEC 60870-5-104 (Port 2404)
- **Framework**: c104 library (industry standard)
- **Station**: Mock RTU/SCADA system (CA=1)
- **Data Points**: 100 total (20 digital, 40 analog scaled, 20 float, 20 counters)
- **Simulation**: Realistic power system data with fluctuations
- **Commands**: General interrogation, spontaneous transmission supported

### Beckhoff ADS (Port 48898)
- **Device**: Mock TwinCAT PLC
- **Variables**: 30+ PLC variables including system info, process data, motor control
- **Types**: BOOL, INT, REAL, STRING data types
- **Features**: Cycle time simulation, alarm logic

### MMS/IEC 61850 (Port 102)
- **Device**: Mock Power System IED
- **Logical Devices**: PROT (protection), CTRL (control), MEAS (measurement)
- **Data Objects**: Circuit breakers, measurements, protection functions
- **Standards**: IEC 61850 compliant data model

### EtherNet/IP (Port 44818)
- **Device**: Mock Industrial Ethernet Device
- **Tags**: 40+ industrial I/O tags (digital/analog inputs/outputs)
- **Classes**: Identity, TCP/IP interface, Assembly objects
- **Vendor**: Mock EtherNet/IP Device (ID: 999)

## Container Management

### Health Checks
The container includes health checks that verify all services are responding:
```bash
# Check container health
docker inspect oida-mock | grep Health -A 10
```

### Logs
Service logs are available in the container and can be mapped to host:
```bash
# View specific service logs
docker exec oida-mock tail -f /var/log/oida/modbus.log
docker exec oida-mock tail -f /var/log/oida/opcua.log
```

### Service Control
```bash
# Restart container
docker-compose restart

# Check running processes
docker exec oida-mock ps aux

# Access container shell
docker exec -it oida-mock bash
```

## Network Configuration

The container uses standard ICS protocol ports and can be configured for different network setups:

- **Host Network**: Use `--network host` for direct port access
- **Bridge Network**: Default setup with port mapping
- **Custom Network**: Configure with `compose.yml`

## Troubleshooting

### Common Issues

1. **Port Conflicts**: Ensure ports 502, 4840, 2404, 48898, 102, 44818 are available
2. **Permission Issues**: Some protocols may need elevated privileges
3. **Memory Usage**: Container uses ~200MB RAM for all services

### Debug Mode
```bash
# Run with debug output
docker run -it --rm \
  -p 502:502 -p 4840:4840 -p 2404:2404 -p 48898:48898 -p 102:102 -p 44818:44818 \
  oida-mock bash

# Start services manually for debugging
cd /app/mock_services
python3 modbus_server.py
```

### Service Status
```bash
# Check which services are running
docker exec oida-mock sh -c 'for port in 502 4840 2404 48898 102 44818; do echo -n "Port $port: "; nc -z localhost $port && echo "UP" || echo "DOWN"; done'
```

## Development

### Adding New Protocols
1. Create new server script in `mock_services/`
2. Add to `start_services.sh`
3. Update `compose.yml` ports
4. Update documentation

### Modifying Mock Data
Edit the individual server files to customize:
- Data point values and ranges
- Simulation patterns
- Device information
- Protocol-specific features

## Security Notes

⚠️ **Important**: These are mock services for testing purposes only. They should never be used in production environments or exposed to untrusted networks.

- All services run with minimal authentication
- Some protocols support write operations for testing
- No encryption or security features enabled
- Designed for controlled testing environments only

## License

This mock service container is part of the OIDA project and follows the same license terms.
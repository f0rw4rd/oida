# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Docker-based mock ICS (Industrial Control System) testing environment with 90+ containerized services for testing MSF-ICS security scanners. Includes both stable implementations and intentionally vulnerable versions for security research.

## Key Commands

### Build and Run
```bash
make build              # Build all images
make up                 # Start all services
make down               # Stop all services
make status             # Show service status
make logs               # Follow all logs
make clean              # Remove containers/images
```

### Per-Service Control
```bash
make up-modbus          # Start Modbus TCP
make up-opcua           # Start OPC UA variants
make up-mqtt            # Start MQTT brokers
make up-dicom           # Start DICOM (mock + Orthanc)
make up-hl7             # Start HL7 (mock + Mirth)
make logs-modbus        # Follow specific service logs
```

### Docker Compose Profiles
```bash
docker-compose up -d                              # Start standard services
docker-compose --profile vuln-services up -d      # Start vulnerable CVE variants
docker-compose --profile openelis up -d           # Start medical stack
```

### Direct Docker
```bash
docker build -t msf-ics-mock .
docker run -d --name msf-ics-mock \
  -p 502:502 -p 4840:4840 -p 2404:2404 -p 48898:48898 \
  -p 102:102 -p 44818:44818 -p 47808:47808/udp \
  msf-ics-mock
```

## Architecture

### Service Structure
- **docker-compose.yml**: Defines 90+ services with health checks, resource limits, and network isolation
- **Dockerfile**: Main container running 8 core services via supervisord
- **services/**: Protocol implementations
  - `*_server.py`: Python protocol servers (24 total)
  - `Dockerfile.*`: Protocol-specific Dockerfiles
  - `vulnerable/`: 18 subdirectories with CVE-specific variants
  - `mqtt/`: 5 MQTT broker variants (insecure, auth, sparkplug, TLS, mTLS)

### Main Container (supervisord-managed)
Runs 8 services automatically: Modbus, OPC UA, ADS, EtherNet/IP, BACnet, DNP3, HL7, DICOM

### Port Mapping

| Protocol | Port | Service Container |
|----------|------|------------------|
| Modbus TCP | 502 | msf-ics-mock |
| OPC UA | 4840-4850 | opcua-* variants |
| IEC 104 | 2404-2405, 19998 | iec104-lib60870, iec104-custom-types, iec104-tls |
| Beckhoff ADS | 48898 | msf-ics-mock |
| MMS/IEC 61850 | 102 | mms-libiec61850 |
| EtherNet/IP | 44818 | msf-ics-mock |
| BACnet/IP | 47808/udp | msf-ics-mock |
| DNP3 | 20000-20020 | dnp3-* variants (20020=file transfer) |
| MQTT | 1883-1885, 8883-8884 | mqtt-* brokers |
| HL7 | 2575-2578 | hl7-mock, mirth |
| DICOM | 11112-11113 | dicom-mock, orthanc |
| FHIR | 8081 | fhir-server |
| ASTM/LIS | 1394-1396 | astm-* servers |
| VNC | 5900 | vnc-mock (x11vnc) |
| FTP | 2121 | ftp-mock (vsftpd) |
| SMTP | 2530 | smtp-mock (Postfix) |
| HTTP | 8083 | http-mock (nginx) |

### Vulnerable Services
Located in `services/vulnerable/` with 18 protocol subdirectories. Each container labeled:
```yaml
labels:
  - "oida.cve=CVE-XXXX-XXXXX"
  - "oida.protocol=<protocol>"
  - "oida.severity=<high|medium|low>"
```

### Network
- Docker bridge `ics-network` (172.30.0.0/16)
- Services addressable by hostname (e.g., `modbus-server`)
- Logs mapped to `./logs/`

## Testing with MSF-ICS

```bash
# From parent project (oida CLI)
oida modbus localhost
oida opcua opc.tcp://localhost:4840
oida iec104 localhost:2404

# Direct scanner usage
python -c "from oida.protocols.modbus import ModbusScanner; \
  scanner = ModbusScanner({'rhost': 'localhost', 'rport': 502}); \
  print(scanner.run_scan())"
```

## Adding New Services

1. Create `services/<protocol>_server.py`
2. Create `services/Dockerfile.<protocol>`
3. Add service to `docker-compose.yml`
4. For vulnerable variants, add to `services/vulnerable/<protocol>/`

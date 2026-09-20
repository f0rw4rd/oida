# PCAP Test Fixtures

This directory contains real packet captures used for testing protocol parsers.
All files are genuine network captures from public repositories, not synthetically generated.

## Directory Structure

```
pcap/
├── filtered/              # Protocol-specific extracts from raw/ captures
├── generated/             # Synthetically generated pcaps (scapy)
├── bruteshark/            # BruteShark credential test pcaps
├── credslayer/            # CredSlayer credential test pcaps
├── wireshark/             # Wireshark sample captures
├── internet_samples/      # Internet protocol samples
│
│   ── Protocol directories (flat, one per protocol) ──
│
├── modbus/                # Modbus TCP (port 502) - 15 files
├── dnp3/                  # DNP3 (port 20000) - 212 files (incl. conformance tests)
├── s7comm/                # Siemens S7comm (port 102) - 44 files
├── opcua/                 # OPC UA (port 4840) - 32 files
├── iec104/                # IEC 60870-5-104 (port 2404) - 5 files
├── enip/                  # EtherNet/IP + CIP (port 44818) - 22 files
├── bacnet/                # BACnet/IP (port 47808) - 6 files
├── goose/                 # IEC 61850 GOOSE - 8 files
├── mms/                   # IEC 61850 MMS (port 102) - 25 files
├── ads/                   # Beckhoff ADS/AMS (port 48898) - 10 files
├── profinet/              # PROFINET DCP - 5 files
├── knx/                   # KNX/IP (port 3671) - 3 files
├── ethercat/              # EtherCAT - 1 file
├── fins/                  # FINS/Omron (port 9600) - 1 file
├── mqtt/                  # MQTT (port 1883) - 1 file
├── c37118/                # C37.118 Synchrophasor - 9 files
├── melsec/                # Mitsubishi MELSEC - 6 files
├── hart/                  # HART-IP - 1 file
├── fox/                   # Tridium Fox - 1 file
├── zigbee/                # Zigbee - 1 file
├── arp/                   # ARP - 1 file
├── dns/                   # DNS - 13 files
├── dhcp/                  # DHCP - 2 files
├── lldp/                  # LLDP - 3 files
├── icmp/                  # ICMP - 22 files
├── snmp/                  # SNMP - 11 files
├── sip/                   # SIP/RTP - 1 file
├── tls/                   # TLS - 56 files
├── ftp/                   # FTP credentials - 1 file
├── http/                  # HTTP auth (Basic, Digest, NTLM) - 4 files
├── telnet/                # Telnet sessions - 3 files
├── smtp/                  # SMTP auth - 3 files
├── pop3/                  # POP3 auth - 1 file
├── imap/                  # IMAP auth - 4 files
├── ssh/                   # SSH sessions - 11 files
├── kerberos/              # Kerberos v5 - 3 files
├── smb/                   # SMB/NTLM auth - 2 files
└── ssdp/                  # SSDP - 1 file
```

## Sources and Attribution

### ITI/ICS-Security-Tools

**URL**: https://github.com/ITI/ICS-Security-Tools
**License**: Various / educational use
**Files prefixed with**: `iti_`

Comprehensive ICS security tools repository with pcaps covering:
- Modbus TCP, DNP3, BACnet, EtherNet/IP, CIP
- S7comm (Siemens), IEC 60870-5-104, IEC 61850 (GOOSE + MMS)
- PROFINET, Beckhoff ADS, Omron FINS, Fox/Tridium
- C37.118 Synchrophasor, MELSEC (Mitsubishi), HART-IP
- DigitalBond QuickDraw and OpenICS pcaps
- OpenDNP3 conformance test captures (159 test cases)

### CISAGOV ICSNPP (Industrial Control Systems Network Protocol Parsers)

**URL**: https://github.com/cisagov/ICSNPP
**License**: Public domain (US Government work)
**Files prefixed with**: `cisagov_`

CISA's Zeek parser test traces for:
- Modbus: https://github.com/cisagov/icsnpp-modbus
- DNP3: https://github.com/cisagov/icsnpp-dnp3
- BACnet: https://github.com/cisagov/icsnpp-bacnet
- EtherNet/IP: https://github.com/cisagov/icsnpp-enip
- S7comm: https://github.com/cisagov/icsnpp-s7comm
- OPC UA: https://github.com/cisagov/icsnpp-opcua-binary
- EtherCAT: https://github.com/cisagov/icsnpp-ethercat

### Wireshark / SampleCaptures

**URL**: https://github.com/wireshark/wireshark (test/captures/)
**URL**: https://github.com/briliant-ben/SampleCaptures (wiki mirror)
**License**: GPL-2.0 (Wireshark), various (SampleCaptures)
**Files prefixed with**: `wireshark_`

Wireshark test suite and community sample captures including:
- OPC UA (signed, encrypted, chunked)
- KNX/IP (DataSec, SecureWrapper, TimerNotify)
- S7comm, IEC 104, DNP3, BACnet

### Zeek (formerly Bro)

**URL**: https://github.com/zeek/zeek
**License**: BSD-3-Clause
**Files prefixed with**: `zeek_`

Zeek network security monitor test traces including:
- Modbus (big, small, mixed traffic)
- DNP3 (read, write, select/operate, UDP variants)
- MQTT
- SSH, FTP, HTTP, DNS, DHCP, SNMP, TLS, ICMP, RADIUS

### BruteShark

**URL**: https://github.com/odedshimon/BruteShark
**License**: MIT
**Files prefixed with**: `bruteshark_`

Network forensic analysis tool test pcaps for credential extraction:
- HTTP (Basic, Digest, Digest-MD5, NTLM)
- FTP, Telnet, SMTP, IMAP, POP3
- Kerberos v5 (TCP and UDP)
- SMB/NTLM authentication

### GOOSEStalker

**URL**: https://github.com/cutaway-security/goosestalker
**License**: GPL-3.0
**Files prefixed with**: `goosestalker_`

IEC 61850 GOOSE protocol analysis tool with sample captures.

### goose-IEC61850-scapy

**URL**: https://github.com/mdehus/goose-IEC61850-scapy
**License**: Public / educational use
**Files prefixed with**: `iec61850_scapy_`

IEC 61850 GOOSE captures for Scapy testing.

### The Ultimate PCAP (weberblog.net)

**URL**: https://weberblog.net/the-ultimate-pcap/
**License**: Public domain / educational use

Contains 48,640 packets covering 90+ protocols (in raw/ and filtered/).

### 4SICS Geek Lounge PCAPs (netresec.com)

**URL**: https://www.netresec.com/?page=PCAP4SICS
**License**: Public / research use

ICS lab captures with S7comm/MMS traffic (in raw/).

## Summary Statistics

| Category      | Protocols | Files | Size   |
|---------------|-----------|-------|--------|
| ICS/SCADA     | 20        | 408   | 36 MB  |
| Credentials   | 9         | 32    | 2.5 MB |
| Network       | 7         | 109   | 1.5 MB |
| **Total**     | **36**    | **549** | **40 MB** |

## Usage in Tests

```python
import pytest
from pathlib import Path
from scapy.all import rdpcap

PCAP_DIR = Path(__file__).parent / "fixtures" / "pcap"


def test_modbus_parsing():
    packets = rdpcap(str(PCAP_DIR / "modbus" / "cisagov_modbus_example.pcap"))
    assert len(packets) > 0


def test_s7comm_parsing():
    packets = rdpcap(str(PCAP_DIR / "s7comm" / "cisagov_snap7.pcap"))
    assert len(packets) > 0


def test_opcua_encrypted():
    packets = rdpcap(str(PCAP_DIR / "opcua" / "wireshark_opcua_encrypted.pcapng"))
    assert len(packets) > 0
```

## File Naming Convention

Files are prefixed by source repository for attribution:
- `cisagov_` - CISA ICSNPP project
- `iti_` - ITI ICS-Security-Tools
- `wireshark_` - Wireshark project
- `zeek_` - Zeek/Bro project
- `bruteshark_` - BruteShark project
- `goosestalker_` - GOOSEStalker project
- `bro_` - Bro IDS (legacy Zeek)
- `digitalbond_` - DigitalBond pcaps
- `openics_` - OpenICS project
- `opendnp3_` - OpenDNP3 conformance tests
- `oida_` - Generated by OIDA (scapy, valid wire format, dissector-verified)

## Passive-parser gap coverage (added 2026-09)

Fixtures added to seed listeners for OT protocols the passive parser does not
yet cover. Each was verified to trigger its intended dissector (`tshark -Y`)
or, for non-native protocols, kept as a raw fixture for a future parser.

| Dir | Source | tshark dissector | Verified |
|-----|--------|------------------|----------|
| `selfm/` | `oida_` generated (SEL Fast Message, 0xA5xx) | `selfm` (native, heuristic/TCP) | Message types decode (Relay Def 0xa5c0, FastOp) |
| `egd/` | `oida_` generated (GE Ethernet Global Data) | `egd` (native, UDP 18246) | pid/exid/status fields populate |
| `mqttsn/` | `oida_` generated (MQTT-SN message matrix) | `mqttsn` (native, decode-as UDP 1883) | CONNECT/REGISTER/PUBLISH/SUBSCRIBE parse |
| `rtps/` | `wireshark_` SampleCaptures wiki | `rtps` (native) | 16 RTPS submessages |
| `tte/` | `wireshark_` (briliant-ben mirror) | `tte`/`tte_pcf` (native) | 4 TTEthernet frames |
| `ieee1722/` | `oida_` generated (AVTP subtypes) | `ieee1722` (native, ethertype 0x22F0) | aaf/crf/cvf/iec61883 subtypes decode |
| `modbus/oida_*` | `oida_` generated (UDP + RTU-over-TCP) | `mbudp` / `mbrtu` (native) | FC1/3/6/16 + exception; RTU unit-ids |

**Not tshark-native (raw fixtures only — no pyshark drop-in until a raw parser
or Wireshark plugin is added):**

| Dir | Source | Why |
|-----|--------|-----|
| `bsap/` | `cisagov_` icsnpp-bsap | Wireshark `bsap` is telecom ANSI-A, **not** Bristol/Emerson |
| `s7comm-plus/` | `cisagov_` icsnpp-s7comm | S7comm-plus needs an external Wireshark plugin (shows as `cotp:data`) |
| `roc-plus/` | `cisagov_` icsnpp-roc-plus | Emerson ROC Plus is a Zeek/Spicy parser only |
| `genisys/` | `cisagov_` icsnpp-genisys | Genisys (rail) is a Zeek/Spicy parser only |

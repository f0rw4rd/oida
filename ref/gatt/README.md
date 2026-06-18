# GATT (Generic Attribute Profile) / BLE - Reference Materials

## Protocol Overview

GATT is the application-layer protocol for Bluetooth Low Energy (BLE) that defines how data is organized and exchanged between BLE devices. GATT operates over ATT (Attribute Protocol) which runs on top of L2CAP. It defines services, characteristics, and descriptors as the data model.

- **Transport**: BLE L2CAP channel (CID 0x0004 for ATT), also possible over BR/EDR
- **ATT Protocol**: Opcode (1 byte) + Parameters (variable)
- **ATT Operations**: Read, Write, Notify, Indicate, Find Information, Read By Type/Group
- **GATT Hierarchy**: Service -> Characteristic -> Descriptor
- **Handle Space**: 16-bit handle values (0x0001-0xFFFF)

## Wireshark Dissectors

- **ATT/GATT**: [packet-btatt.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-btatt.c)
- **BLE Link Layer**: [packet-btle.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-btle.c)
- **L2CAP**: [packet-btl2cap.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-btl2cap.c)
- **SMP**: [packet-btsmp.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-btsmp.c)

### Key dissector details:
- ATT opcode dispatch (0x01-0x1D + 0x52 Write Command, 0xD2 Signed Write)
- Handle-based attribute access
- UUID parsing (16-bit short vs. 128-bit full)
- Notification/Indication value parsing
- Error response handling with error codes

## Open-Source Parsers and Implementations

| Project | Language | Description | Link |
|---------|----------|-------------|------|
| **BlueZ** | C | Linux Bluetooth protocol stack | [github.com/bluez/bluez](https://github.com/bluez/bluez) |
| **bleak** | Python | BLE client for Python (cross-platform) | [github.com/hbldh/bleak](https://github.com/hbldh/bleak) |
| **bluepy** | Python | Python BLE interface (Linux) | [github.com/IanHarvey/bluepy](https://github.com/IanHarvey/bluepy) |
| **NimBLE** | C | Apache NimBLE BLE stack | [github.com/apache/mynewt-nimble](https://github.com/apache/mynewt-nimble) |
| **Scapy** | Python | BLE contrib layers | [github.com/secdev/scapy](https://github.com/secdev/scapy) |
| **bumble** | Python | Google's BLE stack for testing | [github.com/nicholasgasior/bumble](https://github.com/nicholasgasior/bumble) |

## Common Parsing Vulnerabilities

### 1. ATT PDU Length
- ATT PDU size determined by L2CAP payload length, not explicit length field
- MTU negotiation (default 23 bytes) vs. actual PDU size
- Read Blob Request with offset beyond attribute value length
- Write Request with value exceeding MTU

### 2. Handle Range Operations
- Find Information Request: start handle > end handle
- Read By Type/Group with invalid handle ranges
- Handle value 0x0000 (reserved/invalid)
- Handle values beyond server's attribute database

### 3. UUID Handling
- 16-bit (BT SIG assigned) vs. 128-bit (vendor-specific)
- UUID format byte in Find Information Response determining UUID size
- Malformed 128-bit UUIDs
- Mixed UUID sizes in single response

### 4. Write Operations
- Write Request vs. Write Command (no response expected)
- Prepare Write for long attributes (offset + value)
- Execute Write (write all / cancel all)
- Queued writes with inconsistent handle/offset pairs

### 5. Notification/Indication Handling
- CCCD (Client Characteristic Configuration Descriptor) enable/disable
- Notifications without prior subscription
- Indication without confirmation (timeout handling)
- Rapid notification flooding

### 6. SMP (Security Manager Protocol)
- Pairing request/response with crafted IO capabilities
- Key distribution flags inconsistencies
- Encryption key size downgrade (7-16 bytes)
- Public key validation in Secure Connections

## Notable Research

- **"KNOB Attack"** - Key Negotiation of Bluetooth (entropy reduction)
- **"BIAS Attack"** - Bluetooth Impersonation Attacks
- **"SweynTooth"** - BLE implementation vulnerabilities across multiple SoC vendors
- **"InternalBlue"** - Broadcom BLE firmware analysis
- **"BLURtooth"** - Cross-transport key derivation issues
- **"BLEEDINGBIT"** - Two critical vulnerabilities in TI BLE chips used in enterprise APs (Cisco, Aruba, Meraki). CVE-2018-16986 (RCE via advertising packets) and CVE-2018-7080 (OAD backdoor)
- **"BrakTooth"** - 16 vulnerabilities in Bluetooth Classic (BR/EDR) stacks affecting Intel, Qualcomm, TI, Infineon, Silicon Labs. CVE-2021-28139 (ESP32 RCE) is the most critical. [PoC on GitHub](https://github.com/Matheus-Garbelini/braktooth_esp32_bluetooth_classic_attacks)
- **"Airoha RACE"** - Unauthenticated GATT service in Airoha BLE SoCs exposes RAM/flash read/write. Affects millions of headphones from Sony, JBL, Bose, etc. Full disclosure at 39C3 (Dec 2025). [RACE Toolkit](https://github.com/auracast-research/race-toolkit)

## Fuzzing Tools

| Tool | Description | Link |
|------|-------------|------|
| **Quarkslab BLE GATT Fuzzer** | GATT layer fuzzer with defined attack scenarios, found real vulnerabilities | [github.com/quarkslab/ble-gatt-fuzzing](https://github.com/quarkslab/ble-gatt-fuzzing) |
| **protocol-fuzzing/ble-fuzzer** | Protocol state fuzzer for BLE, tests hardware OTA or NimBLE in-process | [github.com/protocol-fuzzing/ble-fuzzer](https://github.com/protocol-fuzzing/ble-fuzzer) |
| **SweynTooth PoC** | Proof-of-concept exploits for 12+ BLE link layer vulnerabilities | [github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks](https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks) |
| **BrakTooth PoC** | Bluetooth Classic exploit toolkit for 16 BR/EDR vulnerabilities, ESP32-based | [CISA Alert](https://www.cisa.gov/news-events/alerts/2021/11/04/braktooth-proof-concept-tool-demonstrates-bluetooth-vulnerabilities) |
| **B1ueB0y-BLE-Fuzzing** | Toolkit for testing BLE devices, chips, and protocol stacks | [github.com/Charmve/B1ueB0y-BLE-Fuzzing](https://github.com/Charmve/B1ueB0y-BLE-Fuzzing) |
| **RACE Toolkit** | Python CLI tool for interacting with Airoha RACE protocol over BLE/USB | [github.com/auracast-research/race-toolkit](https://github.com/auracast-research/race-toolkit) |
| **bumble** | Google's BLE stack for testing and fuzzing, pure Python | [github.com/google/bumble](https://github.com/google/bumble) |

## Attack Surface Notes

- **Vendor GATT services are the biggest risk**: Manufacturers routinely expose debug/diagnostic GATT services without authentication. The Airoha RACE vulnerability (CVE-2025-20700/20702) gives unauthenticated RAM/flash read/write on millions of consumer headphones from Sony, JBL, Bose, etc. An attacker within BLE range (~10m) can dump firmware, extract Bluetooth link keys, and impersonate the device to paired phones.
- **BLE link layer is the SweynTooth target**: SoC vendors (TI, NXP, Cypress, Dialog, Microchip, STMicro, Telink) implemented BLE link layer with insufficient bounds checking. LL_LENGTH_REQ with extreme values, LLID=0 deadlocks, and L2CAP length overflow are proven attack patterns.
- **BLEEDINGBIT affects enterprise infrastructure**: TI BLE chips in Cisco/Aruba/Meraki enterprise APs had RCE via advertising packets and OAD firmware backdoor. BLE is often overlooked in enterprise network security.
- **BrakTooth shows Classic BT is also vulnerable**: 16 bugs across Intel, Qualcomm, TI, Infineon, Silicon Labs BT Classic stacks. ESP32 is the easiest to exploit (CVE-2021-28139). PoC requires only a $15 BT dongle.
- **All attacks are radio-range only**: BLE/BT Classic attacks require physical proximity (~10-100m). However, in ICS/OT environments, this often means anyone with facility access.

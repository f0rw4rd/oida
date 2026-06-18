# OCPP (Open Charge Point Protocol) - Fuzzing Reference

## Protocol Overview

OCPP (Open Charge Point Protocol) is the standard for communication between EV charging
stations (Charge Points) and backend management systems (Central Systems / CSMS). It is
maintained by the Open Charge Alliance (OCA).

### Protocol Versions

| Version | Transport | Encoding | Port |
|---------|-----------|----------|------|
| OCPP 1.2 | SOAP/XML | XML | 80/443 |
| OCPP 1.5 | SOAP/XML | XML | 80/443 |
| OCPP 1.6-S | SOAP/XML | XML | 80/443 |
| OCPP 1.6-J | WebSocket | JSON | 80/443/ws |
| OCPP 2.0.1 | WebSocket | JSON | 80/443/ws |
| OCPP 2.1 | WebSocket | JSON | 80/443/ws |

OCPP 1.6-J and 2.0.1 are the most widely deployed. Both use JSON over WebSocket.

### Related Protocols (Same Attack Surface)

- **ISO 15118 / V2GTP**: Vehicle-to-Grid Transport Protocol used for PnC (Plug and Charge).
  Runs over IPv6 link-local, port 15118. EXI-encoded payloads with V2GTP framing.
- **MQTT**: Used internally on some charging platforms for inter-process communication.
- **ACMP**: Autel Cloud Management Protocol - proprietary WebSocket-based protocol on
  some chargers.
- **DLB**: Dynamic Load Balancing protocol (Autel) - used between chargers on local network.
- **HomePlug Green PHY**: PLC (Power Line Communication) used on some chargers for
  ISO 15118 over the charging cable.

## OCPP Message Structure (Fuzzing Target)

### OCPP-J (JSON over WebSocket) Message Framing

All OCPP-J messages are JSON arrays sent as WebSocket text frames:

```
CALL:       [2, "<MessageId>", "<Action>", {<Payload>}]
CALLRESULT: [3, "<MessageId>", {<Payload>}]
CALLERROR:  [4, "<MessageId>", "<ErrorCode>", "<ErrorDescription>", {<ErrorDetails>}]
```

- **MessageTypeId**: Integer 2, 3, or 4
- **MessageId**: UUID string (max 36 chars)
- **Action**: OCPP operation name (e.g., "BootNotification", "Authorize")
- **Payload**: JSON object with operation-specific fields

### High-Value Fuzzing Targets (Message Types)

**Charge Point -> Central System (server-side parsing on CSMS):**

| Action | Key Fields | Length Constraints |
|--------|------------|-------------------|
| BootNotification | chargePointVendor (20), chargePointModel (20), chargePointSerialNumber (25), firmwareVersion (50) | CiString with max lengths |
| Authorize | idTag (20) | CiString20 |
| StartTransaction | connectorId (int), idTag (20), meterStart (int), timestamp | Integer + string fields |
| StopTransaction | transactionId (int), meterStop (int), timestamp, reason | Integer + string + enum |
| MeterValues | connectorId, transactionId, meterValue[] | Nested arrays |
| StatusNotification | connectorId, status, errorCode, info (50) | Enum + string |
| Heartbeat | (empty payload) | Minimal |
| DataTransfer | vendorId (255), messageId (50), data | Large string fields |
| DiagnosticsStatusNotification | status | Enum |
| FirmwareStatusNotification | status | Enum |

**Central System -> Charge Point (server-side parsing on CP):**

| Action | Key Fields | Notes |
|--------|------------|-------|
| RemoteStartTransaction | idTag, connectorId | |
| RemoteStopTransaction | transactionId | |
| ChangeConfiguration | key (50), value (500) | Large value field |
| GetConfiguration | key[] | Array of strings |
| Reset | type | Enum |
| UpdateFirmware | location (URI), retrieveDate | URI parsing |
| SendLocalList | listVersion, localAuthorizationList[] | Large array |
| SetChargingProfile | connectorId, csChargingProfiles | Complex nested structure |
| TriggerMessage | requestedMessage | Enum |

### CiString Types (OCPP-specific bounded strings)

OCPP defines CiString types with maximum lengths. Implementations must validate these:

- CiString20: idTag, chargePointVendor, chargePointModel
- CiString25: chargePointSerialNumber, chargeBoxSerialNumber, iccid, imsi
- CiString50: firmwareVersion, info, messageId
- CiString255: vendorId, data (in some contexts)
- CiString500: value (in ChangeConfiguration)

**Fuzzing strategy**: Send strings exceeding CiString max length. The CVE-2023-49955 DoS
was triggered by a 442MB chargePointVendor field (CiString20 max = 20 chars).
The CVE-2025-59398 crash was triggered by JSON input >255 chars hitting CiString<255>.

### Timestamp Handling

OCPP timestamps use ISO 8601 format. The CVE-2023-52096 bug was triggered by sending
timestamp value `1000000` in a StartTransaction message, which caused invalid month=00
generation and subsequent SQL exceptions.

**Fuzzing strategy**: Send epoch values, negative timestamps, extremely large values,
non-ISO-8601 strings, and boundary values (0, -1, MAX_INT, MAX_LONG).

## Attack Surface Analysis

### Server-Side (CSMS / Central System)

The CSMS receives and parses all Charge Point-initiated messages. Key attack vectors:

1. **JSON parsing**: Malformed JSON, deeply nested objects, extremely large payloads
2. **CiString length validation**: Fields exceeding max length
3. **Integer fields**: connectorId, transactionId, meterStart/meterStop overflow
4. **Timestamp parsing**: Malformed ISO 8601, epoch overflow
5. **Duplicate/extra properties**: OCPP.Core accepted duplicate JSON keys (CVE-2023-49958)
6. **Array handling**: Large arrays in MeterValues, SendLocalList
7. **WebSocket framing**: Fragmented frames, large frames, binary frames on text channel

### Charge Point Side

The Charge Point receives Central System commands. Key attack vectors:

1. **SetChargingProfile**: Complex nested JSON structure with schedules
2. **UpdateFirmware**: URI parsing, path traversal in firmware URLs
3. **SendLocalList**: Large authorization lists
4. **ChangeConfiguration**: Oversized value fields
5. **V2GTP framing**: Integer overflow in length field (CVE-2024-37310)
6. **SDP packet parsing**: Integer overflow in header length (CVE-2025-68137)
7. **ISO 15118 message deserialization**: Type confusion, missing fields (CVE-2025-68141)

### Internal Protocol Surfaces (on charging hardware)

1. **MQTT message handling**: OOB write via crafted MQTT messages (CVE-2024-26001)
2. **HomePlug parsing**: Byte offset mismatch in MME handlers (CVE-2024-26003)
3. **SLIP protocol**: OOB read in CRC parser (CVE-2025-68132)
4. **USB serial**: Buffer overflow via crafted display messages (CVE-2025-24004)

## Implementations to Target

### Open Source CSMS (Central Systems)

| Implementation | Language | Repository |
|---------------|----------|------------|
| SteVe | Java | https://github.com/steve-community/steve |
| OCPP.Core | C# (.NET) | https://github.com/dallmann-consulting/OCPP.Core |
| CitrineOS | TypeScript | https://github.com/citrineos/citrineos |
| ocpp (Shell/NewMotion) | Scala | https://github.com/ShellRechargeSolutionsEU/ocpp |

### Open Source Charge Point / Libraries

| Implementation | Language | Repository |
|---------------|----------|------------|
| libocpp (EVerest) | C++ | https://github.com/EVerest/libocpp |
| everest-core | C++ | https://github.com/EVerest/everest-core |
| ocpp (Python) | Python | https://github.com/mobilityhouse/ocpp |
| ocpp-jaxb | Java | https://github.com/steve-community/ocpp-jaxb |

### Commercial / Proprietary Charge Points

| Vendor | Product | Notable CVEs |
|--------|---------|-------------|
| Phoenix Contact | CHARX SEC-3000/3050/3100/3150 | CVE-2024-26001, CVE-2024-26003, CVE-2025-24003 |
| Autel | MaxiCharger AC Elite Business C50 | CVE-2024-23967 |
| Schneider Electric | EVLink Parking, EVLink Smart Wallbox | Various (EOL products) |
| ABB | Terra AC/DC, ChargerSync | Vendor-specific advisories |
| ChargePoint | Home Flex | Pwn2Own Automotive targets |

## Fuzzing Tools

### OCPP-Specific

- **OCPPStorm**: Black-box OCPP fuzzer with Random, State Machine, and Isla fuzzing modules.
  Academic tool from VehicleSec 2024. Found 5+ CVEs in OCPP.Core and SteVe.
  Paper: https://www.ndss-symposium.org/wp-content/uploads/vehiclesec2024-69-paper.pdf

- **EmuOCPP**: Scalable OCPP security testing tool from VehicleSec 2025.
  Paper: https://www.usenix.org/system/files/vehiclesec25-boussaha.pdf

### General Purpose (Applicable to OCPP)

- **boofuzz**: Python fuzzing framework. Can fuzz WebSocket JSON payloads with
  custom session scripts.
- **Radamsa**: Mutation-based fuzzer. Feed it valid OCPP JSON messages.
- **AFL/AFL++**: Coverage-guided fuzzer. Requires harness for OCPP JSON parser.
- **libFuzzer**: For fuzzing C/C++ OCPP implementations (libocpp, everest-core).
- **Atheris**: Python fuzzer for Python OCPP implementations.

### WebSocket Fuzzing

- **wsrepl**: Interactive WebSocket REPL for manual testing
- **autobahn-testsuite**: WebSocket protocol compliance and fuzzing
- **WebSocket-Fuzzer**: General WebSocket message mutation

## Mutation Strategies for OCPP

### JSON-Level Mutations

1. **Oversized strings**: CiString fields with 1MB+ payloads (CVE-2023-49955 trigger)
2. **Type confusion**: Send integer where string expected, array where object expected
3. **Duplicate keys**: Same JSON key with different values (CVE-2023-49958 trigger)
4. **Nested depth**: Deeply nested JSON objects/arrays (stack exhaustion)
5. **Invalid UTF-8**: Malformed UTF-8 sequences in string values
6. **Null bytes**: Embedded \x00 in string fields
7. **Missing required fields**: Omit mandatory fields like messageId
8. **Extra properties**: Add unexpected fields to payloads

### Protocol-Level Mutations

1. **Invalid MessageTypeId**: Values other than 2, 3, 4
2. **Malformed message array**: Wrong number of elements
3. **Unknown Action names**: Nonexistent OCPP operations
4. **Empty Action**: Zero-length action string
5. **Mismatched MessageIds**: Response with non-matching ID

### Integer Overflow Triggers

1. **connectorId**: 0, -1, MAX_INT, MAX_INT+1
2. **transactionId**: Negative values, large values, 0
3. **meterStart/meterStop**: Boundary values for energy metering
4. **V2GTP length field**: 0xFFFFFFF8-0xFFFFFFFF (CVE-2024-37310 trigger)
5. **SDP header length**: 0xFFFFFFF8-0xFFFFFFFF (CVE-2025-68137 trigger)

### Timestamp Mutations

1. Value `1000000` (CVE-2023-52096 trigger)
2. Epoch 0, negative epoch, year 0000
3. Invalid month/day: "2024-00-01T00:00:00Z", "2024-13-32T25:61:61Z"
4. Extremely long timestamp strings
5. Non-ISO-8601 format strings

## WebSocket Path Enumeration (Endpoint Discovery)

### OCPP WebSocket URL Structure

Per the OCPP-J specification (section 3.1.1), the charge point's connection URL
contains the charge point identity so that the Central System knows which charge
point a WebSocket connection belongs to. The standard URL format is:

```
ws[s]://<host>:<port>/<basePath>/<chargePointId>
```

Where `<basePath>` varies by implementation and `<chargePointId>` is unique per
charge point. This means OCPP endpoints can be discovered by brute-forcing the
base path component.

### Known Default Paths by Implementation

| Implementation | Default Path | Default Port | OCPP Versions |
|---------------|-------------|-------------|---------------|
| SteVe | `/steve/websocket/CentralSystemService/<cpId>` | 8180 | 1.2, 1.5, 1.6 |
| MaEVe (Thoughtworks) | `/ws/<cpId>` | 9310 (ws), 9311 (wss) | 1.6j, 2.0.1 |
| CitrineOS | `/<cpId>` (root) | 8081 (no auth), 8082 (basic auth) | 2.0.1 |
| EVerest ocpp-csms | `/<cpId>` (root) | 9000 | 1.6, 2.0.1 |
| Home Assistant OCPP | `/<cpId>` (root) | 9000 | 1.6 |
| EMQX OCPP Gateway | `/ocpp/<cpId>` | 33033 | 1.6 |
| flowionab ocpp-csms-server | `/ocpp/<cpId>` | 3000 | 1.6, 2.0.1 |
| gregszalay ocpp-csms | `/ocpp/<cpId>` (inferred) | 3000 | 2.0.1 |
| open-ocpp (c-jimenez) | `/ocpp/<cpId>` | 3000 | 1.6, 2.0.1 |
| ocpp-go (lorenzodonini) | `/{configurable}/<cpId>` | configurable | 1.6, 2.0.1 |
| Shell/NewMotion OCPP | `/ocpp/<cpId>` | varies | 1.2-2.0.1 |
| evcc | `/<cpId>` (root) | 8887 | 1.6 |
| ocpp-rpc (Node.js) | `/<cpId>` (root) | 3000 | 1.6, 2.0.1 |
| Python OCPP (mobilityhouse) | `/<cpId>` (root) | 9000 | 1.6, 2.0.1 |
| Zephyr RTOS | `/steve/websocket/CentralSystemService/<cpId>` | varies | 1.6 |
| PcVue OCPP | configurable | configurable | 1.6, 2.0.1 |
| AWS OCPP Gateway | configurable (NLB) | 80, 443 | 1.6, 2.0.1 |

### Additional Open-Source Central Systems

| Implementation | Default Path | Default Port | OCPP Versions |
|---------------|-------------|-------------|---------------|
| Open e-Mobility (ev-server) | `/ocpp/<cpId>` | 8010 (JSON/WS), 8000 (SOAP) | 1.6, 2.0.1 |
| cFos Charging Manager | `/` (root, no path) | 19520 | 1.6 |

### Commercial CSMS Deployments

| Provider | Endpoint Format | Notes |
|----------|----------------|-------|
| has-to-be / be.ENERGISED | `ws[s]://INSTANCE.private.ocpp-broker.com/ocpp/cp/socket/15/<cpId>` | Port 80 (ws), 443 (wss) |
| Monta | `wss://ocpp.monta.app/` | Port 443 (wss), 80 (ws fallback) |
| Sintio | `wss://ocpp.sintio.app/ocpp16/{OrgId}/` | Trailing slash required |
| ChargeHQ | `ws://ocpp.chargehq.net/ocpp16/{EVSE_ID}` | |
| eCarUp | `ws://www.ecarup.com/api/Ocpp16/{ecarupID}/` | |
| Epic Charging | `wss://ocpp.epiccharging.com` | |
| ChargePoint | Proprietary | Uses be.ENERGISED backend |
| Ampcontrol | Custom | API-based integration |

### Charger Vendor URL Quirks

| Vendor | Quirk |
|--------|-------|
| Mennekes, Ensto, Bender | **Trailing slash required** at end of URL |
| myenergi Zappi | **Do NOT add CP ID** to URL (cloud-to-cloud bridge) |
| Zaptec | Auto-appends serial number **in UPPERCASE**; max URL 2038 chars |
| Alfen Eve | URL+password **truncated to 200 chars** in OCPP 1.5/1.6 |
| ABB Terra | TerraConfig does NOT support `wss://` for external OCPP servers |
| KEBA, Vestel | Port in **separate field** -- do not include in URL string |
| Mennekes, Bender | **No special characters** allowed in ChargePoint ID (no spaces, underscores, +, ") |

### Charge Point ID Format Conventions

Real-world charge point IDs follow vendor-specific patterns:

| Vendor/Platform | Format | Example |
|----------------|--------|---------|
| Volt Time | `VT_<serial>` | `VT_0001234` |
| SteVe default | `STEVE_<id>` | `STEVE_01` |
| Generic | `CP_<number>` | `CP_001`, `CP_002` |
| Generic | `CHARGER_<number>` | `CHARGER_001` |
| Generic | `CHARGER-<number>` | `CHARGER-001` |
| ABB | Vendor-specific serial | `ABB-1234567` |
| myenergi | Device serial number | `12345678` |
| OpenEVSE | Custom | `openevse-charger` |
| OIDA Scanner default | `CP_SCANNER_001` | `CP_SCANNER_001` |

Note: OCPP 1.5/1.6 limits the charge point identity to 20 characters (CiString20).
OCPP 2.0.1 extends this to 48 characters.

### Security Implications

WebSocket path brute-forcing is useful for:

1. **Hidden endpoint discovery**: Find CSMS endpoints not listed in public documentation
2. **Version detection**: Different paths may serve different OCPP versions
3. **Access control bypass**: Some paths may have different auth requirements
4. **Charge point enumeration**: Discovering charge point IDs reveals the fleet
5. **CSMS fingerprinting**: Path structure reveals the backend implementation

The `--ws-brute` flag in OIDA automates this by testing all paths from
`ref/ocpp/ws_paths.txt` against a target host.

## Security Research References

- "OCPP Protocol: Security Threats and Challenges" (2017) - https://www.researchgate.net/publication/313781416
- "OCPP in the spotlight: threats and countermeasures" (2023) - https://link.springer.com/article/10.1007/s10207-023-00698-8
- "OCPPStorm: A Comprehensive Fuzzing Tool" (VehicleSec 2024) - https://www.ndss-symposium.org/ndss-paper/auto-draft-457/
- "EmuOCPP: Effective and Scalable OCPP Security" (VehicleSec 2025) - https://www.usenix.org/system/files/vehiclesec25-boussaha.pdf
- "Uncovering Covert Attacks on EV Charging Infrastructure" (ACM AsiaCCS 2024) - https://dl.acm.org/doi/10.1145/3634737.3644999
- Pwn2Own Automotive 2024 CHARX exploitation - https://blog.ret2.io/2024/07/17/pwn2own-auto-2024-charx-bugs/
- Quarkslab EVerest Security Audit (OSTIF-sponsored, 2025) - https://github.com/EVerest/everest-core/security/advisories
- CERT VDE Phoenix Contact Advisory VDE-2024-011 - https://certvde.com/en/advisories/VDE-2024-011
- CERT VDE Phoenix Contact Advisory VDE-2024-019 - https://certvde.com/en/advisories/VDE-2024-019/
- CERT VDE Phoenix Contact Advisory VDE-2025-014 - https://certvde.com/en/advisories/VDE-2025-014/
- SaiFlow OCPP WebSocket hijacking research - https://www.saiflow.com/blog/how-mishandling-of-websockets-can-cause-dos-and-energy-theft
- SaiFlow ABB Terra AC EVSE Takeover - https://www.saiflow.com/blog/abb-terra-ac-improper-authentication-can-lead-to-evse-takeover-cve-2023-0863-cve-2023-0864
- INL "Disrupting EV Charging Sessions" (Resilience Week 2023) - https://inl.elsevierpure.com/en/publications/disrupting-ev-charging-sessions-and-gaining-remote-code-execution
- Sandia National Lab EVSE Cybersecurity (SAND2022-9315) - https://www.osti.gov/servlets/purl/1877784/
- SwRI ISO 15118 SLAC Vulnerability (2025) - https://www.swri.org/newsroom/press-releases/swri-identifies-security-vulnerability-ev-charging-protocol
- Synacktiv Tesla Wall Connector exploit (Pwn2Own 2025) - https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector
- iVision Research CHARX exploitation - https://research.ivision.com/charx-exploitation.html
- Pen Test Partners "Smart Car Chargers: Plug-n-Play for Hackers?" (2021) - https://www.pentestpartners.com/security-blog/smart-car-chargers-plug-n-play-for-hackers/
- SEC Consult Schneider EVlink advisory - https://sec-consult.com/vulnerability-lab/advisory/authentication-bypass-remote-code-execution-in-schneider-electric-evlink-charging-stations/
- SEC Consult Hardy Barth advisory - https://sec-consult.com/vulnerability-lab/advisory/multiple-vulnerabilities-in-echarge-hardy-barth-cph2-and-cpp2-charging-stations/
- ONEKEY eCharge Controllers analysis - https://www.onekey.com/resource/critical-vulnerabilities-in-ev-charging-stations-analysis-of-echarge-controllers
- NIST NCCoE EV Fast Charging Framework - https://www.nccoe.nist.gov/projects/cybersecurity-framework-profile-electric-vehicle-extreme-fast-charging-infrastructure

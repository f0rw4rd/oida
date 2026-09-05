<div align="center">

<img src="assets/oida.png" alt="OIDA" width="140" />

**Scan. Fuzz. Assess. Responsibly in OT.**

One CLI to scan, fuzz, and assess OT protocols on industrial, energy,
building-automation, and healthcare networks. It runs from a single binary, so
it works air-gapped.

[![Python](https://img.shields.io/badge/python-3.10+-5cc8e8.svg)](https://www.python.org/downloads/)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-ffb000.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![PyPI](https://img.shields.io/pypi/v/oida-ics.svg)](https://pypi.org/project/oida-ics/)
[![Email](https://img.shields.io/badge/contact-email-5cc8e8.svg)](mailto:contact@getoida.dev)

📖 **[Docs and live demo at getoida.dev](https://getoida.dev)**

</div>

---

Every protocol uses the same `oida <protocol> <target>` syntax. It is the
NetExec model for industrial control systems: if you know `nxc smb`, you already
know `oida modbus`.

## What it does

- **Scan** — 26 protocol scanners for identification, enumeration, and
  security assessment, all behind one consistent CLI.
- **Fuzz** — 35 protocol fuzzers (boofuzz-backed) with stateful sequencing,
  crash detection, and session replay.
- **Listen** — a passive PCAP pipeline with 100+ protocol listeners that
  extract devices, credentials, and interactions off the wire, no packets sent.

Read-only by default. Anything that writes or changes device state needs an
explicit `--confirm`.

## Install

```bash
pip install 'oida-ics[all]'
```

Protocol stacks ship as extras, so you can install only what you need, like
`pip install 'oida-ics[modbus,opcua]'`. A bare `pip install oida-ics` has no
protocol stacks at all. Standalone single-file binaries (no Python required)
and the full install guide are at
[getoida.dev/getting-started/installation](https://getoida.dev/getting-started/installation/).

## Quickstart

```bash
oida modbus 10.0.0.5                  # scan a single host
oida modbus 10.0.0.0/24 -t 20        # scan a subnet, 20 threads
oida opcua opc.tcp://10.0.0.5:4840   # OPC UA endpoint
oida s7 10.0.0.5                     # Siemens S7 (snap7)
oida discovery eth0                  # find ICS devices on the wire
oida pcap capture.pcap               # passively analyze a capture
```

Every scan can export structured results:

```bash
oida modbus 10.0.0.5 -o results --format json   # also: csv, xml, or all
```

Run `oida` with no arguments for the live protocol list, or `oida <protocol> -h`
for a protocol's full flag set.

## Protocols

| Domain | Protocols |
|---|---|
| **OT / industrial** | Modbus, OPC UA, Siemens S7, DNP3, IEC 60870-5-104, BACnet, EtherNet/IP, PROFINET, EtherCAT, MMS, TASE.2, GOOSE, ADS, HART, KNX, CAN |
| **IoT / application** | MQTT, CoAP, OCPP, SNMP |
| **Healthcare** | HL7, FHIR, DICOM, ASTM |
| **Discovery / passive** | `discovery` (active sweep), `pcap` (passive listener pipeline) |

The full list and the per-protocol guides live at
[getoida.dev/protocols](https://getoida.dev/protocols/modbus/).

## Safety

- Read-only by default; writes and state changes require `--confirm`.
- The tool can crash devices, trigger actuator writes, and extract
  credentials. These are features, not bugs.
- Run it only against systems you own or are authorized to test.

## Links

- **Docs and demo:** [getoida.dev](https://getoida.dev)
- **Discussion:** [GitHub Discussions](https://github.com/f0rw4rd/oida/discussions)
- **Contact:** [contact@getoida.dev](mailto:contact@getoida.dev)
- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md), [Code of Conduct](CODE_OF_CONDUCT.md)
- **Security:** report it through [getoida.dev/contact](https://getoida.dev/contact); see [SECURITY.md](SECURITY.md) for what to include
- **Support:** [ko-fi.com/f0rw4rd](https://ko-fi.com/f0rw4rd)

## Legal

OIDA is built for authorized security research and defensive assessment of OT/ICS and healthcare networks. Use it only against systems you own or have explicit written authorization to test. Computer crime statutes in most jurisdictions apply regardless of intent.

The tool can crash devices, trigger physical actuator writes, and extract credentials. These are features, not bugs. Do not run it against systems you are not prepared to disrupt.

Full terms, capability disclosure, warranty disclaimer, and jurisdiction guidance: [getoida.dev/legal](https://getoida.dev/legal/).

All protocol and vendor names (EtherCAT, PROFINET, Modbus, BACnet, EtherNet/IP, OPC UA, DICOM, HL7, FHIR, KNX, and others) are the property of their respective owners. OIDA is unaffiliated with and unendorsed by any of those organizations.

## License

[AGPL-3.0](LICENSE)

## Trademarks

All marks belong to their owners; used nominatively to describe interoperability; no endorsement implied.

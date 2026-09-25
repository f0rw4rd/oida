<div align="center">

<img src="assets/oida.png" alt="OIDA" width="140" />

**Scan. Fuzz. Assess. Responsibly in OT.**

One CLI to scan, fuzz, and assess OT protocols on industrial, energy,
building-automation, and healthcare networks. It runs from a single binary, so
it works air-gapped.

[![Python](https://img.shields.io/badge/python-3.10+-5cc8e8.svg)](https://www.python.org/downloads/)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-ffb000.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![PyPI](https://img.shields.io/pypi/v/oida-ics.svg)](https://pypi.org/project/oida-ics/)

**[Docs and live demo at getoida.dev](https://getoida.dev)**

</div>

---

Every protocol uses the same `oida <protocol> <target>` syntax. It is the
NetExec model for industrial control systems: if you know `nxc smb`, you already
know `oida modbus`.

## Install

```bash
pip install 'oida-ics[all]'
```

The PyPI package is `oida-ics` (the name `oida` was already taken); the command
it installs is still `oida`. Protocol stacks ship as extras, so you can install
only what you need, like `pip install 'oida-ics[modbus,opcua]'`. A bare
`pip install oida-ics` has no protocol stacks at all. The full install guide is at
[getoida.dev/getting-started/installation](https://getoida.dev/getting-started/installation/).

## Usage

```bash
oida modbus 10.0.0.5                  # scan a host
oida modbus 10.0.0.5:5020             # ...on a non-default port
oida modbus 10.0.0.0/24 -t 20         # scan a subnet
oida opcua opc.tcp://10.0.0.5:4840    # OPC UA
oida discovery eth0                   # find ICS devices on the wire
```

Any target may carry a port - `10.0.0.5:5020`, `10.0.0.0/24:5020`,
`[2001:db8::1]:5020`, or per line in a target file - which saves repeating
`-p` and is the only way to scan hosts on different ports in one run. A port in
the target wins over `-p/--port`.

Defaults are read-only. Writes and state changes need an explicit `--confirm`.
Run `oida <protocol> -h` for a protocol's full flag set.

## Protocols

OIDA ships scanners for Modbus, OPC UA, Siemens S7, DNP3, IEC 60870-5-104,
BACnet, EtherNet/IP, PROFINET, HL7, DICOM, MQTT, SNMP, and many more. The full
list and the per-protocol guides live at
[getoida.dev/protocols](https://getoida.dev/protocols/modbus/).

## Links

- **Docs and demo:** [getoida.dev](https://getoida.dev)
- **Discussion:** [GitHub Discussions](https://github.com/f0rw4rd/oida/discussions)
- **Contact:** [contact@getoida.dev](mailto:contact@getoida.dev)
- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md), [Code of Conduct](CODE_OF_CONDUCT.md)
- **Security:** report it through [getoida.dev/contact](https://getoida.dev/contact); see [SECURITY.md](SECURITY.md) for what to include
- **Support:** [via QuellSec](https://quellsec.dev/#support)

## Legal

OIDA is built for authorized security research and defensive assessment of OT/ICS and healthcare networks. Use it only against systems you own or have explicit written authorization to test. Computer crime statutes in most jurisdictions apply regardless of intent.

The tool can crash devices, trigger physical actuator writes, and extract credentials. These are features, not bugs. Do not run it against systems you are not prepared to disrupt.

Full terms, capability disclosure, warranty disclaimer, and jurisdiction guidance: [getoida.dev/legal](https://getoida.dev/legal/).

All protocol and vendor names (EtherCAT, PROFINET, Modbus, BACnet, EtherNet/IP, OPC UA, DICOM, HL7, FHIR, KNX, and others) are the property of their respective owners. OIDA is unaffiliated with and unendorsed by any of those organizations.

## License

[AGPL-3.0](LICENSE)

## Trademarks

All marks belong to their owners; used nominatively to describe interoperability; no endorsement implied.

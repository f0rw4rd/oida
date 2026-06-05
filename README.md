<div align="center">

<img src="assets/oida.png" alt="OIDA" width="140" />

# OIDA

**Scan. Fuzz. Assess. Responsibly in OT.**

One CLI to scan, fuzz, and assess OT protocols on industrial, energy,
building-automation, and healthcare networks. It runs from a single binary, so
it works air-gapped.

[![Python](https://img.shields.io/badge/python-3.10+-5cc8e8.svg)](https://www.python.org/downloads/)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-ffb000.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![PyPI](https://img.shields.io/pypi/v/oida.svg)](https://pypi.org/project/oida/)
[![Discord](https://img.shields.io/badge/Discord-join-5865F2?logo=discord&logoColor=white)](https://discord.gg/grM9YYSB)

📖 **[Docs and live demo at getoida.dev](https://getoida.dev)**

</div>

---

Every protocol uses the same `oida <protocol> <target>` syntax. It is the
NetExec model for industrial control systems: if you know `nxc smb`, you already
know `oida modbus`.

## Install

```bash
pip install 'oida[all]'
```

Protocol stacks ship as extras, so you can install only what you need, like
`pip install 'oida[modbus,opcua]'`. A bare `pip install oida` has no protocol
stacks at all. The full install guide is at
[getoida.dev/getting-started/installation](https://getoida.dev/getting-started/installation/).

## Usage

```bash
oida modbus 10.0.0.5                  # scan a host
oida modbus 10.0.0.0/24 -t 20         # scan a subnet
oida opcua opc.tcp://10.0.0.5:4840    # OPC UA
oida discovery eth0                   # find ICS devices on the wire
```

Defaults are read-only. Writes and state changes need an explicit `--confirm`.
Run `oida <protocol> -h` for a protocol's full flag set.

## Protocols

OIDA ships scanners for Modbus, OPC UA, Siemens S7, DNP3, IEC 60870-5-104,
BACnet, EtherNet/IP, PROFINET, HL7, DICOM, MQTT, SNMP, and many more. The full
list and the per-protocol guides live at
[getoida.dev/protocols](https://getoida.dev/protocols/modbus/).

## Links

- **Docs and demo:** [getoida.dev](https://getoida.dev)
- **Community:** [Discord](https://discord.gg/grM9YYSB)
- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md), [Code of Conduct](CODE_OF_CONDUCT.md)
- **Security:** report it through [getoida.dev/contact](https://getoida.dev/contact); see [SECURITY.md](SECURITY.md) for what to include
- **Support:** [ko-fi.com/f0rw4rd](https://ko-fi.com/f0rw4rd)

## License

[AGPL-3.0](LICENSE)

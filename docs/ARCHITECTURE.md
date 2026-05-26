# OIDA Class Architecture

Status: living document. Last updated 2026-05-26.

## Two-layer protocol architecture

Every protocol module exposes its functionality through up to **two layers**:

- **Layer 1 — `XxxScanner(NetworkScanner|SerialScanner|BaseScanner)`**
  Library-style protocol implementation. Methods take an explicit *client* /
  *connection* parameter and return values. Designed for `import` and
  composition by other Python code.

- **Layer 2 — `xxx(NetworkConnection|SerialConnection)`**
  NXC-style callable. Constructed with `(args, db, host)`; protocol execution
  is triggered automatically inside `__init__`. CLI dispatch lives here.

  By convention this class is named **lowercase** (`modbus`, `opcua`, `s7`)
  so the CLI entry point reads naturally: `oida modbus 10.0.0.1`.

## Canonical inheritance pattern (facade)

**Modbus is the reference implementation.** Adopt this pattern for new
protocols and when refactoring existing ones:

```
modbus/
├── scanner.py                 # L1: ModbusScanner(NetworkScanner)
│                              #     + 8 ScannerXxxMixin classes
├── nxc_connection.py          # L2: modbus(NetworkConnection)
│                              #     + 11 XxxMixin classes
├── scanner_mixins/            # L1 protocol-impl mixins (take a client param,
│   ├── identification.py      # return data). Pure protocol work.
│   ├── discovery.py
│   └── ...
└── mixins/                    # L2 CLI-dispatch mixins (read self.args,
    ├── identification.py      # write self.results, call self.scanner.X()).
    ├── writes.py              # Thin facade layer.
    └── ...
```

### Why two mixin hierarchies?

They look like duplication but aren't. They separate two concerns:

| `scanner_mixins/` (Layer 1)        | `mixins/` (Layer 2)                       |
| ---------------------------------- | ----------------------------------------- |
| `_read_device_identification(client, …)` | `_handle_identify(self)` |
| Takes a client object              | Reads `self.args`                          |
| Returns a value                    | Updates `self.results` via the L1 scanner |
| Pure protocol work                 | CLI-driven dispatch and orchestration     |
| Library callers use this directly  | Only the NXC class touches this           |

The L2 NXC class stores `self.scanner = ModbusScanner(args_dict)` inside
its `create_conn_obj()`, then the L2 `_handle_X` methods call into
`self.scanner._library_method(self.conn, …)`.

## Protocols that deviate (audit, 2026-05-26)

| Protocol  | L1 (Scanner)   | L2 (NXC)   | Notes                                                     |
| --------- | -------------- | ---------- | --------------------------------------------------------- |
| **modbus** | ✓             | ✓ (delegates) | **Reference architecture**                              |
| ads       | ✓              | ✓ (delegates) | Follows the pattern                                     |
| can / coap / dnp3 / ethercat / ethernetip / goose / hart / iec104 / mms / mqtt / ocpp / snap7 / snmp / tase2 | ✓ | ✓ (delegates) | Follow the pattern |
| **opcua** | ✓              | ✓ (parallel) | L2 does not use L1. ~1,270 LoC of parallel work.        |
| **knx**   | ✓              | ✓ (parallel) | L2 does not use L1. ~1,070 LoC of parallel work.        |
| **discovery** | 2 (DiscoveryScanner, LLDPScanner) | ✓ (delegates) | OK    |
| **astm**  | —              | ✓ (fat NXC)  | No library API                                          |
| **bacnet**| —              | ✓ (fat NXC)  | No library API                                          |
| **dicom** | —              | ✓ (fat NXC)  | No library API                                          |
| **fhir**  | —              | ✓ (fat NXC)  | No library API                                          |
| **hl7**   | —              | ✓ (fat NXC)  | No library API                                          |
| **profinet** | —           | ✓ (fat NXC)  | No library API                                          |

### Refactor targets (work items for the next contributor)

**P0.** Bring `opcua` and `knx` in line with the facade pattern: extract the
mixin work currently composed into the L2 NXC class into protocol-impl
methods on the L1 Scanner that take a client param. Reduce the L2 class to
a CLI dispatcher that owns an instance of the L1 Scanner.
Estimated: ~1 day per protocol.

**P1.** Add a Layer-1 Scanner to the six protocols that currently only ship
an NXC class (`astm`, `bacnet`, `dicom`, `fhir`, `hl7`, `profinet`). The
existing fat-NXC class is the source material; the work is mechanical:
move protocol logic into a `XxxScanner(NetworkScanner)` class, change the
NXC class to delegate to it. Estimated: 1-2 days per protocol.

**P2.** A `BaseSecurityMixin` and `BaseDiscoveryMixin` abstract base in
`src/oida/utils/`. 11 protocols define their own `SecurityMixin` from
scratch; common operations (default-creds lookup via
`load_credentials()`, weak-auth reporting, security-finding emission via
`logger.security_finding()`) can be factored out. The base classes should
be small (one or two concrete helper methods plus abstract hooks). Don't
force every protocol to override every hook — keep the base mixin opt-in
per concrete subclass.

## proto_logger() contract

- `proto_logger()` is called **automatically** by `connection.__init__`
  before `proto_flow()` runs. Subclasses **do not need to call it**.
- It is idempotent: calling it again from a subclass is harmless but
  unnecessary.
- Override `proto_logger()` only if you need to add protocol-specific
  logger context beyond what the base class provides (extra fields,
  custom formatters, etc.).

Historically, all 26 NXC classes called `self.proto_logger()` as the first
line of `proto_flow()`. That was a redundant tradition — the work was
already done by `__init__` before `proto_flow()` was reached. The calls
were removed on 2026-05-26 and the contract was tightened.

## Mixin contract (typing-only protocol)

`src/oida/utils/mixin_protocol.py` defines a `ScannerMixin` `typing.Protocol`
that documents the attributes available to every mixin at runtime
(`self.logger`, `self.args`, `self.results`, `self.conn`). Mixins should
list `ScannerMixin` as a TYPE_CHECKING-only base so MyPy can see the
attributes without forcing inheritance at runtime.

Pattern used in `modbus/scanner_mixins/*`:

```python
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object

class ScannerXxxMixin(_ScannerBase):
    ...
```

Adopt this pattern in any new mixin so the type checker has the right
attribute surface without imposing diamond inheritance at runtime.

# Fuzzer optimizations — ready-to-implement

Each entry is a specific, line-targeted optimization derived from the per-protocol
`fuzzer.md` + `cve_patterns.json` reviews. Tackle them in any order.

## Done in 1.0

- ✅ **mdns Quick_Coverage zero-mutation** — `mdns.py:324-327` section counts changed from `Static` to `Word`. (commit `249aee17`)
- ✅ **IEC 104 DATA_TRANSFER state never reached** — `iec104.py:1090` pre-transitions after `IEC104StateMachine` init. (commit `dea6dc90`)
- ✅ **OPC UA `OPCUA_Query` phantom** — removed in 1.0 release punch list. (commit `19912af5`)
- ✅ **Crash dedup via `crash_hash`** — `models.py`/`orm.py`/`mock.py`. (commit `19912af5`)
- ✅ **Dual DB backends collapsed** — `SQLiteDatabase` removed; `SQLAlchemyDatabase` is canonical. (commit `19912af5`)

## Open — small (≤ 1 hour each)

### Modbus

- **Cap ADU overflow** — `src/oida/fuzz/protocols/modbus/tcp.py` and `rtu.py` — boofuzz `String`/`Bytes` overflow defaults can generate multi-MiB frames that OOM the target before the TCP stack drops. Add a `max_len=4096` to overflow primitives.
- **Audit RTU CRC mutation path** — `modbus/rtu.py:252,272,295,314,331` use `Word("CRC", 0x0000, endian="<")`. Verify the send pipeline doesn't recompute the CRC after boofuzz mutates it. If it does, add a `RTU_Bad_CRC` request that uses `Static` for the CRC bytes.

### DNP3

- **Add `DNP3_Object_Sweep` request** — `dnp3.py`. Iterate `Group("Group", values=range(1,90))` × `Group("Variation", values=range(0,17))` against a Read function code. Targets vendor-specific object-parsing. See `ref/dnp3/cve_patterns.json#dnp3-object-group-sweep`.
- **Add `DNP3_IIN_Master` request** — master-emulation mode; fuzz the 16-bit IIN flags field. See `ref/dnp3/cve_patterns.json#dnp3-iin-flags-master`.
- **Add `DNP3_DL_Bad_CRC` request** — DL block CRC is auto-recomputed; static invalid CRC tests validation.

### EtherNet/IP

- **Re-audit `fuzzable=False` in CIP_Path_*** — `ethernetip.py`. The path-length header byte should stay non-fuzzable, but class/instance/attribute *value* bytes should flip to default-fuzzable. See `ref/ethernetip/cve_patterns.json#enip-cip-path-encoding`.
- **Flip `Forward_Open.OT_RPI / TO_RPI`** to default-fuzzable — extreme RPI values (0, 1, 0xFFFFFFFF) hit timer crashes. See `ref/ethernetip/cve_patterns.json#enip-forward-open-rpi`.
- **Add `CIP_Class_Enumeration` request** — `Group("ClassID", values=[0x01, 0x02, 0x04, 0x06, 0xF4, 0xF5, 0xF6, 0xAC, 0x100, 0x101, 0x110])`. See `ref/ethernetip/cve_patterns.json#enip-class-enumeration`.

### IEC 104

- **Reserved type-ID coverage** — extend the `Group("ASDU.TypeId", ...)` to include 128-135 (reserved) and 136-255 (vendor) ranges. Single-line change. See `ref/iec104/cve_patterns.json#iec104-asdu-type-id-reserved`.
- **Common Address sweep field** — add `Group("ASDU.CommonAddress", values=[0, 1, 65534, 65535, 32767, 32768])` to the existing `IEC104_ASDU_TypeId` request. See `ref/iec104/cve_patterns.json#iec104-common-address-sweep`.

### MMS

- **`MMS_BER_Tag_Confusion` request** — `mms.py`. Take a valid MMS PDU template, replace the outer SEQUENCE tag (0x30) with `Group([0x30, 0x31, 0x80, 0xA0, 0xA1, 0xC0, 0xE0])`. High-yield ASN.1 parser bug class. See `ref/mms/cve_patterns.json#mms-asn1-tag-confusion`.

### ADS

- **`ADSMonitor` integration TODO** — `ads.py`. Wire the existing `ADSMonitor` class into the fuzzer's monitor chain. Single-line registration. Promotes ADS-side error codes (e.g. `0x70A`) to crash events. Audit S6.
- **Add `ADS_Port_Enumeration`** — `Group("AMS.TargetPort", values=[100, 110, 200, 350, 400, 500, 851, 852, 853, 900])` on the ADS_Read request. See `ref/ads/cve_patterns.json#ads-port-enumeration`.
- **Add `ADS_SumReadWrite` request** — Beckhoff-specific bulk operation; missing from current request set. See `ref/ads/cve_patterns.json#ads-sumcommand`.

### SNMP

- **Cap walk recursion** — `snmpv2.py`. The `WALK_XFAIL` is from unbounded GetNext recursion. Add a depth cap (100). See `ref/snmp/cve_patterns.json#snmpv2c-walk-recursion`.
- **Add SNMPv3 USM auth-param fuzzing** — `snmpv3.py`. The 12-byte AuthenticationParameters and 8-byte PrivacyParameters fields need explicit `Group()` mutation (currently treated as derived). See `ref/snmp/cve_patterns.json#snmpv3-usm-auth-params`.
- **Add the four missing SNMPv3 Request types** — SetRequest-PDU, Trap-PDU, InformRequest-PDU, GetBulkRequest-PDU. Audit S8.

### OPC UA

- **Extend ExtensionObject TypeId Group** — `opcua.py`. Current group covers common TypeIds; add vendor-reserved range (0x6XXX). See `ref/opcua/cve_patterns.json#opcua-extension-object-typeid`.

### HL7

- **HL7 v2.x version sweep on MSH-12** — single `Group()` over version strings 2.3/2.4/2.5/2.6/2.7/2.8. See `ref/hl7/fuzzer.md` recommendation 1.
- **Z-segment injection request** — inject a malformed `Z` segment mid-message. Catches parsers that don't skip vendor segments gracefully.

### MQTT

- **Sparkplug B payload fuzzing** — separate Request that wraps a fuzzed protobuf payload inside MQTT PUBLISH. See `ref/mqtt/fuzzer.md`.
- **MQTT 5.0 reason code sweep** — `Group()` over all 256 byte values.

### CoAP

- **Explicit `fuzzable=` annotations** on Ver/T/TKL/Code header bits. Mechanical clarity pass. See `ref/coap/fuzzer.md`.

## Open — medium (1-3 days each)

### Architecture migrations

- **Migrate SMTP to `StatefulFuzzer`** — `smtp.py`. The state names today are metadata tags; framework doesn't enforce. Audit B7/B9.
- **Migrate HTTP to `StatefulFuzzer`** — `http_protocol.py`. Same class; pipelined / Keep-Alive sequences are where smuggling-class bugs live. Audit B10.
- **Migrate OPC UA to `StatefulFuzzer`** — `opcua.py`. Same class; unblocks `OPCUA_State_Confusion` (xfail).

### OPC UA xfailed attack patterns (B5)

- **`OPCUA_NodeIdEncodingOverflow`** — hand-rolled NodeId encoder where length doesn't match encoding byte. See `ref/opcua/cve_patterns.json#opcua-nodeid-encoding-overflow`.
- **`OPCUA_MalformedCert`** — raw socket path needed (asyncua doesn't expose hook). See `ref/opcua/cve_patterns.json#opcua-malformed-cert`.
- **`OPCUA_State_Confusion`** — depends on `StatefulFuzzer` migration above.

### Dead test scaffolding

Tests reference these protocols but no fuzzer module exists:
- `tase2`, `hartip`, `fins`, `dicom`, `industrial_ethernet`, `profinet_dcp`.

Either implement the fuzzer (using `ref/<proto>/` as starting material — see `ref/_NO_FUZZER_YET.md`) or remove the test scaffolding.

## Open — large (≥ 1 week each)

These are new fuzzer modules for protocols where `ref/<proto>/` exists but no
fuzzer is registered. See `ref/_NO_FUZZER_YET.md` for the full list and
difficulty estimates. Top candidates:

- **Siemens S7 / S7comm** (~3 days)
- **HART-IP** (~1 day — hartip-py client is good)
- **TASE.2 / ICCP** (~2 days — derive from mms.py)
- **KNX** (~3 days — xknx tunneling)
- **PROFINET DCP** (~3 days — Layer-2 raw socket)
- **GOOSE** (~3 days — Layer-2 multicast)

## How to verify any of the above

Each cve_patterns.json entry has a `target_request` and `target_field` that
maps to a specific boofuzz primitive. After applying a fix, re-run:

```bash
pytest tests/unit/fuzz -q                              # all fuzzer tests
pytest tests/unit/fuzz/test_<proto>_fuzzer.py -v       # protocol-specific
pytest tests/unit/fuzz/test_fuzzer_coverage.py -v      # request-count regression
```

The coverage test in `test_fuzzer_coverage.py` enforces ICS request count
baselines — when adding a new request, update `ICS_AUDIT_REQUEST_COUNTS` in
that file by the same amount.

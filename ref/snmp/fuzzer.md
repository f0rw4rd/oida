# SNMP v1 / v2c / v3 — OIDA fuzzer notes

| Property | v1 | v2c | v3 |
|---|---|---|---|
| OIDA module | `src/oida/fuzz/protocols/snmpv1.py` | `snmpv2.py` | `snmpv3.py` |
| Boofuzz class | `SNMPv1Fuzzer` | `SNMPv2cFuzzer` | `SNMPv3Fuzzer` |
| Requests | 13 | 12 | 8 (audit S8: low) |
| Mutation depth | 40:72:128 | 52:83:129 | 97:91:188 |
| State machine | None | None | None |

Shared helpers: `snmp_common.py` (BER encoding, varbind helpers).

## CVE patterns covered

See `ref/snmp/cves/README.md`. SNMP has a long parser-CVE history (Net-SNMP,
ucd-snmp, vendor stacks):

| CVE pattern | Where it should fire | Covered? |
|---|---|---|
| BER length encoding (CVE-2002-0012 class) | Mutation of OBJECT IDENTIFIER and VARBIND lengths | ✓ |
| Community string overflow (legacy SNMPv1/2c) | `String` mutation on community field | ✓ |
| SNMPv3 USM authentication parameter (CVE-2018-18066 class) | USM auth field — **not fuzzed**, audit S8 | ✗ |
| SNMPv3 engine ID — non-canonical encoding | covered for v3 init | ✓ |
| GetBulk max-repetitions overflow | covered via boofuzz Word mutation | ✓ |
| Trap PDU enterprise-OID parsing | partial | ⚠ |
| Walk/recursion stack overflow (SNMPv2c "walk" test) | benchmark XFAILed (`WALK_XFAIL`) | ✗ |

## Known gaps

- **v3 USM auth params not fuzzed.** The Authentication Parameters and
  Privacy Parameters fields in the SNMPv3 USM header are critical
  attack surface (CVE-2018-18066 class). Today the fuzzer treats them
  as `Static` after key derivation; should be mutated independently.
- **v3 RequestInfo count = 8** (audit S8) — should be closer to v2c (12).
  Missing: SetRequest-PDU, Trap-PDU, InformRequest-PDU, GetBulkRequest-PDU.
- **v2c walk recursion** — `WALK_XFAIL` marker blocks 5 benchmark tests.
  Symptom of unbounded recursion in the GetNext-driven walk.
- **One tshark validation FAIL** on v3 — hidden in the test summary
  (audit B11).

## Optimization recommendations

1. **Add USM parameter fuzzing.** Mutate `USM.AuthenticationParameters`
   and `USM.PrivacyParameters` as raw bytes (12-byte HMAC truncation
   and 8-byte salt respectively). High-CVE-yield surface.
2. **Add the four missing v3 Request types** (SetRequest, Trap,
   InformRequest, GetBulkRequest). Brings v3 in line with v2c.
3. **Cap walk recursion** at 100 levels.
4. **Expand SNMPv1 community wordlist for fuzzing**, not just for
   brute-force — short and long community strings (1, 32, 256, 1024,
   8192 bytes) catch buffer-size bugs.

# OPC UA — OIDA fuzzer notes

| Property | Value |
|---|---|
| OIDA module | `src/oida/fuzz/protocols/opcua.py` + `opcua_constants.py` |
| Boofuzz class | `OPCUAFuzzer` (BaseFuzzer; uses state names but no `StatefulFuzzer` extension) |
| Requests | 21 (after `OPCUA_Query` phantom was removed in 1.0) |
| Mutation depth | 3 fuzzable : 76 default : 174 Static (Static-heavy) |
| State machine | None at the framework level; state names tracked manually in `RequestInfo.requires_state` |
| Test coverage | `tests/unit/fuzz/test_opcua_fuzzer_audit.py` (53 dedicated tests) + benchmark `(45, 250000, 1800)` |

## CVE patterns covered

See `ref/opcua/cves/README.md`. OPC UA CVEs cluster around:

| CVE pattern | OPC UA fuzzer request | Covered? |
|---|---|---|
| OpenSecureChannel — security mode / policy mismatches | `OPCUA_OpenSecureChannel` | ✓ |
| MessageHeader — `MessageSize` lying about payload | `OPCUA_MessageHeader_Mutation` | ✓ |
| NodeId encoding — index-format / namespace-index overflow | declared by `OPCUA_NodeIdEncodingOverflow` — **xfail, not implemented** | ✗ |
| Malformed certificate (self-signed, wrong key usage) | declared by `OPCUA_MalformedCert` — **xfail, not implemented** | ✗ |
| State-confusion — sending session requests before secure channel | declared by `OPCUA_State_Confusion` — **xfail, not implemented** | ✗ |
| Read / Browse — invalid NodeId references | `OPCUA_Read`, `OPCUA_Browse` | ✓ |
| ExtensionObject — TypeId / encoding mask abuse | covered via boofuzz mutation of ExtensionObject blocks | ✓ |
| String / ByteString overflow | covered via boofuzz `String` defaults | ✓ |
| Subscription denial-of-service (queue depth) | `OPCUA_CreateSubscription` with mutated `RequestedPublishingInterval` | ✓ |
| History read — time-range overflow | `OPCUA_History_Read` | ✓ |

## Known gaps (xfail-tracked)

Three attack-pattern requests are declared in `get_request_definitions()`
but xfailed in `test_opcua_fuzzer_audit.py`. They are open work and a
known limitation of the 1.0 fuzzer:

- `OPCUA_MalformedCert` — sending a session-open with a deliberately
  invalid client certificate to exercise the validator. Blocked because
  asyncua's secure-channel layer doesn't expose a hook for sending pre-
  computed bad cert bytes; would need a raw socket path.
- `OPCUA_NodeIdEncodingOverflow` — varying the NodeId encoding byte
  (0x00 / 0x01 / 0x02 / 0x03 / 0x04 / 0x05) with a payload that lies
  about its own length. Requires a hand-rolled NodeId encoder; the
  boofuzz `Group` over encoding bytes is straightforward but the matched
  payload generator is not.
- `OPCUA_State_Confusion` — sending a `Read` service request before
  `OpenSecureChannel`. Needs `StatefulFuzzer` extension (see audit B10).

These three xfails were called out as a release blocker (B5) but
documented as post-1.0 work in `RELEASE_READINESS.md` since each requires
non-trivial new code.

## Coverage trade-offs

- **Static-heavy mutation profile** (174 Statics vs. 3 fuzzable). This
  is *intended* — most fields are protocol framing (TypeIds, message
  type codes) that boofuzz default-mutate would generate invalid frames
  the dissector rejects before reaching the parser logic. The 76
  default-fuzzable fields carry the variation.
- **Coverage matrix categories** enforced by
  `tests/unit/fuzz/test_opcua_fuzzer_audit.py::TestOPCUACategoryCoverage`:
  baseline, encoding, session, security, services, browse, read, write,
  history, subscriptions, methods, attacks. The xfails sit in the
  `attacks` and `security` categories.

## RequestInfo naming

OPC UA `RequestInfo` entries match real `Request` objects 1:1. This is
the canonical layout — modbus and iec104 use a many-to-one grouping
that confuses `--enable`.

## Optimization recommendations

1. **Land the three xfailed attack requests.** Each one has a clear
   spec in the `test_opcua_fuzzer_audit.py` skip-reason. Estimated
   1-2 days per request, mostly in extending the asyncua client wrapper
   to send raw bytes for the secure-channel path.
2. **Migrate OPC UA fuzzer to `StatefulFuzzer`** so that `requires_state`
   on `RequestInfo` actually drives the session graph. Today it's a
   metadata tag the framework doesn't enforce — meaning a
   `requires_state="SESSION_ACTIVE"` request can fire before any session
   exists. This is the same audit blocker class as B9/B10.
3. **ExtensionObject TypeId mutator** — covered today by `Group()` over
   common TypeIds, but the long tail (vendor-specific TypeIds in the
   0x6XXX range) is unexercised. A small `Group` extension would catch
   vendor parser bugs.

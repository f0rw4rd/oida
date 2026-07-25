# AI-Generated-Codebase Audit — OIDA

**Date:** 2026-07-24 · **Scope:** `src/oida/` (337,719 LOC, 606 files) + `tests/` (290,889 LOC, 697 files)
**Method:** published research on AI-generated-code pathologies → derived checklist → eight parallel verified audits + tooling sweeps.
**Result:** 107 findings. Every one carries a `file:line` and was verified against the code; candidates that did not survive verification are listed in §11 so they are not re-flagged.

---

## 0. The research baseline

| Source | Finding used as a check |
|---|---|
| [Debt Behind the AI Boom (arXiv 2603.28592)](https://arxiv.org/html/2603.28592v2) — 302.6k AI-authored commits | Code smells 89.3% of defects. Top: **broad exception handling (8.5%)**, unused vars/args (10.8%), shadowed outer variables (4.3%), access to protected members (4.1%). Correctness: undefined reference 4.9%. Security 4.7%: path traversal, unsafe format strings, non-literal regex, child process, raw SQL. >15% of AI commits introduce a detectable issue. |
| [GitClear, 211M LOC 2020–2024](https://www.gitclear.com/ai_assistant_code_quality_2025_research) | Duplicated 5+ line blocks **up 8×** in 2024; refactored ("moved") lines fell 24.1% → 9.5%; copy-paste overtook refactoring for the first time; **churn +39%**. |
| [Beyond Functional Correctness (arXiv 2604.06373)](https://arxiv.org/abs/2604.06373) | 91% functional correctness but systematic violation of **SRP, SoC, DRY**; 9 CodeScene + 11 SonarQube design-issue categories: duplication, complexity, large methods, exception handling. |
| [Forbes: codebases only AI understands](https://www.forbes.com/councils/forbestechcouncil/2026/03/24/the-new-tech-debt-codebases-only-ai-understands/) · [Tembo](https://www.tembo.io/blog/ai-technical-debt) | **Comprehension debt**: shipping code nobody has a mental model of; docs describe the intended system, not the built one. Maintenance cost →4× by year two. |
| [LLM-revived anti-patterns](https://medium.com/according-to-context/llms-have-revived-these-5-anti-patterns-in-software-engineering-e685159fc4d8) | Over-commenting, print-debugging, high cognitive complexity, empty/placeholder classes and methods. |

**Headline:** OIDA reproduces the *structural* pathologies (duplication, dead scaffolding, exception swallowing, test inflation, doc drift) almost exactly as predicted, and is **markedly cleaner than predicted** on the *semantic* ones (hallucinated APIs: 1 finding in 13,139 checked call sites; security sinks: systematically defended).

---

## 1. Repo-level generation signatures (F1–F10)

**F1 — 628,608 LOC in a 21-day repo history (~29,900 LOC/day, 15.7 commits/day).** First commit 2026-06-18, last 2026-07-09, 329 commits. No human or small team reviews 30k LOC/day; this is the precondition for every other finding here.

**F2 — 29% rework rate.** 1,176,595 insertions vs 338,667 deletions across history. GitClear's AI-churn marker is +39% over baseline; this sits squarely in that band.

**F3 — The pathology is already recurring and self-documented.** Commits `a098f69`, `46f1979`, `c8b58a4`, `0ac6281`, `269fbe7`, `9af5087` are each titled *"<proto>: fix slop-check findings"* across coap/fhir/mqtt/can/dicom/ocpp, deleting 129–407 lines apiece. Dead code is being generated faster than it is swept.

**F4 — Unreviewable working tree.** 262 files changed, +7,009/−1,644 uncommitted, plus **45 untracked `.py` files** including 17 complete new fuzz protocol modules (`astm, can, dicom, ethercat, goose, hart_ip, igmp, knx, netbios, pppoe, profinet, s7comm, sixlowpan, tase2` …) and 27 new test files. An entire feature tranche is staged outside version control.

**F5 — Scratch artifacts committed to the repo root, ungitignored.** `ftp_t.db`, `tmp.7PyMhzIw8j`, `results/modbus.json`, `.claude/`, `.claude-work/` — `git check-ignore` returns NO for all five.

**F6 — `.gitignore` accretion instead of generalization.** `.gitignore:24-39` enumerates **13 individual `.db` filenames** (`oida_fuzz_session.db`, `fuzzer_session.db`, `http_cli_test.db`, `modbus_crash_test.db`, `modbus_rtu_broadcast_test.db`, `modbus_unit_id_test.db`, `test_fuzz_session.db`, `/cve*.db`, `/killtest*.db`, `/rd_rd*.db`, `/spd*.db`, `/spd2*.db`) instead of one `*.db` rule — and still misses `ftp_t.db`. The "add a special case rather than refactor the rule" signature, applied to config.

**F7 — 1,864 blind-except sites (ruff `BLE001`).** The single most common AI code smell in the literature, and OIDA's single most common lint hit. Impact analysis in §2.

**F8 — Complexity distribution:** 737 `C901` complex-structure, 500 `PLR0912` too-many-branches, 370 `PLR0915` too-many-statements. **466 functions >100 lines; 143 functions >200 lines.**

**F9 — 24% of `src/` (81,147 lines) is inline literal data tables, while the documented data layer sits nearly empty.** `CLAUDE.md:178` documents `src/oida/data/` as "Protocol-specific data files (JSON, CSV)" — it holds one 3.6 KB JSON file and three small dirs. Meanwhile `fuzz/protocols/snmpv3.py` carries 12,216 lines of inline data, `utils/vendor_maps.py` 7,592, `snmpv2.py` 5,368, `snmpv1.py` 4,426, `opcua.py` 4,406. Data was generated as Python because Python was what was being generated.

**F10 — `src/oida/utils/vendor_maps.py`: 7,633 lines, provenance stamped 2023-11.** Lines 1, 1742, 1792, 7404 all read `# Update 06.11.2023 from …wireshark…packet-cip.c` / `Last update 2023-11, ethercat.org`. Vendor-ID tables ~2.5 years stale at time of audit, with the refresh procedure preserved only as a shell one-liner in a comment (`:1793`).

---

## 2. Broad exception handling (F11–F22)

The literature's #1 smell. These are the cases where swallowing changes the *answer*, not just the style.

**F11 — CRITICAL: S7 brute-force reports "no weak password" when the connection dies.** `src/oida/protocols/snap7/mixins/security.py:249-253`. `except Exception: continue` wraps `set_session_password()` + `get_cpu_state()`; success is defined as "nothing raised". If the session drops at attempt 50 of 500, every remaining attempt raises and is counted as a wrong password → tool prints "Password not found". Because `AttributeError`/`TypeError` are caught too, a renamed snap7 API would make **every target report secure, forever**.

**F12 — CRITICAL: null-password check is a permanent no-op on any error.** `src/oida/protocols/snap7/mixins/security.py:300-302`. Same shape; `vulnerable` stays `False` and the only trace is a debug line reading "Empty password rejected". A genuinely unauthenticated PLC with one transient read error is reported clean.

**F13 — CRITICAL: TLS certificate audit silently skips its own checks.** `src/oida/protocols/bacnet/sc_tls.py:198-199, 210-211, 234-235`. Weak-RSA, weak-EC-curve, weak-signature-algorithm and SAN checks each end in `except Exception: pass` — **no logging at all**. A device presenting an RSA-1024 or SHA-1-signed operational cert is reported clean if `cert.public_key()` raises on an edge-case cert.

**F14 — HIGH: 120 `except BaseException` sites across 9 async BACnet files defeat Ctrl-C and asyncio cancellation.** e.g. `src/oida/protocols/bacnet/mixins/properties.py:289-291, 314-316`. Catching `BaseException` swallows `KeyboardInterrupt`, `SystemExit` and `CancelledError`, then `continue`s — so an operator's Ctrl-C or an outer `wait_for` timeout is absorbed and the sweep keeps hammering the device. **These evade ruff `E722` precisely because they name `BaseException` rather than using a bare `except:` (E722 is clean repo-wide).**

**F15 — HIGH: `dtls_supports()` returns `True` on failure.** `src/oida/protocols/coap/helpers.py:487-488`. The function exists to detect an unsupported DTLS auth mode *before* touching the filesystem; its fallback is `except Exception: return True`, producing exactly the deferred-failure the docstring claims to prevent.

**F16 — HIGH: OCPP auth probe cannot distinguish a bug from a rejection.** `src/oida/protocols/ocpp/scanner.py:364-366` — `except Exception: loop.close(); return None`, and `None` is the "no usable connection" sentinel.

**F17 — OPC UA "auditing disabled" finding is silently droppable.** `src/oida/protocols/opcua/mixins/security.py:54, 79, 89-90, 161`. The finding at `:46` only fires if the node read *succeeds and returns False*; any read error is debug-logged and the check vanishes.

**F18 — Fuzz timeout calibration silently trains on an empty sample.** `src/oida/fuzz/core/calibration.py:164-165` — `except Exception: return None` excludes every probe error from the RTT set, so a consistently-raising probe yields zero samples and the crash-detection baseline is calibrated on nothing.

**F19 — TCP data-offset silently computed from a wrong options size.** `src/oida/fuzz/primitives/tcp_data_offset.py:96-98` — `except Exception: return 0` ("assume no options") makes every packet in that run malformed in a way the fuzzer did not intend, invalidating the fuzz cases without an error.

**F20 — CAN OBD-II scan conflates "bus down" with "no PIDs supported".** `src/oida/protocols/can/nxc_connection.py:341-344` and `src/oida/protocols/can/mixins/isotp.py:146-149` — `except Exception: continue` around `bus.recv()` busy-spins to the deadline and reports zero supported PIDs.

**F21 — BACnet/SC frame decode failures are indistinguishable from an unreachable device.** `src/oida/protocols/bacnet/sc_link.py:80-81` — a systematic `LPCI.decode` bug drops every response frame and the scan reports "no data".

**F22 — Harvested credential hashes can be written incomplete, silently.** `src/oida/protocols/pcap/scanner.py:843-844` — broad `except Exception` at debug level around `_fill_routing_salts` leaves `net_salt` unset; `_export_hashcat` then writes uncrackable hashes with no operator warning.

*Correct-pattern reference to preserve:* `src/oida/protocols/opcua/mixins/security.py:429-491` classifies exception codes and defaults to `status="inconclusive"` rather than "clean" — the inverse of F11–F13.

---

## 3. Dead scaffolding and placeholder code (F23–F37)

All verified with `grep -rn "\bNAME\b" src tests | grep -v "def NAME"` → 0 hits, after ruling out dynamic loading.

**F23 — `MMSCodec`: 18 of 32 methods dead.** `src/oida/fuzz/core/codecs/mms.py:93`. Dead: `build_confirmed_response` (:137), `build_initiate_response` (:254), `build_conclude_request` (:317), `build_status_request` (:345), `build_information_report` (:485), `build_file_open_request` (:516), `build_file_read_request` (:543), `build_file_close_request` (:558), `build_file_directory_request` (:573), and 9 `build_mms_*` primitives (:613–:715). The class *is* live (`tase2.py:140`, `monitors/industrial.py:440`) — an entire MMS file-services surface was written and never wired to a request definition.

**F24 — `OPCUACodec`: the whole decoder half is dead.** `src/oida/fuzz/core/codecs/opcua.py:106`. 17 methods incl. `decode_boolean` (:231), `decode_byte`, `decode_uint16`, `decode_int32`, `decode_uint32`, `decode_uint64`, `decode_node_id` (:330), plus `encode_sbyte`/`byte`/`boolean`/`float`/`double`/`datetime`, `encode_array` (:483), `encode_uint32_array` (:497), `encode_string_array` (:504). Nothing ever parses an OPC UA response with it.

**F25 — 100 lines of "pattern demonstration" shipped inside a protocol fuzzer.** `src/oida/fuzz/protocols/iec104.py:1204-1300`: `get_next_send_sequence`, `update_recv_sequence_from_response`, `store_interrogation_response`, `get_sequence_info`, `reset_protocol_state`. The only references to four of them are **inside their own docstring `Example:` blocks** (`:1216, :1234, :1257, :1295`); `get_sequence_info` has zero. Self-labelled *"These methods demonstrate the StateContext integration pattern that other protocols can adopt."*

**F26 — `ASN1Builder`: 9 dead builders.** `src/oida/fuzz/core/codecs/asn1.py` — `build_enumerated` (:241), `build_ia5_string` (:335), `build_generalized_time` (:343), `build_utc_time` (:355), `build_set` (:384), `build_application` (:418), `build_indefinite_length` (:533), `build_mms_invoke_id` (:577), `build_mms_object_name` (:581).

**F27 — A feature flag that controls nothing.** `src/oida/fuzz/core/codecs/asn1.py:70,72,74`. `grep -rn "_fuzz_mode" src tests` returns exactly three lines: the initialiser, the public setter `enable_fuzz_mode`, and the setter's write. The attribute is **written twice and never read**; the setter is never called.

**F28 — HTTP state-confusion attack feature never invoked.** `src/oida/fuzz/protocols/http_protocol.py:2821` `test_invalid_state_transitions` (~60 lines, drives an `invalid_tests` table via `enable_invalid_state_testing()`), plus sibling `send_request` (:2779). Zero non-def refs.

**F29 — Carved files are never written to disk.** `src/oida/shared/file_carving_common.py:278` `save_files` (and `:313` `get_files_by_type`) — the only method that persists carved bytes, never called. `FileCarvingMixin` *is* live (`discovery/file_carving.py:82`, `pcap/file_carving.py:23`), so files are carved into `self.files` in memory and discarded; the CLI's `--extract-dir` path (`protocols/pcap/scanner.py:941`) uses tshark `--export-objects` instead.

**F30 — Dead credential exporter.** `src/oida/pcap/ntlm.py:710` `get_john_hashes`. The live `--hashcat` path reads `cred.hashcat_format` (`protocols/pcap/scanner.py:749`).

**F31 — `class MQTTPacketTypes` is entirely unconsumed.** `src/oida/fuzz/protocols/mqtt.py:70` — 20 constants; `grep -rn "MQTTPacketTypes" src tests` → 1 hit, the `class` line. The fuzzer hardcodes its own byte values.

**F32 — Full 4-step OSI handshake helper unreachable.** `src/oida/fuzz/protocols/mms.py:846` `setup_osi_connection` (COTP CR → Session CONNECT → Presentation CP → ACSE AARQ). Siblings `_create_reject_pdu` / `_wrap_with_osi_stack` are test-covered; this one is not reachable.

**F33 — Dead pcap listener accessors.** `src/oida/pcap/enip.py:801` `get_read_operations`, `opcda.py:752` `get_browse_operations`, `opensafety.py:685` `get_nodes_summary`, `sercos.py:455` `get_slaves_summary`.

**F34 — Dead protocol frame builders.** `src/oida/fuzz/protocols/ethercat.py:227` `_mailbox`; `src/oida/fuzz/protocols/ethernetip.py:344` `_create_encap_header` (returns a boofuzz `Block` for the 24-byte EtherNet/IP encapsulation header that no request definition uses).

**F35 — An argparse validator no `add_argument` uses.** `src/oida/utils/cli.py:34` `valid_range` (`'0-100'` format).

**F36 — Dead formatting helpers.** `src/oida/utils/protocol_helpers.py:279` `format_bytes`, `:288` `format_duration`.

**F37 — A dead dataclass field, via its only consumer.** `src/oida/protocols/bacnet/service_catalog.py:284` `callable_services()` filters `SERVICES` on the `callable` field and is never called — so `ServiceSpec.callable` has no consumer at all. Also `src/oida/protocols/tase2/mixins/info_messages.py:238` `get_im_transfer_attributes` (documented IEC 60870-6-503 accessor, 0 refs).

---

## 4. Duplication and DRY collapse (F38–F52) — ~12,000 duplicated lines

Exact-clone detection found only 5 clusters; **structural** clone detection (identifiers → positional placeholders) plus fuzzy clustering found the rest. That gap *is* the AI signature: copy-paste-then-rename, which exact hashing misses.

**F38 — `_update_devices` device-record building: 43 copies, ~2,015 lines — and the base class already supports it.** `src/oida/pcap/modbus.py:769-808`, `enip.py:693-735`, `ads.py:813`, `hartip.py:936`, `amqp.py:477`. `PySharkListenerBase._ensure_device()` (`src/oida/pcap/pyshark_base.py:1056`) **already takes `data_attr=`/`protocol_data=` for exactly this** — but only **22 of 179** call sites use them; **136** assign `device.X_passive_data = …` manually afterward.

**F39 — An entire credential subsystem re-implemented per protocol: ~2,500 lines.** `get_credentials_summary` (41 defs/781 L), `_record_credential` (13/432 L), `_is_duplicate*` (19/190 L), 36 `*Credential` dataclasses of which 16 share the identical core field set (336 L), `hashcat_format` (17/329 L), `get_hashcat_hashes` (15/152 L), 94 trivial passthrough properties (302 L). No shared credential record type exists anywhere.

**F40 — Four byte-identical `_is_duplicate` bodies (same MD5).** `src/oida/pcap/socks.py:426`, `tacacs.py:445`, `pap.py:209`, `rdp.py:177`. Plus **67 inline `for cred in self.credentials:` linear scans across 31 files** — making credential recording O(n²) on large captures.

**F41 — 21 broadcast-probe discovery scanners, ~1,070 of 1,123 lines duplicated, with no base class at all.** `create_udp_socket → get_all_broadcast_addresses → sendto loop → timed recvfrom → seen_ips dedup → _parse_response → finally close`, differing **only in the log-prefix string**. `src/oida/protocols/discovery/infra.py:72-121` (HID) vs `:219-268` (MSSQL) differ by `"HID:"`→`"MSSQL:"`. Also `:386-442`, `:552-601`, `cameras.py:118-165`, `av.py:78-111`, `netgear.py:84-119`, `ics.py`, `vendor.py`, `energy.py`. A `UDPBroadcastProbeScanner(PORT, DISCOVERY_PROBE, PROTOCOL_NAME)` with `_parse_response()` as the only hook removes ~1,000 lines.

**F42 — `DiscoveredDevice` god-dataclass: 96 fields, 80 identically typed.** `src/oida/protocols/discovery/core.py:1200-1606`. 80 fields are `Optional[Dict[str, Any]]`; 28 are named `*_passive_data` (86 such names repo-wide). Every new listener edits this central file — which is what drives F38's 136 manual assignments. Should be one `passive_data: Dict[str, Dict[str, Any]]` keyed by protocol.

**F43 — 11 discovery listeners copy the base class instead of inheriting it, and the copy *undid* the parameterization.** `PassiveListenerBase` exists at `src/oida/protocols/discovery/base.py:26`. Diffing `base.py:94-115` against `ntp.py:123-146` and `dhcpv6.py:105-128` shows the copies are the base body with `f"{self.PROTOCOL_NAME}: …"` replaced by a hardcoded `"NTP: …"` / `"DHCPv6: …"`. Non-adopters: `dhcp.py:56`, `dhcpv6.py:75`, `lldp.py:912`, `arp.py:239`, `arp.py:364`, `mdns.py:376`, `ntp.py:86`, `network.py:241/713/1151`, `vrrp.py:34`.

**F44 — `PROTOCOL_CATEGORIES` duplicated byte-identically inside the same directory.** `src/oida/fuzz/protocols/__init__.py:125-219` vs `src/oida/fuzz/protocols/_metadata.py:8-102` — 95 lines, verified identical. `_metadata.py`'s own docstring says *"import this instead of the full protocols package"*; `__init__.py` never imports it, it redefines the dict. One-line fix.

**F45 — `FILE_SIGNATURES` duplicated, drifted, and one copy kept a bug.** `src/oida/protocols/discovery/file_carving.py:33-79` vs `src/oida/pcap/file_carving.py:39-88`. Same 7 keys, but the pcap copy has fixes the discovery copy lacks: `min_size: 800` on GIF87a and the "anchor GIF trailer on preceding block terminator" correction. Both files already import from `src/oida/shared/file_carving_common.py` — whose docstring at `:8` explicitly institutionalizes the fork: *"Each consumer defines its own FILE_SIGNATURES dict."* **Strongest case in the report: shared module present, table deliberately excluded, copies diverged, one retained a defect.**

**F46 — The `shared/*_constants.py` pattern exists for 5 protocols and EIGRP was left out.** `src/oida/shared/` holds `glbp_/hsrp_/igmp_/ospf_/pim_constants.py`, each imported by both the pcap and discovery side. EIGRP has the identical pair shape but no shared module — `EIGRP_OPCODES` at `discovery/eigrp_passive.py:31-39` and `pcap/eigrp.py:70-78` verified identical by diff.

**F47 — More same-name constant tables duplicated across modules (~496 lines, 22 tables).** `LINK_FUNC_PRI_TO_SEC`/`SEC_TO_PRI`: `pcap/iec101.py:64` vs `iec103.py:147` — *while `src/oida/pcap/_iec_common.py` already exists and is imported by both*. `EXCEPTION_CODES`: `protocols/modbus/constants.py:196` vs `fuzz/protocols/modbus/constants.py:274`. `CANOPEN_FUNCTION_CODES`/`SDO_ABORT_CODES`: `protocols/can/constants.py:699,805` vs `pcap/canopen.py:77,134`. `ADS_UDP_TAG`: `protocols/ads/constants.py:437` vs `discovery/ics.py:773`.

**F48 — 24 `_create_socket` overrides that exist only to supply a default port.** `src/oida/fuzz/protocols/daytime.py:79-92`, `echo.py:94-107`, `knx.py:120-127`, `netbios.py:108-116`, `dns.py:19-27`, `tftp.py:76-85`, `astm.py:138`, `can.py:117`, `hl7.py:302`, `ethernetip.py:231`. `BaseFuzzer._create_socket` (`fuzz/core/base_fuzzer.py:816`) already delegates to a factory that branches on TCP/UDP/SSL/RAW/ICMP/Serial — it just lacks `DEFAULT_PORT`/`DEFAULT_RECV_TIMEOUT` class attrs.

**F49 — ASN.1 BER encoding duplicated three ways, including a subclass reimplementing its own parent.** `ASN1Builder.encode_length`/`build_integer` (`fuzz/core/codecs/asn1.py:79-115, :179-217`) reappear as free functions in `fuzz/primitives/asn1_blocks.py:65-84, :124-148`; then `MMSCodec`, which **inherits** `ASN1Builder`, reimplements integer packing a third time at `fuzz/core/codecs/mms.py:732-755`. The codec layer — the thing that exists to be a single source of truth — duplicated with itself.

**F50 — Session get-or-create: 18 named methods + 21 inline sites, ~233 lines, zero base support.** 7-member exact structural clone: `pcap/hartip.py:643-656`, `knx.py:624-639`, `iec101.py:214-229`, `iec104.py:493-508`, `iec103.py:343-358`, `profinet.py:1048-1063`, `synchrophasor.py:302-317`. Plus `_get_session` in `ftp.py:217`, `smtp.py:555`, `imap.py:483`, `telnet.py:558`. `grep session src/oida/pcap/pyshark_base.py` returns nothing.

**F51 — `_get_ek_layer_dicts`: 7-member exact structural clone of pure PyShark plumbing.** `pcap/modbus.py:228-243`, `knx.py:472-485`, `mysql.py:1082-1097`, `iec104.py:980-994`. Bodies differ only in the protocol name inside a debug string; even the docstrings were copy-edited. Zero protocol specificity.

**F52 — 17 `cleanup()` overrides where the base already implements it.** `connection.cleanup()` (`src/oida/connection.py:294-309`) already does close/disconnect + debug log; the only delta is routing through `self.scanner.disconnect`. `protocols/modbus/nxc_connection.py:966-975`, `mqtt/…:390-399`, `ethercat/…:99-108`, `ads/…:2437-2443`, `hart/…:873-880`. Same shape: `_get_interface_mac` has 5 near-identical `fcntl.ioctl(0x8927)` copies (`fuzz/protocols/goose.py:160`, `pppoe.py:161`, `ethernet.py:187`, `ethercat.py:153`) — `goose.py` even carries the comment `# Ethernet / MAC helpers (mirrors ethernet.py)`. `src/oida/utils/iface_info.py` already exists.

**Also: 6 verbatim `harvest()` alert-merge copies** (`pcap/c1222.py:760-769`, `mqtt.py:686-695`, `opensafety.py:674-683`, `cipsafety.py:855-864`, `coap.py`, `eigrp.py`) — base `harvest()` has no `_alerts` hook.

---

## 5. Test-suite inflation (F53–F67)

21,715 collected tests across 629 files, 290,889 LOC — a 0.86 test:source LOC ratio. Volume is not assurance.

**F53 — 128 modbus "scanner" tests execute zero production code.** Representative: `tests/unit/modbus/test_scanner_registers.py:431 test_gateway_path_unavailable_exception` sets `mock_client.read_holding_registers.return_value = error_response`, **discards** the constructed scanner, then calls the *mock* and asserts it returns what it was just told to return — `assert 10 == 10` with extra steps. Spread: `test_scanner_writes.py` (28), `test_scanner_advanced_fc.py` (25), `test_scanner_diagnostics.py` (24), `test_scanner_registers.py` (24), `test_scanner_identification.py` (23). **Not one of the 128 has an assertion that touches a scanner object.** These files are the bulk of modbus unit coverage and they validate `unittest.mock`.

**F54 — The "Category A (strict)" test taxonomy is fiction in the two largest integration files.** `tests/integration/test_dnp3_integration.py:42` declares *"Category A (strict — assert success + validate data): 23 tests"*, but 15 `[Category A]`-tagged tests assert **only** `result.success`: `:369, :412, :431, :1330, :1351, :1373`. Same at `tests/integration/test_hl7_integration.py:42` (claims 60 strict): `:424, :445, :489, :935`. `test_read_variation_counter` passes if the scanner never read a counter. **63 tests suite-wide assert nothing but a CLI exit code.**

**F55 — `assert True  # Finding confirmed`.** `tests/integration/test_opcua_integration.py:1024`, inside `test_security_finding_no_rbac_insecure`. The RBAC check is a literal no-op; the only live assertion accepts any of `"rbac"`/`"role"`/`"auth method"` appearing in output — it passes on the *label* being printed.

**F56 — A green test run on a broken mock.** `tests/integration/test_hart_mock.py:146 test_tcp_connect` is `sock.connect(...)` + `assert True`; the module's autouse fixture `is_mock_running()` (`:53`) is `except Exception: return False`, so any error silently skips the whole module.

**F57 — A fuzz test that passes on every realistic failure.** `tests/integration/fuzz/test_definition_execution.py:113-126`: `FuzzTimeout → pass`, `ConnectionError/OSError → pass`, `ImportError → skip`, `"No requests specified" → skip`. It asserts "does not crash in a novel way", not "the definition executes". 5 tests in the file have no assertion at all.

**F58 — 24 permanently-skipped tests with `pass` bodies — pure count inflation.** `tests/integration/test_dnp3_integration.py:1633-1667` (7), `test_can_integration.py:2005-2020` (4), `test_astm_integration.py:2267-2277` (3), `test_iec104_integration.py:1236-1246` (3), `test_snmp_integration.py:4033-4061` (3), `test_fhir_integration.py:984-998` (2), `test_ads_integration.py:2139` (1). Each is `@pytest.mark.skip` + docstring + `pass` — no test code that could ever be un-skipped.

**F59 — 12 tests whose assertion was written as an English comment.** `tests/unit/astm/test_astm_scanner.py:956 test_proto_flow_basic` ends `scanner.proto_flow()` / `# Should have called enum_host_info path`. Also `:969` (`# Should return early, no data`), `:519`, `:551`, and four `print_host_info()` tests at `:1059-1086` each ending `# Should not raise`. `proto_flow` could return immediately and all 12 pass.

**F60 — 23 identical copy-pasted fuzzer tests under 8 different names.** Same 2-statement body `connected = _connected_names(_build(_make_config(enabled_requests=[name]))); assert connected == {name}` across `tests/unit/fuzz/test_profinet_fuzzer.py:115`, `test_ads_discovery.py:92`, `test_ethercat_fuzzer.py:100`, `test_netbios_fuzzer.py:88`, `test_ipv4_request_gating.py:84`, `test_hart_ip_fuzzer.py:92`, `test_bacnet_truncation.py:97`, `test_eip_forward_close.py:98` + 15 more. One `@parametrize` covers it.

**F61 — Whole files duplicated between `tests/unit/` and `tests/integration/`.** `test_http_custom_headers.py` exists in both with byte-identical bodies (`:72/:69`, `:136/:133`, `:348/:345`) — neither touches a network, so the "integration" copy is a mislabelled duplicate. Also `test_mms_fuzzer_integration.py:672` vs `:604`, and `tests/unit/astm/test_scanner.py:399` vs `tests/integration/test_astm_integration.py:2170`. **298 test functions are byte-identical bodies in 133 groups; 209 cross-file; 89 groups span directories.**

**F62 — A change-detector test that re-types its own constants.** `tests/unit/fuzz/test_mms_fuzzer_integration.py:672 test_pdu_types`: `assert MMSFuzzer.PDU_CONFIRMED_REQUEST == 160`, `== 161`, `== 162` … 8 asserts restating the source file. Duplicated in the integration copy for 16 total.

**F63 — 153 test functions contain zero assertions of any kind** (no `assert`, no `self.assert*`, no `pytest.raises`); **24 have a body that is literally `pass`**; **870 tests' every assertion is weak** (`isinstance` / `is not None` / bare truthiness).

**F64 — 15 zero-assertion "validation passes" tests.** `tests/unit/dnp3/test_scanner.py:620, :636, :968, :976, :984, :1124, :1132, :1617` — each `validate_args(args)` + `# Should not raise`. `test_ao_value_accepts_float` passes even if the float is silently discarded or coerced to 0. Same shape at `tests/unit/ads/test_proto_args_confirm.py:61,70,74,78,83`.

**F65 — 341 test functions can silently skip themselves; the fuzz state-machine suite is effectively optional.** `tests/integration/fuzz/test_state_machine_real.py` (38 skip paths), `test_state_traversal.py` (37), `tests/unit/fuzz/test_state_coverage.py` (21), `test_state_machine_reachability.py` (20), `test_docker_modbus.py` (18). The gate is `PROTOCOL_FUZZERS.get(name) → None → pytest.skip` (**168 occurrences**) plus 105 `importorskip`. A protocol dropping out of the registry — the exact regression these tests exist to catch — converts them to skips, not failures. **538 `pytest.skip()` calls total.**

**F66 — A test that skips on the failure it exists to detect.** `tests/unit/test_import_resolution.py:270` guards against dead internal imports; its fallback `importlib.import_module(target)` is wrapped in `except Exception: pytest.skip(...)`. A module that fails to import — strictly worse than the bug being hunted — yields a skip. (This one file also generates **1,085 of the 21,715 collected tests**, 5% of the suite.)

**F67 — Conditionally-disabled content assertions in the pcap harness.** `tests/integration/pcap/conftest.py:275`: `if expect_details and listener.interactions:` no-ops the field-extraction check when nothing parsed. **39 call sites pass `min_interactions=0` and 155 pass `min_devices=0`**, dropping those to `assert isinstance(devices, dict)`. `tests/integration/pcap/test_smb_passive.py:80 test_credslayer_smb_ntlm` never checks the credential-extraction path it is named for. Related: `tests/integration/fuzz/test_state_traversal.py:38-42` catches `StateTransitionError` at construction — in a file whose stated purpose is verifying state traversal.

---

## 6. Comprehension debt / documentation drift (F68–F79)

Root cause: a doc-purge (commits `158ae5e`, `b058340`, `b611684`, `6276fb5`, "content now at getoida.dev") deleted the developer docs but left every cross-reference pointing at them.

**F68 — README's first usage example is a broken command.** `README.md:41` `oida modbus 10.0.0.0/24 -t 20` → `oida modbus: error: unrecognized arguments: -t 20`. `-t`/`-o` are *global* flags parsed only **before** the subcommand; every doc example places them after the target. This is the literal first copy-paste a new user runs.

**F69 — `CLAUDE.md`'s Documentation Map is a map to deleted files.** Of 15 rows at `CLAUDE.md:246-262`, **10 targets do not exist**: `docs/ARCHITECTURE.md`, `docs/new-protocol.md`, `STYLE_GUIDE.md`, `RELEASE_READINESS.md`, `RELEASE_TODO.md`, `TEST_REPORT.md`, `DISCLAIMER.md`, `docs/REAL_COVERAGE_PROPOSAL.md`, `ref/<proto>/`, `ref/_FUZZER_OPTIMIZATIONS_TODO.md`.

**F70 — The body text still cites those deleted docs as authority.** `CLAUDE.md:232` "See `docs/ARCHITECTURE.md` for the facade pattern"; `:234` "See `STYLE_GUIDE.md`"; `:249-250, :253`.

**F71 — Two of three protocol-flag examples are wrong.** `CLAUDE.md:113` `--browse` → `error: unrecognized arguments` (the flag is `--dump`). `CLAUDE.md:104-105` `-o results` → `error: unrecognized arguments` (`--output` works; short `-o` does not, post-subcommand).

**F72 — `src/oida/configs/` is documented but absent.** `CLAUDE.md:177` claims "YAML configuration files"; no such directory exists.

**F73 — The one cited "specific test module" path does not exist.** `CLAUDE.md:21` `pytest tests/unit/test_modbus_scanner.py` → `No such file`. There are no flat `tests/unit/*.py` modules of that name.

**F74 — The "Key test files" list names four files that exist nowhere.** `CLAUDE.md:189-194`: `test_standalone_types.py`, `test_security_analysis.py`, `test_integration.py`, `test_mock_servers.py` — `find` returns empty for all four.

**F75 — "25+ test files" understates by ~24×.** `CLAUDE.md:182`; actual 630 `test_*.py` files.

**F76 — README's PyPI badge points at a different distribution than the install command.** `README.md:13` links `pypi.org/project/oida-ics/`; `pyproject.toml:6` is `name = "oida"` and `README.md:29` installs `oida[all]`.

**F77 — CHANGELOG version ahead of the code.** `CHANGELOG.md:7` `## 1.0.0 — unreleased` vs `src/oida/__init__.py:22 __version__ = "0.9.9"` (latest tag `v0.9.9-rc9`).

**F78 — The security-disclosure channel is described wrong.** `CLAUDE.md:258` calls `SECURITY.md` a "Private vulnerability disclosure **email**"; `SECURITY.md:9` routes to a web form (`https://getoida.dev/contact`) with no email.

**F79 — The commit-msg hook description is inaccurate.** `CLAUDE.md:239` describes a literal-string matcher; the actual hook is a script, `.githooks/no-ai-coauthor` (id `no-ai-coauthor`). Load-bearing instruction, so worth correcting.

*Correctly-maintained counts — do not "fix":* `CLAUDE.md:151` "26 protocols" matches `ProtocolLoader.get_protocols()` exactly, and `:161` "109 listeners" matches `len(LISTENER_REGISTRY)` exactly. These two are the only numeric claims that are true. Doc volume itself is modest (42 tracked `.md`, 8,259 lines) — **the debt is that the map drifted faster than the territory, not that there is too much of it.**

---

## 7. Real latent bugs from AI-code-specific classes (F80–F86)

**F80 — "Reset to balanced" is a one-way downgrade; fuzz coverage silently collapses.** `src/oida/fuzz/primitives/reduced_string.py:161-164`. `set_reduction_level("aggressive")` writes into `ReducedString.__dict__` (`:138-155`); the `"balanced"` branch then "restores" by reading the already-overwritten value. Verified live: `balanced initial: 27 → after aggressive: 10 → back to balanced: 10`, while `reduction_level` reports `"balanced"`. Any process fuzzing protocol A aggressively then B at balanced runs B on the 10-entry library while logging "balanced (507 mutations)". **This is the only one of 110 `RUF012` hits that is actually mutated.**

**F81 — `--seed` reproducibility is dead.** `src/oida/utils/fuzzer.py:26` sets `_random_seeded = False` and **that is the only write in the tree** (2 occurrences total). `_generate_random_bytes()` (`:112`) branches on it: `True` → deterministic, `else` → `os.urandom`. `fuzz/core/base_fuzzer.py:155-156` calls `random.seed(config.seed)` + `set_mutation_seed()` but never flips the flag. `oida fuzz --seed 1234` twice produces different payloads; **a crash found in run 1 is not replayable in run 2.**

**F82 — `time.sleep()` inside the shared lock serializes every threaded scan.** `src/oida/utils/rate_limiter.py:60-66` sleeps in the critical section of a process-global `RateLimiter`. With `-t 20 --rate 1`, all 20 workers block on a mutex held for a full second — the thread pool degenerates to strictly serial and workers cannot progress on unrelated I/O.

**F83 — Unsynchronised lazy singleton, and the codebase's own correct idiom sits two files away.** `src/oida/utils/fuzzer.py:98` initialises `_radamsa` with no lock and no double-check. `src/oida/utils/ics_logger.py:895-901` does the same job correctly with `_mac_parser_lock` + double-checked `if … is None`. Under `-t N`, two threads each build a `NativeRadamsaMutator`, one is discarded, and the survivor's RNG state is driven concurrently — compounding F81.

**F84 — An unhashable dataclass, protected by a project-wide lint ignore whose stated rationale doesn't apply.** `src/oida/protocols/snap7/models.py:26-28, :55`: `@dataclass` + hand-written `__eq__` ⇒ `__hash__ = None`. Verified: `{S7FirmwareVersion(4,1,3)}` → `TypeError: unhashable type`. `pyproject.toml` ignores `PLW1641` globally with the comment *"Construct adapter pattern"* — but the single real hit is a plain snap7 dataclass, not a Construct adapter. Latent: only `snap7/mixins/device_info.py:142` constructs these today.

**F85 — U+00A0 NO-BREAK SPACE embedded in OUI vendor-name *data*.** `src/oida/utils/vendor_maps.py:7167, 7205, 7209` — `"Trafag AG \xa0sensors & controls"`, `"AtomHorizon\xa0 Electric (JINAN) Co., LTD"`, `"Shenzhen\xa0 Megmeet\xa0 Drive Technology Co., Ltd."` (confirmed via `cat -A` → `M-BM-`). These are lookup **values**, not console text: any exact-match, `--filter-vendor`, or CSV/JSON consumer comparing against the normal-space spelling silently misses.

**F86 — A dead registry entry wiring a PROFINET name to an SSDP scanner.** `src/oida/protocols/discovery/scanner.py:124-129`: `"dcp-listen"` maps to `SSDPScanner` with the trailing comment `# Placeholder`. Not reachable at runtime (`enable_dcp` dispatches to `self._run_dcp_active` at `:882`) — it exists **solely** so a category lookup at `:973` resolves. `SSDPScanner` is registered under 3 unrelated keys (`ssdp-listen`, `dcp-listen`, `ssdp-search`). A trap for the next maintainer.

---

## 8. Convention divergence across siblings (F87–F94)

Each module was generated in isolation, so conventions drifted.

**F87 — The single largest behavioural divergence: three mutually exclusive device-enrichment conventions across 159 call sites in 109 listeners.**
- **91 sites** gate on `if is_new:` with **no `else`** → first-packet-wins, every later packet discarded (`pcap/bacnet.py:830`, `knx.py:666,686`, `profinet.py:1106,1132,1153`, `mms.py:1290,1307`, `iec104.py:1428`)
- **44 sites** gate with a proper `else` merge (`pcap/dhcp.py:471`, `kerberos.py:930`, `ipp.py:447`)
- **24 sites** write unconditionally (`pcap/dnp3.py:1165`, `ldap.py:1380`, `mssql.py:1495`)

`src/oida/pcap/modbus.py` uses two of the three **in the same method** (`:792`, `:806`). Failure: a Modbus PLC whose first observed packet is a truncated exception response is recorded as a stub and never corrected for the rest of a multi-hour capture — while the same capture under the other two conventions yields a complete record. Invisible to ruff.

**F88 — 275 raw `print(` calls in a tool with a full logging framework.** `fuzz_cli.py` 122, `serial_cli.py` 32, `cli.py` 13, `fuzz/core/base_fuzzer.py` 10, plus **85 across 52 of 111 pcap listeners** (58 at module scope in `display_*` helpers outside any `def`). Consequence: `--format json` / `-o` output interleaves with un-redirectable stdout, and `set_json_log_path()` (`ics_logger.py:75`) captures none of it.

**F89 — The documented logging convention has zero adopters.** 102/111 listeners use `self.logger`, 4 use `get_module_logger`, 7 use neither. The `log()` legacy facade and `proto_logger()` that `CLAUDE.md` names as the convention have **0 uses** in `src/oida/pcap/`. Repo-wide: `self.logger.` 7,360 · `self.log.` 464 · `logging.getLogger` 75 · `get_logger(` 53 · `proto_logger(` 13.

**F90 — The custom exception hierarchy is unused by 21 of 27 protocols.** `src/oida/utils/exceptions.py` defines 12 classes; 119 builtin raises vs 27 custom. `discovery` 26/0, `bacnet` 27/0, `knx` 17/0, `modbus` 15/1. Only `dnp3` (20/16) meaningfully uses it. **`except ProtocolError` in caller code catches nothing for 21 of 27 protocols.** Repo-wide: 185 `raise ValueError`, 19 `RuntimeError`, 8 vanilla `raise Exception`, 44 custom.

**F91 — `--timeout` defaults disagree by three orders of magnitude, including a units mismatch.** Only 7 of 26 `proto_args.py` define one: `dnp3` 0.5, `discovery` 3, `profinet` 3.0, `can` 5.0, `knx` 5.0, `goose` 10, `fhir` 30 — and `src/oida/protocols/ads/proto_args.py:105-109` uses `--ads-timeout default=500` in **milliseconds** while every sibling is seconds. A user carrying `-t 5` across protocols gets 5 s everywhere and 5 ms on ADS.

**F92 — Return-type annotation coverage ranges 23% → 96% across 26 protocol dirs.** `dicom` 9/39 (23%), `bacnet` 48/184 (26%), `ads` 36/133 (27%) vs `tase2` 46/48 (96%), `can` 95%, `ethercat` 85%. Directory aggregates: `pcap/` 92% vs `protocols/` 64%. `mypy src/oida/` cannot be promoted from informational to a CI gate without a bulk pass on ~1,000 functions.

**F93 — `__all__` convention followed in 22/26 protocol `__init__.py`, 1/112 pcap modules, 3/24 utils modules** — and where followed, 69 `RUF022` unsorted hits mean the ordering is per-module ad-hoc.

**F94 — 24 `# noqa` directives suppressing lint rules this project never enables (`RUF100`).** `F401` ×11 (`protocols/coap/__init__.py:20,32,42`, `dicom/__init__.py:43-45`), `F841` (`discovery/eigrp_passive.py:165`, `ospf_passive.py:144`, `iec104/serial.py:407`), `BLE001` (`hl7/segments.py:1504,1516`), `S324` (`pcap/radius.py:140`), `SIM115` (`can/nxc_connection.py:1086`), `PLE0704` (`fuzz/core/connections/tcp.py:342,348`), `F811` (`knx/helpers.py:72`). Suppressions written against an *imagined* lint config — the classic per-module isolated-generation signature, giving false confidence those lines were reviewed for those hazards.

Also: **F95 — deliberate homoglyph fuzz payloads carry no `# noqa: RUF001`** (`fuzz/primitives/smart_string.py:162-164, :283` — `"ＡＤＭＩＮ"`, Cyrillic `"аdmin"`, `"ɑdmin"`, `"еxample.com"`). The 45-hit RUF001/2/3 signal is therefore inverted: intentional payloads look like violations while the genuine data corruption in F85 is indistinguishable. Anyone bulk-`--fix`ing would destroy the payloads.

---

## 9. Packaging and dependency drift (F96–F101)

**F96 — HIGH: `pip install oida[fuzz]` produces a broken fuzzer.** `src/oida/fuzz/monitors/base.py:9` and `application.py:8` do an unconditional module-level `import urllib3`. urllib3 is **not** in the `fuzz` extra's transitive closure (verified: closure of `boofuzz, sqlalchemy, pyasn1, crc, h2, scapy, brotli, cryptography` = 30 packages, no urllib3). It reaches the dev venv only via `requests` (declared **only** under the `fhir` extra) or `docker` (dev). Empirically confirmed with a `find_spec` blocker: `import oida.fuzz.monitors.base` → `ModuleNotFoundError: No module named 'urllib3'`.

**F97 — `hpack` is imported unconditionally but never declared.** `src/oida/fuzz/protocols/http2.py:30`. It currently resolves only because `h2==4.3.0` happens to depend on it — the HTTP/2 fuzzer breaks silently if that transitive edge ever changes.

**F98 — MQTT SOCKS-proxy support is fiction three ways over.** `src/oida/protocols/mqtt/mixins/connection.py:88` does `import socks`. PySocks appears nowhere in `pyproject.toml` or `uv.lock` and is **not installed**. The branch is also unreachable — it gates on paho's `client._get_proxy()`, and OIDA never calls `proxy_set()` (`grep -rn proxy_set src/` → no hits), so it always returns `None`. And it reaches into a **protected member** of a third-party client (the 4.1%-prevalence AI smell). Dead code that would crash if it ever became live.

**F99 — `tqdm==4.67.3` is a mandatory core dependency with zero uses.** `grep -rn tqdm --include='*.py' src/ tests/` → **0 hits**; the only occurrence in the entire repo is `pyproject.toml:43`. Every user of every install downloads it.

**F100 — `astm = []` is an empty extra for a documented protocol.** `pip install oida[astm]` installs nothing, while `CLAUDE.md` lists astm among supported protocols with an extra.

**F101 — `boofuzz.__version__` does not exist; replay metadata is permanently `"unknown"`.** `src/oida/fuzz/core/session/manager.py:199`. Verified: `hasattr(boofuzz,'__version__')` → `False`; `[a for a in dir(boofuzz) if 'version' in a.lower()]` → `[]` on the exact pin 0.4.2. Wrapped in `except (ImportError, AttributeError)`, so it never crashes — it silently degrades the deterministic-replay validation the field exists to support, on every run. Fix: `importlib.metadata.version("boofuzz")`.

*Environment note (not a code defect):* the local `.venv` has `_pyiec61850.cpython-**310**.so` under Python 3.13, so `import pyiec61850` fails into stub MMS constants. `uv.lock` correctly lists cp313 wheels — re-run `uv sync --all-extras`.

---

## 10. Security (F102–F105) — the strongest area

Contrary to the research prior (4.7% of AI defects are security), **no accidental operator-facing vulnerability was found.** The predicted sinks are systematically defended, and centrally rather than ad-hoc.

**F102 — `verify=False` with no opt-in, unlike its sibling.** `src/oida/fuzz/monitors/application.py:98` disables TLS validation unconditionally in the liveness monitor. A MITM could feed forged "healthy" responses, masking the very crash being fuzzed for. `http2.py:239` honours a `verify_ssl` flag; this one has none. Add the flag for parity.

**F103 — Operator-side SSRF via SSDP `LOCATION`.** `src/oida/protocols/discovery/ssdp.py:194` `urlopen(location)` where `location` comes from a multicast reply. Scheme is restricted to http/https and the body capped at 1 MB, but the **host is not restricted to the responder** — a rogue LAN device can aim the tool at any internal endpoint. Documented in-code as an accepted trade-off (`:173-180`); flagged only because it is the single attacker-influenced outbound request in the tool.

**F104 — Bare `assert` guarding control flow.** `src/oida/fuzz/protocols/tcp.py:437` — vanishes under `python -O`.

**F105 — DES-ECB in the VNC fuzzer is correct, not a defect.** `src/oida/fuzz/protocols/vnc.py:532` — RFC 6143 §7.2.2 mandates it; documented in-code. Listed so the `S305` hit is not "fixed" by someone later.

**Verified clean:** path traversal on carved/extracted files is closed by `safe_output_path`/`safe_file_path` (`utils/common_types.py:50-106`: basename strip, `..` block, `realpath` + `startswith(base+os.sep)` — symlink-safe), used by all 11 device-file writers incl. `discovery/file_extraction.py:86,96`. XXE closed by `defusedxml` hard-imports (`ssdp.py:205,324`, `cameras.py:184`, `profinet/gsdml_parser.py:161`); the two `minidom` hits parse XML the tool generated itself. No unsafe deserialization (both `yaml` calls are `safe_load`; no `pickle`/`eval`/`exec` on untrusted data). No command injection (all `subprocess.run` use list-form args with `shutil.which`-resolved binaries; `fuzz/core/session/commands.py:20` explicitly raises on `shell=True`). All 33 `S311` randoms are transaction IDs, ephemeral ports, or fuzz payloads. All 24 `S105/106/107` "hardcoded passwords" are field names and regex constants.

---

## 11. Verified-clean — do not re-flag

Recorded so future passes don't re-litigate these.

- **Hallucinated APIs: 1 finding (F101) in 13,139 introspected call sites.** Live `inspect.signature` verification of every constructor/function call's kwargs and arity, plus `hasattr` resolution of every `from lib import X` and `lib.attr`, scapy `fields_desc` field names, and `lazy_import` proxy surfaces — **all clean**. Detectors were validated against 5 planted canaries (bad kwarg, `unit=` on `read_holding_registers`, fake method, fake module attr, bad scapy field); all 5 caught. Cause: every pyproject pin is `==`-exact and matches installed versions, and the version-churn hot spots are handled deliberately (`protocols/modbus/scanner.py:105-119` has a real pymodbus 2.x/3.x shim). *Caveat: the 109 pcap listeners access pyshark fields dynamically (`pkt.layer.field`) — unverifiable without a real-capture corpus.*
- **`PLW2901` (69 hits): 0 real bugs.** All are `for x in …: x = x.strip()` consumed in the same iteration.
- **`RUF013` implicit-Optional (72 hits): 0 real NPE risks.** Every one is guarded before use. Mechanically fixable, zero behaviour change.
- **`RUF012` mutable-class-default (110 hits): 109 are read-only constant tables.** Only F80 mutates. The one real consumer of `PROTOCOL_OPTIONS` (`fuzz/core/base_fuzzer.py:650-651`) copies to a local before `.update()`.
  → **~251 of 261 hits across these three "bug-shaped" rules are pure style.** The predicted shadowing/implicit-Optional pathologies do not manifest; what *did* manifest is class-state mutation, dead flags, and unsynchronised singletons.
- **`ruff F841` (assigned-never-read) and an AST unreachable-code sweep: both clean.** Dead-write and unreachable-code categories are essentially absent.
- **`proto_args.py` across all 26 protocols (9,756 L): zero duplicated `add_argument` blocks** — all 26 use `utils/proto_args_factory.py`. The one area where the shared-abstraction pattern was applied consistently, and proof the clone detector isn't flagging noise.
- **`_define_protocol` (49 overrides, 44,829 lines = 13.3% of src) and `_format_protocol_columns` (108 overrides) are legitimate per-protocol extension points, not duplication.** Note the size is misleading: `fuzz/protocols/opcua.py:704`'s 3,409-line `_define_protocol()` has **max block nesting depth 1** and is 2,368 constants — declarative data, not tangled logic. It is unmaintainable-by-hand and untestable in parts (see F9), but it is not the complexity hazard the line count suggests.
- **52 of 58 `harvest()` overrides correctly call `super().harvest()`.** Fuzzer restart/crash-callback logic is properly centralized.
- **`CLAUDE.md`'s "26 protocols" and "109 listeners" counts are exactly correct.**
- **`uv.lock` drift contract is satisfied** — `pyproject.toml` and `uv.lock` are modified together in the working tree.
- **vulture false positives ruled out:** all ~109 `*PassiveListener` classes and `feed_packets` (dynamic `__getattr__` at `pcap/__init__.py:135`, 38 test call sites); `discovery/scanner.py:398-423` `enable_*` flags (consumed via `getattr(self, f"enable_{name}")` at `:962`); `models.py:384 _set_sqlite_pragma` (`@event.listens_for`); pydnp3/asyncua/zeroconf callback methods.

---

## 12. Where to start

Ranked by (damage prevented) ÷ (effort):

1. **F11, F12, F13** — three security checks that report "clean" when they crashed. This is a pentest tool; a false negative is the worst possible output. Small, local fixes.
2. **F96** — `pip install oida[fuzz]` is broken today. Add `urllib3` and `hpack` to the `fuzz` extra. One line.
3. **F81, F80** — `--seed` doesn't reproduce and fuzz coverage silently downgrades. Both are one-line state bugs that undermine every fuzzing result.
4. **F44, F46, F47, F13-adjacent F45** — constant tables that were duplicated when the shared module already existed and was already imported. ~1,200 lines removed for near-zero risk; F45 also closes a real drift bug.
5. **F87** — pick one device-enrichment convention and apply it to all 159 sites. This is the largest silent behavioural inconsistency in the tool.
6. **F38, F39, F42, F50** — four missing abstractions in `pcap/pyshark_base.py` account for **~7,400 of the ~12,000 duplicated lines**. Highest raw payoff, largest effort.
7. **F53, F54, F65** — the tests that create the most false confidence. Fix these before trusting the suite to gate anything.
8. **F68–F79** — one afternoon restoring `CLAUDE.md` and `README.md` to describe the system that exists.

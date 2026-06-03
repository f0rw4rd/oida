# Test Gap Audit

*Why did the test suite miss the bugs found in CODE_REVIEW.md, and how
many more bugs of the same shape exist?*

## Executive summary

The OIDA test suite is large (3000+ tests) but tests the *wrong altitude*
for the bug classes that hurt in production. Five systemic patterns
dominate, ranked by blast radius:

1. **Mock-shape over real-shape.** Bare `MagicMock()` and `AsyncMock()`
   accept any kwargs and turn every attribute into a coroutine, so
   pymodbus `slave=`→`device_id=` renames, asyncua sync setters awaited
   as async, and ethernetip `cleanup()` arity drift all pass green at
   the unit layer and only manifest against real libraries. There is
   zero use of `create_autospec(real_class, instance=True)` in the
   codebase.
2. **Output-shape over ground-truth.** Classifiers (VRRP master/backup,
   DICOM Command/Data PDV, VNC auth_result, NBSS direction, PTP
   event/general) are tested by asserting they return the value the
   *implementation* computes — never against an RFC-authoritative
   fixture. Two latent inversions (DICOM PDV flags backwards, VNC
   SecurityResult inverted) fall directly out of this gap.
3. **Self-consistent silent fallbacks.** Five HL7 mixin entry points
   (`_create_mfn/bar/dft_message`) wrap their builder calls in
   `try/except Exception → _create_test_message(...)`, hiding seven
   undefined `build_*` methods. Same shape in modbus raw-fc (`except`
   swallows TypeErrors from kwarg drift), ethernetip cleanup (`except`
   swallows arity errors as debug logs), and OCPP TLS check
   (`ModuleNotFoundError` becomes "TLS check disabled"). Tests assert
   "function returned something" rather than "the intended branch ran."
4. **No log-content assertions.** `grep -rn caplog tests/` returns
   nothing in 3000+ tests. Every credential the suite injects into a
   listener (PAP, IRC, HTTP Basic, RDP, SOCKS, TACACS+, BFD, RIP, VRRP)
   gets re-logged at INFO into stdout and `--json-log` because no test
   ever inspects the log stream as data. Same for S7/HART/OPCUA
   `security_finding(..., f"...password... {password}")` leaks.
5. **Argparse defaults declared in two places.** `add_common_args` sets
   `--format=csv,json`; main `cli.py` sets `--format=console`. When
   protocols read `getattr(self.args, "format", "json")` the "console"
   value silently routes export to a no-op. Five+ modules (BACnet,
   FHIR, ADS×18, OPCUA×4, EtherNet/IP) silently write zero files for
   any `oida X host -o out/` invocation that omits `-f`.

**Headline finding:** the `confirm-gate-missing` class is the most
operationally dangerous. Twelve new HIGH-severity unguarded write/brute
paths exist across IEC 104 (clock_read writes the outstation's clock),
DNP3 (`--time-sync`), DICOM (`--store`, `--move`, `--aet-brute`), MQTT
(`--brute`), FHIR (`--default-creds`), Snap7 (`--brute`/`--default-creds`),
HART (`--raw-command`), Modbus (`--raw-fc`, `--test-write`), and ASTM
(`--send-patient`). The existing per-flag confirm tests work but are
opt-in — a meta-test that walks every parser's "requires --confirm" help
text would have caught every one at the moment of commit.

## Per-gap-class breakdown

### import-depth-crash

**Why tests missed it:** Existing smoke tests import each protocol's
top-level package, which executes `__init__.py` cleanly. The buggy
imports live inside function bodies (`from ...utils.fuzzer import fuzz`
with 3 dots instead of 4), so Python defers them until call time. No
unit test ever invokes `_fuzz_property`, `_fuzz_cfind_queries`,
`_setup_authentication` RBAC branch, or `_check_tls_certificate`
post-handshake, so the `ModuleNotFoundError` only fires the first time
the feature is used against a real target. `try/except Exception`
wrappers around the call sites then convert the crash into a silent
"feature disabled" debug log (OCPP TLS especially).

**Missing test category:** static-import-resolution AST walk. Walk every
`.py` under `src/oida`, find every function-body `ImportFrom`, statically
resolve each against `importlib.util.find_spec`, fail the test on miss.
No protocol dependencies needed; sub-second runtime.

**Reproducing test:**
```python
import ast, importlib.util, pathlib
import pytest

SRC_ROOT = pathlib.Path(__file__).resolve().parents[2] / "src" / "oida"


def _collect_function_level_relative_imports():
    out = []
    for py in SRC_ROOT.rglob("*.py"):
        rel = py.relative_to(SRC_ROOT.parent)
        pkg_parts = list(rel.with_suffix("").parts[:-1])
        try:
            tree = ast.parse(py.read_text())
        except SyntaxError:
            continue
        for fn in (n for n in ast.walk(tree)
                   if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
            for node in ast.walk(fn):
                if isinstance(node, ast.ImportFrom) and node.level and node.module:
                    out.append((py, node.lineno, node.level, node.module, pkg_parts))
    return out


@pytest.mark.parametrize(
    "path,lineno,level,module,pkg_parts",
    _collect_function_level_relative_imports(),
)
def test_function_level_relative_import_resolves(path, lineno, level, module, pkg_parts):
    assert level <= len(pkg_parts), (
        f"{path}:{lineno}: relative level {level} exceeds package depth {len(pkg_parts)}"
    )
    base = pkg_parts[: len(pkg_parts) - (level - 1)]
    target = ".".join(base + module.split("."))
    try:
        spec = importlib.util.find_spec(target)
    except (ImportError, ModuleNotFoundError, ValueError) as exc:
        pytest.fail(f"{path}:{lineno}: `from {'.' * level}{module}` resolves to non-existent {target!r}: {exc}")
    assert spec is not None, f"{path}:{lineno}: resolves to missing package {target!r}"
```

**Latent findings (4 new):**
- **HIGH** `src/oida/protocols/dicom/mixins/fuzz.py:40` — wrong dot count on `from ...utils.fuzzer import fuzz` (3 dots, should be 4). Resolves to non-existent `oida.protocols.dicom.utils.fuzzer`. Crashes any `oida dicom --fuzz` run.
- **HIGH** `src/oida/protocols/opcua/mixins/fuzz.py:94` — same: `from ...utils.fuzzer import fuzz` inside `_fuzz_node()` async body. Crashes first OPC UA Variable fuzz attempt.
- **HIGH** `src/oida/protocols/opcua/mixins/credentials.py:310` — `from ...utils.export_utils import export_data` (3 dots, should be 4) inside RBAC reporting branch. Crashes after successful RBAC test.
- **HIGH** `src/oida/protocols/ocpp/mixins/security.py:54` — `from ...utils.socket_helpers import check_tls_certificate` (3 dots, should be 4). Wrapping `try/except Exception` swallows the `ModuleNotFoundError` and silently disables TLS cert inspection for every OCPP `wss://` scan — defect-in-defense.

**Grep queries used:**
```bash
grep -rEn 'from \.\.\.utils|from \.\.\.\.utils|from \.\.\.[a-z]' \
    src/oida/protocols/*/mixins/ src/oida/protocols/*/scanner_mixins/
```

---

### runtime-kwarg-mismatch

**Why tests missed it:** `MagicMock()` accepts arbitrary kwargs without
TypeError, so `mock.read_holding_registers(0, count=3, slave=1)` never
fails even when pymodbus 3.12 renamed `slave=` to `device_id=`.
Integration tests then have explicit fallbacks (try/except → 0 results)
that normalize the TypeError to "empty target." `test_modbus_integration.py`
even documents the bug and writes conditional assertions around it.
For ethernetip `cleanup()`, the existing test only `hasattr`-checks the
method, never calls it.

**Missing test category:** third-party-library signature-conformance
contracts. Per-library file in `tests/contracts/` that extracts the
kwargs production code passes and asserts `inspect.signature(real_method)`
accepts them. Companion: `strict_signature_mock(real_class)` fixture
wrapping `MagicMock(spec=real_class)` for drop-in replacement of bare
mocks.

**Reproducing test:** maintain a static `PRODUCTION_CALLS = [(method_name,
{kwargs_used}), ...]` for every pymodbus call site; parametrize over it
and assert `set(kwargs_used) <= set(inspect.signature(getattr(
ModbusTcpClient, method_name)).parameters)`. Fails the moment pymodbus
renames `slave=` → `device_id=`.

**Latent findings (0 new):** the search returned no additional sites
beyond the canonical pymodbus / ethernetip already in CODE_REVIEW.md.

**Grep queries used:**
```bash
grep -rn 'slave=' src/oida/ | grep -v device_id
grep -rn 'self\.scanner\._[a-z_]*(' src/oida/protocols/
grep -rn 'unit=|slave=' src/oida/
```

---

### callee-not-defined

**Why tests missed it:** Two compounding factors. (1) `tests/unit/hl7/conftest.py`
auto-marks the whole HL7 unit suite as `network`, and `pyproject.toml`'s
default pytest invocation is `-m "not network"`. Every HL7 unit test is
silently deselected by CI. (2) `_create_*_message` mixins wrap their
builder calls in `try/except Exception: return self._create_test_message(...)`,
so callers always get a non-None MSH string. Tests that only assert
`msg is not None and "MSH|" in msg` pass even when every typed segment
fails to build.

**Missing test category:** silent-fallback-detection (assert
`Failed to create` debug line was NOT emitted) plus static AST mixin →
scanner attribute resolution (every `self.scanner._foo(...)` call site
must resolve to a real attribute on the real scanner class).

**Reproducing test:**
```python
import logging
import pytest

pytestmark = []  # override the auto-network mark


@pytest.fixture
def hl7_scanner_no_network():
    from oida.protocols.hl7 import hl7
    from oida.protocols.hl7.segments import HL7SegmentBuilder
    scanner = hl7.__new__(hl7)
    scanner.args = type("A", (), {"hl7_version": "2.5", "confirm": True})()
    scanner.ip, scanner.conn = "127.0.0.1", None
    scanner.results = {"data": {}}
    scanner.detected_version = None
    scanner.segment_builder = HL7SegmentBuilder(version="2.5")
    return scanner


@pytest.mark.parametrize("method,trigger,required_seg", [
    ("_create_mfn_message", "M01", "MFI|"),
    ("_create_mfn_message", "M02", "STF|"),
    ("_create_mfn_message", "M04", "PRC|"),
    ("_create_bar_message", None,  "GT1|"),
    ("_create_dft_message", None,  "FT1|"),
])
def test_mixin_does_not_swallow_attribute_error(
    hl7_scanner_no_network, caplog, method, trigger, required_seg
):
    fn = getattr(hl7_scanner_no_network, method)
    with caplog.at_level(logging.DEBUG):
        msg = fn(trigger) if trigger else fn()
    assert msg is not None
    assert not any("Failed to create" in r.message for r in caplog.records)
    assert required_seg in msg
```

**Latent findings (6 new):**
- **HIGH** `src/oida/protocols/hl7/mixins/master_file.py:96` — calls `self.segment_builder.build_mfe(...)`; method does not exist on `HL7SegmentBuilder`. MFN^M01 silently falls back to generic test message.
- **HIGH** `src/oida/protocols/hl7/mixins/master_file.py:108` — calls `self.segment_builder.build_stf(...)`; not defined. MFN^M02 (Staff Master File) feature non-functional.
- **HIGH** `src/oida/protocols/hl7/mixins/master_file.py:128` — calls `self.segment_builder.build_prc(...)`; not defined. MFN^M04 (Charge Description Master) non-functional.
- **HIGH** `src/oida/protocols/hl7/mixins/financial.py:154` — calls `self.segment_builder.build_gt1(...)`; not defined. BAR^P01 guarantor segment never emitted.
- **HIGH** `src/oida/protocols/hl7/mixins/financial.py:167` — calls `self.segment_builder.build_in1(...)`; not defined. `--insurance-company` flag silently no-ops.
- **HIGH** `src/oida/protocols/hl7/mixins/financial.py:204` — calls `self.segment_builder.build_ft1(...)`; not defined. DFT^P03 financial transaction segment never emitted.

**Grep queries used:**
```bash
grep -rn 'self\.segment_builder\.\(build_[a-z0-9_]\+\)' src/oida/protocols/hl7/
grep -n 'def build_[a-z0-9_]\+' src/oida/protocols/hl7/segments.py
# set-difference between called and defined
```

---

### confirm-gate-missing

**Why tests missed it:** Confirm gates ARE tested — but only one flag at
a time, hand-written, by the same developer who forgot to wire the gate.
There is no meta-test that walks every parser's "requires --confirm"
help text and verifies the dispatcher honours it. Integration tests
actively fire `--probe-ops` at mock targets and assert success (the
opposite of catching the gate). Boilerplate `mock_args.probe_ops = False`
appears in 6 different test classes — every author defensively zeroes
the flag so it stays out of the way; nobody flips it to True and asserts
the gate.

**Missing test category:** cross-protocol confirm-gate contract test
(`tests/contracts/test_confirm_gate_contract.py`) plus a `scripts/code_review.sh`
lint pass that greps `requires --confirm` in `proto_args.py` against
`if not confirm` / `if not self.args.confirm` in the same protocol.

**Reproducing test:** parametrize over `["hl7","coap","can","snap7","opcua","bacnet"]`,
walk each `proto_args` parser, filter to flags whose help matches
`/requires --confirm/i` or whose name matches a dangerous-verb regex
(`write|fuzz|brute|delete|patch|assess|audit|probe|call[-_]method|id[-_]scan|test[-_]write`).
For each flag: build a Namespace with `confirm=False` and that single
dest=True, patch `create_conn_obj` to return False, call `proto_flow()`,
assert `"--confirm" in " ".join(logger.fail.call_args_list)`. Full code
in §confirm-gate of the per-class analysis JSON.

**Latent findings (12 new):**
- **HIGH** `src/oida/protocols/iec104/scanner.py:1340` — `--clock-read` (help text says "Read") actually issues C_CS_NA_1 (Type 103) clock-sync write that overwrites the outstation clock. No confirm gate. Triggers actcon + pollutes SOE log.
- **HIGH** `src/oida/protocols/dnp3/scanner.py:861` — `--time-sync` writes master timestamp to outstation. Omitted from `validate_args` control_ops list, dispatcher has no inline check.
- **HIGH** `src/oida/protocols/dicom/mixins/operations.py:281` — `--store` performs C-STORE upload (writes attacker-controlled DICOM files into PACS). Author even emits `security_finding("Unrestricted upload", ...)` on success — knows it writes, still no confirm.
- **HIGH** `src/oida/protocols/dicom/mixins/operations.py:350` — `--move` issues C-MOVE to attacker-controlled `--dest-aet`, canonical PHI exfiltration primitive. No confirm.
- **HIGH** `src/oida/protocols/dicom/mixins/enumeration.py:33` — `--aet-brute`/`--common-ae` runs AE-Title brute force (hundreds of associations), trips PACS rate-limit / SIEM. No confirm.
- **HIGH** `src/oida/protocols/mqtt/scanner.py:759` — `--brute` / `--default-creds` runs credential brute-force against broker with zero-second rate. Trips EMQX/HiveMQ/Mosquitto-auth lockout. Other MQTT write paths gate; brute does not.
- **HIGH** `src/oida/protocols/fhir/mixins/security.py:298` — `--default-creds` expands to 56 username×password OAuth2 token-endpoint requests with no confirm gate. Same bug shape as MQTT.
- **HIGH** `src/oida/protocols/snap7/nxc_connection.py:389` — explicit `--brute` and `--default-creds` bypass `_require_confirm()` (not in DANGEROUS_ACTIONS). Trips Siemens S7 account-lockout / SCALANCE SIEM.
- **HIGH** `src/oida/protocols/hart/nxc_connection.py:440` — `--raw-command` sends arbitrary HART command incl. writes 6/17/18/19/41/42/53 (master reset). Named-write siblings in same file all check confirm; raw path was wired around.
- **HIGH** `src/oida/protocols/modbus/mixins/raw_function_codes.py:25` — `--raw-fc` sends arbitrary FC+payload incl. 5/6/15/16 writes, FC 8 restart, FC 23, vendor codes 65-72. No confirm.
- **MEDIUM** `src/oida/protocols/modbus/mixins/writes.py:326` — `--test-write` / `--test-write-thorough` issue real FC 5/6/15/16 write transactions logged by every SCADA historian. Help text calls it "safest," still a real write.
- **MEDIUM** `src/oida/protocols/astm/nxc_connection.py:71` — `--send-patient` injects forged P (Patient) demographics into LIS. Sibling `--send-order` two lines above explicitly gates on confirm; patient path does not.

**Grep queries used:**
```bash
grep -rn 'args.confirm\|self.confirm\|getattr.*confirm' src/oida/protocols/
grep -rn 'add_argument.*"--(fuzz|brute|inject|crash|reset|...)' src/oida/protocols/
grep -rn '_send_query_record\|_send_patient\|_send_order' src/oida/protocols/astm/
```

---

### credential-log-leak

**Why tests missed it:** `grep -rn caplog tests/` returns nothing in
3000+ tests. The pcap listener harness `_run_listener_test` returns
`(listener, devices, result)` — test authors assert on `listener.credentials`
(structured state) but never on log content. The framework's own
`ICSLogger` uses `print()`-style display methods that don't propagate
to the stdlib root logger, so naive `caplog` catches nothing anyway.
With no fixture/helper for log-as-data assertions, every new
`logger.info(f"...{password}...")` regression is invisible.

**Missing test category:** autouse `no_credential_leak` fixture in
`tests/conftest.py` that captures every log record (stdlib root +
`oida.utils.ics_logger` channels + stdout/stderr via `capsys`) and on
teardown asserts no record contains seeded credential strings. Companion
per-site reproducers under `tests/unit/security/test_credential_log_leak.py`.

**Reproducing test:** install a `logging.Handler` that buffers every
record on the root logger, force the listener's logger to propagate,
call `listener._record_password_credential(password=SECRET, ...)`,
assert (a) `SECRET` IS in `listener.credentials` (structured state is
the feature) and (b) `SECRET` is NOT in any buffered record (the
missing assertion). Full code in §credential-log-leak of the per-class
analysis JSON.

**Latent findings (15 new):**
- **HIGH** `src/oida/pcap/passive/pap.py:205` — `logger.info(f"PAP: {username}:{password}")` writes every PAP cred to stdout + json-log at INFO.
- **HIGH** `src/oida/pcap/passive/irc.py:142` — `logger.info(f"IRC PASS: {password} ...")` for every IRC `PASS` command (often reused operator creds).
- **HIGH** `src/oida/pcap/passive/http.py:553` — `logger.info(f"HTTP Basic Auth: {username}:{password} @ ...")` for every Basic Auth pair.
- **HIGH** `src/oida/pcap/passive/rdp.py:163` — `logger.info(f"RDP: {username}:{password} ...")` typically AD domain credentials.
- **HIGH** `src/oida/pcap/passive/socks.py:233` — `logger.info(f"SOCKS: {username}:{password} ...")` for every SOCKS5 subnegotiation.
- **HIGH** `src/oida/pcap/passive/tacacs.py:411` — `logger.info(f"TACACS+: {username}:{password} ...")` typically Cisco/Juniper enable passwords.
- **HIGH** `src/oida/pcap/passive/bfd.py:284` — `logger.info(f"BFD: Simple Password={password} ...")`.
- **HIGH** `src/oida/pcap/passive/rip.py:196` — `logger.info(f"RIP: Simple Password={auth_passwd} ...")`.
- **HIGH** `src/oida/pcap/passive/vrrp.py:269` — `logger.info(f"VRRP: auth_string={auth_string} ...")` (keys to spoof VRRP master).
- **HIGH** `src/oida/protocols/snap7/mixins/security.py:230` — `logger.security_finding("Weak password", f"S7 password found: {test_password}")` leaks recovered PLC password to console + json-log.
- **HIGH** `src/oida/protocols/hart/nxc_connection.py:522` — `logger.security_finding("Weak password", f"Device lock code found: '{code}'")` leaks cracked HART lock code.
- **HIGH** `src/oida/protocols/opcua/mixins/credentials.py:70` — `logger.security_finding("Default credentials", f"Valid OPC UA credentials: {username}:{password}")` leaks verified pair.
- **MEDIUM** `src/oida/protocols/mqtt/nxc_connection.py:154` — `logger.fail(f"Authentication failed ({username}:{password})")` leaks attempted password per host on CIDR sweeps.
- **MEDIUM** `src/oida/protocols/snmp/mixins/brute_force.py:36` — `logger.info(f"SNMP: valid community found: '{community}'")` (communities are the SNMP credential, often `private` granting RW).
- **LOW** `src/oida/pcap/passive/smtp.py:416` — SMTP AUTH LOGIN base64-encoded password stored in interaction summary surfaced by harvest stage.

**Grep queries used:**
```bash
grep -rn -E "logger\.(info|display|warning)\s*\(.*(password|secret|token|cred)" src/oida/
grep -rn -E "security_finding\s*\(.*(password|secret|token|cred)" src/oida/
```

---

### dataclass-kwarg-drift

**Why tests missed it:** Existing discovery tests exhaustively cover
`DiscoveredDevice` construction with the *correct* kwargs but never
exercise a producer like `NetManageDevice.to_discovered_device()`.
Producer modules have zero test coverage (grep for `netmanage` in tests
returns nothing). Mypy detects unknown-kwarg dataclass `__init__` calls
but pre-push hook is informational only — the error is emitted and
ignored. Ruff doesn't check kwarg-vs-field.

**Missing test category:** producer-smoke-test per discovery sub-module
+ AST meta-test that walks `src/oida/protocols/discovery/*.py`, finds
every `Call` whose `func.id == "DiscoveredDevice"`, asserts every
`keyword.arg` is in `{f.name for f in dataclasses.fields(DiscoveredDevice)}`.

**Reproducing test:** instantiate `NetManageDevice(...)` with minimal
realistic inputs, call `src.to_discovered_device()` and assert
`isinstance(result, DiscoveredDevice)` — the constructor call itself is
the assertion (TypeError fires on kwarg drift). Plus a parametrized
negative test `pytest.raises(TypeError)` for the old kwarg names
(`ip`, `mac`, `hostname`, `protocol`, `metadata`).

**Latent findings (0 new):** AST walker against 163 schema classes
returned no new drift beyond the canonical netmanage case. Pre-push
mypy promotion remains the right systemic fix.

**Grep queries used:**
```bash
grep -rn '@dataclass' src/oida/
grep -rn 'DiscoveredDevice(\*\*\|DeviceInfo(\*\*\|ScanResults(\*\*' src/oida/
# plus AST walker over 163 dataclass/BaseModel/SQLAlchemy classes
```

---

### async-sync-misuse

**Why tests missed it:** Unit tests use bare `AsyncMock()` for asyncua
`Client`, making EVERY attribute access return a coroutine. So
`await mock.set_user(...)` succeeds even though real
`asyncua.Client.set_user` is a plain synchronous setter. The mocking
pattern is structurally incapable of catching the bug. Integration
tests would catch it but skip when Docker isn't up, and the credential
test paths aren't exercised against the failing branch.

**Missing test category:** spec-bound async mock conformance using
`create_autospec(real_class, instance=True)` which inspects each method
with `inspect.iscoroutinefunction` and assigns AsyncMock vs MagicMock
per attribute. Per-protocol conformance suite under
`tests/contracts/third_party_api/`.

**Reproducing test:** assert `not inspect.iscoroutinefunction(Client.set_user)`
as ground truth, then build a SUT via `__new__` with
`inst._client = create_autospec(Client, instance=True)`, run
`asyncio.run(inst._setup_authentication(...))`, assert
`inst._client.set_user.assert_called_once_with("admin")`. The
`create_autospec` ensures sync methods stay MagicMock — awaiting one
raises `TypeError`. Full code in §async-sync-misuse of the per-class
analysis JSON.

**Latent findings (1 new):**
- **HIGH** `src/oida/protocols/opcua/scanner.py:605` — `_configure_security(client)` calls `client.set_security_string(security_string)` WITHOUT `await`. `set_security_string` IS async on asyncua. Coroutine is dropped (`__del__` emits `RuntimeWarning: coroutine ... never awaited`), cert/policy never wired. Subsequent `client.connect()` runs anonymous/no-security. When user passes `--policy Basic256Sha256 --mode SignAndEncrypt --cert ... --key ...`, scanner either fails to connect or silently downgrades and reports the anonymous result as a successful "secure" scan. Sibling of known scanner.py:361/394 set_user bug.

**Grep queries used:**
```bash
grep -rEn 'await\s+\w+\.(set_|get_|is_|has_|configure)' src/oida/
grep -rEn '[^a-z_]\b(node|child|client)\.(read_value|write_value|connect)\(' src/oida/ \
    | grep -vE 'await\s+|asyncio\.run\('
```

---

### timeout-as-success

**Why tests missed it:** BACnet tests assert on `scanner.logger.display.assert_called()`
and `scanner.logger.warning.assert_called()` — both called on every code
path (banners, progress, warnings), so the assertion fires regardless of
whether the predicate decided rejected/accepted/timeout. Existing tests
actively encode the bug as a feature: `test_bbmd_injection_fd_accepted`
constructs a timeout side-effect and asserts the "accepted" log fires.
The mock logger in `tests/unit/bacnet/conftest.py:109-118` has no `spec=`,
so undeclared methods like `security_finding` silently auto-mock and are
never inspected via `mock_calls`. The missing assertion is one line:
`logger.security_finding.assert_not_called()` on timeout paths.

**Missing test category:** negative-assertion timeout/no-reply tests per
protocol (`tests/unit/{protocol}/test_security_mixin_timeout.py`) backed
by a shared `spec_logger()` fixture built from
`oida.utils.ics_logger.ICSLogger` with `spec=` so undeclared methods
raise AttributeError.

**Reproducing test:** build a bacnet scanner via `object.__new__`,
explicitly attach `logger.security_finding = Mock()` and
`logger.vuln = Mock()`, set `app.request = AsyncMock(return_value=None)`
to simulate every transport call timing out, run the security predicate
under `asyncio.run`, then assert `logger.security_finding.assert_not_called()`
and `logger.vuln.assert_not_called()`. Full code in §timeout-as-success
of the per-class analysis JSON.

**Latent findings (5 new):**
- **HIGH** `src/oida/protocols/bacnet/mixins/security.py:937` — outOfService write probe: `if response is None or not isinstance(response, (ErrorPDU, Error, AbortPDU, RejectPDU)): writable.append(...); security_finding("Writable access", ...)`. On noisy BACnet/IP, every silent device flagged as having writable safety control points.
- **HIGH** `src/oida/protocols/bacnet/mixins/network.py:472` — BBMD BDT write probe: `if response is None: security_finding("Writable access", "BBMD BDT write accepted without authentication")`. Non-BBMDs that drop the BVLC get flagged as accepting writes. Distinct from the known FD-registration bug at network.py:438.
- **MEDIUM** `src/oida/protocols/bacnet/mixins/security.py:104` — `_handle_test_write` reports "Anonymous write access" because `_write_property` `try/except → return False` swallows silent-device failures.
- **LOW** `src/oida/protocols/ethernetip/mixins/cip_security.py:102` — CIP Security read timeout reported as `security_finding("No authentication", "CIP Security: NOT SUPPORTED")`.
- **LOW** `src/oida/protocols/bacnet/mixins/monitoring.py:552` — COV subscription response=None counted as "subscribed"; downstream `monitor_duration` listener silently produces zero notifications.

**Grep queries used:**
```bash
grep -rn 'response is None\|response == None' src/oida/
grep -n 'security_finding\|_add_finding' \
    src/oida/protocols/{snap7,knx,ethernetip,mqtt,bacnet}/mixins/security*.py
```

---

### inverted-classifier

**Why tests missed it:** Tests assert classifier outputs are
*self-consistent within one module*, never against an external authority
(RFC, sibling module's documented return shape, or a hand-labeled
fixture). `test_vrrp_device_type` reads the fixture, sees priority=100,
and asserts `"Backup" in dev.device_type` — actively encoding the
inversion as expected. Fixing the source breaks the test. For Modbus
raw-fc, producer and consumer mock disjoint dicts so the
`is_exception` → `exception` key-name drift is invisible. Ruff/mypy
have no concept of "this dict key was renamed on one side."

**Missing test category:** (a) spec-conformance fixtures with sidecar
`<name>.expected.json` per pcap listing RFC-correct labels; loop and
assert listener output matches. (b) cross-module producer/consumer
contract tests threading the *actual* producer dict into the consumer.

**Reproducing test:** run the VRRP listener over the canonical pcap;
per RFC 5798 §6.4.2 only MASTER routers send Advertisements, so for
every device extracted assert `vrrp_data["state_name"] == "Master"`
regardless of priority. Bug: code uses priority as the discriminator,
so pri=100 advertisements get labeled Backup.

**Latent findings (6 new):**
- **HIGH** `src/oida/pcap/passive/dicom.py:647` — PDV Message Control Header bit 0 inverted (`0=Data Set, 1=Command Set` per PS3.8 §E.2). Code says `is_command = (pdv_flags & 0x01) == 0` then `direction = "request" if is_command else "response"`. Net: every C-STORE-RQ Command PDV labeled "response," every Data PDV labeled "request."
- **HIGH** `src/oida/pcap/passive/vnc.py:349` — RFB SecurityResult inverted: per RFC 6143 §7.2, `0=OK, 1=failed`. Code maps `auth_result in ("1", "True") → "success"`. Every failed VNC auth recorded as success and vice versa. Misleads brute-force forensics.
- **MEDIUM** `src/oida/pcap/passive/netbios.py:357` — NBSS SESSION_MESSAGE (0x00) classified as response. Dominant frame on every SMB connection mislabeled; downstream role-swap tags real clients as "server" and real servers as "client" in NetBIOS device inventory.
- **MEDIUM** `src/oida/pcap/passive/ptp.py:338` — IEEE 1588 event/general flag (UDP 319 vs 320) does NOT correspond to request/response. Code maps all event types to "request" — so Pdelay_Resp (0x3) tagged "request," Sync (0x0) tagged "request" (unsolicited).
- **LOW** `src/oida/pcap/passive/coap.py:280` — CoAP code_val==0 (Empty Message) caught by `is_request` arm before `is_empty` ACK/RST disambiguation can run.
- **LOW** `src/oida/pcap/passive/ipsec.py:199` — IKE direction inferred from responder-SPI-zero (only true for first IKE_SA_INIT). Every IKE_AUTH/INFORMATIONAL mislabeled "response." Should parse ISAKMP flags R bit.

**Grep queries used:**
```bash
grep -rn -E "(\"request\" if|\"response\" if)" src/oida/
grep -rn -E "is_(master|primary|success|failure|exception)\s*=" src/oida/
```

---

### parser-unbounded-or-hang

**Why tests missed it:** Tests assert OUTPUT SHAPE, not LOOP TERMINATION.
The canonical SZL test (`test_all_zeroes_0x001c`) docstring says
"record_len of 0 should not cause infinite loop" — but the test data is
all-zero, so the `rec_index==0` short-circuit fires accidentally. The
real DoS state (record_len=0 AND non-zero first index byte) is never
exercised. No `pytest.mark.timeout`, no bound on output size, no
progress-per-iteration invariant.

**Missing test category:** hostile-fixture tests that feed worst-case
input (zero-progress, infinite-more, never-terminating-frame) inside
`pytest.mark.timeout(3, method="thread")`, then assert the function
returned AND output size is below a sane cap. Convention should be
"every parser with a `while True:` or `while offset < len(data):` gets
a corresponding `test_<parser>_zero_progress_terminates` test."

**Reproducing test:**
```python
import pytest


@pytest.mark.timeout(3, method="thread")
def test_szl_0x001c_zero_record_len_terminates():
    from oida.protocols.snap7.szl_parser import SZLParser
    data = b"\x00\x00\x01\x00" + b"\x00\x07" + b"\x00" * 200  # record_len=0, idx non-zero
    result = SZLParser._parse_0x001c(data, 0)
    assert "szl_id" in result
    assert len(result.get("records", {})) < 1024
```

**Latent findings (6 new):**
- **MEDIUM** `src/oida/fuzz/protocols/ftp.py:541-546` — `_early_capability_detection` `while True: chunk = sock.recv(4096); response += chunk` with no byte cap or iteration count. Sibling at ftp.py:2304 has a cap; this site dropped it.
- **MEDIUM** `src/oida/protocols/ethernetip/mixins/advanced_parsers.py:285-294` — CIP File Upload: when optional size-probe returns None, code reads `total_size` (UDINT, up to 4 GiB) from peer and enters unbounded `while len(file_data) < total_size:` loop.
- **MEDIUM** `src/oida/protocols/ads/ethercat_ops.py:1485-1521` — FoE probe-pass `while True:` with 4096-byte chunks has no iteration/size cap. Cousin `_read_file()` at line 230 caps at 100 MiB; FoE does not.
- **MEDIUM** `src/oida/protocols/ads/ethercat_ops.py:141-175` — ADS FILE_BROWSE `while True:` re-issues FILE_BROWSE on same handle; hostile server returning 320-byte responses forever grows `result["files"]` unboundedly.
- **LOW** `src/oida/protocols/bacnet/mixins/files.py:130-234` — BACnet AtomicReadFile uses peer-supplied `fileSize` (UDINT) to compute `max_reads = file_size // chunk_size + 2`; hostile device with `fileSize=0xFFFFFFFF` produces ~4.2M iterations.
- **LOW** `src/oida/protocols/profinet/mixins/cyclic.py:174-180` — `while True: con._socket.recvfrom(4096)` stale-UDP drain has 0.1s timeout reset per recv; LAN attacker can pin the loop. PROFINET threat model is L2-trusted but bug shape matches.

**Grep queries used:**
```bash
grep -rn 'while True' src/oida/
grep -rn 'while ' src/oida/ | grep -iE 'len\(|< len|offset|pos|remaining'
grep -rn 'struct.unpack.*length\|struct.unpack.*size' src/oida/
```

---

### config-and-default-drift

**Why tests missed it:** Two argparse declarations disagree on
`--format`'s default. `add_common_args(parser)` sets `default="csv,json"`;
main CLI sets `default="console"`. Tests don't exercise the cross-product
(invoke main CLI with `-o` but without `-f`), so the silent zero-file
case never trips an assertion. Protocols read `getattr(self.args, "format", "json")`
with hand-rolled default `"json"` — but the parser ACTUALLY supplies
`"console"`, so the `if output_format == "json": write` branch is skipped
and `success("Dump saved")` lies.

**Missing test category:** end-to-end `tests/integration/cli/test_export_writes_files.py`
that for every protocol invokes `oida <proto> <mock-host> -o tmpdir/`
without `-f` and asserts at least one file landed in tmpdir. Plus a
lint pass that flags `getattr(self.args, "format", <literal>)` and
demands `_effective_export_format(args)` helper.

**Reproducing test:** parametrize over `[(proto, mock_target), ...]`,
invoke `subprocess.run(["oida", proto, target, "-o", str(tmp_path)])`
without `-f`, assert `any(tmp_path.rglob("*"))`. Empty directory means
`--format` default drift silently no-op'd file writes.

**Latent findings (8 new):**
- **HIGH** `src/oida/utils/export_utils.py:99-101 + src/oida/cli.py:372-377` — root drift: `add_common_args` default=`"csv,json"` vs main CLI default=`"console"`. `configure_from_args` copies `"console"` into `_config`; `export_table()` matches only csv/json/xml — `"console"` silently no-ops every file write.
- **HIGH** `src/oida/protocols/bacnet/mixins/state.py:104-117` — `_handle_dump` reads `getattr(self.args, "format", "json")` (real default is `"console"`); neither json nor yaml branch fires for `--dump --output dumps/site-a`, yet `success("Dump saved to {dump_file}")` lies.
- **HIGH** `src/oida/protocols/bacnet/mixins/export.py:41-75` — `_export_results` dispatches on `"json"`/`"csv"`; `"console"` value drops to no-op. `oida bacnet host -o results/` silently writes nothing.
- **HIGH** `src/oida/protocols/fhir/nxc_connection.py:491-526` — same shape: substring/equality checks against `"console"` all false; patient records, capability statements, $everything dumps silently discarded.
- **HIGH** Mass pattern `getattr(self.args, "format", "console") if output_dir else "console"` at ~18 ADS sites + 4 OPCUA sites (`browse.py:304,517`, `discovery.py:186`, `credentials.py:313`) + EtherNet/IP `scanner.py:665`, `controller_info.py:271-350`. Every `oida ads host -o out/` (without `-f`) silently writes nothing.
- **MEDIUM** `src/oida/utils/export_utils.py:96-128 vs src/oida/cli.py:332-394` — `add_common_args` declares `--verbose=store_true`; main parser declares `--verbose=count`. Subparsers built from `add_common_args(parent_parser=)` get `verbose` as `bool` vs `int` depending on dispatch path. Code that tests `verbose > 0` behaves differently across paths.
- **MEDIUM** `src/oida/cli.py:1049-1054 + 657-659 + 994` — `PROTOCOL_ALIASES = {"s7": "snap7"}` resolved *before* export; `oida s7 host -o out/` writes `out/snap7.json`, not `out/s7.json`. Breaks downstream tooling that greps results by CLI name.
- **LOW** `src/oida/fuzz_cli.py:367,802` — `getattr(args, "verbose", False)` fallback type-mismatches parser default `0` (count). Latent until anyone branches on `verbose >= 2`.

**Grep queries used:**
```bash
grep -rn 'getattr(self\.args, "format"' src/
grep -rn 'merge_config\|merge_args' src/
grep -rn 'PROTOCOL_ALIASES' src/
```

---

### garbled-log-string

**Why tests missed it:** Same auto-rewriter pattern flagged in CODE_REVIEW
for discovery/* and the hart/mms/ethercat/iec104 *active* code paths,
but every PCAP listener was missed by the original sweep. No test
inspects log strings as data (same root cause as credential-log-leak),
so refactor-artefact debug strings like `Failed to get svc_code: {e}`
(the local variable name, not the source field) and pasted-source
fragments like `if hasattr(packet, tcp): {e}` go undetected. Catches
under `--debug` produce opaque error logs that hide the real Wireshark
field name being parsed.

**Missing test category:** lint pass + grep-based contract test that
flags any `logger.debug(f"...{e}")` where the f-string contains: a
single-segment local-variable name pattern (`Failed to get <varname>:`),
or pasted python keywords (`if`, `while`, `for`, `with`, `def`, `yield`,
`return`) before `: {e}`. Lives in `tests/contracts/test_log_string_shape.py`.

**Reproducing test:** AST-walk every `.py` under `src/oida`, collect
every `logger.{debug,warning,info}(JoinedStr(...))` call, parametrize
over the joined constant text. Fail if it matches `PASTED_SRC =
re.compile(r"\b(if|while|for|with|def|yield|return|import)\b\s")` or
`BARE_VAR = re.compile(r"Failed to get [a-z_]{1,12}: \{e\}")`.
Sub-second runtime; catches every site in one pass.

**Latent findings (20 sites, aggregated by file cluster):**

*Pcap-listener cluster (most pervasive; 60+ sites across 28 files):*
- **MEDIUM** `src/oida/pcap/passive/dnp3.py` lines 330,335,349,417,436,455,467,474,484 — 9 sites in DNP3 application-layer parser.
- **MEDIUM** `src/oida/pcap/passive/bacnet.py` lines 327,338,350,360,391,396,499 — 7 sites in APDU/NPDU parser.
- **MEDIUM** `src/oida/pcap/passive/enip.py` lines 268,540,549,554 — CIP class/instance/attribute + encap cmd.
- **MEDIUM** `src/oida/pcap/passive/smb.py` lines 465,542,552,613,633 — dialect/cmd/NTSTATUS/CreateAction.
- **MEDIUM** `src/oida/pcap/passive/s7comm.py` lines 310,406,944 — function code, PDU length, userdata type.
- **MEDIUM** `src/oida/pcap/passive/opcua.py` lines 552,977,1192,1238 — security mode, payload extraction, certificate.
- **MEDIUM** `src/oida/pcap/passive/iec104.py` lines 1185,1212,1242 — sco/dco/rco command-value extractors.
- **MEDIUM** `src/oida/pcap/passive/mms.py` lines 318,324 — service-code dispatcher.
- **MEDIUM** `src/oida/pcap/passive/vnc.py` lines 612,629 — security-type negotiation.
- **MEDIUM** `src/oida/pcap/passive/ethercat.py:1419` — critical OD-range scanner.
- **MEDIUM** Small-listener cluster `mdns.py:134, wsdiscovery.py:138, smartinstall.py:101, pjl.py:127,322, ssdp.py:103, ntlm.py:207,300` — 8 sites.
- **MEDIUM** Auth/file-transfer cluster `kerberos.py:591, tacacs.py:320, radius.py:391, rsync.py:460, telnet.py:365, mysql.py:1139, ntp.py:391` — 7 sites.
- **MEDIUM** Additional ADS/Modbus/FINS sites `ads.py:528, modbus.py:330,694, fins.py:263,462` — 5 sites missed by CR sweep.
- **MEDIUM** `src/oida/pcap/passive/pyshark_base.py:413,575,594` — shared base inherited by all 109 listeners.

*Active-protocol cluster (missed by original sweep):*
- **MEDIUM** `src/oida/protocols/dnp3/{scanner.py:1065,1071,1077, mixins/polling.py:461}` — 4 sites in outstation cleanup + polling.
- **MEDIUM** `src/oida/protocols/profinet/{mixins/rpc.py:711,737,797, dcp.py:86, mixins/cyclic.py:179}` — 5 sites.
- **MEDIUM** `src/oida/protocols/{coap/nxc_connection.py:543, ethernetip/mixins/controller_info.py:541, mqtt/nxc_connection.py:217,220, mqtt/mixins/messaging.py:88}` — 5 sites.
- **MEDIUM** `src/oida/protocols/hl7/segments.py:151,1081` — 2 sites (PV1 enrichment + index check).
- **LOW** `src/oida/protocols/{snmp/mixins/version_detection.py:90, dicom/mixins/fuzz.py:113, knx/mixins/security.py:147}` — 3 fuzz/brute loop sites with terse-but-correct templating.

**Grep queries used:**
```bash
grep -rn -E 'logger\.(debug|warning|error|info)\(f"[^"]*\b[a-z]{1,3}: \{e\}' src/oida/
grep -rn -E 'logger\.(debug|warning|error|info)\(f"Failed to get [a-z]{1,4}:' src/oida/
grep -rn -E 'logger\.(debug|warning|error|info)\(f"(with open|yield |return |if |for |while |def |import )' src/oida/
```

---

## Recommended test infrastructure to add

In priority order (closes most gap classes first):

1. **`tests/contracts/` top-level folder** (≈4h to scaffold).
   Cross-cutting invariants. Closes: `confirm-gate-missing`,
   `runtime-kwarg-mismatch`, `async-sync-misuse`,
   `dataclass-kwarg-drift`, `garbled-log-string`. Sub-tree:
   - `test_confirm_gate_contract.py` — meta-test over every parser.
   - `third_party_api/test_<lib>_signature_conformance.py` — per
     third-party library, walks production call sites and checks
     against `inspect.signature(real_method)`.
   - `third_party_api/conftest.py::specced_client(lib_class)` — wraps
     `create_autospec(..., instance=True)`.
   - `test_dataclass_kwarg_drift.py` — AST walker over every
     `DiscoveredDevice(...)`, `DeviceInfo(...)`, `ScanResults(...)`
     call site.
   - `test_log_string_shape.py` — AST walker that flags pasted-source
     and bare-variable-name debug strings.

2. **Autouse `no_credential_leak` fixture in `tests/conftest.py`**
   (≈2h). Captures every log record (stdlib root + `oida.utils.ics_logger`
   channels + stdout/stderr) and on teardown asserts no record contains
   seeded credential strings. All 3000+ existing tests gain the guard
   for free. Closes: `credential-log-leak`.

3. **`tests/unit/test_import_resolution.py`** (≈1h).
   Static AST walk + `importlib.util.find_spec` over every function-body
   relative `ImportFrom`. Sub-second runtime, zero protocol deps.
   Closes: `import-depth-crash`.

4. **`tests/integration/cli/test_export_writes_files.py`** (≈3h).
   Parametrized over every protocol; invokes `oida <proto> <mock-host> -o tmpdir/`
   *without* `-f` and asserts at least one file lands. Closes:
   `config-and-default-drift`.

5. **`tests/unit/{protocol}/test_security_mixin_timeout.py`** template
   + `spec_logger()` fixture built from `ICSLogger` with `spec=` (≈4h
   across the 6 protocols with `response is None` patterns: bacnet,
   ocpp, ethernetip, modbus, snap7, mqtt). Negative assertions
   (`security_finding.assert_not_called()`) on timeout paths. Closes:
   `timeout-as-success`.

6. **`tests/integration/pcap/spec_conformance/` with sidecar `<name>.expected.json`**
   (≈6h initial, ≈30min/protocol thereafter). Per-packet RFC-correct
   labels for VRRP, HSRP, GLBP, OSPF DR/BDR, STP root, DICOM PDV, VNC,
   NBSS, PTP, CoAP, IPSec. Closes: `inverted-classifier`.

7. **`tests/unit/{protocol}/test_mixin_callee_exists.py`** (≈1h per
   protocol). AST scan of `mixins/*.py` for
   `self.scanner._x(...)` / `self.segment_builder.build_x(...)`,
   assert attribute resolves on the real class. Closes:
   `callee-not-defined`.

8. **Hostile-fixture tests with `pytest.mark.timeout(3, method="thread")`**
   convention (≈30min per parser; ≈10 parsers). Worst-case input that
   defeats progress invariants; assert function returned AND output
   size bounded. Closes: `parser-unbounded-or-hang`.

9. **Pre-push hook promotion: mypy from informational to blocking for
   `src/oida/protocols/discovery/` and `src/oida/utils/common_types.py`**
   (≈10min). Mypy already detects unknown-kwarg dataclass `__init__` —
   the only reason it didn't catch netmanage was the hook being
   advisory. Closes: residual `dataclass-kwarg-drift`.

10. **Fix `tests/unit/hl7/conftest.py`** (≈30min). Stop blanket-marking
    the entire HL7 unit suite as `network`. The directory mark is the
    root cause that hid five existing MFN/BAR/DFT tests from CI. Only
    mark tests that genuinely call `proto_flow()`.

11. **Add check #15 to `scripts/code_review.sh`** (≈1h). Grep
    `requires --confirm` in `proto_args.py` against
    `if not confirm` / `if not self.args.confirm` in the same protocol.
    Catches gate-missing at review time even before tests run.

12. **Extend `tests/integration/pcap/conftest.py::_run_listener_test`
    to return captured log buffer alongside `(listener, devices, result)`**
    (≈1h). Makes credential-leak assertions ergonomic for every existing
    passive-listener test.

---

## All new latent findings, by severity

**HIGH (24):**
| File:line | Class | Title |
|---|---|---|
| `src/oida/protocols/dicom/mixins/fuzz.py:40` | import-depth | wrong dot count on fuzzer import |
| `src/oida/protocols/opcua/mixins/fuzz.py:94` | import-depth | wrong dot count on fuzzer import |
| `src/oida/protocols/opcua/mixins/credentials.py:310` | import-depth | wrong dot count on export_utils import |
| `src/oida/protocols/ocpp/mixins/security.py:54` | import-depth | wrong dot count, swallowed → TLS check silently disabled |
| `src/oida/protocols/hl7/mixins/master_file.py:96` | callee-not-defined | build_mfe() not defined |
| `src/oida/protocols/hl7/mixins/master_file.py:108` | callee-not-defined | build_stf() not defined |
| `src/oida/protocols/hl7/mixins/master_file.py:128` | callee-not-defined | build_prc() not defined |
| `src/oida/protocols/hl7/mixins/financial.py:154` | callee-not-defined | build_gt1() not defined |
| `src/oida/protocols/hl7/mixins/financial.py:167` | callee-not-defined | build_in1() not defined |
| `src/oida/protocols/hl7/mixins/financial.py:204` | callee-not-defined | build_ft1() not defined |
| `src/oida/protocols/iec104/scanner.py:1340` | confirm-gate | --clock-read writes outstation clock |
| `src/oida/protocols/dnp3/scanner.py:861` | confirm-gate | --time-sync writes outstation clock |
| `src/oida/protocols/dicom/mixins/operations.py:281` | confirm-gate | --store uploads DICOM files |
| `src/oida/protocols/dicom/mixins/operations.py:350` | confirm-gate | --move exfiltrates PHI |
| `src/oida/protocols/dicom/mixins/enumeration.py:33` | confirm-gate | --aet-brute trips PACS rate-limit |
| `src/oida/protocols/mqtt/scanner.py:759` | confirm-gate | --brute trips broker lockout |
| `src/oida/protocols/fhir/mixins/security.py:298` | confirm-gate | --default-creds OAuth2 brute |
| `src/oida/protocols/snap7/nxc_connection.py:389` | confirm-gate | --brute bypasses _require_confirm() |
| `src/oida/protocols/hart/nxc_connection.py:440` | confirm-gate | --raw-command incl. master reset |
| `src/oida/protocols/modbus/mixins/raw_function_codes.py:25` | confirm-gate | --raw-fc incl. writes/restart |
| `src/oida/pcap/passive/pap.py:205` | cred-leak | PAP cleartext at INFO |
| `src/oida/pcap/passive/irc.py:142` | cred-leak | IRC PASS at INFO |
| `src/oida/pcap/passive/http.py:553` | cred-leak | HTTP Basic at INFO |
| `src/oida/pcap/passive/rdp.py:163` | cred-leak | RDP cleartext at INFO |
| `src/oida/pcap/passive/socks.py:233` | cred-leak | SOCKS5 cleartext at INFO |
| `src/oida/pcap/passive/tacacs.py:411` | cred-leak | TACACS+ cleartext at INFO |
| `src/oida/pcap/passive/bfd.py:284` | cred-leak | BFD simple password at INFO |
| `src/oida/pcap/passive/rip.py:196` | cred-leak | RIP simple password at INFO |
| `src/oida/pcap/passive/vrrp.py:269` | cred-leak | VRRP auth_string at INFO |
| `src/oida/protocols/snap7/mixins/security.py:230` | cred-leak | S7 password via security_finding |
| `src/oida/protocols/hart/nxc_connection.py:522` | cred-leak | HART lock code via security_finding |
| `src/oida/protocols/opcua/mixins/credentials.py:70` | cred-leak | OPCUA creds via security_finding |
| `src/oida/protocols/opcua/scanner.py:605` | async-sync | set_security_string not awaited; silent downgrade |
| `src/oida/protocols/bacnet/mixins/security.py:937` | timeout-as-success | outOfService writable findings on timeout |
| `src/oida/protocols/bacnet/mixins/network.py:472` | timeout-as-success | BBMD BDT write accepted on timeout |
| `src/oida/pcap/passive/dicom.py:647` | inverted-classifier | Command/Data PDV flag inverted |
| `src/oida/pcap/passive/vnc.py:349` | inverted-classifier | RFB SecurityResult inverted |
| `src/oida/utils/export_utils.py:99 + cli.py:372` | config-drift | --format default disagreement |
| `src/oida/protocols/bacnet/mixins/state.py:104` | config-drift | _handle_dump silent no-op |
| `src/oida/protocols/bacnet/mixins/export.py:41` | config-drift | _export_results silent no-op |
| `src/oida/protocols/fhir/nxc_connection.py:491` | config-drift | _export_results silent no-op |
| ADS×18 + OPCUA×4 + EtherNet/IP sites | config-drift | mass `getattr(args, "format", "console")` no-op |

**MEDIUM (aggregated):**
- 2 confirm-gate: modbus `--test-write`, astm `--send-patient`.
- 2 cred-leak: mqtt fail log, snmp community at INFO.
- 3 timeout-as-success: bacnet `_handle_test_write`, BAC0 `_write_property` swallow, BACnet COV silent zero-notifications.
- 2 inverted-classifier: NBSS direction, PTP event/general.
- 4 parser-unbounded: FTP FEAT, CIP File Upload, FoE probe/file-browse, BACnet AtomicReadFile.
- 2 config-drift: `add_common_args` verbose type, PROTOCOL_ALIASES filename.
- ~55 garbled-log-string sites across 28 pcap listeners + active dnp3/profinet/coap/mqtt/eip/hl7. Single contract test catches them all in one shot.

**LOW (aggregated):**
- 1 cred-leak: SMTP AUTH LOGIN base64 in interaction summary.
- 1 timeout-as-success: EIP CIP Security timeout → "NOT SUPPORTED".
- 2 inverted-classifier: CoAP Empty Message, IKE rspi-zero direction.
- 2 parser-unbounded: BACnet AtomicReadFile, Profinet UDP drain.
- 1 config-drift: fuzz_cli verbose getattr fallback.
- 3 garbled-log-string fuzz/brute loops.

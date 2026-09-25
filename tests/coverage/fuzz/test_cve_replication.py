"""Axis 2 of the real-coverage suite: CVE replication.

For every vulnerable CVE mock in the docker stack, drive the matching
protocol fuzzer at it for a bounded number of test cases and record
whether the fuzzer triggered a crash. This is the only measurement that
scores the fuzzers by *outcome* (did they break a known-vulnerable
target) rather than by *reach* (how many mutations they emit).

Design:

- **Case discovery is dynamic.** Cases are built at collection time from
  the ``oida.*`` labels on ``docker/mocks/compose.cve.yml`` — the same
  source of truth ``services.py`` uses — so the host port, CVE id, and
  protocol never drift from the compose stack. There is no hand-kept
  container/port table to rot.

- **Scorecard, not pass/fail.** Every fuzzer x mock pair appends a record
  to ``tests/coverage/results/cve_replication_<run-id>.json`` with the
  crash outcome (or the skip/error reason). This is the trend artifact
  the nightly job publishes.

- **Curated hard assertions.** Only pairs listed in
  ``VERIFIED_REPRODUCTIONS`` are asserted to crash. A pair earns its place
  there after a human confirms, with the mock up, that the fuzzer really
  reproduces the CVE in ``CASE_CAP`` cases. Everything else is recorded
  without failing — an unproven pair is a data point, not a red build.

Marked ``cve_replication`` and ``slow`` so it stays out of the default
unit/integration sweep. Run explicitly with::

    python services.py up cve                       # or a subset, e.g. `up modbus`
    pytest tests/coverage/fuzz/ -m cve_replication -v

Or via the nightly job (``.github/workflows/coverage-nightly.yml``).
"""

from __future__ import annotations

import datetime
import json
import os
import pathlib
import shutil
import socket
import subprocess
from typing import Any, NamedTuple, Optional

import pytest

COMPOSE_CVE = pathlib.Path(__file__).resolve().parents[3] / "docker" / "mocks" / "compose.cve.yml"

# Default per-pair test-case budget. A bounded run: boofuzz stops at this
# mutation index (there is no ``max_test_cases`` field — the cap is
# ``index_end``). Override for a deeper nightly sweep via the env var.
CASE_CAP = int(os.environ.get("OIDA_CVE_CASE_CAP", "1500"))

# oida.group values that don't map 1:1 onto a PROTOCOL_FUZZERS key.
# (The SNMP mocks are one group; the fuzzer is versioned — v2c is the
# most representative agent-side parser.)
GROUP_TO_FUZZER = {
    "snmp": "snmpv2c",
}

# Fuzzers whose transport is UDP regardless of the compose port proto.
# Some CVE mocks publish their UDP service on a bare ``host:container``
# mapping (docker defaults that to tcp in the label), so the compose
# proto suffix alone under-detects UDP. These fuzzers self-select UDP at
# runtime; we mirror that here so the pre-probe and config agree.
UDP_FUZZERS = {
    "dns",
    "dhcp",
    "dhcpv6",
    "snmpv1",
    "snmpv2c",
    "snmpv3",
    "coap",
    "ntp",
    "tftp",
    "bacnet",
    "mdns",
}

# Pairs a human has confirmed reproduce their CVE against the live mock
# within CASE_CAP cases. These are hard-asserted to crash; grow this set
# as the nightly scorecard confirms reproductions. Keyed by
# (fuzzer_protocol, cve_id). A pair that becomes unreachable simply skips
# (the assertion runs only after a completed run), so this stays a
# regression check, not a flakiness source.
VERIFIED_REPRODUCTIONS: set[tuple[str, str]] = {
    # Verified 2026-08-01: the modbus fuzzer crashes the CVE-2024-10918
    # mock (uModbus OOB read) within ~31 cases — 21 crash cases recorded
    # at a 40-case cap.
    ("modbus", "CVE-2024-10918"),
    # Verified 2026-08-01: the iec104 fuzzer crashes the lib60870 handleASDU
    # null-deref mock (iec104-handleasdu-null, port 24042) — 1 crash recorded.
    ("iec104", "lib60870-handleASDU-nullderef"),
    # Verified 2026-08-01: the tftp fuzzer crashes atftpd CVE-2021-46671
    # (options-parsing use-after-poison) — the crash fires during the TFTP
    # read preflight probe (container exits with an ASan abort), caught by the
    # preflight-crash detection below.
    ("tftp", "CVE-2021-46671"),
    # Verified 2026-08-01: the dhcp fuzzer crashes dnsmasq CVE-2018-20679
    # (ASan DEADLYSIGNAL) during the DHCPDISCOVER preflight probe. Needed the
    # container-liveness signal to detect — the UDP socket re-probe reads
    # "still up" because docker-proxy holds the port after the mock dies.
    ("dhcp", "CVE-2018-20679"),
}


class CVECase(NamedTuple):
    cve_id: str
    container: str
    host_port: int
    fuzzer: str  # PROTOCOL_FUZZERS key
    transport: str  # "tcp" | "udp" | "iec104"


def _parse_labels(raw: Any) -> dict[str, str]:
    """Normalise a compose ``labels:`` value (list or dict) to a dict."""
    out: dict[str, str] = {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, str) and "=" in item:
                k, v = item.split("=", 1)
                out[k] = v
    return out


def _transport_for(fuzzer: str, ports: list) -> str:
    """Pick the fuzzer transport from the fuzzer name + compose port mappings."""
    if fuzzer == "iec104":
        return "iec104"
    if fuzzer in UDP_FUZZERS:
        return "udp"
    for entry in ports or []:
        if isinstance(entry, str) and entry.endswith("/udp"):
            return "udp"
    return "tcp"


def _discover_cve_cases() -> list[CVECase]:
    """Build the case list from compose.cve.yml ``oida.*`` labels.

    Returns an empty list (rather than raising) when the compose file or
    pyyaml is unavailable, so collection degrades to "no cases" instead
    of an error.
    """
    try:
        import yaml
    except ImportError:
        return []
    if not COMPOSE_CVE.exists():
        return []
    try:
        cfg = yaml.safe_load(COMPOSE_CVE.read_text()) or {}
    except yaml.YAMLError:
        return []

    try:
        from oida.fuzz.protocols import PROTOCOL_FUZZERS
    except ImportError:
        return []

    cases: list[CVECase] = []
    for svc in (cfg.get("services") or {}).values():
        labels = _parse_labels(svc.get("labels"))
        cve = labels.get("oida.cve")
        if not cve:
            continue  # not a CVE mock
        group = labels.get("oida.group") or labels.get("oida.protocol") or ""
        fuzzer = GROUP_TO_FUZZER.get(group, group)
        if fuzzer not in PROTOCOL_FUZZERS:
            continue  # no matching fuzzer for this mock
        port_label = labels.get("oida.ports", "")
        try:
            host_port = int(str(port_label).split(",")[0].split("/")[0].strip())
        except (ValueError, AttributeError):
            continue  # can't determine a host port
        container = svc.get("container_name") or fuzzer
        transport = _transport_for(fuzzer, svc.get("ports") or [])
        cases.append(CVECase(cve, container, host_port, fuzzer, transport))

    return sorted(cases, key=lambda c: (c.fuzzer, c.cve_id))


CVE_CASES = _discover_cve_cases()


def _mock_reachable(host: str, port: int, timeout: float = 1.0) -> bool:
    """TCP probe to skip pairs whose mock container isn't published."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _udp_reachable(host: str, port: int, timeout: float = 1.0) -> bool:
    """Best-effort UDP liveness probe.

    A connected UDP socket to a *closed* local port surfaces the ICMP
    port-unreachable as ``ConnectionRefusedError`` on the next recv — this
    is reliable on localhost, which is where the mocks publish. A timeout
    (no ICMP refusal) means "up but silent to a null probe" → treat as
    reachable so we still fuzz a live-but-quiet service. This keeps the
    offline sweep from running a full budget against a dead UDP port.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(b"\x00")
        try:
            sock.recv(1)
        except ConnectionRefusedError:
            return False
        except socket.timeout:
            return True
        return True
    except ConnectionRefusedError:
        return False
    except OSError:
        return True  # can't probe (e.g. no route) — let the fuzzer preflight decide
    finally:
        sock.close()


def _container_down(container: str) -> Optional[bool]:
    """Authoritative liveness for a named docker mock via ``docker inspect``.

    Returns True if the container exists and is NOT running (crashed/exited),
    False if it is running, and None if the answer is unknown (docker not on
    PATH, container not found, or inspect failed). This is more reliable than a
    socket probe for UDP mocks: docker-proxy keeps the published host port
    bound even after the backing container dies, so a UDP liveness probe sees
    no ICMP-refused and wrongly reports "up". Container state does not lie.
    """
    if not shutil.which("docker"):
        return None
    try:
        out = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", container],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    val = out.stdout.strip()
    if val == "false":
        return True
    if val == "true":
        return False
    return None


def _probe(host: str, port: int, transport: str, attempts: int = 3) -> bool:
    """Transport-aware reachability check with retries.

    Retries so a momentarily-slow mock isn't mistaken for a crashed one.
    Each underlying probe carries its own ~1s timeout, which spaces the
    attempts without an explicit sleep.
    """
    for _ in range(attempts):
        if transport == "udp":
            if _udp_reachable(host, port):
                return True
        elif _mock_reachable(host, port):
            return True
    return False


def _write_run_record(record: dict[str, Any]) -> None:
    """Append a scorecard record to the per-run JSON manifest.

    Mirrors the scanner coverage suite: all cases in one pytest run share
    a ``cve_replication_<run-id>.json`` file; the run-id comes from the
    nightly workflow's env var or defaults to ``manual-<date>``.
    """
    results_dir = pathlib.Path(__file__).resolve().parents[1] / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    run_id = os.environ.get(
        "OIDA_COVERAGE_RUN_ID",
        "manual-" + datetime.date.today().isoformat(),
    )
    out_path = results_dir / f"cve_replication_{run_id}.json"
    if out_path.exists():
        try:
            existing = json.loads(out_path.read_text())
        except json.JSONDecodeError:
            existing = []
    else:
        existing = []
    existing.append(record)
    out_path.write_text(json.dumps(existing, indent=2, sort_keys=True))


def _run_fuzzer_against(case: CVECase, host: str, db_stem: str) -> int:
    """Drive ``case.fuzzer`` at ``host:case.host_port`` for CASE_CAP cases.

    Returns the number of recorded crash test-cases. Raises
    ``ConnectionError`` if the fuzzer's preflight can't reach the target
    (caller converts that to a skip).
    """
    from oida.fuzz.core.config import FuzzerConfig, ProtocolType
    from oida.fuzz.core.database.orm import SQLAlchemyDatabase
    from oida.fuzz.protocols import PROTOCOL_FUZZERS

    proto_type = {
        "udp": ProtocolType.UDP,
        "iec104": ProtocolType.IEC104,
    }.get(case.transport, ProtocolType.TCP)

    cfg = FuzzerConfig(
        target_ip=host,
        target_port=case.host_port,
        protocol=case.fuzzer,
        protocol_type=proto_type,
        session_filename=db_stem,  # -> f"{db_stem}.db"
        index_start=1,
        index_end=CASE_CAP,  # the only case cap
        log_session=True,  # required for DB crash recording
        web_interface=False,  # don't bind the boofuzz web UI
        console_output=False,
        enumerate=False,  # skip capability probing
        calibrate=False,  # skip 50-probe timeout calibration
        reuse_target_connection=False,  # better crash detection
        pause_on_crash=False,  # never block on stdin
    )
    fuzzer = PROTOCOL_FUZZERS[case.fuzzer](cfg)  # default RealConnectionFactory

    run_exc: Optional[BaseException] = None
    try:
        fuzzer.fuzz_all()  # non-interactive
    except ConnectionError as exc:
        # Usually preflight (mock down) — but a hard crash mid-run can also
        # surface as a connection error. Read the DB before deciding.
        run_exc = exc
    except Exception as exc:  # noqa: BLE001
        # A fuzzer that crashes the target hard raises here ("target
        # unresponsive after N recovery attempts") — the crash IS recorded
        # in the DB, so this exception is a reproduction signal, not a bug.
        run_exc = exc

    # Read recorded crashes regardless of how fuzz_all() returned. A
    # non-zero count means the fuzzer broke the target — return it even
    # when fuzz_all() raised, because the raise *is* the crash.
    crash_count = 0
    try:
        db = SQLAlchemyDatabase(f"{db_stem}.db")
        db.init_schema()
        crash_count = len(db.get_test_cases(result_filter="crash", limit=None))
    except Exception:  # noqa: BLE001 - DB unreadable; fall through to exc handling
        crash_count = 0

    if crash_count > 0:
        return crash_count
    if run_exc is not None:
        raise run_exc  # no crash recorded → propagate for skip/error classification
    return 0


@pytest.mark.cve_replication
@pytest.mark.slow
# A bounded fuzz run legitimately outlives the repo's global 60s per-test
# timeout (reconnect-per-case makes it ~1 case/sec against some mocks). The
# global timeout would kill the run mid-flight BEFORE the scorecard record is
# written — turning a real result into a silent "no record". Disable it here so
# every pair always completes and records; the case budget (index_end) is the
# real bound.
@pytest.mark.timeout(0)
@pytest.mark.skipif(not CVE_CASES, reason="no CVE mocks discoverable in compose.cve.yml")
@pytest.mark.parametrize(
    "case",
    CVE_CASES,
    ids=[f"{c.fuzzer}-{c.cve_id}" for c in CVE_CASES],
)
def test_fuzzer_triggers_cve(case: CVECase, tmp_path):
    """Run the protocol fuzzer against its CVE mock; record the outcome.

    Writes a scorecard record for every pair. Hard-asserts a crash only
    for pairs in ``VERIFIED_REPRODUCTIONS``.
    """
    host = os.environ.get("OIDA_COVERAGE_HOST", "127.0.0.1")
    record: dict[str, Any] = {
        "cve_id": case.cve_id,
        "container": case.container,
        "target": f"{host}:{case.host_port}",
        "protocol": case.fuzzer,
        "transport": case.transport,
        "case_cap": CASE_CAP,
        "crashed": None,
        "crash_count": None,
        "skipped": None,
        "error": None,
        "note": None,
        "verified_pair": (case.fuzzer, case.cve_id) in VERIFIED_REPRODUCTIONS,
    }

    # Fast pre-probe so a down mock skips in ~1s instead of burning the
    # full case budget against a dead port. iec104 rides a TCP control
    # plane, so it uses the TCP probe.
    if case.transport == "udp":
        reachable = _udp_reachable(host, case.host_port)
    else:
        reachable = _mock_reachable(host, case.host_port)
    if not reachable:
        record["skipped"] = f"mock unreachable ({case.transport} pre-probe)"
        _write_run_record(record)
        pytest.skip(
            f"{case.container} not reachable on {host}:{case.host_port} "
            f"(run: python services.py up {case.fuzzer})"
        )

    crash_count: Optional[int] = None
    try:
        crash_count = _run_fuzzer_against(case, host, str(tmp_path / "cve_repro"))
        record["crashed"] = crash_count > 0
        record["crash_count"] = crash_count
    except Exception as exc:  # noqa: BLE001 - classify via liveness, don't red the sweep
        # ``_run_fuzzer_against`` already returns a positive count for any crash
        # the fuzzer DB captured, so reaching here means fuzz_all() raised
        # WITHOUT a recorded crash. Two possibilities, disambiguated by the
        # target's liveness — which the initial pre-probe confirmed was up:
        #   * target now DOWN  → the fuzzer (often its very first preflight probe)
        #     crashed it before any case was DB-recorded. That IS a reproduction,
        #     not a skip. Observed: atftpd CVE-2021-46671, dnsmasq CVE-2018-20679
        #     both crash on the preflight probe.
        #   * target still UP  → a flaky/over-strict preflight monitor or a real
        #     harness error, not a target crash → skip honestly.
        # Prefer container liveness (authoritative — a socket probe can't see a
        # crashed UDP mock behind docker-proxy, which keeps the host port bound);
        # fall back to the socket probe only when container state is unavailable.
        down = _container_down(case.container)
        crashed = down is True or (
            down is None and not _probe(host, case.host_port, case.transport)
        )
        if crashed:
            record["crashed"] = True
            record["crash_count"] = crash_count = 1
            record["note"] = f"crashed during fuzzer preflight/run ({type(exc).__name__}: {exc})"
        else:
            if isinstance(exc, ConnectionError):
                record["skipped"] = (
                    f"preflight unreachable (target still up — monitor false-negative?): {exc}"
                )
            else:
                record["error"] = f"{type(exc).__name__}: {exc}"
            _write_run_record(record)
            pytest.skip(f"{case.fuzzer} could not fuzz {case.container}: {exc}")

    _write_run_record(record)

    if (case.fuzzer, case.cve_id) in VERIFIED_REPRODUCTIONS:
        assert crash_count and crash_count >= 1, (
            f"{case.fuzzer} fuzzer did not trigger {case.cve_id} against "
            f"{case.container} in {CASE_CAP} cases (this is a VERIFIED pair — "
            f"a regression, or the mock changed)"
        )

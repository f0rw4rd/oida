"""Fleet-wide uniform connect-failure output, exercised through the real CLI.

The GH #59 unit tests (test_unified_connect_output.py) and the source-level
invariant (test_connect_failure_contract.py) pin the contract per module.
What neither catches is the assembled CLI: a runner whose create_conn_obj
was adopted but whose scanner still prints its own failure line, a banner
at debug level that never renders, a canonical line printing "host:None",
a port flag the subparser does not even accept.

This suite shells the real CLI (from this repo's src tree) for every
connect-capable protocol against a guaranteed-dead loopback target and
asserts the observable contract:

1. exactly one ``Connect failed: <cause>`` line,
2. a ``Connecting`` banner line before it,
3. the JSON export carries ``error: "connect <cause>..."`` and
   ``success: false``.

Target: ``127.0.0.1:45672`` in the embedded ``host:port`` form - the port is
held closed by simply not listening on it. TCP connects there fail with
ECONNREFUSED (deterministic on loopback, no external network needed); UDP
transports get silence, which their runners report as timeout. The
embedded form (not ``--port``) is deliberate: ethercat/profinet/fhir/goose
subparsers reject a ``--port`` flag outright, so the flag cannot be part of
the fleet-wide invocation.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SRC = str(Path(__file__).resolve().parents[3] / "src")

# Deterministic loopback target: the port is chosen to be free, then held
# closed by not listening on it. ECONNREFUSED on TCP, silence on UDP.
HOST = "127.0.0.1"
PORT = 45672
TARGET = f"{HOST}:{PORT}"

# Host:port token matcher for the per-line ``PROTO host:port`` prefixes and
# banner targets in the effective-port consistency sweep below.
_PREFIX_RE = re.compile(rf"\b{re.escape(HOST)}:(\d+)")

# Protocols with no single-target connect stage (passive listeners, local
# buses, request-response sweeps) - their runners are held to the
# source-level contract by test_connect_failure_contract.py instead.
_EXEMPT = {
    "pcap",  # passive file listener
    "discovery",  # interface sweep
    "snmp",  # UDP request-response sweep, no connect stage
    "can",  # local SocketCAN bus
    # pyads routes through the local AMS router (TCP 48898) and ignores the
    # target port entirely, so wherever a mock router is listening the
    # scan connects regardless of the dead port above - a false positive
    # in any environment that runs the oida docker mocks.
    "ads",
}

# Per-protocol overrides: (target, extra argv, expected cause) against the
# dead loopback endpoint. Defaults: embedded TARGET, no extras, "refused".
# UDP transports get silence = timeout. Portless / capability paths
# (ethercat raw socket) are driven to their connect path explicitly where
# the default mode is a passive discovery that never connects.
_PROTOCOL_OVERRIDES: dict[str, tuple[str, list[str], str]] = {
    # UDP transports: silence = timeout
    "bacnet": (TARGET, [], "timeout"),
    "coap": (TARGET, [], "timeout"),
    "hart": (TARGET, [], "timeout"),
    "knx": (TARGET, ["--device-info"], "timeout"),
    # Portless layer-2 bus: capability check gates the connect (container
    # runs unprivileged, so raw socket is denied -> permission)
    "ethercat": (TARGET, [], "permission"),
    # Hart-IP is UDP, but on loopback a closed port answers with ICMP
    # port-unreachable, which a connected socket surfaces as ECONNREFUSED -
    # the probe classifies it "refused", not the silent-network "timeout".
    "hart": (TARGET, [], "refused"),
    # MMS-backed enumeration: the connect target is the --mms-enum host,
    # not the positional (interface) target; --mms-port carries the port.
    "goose": (HOST, ["--mms-enum", HOST, "--mms-port", str(PORT)], "refused"),
    # RPC-only mode: UDP silence = timeout (default mode needs an interface)
    "profinet": (TARGET, ["--rpc-only"], "timeout"),
    # Plain HTTP, else the dead port looks like a TLS failure
    "fhir": (TARGET, ["--no-tls"], "refused"),
}


# Effective-port variants: modes whose REAL port differs from the protocol's
# default_port. Each case runs against the same dead loopback endpoint, so the
# run fails - but everything it prints (and exports) must agree on the port it
# actually targeted. This is the fleet guard for the shipped bug class where a
# banner/probe/failure-line/logger-prefix drifted from the port the connect
# ran on (iec104 banner, coap DTLS, mqtt TLS; goose mms_port, dicom 2762).
# Rows: (protocol, argv, expected_port). Target is the dead HOST:PORT embedded
# in argv itself - these flags change the effective port, so --port/embedded
# forms vary per case.
_PORT_VARIANTS: list[tuple[str, list[str], int]] = [
    # -p wins over everything: banner, failure line, prefixes all show it.
    ("iec104", [HOST, "--port", str(PORT)], PORT),
    # DTLS switches the default to 5684 when no -p is given.
    ("coap", ["--dtls-rpk", "deadbeef", HOST], 5684),
    # --tls switches the default to 8883 when no -p is given.
    ("mqtt", [HOST, "--tls"], 8883),
    # Explicit -p wins even over the TLS default (the pre-fix mqtt bug).
    ("mqtt", [HOST, "--tls", "--port", "1883"], 1883),
    # --tls switches the default to 2762 when no -p is given.
    ("dicom", [HOST, "--tls"], 2762),
    # --mms-enum carries its own port via --mms-port.
    ("goose", ["--mms-enum", HOST, "--mms-port", str(PORT)], PORT),
]


def _live_protocols() -> list[str]:
    """Ask the loader, in a subprocess, for the registered protocol names."""
    code = (
        "from oida.loader import ProtocolLoader; "
        "print(' '.join(sorted(ProtocolLoader("
        + repr(SRC + "/oida/protocols")
        + ").get_protocols())))"
    )
    out = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=120,
        env={**os.environ, "PYTHONPATH": SRC},
    )
    if out.returncode != 0:
        raise RuntimeError(f"loader subprocess failed: {out.stderr[:500]}")
    return out.stdout.split()


def _connect_capable_cases() -> list[tuple[str, str, list[str], str]]:
    """(protocol, target, extra argv, expected cause) per protocol."""
    cases = []
    for name in _live_protocols():
        if name in _EXEMPT:
            continue
        target, extra, cause = _PROTOCOL_OVERRIDES.get(name, (TARGET, [], "refused"))
        cases.append((name, target, extra, cause))
    return cases


class TestFleetConnectOutput(unittest.TestCase):
    """Every connect-capable protocol prints the same failure shape."""

    maxDiff = None

    @classmethod
    def setUpClass(cls):
        # Sanity: the chosen port must not be in use (nothing listening).
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind((HOST, PORT))
        except OSError as e:
            raise unittest.SkipTest(f"port {PORT} busy: {e}") from e
        finally:
            probe.close()

    def _run_cli(self, protocol: str, target: str, extra: list[str]) -> tuple[str, str, str]:
        cmd = [sys.executable, "-m", "oida.cli", protocol, target, *extra]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=90,
            cwd=Path(SRC).parent,
            env={**os.environ, "PYTHONPATH": SRC},
        )
        return proc.stdout, proc.stderr, str(proc.returncode)

    def test_fleet_connect_failure_shape(self):
        failures = []
        for protocol, target, extra, expected_cause in _connect_capable_cases():
            with self.subTest(protocol=protocol):
                stdout, stderr, rc = self._run_cli(protocol, target, extra)
                combined = stdout + stderr

                fail_lines = [ln for ln in combined.splitlines() if "Connect failed:" in ln]
                self.assertEqual(
                    len(fail_lines),
                    1,
                    f"{protocol}: expected exactly 1 'Connect failed:' line, got {len(fail_lines)}\n"
                    f"output:\n{combined}",
                )
                self.assertIn(
                    f"Connect failed: {expected_cause}",
                    fail_lines[0],
                    f"{protocol}: wrong cause in {fail_lines[0]!r}\noutput:\n{combined}",
                )
                # No target=port garbage in the canonical line.
                self.assertNotIn(":None", fail_lines[0], f"{protocol}: port rendered as None")
                self.assertNotIn(":0)", fail_lines[0], f"{protocol}: port rendered as 0")

                banner = [ln for ln in combined.splitlines() if "Connecting" in ln]
                self.assertTrue(
                    banner,
                    f"{protocol}: no Connecting banner before failure\noutput:\n{combined}",
                )

                if rc == "0":
                    failures.append(f"{protocol}: exit code 0 on connect failure")
        self.assertFalse("\n".join(failures), "\n".join(failures))

    def test_fleet_effective_port_consistency(self):
        """Alternate-port modes: every line and the export agree on the port.

        For each variant: the Connecting banner, every ``PROTO host:port``
        prefix, the Connect failed line, and the JSON export's ``port`` field
        must all show the port the connect actually targeted. A runner that
        stamps one of args.port / results["port"] / logger.extra["port"] but
        not the others shows up here as a disagreement between its own lines.
        """
        failures = []
        for protocol, argv, expected_port in _PORT_VARIANTS:
            with self.subTest(protocol=protocol, port=expected_port):
                # One CLI run feeds all assertions: --output/--format json
                # does not suppress stdout, so the same process yields both
                # the log lines (banner, prefixes, Connect failed) and the
                # JSON export.
                with tempfile.TemporaryDirectory() as out_dir:
                    proc = subprocess.run(
                        [
                            sys.executable,
                            "-m",
                            "oida.cli",
                            protocol,
                            *argv,
                            "--output",
                            out_dir,
                            "--format",
                            "json",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=90,
                        cwd=Path(SRC).parent,
                        env={**os.environ, "PYTHONPATH": SRC},
                    )
                    combined = proc.stdout + proc.stderr
                    lines = combined.splitlines()
                    want = f"{HOST}:{expected_port}"

                    banner = [ln for ln in lines if "Connecting" in ln]
                    if not banner:
                        failures.append(f"{protocol}: no Connecting banner\n{combined}")
                    elif want not in banner[0]:
                        failures.append(
                            f"{protocol}: banner {banner[0]!r} lacks {want}\n{combined}"
                        )

                    # Every prefixed line must carry the effective port. The
                    # prefix is ``PROTO host:port`` - the port token after the
                    # host must be the expected one, not a stale default.
                    bad = [
                        ln
                        for ln in lines
                        for m in [_PREFIX_RE.search(ln)]
                        if m and int(m.group(1)) != expected_port
                    ]
                    # The invocation line ("oida <proto> host:port") legitimately
                    # shows the embedded/default target, not the effective port.
                    bad = [ln for ln in bad if not ln.lstrip().startswith("oida ")]
                    if bad:
                        failures.append(
                            f"{protocol}: lines disagree on port {expected_port}:\n"
                            + "\n".join(bad)
                        )

                    # JSON export must carry the same port.
                    files = list(Path(out_dir).glob("*.json"))
                    if not files:
                        failures.append(f"{protocol}: no JSON export\n{proc.stdout}{proc.stderr}")
                        continue
                    data = json.loads(files[0].read_text())
                    row = data[0] if isinstance(data, list) else data
                    if row.get("port") != expected_port:
                        failures.append(
                            f"{protocol}: JSON port {row.get('port')!r} != {expected_port}"
                        )
        self.assertFalse("\n".join(failures), "\n".join(failures))

    def test_fleet_connect_json_contract(self):
        """--format json --output exports the failure in the JSON contract."""
        with tempfile.TemporaryDirectory() as tmp:
            for protocol, target, extra, expected_cause in _connect_capable_cases():
                with self.subTest(protocol=protocol):
                    out_dir = Path(tmp) / protocol
                    out_dir.mkdir()
                    cmd = [
                        sys.executable,
                        "-m",
                        "oida.cli",
                        protocol,
                        target,
                        *extra,
                        "--format",
                        "json",
                        "--output",
                        str(out_dir),
                    ]
                    proc = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=90,
                        cwd=Path(SRC).parent,
                        env={**os.environ, "PYTHONPATH": SRC},
                    )
                    # Find the JSON file the run wrote
                    files = list(out_dir.glob("*.json"))
                    self.assertTrue(
                        files, f"{protocol}: no JSON export produced\nstdout:\n{proc.stdout}"
                    )
                    data = json.loads(files[0].read_text())
                    rows = data if isinstance(data, list) else data.get("results", [data])
                    row = rows[-1] if isinstance(rows, list) else rows
                    self.assertFalse(row.get("success"), f"{protocol}: success true on failure")
                    self.assertTrue(
                        str(row.get("error", "")).startswith(f"connect {expected_cause}"),
                        f"{protocol}: error was {row.get('error')!r}",
                    )


if __name__ == "__main__":
    unittest.main()

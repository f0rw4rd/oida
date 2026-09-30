"""Multi-target sweep console output must not interleave per-target blocks.

The GH-style bug this pins: with N ThreadPoolExecutor workers each streaming
their scan lines as they happen, a CIDR sweep shuffles every host's output
line by line and buries findings in noise from dead hosts. The fix buffers
each target's console lines and emits them as one contiguous block when the
target completes, with the progress counter thinned to ~10% steps in piped
output (one line per target would add hundreds of lines to a /24).

This contract suite shells the real CLI (same harness style as
tests/integration/common/test_fleet_connect_output.py) against dead
loopback targets -- ECONNREFUSED is deterministic on loopback, no docker
mocks, no external network -- and asserts the observable sweep contract:

1. Contiguity: no host's lines appear strictly inside another host's block.
2. Exactly one ``Connect failed:`` line per host (the unified contract
   survives the new buffering).
3. Piped progress lines are bounded: ~10% steps, not one per target.

Runs without docker and without the network, per the contracts rule.
"""

from __future__ import annotations

import math
import os
import re
import socket
import subprocess
import sys
import unittest
from pathlib import Path

SRC = str(Path(__file__).resolve().parents[2] / "src")

HOST = "127.0.0.1"
PORT = 45672
TARGET = f"{HOST}:{PORT}"

# Match the per-line ``PROTO host:port`` prefix. Protocol token is a run of
# non-space printable chars (names contain "/" for HTTPS variants and digits
# like IEC104); host is captured without the port.
_PREFIX_RE = re.compile(r"^\S+\s+(\d{1,3}(?:\.\d{1,3}){3}):\d+\s")

# Sweep size: small (fast, sub-second even with per-target timeouts) but
# larger than the default worker count, so blocks genuinely overlap in time.
SWEEP_TARGETS = ["127.0.0.1:45672", "127.0.0.2:45672", "127.0.0.3:45672", "127.0.0.4:45672"]


class TestSweepOutputGrouping(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        # The port must be dead (nothing listening) so connects fail fast.
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind((HOST, PORT))
        except OSError as e:
            raise unittest.SkipTest(f"port {PORT} busy: {e}") from e
        finally:
            probe.close()

    def _run_sweep(self, protocol: str, extra: list[str]) -> str:
        cmd = [sys.executable, "-m", "oida.cli", protocol, ",".join(SWEEP_TARGETS), *extra]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(Path(SRC).parent),
            env={**os.environ, "PYTHONPATH": SRC},
        )
        return proc.stdout + proc.stderr

    def test_blocks_are_contiguous(self):
        # s7/snap7: TCP connect, fast ECONNREFUSED on dead loopback ports.
        combined = self._run_sweep("s7", ["--timeout", "3"])
        positions: dict[str, list[int]] = {}
        for i, line in enumerate(combined.splitlines()):
            m = _PREFIX_RE.match(line)
            if m:
                positions.setdefault(m.group(1), []).append(i)

        self.assertTrue(positions, f"no per-host prefixed lines found\noutput:\n{combined}")

        for host, idx in positions.items():
            span = set(range(idx[0], idx[-1] + 1))
            for other, oidx in positions.items():
                if other == host:
                    continue
                overlap = span & set(oidx)
                self.assertFalse(
                    overlap,
                    f"host {other} lines {sorted(overlap)} fall inside {host}'s block "
                    f"({idx[0]}..{idx[-1]})\noutput:\n{combined}",
                )

    def test_one_connect_failed_line_per_host(self):
        combined = self._run_sweep("s7", ["--timeout", "3"])
        fail_lines = [ln for ln in combined.splitlines() if "Connect failed:" in ln]
        self.assertEqual(
            len(fail_lines),
            len(SWEEP_TARGETS),
            f"expected one 'Connect failed:' line per target, got {len(fail_lines)}\n"
            f"output:\n{combined}",
        )

    def test_piped_progress_bounded(self):
        combined = self._run_sweep("s7", ["--timeout", "3"])
        progress = [ln for ln in combined.splitlines() if "Progress:" in ln]
        # ~10% steps + the final 100% line; allow one either side for small
        # totals where every step crosses a boundary (same as pre-fix).
        bound = math.ceil(100 / 10) + 1
        self.assertLessEqual(
            len(progress),
            bound,
            f"{len(progress)} progress lines exceeds bound {bound}\noutput:\n{combined}",
        )


if __name__ == "__main__":
    unittest.main()

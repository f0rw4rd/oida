"""Axis 3 of the real-coverage suite: Conpot-vs-Python-mock fidelity diff.

For each protocol Conpot supports (modbus, s7, iec104, enip, bacnet),
run the scanner against the Conpot container AND against our Python
mock. Diff the resulting ``results["data"]`` dicts and classify each
disagreement:

- **both wrong, differently**: both mocks are simulations; scanner reads
  what each provides. No bug.
- **python lies**: Python mock returns something Conpot doesn't —
  Python mock has trained the scanner on fiction.
- **python incomplete**: Conpot returns something Python mock doesn't —
  integration tests under-test the scanner.

Conpot is treated as the ground-truth proxy (it's also a simulation,
but it tries to mimic real vendor behaviour — Siemens S7-1200, Schneider
Modicon, Triconex). The diff catches Python-mock invention, not
absolute correctness.

Marked ``slow`` and ``fidelity`` so it doesn't run in the default
unit / integration sweep. Run explicitly with::

    pytest tests/coverage/fidelity/ -m fidelity -v

Or in the nightly CI job. This file is the scaffold; per-protocol
classification rules land as the diff stabilises.
"""

from __future__ import annotations

import json
import socket
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

# Per-protocol (conpot_container, conpot_port, python_mock_container, python_mock_port).
# Conpot is treated as ground-truth proxy; Python mock is the unit-under-test.
CONPOT_FIDELITY_CASES: list[tuple[str, str, int, str, int]] = [
    ("modbus", "modbus-conpot", 502, "modbus-mock", 502),
    ("s7", "s7comm-snap7", 102, "s7comm-snap7", 102),  # no python mock yet — placeholder
    ("iec104", "iec104-conpot", 2409, "iec104-lib60870", 2404),
    ("ethernetip", "ethernetip-conpot", 44823, "ethernetip-mock", 44818),
    ("bacnet", "bacnet-conpot", 47808, "bacnet-mock", 47808),
]


def _mock_reachable(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _results_dir() -> Path:
    """Where to write per-run diff manifests (gitignored)."""
    p = Path(__file__).resolve().parent.parent / "results"
    p.mkdir(parents=True, exist_ok=True)
    return p


@pytest.mark.fidelity
@pytest.mark.slow
@pytest.mark.parametrize(
    "protocol,conpot_container,conpot_port,python_container,python_port",
    CONPOT_FIDELITY_CASES,
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_conpot_vs_python_mock(
    protocol: str,
    conpot_container: str,
    conpot_port: int,
    python_container: str,
    python_port: int,
):
    """Diff scanner output between Conpot and the Python mock.

    Currently a SCAFFOLD: skips when either mock isn't reachable on
    localhost. The per-protocol scanner invocation, normalisation, and
    diff classification land as the harness matures.
    """
    host = "127.0.0.1"

    if not _mock_reachable(host, conpot_port):
        pytest.skip(
            f"Conpot {conpot_container} not reachable on {host}:{conpot_port} "
            f"(run: docker compose -f docker/mocks/compose.yml up -d {conpot_container})"
        )
    if not _mock_reachable(host, python_port):
        pytest.skip(f"Python mock {python_container} not reachable on {host}:{python_port}")

    # TODO(coverage axis 3): run the scanner against both endpoints,
    # diff results["data"], classify each disagreement, write manifest.
    # Sketch:
    #   from oida.loader import ProtocolLoader
    #   cls = ProtocolLoader('src/oida/protocols').load_protocol_class(protocol)
    #   conpot_out = run(cls, host, conpot_port)
    #   python_out = run(cls, host, python_port)
    #   diff = diff_results(conpot_out, python_out)
    #   classified = classify(diff)  # both_wrong / python_lies / python_incomplete
    #   _write_manifest(protocol, classified)
    #   assert classified.python_lies == [], f"Python mock invents data: {classified.python_lies}"
    pytest.skip("Fidelity-diff harness pending")


def _write_manifest(protocol: str, classified: dict[str, Any]) -> Path:
    """Write per-protocol diff manifest to ``tests/coverage/results/fidelity_<date>.json``.

    Manifest format::

        {
          "protocol": "modbus",
          "timestamp": "2026-06-02T16:00:00",
          "diffs": [{"field": "...", "conpot": "...", "python": "...", "class": "python_lies"}, ...],
          "summary": {"both_wrong": N, "python_lies": M, "python_incomplete": K}
        }
    """
    date = datetime.now().strftime("%Y%m%d")
    path = _results_dir() / f"fidelity_{date}.json"
    existing: dict[str, Any] = {}
    if path.exists():
        existing = json.loads(path.read_text())
    existing[protocol] = {
        "timestamp": datetime.now().isoformat(),
        **classified,
    }
    path.write_text(json.dumps(existing, indent=2, default=str))
    return path

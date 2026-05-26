"""Scanner field-coverage % per protocol.

For each protocol with a known mock target in the docker stack, run the
scanner with a maximal-feature scan against the target, then compute
two coverage numbers:

- **Wire coverage**: fraction of fields in ``ref/<proto>/tshark_fields.json``
  that show up in the scanner's result tree. (Low bar — these are
  framing fields.)
- **Semantic coverage**: fraction of ``EXPECTED_SURFACE[proto]`` keys
  actually populated by the scan.

Results are written to ``tests/coverage/results/scanner_<run-id>.json``
for nightly trendline tracking.

Tests are skipped when the target container isn't reachable. This file
is **not** part of the PR test path — only the nightly coverage job
runs it.
"""

from __future__ import annotations

import datetime
import json
import os
import pathlib
from typing import Any

import pytest

from .conftest import container_target, ensure_protocol_dep, flatten_surface, make_args
from .surface import expected_for

REF_ROOT = pathlib.Path(__file__).resolve().parents[2].parent / "ref"


def _load_tshark_fields(protocol: str) -> set[str]:
    """Return the set of tshark dissector field names for a protocol."""
    path = REF_ROOT / protocol / "tshark_fields.json"
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return set()
    fields = data.get("dissector_fields", {}).get("fields", [])
    return {f["name"] for f in fields if isinstance(f, dict) and "name" in f}


def _write_run_record(results_dir: str, record: dict[str, Any]) -> None:
    """Append a coverage record to the per-run JSON manifest.

    All test cases in a single pytest run share one ``scanner_<ISO>.json``
    file. The run-id comes from an env var (set by the nightly workflow)
    or defaults to "manual-<date>".
    """
    run_id = os.environ.get(
        "OIDA_COVERAGE_RUN_ID",
        "manual-" + datetime.date.today().isoformat(),
    )
    out_path = pathlib.Path(results_dir) / f"scanner_{run_id}.json"
    if out_path.exists():
        try:
            existing = json.loads(out_path.read_text())
        except json.JSONDecodeError:
            existing = []
    else:
        existing = []
    existing.append(record)
    out_path.write_text(json.dumps(existing, indent=2, sort_keys=True))


# --------------------------------------------------------------------------- #
# Protocol-specific tests
# --------------------------------------------------------------------------- #


@pytest.mark.coverage
def test_modbus_coverage(coverage_results_dir):
    """Modbus scanner coverage against modbus-mock (port 502)."""
    ensure_protocol_dep("pymodbus")
    host, port, target_name = container_target(
        ("modbus-mock", 502),
        ("modbus-conpot", 5503),
    )

    from oida.protocols.modbus.nxc_connection import modbus

    args = make_args(
        port=port,
        scan_range="0-100",
        unit_id=1,
        device_info=True,
        function_codes=True,
        rhost=host,
    )
    scanner = modbus(args, None, host)
    populated = flatten_surface(scanner.results.get("data", {}))
    expected = expected_for("modbus")

    semantic_hit = populated & expected
    semantic_miss = expected - populated
    semantic_pct = 100.0 * len(semantic_hit) / max(len(expected), 1)

    wire_fields = _load_tshark_fields("modbus")
    # Wire coverage for modbus is a low bar (only 7 MBAP fields). We
    # check it's reported, not asserted, since the scanner doesn't
    # populate raw mbtcp.* fields directly — it parses them into
    # semantic structures.
    wire_pct = 0.0  # see comment above; placeholder for parity with other protocols

    _write_run_record(
        coverage_results_dir,
        {
            "protocol": "modbus",
            "target": f"{host}:{port}",
            "target_name": target_name,
            "semantic_coverage_pct": round(semantic_pct, 1),
            "semantic_populated": sorted(semantic_hit),
            "semantic_missing": sorted(semantic_miss),
            "wire_coverage_pct": wire_pct,
            "wire_field_count": len(wire_fields),
        },
    )

    # Assertion: at least one expected key was populated. The test
    # surfaces *trends*, not pass/fail per-run.
    assert semantic_hit, (
        f"modbus scanner populated none of the expected keys: "
        f"expected={sorted(expected)}, populated={sorted(populated)}"
    )


@pytest.mark.coverage
def test_iec104_coverage(coverage_results_dir):
    """IEC 104 scanner coverage against iec104-mock (port 2404)."""
    ensure_protocol_dep("c104")
    host, port, target_name = container_target(
        ("iec104-mock", 2404),
        ("iec104-conpot", 2409),
    )

    from oida.protocols.iec104.nxc_connection import iec104

    args = make_args(
        port=port,
        common_address=1,
        interrogate=True,
        rhost=host,
    )
    scanner = iec104(args, None, host)
    populated = flatten_surface(scanner.results.get("data", {}))
    expected = expected_for("iec104")

    semantic_hit = populated & expected
    semantic_pct = 100.0 * len(semantic_hit) / max(len(expected), 1)

    _write_run_record(
        coverage_results_dir,
        {
            "protocol": "iec104",
            "target": f"{host}:{port}",
            "target_name": target_name,
            "semantic_coverage_pct": round(semantic_pct, 1),
            "semantic_populated": sorted(semantic_hit),
            "semantic_missing": sorted(expected - populated),
        },
    )
    assert semantic_hit


@pytest.mark.coverage
def test_ethernetip_coverage(coverage_results_dir):
    """EtherNet/IP scanner coverage against ethernetip-mock (port 44818)."""
    ensure_protocol_dep("pycomm3")
    host, port, target_name = container_target(
        ("ethernetip-mock", 44818),
        ("ethernetip-conpot", 44823),
    )

    from oida.protocols.ethernetip.nxc_connection import ethernetip

    args = make_args(port=port, rhost=host)
    scanner = ethernetip(args, None, host)
    populated = flatten_surface(scanner.results.get("data", {}))
    expected = expected_for("ethernetip")

    semantic_hit = populated & expected
    semantic_pct = 100.0 * len(semantic_hit) / max(len(expected), 1)

    _write_run_record(
        coverage_results_dir,
        {
            "protocol": "ethernetip",
            "target": f"{host}:{port}",
            "target_name": target_name,
            "semantic_coverage_pct": round(semantic_pct, 1),
            "semantic_populated": sorted(semantic_hit),
            "semantic_missing": sorted(expected - populated),
        },
    )
    assert semantic_hit


@pytest.mark.coverage
def test_dnp3_coverage(coverage_results_dir):
    """DNP3 scanner coverage against dnp3-basic (port 20000)."""
    ensure_protocol_dep("yadnp3")
    host, port, target_name = container_target(("dnp3-basic", 20000))

    from oida.protocols.dnp3.nxc_connection import dnp3

    args = make_args(
        port=port,
        outstation_addr=1024,
        rhost=host,
    )
    scanner = dnp3(args, None, host)
    populated = flatten_surface(scanner.results.get("data", {}))
    expected = expected_for("dnp3")

    semantic_hit = populated & expected
    semantic_pct = 100.0 * len(semantic_hit) / max(len(expected), 1)

    _write_run_record(
        coverage_results_dir,
        {
            "protocol": "dnp3",
            "target": f"{host}:{port}",
            "target_name": target_name,
            "semantic_coverage_pct": round(semantic_pct, 1),
            "semantic_populated": sorted(semantic_hit),
            "semantic_missing": sorted(expected - populated),
        },
    )
    assert semantic_hit


@pytest.mark.coverage
def test_bacnet_coverage(coverage_results_dir):
    """BACnet scanner coverage against bacnet-mock (UDP 47808)."""
    ensure_protocol_dep("bacpypes3")
    host, port, target_name = container_target(
        ("bacnet-mock", 47808),
        ("bacnet-conpot", 47812),
        udp=True,
    )

    from oida.protocols.bacnet.nxc_connection import bacnet

    args = make_args(
        port=port,
        who_is=True,
        rhost=host,
    )
    scanner = bacnet(args, None, host)
    populated = flatten_surface(scanner.results.get("data", {}))
    expected = expected_for("bacnet")

    semantic_hit = populated & expected
    semantic_pct = 100.0 * len(semantic_hit) / max(len(expected), 1)

    _write_run_record(
        coverage_results_dir,
        {
            "protocol": "bacnet",
            "target": f"{host}:{port}",
            "target_name": target_name,
            "semantic_coverage_pct": round(semantic_pct, 1),
            "semantic_populated": sorted(semantic_hit),
            "semantic_missing": sorted(expected - populated),
        },
    )
    assert semantic_hit


@pytest.mark.coverage
def test_ads_coverage(coverage_results_dir):
    """ADS scanner coverage against ads-mock (port 48898)."""
    ensure_protocol_dep("pyads")
    host, port, target_name = container_target(("ads-mock", 48898))

    from oida.protocols.ads.nxc_connection import ads

    args = make_args(
        port=port,
        device_info=True,
        rhost=host,
    )
    scanner = ads(args, None, host)
    populated = flatten_surface(scanner.results.get("data", {}))
    expected = expected_for("ads")

    semantic_hit = populated & expected
    semantic_pct = 100.0 * len(semantic_hit) / max(len(expected), 1)

    _write_run_record(
        coverage_results_dir,
        {
            "protocol": "ads",
            "target": f"{host}:{port}",
            "target_name": target_name,
            "semantic_coverage_pct": round(semantic_pct, 1),
            "semantic_populated": sorted(semantic_hit),
            "semantic_missing": sorted(expected - populated),
        },
    )
    assert semantic_hit

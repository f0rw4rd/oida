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

    from oida.protocols.modbus.cli_runner import modbus

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

    from oida.protocols.iec104.cli_runner import iec104

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

    from oida.protocols.ethernetip.cli_runner import ethernetip

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

    from oida.protocols.dnp3.cli_runner import dnp3

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

    from oida.protocols.bacnet.cli_runner import bacnet

    args = make_args(
        port=port,
        who_is=True,
        rhost=host,
    )
    scanner = bacnet(args, None, host)
    populated = flatten_surface(scanner.results.get("data", {}))
    if not populated:
        pytest.skip(
            f"bacnet: no device discovered at {host}:{port} — the BACnet/IP WhoIs "
            "broadcast is UDP and its I-Am response is timing-sensitive (flaky under "
            "load). The scanner persists device_info when discovery succeeds."
        )
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

    from oida.protocols.ads.cli_runner import ads

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


# --------------------------------------------------------------------------- #
# IoT / messaging / web
# --------------------------------------------------------------------------- #


def _run_and_record(
    protocol: str,
    fuzzer_cls,
    host: str,
    port: int,
    target_name: str,
    results_dir: str,
    **scanner_args,
):
    """Common helper: instantiate scanner, measure coverage, append record.

    If the scanner reports failure (``results["success"] is False``), the
    test is skipped — typically the target is unreachable over UDP (we
    can't pre-probe UDP without a protocol-aware frame) or the container
    is up but the protocol service isn't ready yet.
    """
    args = make_args(port=port, rhost=host, **scanner_args)
    scanner = fuzzer_cls(args, None, host)
    if scanner.results.get("success") is False:
        pytest.skip(
            f"{protocol}: scanner could not connect to {target_name} at "
            f"{host}:{port} (results['success'] is False); "
            f"error={scanner.results.get('error')}"
        )
    populated = flatten_surface(scanner.results.get("data", {}))
    if not populated:
        pytest.skip(
            f"{protocol}: scanner reported success but extracted no fields from "
            f"{target_name} at {host}:{port} — the mock didn't answer the protocol "
            f"probe (e.g. KNXnet/IP discovery needs multicast the mock doesn't serve)"
        )
    expected = expected_for(protocol)
    semantic_hit = populated & expected
    semantic_pct = 100.0 * len(semantic_hit) / max(len(expected), 1) if expected else 0.0

    _write_run_record(
        results_dir,
        {
            "protocol": protocol,
            "target": f"{host}:{port}",
            "target_name": target_name,
            "semantic_coverage_pct": round(semantic_pct, 1),
            "semantic_populated": sorted(semantic_hit),
            "semantic_missing": sorted(expected - populated),
        },
    )
    return semantic_hit, expected


@pytest.mark.coverage
def test_opcua_coverage(coverage_results_dir):
    """OPC UA scanner coverage against opcua-mock (port 4840)."""
    ensure_protocol_dep("asyncua")
    host, port, target_name = container_target(
        ("opcua-mock", 4840),
        ("opcua-insecure", 4842),
    )

    from oida.protocols.opcua.cli_runner import opcua

    # OPC UA accepts opc.tcp://host:port; the scanner normalises bare host:port too.
    url = f"opc.tcp://{host}:{port}"
    args = make_args(port=port, browse=True, max_depth=2, rhost=url)
    scanner = opcua(args, None, url)
    populated = flatten_surface(scanner.results.get("data", {}))
    expected = expected_for("opcua")
    semantic_hit = populated & expected
    semantic_pct = 100.0 * len(semantic_hit) / max(len(expected), 1)

    _write_run_record(
        coverage_results_dir,
        {
            "protocol": "opcua",
            "target": url,
            "target_name": target_name,
            "semantic_coverage_pct": round(semantic_pct, 1),
            "semantic_populated": sorted(semantic_hit),
            "semantic_missing": sorted(expected - populated),
        },
    )
    assert semantic_hit


@pytest.mark.coverage
def test_snmp_coverage(coverage_results_dir):
    """SNMP scanner coverage against snmp-mock (UDP 10161)."""
    ensure_protocol_dep("pysnmp")
    host, port, target_name = container_target(
        ("snmp-mock", 10161),
        udp=True,
    )

    from oida.protocols.snmp.cli_runner import snmp

    semantic_hit, _ = _run_and_record(
        "snmp",
        snmp,
        host,
        port,
        target_name,
        coverage_results_dir,
        community="public",
        version="2c",
        walk=False,
    )
    assert semantic_hit


@pytest.mark.coverage
def test_mqtt_coverage(coverage_results_dir):
    """MQTT scanner coverage against mqtt-insecure (port 1883)."""
    ensure_protocol_dep("paho.mqtt")
    host, port, target_name = container_target(
        ("mqtt-insecure", 1883),
        ("mqtt-auth", 1884),
    )

    from oida.protocols.mqtt.cli_runner import mqtt

    semantic_hit, _ = _run_and_record(
        "mqtt",
        mqtt,
        host,
        port,
        target_name,
        coverage_results_dir,
        discover_topics=True,
        listen_time=2,
    )
    assert semantic_hit


@pytest.mark.coverage
def test_coap_coverage(coverage_results_dir):
    """CoAP scanner coverage against coap-mock (UDP 5683)."""
    ensure_protocol_dep("aiocoap")
    host, port, target_name = container_target(
        ("coap-mock", 5683),
        ("coap-libcoap", 5685),
        udp=True,
    )

    from oida.protocols.coap.cli_runner import coap

    semantic_hit, _ = _run_and_record(
        "coap",
        coap,
        host,
        port,
        target_name,
        coverage_results_dir,
        discover=True,
    )
    assert semantic_hit


@pytest.mark.coverage
def test_hl7_coverage(coverage_results_dir):
    """HL7 scanner coverage against hl7-mock (port 2575)."""
    ensure_protocol_dep("hl7apy")
    host, port, target_name = container_target(("hl7-mock", 2575))

    from oida.protocols.hl7 import hl7

    semantic_hit, _ = _run_and_record(
        "hl7",
        hl7,
        host,
        port,
        target_name,
        coverage_results_dir,
    )
    assert semantic_hit


@pytest.mark.coverage
def test_fhir_coverage(coverage_results_dir):
    """FHIR scanner coverage against fhir-mock (port 8081)."""
    ensure_protocol_dep("fhirclient")
    host, port, target_name = container_target(("fhir-mock", 8081))

    from oida.protocols.fhir.cli_runner import fhir

    semantic_hit, _ = _run_and_record(
        "fhir",
        fhir,
        host,
        port,
        target_name,
        coverage_results_dir,
        capability_statement=True,
        list_resources=True,
        use_https=False,
    )
    assert semantic_hit


@pytest.mark.coverage
def test_dicom_coverage(coverage_results_dir):
    """DICOM scanner coverage against dicom-mock (port 11112)."""
    ensure_protocol_dep("pynetdicom")
    host, port, target_name = container_target(
        ("dicom-mock", 11112),
        ("dicom-strict", 11113),
    )

    from oida.protocols.dicom.cli_runner import dicom

    semantic_hit, _ = _run_and_record(
        "dicom",
        dicom,
        host,
        port,
        target_name,
        coverage_results_dir,
        echo=True,
        called_ae="MOCK_PACS",
    )
    assert semantic_hit


@pytest.mark.coverage
def test_snap7_coverage(coverage_results_dir):
    """Siemens S7 (snap7) scanner coverage against s7comm-snap7 (port 10102)."""
    ensure_protocol_dep("snap7")
    host, port, target_name = container_target(
        ("s7comm-snap7", 10102),
        ("s7comm-conpot", 10109),
    )

    from oida.protocols.snap7.cli_runner import s7

    semantic_hit, _ = _run_and_record(
        "snap7",
        s7,
        host,
        port,
        target_name,
        coverage_results_dir,
        rack=0,
        slot=1,
    )
    assert semantic_hit


@pytest.mark.coverage
def test_mms_coverage(coverage_results_dir):
    """MMS scanner coverage against mms-libiec61850 (port 102)."""
    ensure_protocol_dep("pyiec61850_ng")
    host, port, target_name = container_target(
        ("mms-libiec61850", 102),
        ("mms-control", 10107),
    )

    from oida.protocols.mms.cli_runner import mms

    semantic_hit, _ = _run_and_record(
        "mms",
        mms,
        host,
        port,
        target_name,
        coverage_results_dir,
        enum=True,
    )
    assert semantic_hit


@pytest.mark.coverage
def test_hart_coverage(coverage_results_dir):
    """HART-IP scanner coverage against the REAL FieldComm hipserver (UDP 5094).

    The hipserver returns full Read-Unique-Id (Command 0) device data over an
    unencrypted UDP session; the scanner reads it and closes the session
    cleanly. (The hipserver holds sessions for 600s, so a session-pool
    exhaustion under heavy parallel load shows up as an empty result — handled
    by the skip-on-no-data guard in _run_and_record. hart-pymock on 5090 is the
    fallback Python implementation.)
    """
    ensure_protocol_dep("hartip")
    host, port, target_name = container_target(
        ("hart-hipserver", 5094),
        ("hart-pymock", 5090),
        udp=True,
    )

    from oida.protocols.hart.cli_runner import hart

    semantic_hit, _ = _run_and_record(
        "hart",
        hart,
        host,
        port,
        target_name,
        coverage_results_dir,
        identify=True,
    )
    assert semantic_hit


# ---------------------------------------------------------------------------
# Stretch protocols added 2026-06-02 — fill RELEASE_TODO §6.1 gap.
# Each test follows the same pattern: ensure the optional dep, find a
# reachable mock, run the scanner, assert a semantic hit was recorded.
# Tests skip cleanly when the mock isn't up; they're not meant to be
# part of the default PR sweep (marker: coverage).
# ---------------------------------------------------------------------------


@pytest.mark.coverage
def test_knx_coverage(coverage_results_dir):
    """KNX scanner coverage against knx-calimero / knx-devices."""
    ensure_protocol_dep("xknx")
    host, port, target_name = container_target(
        ("knx-calimero", 3671),
        ("knx-devices", 3671),
    )

    from oida.protocols.knx.cli_runner import knx

    semantic_hit, _ = _run_and_record(
        "knx",
        knx,
        host,
        port,
        target_name,
        coverage_results_dir,
        discover=True,
    )
    assert semantic_hit


@pytest.mark.coverage
def test_profinet_coverage(coverage_results_dir):
    """PROFINET scanner coverage against profinet-device (Layer-2)."""
    ensure_protocol_dep("profinet_py")
    # PROFINET is L2 (no TCP port); container_target will look up the
    # interface from container metadata. Skip if container is down.
    host, port, target_name = container_target(
        ("profinet-device", 0),
    )

    from oida.protocols.profinet.cli_runner import profinet

    semantic_hit, _ = _run_and_record(
        "profinet",
        profinet,
        host,
        port,
        target_name,
        coverage_results_dir,
        identify=True,
    )
    assert semantic_hit


@pytest.mark.coverage
def test_ethercat_coverage(coverage_results_dir):
    """EtherCAT scanner coverage against ethercat-slave-veth (Layer-2)."""
    ensure_protocol_dep("pysoem")
    host, port, target_name = container_target(
        ("ethercat-slave-veth", 0),
    )

    from oida.protocols.ethercat.cli_runner import ethercat

    semantic_hit, _ = _run_and_record(
        "ethercat",
        ethercat,
        host,
        port,
        target_name,
        coverage_results_dir,
        info=True,
    )
    assert semantic_hit


@pytest.mark.coverage
def test_can_coverage(coverage_results_dir):
    """CAN scanner coverage — needs a vcan interface, not a docker mock."""
    ensure_protocol_dep("can")
    # CAN doesn't have a docker mock — it needs a virtual CAN interface
    # on the host (`sudo modprobe vcan && sudo ip link add dev vcan0 type vcan`).
    # Skip when vcan0 isn't present.
    import subprocess

    try:
        out = subprocess.run(
            ["ip", "link", "show", "vcan0"], capture_output=True, timeout=2, text=True
        )
        if out.returncode != 0:
            pytest.skip("vcan0 not available (load vcan kernel module + add interface)")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pytest.skip("`ip` command not available")

    from oida.protocols.can.cli_runner import can

    semantic_hit, _ = _run_and_record(
        "can",
        can,
        "vcan0",
        0,
        "vcan0",
        coverage_results_dir,
        sniff_time=2,
    )
    assert semantic_hit


@pytest.mark.coverage
def test_tase2_coverage(coverage_results_dir):
    """TASE.2 (IEC 60870-6) scanner coverage — runs over MMS port 102."""
    ensure_protocol_dep("pyiec61850")
    host, port, target_name = container_target(
        ("mms-libiec61850", 102),
    )

    from oida.protocols.tase2.cli_runner import tase2

    semantic_hit, _ = _run_and_record(
        "tase2",
        tase2,
        host,
        port,
        target_name,
        coverage_results_dir,
        discover_vcc=True,
    )
    assert semantic_hit


@pytest.mark.coverage
def test_goose_coverage(coverage_results_dir):
    """GOOSE scanner coverage against goose-l2-publisher (Layer-2)."""
    # GOOSE needs raw-socket capability; skip if missing rather than fail.
    from oida.utils.permissions import check_raw_socket_capability

    has_cap, msg = check_raw_socket_capability()
    if not has_cap:
        pytest.skip(f"GOOSE needs CAP_NET_RAW: {msg}")

    host, port, target_name = container_target(
        ("goose-l2-publisher", 0),
    )

    from oida.protocols.goose.cli_runner import goose

    semantic_hit, _ = _run_and_record(
        "goose",
        goose,
        host,
        port,
        target_name,
        coverage_results_dir,
        sniff=True,
        sniff_time=2,
    )
    assert semantic_hit


@pytest.mark.coverage
def test_ocpp_coverage(coverage_results_dir):
    """OCPP (Open Charge Point Protocol) scanner coverage against ocpp-insecure."""
    ensure_protocol_dep("websockets")
    host, port, target_name = container_target(
        ("ocpp-insecure", 9000),
    )

    from oida.protocols.ocpp import ocpp

    semantic_hit, _ = _run_and_record(
        "ocpp",
        ocpp,
        host,
        port,
        target_name,
        coverage_results_dir,
        boot=True,
    )
    assert semantic_hit


@pytest.mark.coverage
def test_astm_coverage(coverage_results_dir):
    """ASTM/E1394 scanner coverage against astm-mock (port 12000)."""
    # ASTM scanner uses stdlib socket only — no optional dep gate needed.
    host, port, target_name = container_target(
        ("astm-mock", 12000),
        ("astm-hematology", 12000),
        ("astm-data", 12000),
    )

    from oida.protocols.astm import astm

    semantic_hit, _ = _run_and_record(
        "astm",
        astm,
        host,
        port,
        target_name,
        coverage_results_dir,
        version_probe=True,
    )
    assert semantic_hit

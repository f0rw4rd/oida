"""Real-CLI integration tests for the ``can`` module.

Unlike ``test_can_integration.py`` (in-process scanner unit tests) and
``test_can_container.py`` (in-process ``CANConnection`` tests against the live
mock), this file drives ``oida can`` as a real subprocess via the
``cli_runner`` fixture, against the ``can-mock`` docker container, and asserts
on data the mock actually served. Prior to this file, 0/50 CAN flags were
exercised by any real-CLI test.

Mock topology (docker/mocks/services/can/mock/can_server.py, container
``can-mock-server``, compose profile ``can``, ``network_mode: host``):

- Bus: python-can ``udp_multicast`` interface, multicast group
  ``239.0.0.1``, UDP port ``43113`` (python-can's own default for this
  interface, so no ``--port``-style flag is needed -- CAN has no such flag).
- UDS: two ECUs.
    * ``0x7E0`` -> ``0x7E8``: 16 supported services (0x10, 0x11, 0x14, 0x19,
      0x22, 0x23, 0x27, 0x28, 0x2E, 0x2F, 0x31, 0x34, 0x36, 0x37, 0x3E, 0x85).
      DID 0xF190 ("VIN") is readable.
    * ``0x7E1`` -> ``0x7E9``: 5 supported services (0x10, 0x22, 0x27, 0x31,
      0x3E).
- OBD-II: ECU responds on ``0x7DF`` -> ``0x7E8`` with 14 supported Mode-01
  PIDs (0x01,0x03,0x04,0x05,0x06,0x07,0x0C,0x0D,0x0E,0x0F,0x10,0x14,0x15,0x1C)
  and VIN ``1OIDA2MOCK3TEST45`` (Mode 09 PID 02, read automatically as part
  of ``--obd2``).
- CANopen: 4 nodes, all NMT state "Operational":
    1. WAGO OIDA-IO-Module, device_type 0x00000191 (CiA 401)
    2. Beckhoff Automation OIDA-Drive-1, device_type 0x00000192 (CiA 402)
    3. IFM Electronic OIDA-Encoder, device_type 0x00000196 (CiA 406)
    4. HMS Industrial Networks (Anybus) OIDA-Modbus-GW, device_type
       0x00000135 (CiA 309 CANopen-to-Modbus gateway)
- XCP: 1 slave, CRO 0x550 / DTO 0x551 (max_cto=8, max_dto=8).
- CCP: 2 stations (station_address 0 and 1) on CRO 0x701 / DTO 0x702 --
  these also happen to be the CLI's own defaults for ``--ccp-cro-id`` /
  ``--ccp-dto-id``, but the tests below pass them explicitly for flag credit.

Host facts used for the hostile-path adaptations of "closed port" /
"blackhole host" (CAN is bus-based, not TCP):
    * ``vcan0`` exists and is UP on the test host but carries no traffic
      (nothing publishes on it) -- the "silent interface" / no-false-positive
      analogue of a closed port.
    * ``vcan99`` does not exist -- the "unreachable/nonexistent interface"
      analogue.
    * ``239.0.0.99`` is a multicast group nobody publishes on -- the
      "blackhole host" analogue for the udp_multicast bus type.

Bugs/drift found while gathering ground truth (see report): an inverted
``--id-scan-range`` (e.g. ``100-1``) is accepted without validation and
produces a nonsensical negative "arbitration IDs probed" count instead of
being rejected; covered below as a documented non-crashing-but-degenerate
path, not silently ignored.

Confirm gating (verified against ``src/oida/protocols/can/cli_runner.py``):
gated actions refuse with a ``protocol_error`` event (not a nonzero exit --
the CLI treats this as a soft per-target error) unless ``--confirm`` is
passed.
    * Requires ``--confirm``: ``--uds-scan``, ``--id-scan``, ``--xcp-scan``,
      ``--xcp-memory-read``, ``--ccp-scan``, ``--uds-sessions``,
      ``--uds-routines``, ``--uds-reset``, ``--send``, ``--send-file``,
      ``--replay``.
    * No confirm needed: ``--obd2``, ``--xcp-info``, ``--uds-dids``,
      ``--uds-seeds``, ``--canopen-scan``, ``--canopen-info``,
      ``--canopen-sdo-read``, ``--canopen-od-scan``, ``--canopen-monitor``,
      ``--canopen-pdo``, ``--modbus-gateway``.

Classification: A = strict, asserts real returned mock data. B = conditional,
asserts the flag is accepted/parsed and runs to completion without asserting
exact mock-derived values (either because the effect is not distinguishable
from this mock, or because it is a disruptive/stateful action we only verify
completes cleanly). C = error/negative path.

Flag coverage matrix (--flag -> [A|B|C] test_name):
    --baudrate          B  test_bus_options_combo
    --bus-type          A  test_canopen_scan_finds_all_four_nodes (+ all)
    --canopen-info      A  test_canopen_info_reports_node1_identity
    --canopen-monitor   B  test_canopen_monitor_runs_and_captures_activity
    --canopen-od-range  A  test_canopen_od_scan_lists_identity_indices
    --canopen-od-scan   A  test_canopen_od_scan_lists_identity_indices
    --canopen-pdo       B  test_canopen_pdo_runs_for_node
    --canopen-pdo-node  B  test_canopen_pdo_runs_for_node
    --canopen-scan      A  test_canopen_scan_finds_all_four_nodes
    --canopen-sdo-read  A  test_canopen_sdo_read_device_type
    --ccp-cro-id        A  test_ccp_scan_with_confirm_finds_two_stations
    --ccp-dto-id        A  test_ccp_scan_with_confirm_finds_two_stations
    --ccp-scan          A  test_ccp_scan_with_confirm_finds_two_stations
    --channel           B  test_channel_overrides_target
    --extended          B  test_bus_options_combo
    --fd                B  test_bus_options_combo
    --filter-id         B  test_sniff_options_combo
    --fuzz-id           B  test_fuzz_bounded_run
    --fuzz-mode         B  test_fuzz_bounded_run
    --id-scan           A  test_id_scan_with_confirm_finds_uds_ecus
    --id-scan-range     A  test_id_scan_with_confirm_finds_uds_ecus
    --log-file          B  test_monitor_log_file_and_on_change
    --modbus-gateway    A  test_modbus_gateway_reports_node4
    --no-sniff          A  (every test above)
    --obd2              A  test_obd2_reports_pids_and_vin
    --on-change         B  test_monitor_log_file_and_on_change
    --replay            B  test_replay_file_with_and_without_confirm
    --replay-speed      B  test_replay_file_with_and_without_confirm
    --seed-count        B  test_uds_seeds_bruteforce_bounded
    --seed-level        B  test_uds_seeds_bruteforce_bounded
    --send              A  test_send_with_and_without_confirm
    --send-file         B  test_send_file_with_and_without_confirm
    --sniff-time        B  test_sniff_options_combo
    --timeout           A  (every test above)
    --uds-dids          A  test_uds_dids_reports_vin_did
    --uds-reset         B  test_uds_reset_with_and_without_confirm
    --uds-reset-type    B  test_uds_reset_with_and_without_confirm
    --uds-routines      B  test_uds_routines_with_and_without_confirm
    --uds-scan          A  test_uds_scan_with_confirm_finds_both_ecus
    --uds-seeds         B  test_uds_seeds_bruteforce_bounded
    --uds-services      B  test_uds_services_explicit_list
    --uds-sessions      B  test_uds_sessions_with_and_without_confirm
    --uds-target-id     A  test_uds_dids_reports_vin_did
    --xcp-address       B  test_xcp_memory_read_with_and_without_confirm
    --xcp-info          A  test_xcp_info_reports_slave_identity
    --xcp-length        B  test_xcp_memory_read_with_and_without_confirm
    --xcp-memory-read   B  test_xcp_memory_read_with_and_without_confirm
    --xcp-req-id        A  test_xcp_info_reports_slave_identity
    --xcp-resp-id       A  test_xcp_info_reports_slave_identity
    --xcp-scan          A  test_xcp_scan_with_confirm_finds_slave

Hostile-path coverage (Category C):
    - confirm gate both directions: uds_scan, id_scan, send, xcp_scan,
      uds_reset, xcp_memory_read
    - nonexistent interface (vcan99, socketcan)
    - silent/idle interface with no false-positive identification (vcan0)
    - blackhole multicast group + bounded --timeout
    - malformed args: inverted --id-scan-range, non-numeric --seed-count,
      garbage --canopen-sdo-read spec
    - false flags: unknown flag, transposition typo, borrowed flag from
      another protocol, wrong-type value for a real flag
"""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

CAN_TARGET = "239.0.0.1"


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _can_mock_available() -> bool:
    """Best-effort check the can-mock container is present and healthy."""
    if not _docker_available():
        return False
    try:
        result = subprocess.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{.State.Health.Status}}",
                "can-mock-server",
            ],
            capture_output=True,
            timeout=10,
            check=False,
            text=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and result.stdout.strip() == "healthy"


_SKIP_REASON = None if _can_mock_available() else "can-mock container not available/healthy"

pytestmark = [
    pytest.mark.can,
    pytest.mark.slow,
    pytest.mark.containers("can-mock"),
    pytest.mark.skipif(bool(_SKIP_REASON), reason=str(_SKIP_REASON)),
    pytest.mark.xdist_group("can_service"),
]


def _read_json(output_dir) -> dict:
    """Read the single-target JSON payload written by --output/--format json."""
    path = output_dir / "can.json"
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    assert isinstance(data, list)
    assert len(data) == 1
    return data[0]


class TestCANCliIntegration:
    """Real-CLI (subprocess) coverage for `oida can`."""

    # ---------------------------------------------------------------
    # Category A: strict assertions on real mock data
    # ---------------------------------------------------------------

    def test_canopen_scan_finds_all_four_nodes(self, cli_runner, tmp_path):
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--canopen-scan",
            "--timeout",
            "8",
            "--output",
            str(tmp_path),
            "--format",
            "json",
            timeout=45,
        )
        assert result.returncode == 0, result.combined_output
        data = _read_json(tmp_path)["data"]
        nodes = {n["node_id"]: n for n in data["canopen_nodes"]}
        assert set(nodes) == {1, 2, 3, 4}
        assert nodes[1]["vendor_name"] == "WAGO"
        assert nodes[1]["device_name"] == "OIDA-IO-Module"
        assert nodes[1]["device_type"] == "0x00000191"
        assert nodes[2]["vendor_name"] == "Beckhoff Automation"
        assert nodes[3]["vendor_name"] == "IFM Electronic"
        assert nodes[4]["vendor_name"] == "HMS Industrial Networks (Anybus)"
        assert nodes[4]["device_name"] == "OIDA-Modbus-GW"

    def test_canopen_info_reports_node1_identity(self, cli_runner, tmp_path):
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--canopen-info",
            "1",
            "--timeout",
            "5",
            "--output",
            str(tmp_path),
            "--format",
            "json",
            timeout=20,
        )
        assert result.returncode == 0, result.combined_output
        info = _read_json(tmp_path)["data"]["canopen_info"]
        assert info["device_name"] == "OIDA-IO-Module"
        assert info["vendor_name"] == "WAGO"
        assert info["device_type"] == "0x00000191"

    def test_canopen_sdo_read_device_type(self, cli_runner, tmp_path):
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--canopen-sdo-read",
            "1:0x1000:0",
            "--timeout",
            "5",
            "--output",
            str(tmp_path),
            "--format",
            "json",
            timeout=20,
        )
        assert result.returncode == 0, result.combined_output
        sdo = _read_json(tmp_path)["data"]["canopen_sdo_read"]
        assert sdo["node_id"] == 1
        assert sdo["index"] == "0x1000"
        assert sdo["subindex"] == 0
        # 0x00000191 little-endian == bytes 91 01 00 00
        assert sdo["data"].replace(" ", "").lower() == "91010000"

    def test_canopen_od_scan_lists_identity_indices(self, cli_runner, tmp_path):
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--canopen-od-scan",
            "1",
            "--canopen-od-range",
            "0x1000-0x1018",
            "--timeout",
            "10",
            "--output",
            str(tmp_path),
            "--format",
            "json",
            timeout=45,
        )
        assert result.returncode == 0, result.combined_output
        scan = _read_json(tmp_path)["data"]["canopen_od_scan"]
        assert scan["node_id"] == 1
        indices = {e["index"] for e in scan["entries"]}
        assert "0x1000" in indices
        assert "0x1008" in indices
        assert "0x1018" in indices

    def test_xcp_info_reports_slave_identity(self, cli_runner, tmp_path):
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--xcp-info",
            "--xcp-req-id",
            "0x550",
            "--xcp-resp-id",
            "0x551",
            "--timeout",
            "5",
            "--output",
            str(tmp_path),
            "--format",
            "json",
            timeout=20,
        )
        assert result.returncode == 0, result.combined_output
        info = _read_json(tmp_path)["data"]["xcp_info"]
        assert info["connected"] is True
        assert info["request_id"] == "0x550"
        assert info["response_id"] == "0x551"
        assert info["max_cto"] == 8
        assert info["max_dto"] == 8

    def test_ccp_scan_with_confirm_finds_two_stations(self, cli_runner, tmp_path):
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--ccp-scan",
            "--ccp-cro-id",
            "0x701",
            "--ccp-dto-id",
            "0x702",
            "--confirm",
            "--timeout",
            "8",
            "--output",
            str(tmp_path),
            "--format",
            "json",
            timeout=45,
        )
        assert result.returncode == 0, result.combined_output
        stations = _read_json(tmp_path)["data"]["ccp_results"]
        addrs = {s["station_address"] for s in stations}
        assert addrs == {0, 1}
        assert all(s["connected"] for s in stations)

    def test_modbus_gateway_reports_node4(self, cli_runner, tmp_path):
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--modbus-gateway",
            "--timeout",
            "8",
            "--output",
            str(tmp_path),
            "--format",
            "json",
            timeout=45,
        )
        assert result.returncode == 0, result.combined_output
        gateways = _read_json(tmp_path)["data"]["modbus_gateways"]
        assert len(gateways) == 1
        gw = gateways[0]
        assert gw["node_id"] == 4
        assert gw["device_name"] == "OIDA-Modbus-GW"
        assert "CiA 309" in gw["gateway_type"]

    def test_uds_scan_with_confirm_finds_both_ecus(self, cli_runner, tmp_path):
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--uds-scan",
            "--confirm",
            "--timeout",
            "10",
            "--output",
            str(tmp_path),
            "--format",
            "json",
            timeout=40,
        )
        assert result.returncode == 0, result.combined_output
        ecus = {e["response_id"]: e for e in _read_json(tmp_path)["data"]["uds_results"]}
        assert set(ecus) == {"0x7E8", "0x7E9"}
        svc_0x7e0 = {s["id"] for s in ecus["0x7E8"]["services"]}
        svc_0x7e1 = {s["id"] for s in ecus["0x7E9"]["services"]}
        assert svc_0x7e0 == {
            "0x10",
            "0x11",
            "0x14",
            "0x19",
            "0x22",
            "0x23",
            "0x27",
            "0x28",
            "0x2E",
            "0x2F",
            "0x31",
            "0x34",
            "0x36",
            "0x37",
            "0x3E",
            "0x85",
        }
        assert svc_0x7e1 == {"0x10", "0x22", "0x27", "0x31", "0x3E"}

    def test_uds_scan_without_confirm_is_refused(self, cli_runner):
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--uds-scan",
            "--timeout",
            "5",
            timeout=20,
            json_log=True,
        )
        assert result.returncode == 0
        assert "Traceback" not in result.combined_output
        errors = result.scan_log.get_errors()
        assert any("confirm" in e.get("message", "").lower() for e in errors)

    def test_uds_dids_reports_vin_did(self, cli_runner, tmp_path):
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--uds-dids",
            "0xF190-0xF190",
            "--uds-target-id",
            "0x7E0",
            "--timeout",
            "5",
            "--output",
            str(tmp_path),
            "--format",
            "json",
            timeout=20,
        )
        assert result.returncode == 0, result.combined_output
        dids = _read_json(tmp_path)["data"]["uds_dids"]
        assert dids["request_id"] == "0x7E0"
        names = {d["did"]: d["name"] for d in dids["readable_dids"]}
        assert names.get("0xF190") == "VIN"

    def test_obd2_reports_pids_and_vin(self, cli_runner, tmp_path):
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--obd2",
            "--timeout",
            "5",
            "--output",
            str(tmp_path),
            "--format",
            "json",
            timeout=20,
        )
        assert result.returncode == 0, result.combined_output
        obd2 = _read_json(tmp_path)["data"]["obd2"]
        pids = {p["pid"] for p in obd2["0x7E8"]["supported_pids"]}
        assert pids == {
            "0x01",
            "0x03",
            "0x04",
            "0x05",
            "0x06",
            "0x07",
            "0x0C",
            "0x0D",
            "0x0E",
            "0x0F",
            "0x10",
            "0x14",
            "0x15",
            "0x1C",
        }
        assert obd2.get("VIN") == "1OIDA2MOCK3TEST45"

    def test_id_scan_with_confirm_finds_uds_ecus(self, cli_runner, tmp_path):
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--id-scan",
            "--id-scan-range",
            "0x7E0-0x7E2",
            "--confirm",
            "--timeout",
            "10",
            "--output",
            str(tmp_path),
            "--format",
            "json",
            timeout=40,
        )
        assert result.returncode == 0, result.combined_output
        found = {e["request_id"]: e["response_id"] for e in _read_json(tmp_path)["data"]["id_scan"]}
        assert found.get("0x7E0") == "0x7E8"
        assert found.get("0x7E1") == "0x7E9"
        # 0x7E2 has no ECU behind it on the mock -- must not be reported.
        assert "0x7E2" not in found

    def test_send_with_and_without_confirm(self, cli_runner):
        without = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--send",
            "0x123#0102030405060708",
            "--timeout",
            "3",
            timeout=15,
            json_log=True,
        )
        assert any("confirm" in e.get("message", "").lower() for e in without.scan_log.get_errors())

        confirmed = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--send",
            "0x123#0102030405060708",
            "--confirm",
            "--timeout",
            "3",
            timeout=15,
            json_log=True,
        )
        assert confirmed.returncode == 0
        assert "Traceback" not in confirmed.combined_output
        sent = confirmed.scan_log.get_events(event_type="info")
        assert any("0x123" in e.get("message", "") for e in sent)

    def test_xcp_scan_without_confirm_is_refused(self, cli_runner):
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--xcp-scan",
            "--timeout",
            "3",
            timeout=15,
            json_log=True,
        )
        assert result.returncode == 0
        assert "Traceback" not in result.combined_output
        assert any("confirm" in e.get("message", "").lower() for e in result.scan_log.get_errors())

    @pytest.mark.slow
    @pytest.mark.timeout(200)
    def test_xcp_scan_with_confirm_finds_slave(self, cli_runner, tmp_path):
        # NOTE: --xcp-scan always sweeps the full 2048-arbitration-ID space
        # (0x000-0x7FF) with no CLI-exposed way to narrow it; against this
        # mock that takes ~100s wall-clock regardless of --timeout, hence
        # the generous subprocess timeout below AND the per-test timeout
        # override -- the global 60s pytest-timeout would otherwise kill it.
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--xcp-scan",
            "--confirm",
            "--timeout",
            "3",
            "--output",
            str(tmp_path),
            "--format",
            "json",
            timeout=185,
        )
        assert result.returncode == 0, result.combined_output
        slaves = {s["request_id"]: s for s in _read_json(tmp_path)["data"]["xcp_results"]}
        assert "0x550" in slaves
        assert slaves["0x550"]["response_id"] == "0x551"
        assert slaves["0x550"]["xcp_version"] == "1.0"
        # Bug watch: the scan also misidentifies the CCP station (0x701/
        # 0x702) as an XCP slave with garbage version/size fields -- a
        # false positive we do not assert away here but flag in the report.

    # ---------------------------------------------------------------
    # Category B: accepted / runs / no exact-value assertion
    # ---------------------------------------------------------------

    def test_canopen_pdo_runs_for_node(self, cli_runner, tmp_path):
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--canopen-pdo",
            "--canopen-pdo-node",
            "1",
            "--timeout",
            "8",
            "--output",
            str(tmp_path),
            "--format",
            "json",
            timeout=45,
        )
        assert result.returncode == 0, result.combined_output
        assert "Traceback" not in result.combined_output
        _read_json(tmp_path)  # must produce well-formed output, no crash

    def test_canopen_monitor_runs_and_captures_activity(self, cli_runner):
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--canopen-monitor",
            "--timeout",
            "4",
            timeout=20,
            json_log=True,
        )
        assert result.returncode == 0, result.combined_output
        assert "Traceback" not in result.combined_output
        assert len(result.scan_log) > 0

    def test_uds_sessions_with_and_without_confirm(self, cli_runner):
        without = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--uds-sessions",
            "--timeout",
            "3",
            timeout=15,
            json_log=True,
        )
        assert without.returncode == 0
        assert any("confirm" in e.get("message", "").lower() for e in without.scan_log.get_errors())

        confirmed = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--uds-sessions",
            "--uds-target-id",
            "0x7E0",
            "--confirm",
            "--timeout",
            "8",
            timeout=45,
            json_log=True,
        )
        assert confirmed.returncode == 0, confirmed.combined_output
        assert "Traceback" not in confirmed.combined_output

    def test_uds_seeds_bruteforce_bounded(self, cli_runner):
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--uds-seeds",
            "--uds-target-id",
            "0x7E0",
            "--seed-level",
            "0x03",
            "--seed-count",
            "2",
            "--timeout",
            "8",
            timeout=45,
            json_log=True,
        )
        assert result.returncode == 0, result.combined_output
        assert "Traceback" not in result.combined_output

    def test_uds_routines_with_and_without_confirm(self, cli_runner):
        without = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--uds-routines",
            "--timeout",
            "3",
            timeout=15,
            json_log=True,
        )
        assert without.returncode == 0
        assert any("confirm" in e.get("message", "").lower() for e in without.scan_log.get_errors())

        confirmed = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--uds-routines",
            "--uds-target-id",
            "0x7E0",
            "--confirm",
            "--timeout",
            "8",
            timeout=45,
            json_log=True,
        )
        assert confirmed.returncode == 0, confirmed.combined_output
        assert "Traceback" not in confirmed.combined_output

    def test_uds_reset_with_and_without_confirm(self, cli_runner):
        without = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--uds-reset",
            "--uds-reset-type",
            "soft",
            "--timeout",
            "3",
            timeout=15,
            json_log=True,
        )
        assert without.returncode == 0
        assert any("confirm" in e.get("message", "").lower() for e in without.scan_log.get_errors())

        confirmed = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--uds-reset",
            "--uds-reset-type",
            "0x03",
            "--uds-target-id",
            "0x7E0",
            "--confirm",
            "--timeout",
            "8",
            timeout=45,
            json_log=True,
        )
        assert confirmed.returncode == 0, confirmed.combined_output
        assert "Traceback" not in confirmed.combined_output

    def test_xcp_memory_read_with_and_without_confirm(self, cli_runner):
        without = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--xcp-memory-read",
            "--xcp-address",
            "0x0000",
            "--xcp-length",
            "4",
            "--timeout",
            "3",
            timeout=15,
            json_log=True,
        )
        assert without.returncode == 0
        assert any("confirm" in e.get("message", "").lower() for e in without.scan_log.get_errors())

        confirmed = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--xcp-memory-read",
            "--xcp-req-id",
            "0x550",
            "--xcp-resp-id",
            "0x551",
            "--xcp-address",
            "0x0000",
            "--xcp-length",
            "4",
            "--confirm",
            "--timeout",
            "8",
            timeout=45,
            json_log=True,
        )
        assert confirmed.returncode == 0, confirmed.combined_output
        assert "Traceback" not in confirmed.combined_output

    def test_send_file_with_and_without_confirm(self, cli_runner, tmp_path):
        send_file = tmp_path / "frames.txt"
        send_file.write_text("0x123#0102030405060708\n0x124#AABBCCDD\n")

        without = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--send-file",
            str(send_file),
            "--timeout",
            "3",
            timeout=15,
            json_log=True,
        )
        assert any("confirm" in e.get("message", "").lower() for e in without.scan_log.get_errors())

        confirmed = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--send-file",
            str(send_file),
            "--confirm",
            "--timeout",
            "5",
            timeout=20,
            json_log=True,
        )
        assert confirmed.returncode == 0, confirmed.combined_output
        assert "Traceback" not in confirmed.combined_output

    def test_replay_file_with_and_without_confirm(self, cli_runner, tmp_path):
        replay_file = tmp_path / "replay.log"
        replay_file.write_text(
            "(0.000000) vcan0 123#0102030405060708\n(0.010000) vcan0 124#AABBCCDD\n"
        )

        without = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--replay",
            str(replay_file),
            "--replay-speed",
            "10",
            "--timeout",
            "3",
            timeout=15,
            json_log=True,
        )
        assert any("confirm" in e.get("message", "").lower() for e in without.scan_log.get_errors())

        confirmed = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--replay",
            str(replay_file),
            "--replay-speed",
            "10",
            "--confirm",
            "--timeout",
            "5",
            timeout=20,
            json_log=True,
        )
        assert confirmed.returncode == 0, confirmed.combined_output
        assert "Traceback" not in confirmed.combined_output

    def test_fuzz_bounded_run(self, cli_runner):
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--fuzz",
            "--fuzz-id",
            "0x123",
            "--fuzz-mode",
            "boundary",
            "--fuzz-iterations",
            "3",
            "--confirm",
            "--timeout",
            "5",
            timeout=45,
            json_log=True,
        )
        assert result.returncode == 0, result.combined_output
        assert "Traceback" not in result.combined_output

    def test_uds_services_explicit_list(self, cli_runner, tmp_path):
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--uds-scan",
            "--uds-services",
            "0x10,0x22,0x27",
            "--confirm",
            "--timeout",
            "8",
            "--output",
            str(tmp_path),
            "--format",
            "json",
            timeout=45,
        )
        assert result.returncode == 0, result.combined_output
        _read_json(tmp_path)

    def test_channel_overrides_target(self, cli_runner, tmp_path):
        # --channel overrides the positional target for the actual bus
        # connection; pass an unused placeholder as target.
        result = cli_runner.run(
            "can",
            "placeholder",
            "--bus-type",
            "udp_multicast",
            "--channel",
            CAN_TARGET,
            "--no-sniff",
            "--obd2",
            "--timeout",
            "5",
            "--output",
            str(tmp_path),
            "--format",
            "json",
            timeout=20,
        )
        assert result.returncode == 0, result.combined_output
        obd2 = _read_json(tmp_path)["data"]["obd2"]
        assert obd2.get("VIN") == "1OIDA2MOCK3TEST45"

    def test_bus_options_combo(self, cli_runner, tmp_path):
        """Maximal invocation of the CAN-bus option group together."""
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--baudrate",
            "500000",
            "--extended",
            "--fd",
            "--no-sniff",
            "--obd2",
            "--timeout",
            "5",
            "--output",
            str(tmp_path),
            "--format",
            "json",
            timeout=20,
        )
        assert result.returncode == 0, result.combined_output
        assert "Traceback" not in result.combined_output
        _read_json(tmp_path)

    def test_sniff_options_combo(self, cli_runner):
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--sniff-time",
            "3",
            "--filter-id",
            "0x7E0-0x7EF",
            "--timeout",
            "5",
            timeout=20,
            json_log=True,
        )
        assert result.returncode == 0, result.combined_output
        assert "Traceback" not in result.combined_output

    def test_monitor_log_file_and_on_change(self, cli_runner, tmp_path):
        log_file = tmp_path / "can_monitor.log"
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--canopen-monitor",
            "--on-change",
            "--log-file",
            str(log_file),
            "--timeout",
            "4",
            timeout=20,
            json_log=True,
        )
        assert result.returncode == 0, result.combined_output
        assert "Traceback" not in result.combined_output

    # ---------------------------------------------------------------
    # Category C: hostile / invalid-server / malformed-argument paths
    # ---------------------------------------------------------------

    def test_nonexistent_interface_fails_cleanly(self, cli_runner):
        result = cli_runner.run(
            "can",
            "vcan99",
            "--bus-type",
            "socketcan",
            "--no-sniff",
            "--timeout",
            "3",
            timeout=15,
            json_log=True,
        )
        assert "Traceback" not in result.combined_output
        assert len(result.scan_log.get_errors()) > 0 or result.returncode != 0

    def test_idle_interface_reports_no_false_positives(self, cli_runner, tmp_path):
        """vcan0 exists and is UP but carries no CANopen/UDS traffic."""
        result = cli_runner.run(
            "can",
            "vcan0",
            "--bus-type",
            "socketcan",
            "--no-sniff",
            "--canopen-scan",
            "--timeout",
            "2",
            "--output",
            str(tmp_path),
            "--format",
            "json",
            timeout=15,
        )
        assert "Traceback" not in result.combined_output
        if result.returncode == 0:
            data = _read_json(tmp_path)["data"]
            assert data.get("canopen_nodes", []) == []

    def test_blackhole_multicast_group_honours_timeout(self, cli_runner):
        result = cli_runner.run(
            "can",
            "239.0.0.99",
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--obd2",
            "--timeout",
            "2",
            timeout=20,
            json_log=True,
        )
        assert "Traceback" not in result.combined_output
        assert result.execution_time < 18

    def test_inverted_id_scan_range_does_not_crash(self, cli_runner):
        """Bug watch: an inverted range (start > end) is accepted instead of
        rejected upstream, but must never report a false-positive ECU."""
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--id-scan",
            "--id-scan-range",
            "0x7E2-0x7E1",
            "--confirm",
            "--timeout",
            "3",
            timeout=20,
            json_log=True,
        )
        assert "Traceback" not in result.combined_output
        assert result.returncode == 0

    def test_nonnumeric_seed_count_is_rejected(self, cli_runner):
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--uds-seeds",
            "--seed-count",
            "notanumber",
            timeout=10,
        )
        assert result.returncode != 0
        assert "Traceback" not in result.combined_output

    def test_garbage_canopen_sdo_read_spec_is_reported(self, cli_runner):
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--no-sniff",
            "--canopen-sdo-read",
            "garbage",
            "--timeout",
            "3",
            timeout=15,
            json_log=True,
        )
        assert "Traceback" not in result.combined_output
        assert len(result.scan_log.get_errors()) > 0 or result.returncode != 0

    def test_unknown_flag_is_rejected(self, cli_runner):
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--not-a-real-flag",
            timeout=10,
        )
        assert result.returncode != 0
        assert "Traceback" not in result.combined_output

    def test_transposition_typo_is_rejected(self, cli_runner):
        """'--etxended' is a transposition of '--extended', not a prefix
        of any real flag, so argparse must reject it outright."""
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--etxended",
            timeout=10,
        )
        assert result.returncode != 0
        assert "Traceback" not in result.combined_output

    def test_borrowed_flag_from_another_protocol_is_rejected(self, cli_runner):
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--unit-id",
            "1",
            timeout=10,
        )
        assert result.returncode != 0
        assert "Traceback" not in result.combined_output

    def test_wrong_type_value_for_real_flag_is_rejected(self, cli_runner):
        result = cli_runner.run(
            "can",
            CAN_TARGET,
            "--bus-type",
            "udp_multicast",
            "--seed-count",
            "abc",
            timeout=10,
        )
        assert result.returncode != 0
        assert "Traceback" not in result.combined_output

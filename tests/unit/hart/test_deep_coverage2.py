#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Deep unit tests for HART -- part 2.

Covers DeviceInfoMixin read methods, HARTScanner.connect/discover/probe_version,
the radamsa-backed fuzz path, bruteforce_lock orchestration, poll-address
scanning, and the nxc proto_flow() dispatch end-to-end (all with a mocked
hartip-py transport).
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from hartip import DeviceInfo, Variable

from oida.protocols.hart.scanner import HARTScanner, LockState
from oida.protocols.hart import nxc_connection
from oida.protocols.hart.nxc_connection import hart
from oida.utils.ics_logger import get_logger

from tests.unit.hart.test_deep_coverage import FakeClient, FakeResponse, make_scanner

pytestmark = [pytest.mark.hart]


# ===========================================================================
# DeviceInfoMixin read methods (Command 0/1/2/3/15/48)
# ===========================================================================


class TestReadDeviceInfo:
    def _lib_info(self, **kw):
        defaults = dict(
            manufacturer_id=0x26,
            manufacturer_name="Rosemount (Emerson)",
            device_type=0x2A,
            unique_address=b"\x01\x02\x03",
            hart_revision=7,
            software_revision=2,
            device_revision=5,
            hardware_revision=2,
            physical_signaling=0,
            flags=0x80,  # write-protected bit set
        )
        defaults.update(kw)
        return DeviceInfo(
            **{
                k: v
                for k, v in defaults.items()
                if k in {f for f in DeviceInfo.__dataclass_fields__}
            }
        )

    def test_read_device_info_maps_fields_and_flags(self):
        cmd0 = FakeResponse(response_code=0, parsed=self._lib_info(flags=0xC0))
        # cmd 13 tag response with parsed dict, payload >= 21 bytes
        cmd13 = FakeResponse(
            response_code=0,
            payload=b"\x00" * 21,
            parsed={"tag": "PT-101", "descriptor": "PRESSURE", "date": "2024-06-15"},
        )

        client = MagicMock()
        client.read_unique_id.return_value = cmd0
        client.read_tag_descriptor_date.return_value = cmd13

        scanner = make_scanner(client=client)
        info = scanner.read_device_info()
        assert info.manufacturer_id == 0x26
        assert info.device_type == 0x2A
        assert info.protocol_revision == 7
        # flags 0xC0 => write_protected (0x80) AND config_changed (0x40)
        assert info.write_protected is True
        assert info.config_changed is True
        assert info.tag == "PT-101"
        assert info.descriptor == "PRESSURE"

    def test_read_device_info_wireless_signaling(self):
        cmd0 = FakeResponse(response_code=0, parsed=self._lib_info(physical_signaling=4))
        client = MagicMock()
        client.read_unique_id.return_value = cmd0
        client.read_tag_descriptor_date.return_value = FakeResponse(response_code=1, payload=b"")
        scanner = make_scanner(client=client)
        info = scanner.read_device_info()
        assert info.is_wireless is True

    def test_read_device_info_bad_response_code(self):
        client = MagicMock()
        client.read_unique_id.return_value = FakeResponse(response_code=1)
        scanner = make_scanner(client=client)
        assert scanner.read_device_info() is None

    def test_read_device_info_no_client(self):
        scanner = make_scanner(client=None)
        assert scanner.read_device_info() is None


class TestReadVariables:
    def test_read_primary_variable(self):
        var = Variable(value=25.5, unit_code=32, unit_name="degC", label="PV")
        client = MagicMock()
        client.read_primary_variable.return_value = FakeResponse(response_code=0, parsed=var)
        scanner = make_scanner(client=client)
        pv = scanner.read_primary_variable()
        assert pv.value == 25.5
        assert pv.units_name == "degC"
        assert pv.name == "Primary Variable"

    def test_read_primary_variable_bad_code(self):
        client = MagicMock()
        client.read_primary_variable.return_value = FakeResponse(response_code=1)
        scanner = make_scanner(client=client)
        assert scanner.read_primary_variable() is None

    def test_read_current_and_percent(self):
        client = MagicMock()
        client.read_current_and_percent.return_value = FakeResponse(
            response_code=0, parsed={"current_mA": 12.5, "percent_range": 50.0}
        )
        scanner = make_scanner(client=client)
        assert scanner.read_current_and_percent() == (12.5, 50.0)

    def test_read_current_bad_code_returns_zero(self):
        client = MagicMock()
        client.read_current_and_percent.return_value = FakeResponse(response_code=1)
        scanner = make_scanner(client=client)
        assert scanner.read_current_and_percent() == (0.0, 0.0)

    def test_read_all_variables_builds_loop_and_dynamics(self):
        parsed = {
            "loop_current": 12.5,
            "variables": [
                Variable(value=25.5, unit_code=6, unit_name="psi", label="PV"),
                Variable(value=23.2, unit_code=32, unit_name="degC", label="SV"),
            ],
        }
        client = FakeClient(responses={3: FakeResponse(response_code=0, parsed=parsed)})
        scanner = make_scanner(client=client)
        variables = scanner.read_all_variables()
        names = [v.name for v in variables]
        assert "Loop Current" in names
        assert "Primary Variable" in names
        assert "Secondary Variable" in names
        loop = next(v for v in variables if v.name == "Loop Current")
        assert loop.value == 12.5 and loop.units_name == "mA"

    def test_read_all_variables_bad_code(self):
        client = FakeClient(responses={3: FakeResponse(response_code=1)})
        scanner = make_scanner(client=client)
        assert scanner.read_all_variables() == []

    def test_read_output_info(self):
        parsed = {
            "alarm_selection_code": 1,
            "transfer_function_code": 0,
            "range_units_code": 6,
            "range_unit_name": "psi",
            "upper_range_value": 100.0,
            "lower_range_value": 0.0,
            "damping_value": 2.0,
        }
        client = MagicMock()
        client.read_output_info.return_value = FakeResponse(response_code=0, parsed=parsed)
        scanner = make_scanner(client=client)
        out = scanner.read_output_info()
        assert out["upper_range"] == 100.0
        assert out["units_name"] == "psi"
        assert out["damping_seconds"] == 2.0

    def test_read_output_info_bad_code(self):
        client = MagicMock()
        client.read_output_info.return_value = FakeResponse(response_code=1)
        scanner = make_scanner(client=client)
        assert scanner.read_output_info() == {}

    def test_read_additional_status_decodes_flags(self):
        client = MagicMock()
        client.read_additional_status.return_value = FakeResponse(
            response_code=0, parsed={"extended_device_status": 0x01}
        )
        scanner = make_scanner(client=client)
        status = scanner.read_additional_status()
        assert "extended_device_status_decoded" in status
        assert status["extended_device_status_decoded"]["maintenance_required"] is True

    def test_read_additional_status_no_flags(self):
        client = MagicMock()
        client.read_additional_status.return_value = FakeResponse(
            response_code=0, parsed={"extended_device_status": 0}
        )
        scanner = make_scanner(client=client)
        status = scanner.read_additional_status()
        assert "extended_device_status_decoded" not in status


# ===========================================================================
# HARTScanner connect / discover / probe_version
# ===========================================================================


class TestScannerConnect:
    def test_connect_plaintext_udp(self):
        scanner = HARTScanner({"rhost": "10.0.0.5"})
        fake = MagicMock()
        with patch("oida.protocols.hart.scanner.HARTIPClient", return_value=fake) as mk:
            result = scanner.connect()
        assert result is fake
        fake.connect.assert_called_once()
        _, kwargs = mk.call_args
        assert kwargs["protocol"] == "udp"
        assert "psk_identity" not in kwargs

    def test_connect_tls_switches_udp_to_tcp(self):
        scanner = HARTScanner({"rhost": "10.0.0.5", "psk-identity": "id", "psk-key": "deadbeef"})
        assert scanner.transport == "udp"
        fake = MagicMock()
        with patch("oida.protocols.hart.scanner.HARTIPClient", return_value=fake) as mk:
            scanner.connect()
        _, kwargs = mk.call_args
        assert kwargs["protocol"] == "tcp"  # auto-switched for TLS
        assert kwargs["psk_identity"] == "id"
        assert scanner.transport == "tcp"

    def test_connect_failure_returns_none(self):
        scanner = HARTScanner({"rhost": "10.0.0.5"})
        fake = MagicMock()
        fake.connect.side_effect = OSError("refused")
        with patch("oida.protocols.hart.scanner.HARTIPClient", return_value=fake):
            assert scanner.connect() is None

    def test_probe_version(self):
        scanner = HARTScanner({"rhost": "10.0.0.5"})
        with patch("oida.protocols.hart.scanner.probe_server_version", return_value=2):
            assert scanner.probe_version() == 2
            assert scanner.server_version == 2

    def test_probe_version_failure(self):
        scanner = HARTScanner({"rhost": "10.0.0.5"})
        with patch("oida.protocols.hart.scanner.probe_server_version", side_effect=OSError("x")):
            assert scanner.probe_version() is None

    def test_disconnect_closes_client(self):
        scanner = HARTScanner({"rhost": "10.0.0.5"})
        client = MagicMock()
        scanner.client = client
        scanner.disconnect()
        client.close.assert_called_once()
        assert scanner.client is None


class TestScannerDiscover:
    def test_discover_not_connected(self):
        scanner = HARTScanner({"rhost": "10.0.0.5"})
        scanner.client = None
        assert scanner.discover() == {"error": "Not connected"}

    def test_discover_assembles_result_dict(self):
        from oida.protocols.hart.scanner import HARTDeviceInfo, HARTVariable

        scanner = HARTScanner({"rhost": "10.0.0.5"})
        scanner.client = MagicMock()

        di = HARTDeviceInfo(
            manufacturer_id=0x26,
            manufacturer_name="Emerson",
            device_type=42,
            protocol_revision=7,
            write_protected=False,
            lock_state=LockState.UNLOCKED,
        )
        scanner.read_device_info = MagicMock(return_value=di)
        scanner.read_all_variables = MagicMock(
            return_value=[HARTVariable(name="PV", value=1.0, units_code=6, units_name="psi")]
        )
        scanner.read_output_info = MagicMock(return_value={"upper_range": 100.0})
        scanner.detect_wirelesshart = MagicMock(return_value={"is_wireless": False})

        result = scanner.discover()
        assert result["connected"] is True
        assert result["device_info"]["manufacturer"] == "Emerson"
        assert len(result["variables"]) == 1
        # protocol findings appended (HART 7 + writable -> HART-SEC-002 at least)
        ids = [f.get("id") for f in result["security_findings"]]
        assert "HART-SEC-002" in ids

    def test_discover_wireless_merges_into_device_info(self):
        from oida.protocols.hart.scanner import HARTDeviceInfo

        scanner = HARTScanner({"rhost": "10.0.0.5"})
        scanner.client = MagicMock()
        di = HARTDeviceInfo(manufacturer_id=1, protocol_revision=7, lock_state=LockState.UNLOCKED)
        scanner.read_device_info = MagicMock(return_value=di)
        scanner.read_all_variables = MagicMock(return_value=[])
        scanner.read_output_info = MagicMock(return_value={})
        scanner.detect_wirelesshart = MagicMock(
            return_value={
                "is_wireless": True,
                "is_gateway": True,
                "network_id": 0x1234,
                "sub_device_count": 2,
                "long_tag": "GW",
                "security_findings": [{"id": "HART-WIRELESS-001"}],
            }
        )
        result = scanner.discover()
        assert result["device_info"]["is_wireless"] is True
        assert result["device_info"]["wireless_network_id"] == 0x1234
        ids = [f.get("id") for f in result["security_findings"]]
        assert "HART-WIRELESS-001" in ids


# ===========================================================================
# FuzzMixin: radamsa-backed fuzz path
# ===========================================================================


class TestRadamsaFuzz:
    def test_fuzz_falls_back_to_basic_when_radamsa_unavailable(self):
        client = FakeClient(default=FakeResponse(response_code=0))
        scanner = make_scanner(client=client)
        fake_lazy = MagicMock()
        fake_lazy.is_available = False
        with patch("oida.utils.lazy_import.lazy_import", return_value=fake_lazy):
            result = scanner.fuzz_commands(iterations=4, command_list=[0])
        # Basic-fuzz shape: 'tested' present and equals payload-slice count.
        assert result["tested"] == 4

    def test_fuzz_with_radamsa_flags_anomaly_on_unexpected_code(self):
        # baseline returns 0; a fuzzed send returns an unexpected code (not in
        # the allowed too-few/too-large/etc set) -> anomaly recorded.
        seq = {"n": 0}

        def responder(command, address, data):
            seq["n"] += 1
            if seq["n"] == 1:
                return FakeResponse(response_code=0)  # baseline
            return FakeResponse(response_code=8)  # unexpected => anomaly

        client = FakeClient(default=responder)
        scanner = make_scanner(client=client)

        fake_lazy = MagicMock()
        fake_lazy.is_available = True
        # fuzz() yields (payload, desc) tuples
        fake_lazy.fuzz = lambda base, count=1: [(b"\xaa\xbb", "mutated")]
        with patch("oida.utils.lazy_import.lazy_import", return_value=fake_lazy):
            result = scanner.fuzz_commands(iterations=4, command_list=[1])
        assert result["tested"] > 0
        assert len(result["anomalies"]) >= 1
        assert any(a.get("response_code") == 8 for a in result["anomalies"])


# ===========================================================================
# SecurityMixin: bruteforce_lock orchestration
# ===========================================================================


class TestBruteforceLock:
    def test_bruteforce_not_connected(self):
        scanner = make_scanner(client=None)
        result = scanner.bruteforce_lock("codes.txt")
        assert result["success"] is False and result["error"] == "Not connected"

    def test_bruteforce_no_wordlist(self):
        scanner = make_scanner(client=MagicMock())
        result = scanner.bruteforce_lock("")
        assert result["error"] == "Wordlist file required"

    def test_bruteforce_not_supported(self):
        from hartip import HARTResponseCode

        client = FakeClient(
            responses={76: FakeResponse(response_code=int(HARTResponseCode.UNDEFINED_COMMAND))}
        )
        scanner = make_scanner(client=client)
        result = scanner.bruteforce_lock("codes.txt")
        assert "not supported" in result["error"].lower()

    def test_bruteforce_already_unlocked(self):
        client = FakeClient(responses={76: FakeResponse(response_code=0, payload=bytes([0]))})
        scanner = make_scanner(client=client)
        result = scanner.bruteforce_lock("codes.txt")
        assert result["success"] is True
        assert "unlocked" in result["password"].lower()

    def test_bruteforce_permanently_locked(self):
        client = FakeClient(responses={76: FakeResponse(response_code=0, payload=bytes([2]))})
        scanner = make_scanner(client=client)
        result = scanner.bruteforce_lock("codes.txt")
        assert result["success"] is False
        assert "permanently" in result["error"].lower()

    def test_bruteforce_locked_runs_password_scanner(self):
        """Locked device delegates to make_password_scanner and returns its result."""
        client = FakeClient(responses={76: FakeResponse(response_code=0, payload=bytes([1]))})
        scanner = make_scanner(client=client)

        fake_runner = MagicMock(return_value={"success": True, "password": "1234", "tested": 9})
        with patch(
            "oida.utils.login_scanner.make_password_scanner", return_value=fake_runner
        ) as mk:
            result = scanner.bruteforce_lock("codes.txt", delay=0.05)
        mk.assert_called_once()
        assert result == {"success": True, "password": "1234", "tested": 9}


# ===========================================================================
# EnumerationMixin: poll-address scan
# ===========================================================================


class TestScanPollAddresses:
    def test_scan_finds_devices_per_address(self):
        scanner = make_scanner(client=None)
        lib_info = DeviceInfo(
            manufacturer_id=0x26,
            manufacturer_name="Emerson",
            device_type=0x2A,
        )

        def make_probe_client(*a, **kw):
            c = MagicMock()

            # only address 0 and 2 answer
            def read_uid(addr):
                if addr in (0, 2):
                    return FakeResponse(response_code=0, parsed=lib_info)
                return FakeResponse(response_code=1)

            c.read_unique_id.side_effect = read_uid
            return c

        with patch(
            "oida.protocols.hart.hartip.HARTIPClient",
            side_effect=make_probe_client,
        ):
            results = scanner.scan_poll_addresses(0, 3, threads=2, timeout=0.1)
        addrs = sorted(r["address"] for r in results)
        assert addrs == [0, 2]
        assert results[0]["manufacturer"] == "Emerson"

    def test_scan_handles_connection_errors(self):
        scanner = make_scanner(client=None)

        with patch(
            "oida.protocols.hart.hartip.HARTIPClient",
            side_effect=OSError("refused"),
        ):
            results = scanner.scan_poll_addresses(0, 2, threads=2, timeout=0.1)
        assert results == []

    def test_scan_closes_client_when_connect_fails(self):
        # Regression: a client that constructs but fails to connect must still
        # be closed, otherwise the probe leaks its socket/resources.
        scanner = make_scanner(client=None)
        created = []

        def make_probe_client(*a, **kw):
            c = MagicMock()
            c.connect.side_effect = OSError("refused")
            created.append(c)
            return c

        with patch(
            "oida.protocols.hart.hartip.HARTIPClient",
            side_effect=make_probe_client,
        ):
            results = scanner.scan_poll_addresses(0, 2, threads=2, timeout=0.1)

        assert results == []
        assert created, "expected probe clients to be constructed"
        for c in created:
            c.close.assert_called_once()


# ===========================================================================
# nxc proto_flow end-to-end dispatch
# ===========================================================================


def _full_args(**overrides):
    base = dict(
        scan_addresses=None,
        enumerate_commands=False,
        security_analysis=False,
        fuzz=False,
        scan_mode="enumeration",
        read_all_vars=False,
        read_id=False,
        read_pv=False,
        read_current=False,
        read_tag=False,
        read_output=False,
        read_status=False,
        enumerate_device_specific=False,
        probe_calibration=False,
        probe_write=False,
        list_sub_devices=False,
        check_lock=False,
        bruteforce_lock=None,
        raw_command=None,
        write_poll_addr=None,
        write_tag=None,
        write_message=None,
        master_reset=False,
        confirm=False,
        quiet=True,
        detect_wireless=False,
        wireless_info=False,
        probe_version=False,
        tcp=False,
        port=5094,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _flow_nxc(args):
    h = hart.__new__(hart)
    h.protocol_name = "HART"
    h.default_port = 5094
    h.host = "10.0.0.5"
    h.logger = get_logger(protocol="HART", host="10.0.0.5", port=5094, verbose=False)
    h.results = {"host": "10.0.0.5", "ip": "10.0.0.5", "data": {}, "success": None}
    h.conn = None
    h.args = args
    return h


class TestProtoFlow:
    def test_proto_flow_address_scan_mode_short_circuits(self):
        args = _full_args(scan_addresses="0-3")
        h = _flow_nxc(args)
        h._convert_args_to_dict = MagicMock(return_value={"rhost": "10.0.0.5"})
        scanner = MagicMock()
        scanner.scan_poll_addresses.return_value = [
            {"address": 1, "manufacturer": "E", "device_type": 1, "device_type_name": "x"}
        ]
        with patch.object(nxc_connection, "HARTScanner", return_value=scanner):
            h.proto_flow()
        # address scan ran; normal connect path skipped
        scanner.scan_poll_addresses.assert_called_once()
        assert "address_scan" in h.results["data"]

    def test_proto_flow_connection_failure_sets_error(self):
        args = _full_args()
        h = _flow_nxc(args)
        h._convert_args_to_dict = MagicMock(return_value={"rhost": "10.0.0.5"})
        scanner = MagicMock()
        scanner.connect.return_value = None  # connection fails
        with patch.object(nxc_connection, "HARTScanner", return_value=scanner):
            h.proto_flow()
        assert h.results["success"] is False
        assert h.results["error"] == "Connection failed"

    def test_proto_flow_full_mode_runs_enum_and_security(self):
        args = _full_args(scan_mode="full")
        h = _flow_nxc(args)
        h._convert_args_to_dict = MagicMock(return_value={"rhost": "10.0.0.5"})
        scanner = MagicMock()
        scanner.connect.return_value = MagicMock()
        scanner.psk_identity = None
        scanner.psk_key = None
        scanner.cipher_suite = None
        scanner.read_device_info.return_value = None
        scanner.read_all_variables.return_value = []
        scanner.read_output_info.return_value = {}
        scanner.enumerate_commands.return_value = {"supported": [0], "unsupported": []}
        scanner.security_analysis.return_value = [{"severity": "high", "issue": "x"}]
        with patch.object(nxc_connection, "HARTScanner", return_value=scanner):
            h.proto_flow()
        # full mode auto-enables both enumeration and security analysis
        scanner.enumerate_commands.assert_called_once()
        scanner.security_analysis.assert_called_once()

    def test_proto_flow_discovery_mode_stops_early(self):
        args = _full_args(scan_mode="discovery")
        h = _flow_nxc(args)
        h._convert_args_to_dict = MagicMock(return_value={"rhost": "10.0.0.5"})
        scanner = MagicMock()
        scanner.connect.return_value = MagicMock()
        scanner.psk_identity = None
        scanner.psk_key = None
        scanner.cipher_suite = None
        scanner.read_device_info.return_value = None
        with patch.object(nxc_connection, "HARTScanner", return_value=scanner):
            h.proto_flow()
        # discovery mode must not probe variables / enumerate / analyze
        scanner.enumerate_commands.assert_not_called()
        scanner.security_analysis.assert_not_called()
        scanner.read_all_variables.assert_not_called()

    # --- scan_mode derived from the --discover/--full shortcut flags ---
    # The real HART argparse Namespace has no scan_mode attribute; proto_flow
    # must derive it from the boolean discovery flags (finding #1).
    def test_proto_flow_discover_flag_stops_early(self):
        # No scan_mode attr at all; only --discover set.
        args = _full_args(discover=True, full=False, quick=False)
        del args.scan_mode
        h = _flow_nxc(args)
        h._convert_args_to_dict = MagicMock(return_value={"rhost": "10.0.0.5"})
        scanner = MagicMock()
        scanner.connect.return_value = MagicMock()
        scanner.psk_identity = None
        scanner.psk_key = None
        scanner.cipher_suite = None
        scanner.read_device_info.return_value = None
        with patch.object(nxc_connection, "HARTScanner", return_value=scanner):
            h.proto_flow()
        scanner.enumerate_commands.assert_not_called()
        scanner.security_analysis.assert_not_called()
        scanner.read_all_variables.assert_not_called()

    def test_proto_flow_full_flag_runs_enum_and_security(self):
        # No scan_mode attr; only --full set -> auto enum + security.
        args = _full_args(discover=False, full=True, quick=False)
        del args.scan_mode
        h = _flow_nxc(args)
        h._convert_args_to_dict = MagicMock(return_value={"rhost": "10.0.0.5"})
        scanner = MagicMock()
        scanner.connect.return_value = MagicMock()
        scanner.psk_identity = None
        scanner.psk_key = None
        scanner.cipher_suite = None
        scanner.read_device_info.return_value = None
        scanner.read_all_variables.return_value = []
        scanner.read_output_info.return_value = {}
        scanner.enumerate_commands.return_value = {"supported": [0], "unsupported": []}
        scanner.security_analysis.return_value = [{"severity": "high", "issue": "x"}]
        with patch.object(nxc_connection, "HARTScanner", return_value=scanner):
            h.proto_flow()
        scanner.enumerate_commands.assert_called_once()
        scanner.security_analysis.assert_called_once()

    def test_proto_flow_enumerate_device_specific_flag_reaches_handler(self):
        # --enumerate-device-specific now reaches its handler (finding #2).
        args = _full_args(enumerate_device_specific=True, command_range="128-130")
        del args.scan_mode
        h = _flow_nxc(args)
        h._convert_args_to_dict = MagicMock(return_value={"rhost": "10.0.0.5"})
        scanner = MagicMock()
        scanner.connect.return_value = MagicMock()
        scanner.psk_identity = None
        scanner.psk_key = None
        scanner.cipher_suite = None
        scanner.read_device_info.return_value = None
        scanner.read_all_variables.return_value = []
        scanner.read_output_info.return_value = {}
        scanner.enumerate_device_specific_commands.return_value = [129]
        with patch.object(nxc_connection, "HARTScanner", return_value=scanner):
            h.proto_flow()
        scanner.enumerate_device_specific_commands.assert_called_once()
        assert h.results["data"]["device_specific_commands"] == [129]

    def test_proto_flow_probe_write_flag_reaches_handler(self):
        # --probe-write reaches _handle_command_probes (finding #2). With
        # --confirm it runs security_analysis; the handler is now reachable.
        args = _full_args(probe_write=True, confirm=True)
        del args.scan_mode
        h = _flow_nxc(args)
        h._convert_args_to_dict = MagicMock(return_value={"rhost": "10.0.0.5"})
        scanner = MagicMock()
        scanner.connect.return_value = MagicMock()
        scanner.psk_identity = None
        scanner.psk_key = None
        scanner.cipher_suite = None
        scanner.read_device_info.return_value = None
        scanner.read_all_variables.return_value = []
        scanner.read_output_info.return_value = {}
        scanner.security_analysis.return_value = [
            {"severity": "high", "issue": "Write command accessible"}
        ]
        with patch.object(nxc_connection, "HARTScanner", return_value=scanner):
            h.proto_flow()
        assert "command_probes" in h.results["data"]

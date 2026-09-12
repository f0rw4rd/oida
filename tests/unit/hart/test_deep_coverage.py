#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Deep unit tests for the HART module's behavioral logic.

These tests target the previously-uncovered code paths:
  * mixins/security.py    -- confirm-gating of mutating probes, lock analysis,
                             finding emission (HART-SEC-010/011, HART-LOCK-*).
  * mixins/enumeration.py -- command enumeration response classification,
                             WirelessHART detection, sub-device listing.
  * mixins/fuzz.py        -- write-command building (cmd 6/17/18/38/42),
                             raw-command result construction, basic fuzzing.
  * cli_runner.py     -- proto_flow dispatch helpers, targeted-read wiring,
                             and the --confirm gates on every mutating handler.

The hartip-py transport is mocked: a `FakeClient` returns scripted
`FakeResponse` objects per HART command so we assert on what the scanner
*builds and sends* and how it *classifies* responses, not on a live device.
"""

import struct
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from oida.protocols.hart.scanner import HARTScanner, LockState
from oida.protocols.hart.cli_runner import hart
from oida.utils.ics_logger import get_logger

pytestmark = [pytest.mark.hart]


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeResponse:
    """Stand-in for hartip.HARTIPResponse."""

    def __init__(self, response_code=0, payload=b"", parsed=None, device_status=0):
        self.response_code = response_code
        self.payload = payload
        self.parsed = parsed
        self.device_status = device_status


class FakeClient:
    """Scriptable HART-IP client.

    `responses` maps a HART command number -> FakeResponse (or callable
    taking (command, address, data) -> FakeResponse). Records every
    send_command call so tests can assert on the wire payload built by the
    scanner.
    """

    def __init__(self, responses=None, default=None):
        self.responses = responses or {}
        self.default = default if default is not None else FakeResponse(response_code=1)
        self.sent = []  # list of (command, address, data)
        self.closed = False

    def send_command(self, command, address=0, data=b""):
        self.sent.append((command, address, data))
        resp = self.responses.get(command, self.default)
        if callable(resp):
            return resp(command, address, data)
        return resp

    def close(self):
        self.closed = True

    def connect(self):
        return self

    # high-level helpers used by mixins (delegate to send_command-style lookup)
    def read_lock_state(self, address=0):
        return self.send_command(76, address)

    def read_unique_id(self, address=0):
        return self.send_command(0, address)

    def read_long_tag(self, address=0):
        return self.send_command(20, address)

    def read_additional_status(self, address=0):
        return self.send_command(48, address)

    def write_poll_address(self, new_address, address=0, loop_current_mode=0):
        self.sent.append((6, address, ("poll", new_address)))
        return self.responses.get(6, self.default)

    def write_tag_descriptor_date(self, tag, descriptor, day, month, year, address=0):
        self.sent.append((18, address, ("tag", tag, descriptor, day, month, year)))
        return self.responses.get(18, self.default)

    def write_message(self, message, address=0):
        self.sent.append((17, address, ("msg", message)))
        return self.responses.get(17, self.default)

    def perform_self_test(self, address=0):
        return self.send_command(41, address)


def make_scanner(confirm=False, server_version=None, client=None, poll_addr=0):
    scanner = HARTScanner({"rhost": "10.0.0.5", "confirm": confirm, "poll-addr": poll_addr})
    scanner.server_version = server_version
    scanner.client = client
    return scanner


def make_nxc(args_kwargs=None, scanner=None, conn=True):
    """Build a hart() nxc instance without triggering proto_flow()."""
    h = hart.__new__(hart)
    h.protocol_name = "HART"
    h.default_port = 5094
    h.host = "10.0.0.5"
    h.logger = get_logger(protocol="HART", host="10.0.0.5", port=5094, verbose=False)
    h.results = {"host": "10.0.0.5", "ip": "10.0.0.5", "data": {}}
    h.scanner = scanner if scanner is not None else MagicMock()
    h.conn = conn
    h.args = SimpleNamespace(**(args_kwargs or {}))
    return h


# ===========================================================================
# SecurityMixin: confirm-gating (the core safety behavior)
# ===========================================================================


class TestSecurityConfirmGating:
    def test_unconfirmed_does_not_probe_write_commands(self):
        """Without --confirm, NO write/dangerous commands are transmitted."""
        client = FakeClient(default=FakeResponse(response_code=0))
        scanner = make_scanner(confirm=False, client=client)

        findings = scanner.security_analysis()

        # The only command-level interaction allowed is the non-mutating
        # Command 48 (read additional status). Cmd 6/17/18/38/42/45/46 must NOT
        # appear on the wire.
        sent_cmds = {c for (c, _a, _d) in client.sent}
        mutating = {6, 17, 18, 19, 35, 38, 42, 43, 44, 45, 46, 50}
        assert sent_cmds.isdisjoint(mutating)

        # And the skip-notice finding is emitted instead.
        issues = [f["issue"] for f in findings]
        assert "Write/calibration accessibility probes skipped" in issues
        assert "No authentication" in issues

    def test_confirmed_probes_write_and_dangerous_commands(self):
        """With --confirm, accessible write/dangerous commands are flagged."""

        def responder(command, address, data):
            # Everything responds "success" => accessible.
            return FakeResponse(response_code=0)

        client = FakeClient(default=responder)
        scanner = make_scanner(confirm=True, client=client)

        findings = scanner.security_analysis()
        sent_cmds = {c for (c, _a, _d) in client.sent}

        # Confirm path actually transmits the write/dangerous probes.
        assert 6 in sent_cmds and 17 in sent_cmds and 42 in sent_cmds

        issues = [f["issue"] for f in findings]
        # Write-command accessibility (medium) for Cmd 6.
        assert any("Write command accessible: Write Polling Address" == i for i in issues)
        # Dangerous-command accessibility (critical) for Cmd 42 master reset.
        assert any("Dangerous command accessible: Master Reset" == i for i in issues)

        # Each accessible-write finding carries the command number + severity.
        wc = next(
            f for f in findings if f["issue"] == "Write command accessible: Write Polling Address"
        )
        assert wc["command"] == 6

    def test_confirmed_undefined_commands_not_flagged(self):
        """Commands returning UNDEFINED/NOT_IMPLEMENTED are not flagged accessible."""
        from hartip import HARTResponseCode

        client = FakeClient(
            default=FakeResponse(response_code=int(HARTResponseCode.UNDEFINED_COMMAND))
        )
        scanner = make_scanner(confirm=True, client=client)

        findings = scanner.security_analysis()
        issues = [f["issue"] for f in findings]
        assert not any(i.startswith("Write command accessible") for i in issues)
        assert not any(i.startswith("Dangerous command accessible") for i in issues)

    def test_dangerous_command_writeprotect_suppressed(self):
        """Dangerous cmd returning IN_WRITE_PROTECT_MODE is not flagged."""
        from hartip import HARTResponseCode

        def responder(command, address, data):
            if command in (42, 43, 45, 46):
                return FakeResponse(response_code=int(HARTResponseCode.IN_WRITE_PROTECT_MODE))
            return FakeResponse(response_code=int(HARTResponseCode.UNDEFINED_COMMAND))

        client = FakeClient(default=responder)
        scanner = make_scanner(confirm=True, client=client)
        findings = scanner.security_analysis()
        assert not any(f["issue"].startswith("Dangerous command accessible") for f in findings)

    def test_confirmed_writeprotect_detection_enabled(self):
        """Cmd 38 IN_WRITE_PROTECT_MODE => 'Write protect enabled' info finding."""
        from hartip import HARTResponseCode

        def responder(command, address, data):
            if command == 38:
                return FakeResponse(response_code=int(HARTResponseCode.IN_WRITE_PROTECT_MODE))
            return FakeResponse(response_code=int(HARTResponseCode.UNDEFINED_COMMAND))

        client = FakeClient(default=responder)
        scanner = make_scanner(confirm=True, client=client)
        findings = scanner.security_analysis()
        issues = [f["issue"] for f in findings]
        assert "Write protect enabled" in issues
        assert "Write protect disabled" not in issues

    def test_confirmed_writeprotect_disabled_finding(self):
        """Cmd 38 success (not write-protect) => 'Write protect disabled' high."""
        from hartip import HARTResponseCode

        def responder(command, address, data):
            if command == 38:
                return FakeResponse(response_code=0)
            return FakeResponse(response_code=int(HARTResponseCode.UNDEFINED_COMMAND))

        client = FakeClient(default=responder)
        scanner = make_scanner(confirm=True, client=client)
        findings = scanner.security_analysis()
        next(f for f in findings if f["issue"] == "Write protect disabled")

    def test_not_connected_returns_error(self):
        scanner = make_scanner(confirm=True, client=None)
        scanner.security_analysis()


class TestSecurityVersionAndStatusFindings:
    def test_hartip_v1_no_tls_finding(self):
        from hartip import HARTResponseCode

        client = FakeClient(
            default=FakeResponse(response_code=int(HARTResponseCode.UNDEFINED_COMMAND))
        )
        scanner = make_scanner(confirm=False, server_version=1, client=client)
        findings = scanner.security_analysis()
        v1 = next(f for f in findings if f.get("id") == "HART-SEC-010")
        assert "v1" in v1["issue"]

    def test_no_v1_finding_when_version_2(self):
        client = FakeClient(default=FakeResponse(response_code=1))
        scanner = make_scanner(confirm=False, server_version=2, client=client)
        findings = scanner.security_analysis()
        assert not any(f.get("id") == "HART-SEC-010" for f in findings)

    def test_extended_status_flags_emit_finding(self):
        """Cmd 48 with an active extended-status bit -> HART-SEC-011 medium."""
        # ext_status 0x01 == maintenance_required per decode_extended_device_status.
        cmd48 = FakeResponse(
            response_code=0,
            payload=bytes([0x00, 0x01]),
            parsed={"extended_device_status": 0x01},
        )
        client = FakeClient(responses={48: cmd48}, default=FakeResponse(response_code=1))
        scanner = make_scanner(confirm=False, client=client)
        findings = scanner.security_analysis()
        sec011 = next(f for f in findings if f.get("id") == "HART-SEC-011")
        assert "maintenance_required" in sec011["description"]

    def test_no_status_finding_when_clean(self):
        cmd48 = FakeResponse(
            response_code=0, payload=bytes([0, 0]), parsed={"extended_device_status": 0}
        )
        client = FakeClient(responses={48: cmd48}, default=FakeResponse(response_code=1))
        scanner = make_scanner(confirm=False, client=client)
        findings = scanner.security_analysis()
        assert not any(f.get("id") == "HART-SEC-011" for f in findings)


# ===========================================================================
# SecurityMixin: lock state + lock analysis + unlock command building
# ===========================================================================


class TestLockState:
    def test_read_lock_state_unlocked(self):
        client = FakeClient(responses={76: FakeResponse(response_code=0, payload=bytes([0]))})
        scanner = make_scanner(client=client)
        assert scanner.read_lock_state() == LockState.UNLOCKED

    def test_read_lock_state_locked(self):
        client = FakeClient(responses={76: FakeResponse(response_code=0, payload=bytes([1]))})
        scanner = make_scanner(client=client)
        assert scanner.read_lock_state() == LockState.LOCKED

    def test_read_lock_state_not_supported(self):
        from hartip import HARTResponseCode

        client = FakeClient(
            responses={76: FakeResponse(response_code=int(HARTResponseCode.UNDEFINED_COMMAND))}
        )
        scanner = make_scanner(client=client)
        assert scanner.read_lock_state() == LockState.NOT_SUPPORTED

    def test_read_lock_state_no_client(self):
        scanner = make_scanner(client=None)
        assert scanner.read_lock_state() == LockState.UNKNOWN

    def test_try_unlock_builds_command_71_with_unlock_byte(self):
        """try_unlock builds Cmd 71 payload: 0x00 (unlock) + 6-byte packed code."""
        from hartip import pack_ascii

        client = FakeClient(responses={71: FakeResponse(response_code=0)})
        scanner = make_scanner(client=client)
        ok = scanner.try_unlock("SECRET")
        assert ok is True
        cmd, addr, data = client.sent[-1]
        assert cmd == 71
        assert data[0] == 0  # 0 = unlock
        expected_code = pack_ascii("SECRET"[:8].ljust(8).upper())
        assert data[1:] == expected_code

    def test_try_lock_builds_command_71_with_lock_byte(self):
        client = FakeClient(responses={71: FakeResponse(response_code=0)})
        scanner = make_scanner(client=client)
        ok = scanner.try_lock("KEY")
        assert ok is True
        cmd, addr, data = client.sent[-1]
        assert cmd == 71
        assert data[0] == 1  # 1 = lock

    def test_try_unlock_failure_returns_false(self):
        client = FakeClient(responses={71: FakeResponse(response_code=7)})
        scanner = make_scanner(client=client)
        assert scanner.try_unlock("nope") is False


# ===========================================================================
# EnumerationMixin: command enumeration response classification
# ===========================================================================


class TestEnumerateCommands:
    def test_classifies_supported_unsupported_error(self):
        from hartip import HARTResponseCode

        def responder(command, address, data):
            if command == 0:
                return FakeResponse(response_code=int(HARTResponseCode.SUCCESS))
            if command == 1:
                return FakeResponse(response_code=int(HARTResponseCode.UNDEFINED_COMMAND))
            if command == 2:
                return FakeResponse(response_code=int(HARTResponseCode.CMD_NOT_IMPLEMENTED))
            # other-non-error codes count as supported with a code label
            return FakeResponse(response_code=int(HARTResponseCode.IN_WRITE_PROTECT_MODE))

        client = FakeClient(default=responder)
        scanner = make_scanner(client=client)
        result = scanner.enumerate_commands("0-3")

        assert 0 in result["supported"]
        assert 1 in result["unsupported"]
        assert 2 in result["unsupported"]
        # cmd 3 -> non-error, non-undefined => supported with a named detail
        assert 3 in result["supported"]
        assert result["details"][3] == "IN_WRITE_PROTECT_MODE"

    def test_timeout_goes_to_error_bucket(self):
        from hartip import HARTIPTimeoutError

        def responder(command, address, data):
            raise HARTIPTimeoutError("no answer")

        client = FakeClient(default=responder)
        scanner = make_scanner(client=client)
        result = scanner.enumerate_commands("5")
        assert result["error"] == [5]

    def test_range_and_comma_parsing(self):
        client = FakeClient(default=FakeResponse(response_code=0))
        scanner = make_scanner(client=client)
        scanner.enumerate_commands("0-2,7")
        sent = sorted(c for (c, _a, _d) in client.sent)
        assert sent == [0, 1, 2, 7]

    def test_not_connected(self):
        scanner = make_scanner(client=None)
        result = scanner.enumerate_commands("0-1")
        assert result == {"error": ["Not connected"]}

    def test_enumerate_device_specific_returns_supported(self):
        """Device-specific (128-253) returns only the supported command list."""
        from hartip import HARTResponseCode

        def responder(command, address, data):
            if command in (130, 131):
                return FakeResponse(response_code=int(HARTResponseCode.SUCCESS))
            return FakeResponse(response_code=int(HARTResponseCode.UNDEFINED_COMMAND))

        client = FakeClient(default=responder)
        scanner = make_scanner(client=client)
        supported = scanner.enumerate_device_specific_commands(128, 132)
        assert supported == [130, 131]


# ===========================================================================
# EnumerationMixin: WirelessHART detection + sub-device listing
# ===========================================================================


class TestWirelessDetection:
    def test_network_id_detection_marks_wireless(self):
        """Cmd 768 success -> is_wireless True, network_id parsed big-endian."""

        def responder(command, address, data):
            if command == 768:
                return FakeResponse(response_code=0, payload=struct.pack(">H", 0xABCD))
            return FakeResponse(response_code=1)

        client = FakeClient(default=responder)
        scanner = make_scanner(client=client)
        result = scanner.detect_wirelesshart(device_info=None)
        assert result["is_wireless"] is True
        assert result["network_id"] == 0xABCD
        assert "network_id_768" in result["detection_method"]
        # wireless findings emitted
        ids = [f["id"] for f in result["security_findings"]]
        assert "HART-WIRELESS-001" in ids
        assert "HART-WIRELESS-003" in ids

    def test_gateway_detection_via_subdevice_count(self):
        def responder(command, address, data):
            if command == 85:
                return FakeResponse(response_code=0, payload=struct.pack(">H", 3))
            return FakeResponse(response_code=1)

        client = FakeClient(default=responder)
        scanner = make_scanner(client=client)
        result = scanner.detect_wirelesshart(device_info=None)
        assert result["is_gateway"] is True
        assert result["sub_device_count"] == 3
        ids = [f["id"] for f in result["security_findings"]]
        assert "HART-WIRELESS-002" in ids

    def test_non_wireless_emits_no_findings(self):
        client = FakeClient(default=FakeResponse(response_code=1))
        scanner = make_scanner(client=client)
        result = scanner.detect_wirelesshart(device_info=None)
        assert result["is_wireless"] is False
        assert result["security_findings"] == []

    def test_detect_not_connected(self):
        scanner = make_scanner(client=None)
        result = scanner.detect_wirelesshart(device_info=None)
        assert result["is_wireless"] is False
        assert "error" in result


class TestSubDeviceListing:
    def test_lists_subdevices_with_parsed_identity(self):
        """Cmd 85 count then Cmd 84 per-index returns mfr/type/id."""

        def responder(command, address, data):
            if command == 85:
                return FakeResponse(response_code=0, payload=struct.pack(">H", 2))
            if command == 84:
                idx = struct.unpack(">H", data)[0]
                # payload: mfr_id, dev_type, 3-byte id, then long tag region
                payload = bytes([0x26, 0x2A, idx, 0x00, 0x01]) + b"\x00" * 30
                return FakeResponse(response_code=0, payload=payload)
            return FakeResponse(response_code=1)

        client = FakeClient(default=responder)
        scanner = make_scanner(client=client)
        subs = scanner.list_sub_devices()
        assert len(subs) == 2
        assert subs[0]["manufacturer_id"] == 0x26
        assert subs[0]["device_type"] == 0x2A
        assert subs[0]["index"] == 0
        assert "manufacturer" in subs[0]

    def test_no_subdevices_when_count_zero(self):
        client = FakeClient(
            responses={85: FakeResponse(response_code=0, payload=struct.pack(">H", 0))}
        )
        scanner = make_scanner(client=client)
        assert scanner.list_sub_devices() == []

    def test_subdevices_not_connected(self):
        scanner = make_scanner(client=None)
        assert scanner.list_sub_devices() == []


# ===========================================================================
# FuzzMixin: write command building + raw command + basic fuzz
# ===========================================================================


class TestWriteOperations:
    def test_write_poll_address_uses_command_6(self):
        client = FakeClient(responses={6: FakeResponse(response_code=0)})
        scanner = make_scanner(client=client, poll_addr=2)
        ok = scanner.write_poll_address(7)
        assert ok is True
        cmd, addr, data = client.sent[-1]
        assert cmd == 6
        assert addr == 2  # current poll address used for the request
        assert data == ("poll", 7)

    def test_write_tag_uses_command_18(self):
        client = FakeClient(responses={18: FakeResponse(response_code=0)})
        scanner = make_scanner(client=client)
        ok = scanner.write_tag("NEWTAG", "DESC", date=(15, 6, 124))
        assert ok is True
        cmd, addr, data = client.sent[-1]
        assert cmd == 18
        assert data[1] == "NEWTAG" and data[2] == "DESC"
        assert data[3:6] == (15, 6, 124)

    def test_write_message_uses_command_17(self):
        client = FakeClient(responses={17: FakeResponse(response_code=0)})
        scanner = make_scanner(client=client)
        assert scanner.write_message("HELLO") is True
        cmd, addr, data = client.sent[-1]
        assert cmd == 17 and data[1] == "HELLO"

    def test_reset_config_flag_command_38(self):
        client = FakeClient(responses={38: FakeResponse(response_code=0)})
        scanner = make_scanner(client=client)
        assert scanner.reset_config_flag() is True
        assert client.sent[-1][0] == 38

    def test_master_reset_command_42(self):
        client = FakeClient(responses={42: FakeResponse(response_code=0)})
        scanner = make_scanner(client=client)
        assert scanner.perform_master_reset() is True
        # Critically: must NOT run self-test (cmd 41) before reset.
        sent_cmds = [c for (c, _a, _d) in client.sent]
        assert 41 not in sent_cmds
        assert sent_cmds == [42]

    def test_write_returns_false_on_error_code(self):
        client = FakeClient(responses={6: FakeResponse(response_code=7)})
        scanner = make_scanner(client=client)
        assert scanner.write_poll_address(3) is False

    def test_write_not_connected(self):
        scanner = make_scanner(client=None)
        assert scanner.write_poll_address(1) is False
        assert scanner.write_message("x") is False
        assert scanner.reset_config_flag() is False
        assert scanner.perform_master_reset() is False


class TestRawCommand:
    def test_raw_command_success_result(self):
        resp = FakeResponse(response_code=0, payload=b"\xde\xad", device_status=0x10)
        client = FakeClient(responses={11: resp})
        scanner = make_scanner(client=client)
        result = scanner.send_raw_command(11, b"\x01")
        assert result["success"] is True
        assert result["command"] == 11
        assert result["payload"] == "dead"
        assert result["payload_length"] == 2
        assert result["device_status"] == 0x10
        assert result["response_code_name"] == "SUCCESS"

    def test_raw_command_unknown_code_name(self):
        resp = FakeResponse(response_code=200, payload=b"")
        client = FakeClient(responses={50: resp})
        scanner = make_scanner(client=client)
        result = scanner.send_raw_command(50)
        assert result["success"] is False
        assert "Unknown" in result["response_code_name"]

    def test_raw_command_not_connected(self):
        scanner = make_scanner(client=None)
        result = scanner.send_raw_command(1)
        assert result == {"success": False, "error": "Not connected"}


class TestBasicFuzz:
    def test_basic_fuzz_counts_payloads_per_command(self):
        client = FakeClient(default=FakeResponse(response_code=0))
        scanner = make_scanner(client=client)
        # _basic_fuzz bypasses radamsa; iterations limits payload slice.
        result = scanner._basic_fuzz(iterations=3, command_list=[0, 1])
        assert result["tested"] == 6  # 2 commands * 3 payloads
        per_cmd = {c["command"]: c["iterations"] for c in result["commands_fuzzed"]}
        assert per_cmd == {0: 3, 1: 3}

    def test_basic_fuzz_records_timeout_anomaly(self):
        from hartip import HARTIPTimeoutError

        def responder(command, address, data):
            raise HARTIPTimeoutError("dead")

        client = FakeClient(default=responder)
        scanner = make_scanner(client=client)
        result = scanner._basic_fuzz(iterations=2, command_list=[0])
        assert len(result["anomalies"]) == 2
        assert all(a["error"] == "timeout" for a in result["anomalies"])

    def test_fuzz_commands_not_connected(self):
        scanner = make_scanner(client=None)
        assert scanner.fuzz_commands() == {"error": "Not connected"}


# ===========================================================================
# cli_runner: --confirm gating on every mutating handler
# ===========================================================================


class TestNxcConfirmGating:
    def test_probe_write_blocked_without_confirm(self):
        scanner = MagicMock()
        h = make_nxc({"confirm": False}, scanner=scanner)
        h._handle_command_probes()
        scanner.security_analysis.assert_not_called()
        assert "command_probes" not in h.results["data"]

    def test_probe_write_runs_with_confirm(self):
        scanner = MagicMock()
        scanner.security_analysis.return_value = [
            {"severity": "medium", "issue": "Write command accessible: Write Message"},
            {"severity": "high", "issue": "No authentication"},
        ]
        h = make_nxc({"confirm": True}, scanner=scanner)
        h._handle_command_probes()
        scanner.security_analysis.assert_called_once()
        probes = h.results["data"]["command_probes"]
        assert len(probes) == 1
        assert "command accessible" in probes[0]["issue"].lower()

    def test_fuzz_blocked_without_confirm(self):
        scanner = MagicMock()
        h = make_nxc(
            {"confirm": False, "fuzz_iterations": 10, "fuzz_commands": None}, scanner=scanner
        )
        h._handle_fuzz()
        scanner.fuzz_commands.assert_not_called()

    def test_fuzz_runs_with_confirm_and_parses_command_list(self):
        scanner = MagicMock()
        scanner.fuzz_commands.return_value = {"tested": 5, "anomalies": []}
        h = make_nxc(
            {"confirm": True, "fuzz_iterations": 7, "fuzz_commands": "1, 2 ,3"}, scanner=scanner
        )
        h._handle_fuzz()
        scanner.fuzz_commands.assert_called_once_with(7, command_list=[1, 2, 3])
        assert h.results["data"]["fuzzing"]["tested"] == 5

    def test_fuzz_invalid_command_list_aborts(self):
        scanner = MagicMock()
        h = make_nxc(
            {"confirm": True, "fuzz_iterations": 7, "fuzz_commands": "1,bad"}, scanner=scanner
        )
        h._handle_fuzz()
        scanner.fuzz_commands.assert_not_called()

    def test_raw_command_blocked_without_confirm(self):
        scanner = MagicMock()
        h = make_nxc({"confirm": False, "raw_command": 42, "raw_data": None}, scanner=scanner)
        h._handle_raw_command()
        scanner.send_raw_command.assert_not_called()

    def test_raw_command_runs_with_confirm(self):
        scanner = MagicMock()
        scanner.send_raw_command.return_value = {"success": True, "response_code_name": "SUCCESS"}
        h = make_nxc({"confirm": True, "raw_command": 11, "raw_data": "01 02"}, scanner=scanner)
        h._handle_raw_command()
        scanner.send_raw_command.assert_called_once_with(11, b"\x01\x02")

    def test_raw_command_invalid_hex_aborts(self):
        scanner = MagicMock()
        h = make_nxc({"confirm": True, "raw_command": 11, "raw_data": "zzzz"}, scanner=scanner)
        h._handle_raw_command()
        scanner.send_raw_command.assert_not_called()

    def test_bruteforce_blocked_without_confirm(self):
        scanner = MagicMock()
        h = make_nxc(
            {"confirm": False, "bruteforce_lock": "codes.txt", "bruteforce_delay": 0.1},
            scanner=scanner,
        )
        h._handle_bruteforce_lock()
        scanner.bruteforce_lock.assert_not_called()

    def test_bruteforce_runs_with_confirm_and_emits_finding(self):
        scanner = MagicMock()
        scanner.bruteforce_lock.return_value = {"success": True, "password": "1234", "tested": 5}
        h = make_nxc(
            {"confirm": True, "bruteforce_lock": "codes.txt", "bruteforce_delay": 0.2},
            scanner=scanner,
        )
        h._handle_bruteforce_lock()
        scanner.bruteforce_lock.assert_called_once_with(wordlist="codes.txt", delay=0.2)
        assert h.results["data"]["bruteforce"]["password"] == "1234"

    def test_write_operations_all_gated_without_confirm(self):
        scanner = MagicMock()
        h = make_nxc(
            {
                "confirm": False,
                "write_poll_addr": 5,
                "write_tag": "T",
                "write_message": "M",
                "reset_config_flag": True,
                "self_test": True,
                "master_reset": True,
                "write_descriptor": "",
            },
            scanner=scanner,
        )
        h._handle_write_operations()
        scanner.write_poll_address.assert_not_called()
        scanner.write_tag.assert_not_called()
        scanner.write_message.assert_not_called()
        scanner.reset_config_flag.assert_not_called()
        scanner.perform_self_test.assert_not_called()
        scanner.perform_master_reset.assert_not_called()

    def test_write_operations_dispatch_with_confirm(self):
        scanner = MagicMock()
        scanner.write_poll_address.return_value = True
        scanner.write_tag.return_value = True
        scanner.perform_master_reset.return_value = True
        h = make_nxc(
            {
                "confirm": True,
                "write_poll_addr": 9,
                "write_tag": "TAG1",
                "write_descriptor": "DESC",
                "master_reset": True,
            },
            scanner=scanner,
        )
        h._handle_write_operations()
        scanner.write_poll_address.assert_called_once_with(9)
        scanner.write_tag.assert_called_once_with("TAG1", "DESC")
        scanner.perform_master_reset.assert_called_once()

    def test_lock_operations_gated_without_confirm(self):
        scanner = MagicMock()
        h = make_nxc({"confirm": False, "unlock": "1234", "lock": "5678"}, scanner=scanner)
        h._handle_lock_operations()
        scanner.try_unlock.assert_not_called()
        scanner.try_lock.assert_not_called()

    def test_lock_operations_dispatch_with_confirm(self):
        scanner = MagicMock()
        scanner.try_unlock.return_value = True
        scanner.try_lock.return_value = True
        h = make_nxc({"confirm": True, "unlock": "abc", "lock": "def"}, scanner=scanner)
        h._handle_lock_operations()
        scanner.try_unlock.assert_called_once_with("abc")
        scanner.try_lock.assert_called_once_with("def")


# ===========================================================================
# cli_runner: dispatch helpers + targeted reads + finding emission
# ===========================================================================


class TestNxcDispatchHelpers:
    def test_has_specific_action_true_for_each_flag(self):
        for flag in ["read_pv", "enumerate_commands", "fuzz", "master_reset", "raw_command"]:
            h = make_nxc({flag: True})
            assert h._has_specific_action() is True

    def test_has_specific_action_false_when_none(self):
        h = make_nxc({"read_pv": False})
        assert h._has_specific_action() is False

    def test_enumerate_device_specific_records_results(self):
        # --enumerate-device-specific is gated on --confirm (blind-probes
        # vendor-defined commands that may mutate the device).
        scanner = MagicMock()
        scanner.enumerate_device_specific_commands.return_value = [130, 200]
        h = make_nxc({"confirm": True}, scanner=scanner)
        h._handle_enumerate_device_specific()
        assert h.results["data"]["device_specific_commands"] == [130, 200]

    def test_enumerate_device_specific_requires_confirm(self):
        scanner = MagicMock()
        h = make_nxc({"confirm": False}, scanner=scanner)
        h._handle_enumerate_device_specific()
        scanner.enumerate_device_specific_commands.assert_not_called()

    def test_enumerate_commands_records_supported(self):
        scanner = MagicMock()
        scanner.enumerate_commands.return_value = {"supported": [0, 1], "unsupported": [2]}
        h = make_nxc({"command_range": "0-2"}, scanner=scanner)
        h._handle_enumerate_commands()
        scanner.enumerate_commands.assert_called_once_with("0-2")
        assert h.results["data"]["command_enumeration"]["supported"] == [0, 1]

    def test_security_analysis_records_findings(self):
        scanner = MagicMock()
        scanner.security_analysis.return_value = [
            {"severity": "critical", "issue": "A"},
            {"severity": "high", "issue": "B"},
        ]
        h = make_nxc({}, scanner=scanner)
        h._handle_security_analysis()
        assert h.results["data"]["security_findings"] == scanner.security_analysis.return_value

    def test_check_lock_unlocked_emits_security_finding(self):
        scanner = MagicMock()
        scanner.read_lock_state.return_value = LockState.UNLOCKED
        h = make_nxc({}, scanner=scanner)
        h.logger.clear_findings()
        h._handle_check_lock()
        assert h.results["data"]["lock_state"] == LockState.UNLOCKED
        findings = h.logger.to_list()
        assert any("No authentication" in str(f) for f in findings)

    def test_check_lock_locked_no_finding(self):
        scanner = MagicMock()
        scanner.read_lock_state.return_value = LockState.LOCKED
        h = make_nxc({}, scanner=scanner)
        h.logger.clear_findings()
        h._handle_check_lock()
        assert h.results["data"]["lock_state"] == LockState.LOCKED
        # A locked device should not emit the "No authentication" finding.
        findings = h.logger.to_list()
        assert not any("No authentication" in str(f) for f in findings)

    def test_address_scan_parses_range_and_clamps(self):
        scanner = MagicMock()
        scanner.scan_poll_addresses.return_value = [
            {"address": 0, "manufacturer": "Emerson", "device_type": 42, "device_type_name": "PT"}
        ]
        h = make_nxc({"threads": 4, "timeout": 2}, scanner=scanner)
        h._handle_address_scan("0-99")  # end clamped to 15
        args, _ = scanner.scan_poll_addresses.call_args
        assert args[0] == 0 and args[1] == 15
        assert len(h.results["data"]["address_scan"]) == 1

    def test_address_scan_invalid_range(self):
        scanner = MagicMock()
        h = make_nxc({}, scanner=scanner)
        h._handle_address_scan("not-a-range")
        scanner.scan_poll_addresses.assert_not_called()
        assert "error" in h.results

    def test_list_sub_devices_records(self):
        scanner = MagicMock()
        scanner.list_sub_devices.return_value = [
            {"index": 0, "manufacturer": "E", "device_type": 1, "long_tag": "TAG", "device_id": "x"}
        ]
        h = make_nxc({}, scanner=scanner)
        h._handle_list_sub_devices()
        assert len(h.results["data"]["sub_devices"]) == 1


class TestNxcTargetedReads:
    def test_read_pv_records_primary_variable(self):
        from oida.protocols.hart.scanner import HARTVariable

        scanner = MagicMock()
        scanner.read_primary_variable.return_value = HARTVariable(
            name="Primary Variable", value=25.5, units_code=32, units_name="degC"
        )
        h = make_nxc({"read_pv": True}, scanner=scanner)
        h.results["data"]["device_info"] = {}
        h._handle_targeted_reads()
        pv = h.results["data"]["primary_variable"]
        assert pv["value"] == 25.5 and pv["units"] == "degC"

    def test_read_current_records_loop_current(self):
        scanner = MagicMock()
        scanner.read_current_and_percent.return_value = (12.5, 50.0)
        h = make_nxc({"read_current": True}, scanner=scanner)
        h.results["data"]["device_info"] = {}
        h._handle_targeted_reads()
        lc = h.results["data"]["loop_current"]
        assert lc["mA"] == 12.5 and lc["percent"] == 50.0

    def test_read_status_records_additional_status(self):
        scanner = MagicMock()
        scanner.read_additional_status.return_value = {
            "extended_device_status_decoded": {"maintenance_required": True, "other": False}
        }
        h = make_nxc({"read_status": True}, scanner=scanner)
        h.results["data"]["device_info"] = {}
        h._handle_targeted_reads()
        assert "additional_status" in h.results["data"]

    def test_read_output_records_output_info(self):
        scanner = MagicMock()
        scanner.read_output_info.return_value = {
            "lower_range": 0.0,
            "upper_range": 100.0,
            "units_name": "psi",
            "damping_seconds": 2.0,
        }
        h = make_nxc({"read_output": True}, scanner=scanner)
        h.results["data"]["device_info"] = {}
        h._handle_targeted_reads()
        assert h.results["data"]["output_info"]["upper_range"] == 100.0

    def test_targeted_reads_noop_when_no_flags(self):
        scanner = MagicMock()
        h = make_nxc({}, scanner=scanner)
        h.results["data"]["device_info"] = {}
        h._handle_targeted_reads()
        scanner.read_primary_variable.assert_not_called()
        scanner.read_current_and_percent.assert_not_called()


# ===========================================================================
# cli_runner: create_conn_obj encryption state + enum/print host info
# ===========================================================================


class TestNxcConnectionAndHostInfo:
    def test_create_conn_obj_flags_plaintext(self):
        scanner = MagicMock()
        scanner.connect.return_value = MagicMock()
        scanner.psk_identity = None
        scanner.psk_key = None
        scanner.cipher_suite = None
        h = make_nxc({"port": 5094, "tcp": False, "probe_version": False}, scanner=scanner)
        h.create_conn_obj()
        enc = h.results["data"]["encryption_status"]
        assert enc["tls_supported"] is False
        assert enc["version"] == "HART-IP v1"

    def test_create_conn_obj_flags_tls_when_psk(self):
        scanner = MagicMock()
        scanner.connect.return_value = MagicMock()
        scanner.psk_identity = "id"
        scanner.psk_key = "deadbeef"
        scanner.cipher_suite = "TLS_PSK_WITH_AES_128_CCM"
        h = make_nxc({"port": 5094, "tcp": True, "probe_version": False}, scanner=scanner)
        h.create_conn_obj()
        enc = h.results["data"]["encryption_status"]
        assert enc["tls_supported"] is True
        assert enc["version"] == "HART-IP v2"
        assert enc["cipher"] == "TLS_PSK_WITH_AES_128_CCM"

    def test_enum_host_info_maps_device_fields(self):
        from oida.protocols.hart.scanner import HARTDeviceInfo

        scanner = MagicMock()
        scanner.read_device_info.return_value = HARTDeviceInfo(
            manufacturer_id=0x26,
            manufacturer_name="Rosemount (Emerson)",
            device_type=42,
            protocol_revision=7,
            tag="PT-101",
            unique_id=b"\x01\x02\x03",
            write_protected=False,
        )
        h = make_nxc({"detect_wireless": False, "wireless_info": False}, scanner=scanner)
        h.enum_host_info()
        di = h.results["data"]["device_info"]
        assert di["manufacturer_id"] == 0x26
        assert di["tag"] == "PT-101"
        assert di["unique_id"] == "010203"
        assert di["protocol_revision"] == 7

    def test_print_host_info_emits_writable_finding(self):
        scanner = MagicMock()
        h = make_nxc({"quiet": False}, scanner=scanner)
        h.logger.clear_findings()
        h.results["data"]["device_info"] = {
            "manufacturer": "Emerson",
            "device_type": 42,
            "protocol_revision": 7,
            "write_protected": False,
            "tag": "PT-101",
            "unique_id": "010203",
        }
        h.print_host_info()
        findings = h.logger.to_list()
        assert any("Writable access" in str(f) or "writable" in str(f).lower() for f in findings)

    def test_print_host_info_emits_outdated_protocol_for_hart5(self):
        scanner = MagicMock()
        h = make_nxc({"quiet": False}, scanner=scanner)
        h.logger.clear_findings()
        h.results["data"]["device_info"] = {
            "manufacturer": "Old",
            "device_type": 1,
            "protocol_revision": 5,
            "write_protected": True,
        }
        h.print_host_info()
        findings = h.logger.to_list()
        assert any("Outdated protocol" in str(f) or "rev 5" in str(f).lower() for f in findings)

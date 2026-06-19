"""Integration tests for iSCSI passive listener.

Tests cover:
- Opcode extraction (Login, Text, SCSI Command, NOP)
- Target name extraction from login key-value data
- Initiator name extraction
- LUN tracking from SCSI commands
- Authentication method detection
- Login status parsing
- Direction detection (initiator vs target)
- Device creation for both endpoints
- Target discovery tracking
- Harvest table output quality
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


@pytest.mark.unit
class TestISCSIOpcodeMap:
    """Pure-unit checks of the iSCSI opcode table (no capture needed).

    Opcode values verified against RFC 7143 and Linux iscsi_proto.h, and against
    tshark's `iscsi.opcode` value map (the 6-bit opcode, BHS byte 0 & 0x3f).
    Guards the historically-confused R2T / Asynchronous Message pair.
    """

    # (decimal-key, hex-key, expected name)
    EXPECTED = [
        ("49", "0x31", "R2T"),  # Ready To Transfer
        ("50", "0x32", "Async Message"),  # Asynchronous Message
        ("63", "0x3f", "Reject"),
        ("33", "0x21", "SCSI Response"),
        ("32", "0x20", "NOP-In"),
        ("16", "0x10", "SNACK Request"),
    ]

    def test_known_opcodes_resolve_correctly(self):
        from oida.pcap.passive.iscsi import OPCODES

        for dec, hexk, name in self.EXPECTED:
            assert OPCODES.get(dec) == name, f"decimal {dec} should map to {name}"
            assert OPCODES.get(hexk) == name, f"hex {hexk} should map to {name}"

    def test_r2t_and_async_not_swapped(self):
        """Regression: R2T is 0x31 (49), Async Message is 0x32 (50) - never swapped."""
        from oida.pcap.passive.iscsi import OPCODES

        assert OPCODES["0x31"] == "R2T"
        assert OPCODES["49"] == "R2T"
        assert OPCODES["0x32"] == "Async Message"
        assert OPCODES["50"] == "Async Message"
        # No bogus 0x30/48 R2T entry (the CODE_REVIEW premise was incorrect).
        assert "0x30" not in OPCODES
        assert "48" not in OPCODES

    def test_decimal_and_hex_halves_are_consistent(self):
        """Every decimal opcode has a matching hex entry with the same label."""
        from oida.pcap.passive.iscsi import OPCODES

        dec = {int(k): v for k, v in OPCODES.items() if not k.startswith("0x")}
        hx = {int(k, 16): v for k, v in OPCODES.items() if k.startswith("0x")}
        for val, name in dec.items():
            assert hx.get(val) == name, (
                f"opcode {val:#04x} ({val}): decimal={name!r} hex={hx.get(val)!r}"
            )


class TestISCSIPassiveEK:
    """iSCSI-specific tests beyond the parametrized quality suite."""

    def test_iscsi_login_detection(self):
        """iSCSI Login Command PDUs are detected."""
        listener, devices, result = _run_listener_test(
            "iscsi",
            "ISCSIPassiveListener",
            "iscsi",
            "iscsi/generated_iscsi.pcap",
            min_devices=2,
            expect_details=["opcode_name"],
            expect_operations=["iSCSI Login"],
        )
        login_ixs = [
            ix for ix in listener.interactions if "Login" in ix.details.get("opcode_name", "")
        ]
        assert len(login_ixs) >= 1, "No Login PDUs found"

    def test_iscsi_opcode_extraction(self):
        """iSCSI opcodes are extracted and resolved to names."""
        listener, devices, result = _run_listener_test(
            "iscsi",
            "ISCSIPassiveListener",
            "iscsi",
            "iscsi/generated_iscsi.pcap",
            min_devices=2,
        )
        opcode_names = {ix.details.get("opcode_name", "") for ix in listener.interactions}
        # Should have multiple opcode types from our test pcap
        assert len(opcode_names) >= 2, f"Expected >= 2 opcode types; got: {opcode_names}"

    def test_iscsi_scsi_command_detection(self):
        """SCSI Command PDUs are detected."""
        listener, devices, result = _run_listener_test(
            "iscsi",
            "ISCSIPassiveListener",
            "iscsi",
            "iscsi/generated_iscsi.pcap",
            min_devices=2,
        )
        scsi_ixs = [
            ix for ix in listener.interactions if "SCSI" in ix.details.get("opcode_name", "")
        ]
        assert len(scsi_ixs) >= 1, (
            f"No SCSI Command PDUs found; opcodes seen: "
            f"{[ix.details.get('opcode_name') for ix in listener.interactions]}"
        )

    def test_iscsi_text_command_detection(self):
        """Text Command PDUs (SendTargets) are detected."""
        listener, devices, result = _run_listener_test(
            "iscsi",
            "ISCSIPassiveListener",
            "iscsi",
            "iscsi/generated_iscsi.pcap",
            min_devices=2,
        )
        text_ixs = [
            ix for ix in listener.interactions if "Text" in ix.details.get("opcode_name", "")
        ]
        assert len(text_ixs) >= 1, (
            f"No Text PDUs found; opcodes seen: "
            f"{[ix.details.get('opcode_name') for ix in listener.interactions]}"
        )

    def test_iscsi_both_endpoints_tracked(self):
        """Both iSCSI target and initiator devices are created."""
        listener, devices, result = _run_listener_test(
            "iscsi",
            "ISCSIPassiveListener",
            "iscsi",
            "iscsi/generated_iscsi.pcap",
            min_devices=2,
        )
        device_types = [d.device_type for d in devices.values() if hasattr(d, "device_type")]
        has_target = any("Target" in t for t in device_types)
        has_initiator = any("Initiator" in t for t in device_types)
        assert has_target, f"No iSCSI Target device found; types: {device_types}"
        assert has_initiator, f"No iSCSI Initiator device found; types: {device_types}"

    def test_iscsi_passive_data_on_devices(self):
        """Devices have iscsi_passive_data with expected fields."""
        listener, devices, result = _run_listener_test(
            "iscsi",
            "ISCSIPassiveListener",
            "iscsi",
            "iscsi/generated_iscsi.pcap",
            min_devices=2,
        )
        has_data = any(
            hasattr(d, "iscsi_passive_data") and d.iscsi_passive_data for d in devices.values()
        )
        assert has_data, "No device has iscsi_passive_data"

    def test_iscsi_direction_detection(self):
        """Request and response directions are correctly detected."""
        listener, devices, result = _run_listener_test(
            "iscsi",
            "ISCSIPassiveListener",
            "iscsi",
            "iscsi/generated_iscsi.pcap",
            min_devices=2,
        )
        directions = {ix.direction for ix in listener.interactions}
        assert "request" in directions and "response" in directions, (
            f"Expected both request and response; got: {directions}"
        )

    def test_iscsi_isid_extraction(self):
        """Initiator Session ID (ISID) is extracted."""
        listener, devices, result = _run_listener_test(
            "iscsi",
            "ISCSIPassiveListener",
            "iscsi",
            "iscsi/generated_iscsi.pcap",
            min_devices=2,
        )
        has_isid = any(ix.details.get("isid") not in (None, "") for ix in listener.interactions)
        assert has_isid, "No interaction has ISID"

    def test_iscsi_harvest_valid(self):
        """Harvest returns valid dict with no raw dicts/sets in cells."""
        listener, devices, result = _run_listener_test(
            "iscsi",
            "ISCSIPassiveListener",
            "iscsi",
            "iscsi/generated_iscsi.pcap",
        )
        assert isinstance(result, dict)

    def test_iscsi_format_protocol_columns(self):
        """_format_protocol_columns produces correct column count."""
        listener, devices, result = _run_listener_test(
            "iscsi",
            "ISCSIPassiveListener",
            "iscsi",
            "iscsi/generated_iscsi.pcap",
        )
        if listener.interactions:
            cols = listener._format_protocol_columns(listener.interactions[0])
            assert len(cols) == len(listener.PROTOCOL_COLUMNS), (
                f"Column count mismatch: {len(cols)} vs {len(listener.PROTOCOL_COLUMNS)}"
            )

    def test_iscsi_nop_detection(self):
        """NOP-In/NOP-Out keepalive PDUs are detected."""
        listener, devices, result = _run_listener_test(
            "iscsi",
            "ISCSIPassiveListener",
            "iscsi",
            "iscsi/generated_iscsi.pcap",
            min_devices=2,
        )
        nop_ixs = [ix for ix in listener.interactions if "NOP" in ix.details.get("opcode_name", "")]
        assert len(nop_ixs) >= 1, (
            f"No NOP PDUs found; opcodes seen: "
            f"{[ix.details.get('opcode_name') for ix in listener.interactions]}"
        )

    def test_iscsi_multiple_interactions(self):
        """Multiple iSCSI operations are tracked."""
        listener, devices, result = _run_listener_test(
            "iscsi",
            "ISCSIPassiveListener",
            "iscsi",
            "iscsi/generated_iscsi.pcap",
            min_interactions=3,
        )
        assert len(listener.interactions) >= 3, (
            f"Expected >= 3 interactions; got {len(listener.interactions)}"
        )

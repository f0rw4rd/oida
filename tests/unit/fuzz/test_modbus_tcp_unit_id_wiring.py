"""Regression tests for Modbus TCP fuzzer Unit ID wiring.

Confirmed finding: the configured ``unit_id`` protocol option was declared
but ignored -- ``_create_mbap_header()`` and the static MBAP header blocks
hardcoded Unit_ID 0x01, so every fuzz request was sent to unit 1 regardless
of ``--protocol-options unit_id=N``.

These tests render the actual boofuzz blocks and assert the configured value
ends up in the wire bytes. They fail before the fix (always 0x01) and pass
after.
"""

import pytest
from boofuzz import Block, Request, Static

from oida.fuzz.core.config import FuzzerConfig
from oida.fuzz.protocols.modbus.tcp import ModbusFuzzer


class MockConnectionFactory:
    """Mock connection factory so no real socket is opened."""

    def create_connection(self, *args, **kwargs):
        class MockConnection:
            def open(self):
                pass

            def close(self):
                pass

            def send(self, data):
                pass

            def recv(self, size):
                return b""

        return MockConnection()


def _make_fuzzer(unit_id=None):
    options = {}
    if unit_id is not None:
        options["unit_id"] = unit_id
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=502,
        session_filename="modbus_unit_id_test",
        protocol="modbus",
        # Skip capability enumeration -- it opens a real pymodbus connection.
        enumerate=False,
        protocol_options=options,
    )
    return ModbusFuzzer(config=config, connection_factory=MockConnectionFactory())


def _render_mbap(fuzzer):
    """Render the MBAP header produced by _create_mbap_header().

    The header's Size field references a sibling "PDU" block, so wrap both in
    a Request (mirroring real usage) and return the rendered Unit_ID byte,
    which is the last byte of the MBAP header (offset 6).
    """
    request = Request(
        "render_probe",
        children=(
            fuzzer._create_mbap_header(),
            Block("PDU", children=(Static("Function_Code", b"\x03"),)),
        ),
    )
    rendered = request.render()
    # MBAP = Transaction(2) Protocol(2) Length(2) Unit_ID(1) => Unit_ID at index 6
    return rendered[6]


class TestModbusTCPUnitIdWiring:
    def test_default_unit_id_is_one(self):
        fuzzer = _make_fuzzer()
        assert fuzzer.unit_id == 1
        assert _render_mbap(fuzzer) == 0x01

    def test_configured_unit_id_used_in_mbap_header(self):
        fuzzer = _make_fuzzer(unit_id=5)
        assert fuzzer.unit_id == 5
        # The bug: this rendered 0x01 regardless of configuration.
        assert _render_mbap(fuzzer) == 0x05

    def test_configured_unit_id_high_value(self):
        fuzzer = _make_fuzzer(unit_id=247)
        assert _render_mbap(fuzzer) == 0xF7

    def test_configured_unit_id_in_baseline_request(self):
        """The static MBAP_Header_Baseline block must also honor unit_id."""
        fuzzer = _make_fuzzer(unit_id=9)
        # Accessing .session lazily builds the protocol definition; the
        # baseline_read request is connected into the session graph.
        baseline = None
        for node in fuzzer.session.nodes.values():
            if node.name == "Modbus_Baseline":
                baseline = node
                break
        assert baseline is not None, "Modbus_Baseline request not found in session"
        rendered = baseline.render()
        # MBAP header Unit_ID is the 7th byte (index 6).
        assert rendered[6] == 0x09

    def test_broadcast_header_unaffected(self):
        """Broadcast header must stay Unit_ID 0 regardless of unit_id option."""
        fuzzer = _make_fuzzer(unit_id=5)
        request = Request(
            "broadcast_probe",
            children=(
                fuzzer._create_broadcast_mbap_header(0x0001),
                Block("PDU", children=(Static("Function_Code", b"\x05"),)),
            ),
        )
        rendered = request.render()
        assert rendered[6] == 0x00


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

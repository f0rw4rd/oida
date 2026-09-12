"""Integration tests for the Modbus UDP and RTU transport variants.

The Modbus/TCP path is covered by test_modbus_passive.py.  These tests
exercise the two additional transports the listener now handles through the
same processing path:
- Modbus/UDP (mbudp -- MBAP over UDP)
- Modbus RTU framed over a stream (mbrtu -- no MBAP, unit id + CRC16)
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestModbusUDP:
    _PCAP = "modbus/oida_modbus_udp_fc_matrix.pcap"
    _FILTER = "mbtcp || mbudp || mbrtu"
    _DECODE = {"udp.port==502": "mbudp"}

    def test_udp_function_codes(self):
        listener, _, _ = _run_listener_test(
            "modbus",
            "ModbusPassiveListener",
            self._FILTER,
            self._PCAP,
            min_interactions=5,
            expect_details=["function_code", "unit_id"],
            expect_operations=["Read", "Write"],
            decode_as=self._DECODE,
        )
        fcs = set()
        for ix in listener.interactions:
            fc = ix.details.get("function_code")
            if fc:
                fcs.add(int(fc))
        # FC1/3 (read) + FC6/16 (write) were produced
        assert {1, 3, 6, 16} <= fcs, f"got {fcs}"

    def test_udp_protocol_label(self):
        listener, devices, _ = _run_listener_test(
            "modbus",
            "ModbusPassiveListener",
            self._FILTER,
            self._PCAP,
            decode_as=self._DECODE,
        )
        protocols = {
            getattr(d, "modbus_passive_data", {}).get("protocol") for d in devices.values()
        }
        assert "Modbus/UDP" in protocols, f"got {protocols}"

    def test_udp_writes_detected(self):
        listener, _, _ = _run_listener_test(
            "modbus",
            "ModbusPassiveListener",
            self._FILTER,
            self._PCAP,
            decode_as=self._DECODE,
        )
        writes = sum(s.write_count for s in listener.sessions.values())
        assert writes >= 2, f"expected write ops; got {writes}"


class TestModbusRTU:
    _PCAP = "modbus/oida_modbus_rtu_over_tcp.pcap"
    _FILTER = "mbtcp || mbudp || mbrtu"
    _DECODE = {"tcp.port==502": "mbrtu"}

    def test_rtu_function_codes(self):
        listener, _, _ = _run_listener_test(
            "modbus",
            "ModbusPassiveListener",
            self._FILTER,
            self._PCAP,
            min_interactions=4,
            expect_details=["function_code", "unit_id"],
            expect_operations=["Read", "Write"],
            decode_as=self._DECODE,
        )
        fcs = {
            int(ix.details["function_code"])
            for ix in listener.interactions
            if ix.details.get("function_code")
        }
        assert {1, 3, 6} <= fcs, f"got {fcs}"

    def test_rtu_protocol_label(self):
        listener, devices, _ = _run_listener_test(
            "modbus",
            "ModbusPassiveListener",
            self._FILTER,
            self._PCAP,
            decode_as=self._DECODE,
        )
        protocols = {
            getattr(d, "modbus_passive_data", {}).get("protocol") for d in devices.values()
        }
        assert "Modbus/RTU" in protocols, f"got {protocols}"

    def test_rtu_unit_ids(self):
        """RTU carries the slave/unit id in the mbrtu layer (no MBAP)."""
        listener, _, _ = _run_listener_test(
            "modbus",
            "ModbusPassiveListener",
            self._FILTER,
            self._PCAP,
            decode_as=self._DECODE,
        )
        unit_ids = set()
        for s in listener.sessions.values():
            unit_ids |= s.unit_ids
        # slaves 0x01, 0x0a and 0x11 appear in the RTU fixture
        assert {1, 10, 17} <= unit_ids, f"got {unit_ids}"

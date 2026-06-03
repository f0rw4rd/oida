"""--probe-ops must filter to read-only types unless --confirm.

CODE_REVIEW.md CRITICAL: the probe iterated _get_fuzz_message_types(),
which includes ADT admissions, ORM orders, BAR/DFT financial, MFN
master-file updates — every probe was a real HL7 write.
"""

import unittest
from unittest.mock import MagicMock, patch


class TestProbeReadOnlyFilter(unittest.TestCase):
    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_default_filters_to_qry_qbp_only(self):
        """Without --confirm only QRY/QBP types should be probed."""
        from oida.protocols.hl7 import hl7

        mock_args = MagicMock()
        mock_args.port = 2575
        mock_args.timeout = 1
        mock_args.confirm = False
        for attr in (
            "find", "get", "store", "move", "aet_brute", "probe_ops",
            "worklist", "dump_all", "fuzz", "tls", "verbose",
            "enum_operators", "enum_devices", "time_analysis",
        ):
            setattr(mock_args, attr, False)
        mock_args.aet = "OIDA"
        mock_args.called_aet = "ANY"

        scanner = hl7(mock_args, None, "127.0.0.1")
        scanner.logger = MagicMock()
        scanner.results = {"data": {}}
        scanner._create_test_message = MagicMock(return_value="MSH|...")
        scanner._send_mllp_message = MagicMock(return_value=None)
        scanner._extract_ack_code = MagicMock(return_value=None)

        scanner._probe_operations()

        # Without --confirm: only QRY/QBP types attempted.
        creates = scanner._create_test_message.call_args_list
        msg_types = {call.args[0] for call in creates}
        self.assertTrue(msg_types.issubset({"QRY", "QBP"}),
                        f"Got unexpected types: {msg_types}")

    @patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
    def test_warning_emitted_about_filter(self):
        from oida.protocols.hl7 import hl7

        mock_args = MagicMock()
        mock_args.port = 2575
        mock_args.timeout = 1
        mock_args.confirm = False
        for attr in (
            "find", "get", "store", "move", "aet_brute", "probe_ops",
            "worklist", "dump_all", "fuzz", "tls", "verbose",
            "enum_operators", "enum_devices", "time_analysis",
        ):
            setattr(mock_args, attr, False)
        mock_args.aet = "OIDA"
        mock_args.called_aet = "ANY"

        scanner = hl7(mock_args, None, "127.0.0.1")
        scanner.logger = MagicMock()
        scanner.results = {"data": {}}
        scanner._create_test_message = MagicMock(return_value=None)
        scanner._send_mllp_message = MagicMock(return_value=None)
        scanner._extract_ack_code = MagicMock(return_value=None)

        scanner._probe_operations()

        warn_msgs = [str(c) for c in scanner.logger.warning.call_args_list]
        self.assertTrue(
            any("read-only" in m for m in warn_msgs),
            f"Expected read-only filter warning, got: {warn_msgs}",
        )


class TestSegmentBuilderAliasKwargs(unittest.TestCase):
    """mixins/pharmacy.py uses caller-friendly kwarg names — RXA/RXG/RXD
    must accept them so calls don't TypeError into silent fallback."""

    def test_rxa_accepts_completion_status(self):
        from oida.protocols.hl7.segments import HL7SegmentBuilder

        b = HL7SegmentBuilder(version="2.5")
        rxa = b.build_rxa(admin_code="J1100", completion_status="CP")
        self.assertIsNotNone(rxa)

    def test_rxg_accepts_give_code_alias(self):
        from oida.protocols.hl7.segments import HL7SegmentBuilder

        b = HL7SegmentBuilder(version="2.5")
        rxg = b.build_rxg(give_code="J1100", give_amount="10")
        self.assertIsNotNone(rxg)

    def test_rxd_accepts_dispense_aliases(self):
        from oida.protocols.hl7.segments import HL7SegmentBuilder

        b = HL7SegmentBuilder(version="2.5")
        rxd = b.build_rxd(
            dispense_code="J1100",
            actual_amount="10",
            actual_units="mg",
            prescription_number="RX1",
            refills_remaining="2",
        )
        self.assertIsNotNone(rxd)


class TestParseMessageOrders(unittest.TestCase):
    """parse_message must return an 'orders' key — response.py reads it."""

    def test_orders_key_present_on_empty_input(self):
        from oida.protocols.hl7.segments import HL7SegmentParser

        result = HL7SegmentParser.parse_message(
            "MSH|^~\\&|TEST|TEST|TEST|TEST|20260603120000||ACK^A01|MSG1|P|2.5"
        )
        self.assertIn("orders", result, "orders key missing — silent KeyError risk")
        self.assertIsInstance(result["orders"], list)


if __name__ == "__main__":
    unittest.main()

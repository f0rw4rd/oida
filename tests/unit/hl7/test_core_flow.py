"""Unit tests for the HL7 core scanner class (oida.protocols.hl7.__init__):
proto_flow dispatch, connection setup, host-info fingerprint, response parse,
result export and teardown.
"""

import types
import unittest
from unittest.mock import Mock, patch

from oida.protocols.hl7.utils import MLLP_END, MLLP_START
from tests.unit.hl7.conftest import _make_hl7_instance


def _flow_args(**kw):
    """Args namespace with every proto_flow feature flag defaulted off."""
    flags = [
        "enum_all",
        "probe_ops",
        "send_adt",
        "send_oru",
        "send_orm",
        "send_rx",
        "send_ras",
        "send_rgv",
        "send_rds",
        "send_siu",
        "send_qry",
        "enum_patients",
        "query_obs",
        "query_rx",
        "query_orders",
        "send_mdm",
        "send_mfn",
        "query_mfn",
        "query_whoami",
        "query_tabular",
        "query_imm",
        "query_imm_forecast",
        "send_bar",
        "send_dft",
        "pcd_01",
        "pcd_03",
        "pcd_alarm",
        "fuzz",
        "enum_providers",
        "enum_apps",
        "enum_locations",
    ]
    base = {f: False for f in flags}
    base.update(
        dict(
            hl7_version="2.5",
            sending_app="OIDA",
            sending_facility="SECURITY",
            message_type=None,
            output=None,
            port=2575,
            timeout=5,
            tls=False,
        )
    )
    base.update(kw)
    return types.SimpleNamespace(**base)


def _scanner(args):
    s = _make_hl7_instance(args, None, "10.0.0.1")
    s.logger = Mock()
    return s


def _mllp(body):
    return MLLP_START + body.encode() + MLLP_END


@patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
class TestProtoFlowDispatch(unittest.TestCase):
    def test_aborts_when_connection_fails(self):
        s = _scanner(_flow_args())
        with patch.object(s, "create_conn_obj", return_value=False) as conn:
            with patch.object(s, "enum_host_info") as enum:
                s.proto_flow()
        conn.assert_called_once()
        enum.assert_not_called()

    def test_probe_ops_short_circuits_other_ops(self):
        s = _scanner(_flow_args(probe_ops=True))
        with (
            patch.object(s, "create_conn_obj", return_value=True),
            patch.object(s, "_probe_operations") as probe,
            patch.object(s, "_analyze_security"),
            patch.object(s, "_export_results"),
            patch.object(s, "_disconnect"),
            patch.object(s, "enum_host_info") as enum,
        ):
            s.proto_flow()
        probe.assert_called_once()
        # enum_host_info (the normal path) must NOT run when probe_ops short-circuits.
        enum.assert_not_called()

    def test_enum_all_expands_to_all_flags(self):
        args = _flow_args(enum_all=True)
        s = _scanner(args)
        with (
            patch.object(s, "create_conn_obj", return_value=True),
            patch.object(s, "enum_host_info"),
            patch.object(s, "print_host_info"),
            patch.object(s, "_analyze_security"),
            patch.object(s, "_export_results"),
            patch.object(s, "_send_qry_message"),
            patch.object(s, "_send_qry_obs_message"),
            patch.object(s, "_send_qry_rx_message"),
            patch.object(s, "_send_qry_orders_message"),
            patch.object(s, "_enum_providers"),
            patch.object(s, "_enum_apps"),
            patch.object(s, "_enum_locations"),
        ):
            s.proto_flow()
        # enum_all sets the individual enumeration flags.
        self.assertTrue(args.enum_providers)
        self.assertTrue(args.enum_apps)
        self.assertTrue(args.enum_locations)
        self.assertTrue(args.enum_patients)
        self.assertTrue(args.query_obs)

    def test_selected_send_flags_dispatch_their_handlers(self):
        s = _scanner(_flow_args(send_adt=True, query_whoami=True, fuzz=True))
        with (
            patch.object(s, "create_conn_obj", return_value=True),
            patch.object(s, "enum_host_info"),
            patch.object(s, "print_host_info"),
            patch.object(s, "_analyze_security"),
            patch.object(s, "_export_results"),
            patch.object(s, "_send_adt_message") as adt,
            patch.object(s, "_send_qbp_q40_message") as whoami,
            patch.object(s, "_fuzz_messages") as fuzz,
            patch.object(s, "_send_oru_message") as oru,
        ):
            s.proto_flow()
        adt.assert_called_once()
        whoami.assert_called_once()
        fuzz.assert_called_once()
        oru.assert_not_called()  # send_oru was False

    def test_dependency_gate_sets_error(self):
        s = _scanner(_flow_args())
        with patch("oida.protocols.hl7.HL7APY_AVAILABLE", False):
            s.proto_flow()
        self.assertFalse(s.results["success"])
        self.assertIn("hl7apy", s.results["error"])


@patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
class TestCreateConnObj(unittest.TestCase):
    def test_success_sets_connected_flag(self):
        s = _scanner(_flow_args(tls=True))
        with patch(
            "oida.protocols.hl7.ConnectionHelper.create_tls_tcp_connection",
            return_value=Mock(),
        ):
            ok = s.create_conn_obj()
        self.assertTrue(ok)
        self.assertTrue(s.results["data"]["connected"])
        self.assertTrue(s.results["data"]["tls_enabled"])

    def test_refused_returns_false(self):
        s = _scanner(_flow_args())
        with patch(
            "oida.protocols.hl7.ConnectionHelper.create_tls_tcp_connection",
            side_effect=ConnectionRefusedError("nope"),
        ):
            ok = s.create_conn_obj()
        self.assertFalse(ok)
        self.assertFalse(s.results["data"]["connected"])
        s.logger.fail.assert_called_with("Connection refused")

    def test_timeout_returns_false(self):
        s = _scanner(_flow_args())
        with patch(
            "oida.protocols.hl7.ConnectionHelper.create_tls_tcp_connection",
            side_effect=TimeoutError(),
        ):
            ok = s.create_conn_obj()
        self.assertFalse(ok)
        s.logger.fail.assert_called_with("Connection timed out")

    def test_generic_error_returns_false(self):
        s = _scanner(_flow_args())
        with patch(
            "oida.protocols.hl7.ConnectionHelper.create_tls_tcp_connection",
            side_effect=OSError("boom"),
        ):
            ok = s.create_conn_obj()
        self.assertFalse(ok)
        self.assertFalse(s.results["data"]["connected"])


@patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
class TestEnumAndPrintHostInfo(unittest.TestCase):
    def test_enum_host_info_parses_response(self):
        s = _scanner(_flow_args())

        class _Conn:
            def __init__(self):
                self._b = _mllp("MSH|^~\\&|MEDITECH|HOSP|OIDA|SEC|20240101||ACK|1|P|2.4\rMSA|AA|1")

            def sendall(self, d):
                pass

            def recv(self, n):
                b, self._b = self._b, b""
                return b

        s.conn = _Conn()
        s.enum_host_info()
        info = s.results["data"]["server_info"]
        self.assertEqual(info["sending_app"], "MEDITECH")
        self.assertEqual(info["vendor"], "Meditech")
        self.assertEqual(s.results["data"]["ack_code"], "AA")

    def test_print_host_info_renders_vendor_and_ack(self):
        s = _scanner(_flow_args())
        s.results["data"]["server_info"] = {
            "sending_app": "EPIC",
            "sending_facility": "HOSP",
            "version": "2.5",
            "vendor": "Epic Systems",
            "product_type": "EMR",
        }
        s.results["data"]["ack_code"] = "AR"
        s.print_host_info()
        # Vendor line displayed; AR ack routed to logger.fail.
        s.logger.fail.assert_called()
        joined = " ".join(str(c.args) for c in s.logger.display.call_args_list)
        self.assertIn("Epic Systems", joined)


@patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
class TestParseResponse(unittest.TestCase):
    def test_autodetects_version(self):
        s = _scanner(_flow_args())
        s.detected_version = None
        s._parse_response(b"MSH|^~\\&|CERNER|HOSP|OIDA|SEC|20240101||ACK|1|P|2.6\rMSA|AA|1")
        self.assertEqual(s.detected_version, "2.6")
        self.assertEqual(s.results["data"]["server_info"]["vendor"], "Cerner Corporation")

    def test_empty_response_is_noop(self):
        s = _scanner(_flow_args())
        s._parse_response(b"")
        self.assertNotIn("server_info", s.results["data"])

    def test_garbage_response_swallowed(self):
        s = _scanner(_flow_args())
        s._parse_response(b"\x00\xff not hl7")
        s.logger.debug.assert_called()


@patch("oida.protocols.hl7.HL7APY_AVAILABLE", True)
class TestExportAndDisconnect(unittest.TestCase):
    def test_export_noop_without_output_dir(self):
        s = _scanner(_flow_args(output=None))
        with patch("oida.utils.export_utils.export_data") as ed:
            s._export_results()
        ed.assert_not_called()

    def test_export_writes_server_and_findings(self):
        s = _scanner(_flow_args(output="/tmp/out", format="json"))
        s.results["data"]["server_info"] = {
            "sending_app": "EPIC",
            "sending_facility": "HOSP",
            "version": "2.5",
            "vendor": "Epic Systems",
            "product_type": "EMR",
        }
        s.results["data"]["security_findings"] = [
            {"operation": "QRY", "issue": "Unrestricted", "description": "d"}
        ]
        with patch("oida.utils.export_utils.export_data") as ed:
            s._export_results()
        # Two export_data calls: server + security findings.
        labels = [c.args[4] for c in ed.call_args_list]
        self.assertIn("hl7_server", labels)
        self.assertIn("hl7_security", labels)

    def test_export_all_format_maps_to_csv_json(self):
        s = _scanner(_flow_args(output="/tmp/out", format="all"))
        s.results["data"]["server_info"] = {"sending_app": "X"}
        with patch("oida.utils.export_utils.export_data") as ed:
            s._export_results()
        # 'all' is rewritten to 'csv,json' for the file format.
        fmt = ed.call_args_list[0].args[2]
        self.assertEqual(fmt, "csv,json")

    def test_disconnect_closes_and_clears(self):
        s = _scanner(_flow_args())
        conn = Mock()
        s.conn = conn
        s._disconnect()
        conn.close.assert_called_once()
        self.assertIsNone(s.conn)

    def test_check_dependencies_reflects_flag(self):
        with patch("oida.protocols.hl7.HL7APY_AVAILABLE", True):
            from oida.protocols.hl7 import hl7

            self.assertTrue(hl7.check_dependencies())


if __name__ == "__main__":
    unittest.main()

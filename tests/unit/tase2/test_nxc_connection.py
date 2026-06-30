#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for the TASE.2/ICCP NXC-style connection class.

TASE.2 is libiec61850-backed (pyiec61850-ng). These tests mock ONLY the
transport/library boundary -- the ``TASE2Scanner`` wrapper and the
``TASE2Client`` connection object it returns -- and drive the REAL
connection/scan flow logic in ``oida.protocols.tase2.nxc_connection``:
action dispatch, spec parsing, --confirm gating, finding emission, result
formatting and error paths.

Construction uses ``tase2.__new__(tase2)`` to bypass the auto-executing
``NetworkConnection.__init__`` so methods run in isolation with realistic args.
"""

import unittest
from types import SimpleNamespace
from unittest.mock import Mock


from oida.protocols.tase2.nxc_connection import tase2


def make_domain(name, is_vcc=False, variables=None, data_sets=None):
    """Build a realistic domain object (matches what TASE2Client returns)."""
    d = Mock()
    d.name = name
    d.is_vcc = is_vcc
    d.variables = variables if variables is not None else []
    d.data_sets = data_sets if data_sets is not None else []
    return d


def make_tase2(scanner=None, conn="__sentinel__", **arg_overrides):
    """Build a tase2 instance without running NetworkConnection.__init__."""
    obj = tase2.__new__(tase2)
    obj.protocol_name = "TASE.2"
    obj.default_port = 102
    obj.logger = Mock()
    obj.ip = "10.0.0.5"
    obj.host = "10.0.0.5"
    obj.results = {"success": None, "data": {}}

    defaults = {"port": 102, "confirm": False, "quiet": False}
    defaults.update(arg_overrides)
    obj.args = SimpleNamespace(**defaults)

    obj.scanner = scanner if scanner is not None else Mock()
    if conn == "__sentinel__":
        obj.conn = Mock(name="conn")
    else:
        obj.conn = conn
    return obj


# ---------------------------------------------------------------------------
# Action detection (_has_action)
# ---------------------------------------------------------------------------
class TestHasAction(unittest.TestCase):
    def test_no_action(self):
        obj = make_tase2()
        self.assertFalse(obj._has_action())

    def test_bool_action(self):
        obj = make_tase2(list_domains=True)
        self.assertTrue(obj._has_action())

    def test_bool_action_false(self):
        obj = make_tase2(list_domains=False)
        self.assertFalse(obj._has_action())

    def test_string_action(self):
        obj = make_tase2(read_point="VCC/P1")
        self.assertTrue(obj._has_action())


# ---------------------------------------------------------------------------
# Confirm gate (_needs_confirm + _execute_action gate)
# ---------------------------------------------------------------------------
class TestConfirmGate(unittest.TestCase):
    def test_read_action_does_not_need_confirm(self):
        obj = make_tase2(list_domains=True)
        self.assertFalse(obj._needs_confirm())

    def test_write_action_needs_confirm(self):
        obj = make_tase2(write_point="VCC/P1:1.0")
        self.assertTrue(obj._needs_confirm())

    def test_each_write_action_flagged(self):
        for action in tase2._WRITE_ACTIONS:
            obj = make_tase2(**{action: "x"})
            self.assertTrue(obj._needs_confirm(), f"{action} should require confirm")

    def test_write_action_blocked_without_confirm(self):
        conn = Mock()
        obj = make_tase2(conn=conn, write_point="VCC/P1:1.0", confirm=False)

        obj._execute_action()

        obj.logger.fail.assert_called_once()
        conn.write_point.assert_not_called()
        self.assertNotIn("action_result", obj.results["data"])

    def test_write_action_proceeds_with_confirm(self):
        conn = Mock()
        obj = make_tase2(conn=conn, write_point="VCC/P1:1.5", confirm=True)

        obj._execute_action()

        conn.write_point.assert_called_once_with("VCC", "P1", 1.5)
        self.assertEqual(obj.results["data"]["action_result"], {"success": True})


# ---------------------------------------------------------------------------
# create_conn_obj + cleartext finding
# ---------------------------------------------------------------------------
class TestCreateConnObj(unittest.TestCase):
    def test_successful_connect_emits_cleartext_finding(self):
        scanner = Mock()
        scanner.connect.return_value = Mock(name="conn")
        scanner.use_tls = False
        obj = make_tase2(scanner=scanner, conn=None)

        obj.create_conn_obj()

        self.assertIsNotNone(obj.conn)
        obj.logger.success.assert_called_once()
        obj.logger.security_finding.assert_called_once()
        finding = obj.logger.security_finding.call_args
        self.assertIn("No encryption", finding[0][0])

    def test_tls_connection_skips_cleartext_finding(self):
        scanner = Mock()
        scanner.connect.return_value = Mock(name="conn")
        scanner.use_tls = True
        obj = make_tase2(scanner=scanner, conn=None)

        obj.create_conn_obj()

        obj.logger.security_finding.assert_not_called()

    def test_failed_connect_logs_fail(self):
        scanner = Mock()
        scanner.connect.return_value = None
        obj = make_tase2(scanner=scanner, conn=None)

        obj.create_conn_obj()

        self.assertIsNone(obj.conn)
        obj.logger.fail.assert_called_once()


# ---------------------------------------------------------------------------
# enum_host_info / print_host_info / _execute_scan
# ---------------------------------------------------------------------------
class TestEnumAndPrint(unittest.TestCase):
    def test_enum_host_info_records_blt_and_domains(self):
        conn = Mock()
        conn.get_bilateral_table_id.return_value = "BLT-7"
        conn.get_server_bilateral_table_count.return_value = 3
        conn.get_domains.return_value = [
            make_domain("VCC", is_vcc=True, variables=["a", "b"], data_sets=["ds1"]),
            make_domain("ICC1", is_vcc=False, variables=["c"]),
        ]
        obj = make_tase2(conn=conn)

        obj.enum_host_info()

        self.assertEqual(obj.results["data"]["bilateral_table"]["id"], "BLT-7")
        self.assertEqual(obj.results["data"]["bilateral_table"]["count"], 3)
        self.assertEqual(obj.results["data"]["domain_count"], 2)
        domains = obj.results["data"]["domains"]
        self.assertEqual(domains[0]["type"], "VCC")
        self.assertEqual(domains[0]["variables"], 2)
        self.assertEqual(domains[0]["data_sets"], 1)
        self.assertEqual(domains[1]["type"], "ICC")

    def test_enum_host_info_handles_exception(self):
        conn = Mock()
        conn.get_bilateral_table_id.side_effect = Exception("blt fail")
        obj = make_tase2(conn=conn)

        # Should swallow the error (logged at debug) and not populate data.
        obj.enum_host_info()

        self.assertNotIn("bilateral_table", obj.results["data"])
        obj.logger.debug.assert_called()

    def test_enum_host_info_noop_without_conn(self):
        obj = make_tase2(conn=None)
        obj.enum_host_info()
        self.assertEqual(obj.results["data"], {})

    def test_print_host_info_quiet(self):
        obj = make_tase2(quiet=True)
        obj.print_host_info()
        obj.logger.display.assert_not_called()

    def test_print_host_info_displays_domains(self):
        obj = make_tase2(quiet=False)
        obj.results["data"]["bilateral_table"] = {"id": "BLT-1"}
        obj.results["data"]["domains"] = [
            {"type": "VCC", "name": "VCC", "variables": 5},
            {"type": "ICC", "name": "ICC1", "variables": 2},
        ]

        obj.print_host_info()

        displayed = " ".join(str(c.args[0]) for c in obj.logger.display.call_args_list)
        self.assertIn("TASE.2 Server", displayed)
        self.assertIn("BLT-1", displayed)
        self.assertIn("VCC", displayed)

    def test_print_host_info_truncates_many_domains(self):
        obj = make_tase2(quiet=False)
        obj.results["data"]["domains"] = [
            {"type": "ICC", "name": f"ICC{i}", "variables": i} for i in range(8)
        ]

        obj.print_host_info()

        displayed = " ".join(str(c.args[0]) for c in obj.logger.display.call_args_list)
        self.assertIn("and 3 more", displayed)

    def test_execute_scan_stores_results(self):
        scanner = Mock()
        scanner.discover.return_value = {"domains": ["VCC"]}
        obj = make_tase2(scanner=scanner)

        obj._execute_scan()

        scanner.discover.assert_called_once_with(obj.conn)
        self.assertEqual(obj.results["data"]["scan_results"], {"domains": ["VCC"]})

    def test_execute_scan_noop_without_conn(self):
        scanner = Mock()
        obj = make_tase2(scanner=scanner, conn=None)
        obj._execute_scan()
        scanner.discover.assert_not_called()


# ---------------------------------------------------------------------------
# Discovery actions (list-domains / variables / data-sets / transfer-sets)
# ---------------------------------------------------------------------------
class TestDiscoveryActions(unittest.TestCase):
    def test_list_domains(self):
        conn = Mock()
        conn.get_domains.return_value = [
            make_domain("VCC", is_vcc=True, variables=["v1"]),
            make_domain("ICC1", is_vcc=False, variables=["v2", "v3"]),
        ]
        obj = make_tase2(conn=conn, list_domains=True)

        obj._execute_action()

        self.assertEqual(obj.results["data"]["action_result"]["domains"], ["VCC", "ICC1"])

    def test_list_variables(self):
        conn = Mock()
        conn.get_domain_variables.return_value = ["P1", "P2", "P3"]
        obj = make_tase2(conn=conn, list_variables="ICC1")

        obj._execute_action()

        conn.get_domain_variables.assert_called_once_with("ICC1")
        self.assertEqual(obj.results["data"]["action_result"]["variables"], ["P1", "P2", "P3"])

    def test_list_data_sets_all(self):
        conn = Mock()
        ds = Mock()
        ds.domain, ds.name, ds.member_count = "ICC1", "DS1", 4
        conn.get_data_sets.return_value = [ds]
        # list_data_sets=True means "all domains" -> domain passed as None.
        obj = make_tase2(conn=conn, list_data_sets=True)

        obj._execute_action()

        conn.get_data_sets.assert_called_once_with(None)
        self.assertEqual(obj.results["data"]["action_result"]["data_sets"], ["ICC1/DS1"])

    def test_list_transfer_sets(self):
        conn = Mock()
        ts = Mock()
        ts.name, ts.rbe_enabled = "TS1", True
        conn.get_transfer_sets.return_value = [ts]
        obj = make_tase2(conn=conn, list_transfer_sets="ICC1")

        obj._execute_action()

        conn.get_transfer_sets.assert_called_once_with("ICC1")
        self.assertEqual(obj.results["data"]["action_result"]["transfer_sets"], ["TS1"])


# ---------------------------------------------------------------------------
# Data access actions (read/write point)
# ---------------------------------------------------------------------------
class TestDataAccess(unittest.TestCase):
    def test_read_point(self):
        conn = Mock()
        pv = Mock()
        pv.value, pv.quality, pv.point_type = 42.0, "GOOD", "Real"
        conn.read_point.return_value = pv
        obj = make_tase2(conn=conn, read_point="ICC1/P1")

        obj._execute_action()

        conn.read_point.assert_called_once_with("ICC1", "P1")
        res = obj.results["data"]["action_result"]
        self.assertEqual(res["value"], 42.0)
        self.assertEqual(res["quality"], "GOOD")

    def test_read_point_invalid_format(self):
        conn = Mock()
        obj = make_tase2(conn=conn, read_point="badformat")

        obj._execute_action()

        obj.logger.fail.assert_called_once()
        conn.read_point.assert_not_called()

    def test_read_point_handles_error(self):
        conn = Mock()
        conn.read_point.side_effect = Exception("no such point")
        obj = make_tase2(conn=conn, read_point="ICC1/P1")

        obj._execute_action()

        self.assertIn("no such point", obj.results["data"]["action_result"]["error"])

    def test_write_point_float(self):
        conn = Mock()
        obj = make_tase2(conn=conn, write_point="ICC1/P1:3.14", confirm=True)

        obj._execute_action()

        conn.write_point.assert_called_once_with("ICC1", "P1", 3.14)

    def test_write_point_int_fallback(self):
        conn = Mock()
        obj = make_tase2(conn=conn, write_point="ICC1/P1:7", confirm=True)

        obj._execute_action()

        # "7" parses as float 7.0 first (float() accepts it).
        conn.write_point.assert_called_once_with("ICC1", "P1", 7.0)

    def test_write_point_non_numeric_fails(self):
        conn = Mock()
        obj = make_tase2(conn=conn, write_point="ICC1/P1:abc", confirm=True)

        obj._execute_action()

        obj.logger.fail.assert_called_once()
        conn.write_point.assert_not_called()

    def test_write_point_bad_path_fails(self):
        conn = Mock()
        obj = make_tase2(conn=conn, write_point="ICC1P1:1.0", confirm=True)

        obj._execute_action()

        obj.logger.fail.assert_called_once()
        conn.write_point.assert_not_called()

    def test_write_point_handles_error(self):
        conn = Mock()
        conn.write_point.side_effect = Exception("denied")
        obj = make_tase2(conn=conn, write_point="ICC1/P1:1.0", confirm=True)

        obj._execute_action()

        self.assertIn("denied", obj.results["data"]["action_result"]["error"])


# ---------------------------------------------------------------------------
# Control actions (send-command / select / operate)
# ---------------------------------------------------------------------------
class TestControlActions(unittest.TestCase):
    def test_send_command(self):
        conn = Mock()
        obj = make_tase2(conn=conn, send_command="ICC1/DEV1:1", confirm=True)

        obj._execute_action()

        conn.send_command.assert_called_once_with("ICC1", "DEV1", 1)
        self.assertEqual(obj.results["data"]["action_result"], {"success": True})

    def test_send_command_non_integer(self):
        conn = Mock()
        obj = make_tase2(conn=conn, send_command="ICC1/DEV1:open", confirm=True)

        obj._execute_action()

        obj.logger.fail.assert_called_once()
        conn.send_command.assert_not_called()

    def test_select_device(self):
        conn = Mock()
        obj = make_tase2(conn=conn, select_device="ICC1/DEV1", confirm=True)

        obj._execute_action()

        conn.select_device.assert_called_once_with("ICC1", "DEV1")

    def test_select_device_bad_format(self):
        conn = Mock()
        obj = make_tase2(conn=conn, select_device="DEV1", confirm=True)

        obj._execute_action()

        obj.logger.fail.assert_called_once()
        conn.select_device.assert_not_called()

    def test_operate_device(self):
        conn = Mock()
        obj = make_tase2(conn=conn, operate_device="ICC1/DEV1:5", confirm=True)

        obj._execute_action()

        conn.operate_device.assert_called_once_with("ICC1", "DEV1", 5)

    def test_operate_device_handles_error(self):
        conn = Mock()
        conn.operate_device.side_effect = Exception("blocked")
        obj = make_tase2(conn=conn, operate_device="ICC1/DEV1:5", confirm=True)

        obj._execute_action()

        self.assertIn("blocked", obj.results["data"]["action_result"]["error"])


# ---------------------------------------------------------------------------
# Transfer set RBE enable/disable
# ---------------------------------------------------------------------------
class TestRbeActions(unittest.TestCase):
    def test_enable_rbe(self):
        conn = Mock()
        obj = make_tase2(conn=conn, enable_rbe="ICC1/TS1", confirm=True)

        obj._execute_action()

        conn.enable_transfer_set.assert_called_once_with("ICC1", "TS1")

    def test_disable_rbe(self):
        conn = Mock()
        obj = make_tase2(conn=conn, disable_rbe="ICC1/TS1", confirm=True)

        obj._execute_action()

        conn.disable_transfer_set.assert_called_once_with("ICC1", "TS1")

    def test_enable_rbe_bad_format(self):
        conn = Mock()
        obj = make_tase2(conn=conn, enable_rbe="TS1", confirm=True)

        obj._execute_action()

        obj.logger.fail.assert_called_once()
        conn.enable_transfer_set.assert_not_called()


# ---------------------------------------------------------------------------
# Info actions (get-blt / server-info / features / version)
# ---------------------------------------------------------------------------
class TestInfoActions(unittest.TestCase):
    def test_get_blt(self):
        conn = Mock()
        conn.get_bilateral_table_id.return_value = "BLT-9"
        conn.get_server_bilateral_table_count.return_value = 2
        obj = make_tase2(conn=conn, get_blt=True)

        obj._execute_action()

        res = obj.results["data"]["action_result"]
        self.assertEqual(res["table_id"], "BLT-9")
        self.assertEqual(res["count"], 2)

    def test_get_server_info(self):
        conn = Mock()
        info = Mock()
        info.vendor = "ACME"
        info.model = "RTU-9000"
        info.revision = "1.2"
        info.bilateral_table_id = "BLT-3"
        info.bilateral_table_count = 1
        info.conformance_blocks = ["Block1", "Block2"]
        conn.get_server_info.return_value = info
        conn.get_domains.return_value = [make_domain("VCC", is_vcc=True)]
        obj = make_tase2(conn=conn, get_server_info=True)

        obj._execute_action()

        si = obj.results["data"]["action_result"]["server_info"]
        self.assertEqual(si["vendor"], "ACME")
        self.assertEqual(si["model"], "RTU-9000")
        self.assertEqual(si["domain_count"], 1)

    def test_get_features(self):
        scanner = Mock()
        scanner.get_supported_features.return_value = {"block1": True, "block4": False}
        obj = make_tase2(scanner=scanner, get_features=True)

        obj._execute_action()

        self.assertEqual(
            obj.results["data"]["action_result"]["supported_features"],
            {"block1": True, "block4": False},
        )

    def test_get_version_known(self):
        scanner = Mock()
        scanner.get_tase2_version.return_value = {"major": 1, "minor": 2}
        obj = make_tase2(scanner=scanner, get_version=True)

        obj._execute_action()

        self.assertEqual(
            obj.results["data"]["action_result"]["tase2_version"], {"major": 1, "minor": 2}
        )
        displayed = " ".join(str(c.args[0]) for c in obj.logger.display.call_args_list)
        self.assertIn("1.02", displayed)

    def test_get_version_unknown(self):
        scanner = Mock()
        scanner.get_tase2_version.return_value = {"major": 0, "minor": 0}
        obj = make_tase2(scanner=scanner, get_version=True)

        obj._execute_action()

        displayed = " ".join(str(c.args[0]) for c in obj.logger.display.call_args_list)
        self.assertIn("Unknown", displayed)


# ---------------------------------------------------------------------------
# Block 1: data type / read-points / data sets
# ---------------------------------------------------------------------------
class TestBlock1Actions(unittest.TestCase):
    def test_get_data_type(self):
        scanner = Mock()
        scanner.get_data_value_type.return_value = {"type_name": "Real"}
        obj = make_tase2(scanner=scanner, get_data_type="ICC1/P1")

        obj._execute_action()

        scanner.get_data_value_type.assert_called_once_with(obj.conn, "ICC1", "P1")
        self.assertEqual(obj.results["data"]["action_result"]["type_info"], {"type_name": "Real"})

    def test_get_data_type_bad_format(self):
        scanner = Mock()
        obj = make_tase2(scanner=scanner, get_data_type="P1")

        obj._execute_action()

        obj.logger.fail.assert_called_once()
        scanner.get_data_value_type.assert_not_called()

    def test_read_points(self):
        scanner = Mock()
        scanner.get_data_values.return_value = [
            {"name": "P1", "value": 1, "quality": "GOOD"},
            {"name": "P2", "error": "bad"},
        ]
        obj = make_tase2(scanner=scanner, read_points="ICC1/P1,P2")

        obj._execute_action()

        scanner.get_data_values.assert_called_once_with(obj.conn, "ICC1", ["P1", "P2"])
        self.assertEqual(len(obj.results["data"]["action_result"]["values"]), 2)

    def test_get_ds_members(self):
        scanner = Mock()
        scanner.get_data_set_members.return_value = [
            {"domain": "ICC1", "name": "P1"},
            {"domain": "ICC1", "name": "P2"},
        ]
        obj = make_tase2(scanner=scanner, get_ds_members="ICC1/DS1")

        obj._execute_action()

        scanner.get_data_set_members.assert_called_once_with(obj.conn, "ICC1", "DS1")
        self.assertEqual(len(obj.results["data"]["action_result"]["members"]), 2)

    def test_read_data_set(self):
        scanner = Mock()
        scanner.read_data_set_values.return_value = [
            {"name": "P1", "value": 10, "quality": "GOOD"},
        ]
        obj = make_tase2(scanner=scanner, read_data_set="ICC1/DS1")

        obj._execute_action()

        scanner.read_data_set_values.assert_called_once_with(obj.conn, "ICC1", "DS1")

    def test_create_data_set(self):
        scanner = Mock()
        scanner.create_data_set.return_value = True
        obj = make_tase2(scanner=scanner, create_data_set="ICC1/DS1:P1,P2", confirm=True)

        obj._execute_action()

        scanner.create_data_set.assert_called_once()
        call = scanner.create_data_set.call_args[0]
        self.assertEqual(call[1], "ICC1")
        self.assertEqual(call[2], "DS1")
        self.assertEqual(
            call[3], [{"domain": "ICC1", "name": "P1"}, {"domain": "ICC1", "name": "P2"}]
        )
        self.assertTrue(obj.results["data"]["action_result"]["success"])

    def test_create_data_set_requires_confirm(self):
        scanner = Mock()
        obj = make_tase2(scanner=scanner, create_data_set="ICC1/DS1:P1", confirm=False)

        obj._execute_action()

        scanner.create_data_set.assert_not_called()
        obj.logger.fail.assert_called_once()

    def test_create_data_set_bad_format(self):
        scanner = Mock()
        obj = make_tase2(scanner=scanner, create_data_set="ICC1DS1:P1", confirm=True)

        obj._execute_action()

        obj.logger.fail.assert_called_once()
        scanner.create_data_set.assert_not_called()

    def test_delete_data_set(self):
        scanner = Mock()
        scanner.delete_data_set.return_value = True
        obj = make_tase2(scanner=scanner, delete_data_set="ICC1/DS1", confirm=True)

        obj._execute_action()

        scanner.delete_data_set.assert_called_once_with(obj.conn, "ICC1", "DS1")


# ---------------------------------------------------------------------------
# Block 5: device tags
# ---------------------------------------------------------------------------
class TestTagActions(unittest.TestCase):
    def test_get_tag(self):
        scanner = Mock()
        scanner.get_tag.return_value = {"tag_value": "NORMAL", "reason": ""}
        obj = make_tase2(scanner=scanner, get_tag="ICC1/DEV1")

        obj._execute_action()

        scanner.get_tag.assert_called_once_with(obj.conn, "ICC1", "DEV1")

    def test_set_tag_with_reason(self):
        scanner = Mock()
        scanner.set_tag.return_value = True
        obj = make_tase2(scanner=scanner, set_tag="ICC1/DEV1:BLOCKED:maint", confirm=True)

        obj._execute_action()

        scanner.set_tag.assert_called_once_with(obj.conn, "ICC1", "DEV1", "BLOCKED", "maint")
        self.assertTrue(obj.results["data"]["action_result"]["success"])

    def test_set_tag_without_reason(self):
        scanner = Mock()
        scanner.set_tag.return_value = True
        obj = make_tase2(scanner=scanner, set_tag="ICC1/DEV1:BLOCKED", confirm=True)

        obj._execute_action()

        scanner.set_tag.assert_called_once_with(obj.conn, "ICC1", "DEV1", "BLOCKED", "")

    def test_set_tag_requires_confirm(self):
        scanner = Mock()
        obj = make_tase2(scanner=scanner, set_tag="ICC1/DEV1:BLOCKED", confirm=False)

        obj._execute_action()

        scanner.set_tag.assert_not_called()
        obj.logger.fail.assert_called_once()

    def test_set_tag_bad_format(self):
        scanner = Mock()
        obj = make_tase2(scanner=scanner, set_tag="ICC1/DEV1", confirm=True)

        obj._execute_action()

        obj.logger.fail.assert_called_once()
        scanner.set_tag.assert_not_called()


# ---------------------------------------------------------------------------
# Block 4: Information Messages
# ---------------------------------------------------------------------------
class TestInformationMessages(unittest.TestCase):
    def test_list_im_stores_specific_domain(self):
        scanner = Mock()
        scanner.get_information_message_stores.return_value = [
            {
                "domain": "ICC1",
                "name": "STORE1",
                "current_count": 2,
                "max_messages": 10,
                "storage_status": "AVAILABLE",
            }
        ]
        obj = make_tase2(scanner=scanner, list_im_stores="ICC1")

        obj._execute_action()

        scanner.get_information_message_stores.assert_called_once_with(obj.conn, "ICC1")
        self.assertEqual(len(obj.results["data"]["action_result"]["im_stores"]), 1)

    def test_list_im_stores_all_domains(self):
        scanner = Mock()
        scanner.get_information_message_stores.return_value = [{"domain": "ICC1", "name": "S1"}]
        obj = make_tase2(scanner=scanner, list_im_stores=True)
        # All-domains path reads previously enumerated domains from results.
        obj.results["data"]["domains"] = [{"name": "ICC1"}]

        obj._execute_action()

        scanner.get_information_message_stores.assert_called_once_with(obj.conn, "ICC1")

    def test_list_messages(self):
        scanner = Mock()
        scanner.get_information_messages.return_value = [
            {"message_id": "M1", "size": 100, "time_created": "2026-01-01"}
        ]
        obj = make_tase2(scanner=scanner, list_messages="ICC1/STORE1")

        obj._execute_action()

        scanner.get_information_messages.assert_called_once_with(obj.conn, "ICC1", "STORE1")
        self.assertEqual(len(obj.results["data"]["action_result"]["messages"]), 1)

    def test_list_messages_bad_format(self):
        scanner = Mock()
        obj = make_tase2(scanner=scanner, list_messages="STORE1")

        obj._execute_action()

        obj.logger.fail.assert_called_once()
        scanner.get_information_messages.assert_not_called()

    def test_read_message(self):
        scanner = Mock()
        scanner.read_information_message.return_value = {
            "content": "hello world",
            "time_created": "2026-01-01",
        }
        obj = make_tase2(scanner=scanner, read_message="ICC1/STORE1/M1")

        obj._execute_action()

        scanner.read_information_message.assert_called_once_with(obj.conn, "ICC1", "STORE1", "M1")

    def test_read_message_error(self):
        scanner = Mock()
        scanner.read_information_message.return_value = {"error": "not found"}
        obj = make_tase2(scanner=scanner, read_message="ICC1/STORE1/M1")

        obj._execute_action()

        obj.logger.fail.assert_called_once()

    def test_write_message_requires_confirm(self):
        scanner = Mock()
        obj = make_tase2(scanner=scanner, write_message="ICC1/STORE1:hi", confirm=False)

        obj._execute_action()

        scanner.write_information_message.assert_not_called()
        obj.logger.fail.assert_called_once()

    def test_write_message(self):
        scanner = Mock()
        scanner.write_information_message.return_value = {"success": True, "message_id": "M5"}
        obj = make_tase2(scanner=scanner, write_message="ICC1/STORE1:hi there", confirm=True)

        obj._execute_action()

        scanner.write_information_message.assert_called_once_with(
            obj.conn, "ICC1", "STORE1", "hi there"
        )
        self.assertTrue(obj.results["data"]["action_result"]["success"])

    def test_write_message_failure(self):
        scanner = Mock()
        scanner.write_information_message.return_value = {"success": False, "error": "full"}
        obj = make_tase2(scanner=scanner, write_message="ICC1/STORE1:hi", confirm=True)

        obj._execute_action()

        obj.logger.fail.assert_called_once()

    def test_delete_message(self):
        scanner = Mock()
        scanner.delete_information_message.return_value = {"success": True}
        obj = make_tase2(scanner=scanner, delete_message="ICC1/STORE1/M1", confirm=True)

        obj._execute_action()

        scanner.delete_information_message.assert_called_once_with(obj.conn, "ICC1", "STORE1", "M1")

    def test_delete_message_bad_format(self):
        scanner = Mock()
        obj = make_tase2(scanner=scanner, delete_message="ICC1/STORE1", confirm=True)

        obj._execute_action()

        obj.logger.fail.assert_called_once()
        scanner.delete_information_message.assert_not_called()

    def test_test_im_with_stores(self):
        scanner = Mock()
        scanner.get_information_message_stores.return_value = [{"domain": "ICC1", "name": "STORE1"}]
        scanner.get_information_messages.return_value = [{"message_id": "M1"}]
        obj = make_tase2(scanner=scanner, test_im=True)
        obj.results["data"]["domains"] = [{"name": "ICC1"}]

        obj._execute_action()

        res = obj.results["data"]["action_result"]
        self.assertTrue(res["block4_accessible"])
        self.assertEqual(len(res["im_stores"]), 1)

    def test_test_im_no_stores(self):
        scanner = Mock()
        scanner.get_information_message_stores.return_value = []
        obj = make_tase2(scanner=scanner, test_im=True)
        obj.results["data"]["domains"] = [{"name": "ICC1"}]

        obj._execute_action()

        res = obj.results["data"]["action_result"]
        self.assertFalse(res["block4_accessible"])


# ---------------------------------------------------------------------------
# Bad-format / error-path coverage for remaining elif branches
# ---------------------------------------------------------------------------
class TestBadFormatAndErrors(unittest.TestCase):
    def test_send_command_bad_path(self):
        conn = Mock()
        obj = make_tase2(conn=conn, send_command="ICC1DEV1:1", confirm=True)
        obj._execute_action()
        obj.logger.fail.assert_called_once()
        conn.send_command.assert_not_called()

    def test_send_command_no_colon(self):
        conn = Mock()
        obj = make_tase2(conn=conn, send_command="ICC1/DEV1", confirm=True)
        obj._execute_action()
        obj.logger.fail.assert_called_once()
        conn.send_command.assert_not_called()

    def test_send_command_handles_error(self):
        conn = Mock()
        conn.send_command.side_effect = Exception("rejected")
        obj = make_tase2(conn=conn, send_command="ICC1/DEV1:1", confirm=True)
        obj._execute_action()
        self.assertIn("rejected", obj.results["data"]["action_result"]["error"])

    def test_select_device_handles_error(self):
        conn = Mock()
        conn.select_device.side_effect = Exception("busy")
        obj = make_tase2(conn=conn, select_device="ICC1/DEV1", confirm=True)
        obj._execute_action()
        self.assertIn("busy", obj.results["data"]["action_result"]["error"])

    def test_operate_device_bad_format(self):
        conn = Mock()
        obj = make_tase2(conn=conn, operate_device="ICC1/DEV1", confirm=True)
        obj._execute_action()
        obj.logger.fail.assert_called_once()
        conn.operate_device.assert_not_called()

    def test_operate_device_bad_path(self):
        conn = Mock()
        obj = make_tase2(conn=conn, operate_device="ICC1DEV1:5", confirm=True)
        obj._execute_action()
        obj.logger.fail.assert_called_once()
        conn.operate_device.assert_not_called()

    def test_enable_rbe_handles_error(self):
        conn = Mock()
        conn.enable_transfer_set.side_effect = Exception("no ts")
        obj = make_tase2(conn=conn, enable_rbe="ICC1/TS1", confirm=True)
        obj._execute_action()
        self.assertIn("no ts", obj.results["data"]["action_result"]["error"])

    def test_disable_rbe_bad_format(self):
        conn = Mock()
        obj = make_tase2(conn=conn, disable_rbe="TS1", confirm=True)
        obj._execute_action()
        obj.logger.fail.assert_called_once()
        conn.disable_transfer_set.assert_not_called()

    def test_disable_rbe_handles_error(self):
        conn = Mock()
        conn.disable_transfer_set.side_effect = Exception("denied")
        obj = make_tase2(conn=conn, disable_rbe="ICC1/TS1", confirm=True)
        obj._execute_action()
        self.assertIn("denied", obj.results["data"]["action_result"]["error"])

    def test_read_points_bad_format(self):
        scanner = Mock()
        obj = make_tase2(scanner=scanner, read_points="ICC1")
        obj._execute_action()
        obj.logger.fail.assert_called_once()
        scanner.get_data_values.assert_not_called()

    def test_get_ds_members_bad_format(self):
        scanner = Mock()
        obj = make_tase2(scanner=scanner, get_ds_members="DS1")
        obj._execute_action()
        obj.logger.fail.assert_called_once()
        scanner.get_data_set_members.assert_not_called()

    def test_read_data_set_bad_format(self):
        scanner = Mock()
        obj = make_tase2(scanner=scanner, read_data_set="DS1")
        obj._execute_action()
        obj.logger.fail.assert_called_once()
        scanner.read_data_set_values.assert_not_called()

    def test_create_data_set_bad_path(self):
        scanner = Mock()
        # Has the colon but the path before it lacks a slash.
        obj = make_tase2(scanner=scanner, create_data_set="ICC1DS1:P1,P2", confirm=True)
        obj._execute_action()
        obj.logger.fail.assert_called_once()
        scanner.create_data_set.assert_not_called()

    def test_create_data_set_failure_logged(self):
        scanner = Mock()
        scanner.create_data_set.return_value = False
        obj = make_tase2(scanner=scanner, create_data_set="ICC1/DS1:P1", confirm=True)
        obj._execute_action()
        obj.logger.fail.assert_called_once()
        self.assertFalse(obj.results["data"]["action_result"]["success"])

    def test_delete_data_set_bad_format(self):
        scanner = Mock()
        obj = make_tase2(scanner=scanner, delete_data_set="DS1", confirm=True)
        obj._execute_action()
        obj.logger.fail.assert_called_once()
        scanner.delete_data_set.assert_not_called()

    def test_delete_data_set_failure_logged(self):
        scanner = Mock()
        scanner.delete_data_set.return_value = False
        obj = make_tase2(scanner=scanner, delete_data_set="ICC1/DS1", confirm=True)
        obj._execute_action()
        obj.logger.fail.assert_called_once()

    def test_get_tag_bad_format(self):
        scanner = Mock()
        obj = make_tase2(scanner=scanner, get_tag="DEV1")
        obj._execute_action()
        obj.logger.fail.assert_called_once()
        scanner.get_tag.assert_not_called()

    def test_set_tag_bad_path(self):
        scanner = Mock()
        obj = make_tase2(scanner=scanner, set_tag="ICC1DEV1:BLOCKED", confirm=True)
        obj._execute_action()
        obj.logger.fail.assert_called_once()
        scanner.set_tag.assert_not_called()

    def test_set_tag_failure_logged(self):
        scanner = Mock()
        scanner.set_tag.return_value = False
        obj = make_tase2(scanner=scanner, set_tag="ICC1/DEV1:BLOCKED", confirm=True)
        obj._execute_action()
        obj.logger.fail.assert_called_once()

    def test_list_im_stores_none_found(self):
        scanner = Mock()
        scanner.get_information_message_stores.return_value = []
        obj = make_tase2(scanner=scanner, list_im_stores="ICC1")
        obj._execute_action()
        self.assertEqual(obj.results["data"]["action_result"]["im_stores"], [])

    def test_list_messages_none(self):
        scanner = Mock()
        scanner.get_information_messages.return_value = []
        obj = make_tase2(scanner=scanner, list_messages="ICC1/STORE1")
        obj._execute_action()
        self.assertEqual(obj.results["data"]["action_result"]["messages"], [])

    def test_read_message_empty(self):
        scanner = Mock()
        scanner.read_information_message.return_value = {}
        obj = make_tase2(scanner=scanner, read_message="ICC1/STORE1/M1")
        obj._execute_action()
        # Neither content nor error -> "empty or not found" display path.
        displayed = " ".join(str(c.args[0]) for c in obj.logger.display.call_args_list)
        self.assertIn("empty or not found", displayed)

    def test_read_message_bad_format(self):
        scanner = Mock()
        obj = make_tase2(scanner=scanner, read_message="ICC1/STORE1")
        obj._execute_action()
        obj.logger.fail.assert_called_once()
        scanner.read_information_message.assert_not_called()

    def test_write_message_bad_path(self):
        scanner = Mock()
        obj = make_tase2(scanner=scanner, write_message="ICC1STORE1:hi", confirm=True)
        obj._execute_action()
        obj.logger.fail.assert_called_once()
        scanner.write_information_message.assert_not_called()

    def test_write_message_no_colon(self):
        scanner = Mock()
        obj = make_tase2(scanner=scanner, write_message="ICC1/STORE1", confirm=True)
        obj._execute_action()
        obj.logger.fail.assert_called_once()
        scanner.write_information_message.assert_not_called()

    def test_delete_message_failure_logged(self):
        scanner = Mock()
        scanner.delete_information_message.return_value = {"success": False, "error": "x"}
        obj = make_tase2(scanner=scanner, delete_message="ICC1/STORE1/M1", confirm=True)
        obj._execute_action()
        obj.logger.fail.assert_called_once()


# ---------------------------------------------------------------------------
# proto_flow integration (mock scanner boundary, real flow)
# ---------------------------------------------------------------------------
class TestProtoFlow(unittest.TestCase):
    def _patch_scanner(self, scanner):
        import oida.protocols.tase2.nxc_connection as mod

        self._mod = mod
        self._orig = mod.TASE2Scanner
        mod.TASE2Scanner = lambda args_dict: scanner

    def _unpatch(self):
        self._mod.TASE2Scanner = self._orig

    def _build(self, **arg_overrides):
        obj = make_tase2(**arg_overrides)
        obj._convert_args_to_dict = lambda: {"rhost": obj.ip}
        return obj

    def test_flow_connection_failure(self):
        obj = self._build()
        scanner = Mock()
        scanner.connect.return_value = None
        self._patch_scanner(scanner)
        try:
            obj.proto_flow()
        finally:
            self._unpatch()

        self.assertFalse(obj.results["success"])
        self.assertEqual(obj.results["error"], "Connection failed")

    def test_flow_runs_scan_when_no_action(self):
        obj = self._build()
        scanner = Mock()
        conn = Mock()
        conn.get_bilateral_table_id.return_value = "BLT"
        conn.get_server_bilateral_table_count.return_value = 1
        conn.get_domains.return_value = [make_domain("VCC", is_vcc=True)]
        scanner.connect.return_value = conn
        scanner.use_tls = False
        scanner.discover.return_value = {"domains": ["VCC"]}
        self._patch_scanner(scanner)
        try:
            obj.proto_flow()
        finally:
            self._unpatch()

        scanner.discover.assert_called_once()
        self.assertIn("scan_results", obj.results["data"])
        # Cleartext finding emitted on the connect path.
        obj.logger.security_finding.assert_called_once()

    def test_flow_dispatches_action(self):
        obj = self._build(list_domains=True)
        scanner = Mock()
        conn = Mock()
        conn.get_bilateral_table_id.return_value = "BLT"
        conn.get_server_bilateral_table_count.return_value = 1
        conn.get_domains.return_value = [make_domain("VCC", is_vcc=True)]
        scanner.connect.return_value = conn
        scanner.use_tls = False
        self._patch_scanner(scanner)
        try:
            obj.proto_flow()
        finally:
            self._unpatch()

        scanner.discover.assert_not_called()
        self.assertIn("action_result", obj.results["data"])


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
class TestCleanup(unittest.TestCase):
    def test_cleanup_disconnects(self):
        scanner = Mock()
        conn = Mock()
        obj = make_tase2(scanner=scanner, conn=conn)

        obj.cleanup()

        scanner.disconnect.assert_called_once_with(conn)

    def test_cleanup_swallows_errors(self):
        scanner = Mock()
        scanner.disconnect.side_effect = Exception("boom")
        obj = make_tase2(scanner=scanner, conn=Mock())

        obj.cleanup()  # must not raise
        obj.logger.debug.assert_called()

    def test_cleanup_noop_without_conn(self):
        scanner = Mock()
        obj = make_tase2(scanner=scanner, conn=None)
        obj.cleanup()
        scanner.disconnect.assert_not_called()


if __name__ == "__main__":
    unittest.main()

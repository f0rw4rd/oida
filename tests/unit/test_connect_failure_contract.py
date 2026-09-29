"""Connect-failure contract tests (GH issue #59).

One condition (nothing listening on target:port) must produce the same
console line and the same JSON ``error`` vocabulary across protocols:

- ``classify_connection_failure()`` maps OSError errno / library message
  strings to refused / timeout / unreachable / tls / auth / unknown.
- ``connection.record_connect_failure()`` stamps success=False and an
  ``error`` starting with ``connect <cause>`` on every call.
"""

from __future__ import annotations

import errno
import socket
import unittest
from unittest.mock import Mock, patch

from oida.utils.protocol_helpers import classify_connection_failure


class TestClassifyConnectionFailure(unittest.TestCase):
    def test_errno_refused(self):
        e = ConnectionRefusedError("Connect call failed")
        e.errno = errno.ECONNREFUSED
        self.assertEqual(classify_connection_failure(e), "refused")

    def test_errno_timeout(self):
        e = OSError("timed out")
        e.errno = errno.ETIMEDOUT
        self.assertEqual(classify_connection_failure(e), "timeout")

    def test_errno_unreachable(self):
        e = OSError("no route to host")
        e.errno = errno.EHOSTUNREACH
        self.assertEqual(classify_connection_failure(e), "unreachable")

    def test_errno_net_unreachable(self):
        e = OSError("net is down")
        e.errno = errno.ENETUNREACH
        self.assertEqual(classify_connection_failure(e), "unreachable")

    def test_message_refused(self):
        self.assertEqual(
            classify_connection_failure(message="[Errno 111] Connection refused"), "refused"
        )

    def test_message_timeout(self):
        self.assertEqual(
            classify_connection_failure(message="Failed to connect within 2s (timeout)"),
            "timeout",
        )

    def test_message_unreachable(self):
        self.assertEqual(classify_connection_failure(message="host unreachable"), "unreachable")

    def test_message_tls(self):
        self.assertEqual(
            classify_connection_failure(message="SSL handshake certificate verify failed"),
            "tls",
        )

    def test_message_auth(self):
        # "rejected" must match only pyiec61850's connection-rejected
        # phrase, not the bare word - this message is an auth rejection.
        self.assertEqual(
            classify_connection_failure(message="server rejected: access denied"), "auth"
        )

    def test_rejected_message_elapsed_nearly_budget_is_timeout(self):
        """pyiec61850 collapses refused and blackhole-timeout into the same
        "connection-rejected" message; elapsed-vs-budget is the only
        discriminator (a real reject lands in milliseconds, a blackhole
        consumes the whole budget)."""
        self.assertEqual(
            classify_connection_failure(
                message="Failed to connect to 10.255.255.1:102: connection-rejected",
                elapsed=9.8,
                timeout_budget=10.0,
            ),
            "timeout",
        )

    def test_rejected_message_elapsed_under_budget_is_refused(self):
        self.assertEqual(
            classify_connection_failure(
                message="Failed to connect to 127.0.0.1:102: connection-rejected",
                elapsed=0.4,
                timeout_budget=10.0,
            ),
            "refused",
        )

    def test_rejected_message_without_elapsed_stays_refused(self):
        """No timing info: keep the message's word (a library that reports
        connection-rejected has usually hit an active refusal)."""
        self.assertEqual(
            classify_connection_failure(
                message="Failed to connect to 127.00.0.1:102: connection-rejected"
            ),
            "refused",
        )

    def test_unknown_for_bare_text(self):
        self.assertEqual(classify_connection_failure(message="some other error"), "unknown")

    def test_none_exception_and_message_is_unknown(self):
        self.assertEqual(classify_connection_failure(), "unknown")

    def test_real_connection_refused_errno(self):
        """Ground truth: a refused connect on loopback carries ECONNREFUSED."""
        try:
            with socket.create_connection(("127.0.0.1", 59999), timeout=1):
                self.skipTest("something is listening on 59999; cannot test refusal")
        except OSError as e:
            self.assertEqual(classify_connection_failure(e), "refused")


class TestRecordConnectFailure(unittest.TestCase):
    def _conn(self):
        """Bare concrete connection with just the attributes the method uses."""
        from oida.connection import connection

        class _Concrete(connection):
            proto_flow = None
            create_conn_obj = None
            enum_host_info = None

        obj = _Concrete.__new__(_Concrete)
        obj.logger = Mock()
        obj.results = {"success": None, "data": {}, "port": 502}
        obj.host = "127.0.0.1"
        return obj

    def test_stamps_success_and_error(self):
        obj = self._conn()
        obj.record_connect_failure("refused")
        self.assertFalse(obj.results["success"])
        self.assertEqual(obj.results["error"], "connect refused")
        obj.logger.fail.assert_called_once_with("Connect failed: refused (127.0.0.1:502)")

    def test_exc_message_folded_in(self):
        obj = self._conn()
        exc = ConnectionRefusedError("[Errno 111] Connect call failed")
        obj.record_connect_failure("refused", exc=exc)
        self.assertIn("Connect call failed", obj.results["error"])
        self.assertTrue(obj.results["error"].startswith("connect refused"))

    def test_detail_appended(self):
        obj = self._conn()
        obj.record_connect_failure("timeout", detail="TLS")
        self.assertEqual(obj.results["error"], "connect timeout (TLS)")

    def test_exc_matching_cause_not_duplicated(self):
        """exc=str 'refused' equals the cause; error stays 'connect refused'."""
        obj = self._conn()
        obj.record_connect_failure("refused", exc=ValueError("refused"))
        self.assertEqual(obj.results["error"], "connect refused")


class TestProtocolConnectFailurePaths(unittest.TestCase):
    """The four protocols named in GH issue #59 must all route their
    connect failures through record_connect_failure(): one failure line,
    success=False, error starting with "connect <cause>".

    The socket probe is patched to "refused" so no test does real network
    I/O against synthetic hosts.
    """

    def _probe_patched(self):
        return patch(
            "oida.utils.protocol_helpers.probe_connect_failure_cause",
            return_value="refused",
        )

    def test_modbus_records_canonical_failure(self):
        """modbus: single failure line (no double print), error set."""
        from oida.protocols.modbus.cli_runner import modbus as ModbusClass

        obj = ModbusClass.__new__(ModbusClass)
        obj.protocol_name = "MODBUS"
        obj.default_port = 502
        obj.conn = None
        obj.args = Mock()
        obj.args.port = 502
        obj.args.timeout = 2
        obj.args.list_maps = False  # Mock attr would be truthy and divert the flow
        obj.args.serial_port = None  # ditto - would divert to the serial branch
        obj.args.udp = False  # ditto - would skip the TCP cause probe
        obj.host = obj.ip = "127.0.0.1"
        obj.logger = Mock()
        obj.results = {"data": {}, "success": None, "port": 502}
        obj.scanner = Mock()
        obj.scanner.connect.return_value = None

        with (
            patch.object(ModbusClass, "_handle_list_maps", return_value=None),
            patch.object(ModbusClass, "_convert_args_to_dict", return_value={}),
            self._probe_patched(),
        ):
            with patch("oida.protocols.modbus.scanner.ModbusScanner") as scanner_cls:
                scanner_cls.return_value = obj.scanner
                obj.proto_flow()

        self.assertFalse(obj.results["success"])
        self.assertTrue(
            obj.results["error"].startswith("connect refused"),
            f"error was {obj.results['error']!r}",
        )
        # Exactly one failure line - the old code printed twice.
        fail_calls = [c for c in obj.logger.fail.call_args_list]
        self.assertEqual(len(fail_calls), 1, f"fail calls: {obj.logger.fail.call_args_list}")

    def test_iec104_records_canonical_failure(self):
        from oida.protocols.iec104.cli_runner import iec104 as IEC104Class

        obj = IEC104Class.__new__(IEC104Class)
        obj.protocol_name = "IEC 104"
        obj.default_port = 2404
        obj.conn = None
        obj.args = Mock()
        obj.args.tls = False
        obj.args.port = 2404
        obj.args.timeout = 2
        obj.host = obj.ip = "127.0.0.1"
        obj.logger = Mock()
        obj.results = {"data": {}, "success": None, "port": 2404}
        obj.scanner = Mock()
        obj.scanner.connect.return_value = None
        obj.scanner.common_address = 1

        with (
            patch.object(IEC104Class, "_convert_args_to_dict", return_value={}),
            patch("oida.protocols.iec104.cli_runner.IEC104Scanner", return_value=obj.scanner),
            self._probe_patched(),
        ):
            obj.proto_flow()

        self.assertFalse(obj.results["success"])
        self.assertEqual(obj.results["error"], "connect refused (TCP)")
        self.assertEqual(obj.logger.fail.call_count, 1)

    def test_dnp3_records_canonical_failure(self):
        from oida.protocols.dnp3.cli_runner import dnp3 as DNP3Class
        from oida.utils.exceptions import ICSConnectionError

        obj = DNP3Class.__new__(DNP3Class)
        obj.protocol_name = "DNP3"
        obj.default_port = 20000
        obj.conn = None
        obj.args = Mock()
        obj.args.port = 20000
        obj.args.timeout = 2
        obj.args.transport = "tcp"
        obj.args.scan_range = None
        obj.host = obj.ip = "127.0.0.1"
        obj.logger = Mock()
        obj.results = {"data": {}, "success": None, "port": 20000}
        obj.scanner = Mock()
        obj.scanner.connect.side_effect = ICSConnectionError(
            "Failed to connect to 127.0.0.1:20000 within 2s", protocol="DNP3"
        )

        with (
            patch("oida.protocols.dnp3.proto_args.validate_args", return_value=None),
            patch.object(DNP3Class, "_build_scanner_args", return_value={}),
            patch("oida.protocols.dnp3.cli_runner.DNP3Scanner", return_value=obj.scanner),
            patch("oida.protocols.dnp3.cli_runner.time.sleep"),
            self._probe_patched(),
        ):
            obj.proto_flow()

        self.assertFalse(obj.results["success"])
        self.assertTrue(
            obj.results["error"].startswith("connect refused"),
            f"error was {obj.results['error']!r}",
        )
        self.assertEqual(obj.logger.fail.call_count, 1)

    def test_opcua_records_canonical_failure(self):
        """opcua: the no-credentials no-anonymous path must set error."""
        from oida.protocols.opcua.cli_runner import opcua as OpcUaClass

        obj = OpcUaClass.__new__(OpcUaClass)
        obj.protocol_name = "OPC UA"
        obj.default_port = 4840
        obj.args = Mock()
        obj.args.port = 4840
        obj.args.timeout = 2
        obj.args.username = None
        obj.args.password = None
        obj.args.certificate = None
        obj.args.privatekey = None
        obj.args.test_rbac = False
        obj.host = obj.ip = "127.0.0.1"
        obj.logger = Mock()
        obj.results = {"data": {}, "success": None, "port": 4840}
        obj._original_url = "opc.tcp://127.0.0.1:4840"
        obj._client = Mock()

        # _pre_auth_discovery path: simulate a refused connect (self + url)
        async def _pre_auth_fail(self_, url):
            obj._connect_failure_cause = "refused"
            obj._connect_failure_exc = ConnectionRefusedError("[Errno 111] Connect call failed")
            return False

        def _parse_creds(value):
            return ([], False) if value is not None else ([], False)

        with (
            patch.object(OpcUaClass, "_pre_auth_discovery", _pre_auth_fail),
            patch.object(OpcUaClass, "_suppress_asyncua_logging", return_value=None),
            patch.object(OpcUaClass, "_restore_asyncua_logging", return_value=None),
            patch("oida.utils.default_credentials.parse_credential_input", _parse_creds),
            patch("oida.protocols.opcua.cli_runner._get_client_class") as gcc,
        ):
            gcc.return_value = Mock()
            # proto_flow runs asyncio.run(_async_proto_flow()); call it
            # directly instead to avoid a real event loop in a unit test.
            import asyncio

            asyncio.run(obj._async_proto_flow())

        self.assertFalse(obj.results["success"])
        self.assertTrue(
            obj.results["error"].startswith("connect refused"),
            f"error was {obj.results['error']!r}",
        )


if __name__ == "__main__":
    unittest.main()

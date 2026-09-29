"""Uniform connect-failure output across protocol runners (GH issue #59 follow-up).

Three observable defects against dead targets like 1.1.1.1:

1. mms prints the failure three times (scanner.connect, create_conn_obj,
   proto_flow) and stamps a generic error, not the canonical
   ``connect <cause>`` string.
2. opcua's classify dead-ends at ``unknown`` when the library exception has
   no errno and an unmatched message; there is no TCP-probe fallback like
   modbus/iec104 have. It also never prints the ``[*] Connecting`` line the
   adopted protocols print.
3. The ``[*] Connecting`` line is hand-placed per protocol, so some protocols
   show it and others don't.

These tests pin the contract: exactly one failure line, ``connect <cause>``
in results["error"], and a Connecting line before the failure. All network
I/O is mocked; nothing here touches a real host.
"""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import Mock, patch


def _base_obj(cls, protocol_name, default_port):
    """Bare instance without running __init__ (heavy and does network-ish setup)."""
    obj = cls.__new__(cls)
    obj.protocol_name = protocol_name
    obj.default_port = default_port
    obj.conn = None
    obj.host = obj.ip = "127.0.0.1"
    obj.logger = Mock()
    obj.results = {"data": {}, "success": None, "port": default_port}
    obj.args = Mock()
    obj.args.port = default_port
    obj.args.timeout = 2
    return obj


class TestMmsSingleFailureLine(unittest.TestCase):
    def test_proto_flow_failure_single_line_and_canonical_error(self):
        from oida.protocols.mms.cli_runner import mms as MmsClass

        obj = _base_obj(MmsClass, "IEC 61850 MMS", 102)
        obj.scanner = Mock()
        obj.scanner.connect.return_value = None

        with (
            patch.object(MmsClass, "_convert_args_to_dict", return_value={}),
            patch("oida.protocols.mms.cli_runner.MMSScanner", return_value=obj.scanner),
            # The raw-socket probe is what recovers the cause; patch it so
            # nothing real is dialed.
            patch(
                "oida.utils.protocol_helpers.probe_connect_failure_cause", return_value="refused"
            ),
        ):
            obj.proto_flow()

        # Exactly ONE fail line: scanner, create_conn_obj and proto_flow each
        # used to print their own (three lines against a dead target).
        self.assertEqual(
            obj.logger.fail.call_count, 1, f"fail calls: {obj.logger.fail.call_args_list}"
        )
        self.assertFalse(obj.results["success"])
        self.assertTrue(
            obj.results["error"].startswith("connect refused"),
            f"error was {obj.results['error']!r}",
        )
        # The scanner-level duplicate must be gone too.
        obj.scanner.logger.fail.assert_not_called()

    def test_scanner_connect_does_not_log_failure(self):
        """MMSScanner.connect() must stop printing its own failure line."""
        from oida.protocols.mms import MMSScanner
        from oida.protocols.mms import _Lib

        _Lib.require()  # ConnectionFailedError is None until the lazy lib loads
        # pyiec61850's ConnectionFailedError requires (host, port, message).
        ConnErr = _Lib.ConnectionFailedError

        scanner = MMSScanner.__new__(MMSScanner)
        scanner.logger = Mock()
        scanner.host = "127.0.0.1"
        scanner.port = 102
        scanner.timeout = 2
        scanner.tls = False
        scanner.tls_port = 3782
        scanner.tls_ca = None
        scanner.tls_pin = None
        scanner.tls_client_cert = None
        scanner.tls_client_key = None

        ConnErr = _Lib.ConnectionFailedError
        with (
            patch.object(MMSScanner, "get_target_info", return_value=("127.0.0.1", 102)),
            patch.object(MMSScanner, "_build_tls_config", return_value=None),
            # Bind the lazy module's MMSClient so connect() raises the real
            # ConnectionFailedError it would see against a dead target.
            patch.object(_Lib.MMSClient, "connect", side_effect=ConnErr("127.0.0.1", 102, "nope")),
        ):
            conn = scanner.connect()

        self.assertIsNone(conn)
        scanner.logger.fail.assert_not_called()


class TestOpcuaCauseClassification(unittest.TestCase):
    def test_unknown_cause_falls_back_to_probe(self):
        """When classification yields 'unknown', the TCP probe must rescue it.

        asyncua's timeout against 1.1.1.1 raised a messageless exception with
        no errno, so the old path printed 'Connect failed: unknown'. modbus and
        iec104 already probe; opcua must too.
        """
        from oida.protocols.opcua.cli_runner import opcua as OpcUaClass

        obj = _base_obj(OpcUaClass, "OPC UA", 4840)
        obj.args.username = None
        obj.args.password = None
        obj.args.certificate = None
        obj.args.privatekey = None
        obj.args.test_rbac = False
        obj._original_url = "opc.tcp://127.0.0.1:4840"
        obj._client = Mock()

        async def _pre_auth_fail(self_, url):
            # Simulate the worst real-world case: a library exception that
            # carries no errno and no recognizable text - classification
            # dead-ends at 'unknown' and only the probe can rescue it.
            from oida.utils.protocol_helpers import classify_connection_failure

            exc = ValueError("something odd")  # unclassifiable by design
            obj._connect_failure_cause = classify_connection_failure(exc)
            obj._connect_failure_exc = exc
            return False

        def _parse_creds(value):
            return ([], False)

        with (
            patch.object(OpcUaClass, "_pre_auth_discovery", _pre_auth_fail),
            patch.object(OpcUaClass, "_suppress_asyncua_logging", return_value=None),
            patch.object(OpcUaClass, "_restore_asyncua_logging", return_value=None),
            patch("oida.utils.default_credentials.parse_credential_input", _parse_creds),
            patch("oida.protocols.opcua.cli_runner._get_client_class") as gcc,
            patch(
                "oida.utils.protocol_helpers.probe_connect_failure_cause",
                return_value="timeout",
            ) as probe,
        ):
            gcc.return_value = Mock()
            asyncio.run(obj._async_proto_flow())

        self.assertEqual(probe.call_count, 1)
        self.assertTrue(
            obj.results["error"].startswith("connect timeout"),
            f"error was {obj.results['error']!r}",
        )

    def test_connecting_line_before_failure(self):
        """opcua must print [*] Connecting like modbus/iec104/mms do."""
        from oida.protocols.opcua.cli_runner import opcua as OpcUaClass

        obj = _base_obj(OpcUaClass, "OPC UA", 7840)
        obj.args.username = None
        obj.args.password = None
        obj.args.certificate = None
        obj.args.privatekey = None
        obj.args.test_rbac = False
        obj._original_url = "opc.tcp://127.0.0.1:4840"
        obj._client = Mock()

        async def _pre_auth_fail(self_, url):
            from oida.utils.protocol_helpers import classify_connection_failure

            obj._connect_failure_cause = classify_connection_failure(TimeoutError())
            obj._connect_failure_exc = TimeoutError()
            return False

        def _parse_creds(value):
            return ([], False)

        with (
            patch.object(OpcUaClass, "_pre_auth_discovery", _pre_auth_fail),
            patch.object(OpcUaClass, "_suppress_asyncua_logging", return_value=None),
            patch.object(OpcUaClass, "_restore_asyncua_logging", return_value=None),
            patch("oida.utils.default_credentials.parse_credential_input", _parse_creds),
            patch("oida.protocols.opcua.cli_runner._get_client_class") as gcc,
            patch(
                "oida.utils.protocol_helpers.probe_connect_failure_cause",
                return_value="timeout",
            ),
        ):
            gcc.return_value = Mock()
            asyncio.run(obj._async_proto_flow())

        info_calls = [c for c in obj.logger.info.call_args_list if "Connecting" in str(c)]
        self.assertEqual(len(info_calls), 1, f"info calls: {obj.logger.info.call_args_list}")


class TestRecordConnectFailureUnknownFallback(unittest.TestCase):
    """record_connect_failure must recover a cause, not stop at unknown.

    A caller whose library raises a bare TimeoutError (asyncua against a
    dead target) must still get 'timeout', not 'unknown': TimeoutError IS the
    timeout signal even without errno or a message. 'Connect failed: unknown'
    tells the operator nothing.
    """

    def test_bare_timeouterror_classifies_as_timeout(self):
        from oida.utils.protocol_helpers import classify_connection_failure

        self.assertEqual(classify_connection_failure(TimeoutError()), "timeout")

    def test_bare_oserror_with_errno(self):
        import errno

        from oida.utils.protocol_helpers import classify_connection_failure

        exc = OSError()
        exc.errno = errno.ETIMEDOUT
        self.assertEqual(classify_connection_failure(exc), "timeout")

    def test_unknown_cause_with_no_exc_probes_target(self):
        """record_connect_failure rescues 'unknown' via the TCP probe.

        Where even classification fails (a library that swallows everything),
        the shared helper can still probe the target itself; one cheap raw
        socket connect is better than telling the operator 'unknown'.
        """
        from oida.connection import NetworkConnection

        # NetworkConnection is abstract; a minimal concrete subclass gets its
        # record_connect_failure() without any protocol baggage.
        class _Concrete(NetworkConnection):
            def proto_flow(self):
                pass

            def create_conn_obj(self):
                pass

            def enum_host_info(self):
                pass

        obj = _Concrete.__new__(_Concrete)
        obj.args = Mock()
        obj.ip = obj.host = "127.0.0.1"
        obj.protocol_name = "X"
        obj.default_port = 102
        obj.host = "127.0.0.1"
        obj.logger = Mock()
        obj.results = {"data": {}, "success": None, "port": 102}

        with patch(
            "oida.utils.protocol_helpers.probe_connect_failure_cause",
            return_value="refused",
        ) as probe:
            obj.record_connect_failure("unknown")

        self.assertEqual(probe.call_count, 1)
        self.assertTrue(obj.results["error"].startswith("connect refused"))
        # The console line carries the rescued cause, not 'unknown'.
        self.assertIn("refused", obj.logger.fail.call_args[0][0])

    def test_probed_true_skips_the_rescue_probe(self):
        """A caller that already ran probe_connect_failure_cause() passes
        probed=True so record_connect_failure() does not connect a second
        time (the probe-then-'or unknown' runner pattern used to fire the
        inner rescue against every alive-but-non-protocol port).
        """
        from oida.connection import NetworkConnection

        class _Concrete(NetworkConnection):
            def proto_flow(self):
                pass

            def create_conn_obj(self):
                pass

            def enum_host_info(self):
                pass

        obj = _Concrete.__new__(_Concrete)
        obj.args = Mock()
        obj.ip = obj.host = "127.0.0.1"
        obj.protocol_name = "X"
        obj.default_port = 102
        obj.logger = Mock()
        obj.results = {"data": {}, "success": None, "port": 102}

        with patch(
            "oida.utils.protocol_helpers.probe_connect_failure_cause",
            return_value="refused",
        ) as probe:
            obj.record_connect_failure("unknown", probed=True)

        self.assertEqual(probe.call_count, 0, "rescue probe must not fire")
        # 'unknown' stands (the caller's own probe found an alive port).
        self.assertTrue(obj.results["error"].startswith("connect unknown"))

    def test_probed_false_still_rescues(self):
        """The flag only opts out; the default path still probes."""
        from oida.connection import NetworkConnection

        class _Concrete(NetworkConnection):
            def proto_flow(self):
                pass

            def create_conn_obj(self):
                pass

            def enum_host_info(self):
                pass

        obj = _Concrete.__new__(_Concrete)
        obj.args = Mock()
        obj.ip = obj.host = "127.0.0.1"
        obj.protocol_name = "X"
        obj.default_port = 102
        obj.logger = Mock()
        obj.results = {"data": {}, "success": None, "port": 102}

        with patch(
            "oida.utils.protocol_helpers.probe_connect_failure_cause",
            return_value="refused",
        ) as probe:
            obj.record_connect_failure("unknown")

        self.assertEqual(probe.call_count, 1)


class TestGooseMmsPortStamping(unittest.TestCase):
    """goose default_port is 0 (passive GOOSE is portless layer-2), so MMS
    enumeration must stamp results["port"] with --mms-port before connecting.

    Without the stamp, record_connect_failure()'s probe rescue targets
    results["port"] = 0; connecting to port 0 returns ECONNREFUSED on Linux
    and an OPEN, alive-but-non-MMS port was misreported as 'refused'
    (verified live: 'goose --mms-enum 127.0.0.1 --mms-port <open port>'
    printed 'Connect failed: refused (127.0.0.1)').
    """

    def test_mms_enum_branch_stamps_mms_port(self):
        from types import SimpleNamespace

        from unittest.mock import patch

        from oida.protocols.goose.cli_runner import goose as GooseClass

        obj = GooseClass.__new__(GooseClass)
        obj.protocol_name = "IEC 61850 GOOSE"
        obj.args = SimpleNamespace(mms_enum="127.0.0.1", mms_port=49467, timeout=2)
        obj.host = obj.ip = "127.0.0.1"
        obj.logger = Mock()
        obj.results = {"data": {}, "success": None, "port": None}
        obj.interface = "eth0"

        # create_conn_obj on failure records with the stamped port: patch the
        # scanner so connect() returns None, and the probe so it would return
        # None (alive port) - the recorded cause must be 'unknown' against
        # 127.0.0.1:49467, never 'refused' against port 0.
        obj.scanner = Mock()
        obj.scanner.connect.return_value = None

        with patch(
            "oida.utils.protocol_helpers.probe_connect_failure_cause",
            return_value=None,
        ) as probe:
            obj.proto_flow()

        # The outer probe hit the real MMS port...
        probe.assert_called_once_with("127.0.0.1", 49467, timeout=2.0)
        # ...and the recorded failure is honest about the alive port.
        self.assertTrue(obj.results["error"].startswith("connect unknown"))
        self.assertIn(
            "(127.0.0.1:49467)",
            obj.logger.fail.call_args[0][0],
            f"line was {obj.logger.fail.call_args[0][0]!r}",
        )
        self.assertFalse(obj.results["success"])


if __name__ == "__main__":
    unittest.main()

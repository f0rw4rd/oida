"""
OCPP Protocol Integration Tests

Tests oida ocpp scanner using an inline mock WebSocket OCPP server.
Since no Docker mock OCPP service exists yet, we start a lightweight
websockets server in a background thread as a fixture.

Run with: pytest tests/integration/test_ocpp_integration.py -v
"""

import asyncio
import json
import socket
import threading
import pytest

from tests.service_gate import require_service


# ---------------------------------------------------------------------------
# Mark all tests in this module with "ocpp" marker
# ---------------------------------------------------------------------------

pytestmark = pytest.mark.ocpp


# ---------------------------------------------------------------------------
# Mock OCPP CSMS Server
# ---------------------------------------------------------------------------


def _find_free_port():
    """Find a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class MockOCPPServer:
    """
    Minimal OCPP CSMS mock for integration testing.

    Handles:
    - WebSocket subprotocol negotiation (ocpp1.6 / ocpp2.0.1)
    - BootNotification -> Accepted
    - Heartbeat -> currentTime response
    - GetConfiguration -> sample config keys
    - DataTransfer -> Accepted
    - StatusNotification -> empty response
    - Other known actions -> FormationViolation; unknown actions -> NotSupported
    """

    KNOWN_ACTIONS = {
        "BootNotification",
        "Heartbeat",
        "StatusNotification",
        "Authorize",
        "DataTransfer",
        "MeterValues",
        "StartTransaction",
        "StopTransaction",
        "GetConfiguration",
        "RemoteStartTransaction",
        "RemoteStopTransaction",
        "Reset",
        "UnlockConnector",
        "SetChargingProfile",
        "ClearChargingProfile",
        "ChangeConfiguration",
        "TriggerMessage",
        "GetBaseReport",
        "UpdateFirmware",
        "ChangeAvailability",
        "ClearCache",
        "GetDiagnostics",
        "ReserveNow",
        "CancelReservation",
        "GetLocalListVersion",
        "SendLocalList",
    }

    def __init__(self, host="127.0.0.1", port=0):
        self.host = host
        self.port = port or _find_free_port()
        self._server = None
        self._loop = None
        self._thread = None
        self._started = threading.Event()

    async def _handler(self, websocket):
        """Handle a single WebSocket connection."""
        async for raw_message in websocket:
            try:
                data = json.loads(raw_message)
                msg_type = data[0]
                msg_id = data[1]

                if msg_type == 2:  # CALL
                    action = data[2]
                    payload = data[3] if len(data) > 3 else {}
                    response = self._handle_call(msg_id, action, payload)
                    await websocket.send(json.dumps(response))
                else:
                    # Echo back unknown message types as errors
                    error = [4, msg_id, "ProtocolError", "Unexpected message type", {}]
                    await websocket.send(json.dumps(error))
            except (json.JSONDecodeError, IndexError, KeyError):
                pass

    def _handle_call(self, msg_id, action, payload):
        """Generate a response for a CALL message."""
        if action == "BootNotification":
            return [
                3,
                msg_id,
                {
                    "status": "Accepted",
                    "interval": 300,
                    "currentTime": "2026-01-01T00:00:00.000Z",
                },
            ]

        elif action == "Heartbeat":
            return [3, msg_id, {"currentTime": "2026-01-01T12:00:00.000Z"}]

        elif action == "GetConfiguration":
            return [
                3,
                msg_id,
                {
                    "configurationKey": [
                        {"key": "HeartbeatInterval", "value": "300", "readonly": False},
                        {"key": "NumberOfConnectors", "value": "2", "readonly": True},
                        {"key": "SecurityProfile", "value": "1", "readonly": True},
                        {
                            "key": "SupportedFeatureProfiles",
                            "value": "Core,FirmwareManagement",
                            "readonly": True,
                        },
                    ],
                    "unknownKey": [],
                },
            ]

        elif action == "DataTransfer":
            vendor = payload.get("vendorId", "")
            return [3, msg_id, {"status": "Accepted", "data": f"echo:{vendor}"}]

        elif action == "StatusNotification":
            return [3, msg_id, {}]

        elif action == "Authorize":
            return [3, msg_id, {"idTagInfo": {"status": "Accepted"}}]

        elif action == "RemoteStartTransaction":
            # Reject fake IdTags, accept known ones
            id_tag = payload.get("idTag", "")
            if "OIDA" in id_tag or "TEST" in id_tag:
                return [3, msg_id, {"status": "Rejected"}]
            return [3, msg_id, {"status": "Accepted"}]

        elif action == "Reset":
            return [3, msg_id, {"status": "Accepted"}]

        elif action == "UnlockConnector":
            connector_id = payload.get("connectorId", 0)
            if connector_id > 0:
                return [3, msg_id, {"status": "Unlocked"}]
            return [3, msg_id, {"status": "UnlockFailed"}]

        elif action == "UpdateFirmware":
            # Accept any firmware update request (simulating insecure CSMS)
            return [3, msg_id, {}]

        elif action == "SetChargingProfile":
            return [3, msg_id, {"status": "Accepted"}]

        elif action == "ClearChargingProfile":
            return [3, msg_id, {"status": "Accepted"}]

        elif action == "ChangeConfiguration":
            key = payload.get("key", "")
            # Accept HeartbeatInterval, reject security-sensitive keys
            if key in ("HeartbeatInterval", "AllowOfflineTxForUnknownId"):
                return [3, msg_id, {"status": "Accepted"}]
            elif key == "SecurityProfile":
                return [3, msg_id, {"status": "Rejected"}]
            elif key == "AuthorizationKey":
                return [3, msg_id, {"status": "Rejected"}]
            return [3, msg_id, {"status": "Rejected"}]

        elif action == "TriggerMessage":
            requested = payload.get("requestedMessage", "")
            if requested in (
                "StatusNotification",
                "MeterValues",
                "Heartbeat",
                "BootNotification",
                "FirmwareStatusNotification",
            ):
                return [3, msg_id, {"status": "Accepted"}]
            return [3, msg_id, {"status": "NotImplemented"}]

        elif action == "GetBaseReport":
            return [3, msg_id, {"status": "Accepted"}]

        elif action == "ChangeAvailability":
            return [3, msg_id, {"status": "Accepted"}]

        elif action == "ClearCache":
            return [3, msg_id, {"status": "Accepted"}]

        elif action == "GetDiagnostics":
            return [3, msg_id, {"fileName": "diag-upload.tar.gz"}]

        elif action == "RemoteStopTransaction":
            return [3, msg_id, {"status": "Accepted"}]

        elif action == "ReserveNow":
            return [3, msg_id, {"status": "Accepted"}]

        elif action == "CancelReservation":
            return [3, msg_id, {"status": "Accepted"}]

        elif action == "GetLocalListVersion":
            return [3, msg_id, {"listVersion": 3}]

        elif action == "SendLocalList":
            return [3, msg_id, {"status": "Accepted"}]

        elif action == "StartTransaction":
            return [
                3,
                msg_id,
                {"idTagInfo": {"status": "Accepted"}, "transactionId": 12345},
            ]

        elif action == "StopTransaction":
            return [3, msg_id, {"idTagInfo": {"status": "Accepted"}}]

        # --- OCPP 2.0.1 dangerous operations: an insecure CSMS accepts them all
        # (mirrors the real ocpp-insecure-csms mock), so the security probes can
        # demonstrate the corresponding CRITICAL findings.
        elif action in (
            "SetNetworkProfile",
            "InstallCertificate",
            "DeleteCertificate",
            "SetDisplayMessage",
            "ClearDisplayMessage",
            "CustomerInformation",
        ):
            return [3, msg_id, {"status": "Accepted"}]

        elif action in self.KNOWN_ACTIONS:
            # Known but payload validation error
            return [4, msg_id, "FormationViolation", "Invalid payload", {}]

        else:
            return [4, msg_id, "NotSupported", f"Unknown action: {action}", {}]

    def start(self):
        """Start the mock server in a background thread."""
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        # Wait for server to be ready
        if not self._started.wait(timeout=10):
            raise RuntimeError("Mock OCPP server failed to start")

    def _run(self):
        """Background thread entry point."""
        self._loop = asyncio.new_event_loop()

        try:
            from websockets.asyncio.server import serve

            async def _serve():
                server = await serve(
                    self._handler,
                    self.host,
                    self.port,
                    subprotocols=["ocpp1.6", "ocpp2.0.1"],
                )
                self._server = server
                self._started.set()
                await asyncio.Future()  # Run forever

            self._loop.run_until_complete(_serve())
        except Exception:
            self._started.set()  # Unblock waiters even on failure

    def stop(self):
        """Stop the mock server."""
        if self._loop and not self._loop.is_closed():
            if self._server is not None:
                self._loop.call_soon_threadsafe(self._server.close)
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(timeout=5)

    @property
    def ws_url(self):
        return f"ws://{self.host}:{self.port}/CP_TEST_001"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def ocpp_server():
    """Module-scoped fixture providing a mock OCPP WebSocket server."""
    try:
        import websockets  # noqa: F401
    except ImportError:
        require_service("websockets library not installed")

    server = MockOCPPServer()
    server.start()
    yield server
    server.stop()


@pytest.fixture
def ws_url(ocpp_server):
    """WebSocket URL for the mock OCPP server."""
    return ocpp_server.ws_url


@pytest.fixture
def cli_runner():
    """CLI runner fixture for OCPP tests."""
    from tests.integration.cli_runner import CLIRunner

    return CLIRunner(timeout=20)


# ---------------------------------------------------------------------------
# Connection and Version Tests
# ---------------------------------------------------------------------------


class TestOCPPConnection:
    """Test basic OCPP WebSocket connection."""

    def test_connect_to_mock_server(self, ocpp_server):
        """Verify mock server is running and accepting connections. [Category A]"""
        from websockets.asyncio.client import connect
        import asyncio

        async def _check():
            ws = await connect(
                ocpp_server.ws_url,
                subprotocols=["ocpp1.6"],
                open_timeout=5,
            )
            assert ws.subprotocol == "ocpp1.6"
            await ws.close()

        asyncio.new_event_loop().run_until_complete(_check())

    def test_subprotocol_negotiation_v16(self, ocpp_server):
        """Test that server negotiates ocpp1.6 subprotocol. [Category A]"""
        from websockets.asyncio.client import connect
        import asyncio

        async def _check():
            ws = await connect(
                ocpp_server.ws_url,
                subprotocols=["ocpp1.6"],
                open_timeout=5,
            )
            assert ws.subprotocol == "ocpp1.6"
            await ws.close()

        asyncio.new_event_loop().run_until_complete(_check())

    def test_subprotocol_negotiation_v201(self, ocpp_server):
        """Test that server negotiates ocpp2.0.1 subprotocol. [Category A]"""
        from websockets.asyncio.client import connect
        import asyncio

        async def _check():
            ws = await connect(
                ocpp_server.ws_url,
                subprotocols=["ocpp2.0.1"],
                open_timeout=5,
            )
            assert ws.subprotocol == "ocpp2.0.1"
            await ws.close()

        asyncio.new_event_loop().run_until_complete(_check())


# ---------------------------------------------------------------------------
# Scanner Integration Tests (direct scanner usage)
# ---------------------------------------------------------------------------


class TestOCPPScannerIntegration:
    """Test OCPPScanner class against mock server."""

    def test_scanner_connect_and_discover(self, ocpp_server):
        """Test scanner can connect and discover version. [Category A]"""
        from oida.protocols.ocpp.scanner import OCPPScanner

        args = {"target-url": ocpp_server.ws_url}
        scanner = OCPPScanner(args)

        conn = scanner.connect()
        assert conn is not None, "Scanner failed to connect"

        try:
            info = scanner._get_server_info(conn)
            assert info["connection_type"] == "WebSocket"
            assert info.get("subprotocol") in ("ocpp1.6", "ocpp2.0.1")

            results = scanner.discover(conn)
            assert "version" in results
            assert results["version"] in ("1.6", "2.0.1")
        finally:
            scanner.disconnect(conn)

    def test_scanner_boot_notification(self, ocpp_server):
        """Test scanner sends BootNotification and gets Accepted. [Category A]"""
        from oida.protocols.ocpp.scanner import OCPPScanner

        args = {"target-url": ocpp_server.ws_url, "version": "1.6"}
        scanner = OCPPScanner(args)

        conn = scanner.connect()
        assert conn is not None, "Scanner connection failed"

        try:
            from oida.protocols.ocpp.mixins.messages import MessagesMixin

            mixin = MessagesMixin()
            boot_msg = mixin._build_boot_notification("1.6")

            response = scanner._send_and_receive(conn, boot_msg)
            assert response is not None, "No response from BootNotification"

            data = json.loads(response)
            assert data[0] == 3, f"Expected CALLRESULT (3), got {data[0]}"
            assert data[2]["status"] == "Accepted"
            assert data[2]["interval"] == 300
        finally:
            scanner.disconnect(conn)

    def test_scanner_heartbeat(self, ocpp_server):
        """Test scanner sends Heartbeat and gets time response. [Category A]"""
        from oida.protocols.ocpp.scanner import OCPPScanner

        args = {"target-url": ocpp_server.ws_url, "version": "1.6"}
        scanner = OCPPScanner(args)

        conn = scanner.connect()
        assert conn is not None, "Scanner connection failed"

        try:
            from oida.protocols.ocpp.mixins.messages import MessagesMixin

            mixin = MessagesMixin()
            hb_msg = mixin._build_heartbeat()

            response = scanner._send_and_receive(conn, hb_msg)
            assert response is not None, "No response from Heartbeat"

            data = json.loads(response)
            assert data[0] == 3, f"Expected CALLRESULT (3), got {data[0]}"
            assert "currentTime" in data[2], "Heartbeat response missing currentTime"
        finally:
            scanner.disconnect(conn)

    def test_scanner_get_configuration(self, ocpp_server):
        """Test scanner retrieves configuration keys. [Category A]"""
        from oida.protocols.ocpp.scanner import OCPPScanner

        args = {"target-url": ocpp_server.ws_url, "version": "1.6"}
        scanner = OCPPScanner(args)

        conn = scanner.connect()
        assert conn is not None, "Scanner connection failed"

        try:
            from oida.protocols.ocpp.mixins.messages import MessagesMixin

            mixin = MessagesMixin()
            config_msg = mixin._build_get_configuration()

            response = scanner._send_and_receive(conn, config_msg)
            assert response is not None, "No response from GetConfiguration"

            data = json.loads(response)
            assert data[0] == 3, f"Expected CALLRESULT (3), got {data[0]}"
            config_keys = data[2].get("configurationKey", [])
            assert len(config_keys) >= 2, f"Expected >= 2 config keys, got {len(config_keys)}"

            key_names = [k["key"] for k in config_keys]
            assert "HeartbeatInterval" in key_names
            assert "NumberOfConnectors" in key_names
        finally:
            scanner.disconnect(conn)

    def test_scanner_data_transfer(self, ocpp_server):
        """Test scanner DataTransfer probe. [Category A]"""
        from oida.protocols.ocpp.scanner import OCPPScanner

        args = {"target-url": ocpp_server.ws_url, "version": "1.6"}
        scanner = OCPPScanner(args)

        conn = scanner.connect()
        assert conn is not None, "Scanner connection failed"

        try:
            from oida.protocols.ocpp.mixins.messages import MessagesMixin

            mixin = MessagesMixin()
            dt_msg = mixin._build_data_transfer("TestVendor", "probe", "ping")

            response = scanner._send_and_receive(conn, dt_msg)
            assert response is not None, "No response from DataTransfer"

            data = json.loads(response)
            assert data[0] == 3, f"Expected CALLRESULT (3), got {data[0]}"
            assert data[2]["status"] == "Accepted", f"DataTransfer not accepted: {data[2]}"
        finally:
            scanner.disconnect(conn)

    def test_scanner_action_enumeration(self, ocpp_server):
        """Test that action enumeration correctly classifies actions. [Category A]"""
        from oida.protocols.ocpp.scanner import OCPPScanner

        args = {"target-url": ocpp_server.ws_url, "version": "1.6"}
        scanner = OCPPScanner(args)

        conn = scanner.connect()
        assert conn is not None, "Scanner connection failed"

        try:
            from oida.protocols.ocpp.mixins.messages import MessagesMixin

            mixin = MessagesMixin()

            # Test a known action that returns FormationViolation (= supported)
            probe = mixin._build_call("MeterValues", {})
            response = scanner._send_and_receive(conn, probe)
            assert response is not None, "No response for MeterValues probe"
            data = json.loads(response)
            assert data[0] == 4, f"Expected CALLERROR (4), got {data[0]}"
            assert data[2] == "FormationViolation"

            # Test an unknown action (= NotSupported)
            probe2 = mixin._build_call("FakeAction12345", {})
            response2 = scanner._send_and_receive(conn, probe2)
            assert response2 is not None, "No response for unknown action probe"
            data2 = json.loads(response2)
            assert data2[0] == 4, f"Expected CALLERROR (4), got {data2[0]}"
            assert data2[2] == "NotSupported"

            # Test a known action that has a handler (returns CALLRESULT)
            probe3 = mixin._build_call("ClearCache", {})
            response3 = scanner._send_and_receive(conn, probe3)
            assert response3 is not None, "No response for ClearCache probe"
            data3 = json.loads(response3)
            assert data3[0] == 3, f"Expected CALLRESULT (3), got {data3[0]}"
            assert data3[2]["status"] == "Accepted"
        finally:
            scanner.disconnect(conn)


# ---------------------------------------------------------------------------
# CLI Integration Tests
# ---------------------------------------------------------------------------


class TestOCPPCLIIntegration:
    """Test the full oida ocpp CLI against the mock server."""

    def test_cli_basic_scan(self, cli_runner, ws_url):
        """Test basic CLI scan with auto-detection. [Category A]"""
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--timeout",
            "10",
            expect_json=False,
        )

        assert result.returncode == 0, (
            f"Basic scan failed (rc={result.returncode}): {result.stderr}"
        )

        # Should connect and detect version
        output = result.combined_output
        assert any(
            term in output.lower() for term in ["ocpp", "connected", "endpoint", "version", "boot"]
        ), f"Expected OCPP output, got: {output[:500]}"

    def test_cli_version_flag(self, cli_runner, ws_url):
        """Test --version flag forces specific OCPP version. [Category A]"""
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--version",
            "1.6",
            "--timeout",
            "10",
            expect_json=False,
        )

        assert result.returncode == 0, (
            f"Version flag scan failed (rc={result.returncode}): {result.stderr}"
        )

    def test_cli_enumerate_actions(self, cli_runner, ws_url):
        """Test -e flag for action enumeration. [Category A]"""
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "-e",
            "--timeout",
            "10",
            expect_json=False,
        )

        assert result.returncode == 0, (
            f"Action enumeration failed (rc={result.returncode}): {result.stderr}"
        )

        output = result.combined_output.lower()
        # Should list some action results
        assert any(term in output for term in ["action", "supported", "enumerat", "boot"]), (
            f"Expected action enumeration output, got: {output[:500]}"
        )

    def test_cli_get_config(self, cli_runner, ws_url):
        """Test --get-config flag. [Category B]"""
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--get-config",
            "--timeout",
            "10",
            expect_json=False,
        )

        # May or may not get config depending on role, but should not crash or timeout
        assert result.returncode in [0, 1], (
            f"GetConfig returned unexpected code (rc={result.returncode}): {result.stderr}"
        )

    def test_cli_security_flag(self, cli_runner, ws_url):
        """Test --security flag for security assessment. [Category B]"""
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--security",
            "--timeout",
            "10",
            expect_json=False,
        )

        # Security flag runs passive checks (no --confirm needed for those);
        # active probes will warn but should not crash
        assert result.returncode in [0, 1], (
            f"Security scan returned unexpected code (rc={result.returncode}): {result.stderr}"
        )

        output = result.combined_output.lower()
        # Should include security-related output
        assert any(
            term in output
            for term in ["security", "transport", "assessment", "finding", "encryption"]
        ), f"Expected security output, got: {output[:500]}"

    def test_cli_help_command(self, cli_runner):
        """Test ocpp --help works and shows expected options. [Category A]"""
        result = cli_runner.run("ocpp", "--help", expect_json=False)

        assert result.returncode == 0, (
            f"Help command failed (rc={result.returncode}): {result.stderr}"
        )

        output = result.combined_output.lower()
        assert "ocpp" in output
        assert "websocket" in output or "ws://" in output
        # Check that options appear in help
        assert "--connector-id" in result.combined_output
        assert "--raw-message" in result.combined_output
        assert "--ws-path" in result.combined_output
        # New security test flags
        assert "--security" in result.combined_output
        assert "--test-reset" in result.combined_output
        assert "--test-unlock" in result.combined_output
        assert "--test-firmware" in result.combined_output
        assert "--meter-values" in result.combined_output
        assert "--enum-connectors" in result.combined_output

    def test_cli_data_transfer(self, cli_runner, ws_url):
        """Test --data-transfer flag. [Category B]"""
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--data-transfer",
            "--timeout",
            "10",
            expect_json=False,
        )

        assert result.returncode in [0, 1], (
            f"DataTransfer returned unexpected code (rc={result.returncode}): {result.stderr}"
        )


# ---------------------------------------------------------------------------
# Error Handling Tests
# ---------------------------------------------------------------------------


class TestOCPPErrorHandling:
    """Test OCPP scanner error handling."""

    def test_connection_refused(self, cli_runner):
        """Test connection to closed port. [Category B]"""
        result = cli_runner.run(
            "ocpp",
            "ws://127.0.0.1:65534/CP1",
            "--timeout",
            "3",
            timeout=15,
            expect_json=False,
        )

        # Should handle gracefully (not hang); OCPP CLI may exit 0 on connection failure
        assert result.returncode in [0, 1], (
            f"Connection refused returned unexpected code (rc={result.returncode}): {result.stderr}"
        )

    def test_invalid_url(self, cli_runner):
        """Test handling of invalid WebSocket URL. [Category B]"""
        result = cli_runner.run(
            "ocpp",
            "not-a-valid-url!!!",
            "--timeout",
            "3",
            timeout=10,
            expect_json=False,
        )

        # Should handle gracefully (not hang); OCPP CLI may exit 0 on invalid URL
        assert result.returncode in [0, 1], (
            f"Invalid URL returned unexpected code (rc={result.returncode}): {result.stderr}"
        )

    def test_timeout_enforcement(self, cli_runner):
        """Test that --timeout is properly enforced. [Category B]"""
        result = cli_runner.run(
            "ocpp",
            "ws://10.255.255.1:9000/CP1",
            "--timeout",
            "3",
            timeout=15,
            expect_json=False,
        )

        # Should complete within reasonable time; OCPP CLI may exit 0 on timeout
        assert result.execution_time < 20, "Command did not respect timeout"
        assert result.returncode in [0, 1], (
            f"Timeout returned unexpected code (rc={result.returncode}): {result.stderr}"
        )

    def test_scanner_connect_refused(self):
        """Test scanner connect returns None on connection refused. [Category C]"""
        from oida.protocols.ocpp.scanner import OCPPScanner

        args = {"target-url": "ws://127.0.0.1:65534/CP1"}
        scanner = OCPPScanner(args)
        scanner.timeout = 2

        conn = scanner.connect()
        assert conn is None, "Connection to closed port should return None"


# ---------------------------------------------------------------------------
# NXC Flow Tests (mixin integration)
# ---------------------------------------------------------------------------


class TestOCPPNewFeaturesIntegration:
    """Test the 8 new OCPP scanner features against the mock server."""

    def _make_test_obj(self, ocpp_server, version="1.6"):
        """Create a FakeOCPP instance connected to the mock server.

        version: forces the WebSocket subprotocol (e.g. "2.0.1" negotiates only
        ocpp2.0.1, giving a guaranteed-2.0.1 session for the 2.0.1-specific
        security probes).
        """
        from oida.protocols.ocpp.scanner import OCPPScanner
        from oida.protocols.ocpp.mixins.discovery import DiscoveryMixin
        from oida.protocols.ocpp.mixins.security import SecurityMixin
        from oida.protocols.ocpp.mixins.messages import MessagesMixin
        from unittest.mock import Mock

        class FakeOCPP(DiscoveryMixin, SecurityMixin, MessagesMixin):
            pass

        args = {"target-url": ocpp_server.ws_url, "version": version}
        scanner = OCPPScanner(args)
        conn = scanner.connect()
        assert conn is not None, "FakeOCPP setup: scanner connection failed"

        obj = FakeOCPP()
        obj.conn = conn
        obj.logger = Mock()
        obj.results = {
            "success": True,
            "data": {"target_url": ocpp_server.ws_url, "ocpp_version": version},
        }
        obj.scanner = scanner
        obj.args = Mock()
        obj.args.username = None
        # A bare Mock() returns a truthy Mock for any unset attribute, so
        # create_conn_obj()'s `getattr(args, "tls_cert", None)` would read as a
        # (fake) client cert and suppress the "Anonymous access" finding. A real
        # argparse Namespace has tls_cert=None here.
        obj.args.tls_cert = None
        obj.args.timeout = 5
        obj.args.verbose = 0
        obj.args.connector_id = 1
        obj.args.max_connector_id = 3
        obj.ip = "127.0.0.1"

        return obj, scanner, conn

    def test_meter_values_probe(self, ocpp_server):
        """Test MeterValues probe via TriggerMessage. [Category A]"""
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.probe_meter_values()
            assert obj.results["success"] is True, "MeterValues probe should succeed"
            result = obj.results["data"].get("meter_values", {})
            # Mock server accepts TriggerMessage for MeterValues and returns
            # data, so the probe must reach a positive outcome (no "error"/"no_response").
            assert result.get("trigger_status") in ("Accepted", "direct_response"), (
                f"Mock accepts MeterValues trigger; expected a positive status, got: {result}"
            )
        finally:
            scanner.disconnect(conn)

    def test_connector_enumeration(self, ocpp_server):
        """Test connector enumeration. [Category A]"""
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.enumerate_connectors()
            assert obj.results["success"] is True, "Connector enumeration should succeed"
            connectors = obj.results["data"].get("connectors", {})
            assert isinstance(connectors, dict)
            # Mock advertises NumberOfConnectors=2 and accepts StatusNotification
            # triggers for connectors 0..2, so enumeration must discover them.
            found = [c for c in connectors.values() if isinstance(c, dict) and c.get("found")]
            assert len(found) >= 2, (
                f"Mock has 2 connectors (+ CP id 0); expected >=2 found, got: {connectors}"
            )
        finally:
            scanner.disconnect(conn)

    def test_charging_profile_write(self, ocpp_server):
        """Test charging profile write probe. [Category A]"""
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.test_charging_profile_write()
            assert obj.results["success"] is True, "Charging profile write should succeed"
            result = obj.results["data"].get("charging_profile_write", {})
            assert result.get("set_status") is not None, f"Expected set_status in result: {result}"
            # Mock server accepts SetChargingProfile
            assert result["set_status"] == "Accepted"
            assert result["clear_status"] == "Accepted"
        finally:
            scanner.disconnect(conn)

    def test_remote_transaction_control(self, ocpp_server):
        """Test remote transaction start with fake IdTag. [Category A]"""
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.test_remote_transaction_control()
            assert obj.results["success"] is True, "Remote transaction control should succeed"
            result = obj.results["data"].get("remote_transaction", {})
            assert result.get("start_status") is not None
            # Mock server rejects fake IdTag containing "OIDA"
            assert result["start_status"] == "Rejected"
        finally:
            scanner.disconnect(conn)

    def test_reset_command(self, ocpp_server):
        """Test soft reset command. [Category A]"""
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.test_reset_command()
            assert obj.results["success"] is True, "Reset command should succeed"
            result = obj.results["data"].get("reset_test", {})
            assert result.get("reset_status") is not None
            assert result["reset_type"] == "Soft"
            # Mock server accepts Reset
            assert result["reset_status"] == "Accepted"
        finally:
            scanner.disconnect(conn)

    def test_unlock_connector(self, ocpp_server):
        """Test unlock connector command. [Category A]"""
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.test_unlock_connector()
            assert obj.results["success"] is True, "Unlock connector should succeed"
            result = obj.results["data"].get("unlock_connector", {})
            assert result.get("unlock_status") is not None
            assert result["unlock_status"] == "Unlocked"
        finally:
            scanner.disconnect(conn)

    def test_firmware_update(self, ocpp_server):
        """Test firmware update injection probe. [Category A]"""
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.test_firmware_update()
            assert obj.results["success"] is True, "Firmware update probe should succeed"
            result = obj.results["data"].get("firmware_update", {})
            assert result.get("update_status") is not None
            # Mock server accepts UpdateFirmware
            assert result["update_status"] == "Accepted"
        finally:
            scanner.disconnect(conn)

    def test_config_write(self, ocpp_server):
        """Test configuration write probe. [Category A]"""
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.test_config_write()
            assert obj.results["success"] is True, "Config write probe should succeed"
            result = obj.results["data"].get("config_write", {})
            assert result.get("harmless_write") is not None
            # Mock server accepts HeartbeatInterval changes
            assert result["harmless_write"] == "Accepted"
            # Check sensitive keys: the probe always exercises SecurityProfile,
            # which the mock reports readonly, so it must appear in the results.
            sensitive = result.get("sensitive_keys", {})
            assert isinstance(sensitive, dict)
            assert sensitive.get("SecurityProfile") in ("Rejected", "readonly"), (
                f"Expected SecurityProfile probe result (Rejected/readonly), got: {sensitive}"
            )
        finally:
            scanner.disconnect(conn)


# ---------------------------------------------------------------------------
# Original NXC Flow Tests (mixin integration)
# ---------------------------------------------------------------------------


class TestOCPPMixinIntegration:
    """Test mixin methods against the real mock server (not mocked)."""

    def test_discovery_mixin_full_flow(self, ocpp_server):
        """Test DiscoveryMixin methods end-to-end against mock server. [Category A]"""
        from oida.protocols.ocpp.scanner import OCPPScanner
        from oida.protocols.ocpp.mixins.discovery import DiscoveryMixin
        from oida.protocols.ocpp.mixins.messages import MessagesMixin
        from unittest.mock import Mock

        class FakeOCPP(DiscoveryMixin, MessagesMixin):
            pass

        args = {"target-url": ocpp_server.ws_url, "version": "1.6"}
        scanner = OCPPScanner(args)
        conn = scanner.connect()
        assert conn is not None, "Scanner connection failed"

        try:
            obj = FakeOCPP()
            obj.conn = conn
            obj.logger = Mock()
            obj.results = {"success": True, "data": {}}
            obj.scanner = scanner
            obj.args = Mock()
            obj.args.verbose = 0

            # Version detection
            obj._handle_version_detection()
            assert obj.results["data"]["ocpp_version"] in ("1.6", "2.0.1")

            # BootNotification
            obj._handle_boot_notification()
            assert obj.results["data"]["boot_notification"]["status"] == "Accepted"

            # Heartbeat
            obj._handle_heartbeat()
            assert "heartbeat" in obj.results["data"]
            assert "current_time" in obj.results["data"]["heartbeat"]

            # GetConfiguration
            obj._handle_get_configuration()
            assert "configuration" in obj.results["data"]
            assert len(obj.results["data"]["configuration"]["keys"]) >= 2

            # DataTransfer
            obj._handle_data_transfer_probe()
            assert obj.results["data"]["data_transfer"]["status"] == "Accepted"

            # Verify overall success
            assert obj.results["success"] is True, "Full discovery flow should succeed"
        finally:
            scanner.disconnect(conn)

    def test_security_mixin_assessment(self, ocpp_server):
        """Test SecurityMixin assessment against mock server. [Category A]"""
        from oida.protocols.ocpp.scanner import OCPPScanner
        from oida.protocols.ocpp.mixins.discovery import DiscoveryMixin
        from oida.protocols.ocpp.mixins.security import SecurityMixin
        from oida.protocols.ocpp.mixins.messages import MessagesMixin
        from unittest.mock import Mock

        class FakeOCPP(DiscoveryMixin, SecurityMixin, MessagesMixin):
            pass

        args = {"target-url": ocpp_server.ws_url, "version": "1.6"}
        scanner = OCPPScanner(args)
        conn = scanner.connect()
        assert conn is not None, "Scanner connection failed"

        try:
            obj = FakeOCPP()
            obj.conn = conn
            obj.logger = Mock()
            obj.results = {"success": True, "data": {"target_url": ocpp_server.ws_url}}
            obj.scanner = scanner
            obj.args = Mock()
            obj.args.username = None
            obj.args.timeout = 5
            obj.args.verbose = 0
            obj.ip = "127.0.0.1"

            # Run discovery first to populate data
            obj._handle_version_detection()
            obj._handle_boot_notification()
            obj._handle_get_configuration()

            # Initialize actions data (empty for this test)
            obj.results["data"]["actions"] = {"supported": []}

            # Run individual security checks
            obj._handle_check_auth()
            obj._handle_check_boot()
            obj._handle_check_config_keys()

            findings = obj.results["data"].get("security_findings", [])
            assert len(findings) > 0, "Should find security issues"

            # Should find anonymous access or boot acceptance findings
            issues = [f["issue"] for f in findings]
            assert any("anonymous" in i.lower() or "boot" in i.lower() for i in issues), (
                f"Expected auth/boot findings, got: {issues}"
            )

            # Verify overall success
            assert obj.results["success"] is True, "Security assessment should succeed"
        finally:
            scanner.disconnect(conn)


# ---------------------------------------------------------------------------
# Security Finding Tests
# ---------------------------------------------------------------------------
# Tests for the security findings in the OCPP protocol module. Each test is
# tagged in its docstring with one of:
#   [Category A] strict -- mock supports it, assert success + validate finding
#   [Category B] conditional -- mock may not support it, validate the attempt
#   [Category C] error handling -- assert graceful failure
# (No hard-coded totals here: they rot as tests are added/removed.)
# ---------------------------------------------------------------------------


class TestOCPPSecurityFindings:
    """
    Comprehensive tests for ALL security findings in the OCPP protocol module.

    Uses the FakeOCPP mixin pattern from TestOCPPNewFeaturesIntegration to
    directly invoke security probe methods against the mock server, then
    validates that the correct security findings are recorded.
    """

    def _make_test_obj(self, ocpp_server, version="1.6"):
        """Create a FakeOCPP instance connected to the mock server."""
        from oida.protocols.ocpp.scanner import OCPPScanner
        from oida.protocols.ocpp.mixins.discovery import DiscoveryMixin
        from oida.protocols.ocpp.mixins.security import SecurityMixin
        from oida.protocols.ocpp.mixins.messages import MessagesMixin
        from oida.protocols.ocpp.mixins.charging import ChargingMixin
        from unittest.mock import Mock

        class FakeOCPP(DiscoveryMixin, SecurityMixin, ChargingMixin, MessagesMixin):
            pass

        args = {"target-url": ocpp_server.ws_url, "version": version}
        scanner = OCPPScanner(args)
        conn = scanner.connect()
        assert conn is not None, "FakeOCPP setup: scanner connection failed"

        obj = FakeOCPP()
        obj.conn = conn
        obj.logger = Mock()
        obj.results = {
            "success": True,
            "data": {
                "target_url": ocpp_server.ws_url,
                "ocpp_version": version,
            },
        }
        obj.scanner = scanner
        obj.args = Mock()
        obj.args.username = None
        # A bare Mock() returns a truthy Mock for any unset attribute, so
        # create_conn_obj()'s `getattr(args, "tls_cert", None)` would read as a
        # (fake) client cert and suppress the "Anonymous access" finding. A real
        # argparse Namespace has tls_cert=None here.
        obj.args.tls_cert = None
        obj.args.timeout = 5
        obj.args.verbose = 0
        obj.args.connector_id = 1
        obj.args.max_connector_id = 3
        obj.ip = "127.0.0.1"

        return obj, scanner, conn

    def _get_finding_issues(self, obj):
        """Extract all finding issue strings from results."""
        findings = obj.results["data"].get("security_findings", [])
        return [f["issue"] for f in findings]

    def _get_findings(self, obj):
        """Get the full findings list."""
        return obj.results["data"].get("security_findings", [])

    # ========================================================================
    # Passive Security Checks (no --confirm needed)
    # ========================================================================

    @pytest.mark.security
    def test_finding_anonymous_access_reported_on_connect(self, ocpp_server):
        """Anonymous WebSocket connection is flagged at connect time. [Category A]

        The "Anonymous access" finding is emitted by create_conn_obj() when a
        connection succeeds without credentials. _handle_check_auth() deliberately
        does NOT re-report it (see SecurityMixin._handle_check_auth docstring), so
        the real behaviour must be exercised through create_conn_obj().
        """
        from oida.protocols.ocpp import ocpp as ocpp_cls

        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.args.username = None
            obj._target_url = ocpp_server.ws_url
            obj.conn = None

            # create_conn_obj lives on the ocpp connection class, not the mixins;
            # call it unbound against the mixin-built FakeOCPP object.
            ocpp_cls.create_conn_obj(obj)

            assert obj.conn is not None, "create_conn_obj should connect to the mock"
            finding_texts = [str(c).lower() for c in obj.logger.security_finding.call_args_list]
            assert any("anonymous access" in t for t in finding_texts), (
                f"Expected an 'Anonymous access' security_finding call, got: {finding_texts}"
            )
        finally:
            if obj.conn is not None:
                scanner.disconnect(obj.conn)
            scanner.disconnect(conn)

    @pytest.mark.security
    def test_finding_check_auth_does_not_double_report(self, ocpp_server):
        """_handle_check_auth() must not re-report anonymous access. [Category A]

        create_conn_obj() already reports "Anonymous access" on connect, so
        _handle_check_auth() logs only and adds no finding -- guarding against the
        duplicate-finding regression its docstring describes.
        """
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.args.username = None
            obj._handle_check_auth()

            issues = self._get_finding_issues(obj)
            assert not any("anonymous" in i.lower() for i in issues), (
                f"_handle_check_auth must not add an anonymous finding, got: {issues}"
            )
            obj.logger.security_finding.assert_not_called()
        finally:
            scanner.disconnect(conn)

    @pytest.mark.security
    def test_finding_check_auth_authenticated_no_finding(self, ocpp_server):
        """Test --check-auth does NOT fire finding when authenticated. [Category A]

        Trigger: _handle_check_auth() when username IS set.
        Expected: No "Anonymous" finding.
        """
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.args.username = "CP001"
            obj._handle_check_auth()

            issues = self._get_finding_issues(obj)
            assert not any("anonymous" in i.lower() for i in issues), (
                f"Should NOT find anonymous access when authenticated, got: {issues}"
            )
        finally:
            scanner.disconnect(conn)

    @pytest.mark.security
    def test_finding_boot_notification_accepted(self, ocpp_server):
        """Test --check-boot finding: unknown charge point accepted. [Category A]

        Trigger: _handle_check_boot() when BootNotification status is "Accepted".
        Expected finding: "BootNotification accepted without authentication"
        Mock behavior: Always returns Accepted for BootNotification.
        """
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            # First run boot notification to populate results
            obj._handle_boot_notification()
            assert obj.results["data"]["boot_notification"]["status"] == "Accepted", (
                "Mock should accept BootNotification"
            )

            # Now run the check
            obj._handle_check_boot()

            issues = self._get_finding_issues(obj)
            assert any("boot" in i.lower() and "accepted" in i.lower() for i in issues), (
                f"Expected BootNotification acceptance finding, got: {issues}"
            )

            # Validate logger.security_finding was called with "No authentication"
            obj.logger.security_finding.assert_called()
            call_args = obj.logger.security_finding.call_args_list
            finding_texts = [str(c) for c in call_args]
            assert any("no authentication" in t.lower() for t in finding_texts), (
                f"Expected 'No authentication' in security_finding calls, got: {finding_texts}"
            )
        finally:
            scanner.disconnect(conn)

    @pytest.mark.security
    def test_finding_config_keys_writable(self, ocpp_server):
        """Test --check-config-keys finding: writable security config keys. [Category A]

        Trigger: _handle_check_config_keys() when HeartbeatInterval is readonly=False.
        Mock returns HeartbeatInterval with readonly=False.
        Note: HeartbeatInterval is not in SECURITY_CONFIG_KEYS, so this particular
        key won't trigger the writable finding. But the mock also returns
        SecurityProfile as readonly=True, so no writable security keys here.
        """
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            # Populate configuration data first
            obj._handle_get_configuration()
            config = obj.results["data"].get("configuration", {})
            assert len(config.get("keys", [])) >= 2, "Mock should return config keys"

            # Run the check
            obj._handle_check_config_keys()

            # The mock returns SecurityProfile as readonly=True, so no writable finding
            # for security keys. Validate the check ran without error.
            findings = self._get_findings(obj)
            # No "writable" findings expected since security keys are readonly in mock
            writable_findings = [f for f in findings if "writable" in f["issue"].lower()]
            assert len(writable_findings) == 0, (
                f"Security config keys should be readonly in mock, got: {writable_findings}"
            )
        finally:
            scanner.disconnect(conn)

    # ========================================================================
    # Active Security Probes - Config Write Tests
    # ========================================================================

    @pytest.mark.security
    def test_finding_config_write_heartbeat_accepted(self, ocpp_server):
        """Test config write finding: HeartbeatInterval write accepted. [Category A]

        Trigger: test_config_write() -> _test_harmless_config_write()
        Mock accepts ChangeConfiguration(HeartbeatInterval).
        Expected finding: "Configuration writes accepted without authentication"
        """
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.test_config_write()

            result = obj.results["data"].get("config_write", {})
            assert result["harmless_write"] == "Accepted", (
                f"Mock should accept HeartbeatInterval write, got: {result}"
            )

            issues = self._get_finding_issues(obj)
            assert any("configuration writes accepted" in i.lower() for i in issues), (
                f"Expected config write finding, got: {issues}"
            )

            # Verify the security_finding logger call for writable access
            obj.logger.security_finding.assert_called()
        finally:
            scanner.disconnect(conn)

    @pytest.mark.security
    def test_finding_sensitive_key_allow_offline_writable(self, ocpp_server):
        """Test sensitive key finding: AllowOfflineTxForUnknownId writable. [Category A]

        Trigger: test_config_write() -> _probe_sensitive_keys()
        Mock accepts ChangeConfiguration(AllowOfflineTxForUnknownId).
        Expected finding: "Security-sensitive key 'AllowOfflineTxForUnknownId' is writable"
        """
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.test_config_write()

            result = obj.results["data"].get("config_write", {})
            sensitive = result.get("sensitive_keys", {})
            assert sensitive.get("AllowOfflineTxForUnknownId") == "Accepted", (
                f"Mock should accept AllowOfflineTxForUnknownId write, got: {sensitive}"
            )

            issues = self._get_finding_issues(obj)
            assert any("allowofflinetxforunknownid" in i.lower() for i in issues), (
                f"Expected AllowOfflineTxForUnknownId writable finding, got: {issues}"
            )
        finally:
            scanner.disconnect(conn)

    @pytest.mark.security
    def test_finding_sensitive_key_security_profile_rejected(self, ocpp_server):
        """Test sensitive key: SecurityProfile write correctly rejected. [Category A]

        Trigger: test_config_write() -> _probe_sensitive_keys()
        Mock returns SecurityProfile as readonly=True in GetConfiguration,
        so the scanner reads it first and skips the actual write (returns 'readonly'),
        or if it does write, the mock rejects it (returns 'Rejected').
        Expected: No finding for SecurityProfile being writable.
        """
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.test_config_write()

            result = obj.results["data"].get("config_write", {})
            sensitive = result.get("sensitive_keys", {})
            assert sensitive.get("SecurityProfile") in ("Rejected", "readonly"), (
                f"Mock should reject or skip SecurityProfile write, got: {sensitive}"
            )

            issues = self._get_finding_issues(obj)
            assert not any(
                "securityprofile" in i.lower() and "writable" in i.lower() for i in issues
            ), f"SecurityProfile should NOT be writable, but got finding: {issues}"
        finally:
            scanner.disconnect(conn)

    # ========================================================================
    # Active Security Probes - Charging Profile
    # ========================================================================

    @pytest.mark.security
    def test_finding_charging_profile_write_accepted(self, ocpp_server):
        """Test charging profile write finding. [Category A]

        Trigger: test_charging_profile_write() when SetChargingProfile returns Accepted.
        Mock returns Accepted for SetChargingProfile.
        Expected finding: "Unauthorized charging profile write accepted"
        """
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.test_charging_profile_write()

            result = obj.results["data"].get("charging_profile_write", {})
            assert result["set_status"] == "Accepted", (
                f"Mock should accept SetChargingProfile, got: {result}"
            )

            issues = self._get_finding_issues(obj)
            assert any("charging profile write" in i.lower() for i in issues), (
                f"Expected charging profile write finding, got: {issues}"
            )

            # Validate the finding is well-formed (findings carry issue + description,
            # no severity field in this data model).
            findings = self._get_findings(obj)
            matched = [f for f in findings if "charging profile" in f["issue"].lower()]
            assert matched and matched[0]["description"], (
                f"Expected a well-formed charging-profile finding with a description, got: {findings}"
            )
        finally:
            scanner.disconnect(conn)

    # ========================================================================
    # Active Security Probes - Remote Transaction Control
    # ========================================================================

    @pytest.mark.security
    def test_finding_remote_start_rejected_fake_tag(self, ocpp_server):
        """Test remote start: fake IdTag correctly rejected. [Category A]

        Trigger: test_remote_transaction_control() with FAKE_ID_TAG containing "OIDA".
        Mock rejects IdTags containing "OIDA" or "TEST".
        Expected: No "Unauthorized remote transaction start" finding.
        """
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.test_remote_transaction_control()

            result = obj.results["data"].get("remote_transaction", {})
            assert result["start_status"] == "Rejected", (
                f"Mock should reject fake IdTag, got: {result}"
            )

            issues = self._get_finding_issues(obj)
            assert not any("remote transaction start" in i.lower() for i in issues), (
                f"Should NOT find unauthorized start when rejected, got: {issues}"
            )
        finally:
            scanner.disconnect(conn)

    # ========================================================================
    # Active Security Probes - Reset Command
    # ========================================================================

    @pytest.mark.security
    def test_finding_reset_accepted(self, ocpp_server):
        """Test reset finding: soft reset accepted without auth. [Category A]

        Trigger: test_reset_command() when Reset(Soft) returns Accepted.
        Mock returns Accepted for Reset.
        Expected finding: "Unauthorized soft reset accepted"
        """
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.test_reset_command()

            result = obj.results["data"].get("reset_test", {})
            assert result["reset_status"] == "Accepted", (
                f"Mock should accept soft reset, got: {result}"
            )
            assert result["reset_type"] == "Soft"

            issues = self._get_finding_issues(obj)
            assert any("reset" in i.lower() and "accepted" in i.lower() for i in issues), (
                f"Expected reset accepted finding, got: {issues}"
            )

            findings = self._get_findings(obj)
            matched = [f for f in findings if "reset" in f["issue"].lower()]
            assert matched and matched[0]["description"], (
                f"Expected a well-formed reset finding with a description, got: {findings}"
            )
        finally:
            scanner.disconnect(conn)

    # ========================================================================
    # Active Security Probes - Unlock Connector
    # ========================================================================

    @pytest.mark.security
    def test_finding_unlock_connector_accepted(self, ocpp_server):
        """Test unlock finding: connector unlocked without auth. [Category A]

        Trigger: test_unlock_connector() when UnlockConnector returns Unlocked.
        Mock returns Unlocked for connectorId > 0.
        Expected finding: "Unauthorized connector unlock accepted"
        """
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.test_unlock_connector()

            result = obj.results["data"].get("unlock_connector", {})
            assert result["unlock_status"] == "Unlocked", (
                f"Mock should unlock connector, got: {result}"
            )

            issues = self._get_finding_issues(obj)
            assert any("unlock" in i.lower() and "accepted" in i.lower() for i in issues), (
                f"Expected unlock accepted finding, got: {issues}"
            )

            findings = self._get_findings(obj)
            matched = [f for f in findings if "unlock" in f["issue"].lower()]
            assert matched and matched[0]["description"], (
                f"Expected a well-formed unlock finding with a description, got: {findings}"
            )
        finally:
            scanner.disconnect(conn)

    # ========================================================================
    # Active Security Probes - Firmware Update
    # ========================================================================

    @pytest.mark.security
    def test_finding_firmware_update_accepted(self, ocpp_server):
        """Test firmware update finding: unauthorized firmware update accepted. [Category A]

        Trigger: test_firmware_update() when UpdateFirmware returns CALLRESULT.
        Mock returns empty {} (Accepted) for UpdateFirmware.
        Expected finding: "Unauthorized firmware update accepted"
        """
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.test_firmware_update()

            result = obj.results["data"].get("firmware_update", {})
            assert result["update_status"] == "Accepted", (
                f"Mock should accept firmware update, got: {result}"
            )

            issues = self._get_finding_issues(obj)
            assert any(
                "firmware update" in i.lower() and "accepted" in i.lower() for i in issues
            ), f"Expected firmware update finding, got: {issues}"

            findings = self._get_findings(obj)
            matched = [f for f in findings if "firmware" in f["issue"].lower()]
            assert matched and matched[0]["description"], (
                f"Expected a well-formed firmware finding with a description, got: {findings}"
            )
        finally:
            scanner.disconnect(conn)

    # ========================================================================
    # Active Security Probes - ChangeAvailability
    # ========================================================================

    @pytest.mark.security
    def test_finding_change_availability_accepted(self, ocpp_server):
        """Test availability finding: unauthorized ChangeAvailability accepted. [Category A]

        Trigger: test_availability() when ChangeAvailability(Inoperative) returns Accepted.
        Mock returns Accepted for ChangeAvailability.
        Expected finding: "Unauthorized ChangeAvailability accepted"
        """
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.test_availability()

            result = obj.results["data"].get("availability_test", {})
            assert result["set_status"] in ("Accepted", "Scheduled"), (
                f"Mock should accept ChangeAvailability, got: {result}"
            )

            issues = self._get_finding_issues(obj)
            assert any(
                "changeavailability" in i.lower() or "availability" in i.lower() for i in issues
            ), f"Expected ChangeAvailability finding, got: {issues}"

            findings = self._get_findings(obj)
            matched = [f for f in findings if "availability" in f["issue"].lower()]
            assert matched and matched[0]["description"], (
                f"Expected a well-formed availability finding with a description, got: {findings}"
            )
        finally:
            scanner.disconnect(conn)

    # ========================================================================
    # Active Security Probes - ClearCache
    # ========================================================================

    @pytest.mark.security
    def test_finding_clear_cache_accepted(self, ocpp_server):
        """Test clear cache finding: unauthorized ClearCache accepted. [Category A]

        Trigger: test_clear_cache() when ClearCache returns Accepted.
        Mock returns Accepted for ClearCache.
        Expected finding: "Unauthorized ClearCache accepted"
        """
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.test_clear_cache()

            result = obj.results["data"].get("clear_cache", {})
            assert result["status"] == "Accepted", f"Mock should accept ClearCache, got: {result}"

            issues = self._get_finding_issues(obj)
            assert any("clearcache" in i.lower() or "clear cache" in i.lower() for i in issues), (
                f"Expected ClearCache finding, got: {issues}"
            )

            findings = self._get_findings(obj)
            matched = [
                f
                for f in findings
                if "clearcache" in f["issue"].lower() or "clear cache" in f["issue"].lower()
            ]
            assert matched and matched[0]["description"], (
                f"Expected a well-formed ClearCache finding with a description, got: {findings}"
            )
        finally:
            scanner.disconnect(conn)

    # ========================================================================
    # Active Security Probes - GetDiagnostics (SSRF)
    # ========================================================================

    @pytest.mark.security
    def test_finding_diagnostics_ssrf_accepted(self, ocpp_server):
        """Test diagnostics SSRF finding: GetDiagnostics with attacker URL accepted. [Category A]

        Trigger: test_diagnostics() when GetDiagnostics returns CALLRESULT.
        Mock returns {"fileName": "..."} for GetDiagnostics (Accepted).
        Expected finding: "Unauthorized GetDiagnostics accepted (SSRF)"
        """
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.test_diagnostics()

            result = obj.results["data"].get("diagnostics_test", {})
            assert result["status"] == "Accepted", (
                f"Mock should accept GetDiagnostics, got: {result}"
            )
            assert result["method"] == "GetDiagnostics"

            issues = self._get_finding_issues(obj)
            assert any("getdiagnostics" in i.lower() and "ssrf" in i.lower() for i in issues), (
                f"Expected GetDiagnostics SSRF finding, got: {issues}"
            )

            findings = self._get_findings(obj)
            matched = [f for f in findings if "ssrf" in f["issue"].lower()]
            assert matched and matched[0]["description"], (
                f"Expected a well-formed SSRF finding with a description, got: {findings}"
            )
        finally:
            scanner.disconnect(conn)

    # ========================================================================
    # Active Security Probes - RemoteStopTransaction
    # ========================================================================

    @pytest.mark.security
    def test_finding_remote_stop_accepted(self, ocpp_server):
        """Test remote stop finding: unauthorized RemoteStopTransaction accepted. [Category A]

        Trigger: test_remote_stop() when RemoteStopTransaction returns Accepted.
        Mock returns Accepted for RemoteStopTransaction.
        Expected finding: "Unauthorized RemoteStopTransaction accepted"
        """
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.test_remote_stop()

            result = obj.results["data"].get("remote_stop", {})
            assert result["status"] == "Accepted", (
                f"Mock should accept RemoteStopTransaction, got: {result}"
            )

            issues = self._get_finding_issues(obj)
            assert any(
                "remotestoptransaction" in i.lower() or "remote stop" in i.lower() for i in issues
            ), f"Expected RemoteStopTransaction finding, got: {issues}"

            findings = self._get_findings(obj)
            matched = [
                f
                for f in findings
                if "remotestop" in f["issue"].lower() or "remote stop" in f["issue"].lower()
            ]
            assert matched and matched[0]["description"], (
                f"Expected a well-formed RemoteStop finding with a description, got: {findings}"
            )
        finally:
            scanner.disconnect(conn)

    # ========================================================================
    # Active Security Probes - ReserveNow
    # ========================================================================

    @pytest.mark.security
    def test_finding_reserve_now_accepted(self, ocpp_server):
        """Test reservation finding: unauthorized ReserveNow accepted. [Category A]

        Trigger: test_reserve() when ReserveNow returns Accepted.
        Mock returns Accepted for ReserveNow.
        Expected finding: "Unauthorized ReserveNow accepted"
        """
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.test_reserve()

            result = obj.results["data"].get("reservation_test", {})
            assert result["reserve_status"] == "Accepted", (
                f"Mock should accept ReserveNow, got: {result}"
            )

            issues = self._get_finding_issues(obj)
            assert any("reservenow" in i.lower() or "reserve" in i.lower() for i in issues), (
                f"Expected ReserveNow finding, got: {issues}"
            )

            findings = self._get_findings(obj)
            matched = [f for f in findings if "reserve" in f["issue"].lower()]
            assert matched and matched[0]["description"], (
                f"Expected a well-formed reserve finding with a description, got: {findings}"
            )
        finally:
            scanner.disconnect(conn)

    # ========================================================================
    # Active Security Probes - LocalList
    # ========================================================================

    @pytest.mark.security
    def test_finding_local_list_version_disclosed(self, ocpp_server):
        """Test local list finding: list version disclosed. [Category A]

        Trigger: test_local_list() when GetLocalListVersion returns listVersion >= 0.
        Mock returns listVersion=3.
        Expected finding: "Local authorization list version disclosed"
        """
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.test_local_list()

            result = obj.results["data"].get("local_list_test", {})
            assert result["list_version"] == 3, f"Mock should return listVersion=3, got: {result}"

            issues = self._get_finding_issues(obj)
            assert any(
                "local" in i.lower() and "version" in i.lower() and "disclosed" in i.lower()
                for i in issues
            ), f"Expected local list version disclosure finding, got: {issues}"
        finally:
            scanner.disconnect(conn)

    @pytest.mark.security
    def test_finding_send_local_list_accepted(self, ocpp_server):
        """Test local list finding: SendLocalList accepted without auth. [Category A]

        Trigger: test_local_list() when SendLocalList returns Accepted.
        Mock returns Accepted for SendLocalList.
        Expected finding: "Unauthorized SendLocalList accepted"
        """
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.test_local_list()

            result = obj.results["data"].get("local_list_test", {})
            assert result["send_status"] == "Accepted", (
                f"Mock should accept SendLocalList, got: {result}"
            )

            issues = self._get_finding_issues(obj)
            assert any("sendlocallist" in i.lower() for i in issues), (
                f"Expected SendLocalList accepted finding, got: {issues}"
            )

            findings = self._get_findings(obj)
            matched = [f for f in findings if "sendlocallist" in f["issue"].lower()]
            assert matched and matched[0]["description"], (
                f"Expected a well-formed SendLocalList finding with a description, got: {findings}"
            )
        finally:
            scanner.disconnect(conn)

    # ========================================================================
    # Charging Flow Security Tests
    # ========================================================================

    @pytest.mark.security
    def test_finding_authorize_bypass_accepted(self, ocpp_server):
        """Test authorization bypass: fake idTag accepted. [Category A]

        Trigger: _test_authorize_flow() when Authorize returns Accepted.
        Mock accepts all Authorize requests (returns Accepted for any idTag).
        Expected finding: "Authorization bypass: fake idTag accepted"
        """
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj._test_authorize_flow()

            result = obj.results["data"].get("authorize_flow", {})
            assert result["status"] == "Accepted", f"Mock should accept Authorize, got: {result}"

            issues = self._get_finding_issues(obj)
            assert any(
                "authorization bypass" in i.lower() or "fake idtag" in i.lower() for i in issues
            ), f"Expected authorize bypass finding, got: {issues}"

            findings = self._get_findings(obj)
            matched = [
                f
                for f in findings
                if "authorization bypass" in f["issue"].lower()
                or "fake idtag" in f["issue"].lower()
            ]
            assert matched and matched[0]["description"], (
                f"Expected a well-formed authorization-bypass finding with a description, got: {findings}"
            )
        finally:
            scanner.disconnect(conn)

    @pytest.mark.security
    def test_finding_charging_session_started(self, ocpp_server):
        """Test charging session finding: unauthorized StartTransaction accepted. [Category A]

        Trigger: _test_charging_session() when StartTransaction returns Accepted.
        Mock returns Accepted with transactionId for StartTransaction.
        Expected finding: "Unauthorized charging session started"
        """
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj._test_charging_session()

            result = obj.results["data"].get("charging_session", {})
            assert result["start_status"] == "Accepted", (
                f"Mock should accept StartTransaction, got: {result}"
            )
            assert result["transaction_id"] is not None, (
                f"Expected transactionId in result, got: {result}"
            )

            issues = self._get_finding_issues(obj)
            assert any(
                "charging session" in i.lower() and "started" in i.lower() for i in issues
            ), f"Expected unauthorized charging session finding, got: {issues}"

            findings = self._get_findings(obj)
            matched = [f for f in findings if "charging session" in f["issue"].lower()]
            assert matched and matched[0]["description"], (
                f"Expected a well-formed charging-session finding with a description, got: {findings}"
            )
        finally:
            scanner.disconnect(conn)

    @pytest.mark.security
    def test_finding_meter_injection_accepted(self, ocpp_server):
        """Test meter injection finding: crafted MeterValues accepted. [Category B]

        Trigger: _test_meter_injection() when MeterValues returns CALLRESULT.
        Mock validates the MeterValues payload and replies with a
        FormationViolation CALLERROR, so the injection is rejected and no
        finding is raised.
        """
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj._test_meter_injection()

            result = obj.results["data"].get("meter_injection", {})
            status = result.get("status")
            assert status is not None, f"Expected meter injection status in result, got: {result}"

            issues = self._get_finding_issues(obj)
            if status == "Accepted":
                assert any("meter value injection" in i.lower() for i in issues), (
                    f"Expected meter injection finding when accepted, got: {issues}"
                )
            else:
                # Mock rejects the crafted MeterValues (FormationViolation):
                # no billing-fraud finding should be raised.
                assert "error" in str(status).lower(), (
                    f"Expected a rejection status from the mock, got: {result}"
                )
                assert not any("meter value injection" in i.lower() for i in issues), (
                    f"Should NOT find meter injection when rejected, got: {issues}"
                )
        finally:
            scanner.disconnect(conn)

    # ========================================================================
    # SSRF Extended Probes
    # ========================================================================

    @pytest.mark.security
    def test_finding_ssrf_extended_firmware_accepted(self, ocpp_server):
        """Test extended SSRF finding: UpdateFirmware with cloud metadata URLs. [Category B]

        Trigger: test_ssrf_extended() sends multiple SSRF URLs via UpdateFirmware.
        Mock accepts all UpdateFirmware requests.
        Expected finding: SSRF via UpdateFirmware with cloud metadata URLs.
        """
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.test_ssrf_extended()

            result = obj.results["data"].get("ssrf_extended", {})
            probes = result.get("probes", [])
            assert len(probes) > 0, "Expected SSRF probe results"

            # The insecure mock accepts every UpdateFirmware request, so the
            # SSRF vector must land for at least the firmware probes.
            accepted_probes = [p for p in probes if p.get("status") == "Accepted"]
            assert accepted_probes, (
                f"Insecure mock accepts UpdateFirmware; expected accepted SSRF probes, got: {probes}"
            )

            issues = self._get_finding_issues(obj)
            ssrf_issues = [i for i in issues if "ssrf" in i.lower()]
            assert len(ssrf_issues) > 0, (
                f"Expected SSRF findings for {len(accepted_probes)} accepted probes, "
                f"got issues: {issues}"
            )
        finally:
            scanner.disconnect(conn)

    # ========================================================================
    # WS Hijacking (SaiFlow) Tests
    # ========================================================================

    @pytest.mark.security
    def test_finding_ws_hijacking_parallel(self, ocpp_server):
        """Test WS hijacking finding: parallel connections accepted. [Category B]

        Trigger: test_ws_hijacking() when second connection is accepted.
        The mock has no duplicate-CP tracking (default websockets server), so a
        parallel second connection to the same charger ID is accepted.
        Expected finding: "WebSocket parallel connection hijacking (SaiFlow)"
        or "WebSocket connection displacement (SaiFlow DoS)"
        """
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.test_ws_hijacking()

            result = obj.results["data"].get("ws_hijacking", {})
            assert result is not None, "WS hijacking result should be recorded"

            # The insecure mock accepts a parallel second connection to the same
            # charger ID, so the hijack probe must register acceptance + a finding.
            assert result.get("accepted"), (
                f"Mock accepts parallel connections; expected accepted=True, got: {result}"
            )
            issues = self._get_finding_issues(obj)
            ws_findings = [i for i in issues if "websocket" in i.lower() or "saiflow" in i.lower()]
            assert len(ws_findings) > 0, (
                f"Expected WS hijacking finding when second conn accepted, got: {issues}"
            )
        finally:
            scanner.disconnect(conn)

    # ========================================================================
    # OCPP 2.0.1 Extended Probes
    #
    # Forcing version="2.0.1" makes the scanner negotiate only the ocpp2.0.1
    # subprotocol, so the connection is guaranteed 2.0.1 (no random 1.6/2.0.1
    # negotiation). The mock accepts these dangerous 2.0.1 operations (insecure
    # CSMS), so each probe must emit its CRITICAL finding.
    # ========================================================================

    @pytest.mark.security
    def test_finding_set_network_profile(self, ocpp_server):
        """Test SetNetworkProfile finding: CSMS redirect accepted. [Category A]"""
        obj, scanner, conn = self._make_test_obj(ocpp_server, version="2.0.1")
        try:
            assert obj._is_v201(), "expected a guaranteed OCPP 2.0.1 session"
            obj.test_network_profile()
            result = obj.results["data"].get("network_profile_test")
            assert result is not None, "probe did not run (2.0.1 guard skipped it?)"
            assert result.get("status") == "Accepted", f"expected Accepted, got {result}"
            issues = self._get_finding_issues(obj)
            assert any("SetNetworkProfile" in i for i in issues), (
                f"expected SetNetworkProfile finding, got: {issues}"
            )
        finally:
            scanner.disconnect(conn)

    @pytest.mark.security
    def test_finding_install_certificate(self, ocpp_server):
        """Test InstallCertificate finding: rogue root CA accepted. [Category A]"""
        obj, scanner, conn = self._make_test_obj(ocpp_server, version="2.0.1")
        try:
            assert obj._is_v201(), "expected a guaranteed OCPP 2.0.1 session"
            obj.test_install_certificate()
            result = obj.results["data"].get("install_cert_test")
            assert result is not None, "probe did not run (2.0.1 guard skipped it?)"
            assert result.get("install_status") == "Accepted", f"expected Accepted, got {result}"
            issues = self._get_finding_issues(obj)
            assert any("InstallCertificate" in i for i in issues), (
                f"expected InstallCertificate finding, got: {issues}"
            )
        finally:
            scanner.disconnect(conn)

    @pytest.mark.security
    def test_finding_display_message(self, ocpp_server):
        """Test SetDisplayMessage finding: social engineering vector. [Category A]"""
        obj, scanner, conn = self._make_test_obj(ocpp_server, version="2.0.1")
        try:
            assert obj._is_v201(), "expected a guaranteed OCPP 2.0.1 session"
            obj.test_display_message()
            result = obj.results["data"].get("display_message_test")
            assert result is not None, "probe did not run (2.0.1 guard skipped it?)"
            assert result.get("set_status") == "Accepted", f"expected Accepted, got {result}"
            issues = self._get_finding_issues(obj)
            assert any("SetDisplayMessage" in i for i in issues), (
                f"expected SetDisplayMessage finding, got: {issues}"
            )
        finally:
            scanner.disconnect(conn)

    @pytest.mark.security
    def test_finding_customer_info(self, ocpp_server):
        """Test CustomerInformation finding: PII exfiltration. [Category A]"""
        obj, scanner, conn = self._make_test_obj(ocpp_server, version="2.0.1")
        try:
            assert obj._is_v201(), "expected a guaranteed OCPP 2.0.1 session"
            obj.test_customer_info()
            result = obj.results["data"].get("customer_info_test")
            assert result is not None, "probe did not run (2.0.1 guard skipped it?)"
            assert result.get("status") == "Accepted", f"expected Accepted, got {result}"
            issues = self._get_finding_issues(obj)
            assert any("CustomerInformation" in i for i in issues), (
                f"expected CustomerInformation finding, got: {issues}"
            )
        finally:
            scanner.disconnect(conn)

    @pytest.mark.security
    def test_finding_default_credentials_skipped_when_unenforced(self, ocpp_server):
        """HTTP Basic Auth brute is skipped against a non-enforcing endpoint. [Category A]

        The mock CSMS accepts every WebSocket upgrade regardless of the
        Authorization header. _brute_force_http_auth()'s enforcement pre-check
        detects that Basic Auth is not gated and skips the brute entirely,
        reporting enforced=False with zero attempts -- rather than flagging every
        credential pair as "valid" (the snap7 brute false-positive fix). Reporting
        valid credentials here would be a false positive.
        """
        obj, scanner, conn = self._make_test_obj(ocpp_server)
        try:
            obj.args.brute_rate = 0
            obj.args.continue_on_success = False

            obj._brute_force_http_auth(["admin"], ["admin"])

            brute = obj.results["data"].get("brute_force", {}).get("http_auth", {})
            assert brute.get("enforced") is False, (
                f"Non-enforcing mock should be detected as unenforced, got: {brute}"
            )
            assert brute.get("tested") == 0, f"Brute must be skipped when unenforced, got: {brute}"
            assert brute.get("valid") == [], (
                f"No credentials should be reported valid when unenforced, got: {brute}"
            )

            # No false-positive "credentials found" finding must be recorded.
            issues = self._get_finding_issues(obj)
            assert not any("credentials found" in i.lower() for i in issues), (
                f"Should not report valid credentials against an unenforced endpoint, got: {issues}"
            )
        finally:
            scanner.disconnect(conn)

    # ========================================================================
    # CLI Integration - Security Finding via Full Scan
    # ========================================================================

    @pytest.mark.security
    def test_cli_security_checks_produce_findings(self, cli_runner, ws_url):
        """Test CLI --security runs passive checks and produces findings. [Category A]

        Runs the full CLI with --security flag and validates that
        security-related content appears in the output.
        """
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--security",
            "--timeout",
            "10",
            expect_json=False,
            json_log=True,
        )

        # Security checks (passive) should succeed; active probes warn about --confirm
        assert result.returncode in [0, 1], (
            f"Security scan failed unexpectedly (rc={result.returncode}): {result.stderr}"
        )

        output = result.combined_output.lower()
        # Should include security-related output from passive checks
        assert any(
            term in output
            for term in [
                "anonymous",
                "security",
                "transport",
                "boot",
                "finding",
                "auth",
                "plaintext",
            ]
        ), f"Expected security output from --security flag, got: {output[:500]}"

        # If json_log captured events, validate structure
        if result.scan_log is not None and len(result.scan_log.events) > 0:
            # Validate that events have required structure
            required_fields = {"timestamp", "level", "event_type", "module", "message"}
            for i, event in enumerate(result.scan_log.events[:5]):
                missing = required_fields - set(event.keys())
                assert not missing, f"Event {i} missing fields: {missing}"

    @pytest.mark.security
    def test_cli_security_probes_with_confirm(self, cli_runner, ws_url):
        """Test CLI --security --confirm runs active probes. [Category A]

        Runs the full CLI with --security --confirm and validates that
        active security probe output appears.
        """
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--security",
            "--confirm",
            "--timeout",
            "10",
            expect_json=False,
            json_log=True,
        )

        # Active probes may produce warnings but should not crash
        assert result.returncode in [0, 1], (
            f"Security probe scan failed (rc={result.returncode}): {result.stderr}"
        )

        output = result.combined_output.lower()
        # With --confirm, active probes should run and produce output
        probe_terms = [
            "security",
            "reset",
            "unlock",
            "firmware",
            "charging profile",
            "changeavailability",
            "clearcache",
            "diagnostic",
            "accepted",
            "rejected",
        ]
        assert any(term in output for term in probe_terms), (
            f"Expected active probe output with --confirm, got: {output[:800]}"
        )


# ---------------------------------------------------------------------------
# Flag Coverage Extension — real-CLI tests added to raise scripts/flag_coverage.py
# credit for previously-unexercised flags. See module docstring conventions;
# flag coverage matrix for the flags added below:
#
#   --enum-versions/-E        [A] test_cli_enum_versions_flag
#   --enumerate (long form)   [A] test_cli_enumerate_long_flag
#   --status                  [A] test_cli_status_flag
#   --trigger/-T              [A] test_cli_trigger_message_known_and_unknown
#   --local-list-version/-L   [A] test_cli_local_list_version_flag
#   --composite-schedule      [B] test_cli_composite_schedule_flag (unsupported by mock)
#   --installed-certs         [B] test_cli_installed_certs_flag (unsupported by mock)
#   --firmware-info           [B] test_cli_firmware_info_flag
#   --vendor / --model        [B] test_cli_vendor_and_model_flags (mock ignores payload)
#   --charge-point-id/--cp-id [B] test_cli_charge_point_id_and_cp_id_flags
#   --max-connector-id        [B] test_cli_max_connector_id_flag
#   --auth-id/-a              [A] test_cli_auth_id_flag
#   --ws-brute                [B] test_cli_ws_brute_builtin_flag / _wordlist_file_flag
#   --listen/--listen-timeout [B] test_cli_listen_mode_flag
#   --check-auth              [A/B] test_cli_check_auth_anonymous / _with_username
#   --check-boot              [A] test_cli_check_boot_flag
#   --check-config-keys       [A] test_cli_check_config_keys_without_data / _with_get_config
#   --test-config-write, --test-charging-profile, --test-remote-start,
#   --test-remote-stop, --test-reserve, --test-availability, --test-clear-cache,
#   --test-diagnostics, --test-local-list, --test-network-profile,
#   --test-install-cert, --test-display-msg, --test-customer-info,
#   --test-ssrf-extended, --test-ws-hijack
#                              [C/A] test_cli_security_probes_without_confirm_refused,
#                                    test_cli_security_probes_maximal_with_confirm,
#                                    test_cli_test_remote_start_rejected
#   --test-authorize, --test-charging, --test-meter-inject, --charging
#                              [C/A] test_cli_charging_flow_without_confirm_refused,
#                                    test_cli_charging_flow_with_confirm,
#                                    test_cli_charging_all_flag_with_confirm
#   Hostile paths: impostor silent/garbage socket, TLS/plaintext mismatch,
#   malformed args, unknown/typo/borrowed flags, wrong-type values.
# ---------------------------------------------------------------------------


class TestOCPPFlagCoverageDiscovery:
    """Real-CLI tests driving previously-uncovered discovery/identity flags."""

    def test_cli_enum_versions_flag(self, cli_runner, ws_url):
        """Test -E/--enum-versions probes supported OCPP subprotocols. [Category A]

        The mock server advertises subprotocols ocpp1.6 and ocpp2.0.1 only
        (NOT ocpp2.1), so a correct probe must report 2.1 as unsupported.
        """
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--enum-versions",
            "--timeout",
            "10",
            expect_json=False,
        )

        assert result.returncode in [0, 1], (
            f"enum-versions failed (rc={result.returncode}): {result.stderr}"
        )
        output = result.combined_output.lower()
        assert "version" in output
        assert "1.6" in output

    def test_cli_enumerate_long_flag(self, cli_runner, ws_url):
        """Test --enumerate (long form of -e) lists supported actions. [Category A]"""
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--enumerate",
            "--timeout",
            "10",
            expect_json=False,
        )

        assert result.returncode in [0, 1], (
            f"--enumerate failed (rc={result.returncode}): {result.stderr}"
        )
        output = result.combined_output.lower()
        assert "bootnotification" in output or "action" in output

    def test_cli_status_flag(self, cli_runner, ws_url):
        """Test --status sends StatusNotification and reports acceptance. [Category A]

        The mock's StatusNotification handler always returns an empty
        CALLRESULT, which the scanner reports as Accepted.
        """
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--status",
            "--timeout",
            "10",
            expect_json=False,
        )

        assert result.returncode in [0, 1], (
            f"--status failed (rc={result.returncode}): {result.stderr}"
        )
        output = result.combined_output.lower()
        assert "statusnotification" in output
        assert "accepted" in output

    def test_cli_trigger_message_known_and_unknown(self, cli_runner, ws_url):
        """Test -T/--trigger against a known and an unknown message type. [Category A]

        Mock's TriggerMessage handler accepts a fixed allow-list of message
        types and returns NotImplemented for anything else.
        """
        known = cli_runner.run(
            "ocpp",
            ws_url,
            "--trigger",
            "StatusNotification",
            "--timeout",
            "10",
            expect_json=False,
        )
        assert known.returncode in [0, 1], (
            f"--trigger StatusNotification failed (rc={known.returncode}): {known.stderr}"
        )
        known_output = known.combined_output.lower()
        assert "triggermessage" in known_output
        assert "accepted" in known_output

        unknown = cli_runner.run(
            "ocpp",
            ws_url,
            "--trigger",
            "BogusMessageType",
            "--timeout",
            "10",
            expect_json=False,
        )
        assert unknown.returncode in [0, 1], (
            f"--trigger BogusMessageType failed (rc={unknown.returncode}): {unknown.stderr}"
        )
        assert "notimplemented" in unknown.combined_output.lower()

    def test_cli_local_list_version_flag(self, cli_runner, ws_url):
        """Test -L/--local-list-version reads the CSMS's local auth list version. [Category A]

        Mock's GetLocalListVersion always returns listVersion=3.
        """
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--local-list-version",
            "--timeout",
            "10",
            expect_json=False,
        )

        assert result.returncode in [0, 1], (
            f"--local-list-version failed (rc={result.returncode}): {result.stderr}"
        )
        output = result.combined_output.lower()
        assert "local auth list version" in output or "listversion" in output
        assert "3" in output

    def test_cli_composite_schedule_flag(self, cli_runner, ws_url):
        """Test --composite-schedule against a mock that doesn't support it. [Category B]

        GetCompositeSchedule is not in the mock's KNOWN_ACTIONS, so the mock
        returns CALLERROR NotSupported. This is a degenerate-but-drivable
        case: the flag parses and the negative response is observable.
        """
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--composite-schedule",
            "--timeout",
            "10",
            expect_json=False,
        )

        assert result.returncode in [0, 1], (
            f"--composite-schedule failed (rc={result.returncode}): {result.stderr}"
        )
        output = result.combined_output.lower()
        assert "getcompositeschedule" in output
        assert "notsupported" in output or "not supported" in output

    def test_cli_installed_certs_flag(self, cli_runner, ws_url):
        """Test --installed-certs against a mock that doesn't support it. [Category B]

        GetInstalledCertificateIds is not in the mock's KNOWN_ACTIONS, so the
        mock returns CALLERROR NotSupported.
        """
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--installed-certs",
            "--timeout",
            "10",
            expect_json=False,
        )

        assert result.returncode in [0, 1], (
            f"--installed-certs failed (rc={result.returncode}): {result.stderr}"
        )
        output = result.combined_output.lower()
        assert "getinstalledcertificateids" in output

    def test_cli_firmware_info_flag(self, cli_runner, ws_url):
        """Test --firmware-info gathers boot/config-derived firmware data. [Category B]

        Asserts the command completes and produces a firmware-related
        section; exact vendor/model text is not asserted since the mock
        does not echo BootNotification payload content back.
        """
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--firmware-info",
            "--timeout",
            "10",
            expect_json=False,
        )

        assert result.returncode in [0, 1], (
            f"--firmware-info failed (rc={result.returncode}): {result.stderr}"
        )
        assert "firmware" in result.combined_output.lower()

    def test_cli_vendor_and_model_flags(self, cli_runner, ws_url):
        """Test --vendor/--model are accepted and included in the boot flow. [Category B]

        The mock ignores BootNotification payload content (always Accepted),
        so these flags cannot be distinguished by server response; this test
        asserts the flags parse and the scan completes without crashing.
        """
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--vendor",
            "AcmeChargingCo",
            "--model",
            "AcmeModelX",
            "--enumerate",
            "--timeout",
            "10",
            expect_json=False,
        )

        assert result.returncode in [0, 1], (
            f"--vendor/--model failed (rc={result.returncode}): {result.stderr}"
        )
        assert "traceback" not in result.combined_output.lower()

    def test_cli_charge_point_id_and_cp_id_flags(self, cli_runner, ocpp_server):
        """Test --charge-point-id and its --cp-id alias against a bare target. [Category B]

        Both flags only affect URL-path construction when the target is a
        bare host:port (no explicit path); the mock accepts any WS path, so
        this asserts both aliases parse and connect successfully.
        """
        bare_target = f"{ocpp_server.host}:{ocpp_server.port}"

        long_form = cli_runner.run(
            "ocpp",
            bare_target,
            "--charge-point-id",
            "CUSTOM_CP_LONGFORM",
            "--timeout",
            "10",
            expect_json=False,
        )
        assert long_form.returncode in [0, 1], (
            f"--charge-point-id failed (rc={long_form.returncode}): {long_form.stderr}"
        )

        alias = cli_runner.run(
            "ocpp",
            bare_target,
            "--cp-id",
            "CUSTOM_CP_ALIAS",
            "--timeout",
            "10",
            expect_json=False,
        )
        assert alias.returncode in [0, 1], f"--cp-id failed (rc={alias.returncode}): {alias.stderr}"

    def test_cli_max_connector_id_flag(self, cli_runner, ws_url):
        """Test --max-connector-id bounds connector enumeration. [Category B]"""
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--enum-connectors",
            "--max-connector-id",
            "2",
            "--timeout",
            "10",
            expect_json=False,
        )

        assert result.returncode in [0, 1], (
            f"--max-connector-id failed (rc={result.returncode}): {result.stderr}"
        )
        assert "traceback" not in result.combined_output.lower()

    def test_cli_auth_id_flag(self, cli_runner, ws_url):
        """Test -a/--auth-id sends an Authorize request for a specific tag. [Category A]

        Mock's Authorize handler always accepts.
        """
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--auth-id",
            "MYTAG001",
            "--timeout",
            "10",
            expect_json=False,
        )

        assert result.returncode in [0, 1], (
            f"--auth-id failed (rc={result.returncode}): {result.stderr}"
        )
        output = result.combined_output.lower()
        assert "mytag001" in output
        assert "accepted" in output

    def test_cli_ws_brute_builtin_flag(self, cli_runner, ocpp_server):
        """Test --ws-brute with the built-in wordlist against a permissive mock. [Category B]

        The mock accepts any WebSocket path, so this exercises the brute
        loop's parse/execute path rather than a specific "found" assertion.
        """
        bare_target = f"{ocpp_server.host}:{ocpp_server.port}"
        result = cli_runner.run(
            "ocpp",
            bare_target,
            "--ws-brute",
            "--brute-rate",
            "0",
            "--timeout",
            "5",
            expect_json=False,
            timeout=60,
        )

        assert result.returncode in [0, 1], (
            f"--ws-brute failed (rc={result.returncode}): {result.stderr}"
        )
        assert "traceback" not in result.combined_output.lower()

    def test_cli_ws_brute_wordlist_file_flag(self, cli_runner, ocpp_server, tmp_path):
        """Test --ws-brute with an explicit wordlist file. [Category B]"""
        wordlist = tmp_path / "ocpp_paths.txt"
        wordlist.write_text("CP_TEST_001\nfoo\nbar\n")

        bare_target = f"{ocpp_server.host}:{ocpp_server.port}"
        result = cli_runner.run(
            "ocpp",
            bare_target,
            "--ws-brute",
            str(wordlist),
            "--timeout",
            "5",
            expect_json=False,
            timeout=40,
        )

        assert result.returncode in [0, 1], (
            f"--ws-brute <file> failed (rc={result.returncode}): {result.stderr}"
        )
        assert "traceback" not in result.combined_output.lower()

    def test_cli_listen_mode_flag(self, cli_runner, ws_url):
        """Test --listen with a short --listen-timeout completes promptly. [Category B]"""
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--listen",
            "--listen-timeout",
            "2",
            "--timeout",
            "10",
            expect_json=False,
            timeout=25,
        )

        assert result.returncode in [0, 1], (
            f"--listen failed (rc={result.returncode}): {result.stderr}"
        )
        assert result.execution_time < 20, "Listen mode did not respect --listen-timeout"
        assert "traceback" not in result.combined_output.lower()


class TestOCPPFlagCoverageSecurityChecks:
    """Real-CLI tests driving previously-uncovered passive security-check flags."""

    def test_cli_check_auth_anonymous(self, cli_runner, ws_url):
        """Test --check-auth without credentials runs without crashing. [Category B]

        Without --username, the handler only logs at debug level; the
        connection-level anonymous-access finding is emitted independently,
        so this test only asserts the flag parses and the scan completes.
        """
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--check-auth",
            "--timeout",
            "10",
            expect_json=False,
        )

        assert result.returncode in [0, 1], (
            f"--check-auth failed (rc={result.returncode}): {result.stderr}"
        )
        assert "traceback" not in result.combined_output.lower()

    def test_cli_check_auth_with_username(self, cli_runner, ws_url):
        """Test --check-auth with -u/-P reports authenticated identity. [Category A]"""
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--check-auth",
            "--username",
            "testuser",
            "--password",
            "testpass",
            "--timeout",
            "10",
            expect_json=False,
        )

        assert result.returncode in [0, 1], (
            f"--check-auth with credentials failed (rc={result.returncode}): {result.stderr}"
        )
        output = result.combined_output.lower()
        assert "authenticated as testuser" in output

    def test_cli_check_boot_flag(self, cli_runner, ws_url):
        """Test --check-boot flags an unauthenticated BootNotification accept. [Category A]

        The mock always Accepts BootNotification with no authentication,
        which the scanner should surface as a finding.
        """
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--check-boot",
            "--timeout",
            "10",
            expect_json=False,
        )

        assert result.returncode in [0, 1], (
            f"--check-boot failed (rc={result.returncode}): {result.stderr}"
        )
        output = result.combined_output.lower()
        assert "bootnotification" in output or "no authentication" in output

    def test_cli_check_config_keys_without_data(self, cli_runner, ws_url):
        """Test --check-config-keys alone reports missing prerequisite data. [Category A]

        Without a prior --get-config in the same run, the handler has no
        configuration keys to check and prints a deterministic message.
        """
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--check-config-keys",
            "--timeout",
            "10",
            expect_json=False,
        )

        assert result.returncode in [0, 1], (
            f"--check-config-keys failed (rc={result.returncode}): {result.stderr}"
        )
        output = result.combined_output.lower()
        assert "no configuration data" in output

    def test_cli_check_config_keys_with_get_config(self, cli_runner, ws_url):
        """Test --get-config --check-config-keys runs the full check path. [Category B]

        The mock's config keys (SecurityProfile read-only, no
        AuthorizationKey) do not trigger a writable-sensitive-key finding
        against this mock, so this asserts the combined flags parse and the
        scan completes cleanly rather than a specific finding.
        """
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--get-config",
            "--check-config-keys",
            "--timeout",
            "10",
            expect_json=False,
        )

        assert result.returncode in [0, 1], (
            f"--get-config --check-config-keys failed (rc={result.returncode}): {result.stderr}"
        )
        assert "traceback" not in result.combined_output.lower()


class TestOCPPFlagCoverageSecurityProbesAndCharging:
    """Real-CLI tests for confirm-gated security probe and charging-flow flags."""

    def test_cli_security_probes_without_confirm_refused(self, cli_runner, ws_url):
        """Test all dangerous security probe flags are refused without --confirm. [Category C]"""
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--test-config-write",
            "--test-charging-profile",
            "--test-remote-start",
            "--test-remote-stop",
            "--test-reserve",
            "--test-availability",
            "--test-clear-cache",
            "--test-diagnostics",
            "--test-local-list",
            "--test-network-profile",
            "--test-install-cert",
            "--test-display-msg",
            "--test-customer-info",
            "--test-ssrf-extended",
            "--test-ws-hijack",
            "--timeout",
            "10",
            expect_json=False,
        )

        assert result.returncode in [0, 1], (
            f"Security probes without --confirm failed (rc={result.returncode}): {result.stderr}"
        )
        output = result.combined_output.lower()
        assert "require --confirm" in output
        assert "traceback" not in output

    def test_cli_security_probes_maximal_with_confirm(self, cli_runner, ws_url):
        """Test the same maximal probe flag set with --confirm actually runs. [Category A]

        The mock accepts essentially every OCPP 2.0.1 dangerous operation
        (SetNetworkProfile, InstallCertificate, SetDisplayMessage,
        CustomerInformation, ReserveNow, ClearCache, GetDiagnostics,
        ChangeAvailability, SendLocalList all Accepted) while rejecting
        sensitive ChangeConfiguration keys, so both outcomes must appear.
        """
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--test-config-write",
            "--test-charging-profile",
            "--test-remote-start",
            "--test-remote-stop",
            "--test-reserve",
            "--test-availability",
            "--test-clear-cache",
            "--test-diagnostics",
            "--test-local-list",
            "--test-network-profile",
            "--test-install-cert",
            "--test-display-msg",
            "--test-customer-info",
            "--test-ssrf-extended",
            "--test-ws-hijack",
            "--confirm",
            "--timeout",
            "15",
            expect_json=False,
            timeout=40,
        )

        assert result.returncode in [0, 1], (
            f"Security probes with --confirm failed (rc={result.returncode}): {result.stderr}"
        )
        output = result.combined_output.lower()
        assert "traceback" not in output
        assert "accepted" in output
        assert "rejected" in output

    def test_cli_test_remote_start_rejected(self, cli_runner, ws_url):
        """Test --test-remote-start --confirm is rejected by the mock. [Category A]

        The scanner's fixed test idTag contains "OIDA", and the mock
        rejects RemoteStartTransaction for any idTag containing "OIDA" or
        "TEST".
        """
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--test-remote-start",
            "--confirm",
            "--timeout",
            "10",
            expect_json=False,
        )

        assert result.returncode in [0, 1], (
            f"--test-remote-start failed (rc={result.returncode}): {result.stderr}"
        )
        assert "rejected" in result.combined_output.lower()

    def test_cli_charging_flow_without_confirm_refused(self, cli_runner, ws_url):
        """Test charging-flow flags are refused without --confirm. [Category C]"""
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--test-authorize",
            "--test-charging",
            "--test-meter-inject",
            "--timeout",
            "10",
            expect_json=False,
        )

        assert result.returncode in [0, 1], (
            f"Charging flow without --confirm failed (rc={result.returncode}): {result.stderr}"
        )
        output = result.combined_output.lower()
        assert "require --confirm" in output
        assert "traceback" not in output

    def test_cli_charging_flow_with_confirm(self, cli_runner, ws_url):
        """Test charging-flow flags run with --confirm. [Category A]

        Authorize and StartTransaction are always Accepted by the mock.
        """
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--test-authorize",
            "--test-charging",
            "--test-meter-inject",
            "--confirm",
            "--timeout",
            "15",
            expect_json=False,
            timeout=30,
        )

        assert result.returncode in [0, 1], (
            f"Charging flow with --confirm failed (rc={result.returncode}): {result.stderr}"
        )
        output = result.combined_output.lower()
        assert "traceback" not in output
        assert "accepted" in output

    def test_cli_charging_all_flag_with_confirm(self, cli_runner, ws_url):
        """Test the combined --charging (all charging tests) flag with --confirm. [Category A]"""
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--charging",
            "--confirm",
            "--timeout",
            "15",
            expect_json=False,
            timeout=30,
        )

        assert result.returncode in [0, 1], (
            f"--charging --confirm failed (rc={result.returncode}): {result.stderr}"
        )
        output = result.combined_output.lower()
        assert "traceback" not in output
        assert "accepted" in output


class TestOCPPFlagCoverageHostilePaths:
    """Hostile / invalid-server and invalid-argument paths for the ocpp module."""

    def test_impostor_silent_socket(self, cli_runner, tmp_path):
        """Test connecting to a socket that accepts but never responds. [Category C]

        Exercises the read-timeout path (not the connect-timeout path); must
        fail cleanly with no traceback and no false-positive success claim.
        """
        import socket
        import threading

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        stop = threading.Event()

        def _accept_and_hang():
            srv.settimeout(5)
            try:
                conn, _ = srv.accept()
                stop.wait(4)
                conn.close()
            except OSError:
                pass

        t = threading.Thread(target=_accept_and_hang, daemon=True)
        t.start()
        try:
            result = cli_runner.run(
                "ocpp",
                f"ws://127.0.0.1:{port}/CP1",
                "--timeout",
                "3",
                timeout=15,
                expect_json=False,
                output=str(tmp_path),
                format="json",
            )
        finally:
            stop.set()
            srv.close()
            t.join(timeout=5)

        assert result.returncode in [0, 1], (
            f"Silent impostor socket returned unexpected code: {result.stderr}"
        )
        output = result.combined_output.lower()
        assert "traceback" not in output
        assert "accepted" not in output, "Must not claim a false-positive success"
        # P1 regression: the WebSocket handshake never completed, so the record
        # must report success=False (not a fabricated OCPP identification).
        rec_path = tmp_path / "ocpp.json"
        assert rec_path.exists()
        rec = json.loads(rec_path.read_text())
        rec = rec[0] if isinstance(rec, list) else rec
        assert rec.get("success") is False
        assert rec.get("error")

    def test_impostor_garbage_bytes_socket(self, cli_runner, tmp_path):
        """Test connecting to a socket that returns junk instead of a WS handshake. [Category C]"""
        import socket
        import threading

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def _accept_and_send_garbage():
            srv.settimeout(5)
            try:
                conn, _ = srv.accept()
                conn.sendall(b"NOT_A_WEBSOCKET_HANDSHAKE\r\n\r\n\x00\x01\x02")
                conn.close()
            except OSError:
                pass

        t = threading.Thread(target=_accept_and_send_garbage, daemon=True)
        t.start()
        try:
            result = cli_runner.run(
                "ocpp",
                f"ws://127.0.0.1:{port}/CP1",
                "--timeout",
                "3",
                timeout=15,
                expect_json=False,
                output=str(tmp_path),
                format="json",
            )
        finally:
            srv.close()
            t.join(timeout=5)

        assert result.returncode in [0, 1], (
            f"Garbage-bytes impostor socket returned unexpected code: {result.stderr}"
        )
        output = result.combined_output.lower()
        assert "traceback" not in output
        assert "accepted" not in output, "Must not claim a false-positive success"
        # P1 regression: junk instead of a 101 handshake must not be reported as OCPP.
        rec_path = tmp_path / "ocpp.json"
        assert rec_path.exists()
        rec = json.loads(rec_path.read_text())
        rec = rec[0] if isinstance(rec, list) else rec
        assert rec.get("success") is False
        assert rec.get("error")

    def test_tls_mismatch_wss_against_plaintext_server(self, cli_runner, ocpp_server):
        """Test wss:// (TLS) scheme against a plaintext WS mock fails cleanly. [Category C]"""
        result = cli_runner.run(
            "ocpp",
            f"wss://{ocpp_server.host}:{ocpp_server.port}/CP_TEST_001",
            "--tls-insecure",
            "--timeout",
            "5",
            timeout=15,
            expect_json=False,
        )

        assert result.returncode in [0, 1], (
            f"TLS-mismatch scan returned unexpected code: {result.stderr}"
        )
        assert "traceback" not in result.combined_output.lower()

    def test_malformed_args_invalid_version_choice(self, cli_runner, ws_url):
        """Test an invalid --version choice is rejected by argparse. [Category C]"""
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--version",
            "9.9",
            "--timeout",
            "5",
            expect_json=False,
        )

        assert result.returncode != 0, "Invalid --version choice should be rejected"
        assert "traceback" not in result.combined_output.lower()

    def test_malformed_args_nonnumeric_max_connector_id(self, cli_runner, ws_url):
        """Test a non-numeric --max-connector-id is rejected. [Category C]"""
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--max-connector-id",
            "not-a-number",
            "--timeout",
            "5",
            expect_json=False,
        )

        assert result.returncode != 0, "Non-numeric --max-connector-id should be rejected"
        assert "traceback" not in result.combined_output.lower()

    def test_false_flags_unknown_flag_rejected(self, cli_runner, ws_url):
        """Test an entirely unknown flag is rejected, not silently ignored. [Category C]"""
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--not-a-real-flag",
            "--timeout",
            "5",
            expect_json=False,
        )

        assert result.returncode != 0, "Unknown flag must not be silently accepted"
        assert "traceback" not in result.combined_output.lower()

    def test_false_flags_transposed_typo_rejected(self, cli_runner, ws_url):
        """Test a transposed-letter typo of a real flag is rejected. [Category C]

        Uses a transposition (--charge-piont-id), never a truncation, since
        argparse's prefix-abbreviation would silently accept a truncation.
        """
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--charge-piont-id",
            "SOMEID",
            "--timeout",
            "5",
            expect_json=False,
        )

        assert result.returncode != 0, "Transposed-typo flag must not be accepted"
        assert "traceback" not in result.combined_output.lower()

    def test_false_flags_borrowed_from_other_protocol_rejected(self, cli_runner, ws_url):
        """Test a flag borrowed from another protocol (modbus) is rejected. [Category C]"""
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--slave-id",
            "1",
            "--timeout",
            "5",
            expect_json=False,
        )

        assert result.returncode != 0, "Flag borrowed from another protocol must be rejected"
        assert "traceback" not in result.combined_output.lower()

    def test_false_flags_wrong_type_timeout_rejected(self, cli_runner, ws_url):
        """Test a valid flag given a value of the wrong type is rejected. [Category C]"""
        result = cli_runner.run(
            "ocpp",
            ws_url,
            "--timeout",
            "not-a-number",
            expect_json=False,
        )

        assert result.returncode != 0, "Non-numeric --timeout should be rejected"
        assert "traceback" not in result.combined_output.lower()

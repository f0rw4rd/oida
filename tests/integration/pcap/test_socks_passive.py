"""Integration tests for SOCKS passive listener in EK mode.

Tests all T1 tshark field extractions:
- socks.version (protocol version)
- socks.auth_method_count (number of auth methods offered)
- socks.auth_method (auth methods offered by client)
- socks.auth_accepted_method (auth method selected by server)
- socks.auth_status (authentication result)
- socks.subnegotiation_version (auth subneg version)
- socks.username (cleartext username)
- socks.password (cleartext password)
"""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]

# Common test parameters
_SOCKS_PARAMS = dict(
    module_name="socks",
    class_name="SOCKSPassiveListener",
    display_filter="socks",
    pcap_subpath="socks/generated_socks.pcap",
)


class TestSOCKSPassiveEK:
    """SOCKS-specific tests beyond the parametrised quality suite."""

    def test_socks_basic(self):
        """Basic smoke test: listener processes packets, finds devices and credentials."""
        listener, devices, result = _run_listener_test(
            **_SOCKS_PARAMS,
            min_devices=2,
            min_interactions=1,
        )
        creds = listener.get_credentials_summary()
        assert len(creds) >= 1, "Expected at least one credential"
        for c in creds:
            assert c.get("protocol") == "SOCKS"
            assert "username" in c

    def test_socks_credential_fields(self):
        """Verify credential summary uses canonical key names for scanner compatibility."""
        listener, devices, result = _run_listener_test(
            **_SOCKS_PARAMS,
            min_devices=2,
        )
        creds = listener.get_credentials_summary()
        assert len(creds) >= 1
        cred = creds[0]

        # Canonical key names that the scanner credential loop expects
        assert "username" in cred
        assert "password" in cred
        assert "credential_type" in cred
        assert "server_ip" in cred
        assert "client_ip" in cred
        assert "auth_method" in cred
        assert "server_port" in cred

        # Verify actual values from the fixture
        assert cred["username"] == "socksuser"
        assert cred["password"] == "sockspass"
        assert cred["credential_type"] == "plaintext"
        assert cred["auth_method"] == "SOCKS5"

    def test_socks_version_extracted(self):
        """T1 field: socks.version is extracted into interaction details."""
        listener, devices, result = _run_listener_test(
            **_SOCKS_PARAMS,
            expect_details=["version"],
        )
        # Every interaction should have a version field
        for ix in listener.interactions:
            version = ix.details.get("version")
            assert version is not None, f"Missing 'version' in interaction: {ix.operation}"
            assert version == "5", f"Expected SOCKS version 5, got {version}"

    def test_socks_auth_method_count_extracted(self):
        """T1 field: socks.auth_method_count is extracted for client greeting packets."""
        listener, devices, result = _run_listener_test(**_SOCKS_PARAMS)
        greeting_ixs = [ix for ix in listener.interactions if ix.operation == "SOCKS Greeting"]
        assert len(greeting_ixs) >= 1, "Expected at least one SOCKS Greeting interaction"

        for ix in greeting_ixs:
            count = ix.details.get("auth_method_count")
            assert count is not None, "Missing 'auth_method_count' in greeting interaction"
            assert count == "1", f"Expected auth_method_count=1, got {count}"

    def test_socks_auth_method_extracted(self):
        """T1 field: socks.auth_method is extracted for client greeting packets."""
        listener, devices, result = _run_listener_test(**_SOCKS_PARAMS)
        greeting_ixs = [ix for ix in listener.interactions if ix.operation == "SOCKS Greeting"]
        assert len(greeting_ixs) >= 1

        for ix in greeting_ixs:
            method = ix.details.get("auth_method")
            assert method is not None, "Missing 'auth_method' in greeting interaction"
            # 2 = Username/Password
            assert method == "2", f"Expected auth_method=2, got {method}"
            assert ix.details.get("auth_method_name") == "Username/Password"

    def test_socks_auth_accepted_method_extracted(self):
        """T1 field: socks.auth_accepted_method is extracted for server method selection."""
        listener, devices, result = _run_listener_test(**_SOCKS_PARAMS)
        method_ixs = [ix for ix in listener.interactions if ix.operation == "SOCKS Method Select"]
        assert len(method_ixs) >= 1, "Expected at least one SOCKS Method Select interaction"

        for ix in method_ixs:
            accepted = ix.details.get("auth_accepted_method")
            assert accepted is not None, "Missing 'auth_accepted_method' in method select"
            assert accepted == "2", f"Expected auth_accepted_method=2, got {accepted}"
            assert ix.details.get("auth_accepted_method_name") == "Username/Password"

    def test_socks_auth_status_extracted(self):
        """T1 field: socks.auth_status is extracted for server auth response."""
        listener, devices, result = _run_listener_test(**_SOCKS_PARAMS)
        auth_resp_ixs = [
            ix for ix in listener.interactions if ix.operation == "SOCKS Auth Response"
        ]
        assert len(auth_resp_ixs) >= 1, "Expected at least one SOCKS Auth Response interaction"

        for ix in auth_resp_ixs:
            status = ix.details.get("auth_status")
            assert status is not None, "Missing 'auth_status' in auth response"
            assert status == "0", f"Expected auth_status=0 (success), got {status}"
            assert ix.details.get("auth_status_name") == "Success"
            assert ix.details.get("success") is True

    def test_socks_subnegotiation_version_extracted(self):
        """T1 field: socks.subnegotiation_version is extracted for auth packets."""
        listener, devices, result = _run_listener_test(**_SOCKS_PARAMS)
        # subneg version appears in auth request and auth response packets
        auth_ixs = [
            ix
            for ix in listener.interactions
            if ix.operation in ("SOCKS Auth Request", "SOCKS Auth Response")
        ]
        assert len(auth_ixs) >= 2, "Expected auth request + response interactions"

        for ix in auth_ixs:
            subneg = ix.details.get("subnegotiation_version")
            assert subneg is not None, f"Missing 'subnegotiation_version' in {ix.operation} details"
            assert subneg == "1", f"Expected subnegotiation_version=1, got {subneg}"

    def test_socks_interaction_types(self):
        """All four SOCKS interaction types are recorded in correct order."""
        listener, devices, result = _run_listener_test(**_SOCKS_PARAMS, min_interactions=4)

        operations = [ix.operation for ix in listener.interactions]
        expected_ops = [
            "SOCKS Greeting",
            "SOCKS Method Select",
            "SOCKS Auth Request",
            "SOCKS Auth Response",
        ]
        assert operations == expected_ops, f"Expected {expected_ops}, got {operations}"

    def test_socks_interaction_directions(self):
        """Verify request/response directions are correct for each packet type."""
        listener, devices, result = _run_listener_test(**_SOCKS_PARAMS, min_interactions=4)

        expected_dirs = {
            "SOCKS Greeting": "request",  # client -> server
            "SOCKS Method Select": "response",  # server -> client
            "SOCKS Auth Request": "request",  # client -> server
            "SOCKS Auth Response": "response",  # server -> client
        }
        for ix in listener.interactions:
            expected = expected_dirs.get(ix.operation)
            if expected:
                assert ix.direction == expected, (
                    f"{ix.operation}: expected direction={expected}, got {ix.direction}"
                )

    def test_socks_flow_ids_populated(self):
        """Every interaction has a non-empty flow_id for stream grouping."""
        listener, devices, result = _run_listener_test(**_SOCKS_PARAMS, min_interactions=4)

        for ix in listener.interactions:
            assert ix.flow_id, f"Empty flow_id on interaction: {ix.operation}"
            assert "<->" in ix.flow_id, f"Malformed flow_id: {ix.flow_id}"

    def test_socks_flow_ids_same_stream(self):
        """All interactions in the same TCP stream share a flow_id."""
        listener, devices, result = _run_listener_test(**_SOCKS_PARAMS, min_interactions=4)

        flow_ids = {ix.flow_id for ix in listener.interactions}
        assert len(flow_ids) == 1, f"Expected 1 flow_id (same stream), got {len(flow_ids)}"

    def test_socks_protocol_columns_set(self):
        """PROTOCOL_COLUMNS is set for operations table auto-generation."""
        from oida.pcap.socks import SOCKSPassiveListener

        assert SOCKSPassiveListener.PROTOCOL_COLUMNS
        assert len(SOCKSPassiveListener.PROTOCOL_COLUMNS) == 4
        assert "version" in SOCKSPassiveListener.PROTOCOL_COLUMNS

    def test_socks_format_protocol_columns_count(self):
        """_format_protocol_columns output must match PROTOCOL_COLUMNS length."""
        listener, devices, result = _run_listener_test(**_SOCKS_PARAMS, min_interactions=1)

        from oida.pcap.socks import SOCKSPassiveListener

        expected = len(SOCKSPassiveListener.PROTOCOL_COLUMNS)
        for ix in listener.interactions:
            row = listener._format_protocol_columns(ix)
            assert len(row) == expected, f"Row has {len(row)} columns, expected {expected}: {row}"

    def test_socks_credential_success_tracking(self):
        """Auth status is correlated back to the credential success field."""
        listener, devices, result = _run_listener_test(**_SOCKS_PARAMS)

        creds = listener.get_credentials_summary()
        assert len(creds) >= 1
        # The fixture has auth_status=0 (success)
        assert creds[0].get("success") is True

    def test_socks_both_devices_tracked(self):
        """Both server and client devices are created."""
        listener, devices, result = _run_listener_test(
            **_SOCKS_PARAMS,
            min_devices=2,
        )

        server_devices = {k: d for k, d in devices.items() if "server" in k}
        client_devices = {k: d for k, d in devices.items() if "client" in k}
        assert len(server_devices) >= 1, "No SOCKS server device"
        assert len(client_devices) >= 1, "No SOCKS client device"

    def test_socks_device_protocol_data(self):
        """Device protocol_data includes SOCKS-specific fields."""
        listener, devices, result = _run_listener_test(**_SOCKS_PARAMS, min_devices=2)

        for key, device in devices.items():
            data = getattr(device, "socks_passive_data", None)
            assert data is not None, f"Device {key} missing socks_passive_data"
            assert "role" in data
            assert "protocol" in data
            assert data["protocol"] == "SOCKS/TCP"

    def test_socks_device_version_enriched(self):
        """Device protocol_data includes socks_version from extracted field."""
        listener, devices, result = _run_listener_test(**_SOCKS_PARAMS, min_devices=2)

        found_version = False
        for key, device in devices.items():
            data = getattr(device, "socks_passive_data", None)
            if data and data.get("socks_version"):
                found_version = True
                assert data["socks_version"] == "5"
        assert found_version, "No device has socks_version in protocol_data"

    def test_socks_credential_deduplication(self):
        """Duplicate credentials are not added."""
        listener, devices, result = _run_listener_test(**_SOCKS_PARAMS)

        creds = listener.credentials
        # The fixture has exactly one auth attempt
        assert len(creds) == 1, f"Expected 1 credential (dedup), got {len(creds)}"

    def test_socks_format_protocol_columns_override(self):
        """_format_protocol_columns is properly overridden and returns correct columns."""
        from oida.pcap.socks import SOCKSPassiveListener, ProtocolInteraction

        listener = SOCKSPassiveListener(interface="lo", timeout=10)
        ix = ProtocolInteraction(
            timestamp="2026-01-01T00:00:00",
            src_ip="1.2.3.4",
            dst_ip="5.6.7.8",
            direction="request",
            operation="SOCKS Greeting",
            details={
                "version": "5",
                "auth_method_count": "1",
                "auth_method": "2",
                "auth_method_name": "Username/Password",
            },
            summary="test",
            flow_id="test-flow",
        )
        row = listener._format_protocol_columns(ix)
        assert len(row) == len(SOCKSPassiveListener.PROTOCOL_COLUMNS)
        assert row[0] == "5"  # Version
        assert row[1] == "SOCKS Greeting"  # Operation


class _FakeLayer:
    """Minimal stand-in for a pyshark layer (attribute access only)."""

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class _FakePacket:
    """Minimal stand-in for a pyshark packet with ip/tcp/socks layers."""

    def __init__(self, socks, src="10.0.0.1", dst="10.0.0.2", sport=40000, dport=1080):
        self.socks = socks
        self.ip = _FakeLayer(src=src, dst=dst)
        self.tcp = _FakeLayer(srcport=sport, dstport=dport, stream="0")


class TestSOCKSCommandNotDropped:
    """Regression: SOCKS command/connect packets must not be silently dropped.

    Command/connect packets carry none of the auth fields and previously
    fell through every branch with neither a recorded interaction nor a
    debug log.
    """

    def test_socks_connect_command_recorded(self):
        """A SOCKS CONNECT command packet yields a 'SOCKS Connect' interaction."""
        from oida.pcap.socks import SOCKSPassiveListener

        listener = SOCKSPassiveListener(interface="lo", timeout=10)
        # CONNECT (command=1) to 93.184.216.34:443 -- no auth fields present.
        packet = _FakePacket(
            _FakeLayer(version="5", command="1", dst="93.184.216.34", dstport="443")
        )
        listener.process_packet(packet)

        assert len(listener.interactions) == 1, "CONNECT packet was silently dropped"
        ix = listener.interactions[0]
        assert ix.operation == "SOCKS Connect"
        assert ix.direction == "request"
        assert ix.details.get("command_name") == "CONNECT"
        assert ix.details.get("dst") == "93.184.216.34"
        assert ix.details.get("dstport") == "443"
        # Table row renders without error and includes the target.
        row = listener._format_protocol_columns(ix)
        assert len(row) == len(SOCKSPassiveListener.PROTOCOL_COLUMNS)
        assert "93.184.216.34:443" in row[2]

    def test_socks_reply_result_recorded(self):
        """A SOCKS server reply packet yields a 'SOCKS Reply' interaction."""
        from oida.pcap.socks import SOCKSPassiveListener

        listener = SOCKSPassiveListener(interface="lo", timeout=10)
        packet = _FakePacket(_FakeLayer(version="5", results="0"))
        listener.process_packet(packet)

        assert len(listener.interactions) == 1, "Reply packet was silently dropped"
        ix = listener.interactions[0]
        assert ix.operation == "SOCKS Reply"
        assert ix.direction == "response"
        assert ix.details.get("results_name") == "Succeeded"

    def test_socks_unclassified_packet_recorded(self):
        """A SOCKS packet with no recognized fields is recorded as generic data."""
        from oida.pcap.socks import SOCKSPassiveListener

        listener = SOCKSPassiveListener(interface="lo", timeout=10)
        packet = _FakePacket(_FakeLayer(version="5"))
        listener.process_packet(packet)

        assert len(listener.interactions) == 1, "Unclassified packet was silently dropped"
        assert listener.interactions[0].operation == "SOCKS Data"

"""Integration tests for Java RMI passive listener.

Tests cover:
- RMI handshake parsing (magic, version, protocol type)
- Protocol type identification (Stream, SingleOp, Multiplex)
- Endpoint hostname/port extraction from server responses
- Call/Return message detection
- Device creation for both RMI client and server
- Harvest output quality
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]

# RMI requires decode_as to be recognized by tshark
RMI_DECODE_AS = {"tcp.port==1099": "rmi"}


# ---------------------------------------------------------------------------
# Fake-packet helpers for driving process_packet directly (no tshark needed)
# ---------------------------------------------------------------------------


class _FakeLayer:
    """Minimal stand-in for a pyshark layer: attribute access -> field value."""

    def __init__(self, **fields):
        self.__dict__.update(fields)


class _FakePacket:
    """Minimal packet exposing the layers the RMI listener accesses."""

    def __init__(self, rmi, src_ip, dst_ip, src_port, dst_port):
        self.rmi = rmi
        self.ip = _FakeLayer(src=src_ip, dst=dst_ip)
        self.tcp = _FakeLayer(srcport=str(src_port), dstport=str(dst_port))


class TestRMISilentDropRegression:
    """Regression: an rmi packet with no magic/input/output token must not be
    silently dropped (CODE_REVIEW.md rmi.py:142-186).

    A serialization-data continuation segment carries none of the fresh stream
    tokens. Previously it fell through every branch with no interaction and no
    debug log. It must now leave a trace.
    """

    def _listener(self):
        from oida.pcap.rmi import RMIPassiveListener

        return RMIPassiveListener(interface="lo", timeout=10)

    def test_data_segment_records_interaction(self):
        """A token-less RMI packet now records a generic 'RMI Data' interaction."""
        listener = self._listener()
        # rmi layer with NO magic / inputstream / outputstream tokens, but a
        # Java serialization marker (0xaced) -- the deserialization surface.
        rmi = _FakeLayer(ser_magic="0xaced", ser_version="5", serialization_data="aceddead")
        pkt = _FakePacket(rmi, "10.0.0.5", "10.0.0.9", src_port=55000, dst_port=1099)

        listener.process_packet(pkt)

        assert listener.interactions, "Token-less RMI packet was silently dropped"
        ops = {ix.operation for ix in listener.interactions}
        assert "RMI Data" in ops, f"Expected 'RMI Data' interaction; got {ops}"
        data_ix = next(ix for ix in listener.interactions if ix.operation == "RMI Data")
        assert data_ix.details.get("message_type") == "Data"
        assert data_ix.details.get("has_serialization") is True

    def test_data_segment_emits_debug_log(self):
        """The previously-silent path now emits an explanatory debug log.

        The listener uses the project's custom module logger (not the stdlib
        root logger caplog hooks into), so capture debug() calls directly.
        """
        listener = self._listener()
        debug_msgs = []
        listener.logger.debug = lambda msg, *a, **k: debug_msgs.append(str(msg))

        rmi = _FakeLayer(serialization_data="deadbeef")  # no tokens, no ser magic
        pkt = _FakePacket(rmi, "10.0.0.5", "10.0.0.9", src_port=55000, dst_port=1099)

        listener.process_packet(pkt)

        assert any("no magic/input/output token" in m for m in debug_msgs), (
            f"Expected a debug log explaining the token-less RMI skip; got {debug_msgs}"
        )
        # Even with no serialization marker, a trace is still recorded.
        assert listener.interactions, "Token-less RMI packet must still leave a trace"

    def test_serialization_without_output_token_flagged(self):
        """Serialized data arriving without a leading output token is still
        flagged into serialization_flows (the related blind spot)."""
        listener = self._listener()
        rmi = _FakeLayer(ser_magic="0xaced", ser_version="5")
        pkt = _FakePacket(rmi, "10.0.0.5", "10.0.0.9", src_port=55000, dst_port=1099)

        listener.process_packet(pkt)

        # Client (lower-port side -> registry 1099) -> server flow recorded.
        assert ("10.0.0.5", "10.0.0.9") in listener.serialization_flows, (
            f"Serialization flow not flagged; got {listener.serialization_flows}"
        )


class TestRMIPassive:
    """Java RMI protocol-specific tests."""

    def test_handshake_extraction(self):
        """RMI handshake packets extract version and protocol type."""
        listener, devices, result = _run_listener_test(
            "rmi",
            "RMIPassiveListener",
            "rmi",
            "rmi/generated_rmi.pcap",
            min_devices=2,
            min_interactions=2,
            expect_details=["message_type"],
            expect_operations=["RMI Handshake"],
            decode_as=RMI_DECODE_AS,
        )

        # Verify handshake interactions have version info
        handshakes = [
            ix for ix in listener.interactions if ix.details.get("message_type") == "Handshake"
        ]
        assert len(handshakes) >= 1, "No handshake interactions found"

    def test_protocol_type_detection(self):
        """RMI protocol types (Stream, SingleOp, Multiplex) are detected."""
        listener, devices, result = _run_listener_test(
            "rmi",
            "RMIPassiveListener",
            "rmi",
            "rmi/generated_rmi.pcap",
            decode_as=RMI_DECODE_AS,
        )

        protocol_names = {
            ix.details.get("protocol_name")
            for ix in listener.interactions
            if ix.details.get("protocol_name")
        }
        # Our pcap has SingleOp and Stream protocols
        assert len(protocol_names) >= 1, f"No protocol types detected; got: {protocol_names}"

    def test_endpoint_extraction(self):
        """Endpoint hostname and port are extracted from server responses."""
        listener, devices, result = _run_listener_test(
            "rmi",
            "RMIPassiveListener",
            "rmi",
            "rmi/generated_rmi.pcap",
            decode_as=RMI_DECODE_AS,
        )

        endpoints = {
            ix.details.get("endpoint_host")
            for ix in listener.interactions
            if ix.details.get("endpoint_host")
        }
        assert "rmi-server.internal" in endpoints, (
            f"Expected rmi-server.internal endpoint; got: {endpoints}"
        )

    def test_protocol_ack_detected(self):
        """ProtocolAck messages from server are detected."""
        listener, devices, result = _run_listener_test(
            "rmi",
            "RMIPassiveListener",
            "rmi",
            "rmi/generated_rmi.pcap",
            decode_as=RMI_DECODE_AS,
        )

        ack_found = any(
            ix.details.get("message_type") == "ProtocolAck" for ix in listener.interactions
        )
        assert ack_found, "No ProtocolAck message found"

    def test_call_message_detected(self):
        """RMI Call messages from client are detected."""
        listener, devices, result = _run_listener_test(
            "rmi",
            "RMIPassiveListener",
            "rmi",
            "rmi/generated_rmi.pcap",
            decode_as=RMI_DECODE_AS,
        )

        call_found = any(ix.details.get("message_type") == "Call" for ix in listener.interactions)
        assert call_found, (
            "No RMI Call message found; message types: "
            f"{[ix.details.get('message_type') for ix in listener.interactions]}"
        )

    def test_both_endpoints_tracked(self):
        """Both RMI client and server devices are discovered."""
        listener, devices, result = _run_listener_test(
            "rmi",
            "RMIPassiveListener",
            "rmi",
            "rmi/generated_rmi.pcap",
            min_devices=2,
            decode_as=RMI_DECODE_AS,
        )

        device_types = [d.device_type for d in devices.values() if hasattr(d, "device_type")]
        has_server = any("Server" in t for t in device_types)
        has_client = any("Client" in t for t in device_types)
        assert has_server, f"No RMI Server device; types: {device_types}"
        assert has_client, f"No RMI Client device; types: {device_types}"

    def test_server_endpoints_tracked(self):
        """Server's discovered endpoints are stored on the device."""
        listener, devices, result = _run_listener_test(
            "rmi",
            "RMIPassiveListener",
            "rmi",
            "rmi/generated_rmi.pcap",
            min_devices=2,
            decode_as=RMI_DECODE_AS,
        )

        # The server device should have endpoint data
        server_devs = [
            d
            for d in devices.values()
            if hasattr(d, "rmi_passive_data")
            and d.rmi_passive_data
            and d.rmi_passive_data.get("role") == "server"
        ]
        assert len(server_devs) >= 1, "No RMI server device with passive data"
        eps = server_devs[0].rmi_passive_data.get("endpoints", [])
        assert len(eps) >= 1, (
            f"No endpoints stored on server device; data: {server_devs[0].rmi_passive_data}"
        )

    def test_harvest_returns_valid_dict(self):
        """Harvest returns a valid dict."""
        listener, devices, result = _run_listener_test(
            "rmi",
            "RMIPassiveListener",
            "rmi",
            "rmi/generated_rmi.pcap",
            decode_as=RMI_DECODE_AS,
        )
        assert isinstance(result, dict)

    def test_protocol_columns_format(self):
        """Protocol columns are formatted correctly."""
        listener, devices, result = _run_listener_test(
            "rmi",
            "RMIPassiveListener",
            "rmi",
            "rmi/generated_rmi.pcap",
            decode_as=RMI_DECODE_AS,
        )

        for ix in listener.interactions:
            cols = listener._format_protocol_columns(ix)
            assert len(cols) == len(listener.PROTOCOL_COLUMNS), (
                f"Column count mismatch: {len(cols)} vs {len(listener.PROTOCOL_COLUMNS)}"
            )

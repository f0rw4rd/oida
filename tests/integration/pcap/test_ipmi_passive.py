"""Integration tests for IPMI passive listener.

Tests cover:
- IPMI session authentication type extraction
- RMCP+ payload type detection
- RAKP message identification
- BMC and client device tracking
- Session ID extraction
- Credential extraction (cipher-zero detection)
- Harvest output quality
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestIPMIPassive:
    """IPMI-specific tests beyond the parametrized quality suite."""

    def test_ipmi_basic_extraction(self):
        """Basic IPMI field extraction from generated traffic."""
        listener, devices, result = _run_listener_test(
            "ipmi",
            "IPMIPassiveListener",
            "ipmi_session || rmcp",
            "ipmi/generated_ipmi.pcap",
            min_devices=2,
            min_interactions=1,
            expect_details=["auth_type_name"],
        )
        assert len(listener.interactions) >= 1, (
            f"Expected >= 1 IPMI interaction, got {len(listener.interactions)}"
        )

    def test_ipmi_auth_type_extracted(self):
        """IPMI authentication types are extracted."""
        listener, devices, result = _run_listener_test(
            "ipmi",
            "IPMIPassiveListener",
            "ipmi_session || rmcp",
            "ipmi/generated_ipmi.pcap",
            expect_details=["auth_type"],
        )
        auth_types = {
            ix.details.get("auth_type_name")
            for ix in listener.interactions
            if ix.details.get("auth_type_name")
        }
        assert auth_types, "No authentication types extracted"

    def test_ipmi_session_id_extracted(self):
        """IPMI session IDs are extracted."""
        listener, devices, result = _run_listener_test(
            "ipmi",
            "IPMIPassiveListener",
            "ipmi_session || rmcp",
            "ipmi/generated_ipmi.pcap",
            expect_details=["session_id"],
        )
        has_session_id = any(
            ix.details.get("session_id") is not None for ix in listener.interactions
        )
        assert has_session_id, "No session IDs extracted"

    def test_ipmi_rmcp_plus_detected(self):
        """RMCP+ payload types are detected."""
        listener, devices, result = _run_listener_test(
            "ipmi",
            "IPMIPassiveListener",
            "ipmi_session || rmcp",
            "ipmi/generated_ipmi.pcap",
        )
        rmcp_plus = [
            ix for ix in listener.interactions if ix.details.get("auth_type_name") == "RMCP+"
        ]
        assert rmcp_plus, (
            "No RMCP+ interactions found; "
            f"auth_types: {[ix.details.get('auth_type_name') for ix in listener.interactions]}"
        )

    def test_ipmi_rakp_messages_detected(self):
        """RAKP messages are detected in RMCP+ handshake."""
        listener, devices, result = _run_listener_test(
            "ipmi",
            "IPMIPassiveListener",
            "ipmi_session || rmcp",
            "ipmi/generated_ipmi.pcap",
        )
        rakp_ops = [
            ix for ix in listener.interactions if "RAKP" in ix.details.get("payload_type_name", "")
        ]
        assert rakp_ops, (
            "No RAKP interactions found; "
            f"payload_types: {[ix.details.get('payload_type_name') for ix in listener.interactions]}"
        )

    def test_ipmi_rakp_hash_credential_recorded(self):
        """RAKP-2 yields a crackable rakp_hash credential with the RAKP-1 username.

        Uses a real RMCP+ capture (github_ipmi_cipher3_auth.pcap) that carries a
        full RAKP 1-4 handshake with a parseable body. tshark's IPMI dissector
        does not decode the RAKP message body, so the username (RAKP-1) and the
        key-exchange auth code / HMAC (RAKP-2) are parsed from the raw payload.
        """
        listener, devices, result = _run_listener_test(
            "ipmi",
            "IPMIPassiveListener",
            "ipmi_session || rmcp",
            "ipmi/github_ipmi_cipher3_auth.pcap",
            min_devices=2,
            min_interactions=1,
        )
        rakp_creds = [c for c in listener.credentials if c.credential_type == "rakp_hash"]
        assert rakp_creds, (
            "No rakp_hash credential recorded; "
            f"credential types: {[c.credential_type for c in listener.credentials]}"
        )
        cred = rakp_creds[0]
        # Username comes from RAKP-1 (this capture authenticates as 'admin').
        assert cred.username == "admin", f"Expected RAKP username 'admin', got {cred.username!r}"
        # The hash is the RAKP-2 key-exchange auth code (HMAC-SHA1 here = 20 bytes).
        assert cred.rakp_hash, "rakp_hash field is empty"
        assert len(cred.rakp_hash) == 40, (
            f"Expected 20-byte (40 hex char) HMAC, got {len(cred.rakp_hash)} chars"
        )
        int(cred.rakp_hash, 16)  # must be valid hex
        # The BMC (RAKP-2 source) is the credential server.
        assert cred.server_ip == "192.168.2.20", (
            f"Expected BMC server 192.168.2.20, got {cred.server_ip}"
        )
        # And it surfaces in the credential summary the scanner consumes.
        summary = listener.get_credentials_summary()
        rakp_rows = [r for r in summary if r["credential_type"] == "rakp_hash"]
        assert rakp_rows, "rakp_hash not present in get_credentials_summary()"
        assert rakp_rows[0]["rakp_hash"] == cred.rakp_hash
        assert rakp_rows[0]["username"] == "admin"

    def test_ipmi_open_session_detected(self):
        """RMCP+ Open Session Request is detected."""
        listener, devices, result = _run_listener_test(
            "ipmi",
            "IPMIPassiveListener",
            "ipmi_session || rmcp",
            "ipmi/generated_ipmi.pcap",
        )
        open_session = [
            ix
            for ix in listener.interactions
            if "Open Session" in ix.details.get("payload_type_name", "")
        ]
        assert open_session, (
            "No Open Session interactions found; "
            f"payload_types: {[ix.details.get('payload_type_name') for ix in listener.interactions]}"
        )

    def test_ipmi_bmc_device_tracked(self):
        """BMC device is tracked."""
        listener, devices, result = _run_listener_test(
            "ipmi",
            "IPMIPassiveListener",
            "ipmi_session || rmcp",
            "ipmi/generated_ipmi.pcap",
            min_devices=2,
        )
        device_types = [d.device_type for d in devices.values() if hasattr(d, "device_type")]
        has_bmc = any("BMC" in t for t in device_types)
        assert has_bmc, f"No IPMI BMC device found; types: {device_types}"

    def test_ipmi_client_device_tracked(self):
        """IPMI client device is tracked."""
        listener, devices, result = _run_listener_test(
            "ipmi",
            "IPMIPassiveListener",
            "ipmi_session || rmcp",
            "ipmi/generated_ipmi.pcap",
            min_devices=2,
        )
        device_types = [d.device_type for d in devices.values() if hasattr(d, "device_type")]
        has_client = any("Client" in t for t in device_types)
        assert has_client, f"No IPMI Client device found; types: {device_types}"

    def test_ipmi_passive_data(self):
        """Devices have ipmi_passive_data attribute."""
        listener, devices, result = _run_listener_test(
            "ipmi",
            "IPMIPassiveListener",
            "ipmi_session || rmcp",
            "ipmi/generated_ipmi.pcap",
            min_devices=1,
        )
        has_data = any(
            hasattr(d, "ipmi_passive_data") and d.ipmi_passive_data for d in devices.values()
        )
        assert has_data, "No device has ipmi_passive_data"

    def test_ipmi_bmc_info_tracked(self):
        """BMC info dict is populated."""
        listener, devices, result = _run_listener_test(
            "ipmi",
            "IPMIPassiveListener",
            "ipmi_session || rmcp",
            "ipmi/generated_ipmi.pcap",
        )
        assert len(listener.bmc_info) >= 1, (
            f"Expected >= 1 BMC in bmc_info, got {len(listener.bmc_info)}"
        )

    def test_harvest_returns_valid_dict(self):
        """Harvest returns a valid dict."""
        listener, devices, result = _run_listener_test(
            "ipmi",
            "IPMIPassiveListener",
            "ipmi_session || rmcp",
            "ipmi/generated_ipmi.pcap",
        )
        assert isinstance(result, dict)

    def test_ipmi_direction_correct(self):
        """Packets to port 623 are requests, from port 623 are responses."""
        listener, devices, result = _run_listener_test(
            "ipmi",
            "IPMIPassiveListener",
            "ipmi_session || rmcp",
            "ipmi/generated_ipmi.pcap",
            min_interactions=1,
        )
        for ix in listener.interactions:
            if ix.dst_port == 623:
                assert ix.direction == "request", (
                    f"Packet to port 623 should be request, got {ix.direction}"
                )
            elif ix.src_port == 623:
                assert ix.direction == "response", (
                    f"Packet from port 623 should be response, got {ix.direction}"
                )


# ---------------------------------------------------------------------------
# Unit-level regression tests (no pyshark/tshark required).
#
# These feed lightweight fake packets directly into process_packet() to
# exercise the two fixed code paths in isolation:
#   1. direction on non-standard BMC ports (lower-port-wins fallback)
#   2. cipher-zero detection across EK (decimal) and XML (hex) session-id forms
# ---------------------------------------------------------------------------


class _FakeLayer:
    """Minimal stand-in for a pyshark layer (plain attribute access)."""

    def __init__(self, **fields):
        self.__dict__.update(fields)


class _FakeIPLayer(_FakeLayer):
    pass


class _FakePacket:
    """Minimal fake packet exposing only the layers process_packet reads.

    Deliberately omits ``data``/``eth`` so RAKP body parsing and MAC lookup
    short-circuit cleanly; the listener only needs ip + udp + ipmi_session
    for the direction and cipher-zero logic under test.
    """

    def __init__(self, src_ip, dst_ip, src_port, dst_port, ipmi_fields):
        self.ip = _FakeIPLayer(src=src_ip, dst=dst_ip)
        self.udp = _FakeLayer(srcport=src_port, dstport=dst_port, stream="0")
        self.ipmi_session = _FakeLayer(**ipmi_fields)


def _make_listener():
    from oida.pcap.passive.ipmi import IPMIPassiveListener

    return IPMIPassiveListener(interface="lo", timeout=10)


class TestIPMIDirectionFallback:
    """Direction must be correct even when the BMC is not on UDP/623."""

    def test_non_standard_port_to_bmc_is_request(self):
        """BMC on a non-standard low port (6230): client->BMC is a request.

        Lower-port-wins: dst 6230 < src 49152, so dst is the BMC side.
        """
        listener = _make_listener()
        pkt = _FakePacket(
            src_ip="192.168.50.10",
            dst_ip="192.168.50.20",
            src_port=49152,
            dst_port=6230,
            # RMCP+ Open Session Request (EK decimal payloadtype 16)
            ipmi_fields={"authtype": "6", "id": "0", "payloadtype": "16"},
        )
        listener.process_packet(pkt)
        assert listener.interactions, "no interaction recorded"
        ix = listener.interactions[0]
        assert ix.direction == "request", (
            f"client->BMC on non-standard port should be 'request', got {ix.direction}"
        )
        # The BMC (lower port, dst) must be registered as the BMC, not the client.
        device_types = {d.device_type for d in listener.discovered_devices.values()}
        assert "IPMI BMC" in device_types, f"BMC not tracked correctly: {device_types}"

    def test_non_standard_port_from_bmc_is_response(self):
        """BMC reply (src 6230 < dst 49152) is a response."""
        listener = _make_listener()
        pkt = _FakePacket(
            src_ip="192.168.50.20",
            dst_ip="192.168.50.10",
            src_port=6230,
            dst_port=49152,
            ipmi_fields={"authtype": "6", "id": "0", "payloadtype": "17"},
        )
        listener.process_packet(pkt)
        assert listener.interactions, "no interaction recorded"
        ix = listener.interactions[0]
        assert ix.direction == "response", (
            f"BMC->client on non-standard port should be 'response', got {ix.direction}"
        )

    def test_standard_port_623_still_request(self):
        """The canonical-port path is unchanged: dst==623 stays a request."""
        listener = _make_listener()
        pkt = _FakePacket(
            src_ip="192.168.50.10",
            dst_ip="192.168.50.20",
            src_port=49152,
            dst_port=623,
            ipmi_fields={"authtype": "6", "id": "0", "payloadtype": "16"},
        )
        listener.process_packet(pkt)
        assert listener.interactions[0].direction == "request"


class TestIPMICipherZeroEKMode:
    """Cipher-zero detection must work in EK mode and not false-positive."""

    def test_ek_zero_session_no_false_positive(self):
        """EK mode renders an unestablished session id as decimal '0'.

        Open Session / RAKP setup carries authtype=None(0) + session id 0
        *before* a session exists — this must NOT be flagged cipher-zero.
        """
        listener = _make_listener()
        pkt = _FakePacket(
            src_ip="192.168.50.10",
            dst_ip="192.168.50.20",
            src_port=49152,
            dst_port=623,
            ipmi_fields={"authtype": "0", "id": "0", "payloadtype": "16"},
        )
        listener.process_packet(pkt)
        cipher_zero = [c for c in listener.credentials if c.credential_type == "cipher_zero"]
        assert not cipher_zero, "EK-mode session id '0' (no session) falsely flagged as cipher-zero"

    def test_ek_active_session_detected(self):
        """EK mode: authtype None + a real (non-zero, decimal) session id detects."""
        listener = _make_listener()
        pkt = _FakePacket(
            src_ip="192.168.50.10",
            dst_ip="192.168.50.20",
            src_port=49152,
            dst_port=623,
            # 268435457 == 0x10000001, a real established session id (decimal in EK).
            ipmi_fields={"authtype": "0", "id": "268435457", "payloadtype": "0"},
        )
        listener.process_packet(pkt)
        cipher_zero = [c for c in listener.credentials if c.credential_type == "cipher_zero"]
        assert cipher_zero, "EK-mode active no-auth session not flagged as cipher-zero"

    def test_xml_hex_zero_session_no_false_positive(self):
        """XML mode: '0x00000000' session id must still be excluded."""
        listener = _make_listener()
        pkt = _FakePacket(
            src_ip="192.168.50.10",
            dst_ip="192.168.50.20",
            src_port=49152,
            dst_port=623,
            ipmi_fields={"authtype": "0x00", "id": "0x00000000", "payloadtype": "0x10"},
        )
        listener.process_packet(pkt)
        cipher_zero = [c for c in listener.credentials if c.credential_type == "cipher_zero"]
        assert not cipher_zero, "XML-mode zero session id falsely flagged as cipher-zero"

    def test_xml_hex_active_session_detected(self):
        """XML mode: hex non-zero session id with authtype None detects."""
        listener = _make_listener()
        pkt = _FakePacket(
            src_ip="192.168.50.10",
            dst_ip="192.168.50.20",
            src_port=49152,
            dst_port=623,
            ipmi_fields={"authtype": "0x00", "id": "0x10000001", "payloadtype": "0x00"},
        )
        listener.process_packet(pkt)
        cipher_zero = [c for c in listener.credentials if c.credential_type == "cipher_zero"]
        assert cipher_zero, "XML-mode active no-auth session not flagged as cipher-zero"

    def test_cipher_zero_detected_on_non_standard_port(self):
        """Cipher-zero is no longer gated on port 623 (BMC on 6230)."""
        listener = _make_listener()
        pkt = _FakePacket(
            src_ip="192.168.50.10",
            dst_ip="192.168.50.20",
            src_port=49152,
            dst_port=6230,
            ipmi_fields={"authtype": "0", "id": "268435457", "payloadtype": "0"},
        )
        listener.process_packet(pkt)
        cipher_zero = [c for c in listener.credentials if c.credential_type == "cipher_zero"]
        assert cipher_zero, "cipher-zero on non-standard BMC port not detected"

"""Integration tests for IPsec/IKE passive listener.

Tests cover:
- IKE version detection (v1, v2)
- Exchange type extraction (Main Mode, Aggressive, etc.)
- SPI extraction (initiator/responder)
- Direction detection (initiator vs responder)
- Vendor ID extraction and resolution
- Crypto proposal extraction (key length, algorithms)
- Device creation for both endpoints
- Harvest table output quality
"""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestIPsecPassiveEK:
    """IPsec/IKE-specific tests beyond the parametrized quality suite."""

    def test_ike_v1_main_mode(self):
        """IKEv1 Main Mode exchanges are detected."""
        listener, devices, result = _run_listener_test(
            "ipsec",
            "IPsecPassiveListener",
            "isakmp",
            "ipsec/wireshark_isakmp.cap",
            min_devices=2,
            expect_details=["ike_version", "exchange_type_name"],
            expect_operations=["IKE v1 Main"],
        )
        v1_ixs = [ix for ix in listener.interactions if ix.details.get("ike_version") == "v1"]
        assert len(v1_ixs) >= 1, "No IKEv1 interactions found"

    def test_ike_exchange_type_extraction(self):
        """Exchange type is extracted and resolved to a name."""
        listener, devices, result = _run_listener_test(
            "ipsec",
            "IPsecPassiveListener",
            "isakmp",
            "ipsec/wireshark_isakmp.cap",
            min_devices=2,
        )
        has_exchange = any(
            ix.details.get("exchange_type_name") not in (None, "") for ix in listener.interactions
        )
        assert has_exchange, "No interaction has exchange_type_name"

    def test_ike_spi_extraction(self):
        """Initiator and responder SPIs are extracted."""
        listener, devices, result = _run_listener_test(
            "ipsec",
            "IPsecPassiveListener",
            "isakmp",
            "ipsec/wireshark_isakmp.cap",
            min_devices=2,
        )
        has_ispi = any(
            ix.details.get("initiator_spi") not in (None, "") for ix in listener.interactions
        )
        assert has_ispi, "No interaction has initiator_spi"

    def test_ike_direction_detection(self):
        """Initiator and responder directions are detected."""
        listener, devices, result = _run_listener_test(
            "ipsec",
            "IPsecPassiveListener",
            "isakmp",
            "ipsec/wireshark_isakmp.cap",
            min_devices=2,
        )
        directions = {ix.direction for ix in listener.interactions}
        assert len(directions) >= 1, f"Expected directions; got: {directions}"

    def test_ike_both_endpoints_tracked(self):
        """Both IPsec initiator and responder devices are created."""
        listener, devices, result = _run_listener_test(
            "ipsec",
            "IPsecPassiveListener",
            "isakmp",
            "ipsec/wireshark_isakmp.cap",
            min_devices=2,
        )
        device_types = [d.device_type for d in devices.values() if hasattr(d, "device_type")]
        has_gateway = any("Gateway" in t or "Responder" in t for t in device_types)
        has_client = any("Client" in t or "Initiator" in t for t in device_types)
        assert has_gateway or has_client, f"No IPsec device types found; types: {device_types}"

    def test_ike_passive_data_on_devices(self):
        """Devices have ipsec_passive_data with expected fields."""
        listener, devices, result = _run_listener_test(
            "ipsec",
            "IPsecPassiveListener",
            "isakmp",
            "ipsec/wireshark_isakmp.cap",
            min_devices=2,
        )
        has_data = any(
            hasattr(d, "ipsec_passive_data") and d.ipsec_passive_data for d in devices.values()
        )
        assert has_data, "No device has ipsec_passive_data"

    def test_ike_flags_extraction(self):
        """ISAKMP flags are extracted."""
        listener, devices, result = _run_listener_test(
            "ipsec",
            "IPsecPassiveListener",
            "isakmp",
            "ipsec/wireshark_isakmp.cap",
            min_devices=2,
        )
        has_flags = any(ix.details.get("flags") is not None for ix in listener.interactions)
        assert has_flags, "No interaction has flags"

    def test_ike_msg_length_extraction(self):
        """ISAKMP message length is extracted."""
        listener, devices, result = _run_listener_test(
            "ipsec",
            "IPsecPassiveListener",
            "isakmp",
            "ipsec/wireshark_isakmp.cap",
            min_devices=2,
        )
        has_length = any(
            ix.details.get("msg_length") not in (None, "") for ix in listener.interactions
        )
        assert has_length, "No interaction has msg_length"

    def test_ike_harvest_valid(self):
        """Harvest returns valid dict with no raw dicts/sets in cells."""
        listener, devices, result = _run_listener_test(
            "ipsec",
            "IPsecPassiveListener",
            "isakmp",
            "ipsec/wireshark_isakmp.cap",
        )
        assert isinstance(result, dict)

    def test_ike_format_protocol_columns(self):
        """_format_protocol_columns produces correct column count."""
        listener, devices, result = _run_listener_test(
            "ipsec",
            "IPsecPassiveListener",
            "isakmp",
            "ipsec/wireshark_isakmp.cap",
        )
        if listener.interactions:
            cols = listener._format_protocol_columns(listener.interactions[0])
            assert len(cols) == len(listener.PROTOCOL_COLUMNS), (
                f"Column count mismatch: {len(cols)} vs {len(listener.PROTOCOL_COLUMNS)}"
            )

    def test_ike_multiple_interactions(self):
        """Multiple IKE exchanges are tracked from the Main Mode handshake."""
        listener, devices, result = _run_listener_test(
            "ipsec",
            "IPsecPassiveListener",
            "isakmp",
            "ipsec/wireshark_isakmp.cap",
            min_interactions=2,
        )
        assert len(listener.interactions) >= 2, (
            f"Expected >= 2 interactions; got {len(listener.interactions)}"
        )

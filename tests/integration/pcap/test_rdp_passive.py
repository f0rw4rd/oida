"""Integration tests for RDP passive listener in EK mode."""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestRDPPassiveEK:
    """RDP-specific tests beyond the parametrised quality suite."""

    def test_rdp_basic(self):
        listener, devices, result = _run_listener_test(
            "rdp",
            "RDPPassiveListener",
            "rdp",
            "rdp/generated_rdp.pcap",
            min_devices=0,
            min_interactions=0,
        )
        # RDP listener should extract credentials when present
        if listener.credentials:
            creds = listener.get_credentials_summary()
            assert len(creds) >= 1, "Expected at least one credential summary entry"
            for c in creds:
                assert c.get("protocol") == "RDP"
                assert "username" in c

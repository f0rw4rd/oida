"""Integration tests for POP3 passive listener in EK mode."""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestPOP3PassiveEK:
    """POP3-specific tests beyond the parametrized quality suite."""

    def test_pop3_credentials_extracted(self):
        listener, devices, result = _run_listener_test(
            "pop3",
            "POP3PassiveListener",
            "pop",
            "pop3/bruteshark_pop3.pcap",
        )

        # POP3 credential extraction
        creds = listener.get_credentials_summary()
        assert len(creds) >= 1, f"Expected at least 1 credential, got {len(creds)}"
        for cred in creds:
            assert cred["protocol"] == "POP3"
            assert cred["username"], "Credential missing username"
            assert "password" in cred, "Credential missing password key"

        # Session tracking
        assert len(listener._sessions) >= 1, "No POP3 sessions tracked"

        # POP3 has no custom harvest tables (interaction/credential tables
        # are now built centrally by the scanner)

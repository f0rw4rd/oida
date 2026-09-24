"""Integration tests for IMAP passive listener in EK mode."""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestIMAPPassiveEK:
    """IMAP-specific tests beyond the parametrized quality suite."""

    def test_imap_credentials_extracted(self):
        listener, devices, result = _run_listener_test(
            "imap",
            "IMAPPassiveListener",
            "imap",
            "imap/bruteshark_imap_login1.pcap",
        )

        # IMAP credential extraction
        creds = listener.get_credentials_summary()
        assert len(creds) >= 1, f"Expected at least 1 credential, got {len(creds)}"
        for cred in creds:
            assert cred["protocol"] == "IMAP"
            assert cred["username"], "Credential missing username"
            assert cred["auth_method"], "Credential missing auth_method"

        # Session tracking
        assert len(listener._sessions) >= 1, "No IMAP sessions tracked"

        # IMAP has no custom harvest tables (interaction/credential tables
        # are now built centrally by the scanner)

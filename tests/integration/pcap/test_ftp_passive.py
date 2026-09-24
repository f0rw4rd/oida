"""Integration tests for FTP passive listener in EK mode."""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestFTPPassiveEK:
    """FTP-specific tests beyond the parametrized quality suite."""

    def test_ftp_credentials_extracted(self):
        listener, devices, result = _run_listener_test(
            "ftp",
            "FTPPassiveListener",
            "ftp",
            "ftp/bruteshark_ftp.pcap",
            expect_details=["command"],
        )

        # FTP credential extraction
        creds = listener.get_credentials_summary()
        assert len(creds) >= 1, f"Expected at least 1 credential, got {len(creds)}"
        for cred in creds:
            assert cred["protocol"] == "FTP"
            assert cred["username"], "Credential missing username"
            assert "password" in cred, "Credential missing password key"

        # Session tracking
        assert len(listener._sessions) >= 1, "No FTP sessions tracked"

"""Integration tests for IRC passive listener in EK mode."""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestIRCPassiveEK:
    """IRC-specific tests beyond the parametrized quality suite."""

    def test_irc_credentials_extracted(self):
        listener, devices, result = _run_listener_test(
            "irc",
            "IRCPassiveListener",
            "irc",
            "irc/generated_irc.pcap",
        )

        # IRC credential extraction (nick/user/pass commands)
        creds = listener.get_credentials_summary()
        assert len(creds) >= 1, f"Expected at least 1 credential, got {len(creds)}"
        for cred in creds:
            assert cred["protocol"] == "IRC"
            assert cred["username"], "Credential missing username"

        # Session tracking
        assert len(listener._sessions) >= 1, "No IRC sessions tracked"

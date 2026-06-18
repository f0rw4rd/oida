"""Integration tests for NTLM passive listener in EK mode."""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestNTLMPassiveEK:
    """NTLM-specific tests beyond the parametrized quality suite."""

    def test_ntlm_hashes_extracted(self):
        listener, devices, result = _run_listener_test(
            "ntlm",
            "NTLMPassiveListener",
            "ntlmssp",
            "smb/bruteshark_ntlm_smb.pcap",
            expect_details=["msg_type"],
        )

        # NTLM hash extraction
        hashes = listener.get_hashes_summary()
        assert len(hashes) >= 1, f"Expected at least 1 hash, got {len(hashes)}"
        for h in hashes:
            assert h["protocol"] == "NTLMSSP"
            assert h["username"], "Hash missing username"
            assert h["domain"], "Hash missing domain"

        # Session tracking (Type 2 challenges stored)
        assert len(listener._sessions) >= 1, "No NTLM sessions tracked"

        # Hashcat export
        hashcat_lines = listener.get_hashcat_hashes()
        assert len(hashcat_lines) >= 1, "No hashcat-format hashes produced"

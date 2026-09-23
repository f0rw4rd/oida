"""Integration tests for SMTP passive listener in EK mode."""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestSMTPPassiveEK:
    """SMTP-specific tests beyond the parametrized quality suite."""

    def test_smtp_credentials_extracted(self):
        listener, devices, result = _run_listener_test(
            "smtp",
            "SMTPPassiveListener",
            "smtp",
            "smtp/bruteshark_smtp_auth_login.pcap",
        )

        # SMTP credential extraction
        creds = listener.get_credentials_summary()
        assert len(creds) >= 1, f"Expected at least 1 credential, got {len(creds)}"
        for cred in creds:
            assert cred["protocol"] == "SMTP"
            assert cred["username"], "Credential missing username"
            assert cred["auth_method"], "Credential missing auth_method"

        # Session tracking
        assert len(listener._sessions) >= 1, "No SMTP sessions tracked"

        # SMTP has no custom harvest tables (interaction/credential tables
        # are now built centrally by the scanner)


class TestSMTPCommandLine:
    """T1: smtp.command_line -- full raw command string."""

    def test_command_line_in_auth_login(self):
        """command_line extracted for every client command in AUTH LOGIN pcap."""
        listener, devices, result = _run_listener_test(
            "smtp",
            "SMTPPassiveListener",
            "smtp",
            "smtp/bruteshark_smtp_auth_login.pcap",
        )

        # At least one request interaction must have command_line
        request_ixs = [ix for ix in listener.interactions if ix.direction == "request"]
        assert len(request_ixs) >= 1, "No request interactions recorded"

        has_command_line = [ix for ix in request_ixs if ix.details.get("command_line")]
        assert len(has_command_line) >= 1, (
            "No request interaction has command_line detail; "
            f"sample details: {request_ixs[0].details}"
        )

        # Verify specific commands appear in command_line
        command_lines = [ix.details["command_line"] for ix in has_command_line]
        assert any("EHLO" in cl for cl in command_lines), (
            f"EHLO not found in any command_line; got: {command_lines[:5]}"
        )
        assert any("AUTH" in cl for cl in command_lines), (
            f"AUTH not found in any command_line; got: {command_lines[:5]}"
        )

    def test_command_line_in_auth_plain(self):
        """command_line extracted for AUTH PLAIN pcap."""
        listener, devices, result = _run_listener_test(
            "smtp",
            "SMTPPassiveListener",
            "smtp",
            "smtp/bruteshark_smtp_auth_plain.pcap",
            min_devices=0,  # loopback IPs fail is_valid_discovered_ip
        )

        request_ixs = [ix for ix in listener.interactions if ix.direction == "request"]
        has_command_line = [ix for ix in request_ixs if ix.details.get("command_line")]
        assert len(has_command_line) >= 1, "No command_line in AUTH PLAIN pcap"

        # AUTH PLAIN command line should include the Base64 blob
        auth_lines = [
            ix.details["command_line"]
            for ix in has_command_line
            if "AUTH" in ix.details["command_line"]
        ]
        assert len(auth_lines) >= 1, "AUTH command not found in command_line"
        assert any("PLAIN" in cl for cl in auth_lines), (
            f"PLAIN not in AUTH command_line; got: {auth_lines}"
        )

    def test_command_line_preserves_mail_from(self):
        """command_line for MAIL FROM preserves the full email address."""
        listener, devices, result = _run_listener_test(
            "smtp",
            "SMTPPassiveListener",
            "smtp",
            "smtp/bruteshark_smtp_auth_login.pcap",
        )

        mail_ixs = [
            ix
            for ix in listener.interactions
            if ix.details.get("command") == "MAIL" and ix.details.get("command_line")
        ]
        assert len(mail_ixs) >= 1, "No MAIL command with command_line"
        assert any("FROM" in ix.details["command_line"] for ix in mail_ixs), (
            f"MAIL FROM not in command_line; got: {[ix.details['command_line'] for ix in mail_ixs]}"
        )

    def test_command_line_in_cram_md5(self):
        """command_line extracted in CRAM-MD5 pcap."""
        listener, devices, result = _run_listener_test(
            "smtp",
            "SMTPPassiveListener",
            "smtp",
            "smtp/bruteshark_smtp_cram_md5.pcap",
            min_devices=0,  # loopback IPs fail is_valid_discovered_ip
        )

        request_ixs = [ix for ix in listener.interactions if ix.direction == "request"]
        has_command_line = [ix for ix in request_ixs if ix.details.get("command_line")]
        assert len(has_command_line) >= 1, "No command_line in CRAM-MD5 pcap"


class TestSMTPAuthUsernamePassword:
    """T1: smtp.auth.username_password -- tshark-decoded AUTH PLAIN blob."""

    def test_auth_plain_via_tshark_field(self):
        """AUTH PLAIN credentials extracted via auth.username_password field."""
        listener, devices, result = _run_listener_test(
            "smtp",
            "SMTPPassiveListener",
            "smtp",
            "smtp/bruteshark_smtp_auth_plain.pcap",
            min_devices=0,  # loopback IPs fail is_valid_discovered_ip
        )

        creds = listener.get_credentials_summary()
        assert len(creds) >= 1, f"Expected at least 1 AUTH PLAIN credential, got {len(creds)}"

        plain_creds = [c for c in creds if c["auth_method"] == "AUTH PLAIN"]
        assert len(plain_creds) >= 1, (
            f"No AUTH PLAIN credentials; methods found: {[c['auth_method'] for c in creds]}"
        )

        # The bruteshark_smtp_auth_plain.pcap has user "username" / pass "password"
        cred = plain_creds[0]
        assert cred["username"] == "username", (
            f"Expected username='username', got {cred['username']!r}"
        )
        assert cred.get("password") == "password", (
            f"Expected password='password', got {cred.get('password')!r}"
        )
        assert cred["credential_type"] == "plaintext"

    def test_no_duplicate_auth_plain(self):
        """AUTH PLAIN via tshark field does not duplicate parameter-based extraction."""
        listener, devices, result = _run_listener_test(
            "smtp",
            "SMTPPassiveListener",
            "smtp",
            "smtp/bruteshark_smtp_auth_plain.pcap",
            min_devices=0,  # loopback IPs fail is_valid_discovered_ip
        )

        plain_creds = [
            c for c in listener.get_credentials_summary() if c["auth_method"] == "AUTH PLAIN"
        ]
        # Should be exactly 1, not duplicated
        assert len(plain_creds) == 1, (
            f"Expected exactly 1 AUTH PLAIN credential, got {len(plain_creds)}; "
            "deduplication may be broken"
        )


class TestSMTPResponseText:
    """T2: smtp.response -- full response text (code + message)."""

    def test_response_text_in_interactions(self):
        """Full response_text stored in response interaction details."""
        listener, devices, result = _run_listener_test(
            "smtp",
            "SMTPPassiveListener",
            "smtp",
            "smtp/bruteshark_smtp_auth_login.pcap",
        )

        response_ixs = [ix for ix in listener.interactions if ix.direction == "response"]
        assert len(response_ixs) >= 1, "No response interactions"

        has_response_text = [ix for ix in response_ixs if ix.details.get("response_text")]
        assert len(has_response_text) >= 1, (
            f"No response interaction has response_text; sample details: {response_ixs[0].details}"
        )

        # 220 banner should be in response_text
        banner_texts = [
            ix.details["response_text"]
            for ix in has_response_text
            if "220" in ix.details.get("response_code", "")
        ]
        assert len(banner_texts) >= 1, "220 banner not found in response_text"
        assert any("ESMTP" in t or "SMTP" in t for t in banner_texts), (
            f"SMTP marker not in 220 response_text; got: {banner_texts}"
        )

    def test_response_text_auth_success(self):
        """235 Authentication succeeded shows in response_text."""
        listener, devices, result = _run_listener_test(
            "smtp",
            "SMTPPassiveListener",
            "smtp",
            "smtp/bruteshark_smtp_auth_login.pcap",
        )

        auth_ok_ixs = [
            ix
            for ix in listener.interactions
            if ix.details.get("response_code") == "235" and ix.details.get("response_text")
        ]
        assert len(auth_ok_ixs) >= 1, "No 235 response with response_text"
        assert (
            "Authentication" in auth_ok_ixs[0].details["response_text"]
            or "235" in auth_ok_ixs[0].details["response_text"]
        )


class TestSMTPDataFragments:
    """T2: smtp.data.fragment.count / smtp.data.reassembled.length."""

    def test_data_fragment_stats_extracted(self):
        """DATA reassembly stats appear in interactions for pcap with email body."""
        listener, devices, result = _run_listener_test(
            "smtp",
            "SMTPPassiveListener",
            "smtp",
            "smtp/credslayer_smtp.pcap",
        )

        data_ixs = [
            ix
            for ix in listener.interactions
            if ix.details.get("data_fragment_count") or ix.details.get("data_reassembled_length")
        ]
        assert len(data_ixs) >= 1, (
            "No interaction has data_fragment_count or data_reassembled_length; "
            "DATA reassembly stats not extracted from credslayer_smtp.pcap"
        )

        # Verify the values are non-empty strings
        ix = data_ixs[0]
        frag_count = ix.details.get("data_fragment_count", "")
        reassembled_len = ix.details.get("data_reassembled_length", "")
        assert frag_count, "data_fragment_count is empty"
        assert reassembled_len, "data_reassembled_length is empty"

        # Values should be numeric strings
        assert str(frag_count).isdigit(), f"data_fragment_count not numeric: {frag_count!r}"
        assert str(reassembled_len).isdigit(), (
            f"data_reassembled_length not numeric: {reassembled_len!r}"
        )

    def test_data_fragments_in_internet_smtp(self):
        """DATA reassembly stats extracted from internet_smtp.pcap."""
        listener, devices, result = _run_listener_test(
            "smtp",
            "SMTPPassiveListener",
            "smtp",
            "smtp/internet_smtp.pcap",
        )

        data_ixs = [
            ix
            for ix in listener.interactions
            if ix.details.get("data_fragment_count") or ix.details.get("data_reassembled_length")
        ]
        assert len(data_ixs) >= 1, "No DATA reassembly stats in internet_smtp.pcap"


class TestSMTPFieldCoverage:
    """Cross-cutting tests verifying overall field coverage."""

    def test_all_t1_fields_extracted_auth_login(self):
        """All T1 fields present in AUTH LOGIN pcap interactions."""
        listener, devices, result = _run_listener_test(
            "smtp",
            "SMTPPassiveListener",
            "smtp",
            "smtp/bruteshark_smtp_auth_login.pcap",
        )

        all_details = {}
        for ix in listener.interactions:
            for k, v in ix.details.items():
                if v:
                    all_details[k] = v

        # T1 fields that should be present
        # command_line: from client commands
        assert "command_line" in all_details, (
            f"command_line not in any interaction; keys: {sorted(all_details.keys())}"
        )
        # auth_username/auth_password via creds (not in details directly)
        assert len(listener.credentials) >= 1, "No credentials extracted"

    def test_all_t1_fields_extracted_auth_plain(self):
        """All T1 fields present in AUTH PLAIN pcap interactions."""
        listener, devices, result = _run_listener_test(
            "smtp",
            "SMTPPassiveListener",
            "smtp",
            "smtp/bruteshark_smtp_auth_plain.pcap",
            min_devices=0,  # loopback IPs fail is_valid_discovered_ip
        )

        all_details = {}
        for ix in listener.interactions:
            for k, v in ix.details.items():
                if v:
                    all_details[k] = v

        assert "command_line" in all_details, (
            f"command_line not in any interaction; keys: {sorted(all_details.keys())}"
        )
        # AUTH PLAIN credential extracted via auth_username_password field
        plain_creds = [c for c in listener.credentials if c.auth_method == "AUTH PLAIN"]
        assert len(plain_creds) >= 1, "AUTH PLAIN credential not extracted"

    def test_harvest_returns_valid_dict(self):
        """harvest() returns a valid dict (no custom tables for SMTP)."""
        listener, devices, result = _run_listener_test(
            "smtp",
            "SMTPPassiveListener",
            "smtp",
            "smtp/bruteshark_smtp_auth_login.pcap",
        )
        assert isinstance(result, dict)

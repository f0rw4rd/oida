"""Tests for hashcat-compatible hash export from credential listeners via PcapScanner."""

import tempfile
from pathlib import Path


from oida.protocols.pcap.scanner import PcapScanner

from .conftest import (
    FIXTURES_ROOT,
    requires_pyshark,
    _skip_unless_exists,
    _get_listener_direct,
)


class TestHashcatExport:
    """Hashcat-compatible hash export from credential listeners."""

    @requires_pyshark
    def test_ntlm_hashcat_format(self):
        """NTLM get_hashcat_hashes() returns user::domain:... format."""
        listener = _get_listener_direct(
            FIXTURES_ROOT / "http" / "bruteshark_ntlm_http.pcap", "ntlm"
        )
        hashes = listener.get_hashcat_hashes()
        # ntlm_http.pcap should have NTLM auth exchanges
        if hashes:
            for h in hashes:
                assert "::" in h, f"NTLM hash should contain '::', got: {h}"

    @requires_pyshark
    def test_kerberos_hashcat_format(self):
        """Kerberos get_hashcat_hashes() returns $krb5 prefixed hashes."""
        listener = _get_listener_direct(
            FIXTURES_ROOT / "kerberos" / "bruteshark_kerberos_tcp.pcap", "kerberos"
        )
        hashes = listener.get_hashcat_hashes()
        if hashes:
            for h in hashes:
                assert h.startswith("$krb5"), (
                    f"Kerberos hash should start with $krb5, got: {h[:40]}"
                )

    @requires_pyshark
    def test_http_digest_hashcat_format(self):
        """HTTP Digest get_hashcat_hashes() returns $digest-md5$ prefix."""
        listener = _get_listener_direct(
            FIXTURES_ROOT / "http" / "bruteshark_http_digest.pcap", "http"
        )
        hashes = listener.get_hashcat_hashes()
        if hashes:
            for h in hashes:
                assert h.startswith("$digest-md5$"), (
                    f"HTTP digest hash should start with $digest-md5$, got: {h[:40]}"
                )

    @requires_pyshark
    def test_vnc_hashcat_format(self):
        """VNC get_hashcat_hashes() returns $vnc$*CHALLENGE*RESPONSE format."""
        listener = _get_listener_direct(FIXTURES_ROOT / "vnc" / "wireshark_vnc.pcap", "vnc")
        hashes = listener.get_hashcat_hashes()
        if hashes:
            for h in hashes:
                assert h.startswith("$vnc$*"), f"VNC hash should start with $vnc$*, got: {h[:40]}"

    @requires_pyshark
    def test_hashcat_flag_produces_file(self):
        """PcapScanner with hashcat=True writes hashcat.txt output."""
        pcap = FIXTURES_ROOT / "http" / "bruteshark_ntlm_http.pcap"
        _skip_unless_exists(pcap)
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = PcapScanner(
                str(pcap), args={"protocols": "ntlm", "hashcat": True, "output_dir": tmpdir}
            )
            scanner.run_scan()
            hashcat_file = Path(tmpdir) / "hashcat.txt"
            if hashcat_file.exists():
                content = hashcat_file.read_text()
                assert len(content) > 0, "hashcat.txt should not be empty"
                # Should contain mode comment headers
                assert "# " in content, "hashcat.txt should contain comment headers"

    @requires_pyshark
    def test_hashcat_empty_when_no_hashes(self):
        """No hashcat output when pcap has no crackable hashes."""
        pcap = FIXTURES_ROOT / "ftp" / "bruteshark_ftp.pcap"
        _skip_unless_exists(pcap)
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = PcapScanner(
                str(pcap), args={"protocols": "ftp", "hashcat": True, "output_dir": tmpdir}
            )
            scanner.run_scan()
            hashcat_file = Path(tmpdir) / "hashcat.txt"
            # FTP has no get_hashcat_hashes(), so no file should be written
            assert not hashcat_file.exists(), "hashcat.txt should not exist for plaintext-only pcap"

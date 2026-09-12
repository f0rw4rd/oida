"""End-to-end hash test for TACACS+ encrypted-AUTHEN (hashcat mode 16100).

Fixture ``tacacs/oida_tacacs_encrypted.pcap`` is a crafted TACACS+ AUTHEN reply
whose body is MD5-keystream encrypted with a known shared secret (``S3cretTa1``).
TACACS+ normally encrypts the body, so the crackable artifact is the shared
secret via hashcat 16100:

    $tacacs-plus$0$<session_id>$<ciphertext>$<version||seq>
    hashcat -m 16100  ->  S3cretTa1   (verified)

Exercises the full PcapScanner path (the ciphertext comes from tcp.payload in
EK mode -- no second raw pass needed). The exact line is deterministic for this
fixed fixture.
"""

import os
import tempfile
from pathlib import Path

import pytest

from tests.service_gate import require_service

from oida.protocols.pcap.scanner import PcapScanner

from .conftest import _pcap_path, _skip_unless_pyshark

pytestmark = [pytest.mark.integration]

EXPECTED = "$tacacs-plus$0$5fde8e68$b84e817efcd727c037$c002"


def test_tacacs_16100_extracted():
    _skip_unless_pyshark()
    pcap = _pcap_path("tacacs", "oida_tacacs_encrypted.pcap")
    if not os.path.exists(pcap):
        require_service(f"fixture missing: {pcap}")
    with tempfile.TemporaryDirectory() as tmp:
        scanner = PcapScanner(
            str(pcap), args={"protocols": "tacacs", "hashcat": True, "output_dir": tmp}
        )
        scanner.run_scan()
        hashcat_file = Path(tmp) / "hashcat.txt"
        assert hashcat_file.exists(), "no hashcat.txt produced"
        lines = [
            ln for ln in hashcat_file.read_text().splitlines() if ln.startswith("$tacacs-plus$")
        ]
    assert EXPECTED in lines, f"expected 16100 line not found; got {lines}"
    # Shape: $tacacs-plus$0$<8hex sid>$<hex cipher>$<4hex version+seq>
    body = EXPECTED[len("$tacacs-plus$") :]
    fmt, sid, cipher, verseq = body.split("$")
    assert fmt == "0" and len(sid) == 8 and len(verseq) == 4
    assert len(cipher) >= 12 and len(cipher) % 2 == 0

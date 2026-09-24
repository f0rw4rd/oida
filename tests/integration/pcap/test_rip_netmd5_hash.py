"""End-to-end hash test for RIPv2 keyed-MD5 authentication.

Fixture ``rip/oida_rip_md5.pcap`` was crafted from John the Ripper's own
``net-md5`` RIPv2 test vector (password ``quagga``) by wrapping its
salt+digest as a real RIPv2/UDP/520 packet. OIDA's extracted line is therefore
expected to equal that published vector byte-for-byte:

    $netmd5$02020000ffff0003002c01145267d48f00000000000000000002...ffff0001$ed9f940c3276afcc06d15babe8a1b61b
    john --format=net-md5  ->  quagga   (verified)

Exercises the full PcapScanner path including the raw-packet salt-fill pass.
Crackability is proven by recomputing MD5(salt || key_padded16) == digest.
"""

import hashlib
import os
import tempfile
from pathlib import Path

import pytest

from tests.service_gate import require_service

from oida.protocols.pcap.scanner import PcapScanner

from tests.integration.pcap.conftest import _pcap_path, _skip_unless_pyshark

pytestmark = [pytest.mark.integration]

KNOWN_KEY = b"quagga"
JTR_VECTOR = (
    "$netmd5$02020000ffff0003002c01145267d48f000000000000000000020000ac100100"
    "ffffff000000000000000001ffff0001$ed9f940c3276afcc06d15babe8a1b61b"
)


def test_rip_netmd5_matches_jtr_vector_and_cracks():
    _skip_unless_pyshark()
    pcap = _pcap_path("rip", "oida_rip_md5.pcap")
    if not os.path.exists(pcap):
        require_service(f"fixture missing: {pcap}")
    with tempfile.TemporaryDirectory() as tmp:
        scanner = PcapScanner(
            str(pcap), args={"protocols": "rip", "hashcat": True, "output_dir": tmp}
        )
        scanner.run_scan()
        hashcat_file = Path(tmp) / "hashcat.txt"
        assert hashcat_file.exists(), "no hashcat.txt produced"
        lines = [ln for ln in hashcat_file.read_text().splitlines() if ln.startswith("$netmd5$")]

    assert JTR_VECTOR in lines, f"OIDA line != JtR net-md5 vector; got {lines}"
    salt_hex, digest = JTR_VECTOR[len("$netmd5$") :].split("$")
    recomputed = hashlib.md5(bytes.fromhex(salt_hex) + KNOWN_KEY.ljust(16, b"\x00")).hexdigest()
    assert recomputed == digest, "net-md5 does not crack to the known key 'quagga'"

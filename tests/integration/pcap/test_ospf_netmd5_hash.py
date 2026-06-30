"""End-to-end hash test for OSPF cryptographic (MD5) authentication.

Fixture ``ospf/oida_ospf_md5.pcap`` is the public Wireshark OSPF-MD5 sample with
the first router's digest RE-KEYED to a known password (``S3cretOs1``) so the
result is crackable in CI. OSPF crypto-auth has no hashcat mode; the crackable
format is John ``net-md5``:

    $netmd5$<ospf-packet-without-digest>$<digest>
    john --format=net-md5  ->  S3cretOs1   (verified)

This exercises the full PcapScanner path INCLUDING the raw-packet salt-fill pass
(EK field extraction + a JSON/include_raw pass for the salt bytes). Crackability
is proven by recomputing MD5(salt || key_padded16) == digest, exactly what
net-md5 does, so the test needs no jumbo-John build.
"""

import hashlib
import os
import tempfile
from pathlib import Path

import pytest

from oida.protocols.pcap.scanner import PcapScanner

from .conftest import _pcap_path, _skip_unless_pyshark

pytestmark = [pytest.mark.integration]

KNOWN_KEY = b"S3cretOs1"


def test_ospf_netmd5_is_crackable():
    _skip_unless_pyshark()
    pcap = _pcap_path("ospf", "oida_ospf_md5.pcap")
    if not os.path.exists(pcap):
        pytest.skip(f"fixture missing: {pcap}")
    with tempfile.TemporaryDirectory() as tmp:
        scanner = PcapScanner(
            str(pcap), args={"protocols": "ospf", "hashcat": True, "output_dir": tmp}
        )
        scanner.run_scan()
        hashcat_file = Path(tmp) / "hashcat.txt"
        assert hashcat_file.exists(), "no hashcat.txt produced"
        lines = [ln for ln in hashcat_file.read_text().splitlines() if ln.startswith("$netmd5$")]

    assert lines, "no $netmd5$ lines extracted (salt-fill pass failed?)"

    # At least one line must crack to the known re-keyed password: net-md5 is
    # MD5(salt || key padded to 16 bytes) == digest.
    cracked = False
    for line in lines:
        salt_hex, digest = line[len("$netmd5$") :].split("$")
        recomputed = hashlib.md5(bytes.fromhex(salt_hex) + KNOWN_KEY.ljust(16, b"\x00")).hexdigest()
        if recomputed == digest:
            cracked = True
    assert cracked, f"no net-md5 line cracked to the known key; lines={lines}"

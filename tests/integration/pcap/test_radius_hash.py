"""End-to-end hash tests for RADIUS CHAP (hashcat 4800) and MS-CHAPv2 (5500).

Fixtures (crafted with known passwords; see docker/capture/ analysis):
  - radius/oida_radius_chap.pcap      -- CHAP-Password, user 'radiususer' / S3cretRa1
  - radius/oida_radius_mschapv2.pcap  -- MS-CHAP2-Response, user 'msuser' / S3cretMs1

RADIUS PAP (User-Password) is XOR-obfuscated and needs the shared secret, so it
is intentionally NOT emitted. Verified:
  hashcat -m 4800 '<resp>:<challenge>:<id>'        -> S3cretRa1
  hashcat -m 5500 'user::::<NTresp>:<challenge8>'   -> S3cretMs1
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

CHAP_EXPECT = "2ef32da31e6df5724e02c5a03954a19a:000102030405060708090a0b0c0d0e0f:01"
MSCHAP_EXPECT = "msuser::::18e44b6847a3bcf4255d26789b4e817de9d3f3ec7e7b0433:b50a3facc88b1d0a"


def _run(fixture: str):
    _skip_unless_pyshark()
    pcap = _pcap_path("radius", fixture)
    if not os.path.exists(pcap):
        require_service(f"fixture missing: {pcap}")
    with tempfile.TemporaryDirectory() as tmp:
        PcapScanner(
            str(pcap), args={"protocols": "radius", "hashcat": True, "output_dir": tmp}
        ).run_scan()
        hashcat_file = Path(tmp) / "hashcat.txt"
        assert hashcat_file.exists(), "no hashcat.txt produced"
        return [ln for ln in hashcat_file.read_text().splitlines() if ln and not ln.startswith("#")]


def test_radius_chap_is_crackable_4800():
    lines = _run("oida_radius_chap.pcap")
    assert CHAP_EXPECT in lines, f"expected 4800 line not found; got {lines}"
    # Prove crackable: CHAP response = MD5(id || password || challenge).
    resp, challenge, cid = CHAP_EXPECT.split(":")
    recomputed = hashlib.md5(
        bytes([int(cid, 16)]) + b"S3cretRa1" + bytes.fromhex(challenge)
    ).hexdigest()
    assert recomputed == resp, "CHAP response does not match known password"


def test_radius_mschapv2_is_crackable_5500():
    lines = _run("oida_radius_mschapv2.pcap")
    assert MSCHAP_EXPECT in lines, f"expected 5500 line not found; got {lines}"
    # Shape: user::::<24-byte NT response>:<8-byte derived challenge>
    user, _, _, _, ntresp, chal8 = MSCHAP_EXPECT.split(":")
    assert user == "msuser"
    assert len(ntresp) == 48 and len(chal8) == 16

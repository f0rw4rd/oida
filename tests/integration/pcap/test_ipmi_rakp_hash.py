"""End-to-end hash test on a REAL captured IPMI 2.0 RAKP handshake.

Fixture ``ipmi/github_ipmi_cipher3_auth.pcap`` is a real RMCP+/RAKP exchange.
OIDA assembles the hashcat mode-7300 line (salt = SIDm‖SIDc‖Rm‖Rc‖GUIDc‖RoleM‖
ULengthM‖UNameM, hash = the RAKP-2 key-exchange auth code). Verified:

    hashcat -m 7300 '<salt>:<hmac>' <wordlist>   ->  admin   (cracked, user "admin")

This pins the 7300 salt assembly on real traffic; the synthetic-vector
counterpart is tests/unit/pcap/test_ipmi_rakp_vector.py.
"""

import re

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]

EXPECTED = (
    "a4a3a2a0fb2db5fffe5a0a60f030cd6953bacea268da472c81fb54dfe1bf5647"
    "8788ea7ba154375b00020003000400050006000700080009140561646d696e"
    ":2d1a28182d6da8dbd294c9008a544f83f85b4d51"
)


def test_ipmi_rakp_hash_is_crackable_mode_7300():
    listener, _devices, _result = _run_listener_test(
        "ipmi",
        "IPMIPassiveListener",
        "ipmi_session || rmcp",
        "ipmi/github_ipmi_cipher3_auth.pcap",
        min_devices=0,
        min_interactions=0,
    )
    hashes = listener.get_hashcat_hashes()
    assert EXPECTED in hashes, f"expected 7300 line not found; got {hashes}"
    # Shape: <salt_hex>:<hmac_hex>, salt ends with role(1)+ulen(1)+username.
    for h in hashes:
        salt, hmac = h.split(":")
        assert re.fullmatch(r"[0-9a-f]+", salt) and re.fullmatch(r"[0-9a-f]+", hmac)
        assert len(salt) > 112  # SIDm+SIDc+Rm+Rc+GUID = 56 bytes minimum + user

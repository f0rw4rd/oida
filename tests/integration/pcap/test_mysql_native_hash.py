"""End-to-end hash test on a REAL captured MySQL native_password handshake.

Fixture ``mysql/oida_mysql_native.pcap`` was captured from a real
``mysql`` -> ``mysql:5.7`` mysql_native_password login (see docker/capture/).
Account ``oida`` / ``S3cretMy1``. The extracted line cracks with:

    hashcat -m 11200 '$mysqlna$<salt>*<hash>' <wordlist>   ->  S3cretMy1  (verified)

Pins the hashcat mode-11200 format end-to-end: ``$mysqlna$`` signature,
40-hex salt (8-byte salt + 12-byte salt2) and 40-hex SHA1 scramble.
"""

import re

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]

EXPECTED = (
    "$mysqlna$2766086c06065c031d2c0a6e1a33722f56282e14*d718d9899ef011dd86cb2a045e0c0303a8541c20"
)


def test_mysql_native_hash_is_crackable_mode_11200():
    listener, _devices, _result = _run_listener_test(
        "mysql",
        "MySQLPassiveListener",
        "mysql",
        "mysql/oida_mysql_native.pcap",
        min_interactions=0,
    )
    hashes = listener.get_hashcat_hashes()
    assert EXPECTED in hashes, f"expected {EXPECTED!r}, got {hashes}"
    for h in hashes:
        m = re.fullmatch(r"\$mysqlna\$([0-9a-f]{40})\*([0-9a-f]{40})", h)
        assert m, f"not a valid mode-11200 line: {h}"

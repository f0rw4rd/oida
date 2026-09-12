"""Regression: VRRP bad-checksum detection must use the right status value.

``src/oida/pcap/vrrp.py`` defined ``CHECKSUM_STATUS_BAD = 2`` (and the module
docstring claims "1=good, 2=bad").  Wireshark's ``vrrp.checksum.status``
(``tshark -G values``) uses the standard checksum-status convention:
0="Bad", 1="Good", 2="Unverified".

So the tampering warning (``if checksum_status == CHECKSUM_STATUS_BAD``) could
never fire for a genuinely bad checksum (0), and an "Unverified" packet (2)
would be misreported as bad.  Empirically confirmed with crafted VRRPv2
advertisements: bad checksum -> listener stored status 0, good -> 1; the
warning log never fired for the bad one.
"""

import pytest

from oida.pcap.vrrp import CHECKSUM_STATUS_BAD

# Authoritative: tshark -G values | grep vrrp.checksum.status
TSHARK_BAD = 0
TSHARK_GOOD = 1
TSHARK_UNVERIFIED = 2


def test_bad_status_constant_is_zero():
    assert CHECKSUM_STATUS_BAD == TSHARK_BAD, (
        "CHECKSUM_STATUS_BAD=2 is tshark's 'Unverified', not 'Bad'; "
        "the tampering warning can never fire for a real bad checksum"
    )


def test_good_is_not_flagged_as_bad():
    assert TSHARK_GOOD != CHECKSUM_STATUS_BAD


def test_unverified_is_not_flagged_as_bad():
    assert TSHARK_UNVERIFIED != CHECKSUM_STATUS_BAD

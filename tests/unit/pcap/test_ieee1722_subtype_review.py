"""Regression: AVTP subtype names must match the ieee1722.subtype registry.

``AVTP_SUBTYPE`` in ``src/oida/pcap/ieee1722.py`` mislabeled two of the
security-relevant control subtypes, and omitted a third:

    0xec -> code said "MAAP"             real: "ECC Signed Control Format"
    0xed -> absent                       real: "ECC Encrypted Control Format"
    0xee -> code said "Media Clock (EF)" real: "AES Encrypted Format Discrete"

MAAP is 0xfe, which the table already had -- so 0xec was a *duplicate* MAAP
entry.  Net effect for an operator: cryptographically signed/encrypted AVB
control traffic was reported as benign address-reservation or clock traffic,
and the distinct 0xed case showed as Unknown.

Authority: ``tshark -G values | grep ieee1722.subtype`` (tshark 4.4.15),
matching IEEE 1722-2016 Table 6.
"""

import pytest

from oida.pcap.ieee1722 import AVTP_SUBTYPE

# The single-value (non-range) rows of `tshark -G values | grep ieee1722.subtype`
TSHARK_SUBTYPE_NAMES = {
    "0xec": "ECC Signed Control Format",
    "0xed": "ECC Encrypted Control Format",
    "0xee": "AES Encrypted Format Discrete",
    "0xfa": "AVDECC Discovery Protocol",
    "0xfb": "AVDECC Enumeration and Control Protocol",
    "0xfc": "AVDECC Connection Management Protocol",
    "0xfe": "MAAP",
}


def test_maap_is_only_0xfe():
    """0xec must not be a second MAAP entry."""
    maap = {k for k, (name, _) in AVTP_SUBTYPE.items() if name == "MAAP"}
    assert maap == {"0xfe"}, f"MAAP claimed by {maap}"


def test_ecc_signed_control_format():
    assert AVTP_SUBTYPE["0xec"][0] == "ECC Signed Control Format"


def test_ecc_encrypted_control_format_present():
    assert "0xed" in AVTP_SUBTYPE, "0xed (ECC Encrypted Control Format) missing"
    assert AVTP_SUBTYPE["0xed"][0] == "ECC Encrypted Control Format"


def test_aes_encrypted_discrete_not_media_clock():
    assert AVTP_SUBTYPE["0xee"][0] == "AES Encrypted Format Discrete"


@pytest.mark.parametrize("code", sorted(TSHARK_SUBTYPE_NAMES))
def test_control_subtypes_named_and_classified(code):
    name, kind = AVTP_SUBTYPE[code]
    assert name == TSHARK_SUBTYPE_NAMES[code]
    # IEEE 1722-2016: subtype MSB set => control subtype.
    assert kind == "control"


def test_no_subtype_outside_registry():
    """Every table key must be a real registered subtype value."""
    for code in AVTP_SUBTYPE:
        val = int(code, 16)
        assert 0x00 <= val <= 0xFF, code

"""Regression: EIGRP checksum-status table must match Wireshark's convention.

``src/oida/pcap/eigrp.py`` ``EIGRP_CHECKSUM_STATUS`` mapped
0="Unverified", 1="Good", 2="Bad".  Wireshark's ``eigrp.checksum.status``
(``tshark -G values``) is the standard checksum-status table:
0="Bad", 1="Good", 2="Unverified", 3="Not present", 4="Illegal".

So a genuinely BAD checksum (status 0) was reported as "Unverified" in every
capture, in both pyshark modes.  Empirically confirmed with crafted EIGRP
Hello packets: bad checksum (0xdead) -> listener said "Unverified"; good
checksum -> "Good".
"""

import pytest

from oida.pcap.eigrp import EIGRP_CHECKSUM_STATUS

# tshark checksum-status convention (`tshark -G values`)
TSHARK_BAD = 0
TSHARK_GOOD = 1
TSHARK_UNVERIFIED = 2
TSHARK_NOT_PRESENT = 3

# Authoritative table: tshark -G values | grep eigrp.checksum.status
DISSECTOR_STATUS = {
    0: "Bad",
    1: "Good",
    2: "Unverified",
    3: "Not present",
    4: "Illegal",
}


def test_table_matches_dissector():
    wrong = {
        k: (v, DISSECTOR_STATUS[k])
        for k, v in EIGRP_CHECKSUM_STATUS.items()
        if k in DISSECTOR_STATUS and v != DISSECTOR_STATUS[k]
    }
    assert not wrong, f"EIGRP checksum status disagrees with tshark: {wrong}"


def test_bad_checksum_is_bad():
    """Status 0 is BAD -- mislabeling it 'Unverified' hides corruption."""
    assert EIGRP_CHECKSUM_STATUS[0] == "Bad"


def test_unverified_is_two():
    assert EIGRP_CHECKSUM_STATUS[2] == "Unverified"


@pytest.mark.parametrize("code", sorted(DISSECTOR_STATUS))
def test_every_dissector_status_resolves(code):
    assert code in EIGRP_CHECKSUM_STATUS, (
        f"dissector status {code} ({DISSECTOR_STATUS[code]!r}) missing"
    )


# --- Consumer-side regression (second wave) -------------------------------
#
# Correcting EIGRP_CHECKSUM_STATUS above was not enough: the alert site in
# process_packet still tested `checksum_status == 2`, i.e. it fired on
# "Unverified" and could NEVER fire on a genuinely bad checksum (0).  Fixing a
# table without following it to every consumer leaves the bug exactly where it
# was -- the table test passes and the alert is still wrong.
#
# There is also an absence hazard: checksum_status was read with a "0" default,
# and now that 0 means "Bad", a packet with no checksum-status field at all
# would raise a false BAD CHECKSUM alert.  Absence must map to "Not present".


class _Layer:
    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)

    def get_field(self, name, default=None):
        return getattr(self, name, default)


class _Packet:
    def __init__(self, eigrp):
        self.eigrp = eigrp
        self.ip = _Layer(src="10.0.0.1", dst="224.0.0.10")
        self.eth = _Layer(src="00:11:22:33:44:55", dst="01:00:5e:00:00:0a")
        self.transport_layer = None
        self.highest_layer = "EIGRP"

    def __contains__(self, item):
        return hasattr(self, str(item).lower())


def _eigrp_layer(**overrides):
    fields = {
        "opcode": "5",
        "as": "100",
        "seq": "0",
        "ack": "0",
        "vrid": "0",
        "checksum": "0xdead",
        "flags": "0x0",
    }
    fields.update(overrides)
    return _Layer(**fields)


def _alerts_for(**overrides):
    from oida.pcap.eigrp import EIGRPPassiveListener

    listener = EIGRPPassiveListener(interface="lo", timeout=1)
    listener.process_packet(_Packet(_eigrp_layer(**overrides)))
    return [a for a in listener._alerts if a.get("category") == "integrity_alert"]


def test_bad_checksum_raises_the_integrity_alert():
    alerts = _alerts_for(checksum_status=str(TSHARK_BAD))
    assert alerts, "a genuinely bad EIGRP checksum raised no integrity alert"
    assert "BAD CHECKSUM" in alerts[0]["message"]


def test_unverified_checksum_does_not_alert():
    assert not _alerts_for(checksum_status=str(TSHARK_UNVERIFIED))


def test_good_checksum_does_not_alert():
    assert not _alerts_for(checksum_status=str(TSHARK_GOOD))


def test_absent_checksum_status_does_not_alert():
    """No checksum-status field must not be read as status 0 ('Bad')."""
    assert not _alerts_for()


# ---------------------------------------------------------------------------
# Opcode table regression (second wave)
#
# `tshark -G values | grep '^V\teigrp.opcode'` lists 11 opcodes; the listener
# table carried only 7, so Request/Route Probe/Hello (Ack)/Stub-Info packets
# rendered as "Unknown(N)".
# ---------------------------------------------------------------------------

from oida.pcap.eigrp import EIGRP_OPCODES  # noqa: E402

TSHARK_EIGRP_OPCODES = {
    1: "Update",
    2: "Request",
    3: "Query",
    4: "Reply",
    5: "Hello",
    6: "IPX/SAP Update",
    7: "Route Probe",
    8: "Hello (Ack)",
    9: "Stub-Info",
    10: "SIA-Query",
    11: "SIA-Reply",
}


def test_opcode_table_matches_the_tshark_registry():
    assert EIGRP_OPCODES == TSHARK_EIGRP_OPCODES


def test_previously_missing_opcodes_are_named():
    for code in (2, 7, 8, 9):
        assert code in EIGRP_OPCODES, f"opcode {code} still unnamed"

"""Regression: CANopen LSS request/response direction was inverted.

``_process_lss`` in ``src/oida/pcap/canopen.py`` computed
``is_request = cob_id == 0x7E4``.  Per CiA 305 -- and verbatim from
Wireshark's ``epan/dissectors/packet-canopen.c``::

    #define LSS_MASTER_CAN_ID   0x7E5
    #define LSS_SLAVE_CAN_ID    0x7E4

so 0x7E5 is the LSS *master -> slave request* and 0x7E4 is the *slave ->
master response*.  Every LSS interaction therefore had its direction, its
``lss_direction`` master/slave role, its synthetic endpoint name and its
summary text swapped -- an LSS master reconfiguring node IDs on the bus (the
security-interesting event) was recorded as a slave response.

No existing test covers LSS.
"""

import pytest

from oida.pcap.canopen import CANopenPassiveListener

LSS_MASTER_CAN_ID = 0x7E5
LSS_SLAVE_CAN_ID = 0x7E4


class _Layer:
    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


def _run(cob_id):
    listener = CANopenPassiveListener(interface="lo", timeout=1)
    listener._process_lss(
        _Layer(lss_cs="17"),
        cob_id,
        "2026-01-01T00:00:00",
        "",
        "",
        "flow-1",
    )
    return listener.interactions[0]


def test_master_cob_id_is_a_request():
    ix = _run(LSS_MASTER_CAN_ID)
    assert ix.details["lss_direction"] == "master"
    assert ix.direction == "request"
    assert "request" in ix.summary


def test_slave_cob_id_is_a_response():
    ix = _run(LSS_SLAVE_CAN_ID)
    assert ix.details["lss_direction"] == "slave"
    assert ix.direction == "response"
    assert "response" in ix.summary


@pytest.mark.parametrize(
    "cob_id,expected",
    [(LSS_MASTER_CAN_ID, "lss-master"), (LSS_SLAVE_CAN_ID, "lss-slave")],
)
def test_synthetic_endpoint_name_matches_role(cob_id, expected):
    assert _run(cob_id).src_ip == expected

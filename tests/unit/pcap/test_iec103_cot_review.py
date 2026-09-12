"""Regression: IEC 103 ``COT_MON`` (monitor-direction Cause of Transmission)
must match Wireshark's ``iec60870_5_103.cot_mon`` value_string.

Before the fix, codes 42 and 43 were entirely absent from ``COT_MON`` (so a
generic-read response/error silently fell back to its bare decimal string),
and 44 was mislabeled "Valid data response" -- the real code 44 is "Generic
write confirmation"; "Valid data response to generic read command" is 42.

A handful of other entries also drifted from the registry text (3, 4, 5, 8).

Authority: local ``tshark -G values | grep 'iec60870_5_103\\.cot_mon'``
(tshark 4.4.15) -- this sandbox's tshark DOES have this table registered
(iec103 COT-monitor is not one of the sparse/missing dissector tables).
"""

from typing import Any, Dict

from oida.pcap.iec103 import COT_MON, IEC103PassiveListener

# Verbatim from `tshark -G values | grep -P '\tiec60870_5_103\.cot_mon\t'`
TSHARK_COT_MON = {
    1: "Spontaneous",
    2: "Cyclic",
    3: "Reset frame count bit (FCB)",
    4: "Reset communication unit (CU)",
    5: "Start / restart",
    6: "Power on",
    7: "Test mode",
    8: "Time synchronization",
    9: "General interrogation",
    10: "Termination of general interrogation",
    11: "Local operation",
    12: "Remote operation",
    20: "Positive acknowledgement of command",
    21: "Negative acknowledgement of command",
    31: "Transmission of disturbance data",
    40: "Positive acknowledgement of generic write command",
    41: "Negative acknowledgement of generic write command",
    42: "Valid data response to generic read command",
    43: "Invalid data response to generic read command",
    44: "Generic write confirmation",
}


def test_cot_mon_table_matches_registry():
    assert COT_MON == TSHARK_COT_MON


def test_code_42_present_valid_generic_read_response():
    assert COT_MON[42] == "Valid data response to generic read command"


def test_code_43_present_invalid_generic_read_response():
    assert COT_MON[43] == "Invalid data response to generic read command"


def test_code_44_is_generic_write_confirmation_not_valid_data_response():
    assert COT_MON[44] == "Generic write confirmation"
    assert COT_MON[44] != "Valid data response"


# ---------------------------------------------------------------------------
# End-to-end through process_packet: a generic-read response (cot_mon=42)
# must carry the real label, not fall through to the bare decimal string.
# ---------------------------------------------------------------------------


class _Layer:
    def __init__(self, fields: Dict[str, Any]):
        for name, val in fields.items():
            setattr(self, name, str(val))


class _Packet:
    def __init__(self, fields: Dict[str, Any]):
        self.iec60870_5_103 = _Layer(fields)


def _make_listener() -> IEC103PassiveListener:
    listener = IEC103PassiveListener("test0")
    listener.get_ip_info = lambda packet: ("10.0.0.1", "10.0.0.2")
    listener.get_port_info = lambda packet: (50000, 2404)
    listener.get_mac_info = lambda packet: ("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02")
    listener.get_flow_id = lambda packet: "flow-1"
    listener.get_stream_id = lambda packet: "stream-1"
    return listener


def _feed(listener: IEC103PassiveListener, fields: Dict[str, Any]):
    listener.process_packet(_Packet(fields))
    return listener.interactions[-1]


def test_generic_read_response_cot_42_end_to_end():
    listener = _make_listener()
    ix = _feed(
        listener,
        {
            "linkaddr": "4",
            "ctrl_prm": "0",
            "asdu_typeid_mon": "10",  # Generic data
            "asdu_address": "11",
            "cot_mon": "42",
        },
    )
    assert ix.details.get("cot_name") == "Valid data response to generic read command"


def test_generic_write_confirmation_cot_44_end_to_end():
    listener = _make_listener()
    ix = _feed(
        listener,
        {
            "linkaddr": "4",
            "ctrl_prm": "0",
            "asdu_typeid_mon": "10",
            "asdu_address": "11",
            "cot_mon": "44",
        },
    )
    assert ix.details.get("cot_name") == "Generic write confirmation"

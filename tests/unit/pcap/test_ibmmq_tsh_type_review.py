"""Regression tests for the IBM MQ TSH segment-type table and its dispatch.

Authority: ``tshark -G values | grep '^V\\tmq.tsh.type'`` (tshark 4.4.15),
which mirrors IBM's ``TSH_*`` constants:

    0x81 MQCONN   0x82 MQDISC   0x83 MQOPEN   0x84 MQCLOSE  0x85 MQGET
    0x86 MQPUT    0x87 MQPUT1   0x88 MQSET    0x89 MQINQ    0x8a MQCMIT
    0x8b MQBACK   0x8c SPI      0x8d MQSTAT   0x8e MQSUB    0x8f MQSUBRQ
    0x91..0x9f    the matching *_REPLY codes
    0xa1..0xaa    XA_*         0xb1..0xba   XA_*_REPLY

The listener previously carried an invented table (0x86=MQOPEN, 0x91=MQPUT,
0x92=MQPUT_REPLY, 0x83=MQMSG, ...) which mislabelled every API verb and, worse,
drove the handler dispatch: queue names were harvested from 0x86 (really MQPUT)
and the PUT handler fired on 0x91/0x92 (really MQCONN_REPLY/MQDISC_REPLY).
"""

import pytest

from oida.pcap.ibmmq import REQUEST_TYPES, TSH_TYPE_NAMES, IBMMQPassiveListener


class _Layer:
    """Minimal stand-in for a pyshark layer (XML-mode style attributes)."""

    def __init__(self, name, **fields):
        self._layer_name = name
        for key, value in fields.items():
            setattr(self, key, value)

    def get_field_value(self, name, raw=False):
        return getattr(self, name.replace(".", "_"), None)


class _Packet:
    def __init__(self, mq_layer):
        self.mq = mq_layer
        self.ip = _Layer("ip", src="10.0.0.5", dst="10.0.0.9")
        self.tcp = _Layer("tcp", srcport="51000", dstport="1414", stream="3")
        self.eth = _Layer("eth", src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee")
        self.layers = [self.eth, self.ip, self.tcp, self.mq]

    def __contains__(self, item):
        return item in ("eth", "ip", "tcp", "mq")


def _listener():
    return IBMMQPassiveListener(interface="lo", timeout=1)


def _feed(listener, **mq_fields):
    listener.process_packet(_Packet(_Layer("mq", **mq_fields)))


# ---------------------------------------------------------------------------
# Table correctness
# ---------------------------------------------------------------------------

TSHARK_TSH_TYPES = {
    "0x01": "INITIAL_DATA",
    "0x02": "RESYNC_DATA",
    "0x03": "RESET_DATA",
    "0x04": "MESSAGE_DATA",
    "0x05": "STATUS_DATA",
    "0x06": "SECURITY_DATA",
    "0x07": "PING_DATA",
    "0x08": "USERID_DATA",
    "0x09": "HEARTBEAT",
    "0x0a": "CONAUTH_INFO",
    "0x0b": "RENEGOTIATE_DATA",
    "0x0c": "SOCKET_ACTION",
    "0x0d": "ASYNC_MESSAGE",
    "0x0e": "REQUEST_MSGS",
    "0x0f": "NOTIFICATION",
    "0x81": "MQCONN",
    "0x82": "MQDISC",
    "0x83": "MQOPEN",
    "0x84": "MQCLOSE",
    "0x85": "MQGET",
    "0x86": "MQPUT",
    "0x87": "MQPUT1",
    "0x88": "MQSET",
    "0x89": "MQINQ",
    "0x8a": "MQCMIT",
    "0x8b": "MQBACK",
    "0x8c": "SPI",
    "0x8d": "MQSTAT",
    "0x8e": "MQSUB",
    "0x8f": "MQSUBRQ",
    "0x91": "MQCONN_REPLY",
    "0x92": "MQDISC_REPLY",
    "0x93": "MQOPEN_REPLY",
    "0x94": "MQCLOSE_REPLY",
    "0x95": "MQGET_REPLY",
    "0x96": "MQPUT_REPLY",
    "0x97": "MQPUT1_REPLY",
    "0x98": "MQSET_REPLY",
    "0x99": "MQINQ_REPLY",
    "0x9a": "MQCMIT_REPLY",
    "0x9b": "MQBACK_REPLY",
    "0x9c": "SPI_REPLY",
    "0x9d": "MQSTAT_REPLY",
    "0x9e": "MQSUB_REPLY",
    "0x9f": "MQSUBRQ_REPLY",
    "0xa1": "XA_START",
    "0xa2": "XA_END",
    "0xa3": "XA_OPEN",
    "0xa4": "XA_CLOSE",
    "0xa5": "XA_PREPARE",
    "0xa6": "XA_COMMIT",
    "0xa7": "XA_ROLLBACK",
    "0xa8": "XA_FORGET",
    "0xa9": "XA_RECOVER",
    "0xaa": "XA_COMPLETE",
    "0xb1": "XA_START_REPLY",
    "0xb2": "XA_END_REPLY",
    "0xb3": "XA_OPEN_REPLY",
    "0xb4": "XA_CLOSE_REPLY",
    "0xb5": "XA_PREPARE_REPLY",
    "0xb6": "XA_COMMIT_REPLY",
    "0xb7": "XA_ROLLBACK_REPLY",
    "0xb8": "XA_FORGET_REPLY",
    "0xb9": "XA_RECOVER_REPLY",
    "0xba": "XA_COMPLETE_REPLY",
}


def test_tsh_type_table_matches_the_tshark_registry():
    assert TSH_TYPE_NAMES == TSHARK_TSH_TYPES


@pytest.mark.parametrize(
    "code,name",
    [("0x83", "MQOPEN"), ("0x86", "MQPUT"), ("0x91", "MQCONN_REPLY"), ("0x92", "MQDISC_REPLY")],
)
def test_previously_mislabelled_codes(code, name):
    """These four were the ones that also drove the wrong handler."""
    assert TSH_TYPE_NAMES[code] == name


def test_no_invented_segment_types():
    """MQMSG / MQMSG_REPLY were never TSH segment types."""
    assert "MQMSG" not in TSH_TYPE_NAMES.values()
    assert "MQMSG_REPLY" not in TSH_TYPE_NAMES.values()


# ---------------------------------------------------------------------------
# Direction
# ---------------------------------------------------------------------------


def test_request_types_are_exactly_the_non_reply_api_codes():
    """Every 0x8x / 0xax code is a client request; every 0x9x / 0xbx a reply."""
    for code in TSH_TYPE_NAMES:
        value = int(code, 16)
        if 0x81 <= value <= 0x8F or 0xA1 <= value <= 0xAA:
            assert code in REQUEST_TYPES, f"{code} ({TSH_TYPE_NAMES[code]}) should be a request"
        elif 0x91 <= value <= 0x9F or 0xB1 <= value <= 0xBA:
            assert code not in REQUEST_TYPES, f"{code} ({TSH_TYPE_NAMES[code]}) is a reply"


def test_mqput_is_a_request_not_a_reply():
    assert "0x86" in REQUEST_TYPES
    assert "0x96" not in REQUEST_TYPES


# ---------------------------------------------------------------------------
# Dispatch: the table drives which handler runs
# ---------------------------------------------------------------------------


def test_queue_name_is_harvested_from_the_real_mqopen():
    """0x83 is MQOPEN -- the Object Descriptor handler must run for it."""
    listener = _listener()
    _feed(listener, tsh_type="0x83", od_objname="PAYMENTS.QUEUE")
    assert listener.queues.get("10.0.0.9") == {"PAYMENTS.QUEUE"}


def test_put_tracking_fires_on_the_real_mqput():
    listener = _listener()
    _feed(listener, tsh_type="0x86", md_applname="PAYENGINE")
    assert listener.applications.get("10.0.0.9") == {"PAYENGINE"}
    assert [op["operation"] for op in listener._write_ops] == ["MQPUT"]


def test_put_tracking_does_not_fire_on_mqconn_reply():
    """0x91 is MQCONN_REPLY, not MQPUT -- it must not log a write op."""
    listener = _listener()
    _feed(listener, tsh_type="0x91", conn_qm="QM1")
    assert listener._write_ops == []


def test_mqdisc_is_labelled_as_disconnect_not_open():
    listener = _listener()
    _feed(listener, tsh_type="0x82")
    names = [ix.details.get("segment_type_name") for ix in listener.interactions]
    assert names == ["MQDISC"]

"""Regression test for the S7comm bare-Ack drop bug.

``process_packet`` routed func 0x04/0x05 (Read/Write Var) into
``_process_read_write`` only for requests or AckData (ROSCTR=3) responses,
but the dispatch chain was an ``if func_code in (0x04, 0x05): if ...:`` — so a
bare Ack (ROSCTR=2) that still carried func 0x04/0x05 matched the outer arm,
skipped the inner guard, and produced NO interaction, violating the listener
invariant that every s7comm-filtered packet yields at least one interaction.

The fix folds the guard into a single condition so an unhandled 0x04/0x05
Ack falls through to the catch-all. This test pins that: a ROSCTR=2 Ack with
func 0x04 must record exactly one interaction.
"""

from oida.pcap.s7comm import S7commPassiveListener


class _Layer:
    def __init__(self, **fields):
        for k, v in fields.items():
            object.__setattr__(self, k, v)


class _Packet:
    def __init__(self, layer):
        self.s7comm = layer


def _make_listener():
    listener = S7commPassiveListener("test0")
    listener.get_ip_info = lambda packet: ("10.0.0.1", "10.0.0.2")
    listener.get_port_info = lambda packet: (50000, 102)
    listener.get_mac_info = lambda packet: ("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02")
    listener.get_flow_id = lambda packet: "flow-1"
    listener.get_stream_id = lambda packet: "stream-1"
    return listener


def test_bare_ack_with_read_func_still_records_interaction():
    listener = _make_listener()
    # ROSCTR=2 (Ack), func 0x04 (Read Var) but no item list — the bare-Ack case.
    listener.process_packet(_Packet(_Layer(header_rosctr="2", param_func="0x04")))
    assert len(listener.interactions) == 1


def test_ackdata_read_still_processed():
    listener = _make_listener()
    listener.process_packet(_Packet(_Layer(header_rosctr="3", param_func="0x04")))
    assert len(listener.interactions) == 1


def test_job_read_request_processed():
    listener = _make_listener()
    listener.process_packet(_Packet(_Layer(header_rosctr="1", param_func="0x04")))
    assert len(listener.interactions) == 1

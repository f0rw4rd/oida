"""Regression test: the IEC-101 link header byte must not be re-read as hex.

``iec60870_101.header`` is FT_UINT8 BASE_HEX.  In XML/PDML it renders "0x68";
in EK mode (``oida pcap -r``, protocols/pcap/scanner.py opens FileCapture with
use_ek=True) tshark emits the BARE DECIMAL int -- proven with enip.command on
tests/fixtures/pcap/enip/iti_enip_test.pcap: XML '0x0063' vs EK 99.

The listener parsed it with ``base=16``, so the EK value 229 became int("229",16)
= 553 and 16 became 22.  The single-char-ACK classification at iec101.py:262
(``header_val == 0xE5``) could therefore never fire on the EK path.
"""

from oida.pcap.iec101 import IEC101PassiveListener


class _Layer:
    def __init__(self, **fields):
        for key, value in fields.items():
            setattr(self, key, value)


class _Packet:
    def __init__(self, iec101):
        self.iec60870_101 = iec101
        self.ip = _Layer(src="10.11.12.13", dst="10.11.12.20")
        self.tcp = _Layer(srcport="2404", dstport="20000", stream="0")
        self.eth = _Layer(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee")
        self.transport_layer = "TCP"
        self.highest_layer = "IEC60870_101"

    def __contains__(self, item):
        return hasattr(self, str(item).lower())


def _feed(header):
    listener = IEC101PassiveListener(interface="lo", timeout=1)
    layer = _Layer(
        linkaddr="1",
        ctrl_prm="0",
        ctrl_func_sec_to_pri="11",
        header=header,
    )
    listener.process_packet(_Packet(layer))
    return listener


def _ops(listener):
    return [i.operation for i in listener.interactions]


def test_single_char_ack_is_recognised_from_a_decimal_header_ek():
    """EK hands over the native int 229 (0xE5)."""
    assert "Single Char ACK (E5h)" in _ops(_feed(229))


def test_single_char_ack_is_recognised_from_a_decimal_header_string():
    assert "Single Char ACK (E5h)" in _ops(_feed("229"))


def test_hex_prefixed_header_still_works():
    assert "Single Char ACK (E5h)" in _ops(_feed("0xe5"))


def test_fixed_length_header_is_not_misread_as_single_char():
    ops = _ops(_feed(16))
    assert ops and "Single Char ACK" not in ops[0]

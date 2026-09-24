"""Regression tests for MySQL passive-listener correctness bugs.

Covers two bugs found in the pcap bug hunt:

1. ``process_packet`` gated single-PDU handling on ``all_field_names``, a
   property that only exists in pyshark's EK mode.  The LiveCapture path in
   ``pyshark_base`` does not pass ``use_ek``, so in production every packet
   fell through to ``_handle_unknown`` -- every interaction became "MySQL
   Data" and ZERO credentials were extracted.  The tests here deliberately
   load in XML mode (no ``use_ek``) because the shared ``_run_listener_test``
   helper always prefers EK mode and therefore cannot catch this.

2. ERR packets were read via a field named ``error_string``, which tshark does
   not register.  The real field is ``mysql.error.message`` (pyshark:
   ``error_message``), so the error text was never extracted in either mode.
"""

import asyncio

import pytest

from tests.service_gate import require_import, require_service

from tests.integration.pcap.conftest import _pcap_path, _skip_unless_pyshark

pytestmark = [pytest.mark.integration]


def _feed_xml_mode(pcap_path, display_filter="mysql"):
    """Run the MySQL listener over *pcap_path* in pyshark XML mode.

    XML mode (no ``use_ek``) is what ``PySharkListenerBase._capture_live``
    uses, so it is the mode the listener actually runs in against a live
    interface.
    """
    import pyshark

    from oida.pcap.mysql import MySQLPassiveListener

    asyncio.set_event_loop(asyncio.new_event_loop())
    cap = pyshark.FileCapture(input_file=str(pcap_path), display_filter=display_filter)
    listener = MySQLPassiveListener(interface="lo", timeout=10)
    packets = []
    try:
        for pkt in cap:
            packets.append(pkt)
    finally:
        try:
            cap.close()
        except Exception:
            pass
    listener.feed_packets(iter(packets))
    return listener, len(packets)


class TestMySQLXmlModeFieldAccess:
    """Bug 1: XML-mode packets must not all collapse to 'MySQL Data'."""

    def test_xml_mode_classifies_operations(self):
        _skip_unless_pyshark()
        pcap = _pcap_path("mysql", "wireshark_mysql_complete.pcap")
        listener, n_packets = _feed_xml_mode(pcap)

        assert n_packets > 0, "fixture yielded no mysql packets"
        assert listener.interactions, "listener produced no interactions"

        ops = {ix.operation for ix in listener.interactions if ix.operation}
        # Before the fix this set was exactly {"MySQL Data"}.
        assert ops != {"MySQL Data"}, (
            "every XML-mode packet fell through to the unknown handler; "
            "the single-PDU guard is EK-only again"
        )
        assert any("Query" in op for op in ops), f"no queries classified in XML mode; saw {ops}"

    def test_xml_mode_extracts_credentials(self):
        _skip_unless_pyshark()
        pcap = _pcap_path("mysql", "wireshark_mysql_complete.pcap")
        listener, _ = _feed_xml_mode(pcap)

        # Before the fix: 0 credentials from 36/36 packets.
        assert len(listener.credentials) >= 1, (
            "no credentials extracted in XML mode -- the production live-capture "
            "path harvests nothing"
        )
        for cred in listener.get_credentials_summary():
            assert cred.get("username"), f"credential without a username: {cred}"


def _write_mysql_err_pcap(path):
    """Build a minimal MySQL greeting/login/ERR exchange as a pcap.

    No MySQL fixture in tests/fixtures/pcap/mysql/ contains an ERR packet, so
    the error-text regression needs a purpose-built capture.
    """
    scapy_all = require_import("scapy.all")

    def pdu(payload: bytes, seq: int) -> bytes:
        n = len(payload)
        return bytes([n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF, seq]) + payload

    client = ("10.0.0.5", 54321)
    server = ("10.0.0.9", 3306)

    greeting = pdu(
        b"\x0a"
        + b"8.0.32\x00"
        + b"\x01\x00\x00\x00"
        + b"12345678"
        + b"\x00"
        + b"\xff\xf7"
        + b"\x21"
        + b"\x02\x00"
        + b"\xff\x81"
        + b"\x15"
        + b"\x00" * 10
        + b"abcdefghijkl\x00"
        + b"mysql_native_password\x00",
        0,
    )
    login = pdu(
        b"\x85\xa6\x03\x00"
        + b"\x00\x00\x00\x01"
        + b"\x21"
        + b"\x00" * 23
        + b"root\x00"
        + b"\x14"
        + b"\x11" * 20
        + b"testdb\x00"
        + b"mysql_native_password\x00",
        1,
    )
    err_text = b"Access denied for user 'root'@'10.0.0.5' (using password: YES)"
    err = pdu(b"\xff" + (1045).to_bytes(2, "little") + b"#28000" + err_text, 2)

    def frame(src, dst, payload, seq, ack):
        return (
            scapy_all.Ether()
            / scapy_all.IP(src=src[0], dst=dst[0])
            / scapy_all.TCP(sport=src[1], dport=dst[1], flags="PA", seq=seq, ack=ack)
            / scapy_all.Raw(payload)
        )

    seq_c, seq_s = 1, 1
    packets = [frame(server, client, greeting, seq_s, seq_c)]
    seq_s += len(greeting)
    packets.append(frame(client, server, login, seq_c, seq_s))
    seq_c += len(login)
    packets.append(frame(server, client, err, seq_s, seq_c))

    scapy_all.wrpcap(str(path), packets)
    return err_text.decode()


class TestMySQLErrorMessageField:
    """Bug 2: ERR text came from a nonexistent 'error_string' field."""

    @pytest.mark.parametrize("use_ek", [False, True])
    def test_err_message_extracted(self, tmp_path, use_ek):
        _skip_unless_pyshark()
        import pyshark

        from oida.pcap.mysql import MySQLPassiveListener

        pcap = tmp_path / "mysql_err.pcap"
        expected_text = _write_mysql_err_pcap(pcap)

        asyncio.set_event_loop(asyncio.new_event_loop())
        kwargs = {"input_file": str(pcap), "display_filter": "mysql"}
        if use_ek:
            from tests.integration.pcap.conftest import _ek_mode_available

            if not _ek_mode_available:
                require_service("pyshark EK-mode fork not installed")
            kwargs["use_ek"] = True

        cap = pyshark.FileCapture(**kwargs)
        listener = MySQLPassiveListener(interface="lo", timeout=10)
        packets = list(cap)
        try:
            cap.close()
        except Exception:
            pass
        listener.feed_packets(iter(packets))

        errors = [ix for ix in listener.interactions if ix.operation == "Error"]
        assert errors, f"no Error interaction; saw {[i.operation for i in listener.interactions]}"

        details = errors[0].details
        assert details.get("error_code") == "1045", f"wrong error_code: {details}"
        # Before the fix this was always "" because tshark has no
        # mysql.error_string field.
        assert details.get("error_string") == expected_text, (
            f"ERR text not extracted (mysql.error.message -> error_message): {details}"
        )
        assert details.get("sqlstate") == "28000", f"sqlstate not extracted: {details}"

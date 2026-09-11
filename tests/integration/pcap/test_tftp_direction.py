"""Regression: TFTP DATA/ACK interaction direction must track the real roles.

DATA was hardcoded "response" and ACK "request", which is wrong for a WRQ
upload (client sources DATA; server sources ACK). Direction now follows the
per-pair server role.
"""

import pytest

from oida.pcap.tftp import TFTPPassiveListener

pytestmark = [pytest.mark.integration]


class _FakeTftp:
    def __init__(self, **fields):
        self._fields = fields

    def get_field(self, name):
        return self._fields.get(name)

    def __getattr__(self, name):
        try:
            return self._fields[name]
        except KeyError as exc:  # pragma: no cover
            raise AttributeError(name) from exc


def _mk():
    return TFTPPassiveListener(interface="lo", timeout=1)


def _data():
    return _FakeTftp(opcode="3", blocknum="1")


def _ack():
    return _FakeTftp(opcode="4", blocknum="1")


def _last_dir(listener):
    return listener.interactions[-1].direction


class TestTftpDirection:
    def test_download_data_is_response_ack_is_request(self):
        listener = _mk()
        # client 10.0.0.9 reads from server 10.0.0.1
        listener._process_rrq(
            _FakeTftp(opcode="1", source_file="f", type="octet"),
            "10.0.0.9",
            "10.0.0.1",
            "",
            "",
            flow_id="10.0.0.9:2000-10.0.0.1:69",
            now="1.0",
        )
        # server -> client DATA
        listener._process_data(
            _data(),
            "10.0.0.1",
            "10.0.0.9",
            "",
            "",
            flow_id="10.0.0.1:1025-10.0.0.9:2001",
            now="2.0",
        )
        assert _last_dir(listener) == "response"
        # client -> server ACK
        listener._process_ack(
            _ack(),
            "10.0.0.9",
            "10.0.0.1",
            "",
            "",
            flow_id="10.0.0.9:2001-10.0.0.1:1025",
            now="3.0",
        )
        assert _last_dir(listener) == "request"

    def test_upload_data_is_request_ack_is_response(self):
        listener = _mk()
        # client 10.0.0.9 writes to server 10.0.0.1 (WRQ upload)
        listener._process_wrq(
            _FakeTftp(opcode="2", destination_file="f", type="octet"),
            "10.0.0.9",
            "10.0.0.1",
            "",
            "",
            flow_id="10.0.0.9:2000-10.0.0.1:69",
            now="1.0",
        )
        # client -> server DATA (upload payload)
        listener._process_data(
            _data(),
            "10.0.0.9",
            "10.0.0.1",
            "",
            "",
            flow_id="10.0.0.9:1025-10.0.0.1:2001",
            now="2.0",
        )
        assert _last_dir(listener) == "request"
        # server -> client ACK
        listener._process_ack(
            _ack(),
            "10.0.0.1",
            "10.0.0.9",
            "",
            "",
            flow_id="10.0.0.1:2001-10.0.0.9:1025",
            now="3.0",
        )
        assert _last_dir(listener) == "response"

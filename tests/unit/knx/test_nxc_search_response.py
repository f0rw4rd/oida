"""Unit tests for KNXnet/IP SearchResponse parsing in nxc_connection.knx.

``_parse_search_response`` decodes a raw KNXnet/IP SEARCH_RESPONSE frame
(HPAI control endpoint + DEVICE_INFO DIB + SUPP_SVC_FAMILIES DIB).  These
tests build byte buffers by hand and assert the decoded dict, plus the
display helpers that consume it.  Only ``self.logger`` is used by the
parser, so the class is created via ``__new__`` without triggering the
network ``proto_flow``.
"""

import struct

import pytest

from oida.protocols.knx.nxc_connection import knx as KnxConn
from tests.unit.knx._harness import SpyLogger


@pytest.fixture
def conn():
    c = KnxConn.__new__(KnxConn)
    c.logger = SpyLogger()
    return c


def build_search_response(
    *,
    service_type=0x0202,
    ctrl_port=3671,
    medium=0x02,  # TP1
    status=0x01,  # programming mode active
    ia_high=0x11,  # area 1, line 1
    ia_low=0x05,  # device 5
    project_id=0x1234,
    serial=b"\x00\x11\x22\x33\x44\x55",
    multicast=b"\xe0\x00\x17\x0c",  # 224.0.23.12
    mac=b"\xaa\xbb\xcc\xdd\xee\xff",
    name=b"Test Gateway",
    services=((0x02, 1), (0x04, 1), (0x05, 1)),  # core, tunnelling, routing
):
    # KNXnet/IP header (6 bytes); total length filled at the end
    body = b""

    # HPAI control endpoint: len(8), proto(1=UDP), 4-byte IP, 2-byte port
    hpai = struct.pack("!BB4sH", 8, 1, b"\x0a\x00\x00\x05", ctrl_port)
    body += hpai

    # DEVICE_INFO DIB: len(54), type(0x01), then 52 bytes payload
    name_field = name[:30].ljust(30, b"\x00")
    dib_dev = bytes([54, 0x01, medium, status, ia_high, ia_low])
    dib_dev += struct.pack("!H", project_id)
    dib_dev += serial + multicast + mac + name_field
    body += dib_dev

    # SUPP_SVC_FAMILIES DIB: len, type(0x02), then (family,version) pairs
    svc_pairs = b"".join(bytes([f, v]) for f, v in services)
    dib_svc = bytes([2 + len(svc_pairs), 0x02]) + svc_pairs
    body += dib_svc

    total = 6 + len(body)
    header = struct.pack("!BBHH", 0x06, 0x10, service_type, total)
    return header + body


class TestParseSearchResponse:
    def test_full_decode(self, conn):
        data = build_search_response()
        res = conn._parse_search_response(data, "10.0.0.5")
        assert res["ip"] == "10.0.0.5"
        assert res["port"] == 3671
        assert res["medium"] == "PL110"  # 0x02
        assert res["programming_mode"] is True
        assert res["individual_address"] == "1.1.5"
        assert res["project_id"] == 0x1234
        assert res["serial"] == "001122334455"
        assert res["multicast_address"] == "224.0.23.12"
        assert res["mac"] == "AA:BB:CC:DD:EE:FF"
        assert res["name"] == "Test Gateway"
        assert res["services"]["KNXnet/IP Tunneling"] == 1
        assert res["services"]["KNXnet/IP Routing"] == 1
        assert res["supports_tunnelling"] is True
        assert res["supports_routing"] is True

    def test_non_default_control_port_decoded(self, conn):
        data = build_search_response(ctrl_port=55000)
        res = conn._parse_search_response(data, "10.0.0.5")
        assert res["port"] == 55000

    def test_medium_ip(self, conn):
        data = build_search_response(medium=0x20)
        res = conn._parse_search_response(data, "1.2.3.4")
        assert res["medium"] == "IP"

    def test_programming_mode_off(self, conn):
        data = build_search_response(status=0x00)
        res = conn._parse_search_response(data, "1.2.3.4")
        assert res["programming_mode"] is False

    def test_individual_address_decoding(self, conn):
        # area 2, line 3, device 10 -> high byte 0x23
        data = build_search_response(ia_high=0x23, ia_low=10)
        res = conn._parse_search_response(data, "1.2.3.4")
        assert res["individual_address"] == "2.3.10"

    def test_no_tunnelling_or_routing(self, conn):
        data = build_search_response(services=((0x02, 1),))  # core only
        res = conn._parse_search_response(data, "1.2.3.4")
        assert res["supports_tunnelling"] is False
        assert res["supports_routing"] is False

    def test_too_short_returns_none(self, conn):
        assert conn._parse_search_response(b"\x00" * 10, "1.2.3.4") is None

    def test_wrong_service_type_returns_none(self, conn):
        data = build_search_response(service_type=0x0201)  # SEARCH_REQUEST
        assert conn._parse_search_response(data, "1.2.3.4") is None

    def test_unknown_service_family_labelled(self, conn):
        data = build_search_response(services=((0x99, 3),))
        res = conn._parse_search_response(data, "1.2.3.4")
        assert "Service 0x99" in res["services"]


class TestDisplayGatewayInfoDict:
    def test_displays_parsed_fields(self, conn):
        gw = {
            "name": "GW1",
            "individual_address": "1.1.5",
            "mac": "AA:BB:CC:DD:EE:FF",
            "serial": "001122334455",
            "multicast_address": "224.0.23.12",
            "medium": "TP1",
            "programming_mode": True,
            "services": {"KNXnet/IP Tunneling": 1},
        }
        conn._display_gateway_info_dict(gw)
        text = conn.logger.all_text()
        assert "GW1" in text
        assert "1.1.5" in text
        assert "001122334455" in text
        # programming mode active is a warning
        assert any("Programming Mode: ACTIVE" in m for m in conn.logger.records["warning"])

    def test_handles_missing_optional_fields(self, conn):
        conn._display_gateway_info_dict({})
        # falls back to default name, no crash
        assert any("KNX/IP Gateway" in m for m in conn.logger.records["success"])


def _make_args(**kw):
    from types import SimpleNamespace

    defaults = dict(
        knxproj=None,
        knxproj_info=False,
        knxproj_hash=False,
        knxproj_password=None,
        knxproj_fast=False,
        knxproj_wordlist=None,
        knxproj_threads=16,
    )
    defaults.update(kw)
    return SimpleNamespace(**defaults)


class TestHandleKnxproj:
    def _conn(self, args):
        c = KnxConn.__new__(KnxConn)
        c.logger = SpyLogger()
        c.args = args
        c.results = {"data": {}}
        return c

    def test_no_knxproj_returns_false(self):
        c = self._conn(_make_args())
        assert c._handle_knxproj() is False

    def test_missing_file_reports_and_returns_true(self, tmp_path):
        c = self._conn(_make_args(knxproj=str(tmp_path / "missing.knxproj")))
        assert c._handle_knxproj() is True
        assert any("File not found" in m for m in c.logger.records["fail"])

    def test_info_mode_short_circuits(self, tmp_path, monkeypatch):
        f = tmp_path / "p.knxproj"
        f.write_bytes(b"PK\x03\x04dummy")
        monkeypatch.setattr(
            "oida.protocols.knx.nxc_connection.get_knxproj_info",
            lambda p: {"project_id": "P1", "ets_version": "5", "password_protected": False},
        )
        c = self._conn(_make_args(knxproj=str(f), knxproj_info=True))
        assert c._handle_knxproj() is True
        # info displayed
        assert any("P1" in m for m in c.logger.records["display"])

    def test_protected_without_password_or_wordlist(self, tmp_path, monkeypatch):
        f = tmp_path / "p.knxproj"
        f.write_bytes(b"PK\x03\x04dummy")
        monkeypatch.setattr(
            "oida.protocols.knx.nxc_connection.get_knxproj_info",
            lambda p: {"project_id": "P1", "ets_version": "5", "password_protected": True},
        )
        c = self._conn(_make_args(knxproj=str(f)))
        assert c._handle_knxproj() is True
        assert any("password protected" in m.lower() for m in c.logger.records["fail"])

    def test_parses_unprotected_project(self, tmp_path, monkeypatch):
        f = tmp_path / "p.knxproj"
        f.write_bytes(b"PK\x03\x04dummy")
        monkeypatch.setattr(
            "oida.protocols.knx.nxc_connection.get_knxproj_info",
            lambda p: {"project_id": "P1", "ets_version": "5", "password_protected": False},
        )
        monkeypatch.setattr(
            "oida.protocols.knx.nxc_connection.parse_knxproj",
            lambda p, pw: {"devices": [{"address": "1.1.1"}]},
        )
        monkeypatch.setattr(
            "oida.protocols.knx.nxc_connection.display_knxproj_data",
            lambda data, logger: None,
        )
        c = self._conn(_make_args(knxproj=str(f)))
        assert c._handle_knxproj() is True
        assert c.results["data"]["knxproj"]["devices"][0]["address"] == "1.1.1"
        assert any("parsed successfully" in m for m in c.logger.records["success"])

    def test_wordlist_crack_success_emits_finding(self, tmp_path, monkeypatch):
        f = tmp_path / "p.knxproj"
        f.write_bytes(b"PK\x03\x04dummy")
        wl = tmp_path / "wl.txt"
        wl.write_text("secret\n")
        monkeypatch.setattr(
            "oida.protocols.knx.nxc_connection.get_knxproj_info",
            lambda p: {"project_id": "P1", "ets_version": "5", "password_protected": True},
        )
        monkeypatch.setattr(
            "oida.protocols.knx.nxc_connection.crack_knxproj",
            lambda *a, **k: "secret",
        )
        monkeypatch.setattr(
            "oida.protocols.knx.nxc_connection.parse_knxproj",
            lambda p, pw: {"devices": []},
        )
        monkeypatch.setattr(
            "oida.protocols.knx.nxc_connection.display_knxproj_data",
            lambda data, logger: None,
        )
        c = self._conn(_make_args(knxproj=str(f), knxproj_wordlist=str(wl)))
        assert c._handle_knxproj() is True
        findings = [t for t, _ in c.logger.findings()]
        assert "Weak password" in findings

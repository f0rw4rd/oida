"""Unit tests for the xknx-based KNXnet/IP unicast discovery in cli_runner.knx.

``_unicast_search`` delegates to xknx's ``request_description`` (a unicast
DESCRIPTION_REQUEST + extended search) and ``_gateway_descriptor_to_dict``
flattens the returned ``GatewayDescriptor`` into a JSON-serialisable dict.
``_display_gateway_info_dict`` renders that capability picture.  Only
``self.logger``/``self.args`` are used, so the class is created via
``__new__`` without triggering the network ``proto_flow``.
"""

import asyncio
from types import SimpleNamespace

import pytest

from oida.protocols.knx.cli_runner import knx as KnxConn
from tests.unit.knx._harness import SpyLogger


@pytest.fixture
def conn():
    c = KnxConn.__new__(KnxConn)
    c.logger = SpyLogger()
    return c


def _slot(*, free=True, usable=True, authorized=True):
    """Stand-in for xknx.io.gateway_scanner.TunnelingSlotStatus."""
    return SimpleNamespace(free=free, usable=usable, authorized=authorized)


def fake_descriptor(**kw):
    """Stand-in for an xknx GatewayDescriptor (only the attrs we read)."""
    d = dict(
        name="IP-Schnittstelle Secure N 148/",
        ip_addr="192.168.1.196",
        port=3671,
        individual_address="1.1.7",
        core_version=2,
        supports_tunnelling=True,
        supports_tunnelling_tcp=True,
        supports_routing=False,
        supports_secure=True,
        tunnelling_requires_secure=None,
        routing_requires_secure=None,
        tunnelling_slots={"1.1.255": _slot(), "1.1.254": _slot(free=False)},
        local_ip="192.168.1.1",
    )
    d.update(kw)
    return SimpleNamespace(**d)


class TestGatewayDescriptorToDict:
    def test_flattens_all_capability_fields(self, conn):
        d = conn._gateway_descriptor_to_dict(fake_descriptor())
        assert d["name"].startswith("IP-Schnittstelle Secure")
        assert d["ip"] == "192.168.1.196"
        assert d["individual_address"] == "1.1.7"
        assert d["core_version"] == 2
        assert d["supports_tunnelling"] is True
        assert d["supports_tunnelling_tcp"] is True
        assert d["supports_routing"] is False
        assert d["supports_secure"] is True
        assert d["tunnelling_slots_total"] == 2
        assert d["tunnelling_slots_free"] == 1
        assert d["tunnelling_slots"]["1.1.255"]["free"] is True
        assert d["tunnelling_slots"]["1.1.254"]["free"] is False

    def test_none_individual_address(self, conn):
        d = conn._gateway_descriptor_to_dict(fake_descriptor(individual_address=None))
        assert d["individual_address"] is None

    def test_empty_slots(self, conn):
        d = conn._gateway_descriptor_to_dict(fake_descriptor(tunnelling_slots={}))
        assert d["tunnelling_slots_total"] == 0
        assert d["tunnelling_slots_free"] == 0


class TestUnicastSearch:
    def test_returns_dict_on_success(self, conn, monkeypatch):
        conn.args = SimpleNamespace(no_nat=False)

        async def fake_request(host, port, local_ip=None, route_back=True):
            assert route_back is True  # NAT on by default
            return fake_descriptor(ip_addr=host)

        monkeypatch.setattr("xknx.io.self_description.request_description", fake_request)
        res = asyncio.run(conn._unicast_search("192.168.1.196", 3671))
        assert res["ip"] == "192.168.1.196"
        assert res["supports_secure"] is True

    def test_no_nat_sets_route_back_false(self, conn, monkeypatch):
        conn.args = SimpleNamespace(no_nat=True)

        async def fake_request(host, port, local_ip=None, route_back=True):
            assert route_back is False
            return fake_descriptor()

        monkeypatch.setattr("xknx.io.self_description.request_description", fake_request)
        assert asyncio.run(conn._unicast_search("192.168.1.196", 3671)) is not None

    def test_returns_none_on_failure(self, conn, monkeypatch):
        from xknx.exceptions import CommunicationError

        conn.args = SimpleNamespace(no_nat=False)

        async def fake_request(host, port, local_ip=None, route_back=True):
            raise CommunicationError("no response")

        monkeypatch.setattr("xknx.io.self_description.request_description", fake_request)
        assert asyncio.run(conn._unicast_search("10.0.0.9", 3671)) is None


class TestDisplayGatewayInfoDict:
    def test_displays_capabilities_and_slots(self, conn):
        gw = conn._gateway_descriptor_to_dict(fake_descriptor())
        conn._display_gateway_info_dict(gw)
        text = conn.logger.all_text()
        assert "IP-Schnittstelle Secure" in text
        assert "1.1.7" in text
        assert "v2" in text
        assert "Tunnelling/TCP" in text
        # KNX Secure supported is surfaced as a warning
        assert any("KNX Secure: supported" in m for m in conn.logger.records["warning"])
        assert "Tunnel slots: 1/2 free" in text

    def test_secure_required_annotated(self, conn):
        gw = conn._gateway_descriptor_to_dict(fake_descriptor(tunnelling_requires_secure=True))
        conn._display_gateway_info_dict(gw)
        assert any("required for: tunnelling" in m for m in conn.logger.records["warning"])

    def test_non_secure_gateway_noted(self, conn):
        gw = conn._gateway_descriptor_to_dict(fake_descriptor(supports_secure=False))
        conn._display_gateway_info_dict(gw)
        assert "not advertised" in conn.logger.all_text()

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
            "oida.protocols.knx.cli_runner.get_knxproj_info",
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
            "oida.protocols.knx.cli_runner.get_knxproj_info",
            lambda p: {"project_id": "P1", "ets_version": "5", "password_protected": True},
        )
        c = self._conn(_make_args(knxproj=str(f)))
        assert c._handle_knxproj() is True
        assert any("password protected" in m.lower() for m in c.logger.records["fail"])

    def test_parses_unprotected_project(self, tmp_path, monkeypatch):
        f = tmp_path / "p.knxproj"
        f.write_bytes(b"PK\x03\x04dummy")
        monkeypatch.setattr(
            "oida.protocols.knx.cli_runner.get_knxproj_info",
            lambda p: {"project_id": "P1", "ets_version": "5", "password_protected": False},
        )
        monkeypatch.setattr(
            "oida.protocols.knx.cli_runner.parse_knxproj",
            lambda p, pw: {"devices": [{"address": "1.1.1"}]},
        )
        monkeypatch.setattr(
            "oida.protocols.knx.cli_runner.display_knxproj_data",
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
            "oida.protocols.knx.cli_runner.get_knxproj_info",
            lambda p: {"project_id": "P1", "ets_version": "5", "password_protected": True},
        )
        monkeypatch.setattr(
            "oida.protocols.knx.cli_runner.crack_knxproj",
            lambda *a, **k: "secret",
        )
        monkeypatch.setattr(
            "oida.protocols.knx.cli_runner.parse_knxproj",
            lambda p, pw: {"devices": []},
        )
        monkeypatch.setattr(
            "oida.protocols.knx.cli_runner.display_knxproj_data",
            lambda data, logger: None,
        )
        c = self._conn(_make_args(knxproj=str(f), knxproj_wordlist=str(wl)))
        assert c._handle_knxproj() is True
        findings = [t for t, _ in c.logger.findings()]
        assert "Weak password" in findings

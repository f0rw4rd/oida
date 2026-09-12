"""Unit tests for oida.protocols.knx.mixins.discovery.DiscoveryMixin.

Covers nm_individual_address_check-based device discovery (specific
address vs range), bus scanning, routing probe, find-by-serial validation
and response handling, gateway-info retrieval, and the fast-bus-scan
wrapper around CustomCEMIHandler.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

from tests.unit.knx._harness import FakeP2P, make_knx, make_payload, make_response


class TestDiscoverDevices:
    def test_specific_individual_address(self, host, patch_xknx_cls):
        host.args = {"individual-address": "1.1.7"}
        # nm check returns True for the one probed address
        patch_xknx_cls.nm_individual_address_check = AsyncMock(return_value=True)
        knx = make_knx(FakeP2P([]))
        devices = asyncio.run(host._discover_devices(knx))
        assert len(devices) == 1
        assert devices[0]["address"] == "1.1.7"
        assert devices[0]["accessible"] is True

    def test_range_scan_filters_occupied(self, host, patch_xknx_cls):
        host.args = {"scan-range": "1.1.1-1.1.3"}
        # occupied only for 1.1.2
        calls = {"1.1.1": False, "1.1.2": True, "1.1.3": False}
        patch_xknx_cls.nm_individual_address_check = AsyncMock(side_effect=lambda knx, a: calls[a])
        knx = make_knx(FakeP2P([]))
        devices = asyncio.run(host._discover_devices(knx))
        assert [d["address"] for d in devices] == ["1.1.2"]

    def test_probe_error_is_swallowed(self, host, patch_xknx_cls):
        host.args = {"individual-address": "1.1.7"}
        patch_xknx_cls.nm_individual_address_check = AsyncMock(side_effect=RuntimeError("boom"))
        knx = make_knx(FakeP2P([]))
        devices = asyncio.run(host._discover_devices(knx))
        assert devices == []


class TestScanBusDevices:
    def test_custom_range_only_checks_given(self, host, patch_xknx_cls):
        seen = []

        async def _check(knx, addr):
            seen.append(addr)
            return addr == "1.1.2"

        patch_xknx_cls.nm_individual_address_check = AsyncMock(side_effect=_check)
        knx = make_knx(FakeP2P([]))
        devices = asyncio.run(host._scan_bus_devices(knx, scan_range="1.1.1-1.1.3"))
        assert seen == ["1.1.1", "1.1.2", "1.1.3"]
        assert [d["address"] for d in devices] == ["1.1.2"]


class TestTestRouting:
    def test_routing_supported_when_put_succeeds(self, host, patch_xknx_cls):
        host.args = {"confirm": True}
        knx = make_knx(FakeP2P([]))
        res = asyncio.run(host._test_routing(knx))
        assert res["routing_supported"] is True
        knx.telegrams.put.assert_awaited()

    def test_routing_failure_recorded(self, host, patch_xknx_cls):
        host.args = {"confirm": True}
        knx = make_knx(FakeP2P([]))
        knx.telegrams.put.side_effect = RuntimeError("no route")
        res = asyncio.run(host._test_routing(knx))
        assert res["routing_supported"] is False
        assert any("no route" in e for e in res["errors"])

    def test_routing_probe_skipped_without_confirm(self, host, patch_xknx_cls):
        # No --confirm: the live GroupValueWrite probe must NOT be sent.
        host.args = {}
        knx = make_knx(FakeP2P([]))
        res = asyncio.run(host._test_routing(knx))
        assert res["routing_supported"] is False
        assert res["error"] == "Missing --confirm flag"
        knx.telegrams.put.assert_not_awaited()


class TestFindDeviceBySerial:
    def test_rejects_wrong_length_serial(self, host, patch_xknx_cls):
        knx = make_knx(FakeP2P([]))
        res = asyncio.run(host._find_device_by_serial(knx, "AABB"))
        assert res["success"] is False
        assert "12 hex chars" in res["error"]

    def test_found_returns_address(self, host, patch_xknx_cls):
        payload = make_payload(address="1.1.42")
        p2p = FakeP2P([make_response(payload=payload)])
        knx = make_knx(p2p)
        res = asyncio.run(host._find_device_by_serial(knx, "AABBCCDDEEFF"))
        assert res["success"] is True
        assert res["address"] == "1.1.42"

    def test_no_response(self, host, patch_xknx_cls):
        p2p = FakeP2P([None])
        knx = make_knx(p2p)
        res = asyncio.run(host._find_device_by_serial(knx, "AABBCCDDEEFF"))
        assert res["success"] is False
        assert res["error"] == "No response"

    def test_response_without_address(self, host, patch_xknx_cls):
        payload = make_payload()
        # make_payload sets a MagicMock; ensure .address resolves to None
        del payload.address
        payload.address = None
        p2p = FakeP2P([make_response(payload=payload)])
        knx = make_knx(p2p)
        res = asyncio.run(host._find_device_by_serial(knx, "AABBCCDDEEFF"))
        assert res["success"] is False
        assert "no address" in res["error"]


class TestReadDomainBySerial:
    def test_rejects_wrong_length_serial(self, host, patch_xknx_cls):
        knx = make_knx(FakeP2P([]))
        res = asyncio.run(host._read_domain_by_serial(knx, "AABB"))
        assert res["success"] is False
        assert "12 hex chars" in res["error"]

    def test_found_returns_domain_address(self, host, patch_xknx_cls):
        payload = make_payload(domain_address=bytes.fromhex("01A2"))
        p2p = FakeP2P([make_response(payload=payload)])
        knx = make_knx(p2p)
        res = asyncio.run(host._read_domain_by_serial(knx, "AABBCCDDEEFF"))
        assert res["success"] is True
        assert res["domain_address"] == "01A2"

    def test_no_response(self, host, patch_xknx_cls):
        p2p = FakeP2P([None])
        knx = make_knx(p2p)
        res = asyncio.run(host._read_domain_by_serial(knx, "AABBCCDDEEFF"))
        assert res["success"] is False
        assert res["error"] == "No response"

    def test_response_without_domain(self, host, patch_xknx_cls):
        payload = make_payload()
        del payload.domain_address
        payload.domain_address = None
        p2p = FakeP2P([make_response(payload=payload)])
        knx = make_knx(p2p)
        res = asyncio.run(host._read_domain_by_serial(knx, "AABBCCDDEEFF"))
        assert res["success"] is False
        assert "no domain address" in res["error"]


class TestGatewayInfo:
    def test_reads_connection_type(self, host):
        knx = MagicMock()
        cm = MagicMock()
        cm.connection_type = "TUNNELING"
        knx.connection_manager = cm
        info = asyncio.run(host._get_gateway_info(knx))
        assert info["connection_type"] == "TUNNELING"

    def test_missing_connection_manager(self, host):
        knx = MagicMock()
        knx.connection_manager = None
        info = asyncio.run(host._get_gateway_info(knx))
        assert "connection_type" not in info


class TestFastBusScan:
    def test_wraps_cemi_handler_results(self, host, patch_xknx_cls, monkeypatch):
        async def fake_discovery(self_h, scan_range, timeout=5, listen_time=0):
            return {
                "devices": {"1.1.3", "1.1.1"},
                "traffic": [{"source": "1.1.1", "destination": "1/2/3"}],
            }

        monkeypatch.setattr(
            "oida.protocols.knx.cemi_handler.CustomCEMIHandler.fast_bus_discovery",
            fake_discovery,
        )
        knx = make_knx(FakeP2P([]))
        res = asyncio.run(host._fast_bus_scan(knx, "1.1.1-1.1.3"))
        addrs = sorted(d["address"] for d in res["devices"])
        assert addrs == ["1.1.1", "1.1.3"]
        assert res["total_found"] == 2
        assert res["traffic"][0]["destination"] == "1/2/3"

    def test_handler_error_recorded(self, host, patch_xknx_cls, monkeypatch):
        async def boom(self_h, *a, **k):
            raise RuntimeError("handler died")

        monkeypatch.setattr(
            "oida.protocols.knx.cemi_handler.CustomCEMIHandler.fast_bus_discovery",
            boom,
        )
        knx = make_knx(FakeP2P([]))
        res = asyncio.run(host._fast_bus_scan(knx, "1.1.1"))
        assert res["error"] == "handler died"
        assert res["total_found"] == 0


class TestListenBusTraffic:
    def test_aggregates_captured_telegrams(self, host, patch_xknx_cls, monkeypatch):
        knx = MagicMock()
        captured_cb = {}
        knx.telegram_queue.register_telegram_received_cb = lambda cb: captured_cb.update(cb=cb)

        def tg(src, dst):
            t = MagicMock()
            t.source_address = src
            t.destination_address = dst
            t.payload = None
            return t

        # On the single duration=1 sleep, feed telegrams through the callback
        # the listener registered, then return.
        async def fake_sleep(_secs):
            cb = captured_cb["cb"]
            await cb(tg("1.1.1", "1/2/3"))
            await cb(tg("1.1.2", "1/2/3"))
            await cb(tg("1.1.1", "4/5/6"))

        monkeypatch.setattr("oida.protocols.knx.mixins.discovery.asyncio.sleep", fake_sleep)

        res = asyncio.run(host._listen_bus_traffic(knx, duration=1))
        assert sorted(res["devices"]) == ["1.1.1", "1.1.2"]
        assert res["group_addresses"]["1/2/3"]["count"] == 2
        assert sorted(res["group_addresses"]["1/2/3"]["sources"]) == ["1.1.1", "1.1.2"]
        assert len(res["telegrams"]) == 3


class TestReadGroupAddress:
    def test_returns_sensor_value(self, host, patch_xknx_cls, monkeypatch):
        sensor = MagicMock()
        sensor.sync = AsyncMock()
        sensor.sensor_value.value = 21.5
        sensor.sensor_value.last_payload = "DPT"

        monkeypatch.setattr("xknx.devices.Sensor", lambda *a, **k: sensor)
        monkeypatch.setattr("xknx.telegram.GroupAddress", lambda x: x)
        monkeypatch.setattr("oida.protocols.knx.mixins.discovery.asyncio.sleep", AsyncMock())
        knx = MagicMock()
        res = asyncio.run(host._read_group_address(knx, "1/2/3"))
        assert res["value"] == 21.5
        assert res["error"] is None
        sensor.sync.assert_awaited()

    def test_no_response(self, host, patch_xknx_cls, monkeypatch):
        sensor = MagicMock()
        sensor.sync = AsyncMock()
        sensor.sensor_value.value = None
        monkeypatch.setattr("xknx.devices.Sensor", lambda *a, **k: sensor)
        monkeypatch.setattr("xknx.telegram.GroupAddress", lambda x: x)
        monkeypatch.setattr("oida.protocols.knx.mixins.discovery.asyncio.sleep", AsyncMock())
        knx = MagicMock()
        res = asyncio.run(host._read_group_address(knx, "1/2/3"))
        assert res["value"] is None
        assert res["error"] == "No response received"

"""Unit tests for oida.protocols.knx.mixins.memory.MemoryMixin.

Covers chunked memory dump reassembly + early stop, the system-memory
write-block and --confirm gates, write verification, group-value writes,
device restart safety, and the memory/group arg parsers.
"""

import asyncio

from tests.unit.knx._harness import FakeP2P, make_knx, make_response


class TestDumpMemory:
    def test_reassembles_chunks(self, host, patch_xknx_cls):
        # max_chunk=12; 20 bytes -> 12 + 8
        p2p = FakeP2P([make_response(data=b"\x11" * 12), make_response(data=b"\x22" * 8)])
        knx = make_knx(p2p)
        res = asyncio.run(host._dump_memory(knx, "1.1.5", 0x0100, 20))
        assert res["data"] == ("11" * 12) + ("22" * 8)
        assert res["error"] is None
        assert res["hex_dump"]
        assert p2p.call_count == 2

    def test_early_stop_on_empty_chunk(self, host, patch_xknx_cls):
        p2p = FakeP2P([make_response(data=b"\xaa" * 12), make_response(data=None)])
        knx = make_knx(p2p)
        res = asyncio.run(host._dump_memory(knx, "1.1.5", 0x0100, 24))
        # only first chunk collected
        assert res["data"] == "aa" * 12
        assert any("Partial" in m for m in host.logger.records["warning"])

    def test_chunk_error_stops_read(self, host, patch_xknx_cls):
        p2p = FakeP2P([make_response(data=b"\xbb" * 12), RuntimeError("nak")])
        knx = make_knx(p2p)
        res = asyncio.run(host._dump_memory(knx, "1.1.5", 0x0100, 24))
        assert res["data"] == "bb" * 12

    def test_extended_memory_uses_16_chunks(self, host, patch_xknx_cls):
        p2p = FakeP2P([make_response(data=b"\x01" * 16)])
        knx = make_knx(p2p)
        res = asyncio.run(host._dump_extended_memory(knx, "1.1.5", 0x0000, 16))
        assert res["data"] == "01" * 16

    def test_user_memory_uses_10_chunks(self, host, patch_xknx_cls):
        p2p = FakeP2P([make_response(data=b"\x05" * 10), make_response(data=b"\x06" * 2)])
        knx = make_knx(p2p)
        res = asyncio.run(host._dump_user_memory(knx, "1.1.5", 0x0000, 12))
        assert res["data"] == ("05" * 10) + ("06" * 2)


class TestWriteMemory:
    def test_blocks_system_memory(self, host, patch_xknx_cls):
        host.args = {"confirm": True}
        knx = make_knx(FakeP2P([]))
        res = asyncio.run(host._write_memory(knx, "1.1.5", 0x0050, b"\x01"))
        assert res["success"] is False
        assert "BLOCKED" in res["error"]
        # never opened a connection
        assert knx.management.connection.call_count == 0

    def test_requires_confirm(self, host, patch_xknx_cls):
        host.args = {"confirm": False}
        knx = make_knx(FakeP2P([]))
        res = asyncio.run(host._write_memory(knx, "1.1.5", 0x0200, b"\x01"))
        assert res["error"] == "Missing --confirm flag"

    def test_write_and_verify_match(self, host, patch_xknx_cls):
        host.args = {"confirm": True}
        # first request = write (no response needed), second = readback
        p2p = FakeP2P([make_response(data=None), make_response(data=b"\x42")])
        knx = make_knx(p2p)
        res = asyncio.run(host._write_memory(knx, "1.1.5", 0x0200, b"\x42"))
        assert res["success"] is True
        assert res["verified"] is True

    def test_write_verify_mismatch(self, host, patch_xknx_cls):
        host.args = {"confirm": True}
        p2p = FakeP2P([make_response(data=None), make_response(data=b"\x00")])
        knx = make_knx(p2p)
        res = asyncio.run(host._write_memory(knx, "1.1.5", 0x0200, b"\x42"))
        assert res["success"] is True
        assert res["verified"] is False
        assert any("verification failed" in m for m in host.logger.records["warning"])


class TestWriteGroupValue:
    def test_puts_telegram(self, host, patch_xknx_cls):
        knx = make_knx(FakeP2P([]))
        res = asyncio.run(host._write_group_value(knx, "1/2/3", b"\x01"))
        assert res["success"] is True
        knx.telegrams.put.assert_awaited()

    def test_error_recorded(self, host, patch_xknx_cls):
        knx = make_knx(FakeP2P([]))
        knx.telegrams.put.side_effect = RuntimeError("queue full")
        res = asyncio.run(host._write_group_value(knx, "1/2/3", b"\x01"))
        assert res["success"] is False
        assert "queue full" in res["error"]


class TestRestartDevice:
    def test_requires_confirm(self, host, patch_xknx_cls):
        host.args = {"confirm": False}
        knx = make_knx(FakeP2P([]))
        res = asyncio.run(host._restart_device(knx, "1.1.5"))
        assert res["error"] == "Missing --confirm flag"
        assert res["success"] is False

    def test_restart_sent(self, host, patch_xknx_cls):
        host.args = {"confirm": True}
        knx = make_knx(FakeP2P([]))
        res = asyncio.run(host._restart_device(knx, "1.1.5"))
        assert res["success"] is True
        patch_xknx_cls.dm_restart.assert_awaited()

    def test_restart_error(self, host, patch_xknx_cls):
        host.args = {"confirm": True}
        patch_xknx_cls.dm_restart.side_effect = RuntimeError("boom")
        knx = make_knx(FakeP2P([]))
        res = asyncio.run(host._restart_device(knx, "1.1.5"))
        assert res["success"] is False
        assert "boom" in res["error"]


class TestParsers:
    def test_parse_memory_range_hex(self, host):
        assert host._parse_memory_range("0x100:256") == (0x100, 256)

    def test_parse_memory_range_decimal(self, host):
        assert host._parse_memory_range("256:16") == (256, 16)

    def test_parse_memory_range_invalid_returns_default(self, host):
        assert host._parse_memory_range("bad") == (0x0100, 256)
        assert host.logger.records["fail"]

    def test_parse_memory_write_hex_addr(self, host):
        assert host._parse_memory_write("0x200:abcd") == (0x200, b"\xab\xcd")

    def test_parse_memory_write_invalid(self, host):
        assert host._parse_memory_write("nope") == (0, b"")

    def test_parse_group_write(self, host):
        assert host._parse_group_write("1/2/3:01") == ("1/2/3", b"\x01")

    def test_parse_group_write_invalid(self, host):
        assert host._parse_group_write("bad") == ("0/0/0", b"")

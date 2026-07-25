"""Unit tests for oida.protocols.knx.mixins.properties.PropertiesMixin.

Covers PropertyValueRead/Write, the --confirm safety gate, property
fuzzing accounting, PropertyDescriptionRead access-rights decode, ADC
reads, and the pure decoder/formatter/arg-parser helpers.
"""

import asyncio
import struct

from tests.unit.knx._harness import (
    FakeP2P,
    ScriptedP2P,
    make_knx,
    make_mgmt,
    make_payload,
    make_response,
)
from unittest.mock import MagicMock


class TestReadProperty:
    def test_returns_hex_value(self, host, patch_xknx_cls):
        p2p = FakeP2P([make_response(data=b"\xde\xad")])
        knx = make_knx(p2p)
        res = asyncio.run(host._read_property(knx, "1.1.5", 0, 78))
        assert res["data"] == "dead"
        assert res["object_index"] == 0
        assert res["property_id"] == 78
        assert res["error"] is None

    def test_empty_payload_leaves_data_none(self, host, patch_xknx_cls):
        p2p = FakeP2P([make_response(data=None)])
        knx = make_knx(p2p)
        res = asyncio.run(host._read_property(knx, "1.1.5", 0, 78))
        assert res["data"] is None

    def test_connection_error_recorded(self, host, patch_xknx_cls):
        knx = make_knx(connection_error=OSError("down"))
        res = asyncio.run(host._read_property(knx, "1.1.5", 0, 78))
        assert "down" in res["error"]


class TestWriteProperty:
    def test_requires_confirm(self, host, patch_xknx_cls):
        host.args = {"confirm": False}
        knx = make_knx(FakeP2P([]))
        res = asyncio.run(host._write_property(knx, "1.1.5", "0:78:00FA"))
        assert res["success"] is False
        assert res["error"] == "Missing --confirm flag"
        # parsed fields still populated
        assert res["object_index"] == 0
        assert res["data"] == "00FA"

    def test_bad_format_rejected(self, host, patch_xknx_cls):
        host.args = {"confirm": True}
        knx = make_knx(FakeP2P([]))
        res = asyncio.run(host._write_property(knx, "1.1.5", "0:78"))
        assert "OBJ:PROP:HEXDATA" in res["error"]

    def test_successful_write(self, host, patch_xknx_cls):
        host.args = {"confirm": True}
        p2p = FakeP2P([make_response(data=b"")])
        knx = make_knx(p2p)
        res = asyncio.run(host._write_property(knx, "1.1.5", "0:78:00FA12"))
        assert res["success"] is True
        assert res["data"] == "00FA12"


class TestFuzzProperty:
    def test_requires_confirm(self, host, patch_xknx_cls):
        host.args = {"confirm": False}
        knx = make_knx(FakeP2P([]))
        res = asyncio.run(host._fuzz_property(knx, "1.1.5", "0:19", iterations=2))
        assert res["error"] == "Missing --confirm flag"
        assert res["success"] is False

    def test_bad_format(self, host, patch_xknx_cls):
        host.args = {"confirm": True}
        knx = make_knx(FakeP2P([]))
        res = asyncio.run(host._fuzz_property(knx, "1.1.5", "019", iterations=2))
        assert "OBJ:PROP" in res["error"]

    def test_runs_fuzz_iterations(self, host, patch_xknx_cls, monkeypatch):
        host.args = {"confirm": True}
        # patch fuzz() to a deterministic 2-payload generator
        import oida.utils.fuzzer as fz

        monkeypatch.setattr(fz, "fuzz", lambda data, count=10: [(b"\x01", "a"), (b"\x02", "b")])
        # read original, then per iteration: write(echo), readback; then restore write
        responses = [
            make_response(data=b"\x00"),  # original read
            make_response(data=b""),  # write payload 1
            make_response(data=b"\x01"),  # readback 1
            make_response(data=b""),  # write payload 2
            make_response(data=b"\x02"),  # readback 2
            make_response(data=b""),  # restore original
        ]
        knx = make_knx(FakeP2P(responses))
        res = asyncio.run(host._fuzz_property(knx, "1.1.5", "0:19", iterations=2))
        assert res["success"] is True


class TestReadPropertyDescription:
    def test_decodes_access_levels_writable(self, host, patch_xknx_cls):
        # access 0x3F -> read_level 3, write_level 15 -> not writable
        # use access 0x31 -> read 3, write 1 -> writable
        payload = make_payload(type_=0x10, max_count=4, access=0x31)
        p2p = FakeP2P([make_response(payload=payload)])
        knx = make_knx(p2p)
        res = asyncio.run(host._read_property_description(knx, "1.1.5", "0:78"))
        assert res["read_level"] == 3
        assert res["write_level"] == 1
        assert res["writable"] is True
        assert res["max_count"] == 4

    def test_write_level_15_not_writable(self, host, patch_xknx_cls):
        payload = make_payload(type_=0x10, max_count=1, access=0x3F)
        p2p = FakeP2P([make_response(payload=payload)])
        knx = make_knx(p2p)
        res = asyncio.run(host._read_property_description(knx, "1.1.5", "0:78"))
        assert res["writable"] is False

    def test_no_payload(self, host, patch_xknx_cls):
        p2p = FakeP2P([make_response(payload=None)])
        knx = make_knx(p2p)
        res = asyncio.run(host._read_property_description(knx, "1.1.5", "0:78"))
        assert res["error"] == "No response or empty payload"

    def test_bad_format(self, host, patch_xknx_cls):
        knx = make_knx(FakeP2P([]))
        res = asyncio.run(host._read_property_description(knx, "1.1.5", "078"))
        assert "OBJ:PROP" in res["error"]


class TestReadAdc:
    def test_returns_value(self, host, patch_xknx_cls):
        p2p = FakeP2P([make_response(value=1023)])
        knx = make_knx(p2p)
        res = asyncio.run(host._read_adc(knx, "1.1.5", 1))
        assert res["value"] == 1023
        assert res["channel"] == 1

    def test_error_recorded(self, host, patch_xknx_cls):
        knx = make_knx(connection_error=OSError("nope"))
        res = asyncio.run(host._read_adc(knx, "1.1.5", 1))
        assert "nope" in res["error"]


class TestDecodePropertyValue:
    def test_manufacturer_id_special(self, host):
        out = host._decode_property_value(struct.pack(">H", 1), 0x04, 12)
        assert "Siemens" in out and "(1)" in out

    def test_char(self, host):
        assert host._decode_property_value(b"A", 0x01, 5) == repr("A")

    def test_unsigned_char(self, host):
        assert host._decode_property_value(b"\x2a", 0x02, 5) == "42"

    def test_signed_int(self, host):
        assert host._decode_property_value(struct.pack(">h", -5), 0x03, 5) == "-5"

    def test_uint(self, host):
        assert host._decode_property_value(struct.pack(">H", 65000), 0x04, 5) == "65000"

    def test_ulong(self, host):
        assert host._decode_property_value(struct.pack(">I", 100000), 0x09, 5) == "100000"

    def test_float(self, host):
        assert host._decode_property_value(struct.pack(">f", 1.5), 0x0A, 5) == "1.5000"

    def test_empty(self, host):
        assert host._decode_property_value(b"", 0x04, 5) == ""

    def test_unknown_type_falls_back_to_hex(self, host):
        assert host._decode_property_value(b"\xab\xcd", 0x3F, 5) == "ABCD"


class TestFormattersAndParsers:
    def test_format_property_line_writeable(self, host):
        line = host._format_property_line(0, 78, "SERIAL", "ABCD", "UINT", 3, 1, True)
        assert "0:78" in line and "[writeable]" in line and "R:3 W:1" in line

    def test_object_type_name_vendor(self, host):
        assert "Vendor-Specific" in host._get_object_type_name(210)

    def test_parse_property_arg_ok(self, host):
        assert host._parse_property_arg("3:78") == (3, 78)

    def test_parse_property_arg_invalid_returns_sentinel(self, host):
        # Malformed input must never fall back to a hardcoded default
        # object/property — that would silently read from a real device.
        assert host._parse_property_arg("bad") == (None, None)
        assert host.logger.records["fail"]


class TestEnumerateObjects:
    def test_discovers_objects_without_property_pass(self, host, patch_xknx_cls):
        # object-type PropertyValueRead (PID 1) returns a type for the first
        # 2 indices then None; >10 consecutive Nones stop the scan.
        seq = [
            make_response(data=b"\x00\x00"),  # obj 0 -> type 0 (Device)
            make_response(data=b"\x00\x01"),  # obj 1 -> type 1 (Address table)
        ] + [make_response(data=None)] * 12  # trailing misses -> stop after 11
        knx = make_knx(FakeP2P(seq))
        res = asyncio.run(
            host._enumerate_objects(knx, "1.1.5", max_objects=20, read_properties=False)
        )
        assert res["total_objects"] == 2
        assert res["objects"][0]["index"] == 0
        assert res["objects"][1]["type"] == 1

    def test_short_data_decoded_as_single_byte(self, host, patch_xknx_cls):
        seq = [make_response(data=b"\x07")] + [make_response(data=None)] * 12
        knx = make_knx(FakeP2P(seq))
        res = asyncio.run(
            host._enumerate_objects(knx, "1.1.5", max_objects=20, read_properties=False)
        )
        assert res["total_objects"] == 1
        assert res["objects"][0]["type"] == 7

    def test_connection_error_sets_error(self, host, patch_xknx_cls):
        knx = make_knx(connection_error=OSError("nope"))
        res = asyncio.run(
            host._enumerate_objects(knx, "1.1.5", max_objects=5, read_properties=False)
        )
        assert "nope" in res["error"]


class TestDiscoverVendorObjects:
    def test_finds_vendor_object_then_stops(self, host, patch_xknx_cls):
        # index 200: a real vendor object (type!=0); then name read; then
        # subsequent PropertyDescriptionRead all "miss" -> stop after 5.
        desc_hit = make_response(payload=make_payload(type_=5, max_count=3, access=0x11))
        name_resp = make_response(data=b"MyVendorObj\x00")

        def handler(payload):
            # first description read returns the hit, the rest return None
            return None

        # use positional FakeP2P: obj200 desc(hit), name read, then misses
        seq = [desc_hit, name_resp] + [None] * 5
        knx = make_knx(FakeP2P(seq))
        res = asyncio.run(host._discover_vendor_objects(knx, "1.1.5"))
        assert res["total_found"] == 1
        assert res["vendor_objects"][0]["index"] == 200
        assert res["vendor_objects"][0]["name"] == "MyVendorObj"

    def test_false_positive_object_filtered(self, host, patch_xknx_cls):
        # type=0, max_count<=1, access=0 -> not a real object
        false_obj = make_response(payload=make_payload(type_=0, max_count=0, access=0))
        seq = [false_obj] * 6  # all false -> stop after 5 consecutive failures
        knx = make_knx(FakeP2P(seq))
        res = asyncio.run(host._discover_vendor_objects(knx, "1.1.5"))
        assert res["total_found"] == 0


class TestDumpAllProperties:
    def test_dump_completes_with_skipped_properties(self, host, patch_xknx_cls):
        # 1 object discovered (PID-1 read), every PropertyDescriptionRead has
        # max_count==0 so all 255 props are skipped -> clean completion.
        def dispatch(payload):
            name = getattr(payload, "_req_name", "")
            if name == "PropertyValueRead":
                # only the discovery read (PID 1) yields object type
                pid = payload.kwargs.get("property_id")
                if pid == 1:
                    return make_response(data=b"\x00\x00")
                return make_response(data=None)
            if name == "PropertyDescriptionRead":
                return make_response(payload=make_payload(max_count=0, type_=0, access=0))
            return None

        p2p = ScriptedP2P(handlers={}, default=dispatch)
        knx = MagicMock()
        knx.management = make_mgmt(p2p)
        res = asyncio.run(host._dump_all_properties(knx, "1.1.5", max_objects=1))
        assert res["error"] is None
        assert len(res["objects"]) == 1
        assert res["total_properties"] == 0

    def test_dump_records_property_with_values(self, host, patch_xknx_cls):
        def dispatch(payload):
            name = getattr(payload, "_req_name", "")
            if name == "PropertyValueRead":
                pid = payload.kwargs.get("property_id")
                start = payload.kwargs.get("start_index")
                if pid == 1 and start == 1:
                    return make_response(data=b"\x00\x00")  # object type for discovery
                # value reads for a discovered property
                return make_response(data=b"\xab")
            if name == "PropertyDescriptionRead":
                pid = payload.kwargs.get("property_id")
                # exactly one property (PID 5) is real, max_count=1
                if pid == 5:
                    return make_response(payload=make_payload(max_count=1, type_=0x04, access=0x31))
                return make_response(payload=make_payload(max_count=0, type_=0, access=0))
            return None

        p2p = ScriptedP2P(handlers={}, default=dispatch)
        knx = MagicMock()
        knx.management = make_mgmt(p2p)
        res = asyncio.run(host._dump_all_properties(knx, "1.1.5", max_objects=1))
        assert res["total_properties"] == 1
        prop = res["objects"][0]["properties"][0]
        assert prop["property_id"] == 5
        assert prop["values"] == ["ab"]
        assert prop["access_read"] == 3
        assert prop["access_write"] == 1

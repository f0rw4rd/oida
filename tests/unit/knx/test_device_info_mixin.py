"""Unit tests for oida.protocols.knx.mixins.device_info.DeviceInfoMixin.

Covers device identification (descriptor + Object-0 property decoding,
manufacturer/serial/prog-mode/APDU parsing, memory fallbacks), firmware
info reads, programming-mode detection (property + memory fallback) and
the display formatter.
"""

import asyncio

from tests.unit.knx._harness import FakeP2P, make_knx, make_payload, make_response


# DEVICE_PROPS read order in _identify_device after the descriptor:
# 12 (mfr), 11 (serial), 55 (product), 78 (hw), 9 (fw), 15 (order),
# 93 (app_ver), 91 (app_id), 54 (prog_mode), 53 (err_flags),
# 56 (max_apdu), 16 (pei). 12 properties total.


def _descriptor(value):
    """DeviceDescriptorResponse payload exposes .value."""
    return make_response(payload=make_payload(value=value))


class TestIdentifyDevice:
    def test_full_property_decode(self, host, patch_xknx_cls):
        responses = [
            _descriptor(b"\x07\xb0"),  # descriptor -> mask 07b0
            make_response(data=b"\x00\x01"),  # 12 manufacturer_id = 1 (Siemens)
            make_response(data=bytes.fromhex("0102030405ee")),  # 11 serial
            make_response(data=b"\xaa"),  # 55 product_id
            make_response(data=b"\xbb"),  # 78 hardware_type
            make_response(data=b"\xcc"),  # 9 firmware_revision
            make_response(data=b"\xab\xcd"),  # 15 order_info
            make_response(data=b"\x01"),  # 93 app_version
            make_response(data=b"\x02"),  # 91 application_id
            make_response(data=b"\x01"),  # 54 prog_mode ON
            make_response(data=b"\x05"),  # 53 error_flags = 5
            make_response(data=b"\x00\xff"),  # 56 max_apdu = 255
            make_response(data=b"\x10"),  # 16 pei_type
        ]
        knx = make_knx(FakeP2P(responses))
        info = asyncio.run(host._identify_device(knx, "1.1.5"))

        assert info["manufacturer_id"] == 1
        assert info["manufacturer_name"] == "Siemens"
        assert info["serial_number"] == "0102030405EE"
        assert info["prog_mode"] == "ON"
        assert info["error_flags"] == 5
        assert info["max_apdu"] == 255
        assert info["descriptor"] == "07B0"
        assert info["mask_version"] == "07B0"
        # generic hex-stored props are uppercased
        assert info["product_id"] == "AA"
        assert info["order_info"] == "ABCD"
        assert info["pei_type"] == "10"

    def test_prog_mode_off_when_zero(self, host, patch_xknx_cls):
        # property order: 12,11,55,78,9,15,93,91,54,... -> prog_mode is 9th prop
        responses = [_descriptor(b"\x00\x12")] + [make_response(data=None)] * 8
        responses.append(make_response(data=b"\x00"))  # 54 prog_mode OFF
        responses += [make_response(data=None)] * 3
        knx = make_knx(FakeP2P(responses))
        info = asyncio.run(host._identify_device(knx, "1.1.5"))
        assert info["prog_mode"] == "OFF"

    def test_manufacturer_memory_fallback(self, host, patch_xknx_cls):
        # descriptor ok, all 12 property reads return no data, then memory
        # fallback for manufacturer (0x0104) and serial (0x010B).
        responses = [_descriptor(b"\x00\x12")]
        responses += [make_response(data=None)] * 12  # property reads empty
        responses.append(make_response(data=b"\x00\x02"))  # mfr fallback -> 2 (ABB)
        responses.append(make_response(data=bytes.fromhex("aabbccddeeff")))  # serial fallback
        knx = make_knx(FakeP2P(responses))
        info = asyncio.run(host._identify_device(knx, "1.1.5"))
        assert info["manufacturer_id"] == 2
        assert info["manufacturer_name"] == "ABB"
        assert info["serial_number"] == "AABBCCDDEEFF"

    def test_property_error_recorded(self, host, patch_xknx_cls):
        responses = [_descriptor(b"\x00\x12")]
        responses += [RuntimeError("nak")] * 12
        responses += [make_response(data=None), make_response(data=None)]
        knx = make_knx(FakeP2P(responses))
        info = asyncio.run(host._identify_device(knx, "1.1.5"))
        assert any("PID 12" in e for e in info["errors"])

    def test_connection_failure_recorded(self, host, patch_xknx_cls):
        knx = make_knx(connection_error=OSError("refused"))
        info = asyncio.run(host._identify_device(knx, "1.1.5"))
        assert any("connection" in e for e in info["errors"])
        assert info["manufacturer_id"] is None


class TestReadFirmwareInfo:
    def test_reads_props_and_mask(self, host, patch_xknx_cls):
        # descriptor then 5 FIRMWARE_PROPS: 9,78,55,15,16
        responses = [
            _descriptor(b"\x07\xb0"),
            make_response(data=b"\x01"),  # 9 firmware_revision
            make_response(data=b"\x02"),  # 78 hardware_type
            make_response(data=b"\x03"),  # 55 product_id
            make_response(data=b"\x04"),  # 15 order_info
            make_response(data=b"\x05"),  # 16 pei_type
        ]
        knx = make_knx(FakeP2P(responses))
        info = asyncio.run(host._read_firmware_info(knx, "1.1.7"))
        assert info["firmware_revision"] == "01"
        assert info["hardware_type"] == "02"
        assert info["mask_version"] == "07b0"  # hex, not upper here
        assert info["bcu_type"]  # resolved from data.parse_bcu_type

    def test_firmware_connection_error(self, host, patch_xknx_cls):
        knx = make_knx(connection_error=OSError("boom"))
        info = asyncio.run(host._read_firmware_info(knx, "1.1.7"))
        assert any("connection" in e for e in info["errors"])


class TestCheckProgrammingMode:
    def test_property_method_used_first(self, host, patch_xknx_cls):
        p2p = FakeP2P([make_response(data=b"\x01")])
        knx = make_knx(p2p)
        res = asyncio.run(host._check_programming_mode(knx, "1.1.5"))
        assert res["programming_mode"] is True
        assert res["method"] == "property"
        assert p2p.call_count == 1  # memory fallback not reached

    def test_memory_fallback_when_property_fails(self, host, patch_xknx_cls):
        # property read raises -> fall through to memory read at 0x011A
        p2p = FakeP2P([RuntimeError("no prop"), make_response(data=b"\x00")])
        knx = make_knx(p2p)
        res = asyncio.run(host._check_programming_mode(knx, "1.1.5"))
        assert res["method"] == "memory"
        assert res["programming_mode"] is False

    def test_both_methods_fail(self, host, patch_xknx_cls):
        p2p = FakeP2P([RuntimeError("no prop"), RuntimeError("no mem")])
        knx = make_knx(p2p)
        res = asyncio.run(host._check_programming_mode(knx, "1.1.5"))
        assert res["method"] is None
        assert res["error"] == "no mem"
        assert any("Programming mode check failed" in m for m in host.logger.records["fail"])


class TestDisplayDeviceInfo:
    def test_warns_on_prog_mode_on_and_error_flags(self, host):
        info = {
            "address": "1.1.5",
            "manufacturer_id": 1,
            "manufacturer_name": "Siemens",
            "serial_number": "AABB",
            "prog_mode": "ON",
            "error_flags": 0x10,
            "max_apdu": 254,
        }
        host._display_device_info(info)
        warns = "\n".join(host.logger.records["warning"])
        assert "Prog Mode" in warns
        assert "Error Flags" in warns

    def test_decodes_ascii_order_info(self, host):
        # "ABC" -> hex 414243
        info = {"address": "1.1.5", "order_info": "414243"}
        host._display_device_info(info)
        disp = "\n".join(host.logger.records["display"])
        assert "ABC" in disp

    def test_warns_when_no_data(self, host):
        info = {"address": "1.1.5", "manufacturer_id": None}
        host._display_device_info(info)
        assert any("No device data" in m for m in host.logger.records["warning"])

"""
Regression tests for four confirmed bugs found during discovery-module review:

- A4: BACnetScanner._parse_i_am_response mis-skips routed (DLEN > 0) NPCI
      destination blocks, misaligning the APDU parse.
- A5: ADSScanner._parse_tlv_tags's TLV walker boundary drops a final,
      complete 4-byte tag header (with a zero-length value).
- A6: LLDPPassiveListener._parse_management_address dispatches on address
      length alone instead of checking management_address_subtype like its
      active sibling (LLDPScanner._parse_management_address) does.
- A1: The "lldp" entry in scanner.py's _SCANNER_CONFIGS registry returns a
      dict from its args_builder instead of the tuple every other entry
      returns, which _run_scanner() would blow up on if lldp were ever
      routed through it.
"""

import struct
import threading
from unittest import mock

import pytest

from oida.protocols.discovery.ics import ADSScanner, BACnetScanner
from oida.protocols.discovery.lldp import LLDPPassiveListener
from oida.protocols.discovery import scanner as scanner_module


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_bacnet():
    s = BACnetScanner.__new__(BACnetScanner)
    s.discovered_devices = {}
    s._lock = threading.Lock()
    return s


def _make_ads():
    s = ADSScanner.__new__(ADSScanner)
    s.discovered_devices = {}
    s._lock = threading.Lock()
    return s


def build_bacnet_i_am_routed(device_instance, vendor_id, max_apdu, dlen, dadr=b"") -> bytes:
    """Build a BACnet/IP I-Am response with a routed (DNET-present) NPCI.

    NPCI destination block layout per ASHRAE 135:
        DNET(2) + DLEN(1) + DADR(DLEN bytes) + HopCount(1)
    """
    assert len(dadr) == dlen

    obj_id = (8 << 22) | device_instance  # object type 8 = device
    # I-Am-Request carries APPLICATION-tagged primitives (ASHRAE 135 clause 21):
    #   app tag 12 -> BACnetObjectIdentifier (4 octets)
    #   app tag 2  -> Unsigned; 1st occurrence = maxAPDULengthAccepted, 2nd = vendorID
    #   app tag 9  -> Enumerated segmentationSupported
    iam = b""
    iam += bytes([0xC4]) + struct.pack(">I", obj_id)  # app tag 12 (Object ID), len 4
    iam += bytes([0x21, max_apdu])  # app tag 2 (Unsigned) -> maxAPDU (1st Unsigned), len 1
    iam += bytes([0x91, 0x00])  # app tag 9 (Enumerated) -> segmentation, len 1
    iam += bytes([0x21, vendor_id])  # app tag 2 (Unsigned) -> vendorID (2nd Unsigned), len 1

    apdu = bytes([0x10, 0x00]) + iam  # unconfirmed request (pdu type 1), I-Am (0x00)

    npdu_control = 0x20  # DNET present, SNET absent
    dnet_block = struct.pack(">H", 0) + bytes([dlen]) + dadr + bytes([0xFF])  # + HopCount
    npdu = bytes([0x01, npdu_control]) + dnet_block

    bvlc = bytes([0x81, 0x0A]) + struct.pack(">H", 4 + len(npdu) + len(apdu))
    return bvlc + npdu + apdu


class _FakeManagementTLV:
    def __init__(self, subtype, addr):
        self.management_address_subtype = subtype
        self.management_address = addr


# ---------------------------------------------------------------------------
# A4: BACnet routed I-Am DLEN handling
# ---------------------------------------------------------------------------


class TestBACnetRoutedIAm:
    def test_dlen_zero_control_case(self):
        """DLEN == 0 already works today; this is the control case."""
        s = _make_bacnet()
        pkt = build_bacnet_i_am_routed(12345, 7, 5, dlen=0)
        s._parse_i_am_response(pkt, "10.0.0.1")

        assert "10.0.0.1" in s.discovered_devices
        dev = s.discovered_devices["10.0.0.1"]
        assert dev.bacnet_data["device_instance"] == 12345
        assert dev.bacnet_data["vendor_id"] == 7
        assert dev.bacnet_data["max_apdu"] == 5

    def test_dlen_six_parses_identically_to_dlen_zero(self):
        """DLEN == 6 (a real routed DADR) must parse to the same I-Am content."""
        s = _make_bacnet()
        pkt = build_bacnet_i_am_routed(12345, 7, 5, dlen=6, dadr=b"\xaa" * 6)
        s._parse_i_am_response(pkt, "10.0.0.2")

        assert "10.0.0.2" in s.discovered_devices
        dev = s.discovered_devices["10.0.0.2"]
        assert dev.bacnet_data["device_instance"] == 12345
        assert dev.bacnet_data["vendor_id"] == 7
        assert dev.bacnet_data["max_apdu"] == 5


# ---------------------------------------------------------------------------
# A5: ADS UDP TLV walker boundary
# ---------------------------------------------------------------------------


class TestADSTLVWalkerBoundary:
    def test_final_complete_4byte_tag_header_is_examined(self):
        """A single 4-byte tag header (zero-length value) exactly fills the
        buffer. The walker must at least enter the loop and inspect it
        instead of silently dropping it because 0 bytes "remain" past the
        header under the old `pos < len(data) - 4` boundary.
        """
        s = _make_ads()
        data = struct.pack("<HH", ADSScanner.ADS_UDP_TAG["HOSTNAME"], 0)
        assert len(data) == 4

        calls = []
        real_unpack = struct.unpack

        def spy_unpack(fmt, buf):
            calls.append(fmt)
            return real_unpack(fmt, buf)

        with mock.patch("oida.protocols.discovery.ics.struct.unpack", side_effect=spy_unpack):
            result = s._parse_tlv_tags(data)

        assert calls, "TLV walker never inspected the final complete tag header"
        assert result == {}

    def test_no_infinite_loop_on_zero_length_tag(self):
        """Regression guard: a zero-length tag must not spin the walker
        forever now that the boundary lets the final header be read.
        """
        s = _make_ads()
        data = struct.pack("<HH", ADSScanner.ADS_UDP_TAG["HOSTNAME"], 0) + b"\x00" * 8
        result = s._parse_tlv_tags(data)
        assert result == {}


# ---------------------------------------------------------------------------
# A6: LLDP passive management-address subtype handling
# ---------------------------------------------------------------------------


class TestLLDPPassiveManagementAddress:
    def test_ipv4_subtype_still_parsed(self):
        """Control case: subtype 1 (IPv4) + 4-byte address must still work."""
        listener = LLDPPassiveListener.__new__(LLDPPassiveListener)
        tlv = _FakeManagementTLV(subtype=1, addr=b"\xc0\xa8\x00\x01")
        assert listener._parse_management_address(tlv) == "192.168.0.1"

    def test_non_ipv4_subtype_with_4byte_address_not_misread_as_ipv4(self):
        """A 4-byte management address whose subtype is NOT IPv4 (e.g. an
        interface-index or other non-IP addressing family) must not be
        printed as a bogus dotted-quad IP just because the length matches.
        """
        listener = LLDPPassiveListener.__new__(LLDPPassiveListener)
        tlv = _FakeManagementTLV(subtype=2, addr=b"\x01\x02\x03\x04")
        assert listener._parse_management_address(tlv) is None


# ---------------------------------------------------------------------------
# A1: scanner registry args_builder contract
# ---------------------------------------------------------------------------


class _DummyScannerState:
    """Stand-in for DiscoveryScanner exposing every attribute any
    args_builder in _SCANNER_CONFIGS references."""

    interface = "eth0"
    timeout = 5
    arp_timeout = 5
    subnet = "192.168.1.0/24"
    logger = mock.MagicMock()


class TestScannerRegistryContract:
    def test_all_args_builders_return_tuples(self):
        dummy = _DummyScannerState()
        offenders = []
        for name, config in scanner_module._SCANNER_CONFIGS.items():
            args_builder = config[1]
            built = args_builder(dummy)
            if not isinstance(built, tuple):
                offenders.append((name, type(built)))

        assert offenders == [], (
            f"args_builder(s) not returning a tuple (breaks `list(args_builder(self))` "
            f"unpacking in _run_scanner): {offenders}"
        )

    def test_lldp_args_builder_is_a_one_tuple_dict(self):
        dummy = _DummyScannerState()
        args_builder = scanner_module._SCANNER_CONFIGS["lldp"][1]
        built = args_builder(dummy)
        assert built == ({"interface": "eth0", "timeout": 5},)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

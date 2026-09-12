"""Regression tests for DNP3 passive-listener IIN correctness bugs.

Two linked bugs found in the pcap bug hunt:

1. ``DNP3PassiveListener._parse_int_field`` used a bare ``int(raw)``.  tshark
   declares ``dnp3.al.iin`` as FT_UINT16 / BASE_HEX, so in pyshark's XML mode
   -- which is what ``PySharkListenerBase._capture_live`` uses against a live
   interface -- the value arrives rendered as ``"0x9000"``.  ``int("0x9000")``
   raised, the exception was swallowed, and ``details["iin"]`` was always
   ``None``: the IIN harvest column, the IIN-driven ``rw="error"``
   classification and ``_decode_iin`` were all dead on the live path.
   EK mode happened to work because it yields a native int, so the shared
   ``_run_listener_test`` helper (which prefers EK mode) could never catch it.

2. ``_decode_iin`` had IIN1 and IIN2 swapped.  ``dnp3.al.iin`` is one
   big-endian 16-bit value: IIN1 is the HIGH byte, IIN2 the LOW byte.  The
   tests below pin that against tshark's own per-bit subfields
   (``dnp3.al.iin.rst`` etc.), which is the authoritative cross-check.
"""

import asyncio
import subprocess

import pytest

from .conftest import _pcap_path, _skip_unless_pyshark

pytestmark = [pytest.mark.integration]

FIXTURE = ("dnp3", "bro_dnp3.pcap")


def _feed(pcap_path, use_ek):
    """Run the DNP3 listener over *pcap_path* in the requested pyshark mode."""
    import pyshark

    from oida.pcap.dnp3 import DNP3PassiveListener

    asyncio.set_event_loop(asyncio.new_event_loop())
    kwargs = {"input_file": str(pcap_path), "display_filter": "dnp3"}
    if use_ek:
        kwargs["use_ek"] = True
    cap = pyshark.FileCapture(**kwargs)
    listener = DNP3PassiveListener(interface="lo", timeout=10)
    packets = list(cap)
    try:
        cap.close()
    except Exception:
        pass
    listener.feed_packets(iter(packets))
    return listener


def _tshark_iin_values(pcap_path):
    """Distinct dnp3.al.iin values tshark itself reports, as ints."""
    proc = subprocess.run(
        ["tshark", "-r", str(pcap_path), "-Y", "dnp3.al.iin", "-T", "fields", "-e", "dnp3.al.iin"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if proc.returncode != 0:
        pytest.skip("tshark could not read the dnp3 fixture")
    out = set()
    for line in proc.stdout.split("\n"):
        line = line.strip()
        if line:
            out.add(int(line, 16))
    return out


class TestDNP3IINParsedInXmlMode:
    """Bug 1: BASE_HEX dnp3.al.iin must parse in XML mode too."""

    def test_xml_mode_extracts_iin(self):
        _skip_unless_pyshark()
        pcap = _pcap_path(*FIXTURE)
        listener = _feed(pcap, use_ek=False)

        assert listener.interactions, "listener produced no interactions"
        parsed = {
            ix.details["iin"] for ix in listener.interactions if ix.details.get("iin") is not None
        }
        # Before the fix this set was empty: int("0x9000") raised and the
        # ValueError was swallowed.
        assert parsed, (
            "no interaction carries details['iin'] in XML mode -- the BASE_HEX "
            "value is being parsed base-10 again"
        )
        assert parsed & {0x8000, 0x9000, 0x1001}, (
            f"expected the fixture's known non-zero IIN values, got {[hex(v) for v in parsed]}"
        )

    def test_xml_and_ek_modes_agree(self):
        _skip_unless_pyshark()
        pcap = _pcap_path(*FIXTURE)
        xml = {
            ix.details["iin"]
            for ix in _feed(pcap, use_ek=False).interactions
            if ix.details.get("iin") is not None
        }
        ek = {
            ix.details["iin"]
            for ix in _feed(pcap, use_ek=True).interactions
            if ix.details.get("iin") is not None
        }
        assert xml == ek, (
            f"XML mode and EK mode disagree on IIN values: "
            f"xml={sorted(hex(v) for v in xml)} ek={sorted(hex(v) for v in ek)}"
        )

    def test_parsed_iin_values_match_tshark(self):
        _skip_unless_pyshark()
        pcap = _pcap_path(*FIXTURE)
        expected = _tshark_iin_values(pcap)
        parsed = {
            ix.details["iin"]
            for ix in _feed(pcap, use_ek=False).interactions
            if ix.details.get("iin") is not None
        }
        missing = expected - parsed
        assert not missing, (
            f"IIN values tshark reports but the listener dropped: "
            f"{sorted(hex(v) for v in missing)}"
        )


class TestDNP3IINByteOrder:
    """Bug 2: IIN1 is the HIGH byte, IIN2 the LOW byte.

    Each expectation below is anchored to a tshark per-bit subfield observed on
    tests/fixtures/pcap/dnp3/bro_dnp3.pcap:
        0x8000 -> dnp3.al.iin.rst   (Device Restart,          IIN1 bit 0x80)
        0x1000 -> dnp3.al.iin.tsr   (Time Sync Required,      IIN1 bit 0x10)
        0x1001 -> tsr + fcni        (Func Code Not Impl,      IIN2 bit 0x01)
        0x9501 -> rst + tsr + fcni
    """

    @pytest.mark.parametrize(
        "value,required",
        [
            (0x8000, {"RESTART"}),
            (0x1000, {"NEED_TIME"}),
            (0x1001, {"NEED_TIME", "NO_FUNC"}),
            (0x9501, {"RESTART", "NEED_TIME", "NO_FUNC"}),
            (0x0001, {"NO_FUNC"}),
        ],
    )
    def test_decode_iin_matches_tshark_bit_semantics(self, value, required):
        from oida.pcap.dnp3 import _decode_iin

        flags = {f for f in _decode_iin(value).split(",") if f}
        assert required <= flags, (
            f"_decode_iin({value:#06x}) = {sorted(flags)}; missing {sorted(required - flags)} "
            f"-- IIN1/IIN2 byte order is swapped again"
        )

    def test_iin2_error_bits_drive_rw_error(self):
        """rw='error' must key off IIN2 (low byte), not IIN1 (high byte)."""
        from oida.pcap.dnp3 import _IIN2_ERROR_BITS

        # 0x0001 = IIN2 "function code not implemented" -> a real error.
        assert (0x0001 & 0xFF) & _IIN2_ERROR_BITS, "real IIN2 error bit not detected in low byte"
        # 0x8000 = IIN1 "device restart" only -> must NOT look like an IIN2 error.
        assert not ((0x8000 & 0xFF) & _IIN2_ERROR_BITS), (
            "IIN1-only value misread as an IIN2 error condition"
        )
        # The pre-fix expression read the high byte, which inverted both above.
        assert not ((0x0001 >> 8) & 0xFF) & _IIN2_ERROR_BITS
        assert ((0x9501 >> 8) & 0xFF) & _IIN2_ERROR_BITS, (
            "sanity: the old high-byte read did produce a false positive on 0x9501"
        )

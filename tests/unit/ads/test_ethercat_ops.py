#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for the EtherCAT-over-ADS bridge operations mixin (ethercat_ops.py).

ethercat_ops.py is raw-L2/pysoem/pyads-backed and cannot be exercised over a
real network in CI (the bridge interface cannot be opened). These tests instead
drive the *pure logic* — datagram/offset construction, parsing of returned
buffers, CoE/SoE/FSoE/ESC/EEPROM decoding, error classification and formatting.

The ONLY thing mocked is the transport boundary: the pyads ``Connection``
object. A ``FakeConn`` returns real on-the-wire byte buffers from
``read``/``read_write``/``write`` keyed on (index_group, index_offset). The
shared helpers (`_read_raw`, `_read_coe_sdo`, struct parsing, error parsing)
and every mixin method under test run for real against those buffers.
"""

import ctypes
import struct
import unittest
from unittest.mock import Mock, patch

from oida.protocols.ads.ethercat_ops import EtherCATOpsMixin, MAX_SLAVE_PORTS
from oida.protocols.ethercat.coe import encode_sdo_offset
from oida.protocols.ethercat.soe import encode_soe_offset
from oida.protocols.ads.constants import ADS_IDX_GRP


# ---------------------------------------------------------------------------
# Fake pyads transport
# ---------------------------------------------------------------------------


class _ShortRead(RuntimeError):
    """Mimics pyads' short-read error string so the helper retry path runs."""


def _to_ctypes(buf: bytes):
    """Return a ctypes c_byte array so helper's bytes(data) works for real."""
    arr = (ctypes.c_byte * len(buf))()
    for i, b in enumerate(buf):
        arr[i] = b - 256 if b > 127 else b
    return arr


class FakeConn:
    """A fake pyads.Connection driven by a (index_group, offset) -> bytes map.

    Mimics the real pyads behaviour the helpers depend on:
      * read()/read_write() take a ctypes type and return a ctypes array
      * a requested size larger than the stored buffer raises a RuntimeError
        whose message contains "N were read" (exactly what pyads emits and
        what the helper short-read retry regex looks for)
      * an unknown (ig, offset) raises an ADSError-style RuntimeError
    """

    def __init__(self, read_map=None, rw_map=None, error_code=None, exact_map=None, raise_map=None):
        # read_map / rw_map: {(ig, offset): bytes}
        self.read_map = read_map or {}
        self.rw_map = rw_map or {}
        # raise_map: {(ig, offset): ads_error_code} -> raise that ADS error for
        # the matching read_write call (models e.g. "1804 = no more files").
        self.raise_map = raise_map or {}
        # exact_map entries are returned truncated to the requested size WITHOUT
        # raising a short-read — models device endpoints (e.g. FILE_READ) that
        # return however many bytes are available up to the requested buffer.
        self.exact_map = exact_map or {}
        # error_code mimics a real pyads.ADSError (a non-RuntimeError exception),
        # so probe handlers that special-case `except RuntimeError` (short-read)
        # fall through to their `except Exception` (real ADS error) branch.
        self.error_code = error_code
        self.opened = False
        self.closed = False
        self.timeout = None
        self.writes = []  # (ig, offset, bytes) recorded for assertions

    # --- lifecycle ---
    def open(self):
        self.opened = True

    def close(self):
        self.closed = True

    def set_timeout(self, ms):
        self.timeout = ms

    # --- helpers ---
    @staticmethod
    def _size_of(ctype):
        return ctypes.sizeof(ctype)

    def _emit(self, buf, size):
        if buf is None:
            raise RuntimeError(f"ADSError(0x710): symbol not found ({0} were read)")
        if size > len(buf):
            raise _ShortRead(
                f"ADSError: Insufficient data (expected {size} bytes, {len(buf)} were read)"
            )
        return _to_ctypes(buf[:size])

    def _maybe_raise_error(self):
        if self.error_code is not None:
            # Non-RuntimeError, like a real pyads.ADSError instance.
            raise Exception(f"ADSError({self.error_code}): simulated")

    # --- transport ops the helpers call ---
    def read(self, index_group, index_offset, ctype, return_ctypes=False):
        self._maybe_raise_error()
        size = self._size_of(ctype)
        key = (index_group, index_offset)
        if key in self.exact_map:
            buf = self.exact_map[key]
            return _to_ctypes(buf[:size])  # truncate, never short-read
        buf = self.read_map.get(key)
        return self._emit(buf, size)

    def read_write(
        self,
        index_group,
        index_offset,
        read_ctype,
        write_bytes,
        write_ctype,
        return_ctypes=False,
    ):
        self._maybe_raise_error()
        if (index_group, index_offset) in self.raise_map:
            raise Exception(f"ADSError({self.raise_map[(index_group, index_offset)]}): simulated")
        size = self._size_of(read_ctype)
        # exact_map: return available bytes truncated to the request, no short-read
        # (models endpoints like the registry browse that return a sized record).
        if (index_group, index_offset) in self.exact_map:
            buf = self.exact_map[(index_group, index_offset)]
            return _to_ctypes(buf[:size])
        # key first by (ig, offset, write_bytes) so handle-based protocols can
        # vary the response per write payload; fall back to (ig, offset).
        key = (index_group, index_offset, bytes(write_bytes))
        if key in self.rw_map:
            buf = self.rw_map[key]
        else:
            buf = self.rw_map.get((index_group, index_offset))
        return self._emit(buf, size)

    def write(self, index_group, index_offset, raw, ctype):
        self._maybe_raise_error()
        self.writes.append((index_group, index_offset, bytes(raw)))


def _make_mixin(read_map=None, rw_map=None, conn=None, error_code=None, timeout_ms=500):
    """Build a bare EtherCATOpsMixin instance with the transport stubbed.

    Returns (obj, fake_conn_factory). The pyads.Connection() factory always
    returns the SAME fake conn so per-test buffers are consistent. The mixin's
    own attributes (logger, ams_netid, ads_timeout_ms) are set directly.
    """
    obj = EtherCATOpsMixin()
    obj.logger = Mock()
    obj.ams_netid = "192.168.1.100.1.1"
    obj.ads_timeout_ms = timeout_ms
    obj._get_ads_port = Mock(return_value=851)

    fake = conn or FakeConn(read_map=read_map, rw_map=rw_map, error_code=error_code)

    pyads_mod = Mock()
    pyads_mod.Connection.return_value = fake
    # _read_coe_string uses pyads.PLCTYPE_STRING — not exercised in these tests
    pyads_mod.PLCTYPE_STRING = object()
    return obj, fake, pyads_mod


def _patch_pyads(pyads_mod):
    return patch("oida.protocols.ads.ethercat_ops._get_pyads", return_value=pyads_mod)


# ---------------------------------------------------------------------------
# _scan_ethercat — master state, slave count, identity, AL state, CoE strings
# ---------------------------------------------------------------------------


class TestScanEtherCAT(unittest.TestCase):
    def test_no_slaves_succeeds_empty(self):
        """slave_count=0 -> success with empty slave list, no slave probing."""
        read_map = {
            (ADS_IDX_GRP["ECAT_AL_STATE"], 0): struct.pack("<H", 8),  # OP
            (ADS_IDX_GRP["ECAT_SLAVE_COUNT"], 0): struct.pack("<H", 0),
        }
        obj, fake, pyads_mod = _make_mixin(read_map=read_map)
        with _patch_pyads(pyads_mod):
            result = obj._scan_ethercat()

        self.assertTrue(result["success"])
        self.assertEqual(result["master_state"], "OP")
        self.assertEqual(result["slave_count"], 0)
        self.assertEqual(result["slaves"], [])

    def test_single_slave_identity_and_state(self):
        """Parse a slave identity object and AL state from master-port reads."""
        first_port = 1001
        read_map = {
            (ADS_IDX_GRP["ECAT_AL_STATE"], 0): struct.pack("<H", 8),
            (ADS_IDX_GRP["ECAT_SLAVE_COUNT"], 0): struct.pack("<H", 1),
            (ADS_IDX_GRP["ECAT_FIRST_PORT"], 0): struct.pack("<H", first_port),
            # identity: vendor=2 (Beckhoff), product, revision, serial
            (ADS_IDX_GRP["ECAT_SLAVE_IDENT"], first_port): struct.pack(
                "<IIII", 0x00000002, 0x044C2C52, 0x00100000, 0x12345678
            ),
            (ADS_IDX_GRP["ECAT_AL_STATE"], first_port): struct.pack("<H", 4),  # SAFE-OP
        }
        obj, fake, pyads_mod = _make_mixin(read_map=read_map)
        with _patch_pyads(pyads_mod):
            result = obj._scan_ethercat()

        self.assertTrue(result["success"])
        self.assertEqual(result["slave_count"], 1)
        self.assertEqual(len(result["slaves"]), 1)
        s = result["slaves"][0]
        self.assertEqual(s["port"], first_port)
        self.assertEqual(s["vendor_id"], "0x00000002")
        self.assertIn("Beckhoff", s["vendor_name"])
        self.assertEqual(s["product_code"], "0x044C2C52")
        self.assertEqual(s["revision"], "0x00100000")
        self.assertEqual(s["serial"], "0x12345678")
        self.assertEqual(s["al_state"], "SAFE-OP")

    def test_slave_count_clamped(self):
        """An implausible device-reported count is clamped to MAX_SLAVE_PORTS."""
        read_map = {
            (ADS_IDX_GRP["ECAT_AL_STATE"], 0): struct.pack("<H", 8),
            (ADS_IDX_GRP["ECAT_SLAVE_COUNT"], 0): struct.pack("<H", 60000),
            (ADS_IDX_GRP["ECAT_FIRST_PORT"], 0): struct.pack("<H", 1001),
        }
        obj, fake, pyads_mod = _make_mixin(read_map=read_map)
        with _patch_pyads(pyads_mod):
            result = obj._scan_ethercat()

        # No identity buffers -> slaves recorded as bare {"port": ...} dicts,
        # and the loop is clamped to MAX_SLAVE_PORTS, not 60000.
        self.assertTrue(result["success"])
        self.assertEqual(result["slave_count"], 60000)  # raw reported value kept
        self.assertEqual(len(result["slaves"]), MAX_SLAVE_PORTS)
        obj.logger.warning.assert_called()

    def test_connection_failure_sets_error(self):
        """If the master connection raises, error is recorded and success stays False."""
        obj, fake, pyads_mod = _make_mixin()
        pyads_mod.Connection.side_effect = RuntimeError("ADSError(1861): Timeout")
        with _patch_pyads(pyads_mod):
            result = obj._scan_ethercat()

        self.assertFalse(result["success"])
        self.assertIn("Timeout", result["error"])


# ---------------------------------------------------------------------------
# _scan_coe_via_ads — CoE dictionary enumeration + subindex walking + access
# ---------------------------------------------------------------------------


class TestScanCoEViaAds(unittest.TestCase):
    def _coe_key(self, idx, sub):
        return (0xF302, encode_sdo_offset(idx, sub))

    def test_reads_object_with_value_and_subindices(self):
        """sub0 is a count -> subindices 1..count are walked and decoded."""
        port = 1001
        idx = 0x1018  # Identity object, sub0 = entry count
        read_map = {
            self._coe_key(idx, 0): bytes([4]),  # sub0 = 4 entries (1 byte)
            self._coe_key(idx, 1): struct.pack("<I", 0x00000002),  # vendor id
            self._coe_key(idx, 2): struct.pack("<I", 0x044C2C52),  # product
            self._coe_key(idx, 3): struct.pack("<I", 0x00100000),  # revision
            self._coe_key(idx, 4): struct.pack("<I", 0x12345678),  # serial
        }
        obj, fake, pyads_mod = _make_mixin(read_map=read_map)
        with _patch_pyads(pyads_mod):
            results = obj._scan_coe_via_ads([port], scan_ranges=[(idx, idx + 1, "Identity", None)])

        objs = results[port]
        # sub0 + 4 subindices = 5 objects
        self.assertEqual(len(objs), 5)
        sub0 = objs[0]
        self.assertEqual(sub0["index"], "0x1018")
        self.assertEqual(sub0["subindex"], 0)
        self.assertEqual(sub0["value"], 4)
        # subindex 1 == vendor id 2, little-endian decode into 'value'
        sub1 = next(o for o in objs if o["subindex"] == 1)
        self.assertEqual(sub1["value"], 0x00000002)
        self.assertEqual(sub1["size"], 4)

    def test_missing_object_skipped(self):
        """An index with no buffer (1-byte probe fails) is skipped entirely."""
        port = 1001
        obj, fake, pyads_mod = _make_mixin(read_map={})
        with _patch_pyads(pyads_mod):
            results = obj._scan_coe_via_ads(
                [port], scan_ranges=[(0x2000, 0x2002, "Manufacturer", None)]
            )
        self.assertEqual(results[port], [])

    def test_filter_subs_reads_specific_subindices(self):
        """A range with filter_subs reads only the requested subindices."""
        port = 1001
        idx = 0x1C12
        read_map = {
            self._coe_key(idx, 1): struct.pack("<H", 0x1600),
            self._coe_key(idx, 2): struct.pack("<H", 0x1601),
        }
        obj, fake, pyads_mod = _make_mixin(read_map=read_map)
        with _patch_pyads(pyads_mod):
            results = obj._scan_coe_via_ads([port], scan_ranges=[(idx, idx + 1, "PDO", [1, 2, 3])])

        objs = results[port]
        subs = sorted(o["subindex"] for o in objs)
        self.assertEqual(subs, [1, 2])  # sub 3 has no buffer -> skipped
        self.assertEqual(objs[0]["value"], 0x1600)

    def test_access_testing_classifies_rw_and_ro(self):
        """test_access=True writes back original data and tags RW vs RO."""
        port = 1001
        idx = 0x2000
        read_map = {self._coe_key(idx, 0): struct.pack("<H", 0xABCD)}
        # writes accepted -> RW
        fake = FakeConn(read_map=read_map)
        obj, _f, pyads_mod = _make_mixin(conn=fake)
        with _patch_pyads(pyads_mod):
            results = obj._scan_coe_via_ads(
                [port], test_access=True, scan_ranges=[(idx, idx + 1, "Mfr", None)]
            )
        obj_dict = results[port][0]
        self.assertEqual(obj_dict["access"], "RW")
        # The write-back must have used the original data, restoring device state
        self.assertTrue(any(w[2] == struct.pack("<H", 0xABCD) for w in fake.writes))

    def test_sub0_not_count_but_sub1_exists(self):
        """When sub0 is not a 1..32 count yet sub1 has data, probe up to 32."""
        port = 1001
        idx = 0xFB00
        read_map = {
            # sub0 is 4 bytes (not a 1-byte count) -> max_sub starts 0
            self._coe_key(idx, 0): struct.pack("<I", 0),
            self._coe_key(idx, 1): b"\xaa\xbb",
            self._coe_key(idx, 2): b"\xcc\xdd",
            # sub 3,4,5 absent -> 3 consecutive misses stop the subindex scan
        }
        obj, fake, pyads_mod = _make_mixin(read_map=read_map)
        with _patch_pyads(pyads_mod):
            results = obj._scan_coe_via_ads([port], scan_ranges=[(idx, idx + 1, "Vendor", None)])
        subs = sorted(o["subindex"] for o in results[port])
        self.assertEqual(subs, [0, 1, 2])

    def test_access_write_only_object_detected(self):
        """Unreadable object that accepts a write -> tagged WO in access mode."""
        port = 1001
        idx = 0x2100

        class WriteOnly(FakeConn):
            # No readable buffer -> read probe fails (object not readable),
            # but writes are accepted -> classified WO.
            pass

        fake = WriteOnly(read_map={})
        obj, _f, pyads_mod = _make_mixin(conn=fake)
        with _patch_pyads(pyads_mod):
            results = obj._scan_coe_via_ads(
                [port], test_access=True, scan_ranges=[(idx, idx + 1, "Mfr", None)]
            )
        objs = results[port]
        self.assertEqual(len(objs), 1)
        self.assertEqual(objs[0]["access"], "WO")

    def test_access_testing_readonly_when_write_rejected(self):
        """A write that raises -> object tagged RO."""
        port = 1001
        idx = 0x2000

        class RejectWrites(FakeConn):
            def write(self, *a, **k):
                raise RuntimeError("ADSError(1796): Access denied")

        fake = RejectWrites(read_map={self._coe_key(idx, 0): struct.pack("<H", 0x11)})
        obj, _f, pyads_mod = _make_mixin(conn=fake)
        with _patch_pyads(pyads_mod):
            results = obj._scan_coe_via_ads(
                [port], test_access=True, scan_ranges=[(idx, idx + 1, "Mfr", None)]
            )
        self.assertEqual(results[port][0]["access"], "RO")


# ---------------------------------------------------------------------------
# _read_eeprom_word / _dump_eeprom_via_ads — SII header parsing
# ---------------------------------------------------------------------------


class TestEEPROM(unittest.TestCase):
    def test_read_eeprom_word_offset_encoding(self):
        """offset = (slave_port << 16) | word_addr; returns raw word bytes."""
        port, word = 1001, 0x0008
        offset = (port << 16) | word
        read_map = {(ADS_IDX_GRP["ECAT_EEPROM_READ"], offset): b"\x05\x00"}
        obj, fake, pyads_mod = _make_mixin(read_map=read_map)
        with _patch_pyads(pyads_mod):
            data = obj._read_eeprom_word(fake, port, word)
        self.assertEqual(data, b"\x05\x00")

    def test_read_eeprom_word_returns_none_on_error(self):
        obj, fake, pyads_mod = _make_mixin(read_map={})
        with _patch_pyads(pyads_mod):
            data = obj._read_eeprom_word(fake, 1001, 0x0000)
        self.assertIsNone(data)

    def test_dump_eeprom_parses_sii_header(self):
        """A full 256-byte EEPROM image is parsed into SII header fields."""
        port = 1001
        # Build a 128-word EEPROM image with known SII fields.
        image = bytearray(256)
        struct.pack_into("<H", image, 0x08, 7)  # station_alias word
        struct.pack_into("<I", image, 0x10, 0x00000002)  # vendor_id
        struct.pack_into("<I", image, 0x14, 0x044C2C52)  # product_code
        struct.pack_into("<I", image, 0x18, 0x00100000)  # revision
        struct.pack_into("<I", image, 0x1C, 0xDEADBEEF)  # serial

        read_map = {}
        for w in range(0x80):
            offset = (port << 16) | w
            read_map[(ADS_IDX_GRP["ECAT_EEPROM_READ"], offset)] = bytes(image[w * 2 : w * 2 + 2])

        obj, fake, pyads_mod = _make_mixin(read_map=read_map)
        with _patch_pyads(pyads_mod):
            results = obj._dump_eeprom_via_ads([port])

        entry = results[port]
        self.assertEqual(len(entry["words"]), 128)
        header = entry["header"]
        self.assertEqual(header["vendor_id"], 0x00000002)
        self.assertEqual(header["product_code"], 0x044C2C52)
        self.assertEqual(header["revision"], 0x00100000)
        # serial aliased from serial_number for display compat
        self.assertEqual(header["serial"], 0xDEADBEEF)
        self.assertEqual(header["station_alias"], 7)

    def test_dump_eeprom_stops_after_three_failures(self):
        """3 consecutive read failures abort the per-slave EEPROM loop early."""
        port = 1001
        read_map = {}
        # Only first 5 words succeed; the rest fail -> stop after 3 misses.
        for w in range(5):
            read_map[(ADS_IDX_GRP["ECAT_EEPROM_READ"], (port << 16) | w)] = b"\xaa\xbb"
        obj, fake, pyads_mod = _make_mixin(read_map=read_map)
        with _patch_pyads(pyads_mod):
            results = obj._dump_eeprom_via_ads([port])
        self.assertEqual(len(results[port]["words"]), 5)


# ---------------------------------------------------------------------------
# _read_esc_registers_via_ads — ESC register decode + router zero-fill guard
# ---------------------------------------------------------------------------


class TestESCRegisters(unittest.TestCase):
    def test_router_zerofill_detected(self):
        """A 256-byte all-zero probe response means AMS router proxy -> skip."""
        port = 1001
        read_map = {(ADS_IDX_GRP["ECAT_ESC_REG"], 0x0130): b"\x00" * 256}
        obj, fake, pyads_mod = _make_mixin(read_map=read_map)
        with _patch_pyads(pyads_mod):
            results = obj._read_esc_registers_via_ads([port])
        self.assertIn("error", results[port])
        self.assertIn("router", results[port]["error"].lower())

    def test_reads_registers_and_decodes_al_status(self):
        """Real ESC: probe short-reads, registers decode, AL Status field parsed."""
        port = 1001
        ig = ADS_IDX_GRP["ECAT_ESC_REG"]
        # Probe at 0x0130 with 256B must short-read (real ESC). Provide a 2-byte
        # buffer so the 256B probe raises RuntimeError (caught -> proceed).
        read_map = {(ig, 0x0130): struct.pack("<H", 0x0018)}  # AL: state=8(OP), errflag set
        # AL Status Code register at 0x0134
        read_map[(ig, 0x0134)] = struct.pack("<H", 0x0011)
        # SyncManager 0 at 0x0800: start, length, ctrl, status, activate
        read_map[(ig, 0x0800)] = struct.pack("<HHBBBx", 0x1000, 256, 0x26, 0x01, 0x01)

        obj, fake, pyads_mod = _make_mixin(read_map=read_map)
        with _patch_pyads(pyads_mod):
            results = obj._read_esc_registers_via_ads([port])

        port_result = results[port]
        self.assertIn("registers", port_result)
        # AL Status decode: low nibble 8 = OP, bit 4 set = error flag
        self.assertEqual(port_result["al_state"], "OP")
        self.assertTrue(port_result["al_error_flag"])
        # SyncManager decode
        self.assertIn("sync_managers", port_result)
        sm0 = port_result["sync_managers"][0]
        self.assertEqual(sm0["start"], "0x1000")
        self.assertEqual(sm0["length"], 256)
        self.assertEqual(sm0["control"], "0x26")

    def test_timeout_recorded(self):
        port = 1001
        obj, fake, pyads_mod = _make_mixin(error_code=1861)
        with _patch_pyads(pyads_mod):
            results = obj._read_esc_registers_via_ads([port])
        self.assertEqual(results[port]["error"], "timeout")


# ---------------------------------------------------------------------------
# FoE — _foe_read_on_conn two-pass read + zero-fill, write, delete
# ---------------------------------------------------------------------------


class TestFoE(unittest.TestCase):
    def test_foe_read_two_pass(self):
        """Probe pass sizes the file (short-read), exact pass returns content."""
        fname = "firmware.bin"
        write_bytes = fname.encode("utf-8")
        open_ig = ADS_IDX_GRP["ECAT_FOE_OPEN_R"]
        read_ig = ADS_IDX_GRP["ECAT_FOE_READ_DATA"]
        close_ig = ADS_IDX_GRP["ECAT_FOE_CLOSE"]
        handle = 0x42
        content = b"HELLO-FIRMWARE-PAYLOAD"  # 22 bytes (< 4096 chunk)

        rw_map = {
            # open returns a 4-byte handle (keyed by write payload = filename)
            (open_ig, 0, write_bytes): struct.pack("<I", handle),
            # read with handle offset: probe asks chunk_size=4096 -> short-read
            # to 22 bytes; exact pass asks 22 -> returns content.
            (read_ig, handle): content,
            (close_ig, handle): b"\x00\x00\x00\x00",
        }
        fake = FakeConn(rw_map=rw_map)
        obj, _f, pyads_mod = _make_mixin(conn=fake)
        with _patch_pyads(pyads_mod):
            result = obj._foe_read_on_conn(fake, fname)

        self.assertTrue(result["success"])
        self.assertEqual(result["size"], len(content))
        self.assertEqual(result["data"], content)

    def test_foe_read_zerofill_router_proxy(self):
        """First chunk all-zero at exact buffer size -> router zero-fill error."""
        fname = "firmware.bin"
        write_bytes = fname.encode("utf-8")
        open_ig = ADS_IDX_GRP["ECAT_FOE_OPEN_R"]
        read_ig = ADS_IDX_GRP["ECAT_FOE_READ_DATA"]
        handle = 0x7
        rw_map = {
            (open_ig, 0, write_bytes): struct.pack("<I", handle),
            (read_ig, handle): b"\x00" * 4096,  # full-size all-zero chunk
        }
        fake = FakeConn(rw_map=rw_map)
        obj, _f, pyads_mod = _make_mixin(conn=fake)
        with _patch_pyads(pyads_mod):
            result = obj._foe_read_on_conn(fake, fname)
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "zero-fill")

    def test_foe_read_open_no_handle(self):
        fname = "nope.bin"
        open_ig = ADS_IDX_GRP["ECAT_FOE_OPEN_R"]
        rw_map = {(open_ig, 0, fname.encode()): b"\x00"}  # < 4 bytes
        fake = FakeConn(rw_map=rw_map)
        obj, _f, pyads_mod = _make_mixin(conn=fake)
        with _patch_pyads(pyads_mod):
            result = obj._foe_read_on_conn(fake, fname)
        self.assertFalse(result["success"])

    def test_foe_write_chunks_and_closes(self):
        """FoE write opens, writes data in 512-byte chunks, closes."""
        port = 1001
        remote = "fw.bin"
        open_ig = ADS_IDX_GRP["ECAT_FOE_OPEN_W"]
        handle = 0x55
        data = b"X" * 1100  # 3 chunks: 512 + 512 + 76
        rw_map = {
            (open_ig, 0, remote.encode("utf-8")): struct.pack("<I", handle),
            (ADS_IDX_GRP["ECAT_FOE_WRITE_DATA"], handle): b"\x00\x00\x00\x00",
            (ADS_IDX_GRP["ECAT_FOE_CLOSE"], handle): b"\x00\x00\x00\x00",
        }
        fake = FakeConn(rw_map=rw_map)
        obj, _f, pyads_mod = _make_mixin(conn=fake)
        with _patch_pyads(pyads_mod):
            result = obj._foe_write_via_ads(port, remote, data)
        self.assertTrue(result["success"])
        self.assertEqual(result["bytes_written"], 1100)

    def test_foe_delete_open_then_close(self):
        """FoE delete opens for write, closes immediately to truncate."""
        port = 1001
        fname = "victim.bin"
        open_ig = ADS_IDX_GRP["ECAT_FOE_OPEN_W"]
        handle = 0x9
        rw_map = {
            (open_ig, 0, fname.encode("utf-8") + b"\x00"): struct.pack("<I", handle),
            (ADS_IDX_GRP["ECAT_FOE_CLOSE"], handle): b"\x00\x00\x00\x00",
        }
        fake = FakeConn(rw_map=rw_map)
        obj, _f, pyads_mod = _make_mixin(conn=fake)
        with _patch_pyads(pyads_mod):
            result = obj._delete_file_foe(port, fname)
        self.assertTrue(result["success"])
        self.assertIn("truncated", result["hint"])

    def test_foe_delete_invalid_port_hint(self):
        """ADS error 24 -> 'Invalid AMS port' hint."""
        port = 9999
        obj, fake, pyads_mod = _make_mixin(error_code=24)
        with _patch_pyads(pyads_mod):
            result = obj._delete_file_foe(port, "x.bin")
        self.assertFalse(result["success"])
        self.assertIn("Invalid AMS port", result["hint"])

    def test_foe_delete_access_denied_hint(self):
        """ADS error 1796 -> access denied / Bootstrap hint."""
        obj, fake, pyads_mod = _make_mixin(error_code=1796)
        with _patch_pyads(pyads_mod):
            result = obj._delete_file_foe(1001, "x.bin")
        self.assertIn("Bootstrap", result["hint"])


# ---------------------------------------------------------------------------
# SoE — _soe_read_with_retry + _read_soe_idn_via_ads element decoding
# ---------------------------------------------------------------------------


class TestSoE(unittest.TestCase):
    def test_soe_read_with_retry_filters_router_zeros(self):
        """256-byte all-zero == router fill -> None."""
        ig = ADS_IDX_GRP["ECAT_SOE_READ"]
        offset = encode_soe_offset(1, element=7)
        fake = FakeConn(read_map={(ig, offset): b"\x00" * 256})
        self.assertIsNone(EtherCATOpsMixin._soe_read_with_retry(fake, offset))

    def test_soe_read_with_retry_short_read(self):
        """Short-read RuntimeError -> retry with reported size, returns data."""
        ig = ADS_IDX_GRP["ECAT_SOE_READ"]
        offset = encode_soe_offset(1, element=7)
        fake = FakeConn(read_map={(ig, offset): b"\x01\x02\x03\x04"})
        # 256B request short-reads to 4 -> retry with 4 -> returns 4 bytes
        data = EtherCATOpsMixin._soe_read_with_retry(fake, offset)
        self.assertEqual(data, b"\x01\x02\x03\x04")

    def test_read_soe_idn_decodes_name_and_value(self):
        """Element 2 decoded as text, element 7 (<=4B) decoded as int value."""
        port, idn = 1001, 1
        ig = ADS_IDX_GRP["ECAT_SOE_READ"]
        read_map = {
            # probe element 7 must short-read (real SoE) -> give small buffer
            (ig, encode_soe_offset(idn, element=7)): struct.pack("<I", 250),
            (ig, encode_soe_offset(idn, element=2)): b"NC cycle time\x00",
            (ig, encode_soe_offset(idn, element=4)): b"us\x00",
        }
        obj, fake, pyads_mod = _make_mixin(read_map=read_map)
        with _patch_pyads(pyads_mod):
            result = obj._read_soe_idn_via_ads(port, idn)

        elems = result["elements"]
        self.assertEqual(elems[2]["text"], "NC cycle time")
        self.assertEqual(elems[4]["text"], "us")
        self.assertEqual(elems[7]["value"], 250)

    def test_read_soe_idn_router_zerofill(self):
        port, idn = 1001, 1
        ig = ADS_IDX_GRP["ECAT_SOE_READ"]
        read_map = {(ig, encode_soe_offset(idn, element=7)): b"\x00" * 256}
        obj, fake, pyads_mod = _make_mixin(read_map=read_map)
        with _patch_pyads(pyads_mod):
            result = obj._read_soe_idn_via_ads(port, idn)
        self.assertIn("error", result)
        self.assertIn("router", result["error"].lower())


# ---------------------------------------------------------------------------
# FSoE — _scan_fsoe_via_ads probe + object decoding
# ---------------------------------------------------------------------------


class TestFSoE(unittest.TestCase):
    def test_fsoe_not_supported_error_code(self):
        """ADS error 1793 on probe -> not supported, no objects."""
        port = 1001
        obj, fake, pyads_mod = _make_mixin(error_code=1793)
        with _patch_pyads(pyads_mod):
            results = obj._scan_fsoe_via_ads([port])
        self.assertFalse(results[port]["fsoe_supported"])

    def test_fsoe_supported_reads_connection_count(self):
        """Probe 0xF980:1 returns a 2-byte connection count -> supported."""
        port = 1001
        ig = ADS_IDX_GRP["COE_SDO"]
        probe_offset = (0xF980 << 16) | 1
        read_map = {(ig, probe_offset): struct.pack("<H", 3)}
        obj, fake, pyads_mod = _make_mixin(read_map=read_map)
        with _patch_pyads(pyads_mod):
            results = obj._scan_fsoe_via_ads([port])
        self.assertTrue(results[port]["fsoe_supported"])
        self.assertEqual(results[port]["connection_count"], 3)

    def test_fsoe_decodes_objects(self):
        """Supported FSoE: object-dictionary entries decoded per declared dtype."""
        from oida.protocols.ethercat.fsoe import FSOE_COE_OBJECTS

        port = 1001
        ig = ADS_IDX_GRP["COE_SDO"]
        probe_offset = (0xF980 << 16) | 1
        read_map = {(ig, probe_offset): struct.pack("<H", 1)}

        # Provide a buffer for the first uint8 object so at least one decodes.
        u8 = next(o for o in FSOE_COE_OBJECTS if o[3] == "uint8")
        idx, sub, _name, _dtype, _sz = u8
        read_map[(ig, (idx << 16) | sub)] = bytes([7])

        obj, fake, pyads_mod = _make_mixin(read_map=read_map)
        with _patch_pyads(pyads_mod):
            results = obj._scan_fsoe_via_ads([port])

        port_result = results[port]
        self.assertTrue(port_result["fsoe_supported"])
        decoded = [o for o in port_result["objects"] if o.get("value") == 7]
        self.assertTrue(decoded, "expected the uint8 object to decode to value 7")
        self.assertEqual(decoded[0]["index"], idx)
        self.assertEqual(decoded[0]["type"], "uint8")

    def test_fsoe_invalid_port(self):
        """ADS error 24 on probe -> not a real port."""
        obj, fake, pyads_mod = _make_mixin(error_code=24)
        with _patch_pyads(pyads_mod):
            results = obj._scan_fsoe_via_ads([9999])
        self.assertFalse(results[9999]["fsoe_supported"])

    def test_fsoe_short_read_probe_means_supported(self):
        """A short-read on the 2-byte probe means real data -> supported."""
        port = 1001
        ig = ADS_IDX_GRP["COE_SDO"]
        probe_offset = (0xF980 << 16) | 1
        # 1-byte buffer: the 2-byte probe short-reads -> RuntimeError path.
        read_map = {(ig, probe_offset): b"\x01"}
        obj, fake, pyads_mod = _make_mixin(read_map=read_map)
        with _patch_pyads(pyads_mod):
            results = obj._scan_fsoe_via_ads([port])
        self.assertTrue(results[port]["fsoe_supported"])
        self.assertEqual(results[port]["connection_count"], -1)


# ---------------------------------------------------------------------------
# FoE discovery wrappers — _foe_read_via_ads, _scan_foe_via_ads, _foe_list_via_ads
# ---------------------------------------------------------------------------


class TestFoEDiscovery(unittest.TestCase):
    def _foe_open_read_map(self, fname, handle, content):
        """Build an rw_map that makes one FoE filename readable via two-pass."""
        open_ig = ADS_IDX_GRP["ECAT_FOE_OPEN_R"]
        read_ig = ADS_IDX_GRP["ECAT_FOE_READ_DATA"]
        close_ig = ADS_IDX_GRP["ECAT_FOE_CLOSE"]
        return {
            (open_ig, 0, fname.encode("utf-8")): struct.pack("<I", handle),
            (read_ig, handle): content,
            (close_ig, handle): b"\x00\x00\x00\x00",
        }

    def test_foe_read_via_ads_success(self):
        """_foe_read_via_ads opens its own connection and returns file bytes."""
        port = 1001
        fname = "firmware.bin"
        content = b"FW-BYTES-XYZ"
        fake = FakeConn(rw_map=self._foe_open_read_map(fname, 0x11, content))
        obj, _f, pyads_mod = _make_mixin(conn=fake)
        with _patch_pyads(pyads_mod):
            result = obj._foe_read_via_ads(port, fname)
        self.assertTrue(result["success"])
        self.assertEqual(result["data"], content)

    def test_foe_read_via_ads_access_denied_hint(self):
        """ADS error 1796 on open -> access denied / Bootstrap hint."""
        obj, fake, pyads_mod = _make_mixin(error_code=1796)
        with _patch_pyads(pyads_mod):
            result = obj._foe_read_via_ads(1001, "fw.bin")
        self.assertFalse(result["success"])
        self.assertIn("Bootstrap", result["hint"])

    def test_scan_foe_finds_readable_file(self):
        """Probe firmware.bin succeeds; scanning the common filename list finds it."""
        port = 1001
        content = b"ROM-IMAGE-1234"
        rw_map = self._foe_open_read_map("firmware.bin", 0x22, content)
        fake = FakeConn(rw_map=rw_map)
        obj, _f, pyads_mod = _make_mixin(conn=fake)
        with _patch_pyads(pyads_mod):
            results = obj._scan_foe_via_ads([port])
        port_result = results[port]
        self.assertTrue(port_result["supported"])
        names = [f["name"] for f in port_result["files"]]
        self.assertIn("firmware.bin", names)
        fw = next(f for f in port_result["files"] if f["name"] == "firmware.bin")
        self.assertEqual(fw["size"], len(content))

    def test_scan_foe_not_supported(self):
        """ADS error 1793 on probe -> FoE not supported, empty file list."""
        obj, fake, pyads_mod = _make_mixin(error_code=1793)
        with _patch_pyads(pyads_mod):
            results = obj._scan_foe_via_ads([1001])
        self.assertFalse(results[1001]["supported"])

    def test_foe_list_finds_and_saves(
        self,
    ):
        """_foe_list_via_ads deep-probes a filename and writes it to save_dir."""
        import tempfile
        import os

        port = 1001
        fname = "firmware.bin"
        content = b"SAVED-CONTENT"
        fake = FakeConn(rw_map=self._foe_open_read_map(fname, 0x33, content))
        obj, _f, pyads_mod = _make_mixin(conn=fake)
        with tempfile.TemporaryDirectory() as td:
            with _patch_pyads(pyads_mod):
                result = obj._foe_list_via_ads(port, save_dir=td)
            self.assertTrue(result["supported"])
            saved = next(f for f in result["files"] if f["name"] == fname)
            self.assertEqual(saved["size"], len(content))
            self.assertTrue(os.path.exists(saved["path"]))
            with open(saved["path"], "rb") as fh:
                self.assertEqual(fh.read(), content)

    def test_foe_list_extra_patterns(self):
        """User patterns are appended to the common filename probe list."""
        port = 1001
        custom = "secret.dat"
        content = b"CUSTOM"
        fake = FakeConn(rw_map=self._foe_open_read_map(custom, 0x44, content))
        obj, _f, pyads_mod = _make_mixin(conn=fake)
        with _patch_pyads(pyads_mod):
            result = obj._foe_list_via_ads(port, patterns=[custom])
        names = [f["name"] for f in result["files"]]
        self.assertIn(custom, names)


# ---------------------------------------------------------------------------
# SoE scan — _scan_soe_via_ads IDN enumeration
# ---------------------------------------------------------------------------


class TestSoEScan(unittest.TestCase):
    def test_scan_soe_router_zerofill(self):
        """256-byte all-zero probe -> SoE not supported (router), no IDNs."""
        port = 1001
        ig = ADS_IDX_GRP["ECAT_SOE_READ"]
        probe_offset = encode_soe_offset(1, element=7)
        read_map = {(ig, probe_offset): b"\x00" * 256}
        obj, fake, pyads_mod = _make_mixin(read_map=read_map)
        with _patch_pyads(pyads_mod):
            results = obj._scan_soe_via_ads([port])
        # Router zero-fill short-circuits the port loop before recording any IDNs.
        self.assertNotIn(port, results)

    def test_scan_soe_reads_idns(self):
        """Real SoE: probe short-reads, IDN values + names decoded for present IDNs."""
        from oida.protocols.ethercat.soe import SOE_STANDARD_IDNS

        port = 1001
        ig = ADS_IDX_GRP["ECAT_SOE_READ"]
        # probe IDN 1 elem 7 must short-read -> give a small buffer
        read_map = {(ig, encode_soe_offset(1, element=7)): struct.pack("<I", 99)}
        # pick a known IDN and give it value + name buffers
        idn = sorted(SOE_STANDARD_IDNS)[0]
        read_map[(ig, encode_soe_offset(idn, element=7))] = struct.pack("<I", 1234)
        read_map[(ig, encode_soe_offset(idn, element=2))] = b"MyIDN\x00"

        obj, fake, pyads_mod = _make_mixin(read_map=read_map)
        with _patch_pyads(pyads_mod):
            results = obj._scan_soe_via_ads([port])

        port_idns = results[port]
        self.assertIn(idn, port_idns)
        self.assertEqual(port_idns[idn]["value"], 1234)
        self.assertEqual(port_idns[idn]["device_name"], "MyIDN")


# ---------------------------------------------------------------------------
# _list_files — TcFileFindData browse parsing
# ---------------------------------------------------------------------------


class TestListFiles(unittest.TestCase):
    def _find_data(self, handle, filename, is_dir):
        """Build a 320-byte TcFileFindData record."""
        buf = bytearray(320)
        struct.pack_into("<I", buf, 0, handle)  # hFile
        attrs = 0x10 if is_dir else 0x20
        struct.pack_into("<I", buf, 4, attrs)  # dwFileAttributes
        name = filename.encode("utf-8")
        buf[48 : 48 + len(name)] = name
        return bytes(buf)

    def test_list_files_parses_first_entry(self):
        """First browse returns a directory entry; subsequent browse errors stop."""
        path = "C:\\TwinCAT\\"
        browse_ig = ADS_IDX_GRP["FILE_BROWSE"]
        file_handle = 5
        first = self._find_data(file_handle, "Boot", is_dir=True)

        # First read_write keyed at offset=1 (handle=1) returns the find record;
        # the continuation read at offset=file_handle errors (1804 = no more).
        rw_map = {(browse_ig, 1): first}
        fake = FakeConn(rw_map=rw_map, raise_map={(browse_ig, file_handle): 1804})
        obj, _f, pyads_mod = _make_mixin(conn=fake)
        with _patch_pyads(pyads_mod):
            result = obj._list_files(path)

        self.assertTrue(result["success"])
        self.assertEqual(len(result["files"]), 1)
        entry = result["files"][0]
        self.assertEqual(entry["name"], "Boot")
        self.assertTrue(entry["is_directory"])

    def test_list_files_handle_zero_no_results(self):
        """A find record with handle=0 means no matches -> success, empty list."""
        path = "C:\\nope\\"
        browse_ig = ADS_IDX_GRP["FILE_BROWSE"]
        rw_map = {(browse_ig, 1): self._find_data(0, "", is_dir=False)}
        fake = FakeConn(rw_map=rw_map)
        obj, _f, pyads_mod = _make_mixin(conn=fake)
        with _patch_pyads(pyads_mod):
            result = obj._list_files(path)
        self.assertTrue(result["success"])
        self.assertEqual(result["files"], [])


# ---------------------------------------------------------------------------
# Files / registry / routes / task data / program download
# ---------------------------------------------------------------------------


class TestFileOps(unittest.TestCase):
    def test_read_file_assembles_chunks(self):
        """Open returns a handle, FILE_READ returns content, success flagged."""
        path = "C:\\TwinCAT\\test.txt"
        open_ig = ADS_IDX_GRP["FILE_OPEN"]
        read_ig = ADS_IDX_GRP["FILE_READ"]
        handle = 7
        content = b"file-contents-here"
        # build the open write payload exactly as the code does
        from oida.protocols.ads.constants import ADS_FILE_FLAG

        flags = ADS_FILE_FLAG["READ"] | ADS_FILE_FLAG["BINARY"]
        open_payload = struct.pack("<I", flags) + path.encode("utf-8") + b"\x00"
        rw_map = {(open_ig, 0, open_payload): struct.pack("<I", handle)}
        # FILE_READ returns however many bytes are available (a short file) up to
        # the requested 64KB buffer, without a short-read error — use exact_map.
        exact_map = {(read_ig, handle): content}
        fake = FakeConn(rw_map=rw_map, exact_map=exact_map)
        obj, _f, pyads_mod = _make_mixin(conn=fake)
        with _patch_pyads(pyads_mod):
            result = obj._read_file(path)

        self.assertTrue(result["success"])
        self.assertEqual(result["data"], content)
        self.assertEqual(result["size"], len(content))

    def test_read_registry_unknown_hive(self):
        obj, fake, pyads_mod = _make_mixin()
        with _patch_pyads(pyads_mod):
            result = obj._read_registry("HKBOGUS", "Some\\Key")
        self.assertFalse(result["success"])
        self.assertIn("Unknown hive", result["error"])

    def test_read_registry_dword(self):
        """REG_DWORD (type 4) decodes a 4-byte little-endian integer."""
        ig = ADS_IDX_GRP["REG_HKLM"]
        # response = type(4) + value(4); the read_write asks for a 4096B buffer
        # and the device returns a short record -> use exact_map (no short-read).
        resp = struct.pack("<I", 4) + struct.pack("<I", 0x12345678)
        fake = FakeConn(exact_map={(ig, 0): resp})
        obj, _f, pyads_mod = _make_mixin(conn=fake)
        with _patch_pyads(pyads_mod):
            result = obj._read_registry("HKLM", "Soft\\Key", "Val")
        self.assertTrue(result["success"])
        self.assertEqual(result["type"], 4)
        self.assertEqual(result["decoded"], 0x12345678)

    def test_add_route_invalid_netid(self):
        """A NetID without 6 parts -> error, no write."""
        obj, fake, pyads_mod = _make_mixin()
        with _patch_pyads(pyads_mod):
            result = obj._add_route("1.2.3", "10.0.0.1")
        self.assertFalse(result["success"])
        self.assertIn("Invalid NetID", result["error"])

    def test_add_route_builds_payload(self):
        """Valid route -> a single write to ROUTE_ADD with the encoded entry."""
        fake = FakeConn()
        obj, _f, pyads_mod = _make_mixin(conn=fake)
        with _patch_pyads(pyads_mod):
            result = obj._add_route("5.80.192.37.1.1", "10.0.0.5", "myroute")
        self.assertTrue(result["success"])
        self.assertEqual(len(fake.writes), 1)
        ig, off, payload = fake.writes[0]
        self.assertEqual(ig, ADS_IDX_GRP["ROUTE_ADD"])
        # netid bytes 5,80,192,37,1,1 appear right after the 4-byte flags
        self.assertEqual(payload[4:10], bytes([5, 80, 192, 37, 1, 1]))
        self.assertIn(b"10.0.0.5", payload)
        self.assertIn(b"myroute", payload)

    def test_task_data_parses_cycle_time(self):
        """TASK_DATA read decodes cycle time (100ns units) and priority."""
        ig = ADS_IDX_GRP["TASK_DATA"]
        # task 0: cycle=10000 (100ns) -> 1.0 ms, priority=5; task1 zero-fill stop
        task0 = struct.pack("<II", 10000, 5) + b"\x00" * 56
        read_map = {(ig, 0): task0, (ig, 1): b"\x00" * 64}
        obj, fake, pyads_mod = _make_mixin(read_map=read_map)
        with _patch_pyads(pyads_mod):
            result = obj._read_task_data()

        self.assertTrue(result["success"])
        self.assertEqual(len(result["tasks"]), 1)
        t = result["tasks"][0]
        self.assertEqual(t["cycle_time_ms"], 1.0)
        self.assertEqual(t["priority"], 5)

    def test_download_program_parses_upload_info(self):
        """SYM_UPLOAD_INFO header gives symbol/datatype sizes; tables downloaded."""
        info_ig = ADS_IDX_GRP["SYM_UPLOAD_INFO"]
        upload_ig = ADS_IDX_GRP["SYM_UPLOAD"]
        dtype_ig = ADS_IDX_GRP["SYM_DTYPE_UPLOAD"]
        sym_size, dt_size = 16, 8
        info = struct.pack("<III", 2, sym_size, dt_size) + b"\x00" * 12  # 24 bytes
        read_map = {
            (info_ig, 0): info,
            (upload_ig, 0): b"S" * sym_size,
            (dtype_ig, 0): b"D" * dt_size,
        }
        fake = FakeConn(read_map=read_map)
        obj, _f, pyads_mod = _make_mixin(conn=fake)
        with _patch_pyads(pyads_mod):
            result = obj._download_plc_program(fake)

        self.assertTrue(result["success"])
        self.assertEqual(result["symbol_count"], 2)
        self.assertEqual(result["symbol_size"], sym_size)
        self.assertEqual(result["datatype_size"], dt_size)
        self.assertEqual(result["symbols"], b"S" * sym_size)
        self.assertEqual(result["datatypes"], b"D" * dt_size)


# ---------------------------------------------------------------------------
# CoE fuzzing — _fuzz_coe_via_ads target discovery + restore
# ---------------------------------------------------------------------------


class TestFuzzCoE(unittest.TestCase):
    def test_fuzz_no_writable_targets(self):
        """With no RW objects discovered, fuzzing reports zero targets."""
        port = 1001
        obj, fake, pyads_mod = _make_mixin(read_map={})
        with _patch_pyads(pyads_mod):
            results = obj._fuzz_coe_via_ads(
                [port], iterations=2, scan_ranges=[(0x2000, 0x2001, "Mfr", None)]
            )
        self.assertEqual(results[port], [])

    def test_fuzz_force_write_targets_readable(self):
        """force_write=True fuzzes a readable object and restores the original."""
        port = 1001
        idx = 0x2000
        read_map = {(0xF302, encode_sdo_offset(idx, 0)): struct.pack("<H", 0xBEEF)}
        fake = FakeConn(read_map=read_map)
        obj, _f, pyads_mod = _make_mixin(conn=fake)
        with _patch_pyads(pyads_mod):
            results = obj._fuzz_coe_via_ads(
                [port],
                iterations=2,
                scan_ranges=[(idx, idx + 1, "Mfr", None)],
                force_write=True,
            )
        port_results = results[port]
        self.assertEqual(len(port_results), 1)
        self.assertEqual(port_results[0]["index"], "0x2000")
        self.assertTrue(port_results[0]["iterations"] >= 2)
        # Original value 0xBEEF must have been written back to restore state.
        self.assertTrue(any(w[2] == struct.pack("<H", 0xBEEF) for w in fake.writes))


# ---------------------------------------------------------------------------
# Module-level constants / static delegate
# ---------------------------------------------------------------------------


class TestModuleLevel(unittest.TestCase):
    def test_max_slave_ports_cap(self):
        self.assertEqual(MAX_SLAVE_PORTS, 1024)

    def test_parse_coe_ranges_static_delegate(self):
        """_parse_coe_ranges is a static delegate to ethercat.coe.parse_coe_ranges."""
        ranges = EtherCATOpsMixin._parse_coe_ranges("0x1000-0x1010")
        self.assertEqual(ranges, [(0x1000, 0x1010, "Communication", None)])


if __name__ == "__main__":
    unittest.main()

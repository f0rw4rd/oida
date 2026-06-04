#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ADS shared helper functions, lazy imports, and error classification utilities.

This module provides the common low-level primitives used by both the
ADSScanner (Layer 1) and the ads NXC class (Layer 2):
- Lazy pyads import and validation
- Raw ADS read/write operations
- CoE SDO read/write helpers
- ADS error classification
- Net ID probing
- pyads stderr capture
"""

import ctypes
import io
import os
import re
import struct
import sys
import tempfile
from contextlib import contextmanager

from ...utils.lazy_import import lazy_import

# Shared CoE definitions (no pysoem dependency -- pure data module)
from ..ethercat.coe import (
    COE_SDO_OFFSETS,
    encode_sdo_offset,
)

# ADS protocol constants (shared with passive listener)
from .constants import (
    ADS_ERROR_CODES,
    ADS_TIMEOUT_MS,
    INDEXGROUP_IOIMAGE_RWIB,
    INDEXGROUP_IOIMAGE_RWOB,
)

import logging

logger = logging.getLogger(__name__)


_pyads = lazy_import("pyads", "ADS")


def _get_pyads():
    """Get pyads module, raising DependencyError if not available."""
    return _pyads()


def _validate_ams_netid(netid: str):
    """Validate AMS Net ID format (6 dot-separated integers, e.g. 192.168.1.1.1.1)."""
    parts = netid.split(".")
    if len(parts) != 6 or not all(p.isdigit() for p in parts):
        raise ValueError(
            f"Invalid AMS Net ID '{netid}'. Expected format: x.x.x.x.y.z "
            f"(e.g., 192.168.1.1.1.1). Check -n/--netid-ext value."
        )


def _get_pyads_constants():
    """Get pyads constants lazily."""
    pyads = _get_pyads()
    return {
        "INDEXGROUP_MEMORYBYTE": pyads.constants.INDEXGROUP_MEMORYBYTE,
        "INDEXGROUP_MEMORYBIT": pyads.constants.INDEXGROUP_MEMORYBIT,
        "INDEXGROUP_DATA": pyads.constants.INDEXGROUP_DATA,
    }


def _read_raw(conn, index_group, index_offset, size):
    """Read raw bytes from ADS device.

    pyads Connection.read() expects a ctypes type as the third argument,
    not a raw integer size. This helper creates the appropriate ctypes
    byte array type for raw reads and returns bytes.
    """
    data = conn.read(index_group, index_offset, ctypes.c_byte * size, return_ctypes=True)
    return bytes(data)


def _read_coe_string(conn, index_group, sdo_offset):
    """Read a CoE SDO string value.

    CoE string SDOs return variable-length data.  Using a fixed ctypes
    buffer raises ``RuntimeError`` when the response is shorter than
    the buffer.  ``PLCTYPE_STRING`` lets pyads handle the framing.
    """
    pyads = _get_pyads()
    return conn.read(index_group, sdo_offset, pyads.PLCTYPE_STRING)


def _read_coe_sdo(conn, index, subindex):
    """Read a CoE SDO object via ADS, handling variable-length responses.

    Probes with 1 byte to check existence, then reads with 256-byte buffer.
    On short-read RuntimeError, retries with the actual size reported by pyads.
    Returns raw bytes, or None if the object doesn't exist.
    """
    ig = 0xF302
    offset = encode_sdo_offset(index, subindex)

    # 1-byte probe — if the object doesn't exist this throws
    try:
        _read_raw(conn, ig, offset, 1)
    except Exception as e:
        logger.debug(f"_read_raw call failed: {e}")
        return None

    # Full read with generous buffer
    try:
        return _read_raw(conn, ig, offset, 256)
    except RuntimeError as e:
        # pyads: "Insufficient data (expected 256 bytes, N were read)"
        m = re.search(r"(\d+)\s+were\s+read", str(e))
        if m:
            actual = int(m.group(1))
            if actual > 0:
                return _read_raw(conn, ig, offset, actual)
        return None
    except Exception as e:
        logger.debug(f"Return value computation failed: {e}")
        return None


def _read_sdo_entry_desc(conn, index, subindex):
    """Read SDO entry description via ig=0xF3FE (name, type, access).

    Returns dict with 'name', 'data_type', 'bit_length', 'obj_access'
    or None if unavailable.
    """
    ig = 0xF3FE
    offset = (index << 16) | subindex
    try:
        raw = _read_raw(conn, ig, offset, 256)
    except RuntimeError as e:
        m = re.search(r"(\d+)\s+were\s+read", str(e))
        if m:
            actual = int(m.group(1))
            if actual >= 10:
                raw = _read_raw(conn, ig, offset, actual)
            else:
                return None
        else:
            return None
    except Exception as e:
        logger.debug(f"ADS CoE object info read failed: {e}")
        return None

    if len(raw) < 10:
        return None
    data_type = struct.unpack_from("<H", raw, 4)[0]
    bit_length = struct.unpack_from("<H", raw, 6)[0]
    obj_access = struct.unpack_from("<H", raw, 8)[0]
    name = raw[10:].rstrip(b"\x00").decode("utf-8", errors="replace")
    return {
        "name": name,
        "data_type": data_type,
        "bit_length": bit_length,
        "obj_access": obj_access,
    }


def _write_raw(conn, index_group, index_offset, data):
    """Write raw bytes to ADS device.

    pyads Connection.write() requires a plc_datatype as the fourth argument.
    This helper creates the appropriate ctypes byte array type for raw writes.
    """
    raw = bytes(data) if not isinstance(data, bytes) else data
    conn.write(index_group, index_offset, raw, ctypes.c_byte * len(raw))


def _write_coe_sdo(conn, index, subindex, data):
    """Write a CoE SDO object via ADS.

    Returns (True, None) on success, (False, error_str) on exception.
    """
    try:
        offset = encode_sdo_offset(index, subindex)
        _write_raw(conn, 0xF302, offset, data)
        return True, None
    except Exception as e:
        return False, str(e)


def _test_coe_write_access(conn, index, subindex, data):
    """Test write access by writing back the same data that was read.

    Returns (True, None) if the write is accepted, (False, error_str) otherwise.
    """
    return _write_coe_sdo(conn, index, subindex, data)


def _test_coe_write_only(conn, index, subindex):
    """Test write-only access for objects where read failed.

    Attempts a 1-byte zero write. Returns (True, None) if accepted,
    (False, error_str) otherwise.
    """
    return _write_coe_sdo(conn, index, subindex, b"\x00")


def _read_write_raw(conn, index_group, index_offset, read_size, write_data):
    """Read/write raw bytes to ADS device.

    pyads Connection.read_write() expects ctypes types for both plc_read_datatype
    and plc_write_datatype, not raw integer sizes.
    """
    write_bytes = bytes(write_data) if not isinstance(write_data, bytes) else write_data
    data = conn.read_write(
        index_group,
        index_offset,
        ctypes.c_byte * read_size,
        write_bytes,
        ctypes.c_byte * len(write_bytes),
        return_ctypes=True,
    )
    return bytes(data)


# ---------------------------------------------------------------------------
# ADS Error Classification Helpers
# ---------------------------------------------------------------------------


def _is_ads_timeout(err_str):
    """ADS error 1861 or generic timeout — endpoint didn't respond."""
    return "1861" in err_str or "timeout" in err_str.lower()


def _is_ads_conn_broken(err_str):
    """Broken TCP connection — AMS router dropped us."""
    return (
        "(-1)" in err_str
        or "reset" in err_str.lower()
        or "broken pipe" in err_str.lower()
        or "write frame" in err_str.lower()
    )


def _is_ads_port_not_found(err_str):
    """ADS error 24 = 'Invalid AMS port' — router confirms no service."""
    return "(24)" in err_str or "invalid ams port" in err_str.lower()


def _is_ads_real_error(err_str):
    """Non-timeout, non-broken ADS error — endpoint exists and answered."""
    return not _is_ads_timeout(err_str) and not _is_ads_conn_broken(err_str)


def _extract_ads_error(err_str):
    """Extract ADS error code and human-readable name from ADSError string."""
    m = re.search(r"\((\d+)\)", err_str)
    if m:
        code = int(m.group(1))
        name = ADS_ERROR_CODES.get(code, "")
        return f"{code}: {name}" if name else str(code)
    return err_str


def _extract_ads_error_code(err_str):
    """Extract numeric ADS error code from ADSError string, or None."""
    m = re.search(r"\((\d+)\)", err_str)
    return int(m.group(1)) if m else None


# ---------------------------------------------------------------------------
# Central Net ID Probe
# ---------------------------------------------------------------------------


def _probe_netid(pyads, netid, port, timeout_ms=ADS_TIMEOUT_MS, master_fallback=True):
    """Probe a single AMS Net ID to determine if it is active.

    Runs a tiered probe:
      1. ``read_device_info()`` on *port* — works on PLC runtimes
      2. CoE SDO read (ig=0xF302) on *port* — works on EtherCAT slave ports
      3. EtherCAT master read (ig=0x0006 on port 0xFFFF) — works on
         EtherCAT subsystems (only when *master_fallback* is True)

    Set *master_fallback=False* for per-port service scanning (otherwise
    the master responds for every non-existent port on an EtherCAT Net ID).

    Returns dict:
        ``{"active": bool, "type": str, "detail": str}``

    ``type`` is one of:
        ``"plc"``      — PLC runtime (read_device_info succeeded)
        ``"ethercat"`` — EtherCAT subsystem (CoE SDO or master responded)
        ``"ads"``      — generic ADS service (non-timeout ADS error)
        ``"none"``     — not reachable (timeout / error 24)
        ``"broken"``   — TCP connection lost

    The caller must handle ``"broken"`` by stopping further probes.
    """
    result = {"active": False, "type": "none", "detail": ""}
    conn = None
    try:
        conn = pyads.Connection(netid, port)
        conn.open()
        conn.set_timeout(timeout_ms)

        # --- Tier 1: read_device_info (PLC runtimes) ---
        try:
            dev_name, dev_ver = conn.read_device_info()
            ver_str = f"{dev_ver.version}.{dev_ver.revision}.{dev_ver.build}"
            result.update(
                active=True,
                type="plc",
                detail=f"{dev_name} v{ver_str}",
            )
            return result
        except Exception as e:
            err = str(e)
            if _is_ads_conn_broken(err):
                result.update(type="broken", detail="connection lost")
                return result
            if _is_ads_real_error(err):
                # Got a real ADS error (not timeout) — endpoint exists but
                # doesn't support device_info.  Fall through to tier 2.
                pass

        # --- Tier 2: CoE SDO probe on given port (EtherCAT slave ports) ---
        try:
            _read_raw(conn, 0xF302, encode_sdo_offset(0x1008, 0), 1)
            result.update(active=True, type="ethercat", detail="CoE SDO accessible")
            return result
        except Exception as e:
            err = str(e)
            if _is_ads_conn_broken(err):
                result.update(type="broken", detail="connection lost")
                return result
            if _is_ads_port_not_found(err):
                # Error 24 = no service on this port.  But the Net ID might
                # still host an EtherCAT master — fall through to tier 3.
                pass
            elif _is_ads_real_error(err):
                result.update(active=True, type="ads", detail=str(e))
                return result

    except Exception as e:
        err = str(e)
        if _is_ads_conn_broken(err):
            result.update(type="broken", detail="connection lost")
            return result
    finally:
        if conn:
            try:
                conn.close()
            except Exception as e:
                logger.debug(f"conn.close(): {e}")

    # --- Tier 3: EtherCAT master probe (port 0xFFFF, ig=0x0006) ---
    # The EtherCAT master lives on a fixed ADS port (65535) and responds
    # to slave-count reads even when no PLC port is active.
    # Skipped for per-port scanning (master_fallback=False) because the
    # master responds regardless of which ADS port was originally tested.
    if not master_fallback:
        if not result["detail"]:
            result["detail"] = "timeout"
        return result

    master_conn = None
    try:
        master_conn = pyads.Connection(netid, 0xFFFF)
        master_conn.open()
        master_conn.set_timeout(timeout_ms)

        count_data = _read_raw(master_conn, 0x0006, 0, 2)
        if count_data and len(count_data) >= 2:
            slave_count = struct.unpack("<H", count_data)[0]
            result.update(
                active=True,
                type="ethercat",
                detail=f"EtherCAT master ({slave_count} slaves)",
            )
            return result
    except Exception as e:
        err = str(e)
        if _is_ads_conn_broken(err):
            result.update(type="broken", detail="connection lost")
            return result
        if _is_ads_real_error(err):
            result.update(active=True, type="ads", detail=str(e))
            return result
    finally:
        if master_conn:
            try:
                master_conn.close()
            except Exception as e:
                logger.debug(f"master_conn.close(): {e}")

    # All tiers failed
    if not result["detail"]:
        result["detail"] = "timeout"
    return result


@contextmanager
def _capture_pyads_stderr(logger=None):
    """Capture pyads C library stderr output and route to debug log.

    The AdsLib C library writes status/error messages directly to fd 2
    (stderr) with no API to disable them.  This context manager redirects
    the fd to a temp file, then replays any captured lines through the
    oida debug logger so they don't clutter normal output.

    If stderr is not backed by a real file descriptor (e.g. it has been
    replaced by a capturing stream under pytest, or redirected to an
    in-memory object), there is no fd-level output to intercept, so the
    context manager degrades to a no-op instead of raising.
    """
    try:
        stderr_fd = sys.stderr.fileno()
    except (AttributeError, ValueError, OSError, io.UnsupportedOperation):
        yield
        return
    old_stderr = os.dup(stderr_fd)
    tmp = tempfile.TemporaryFile(mode="w+")
    try:
        os.dup2(tmp.fileno(), stderr_fd)
        yield
    finally:
        os.dup2(old_stderr, stderr_fd)
        os.close(old_stderr)
        tmp.seek(0)
        captured = tmp.read()
        tmp.close()
        if captured and logger:
            for line in captured.strip().splitlines():
                logger.debug("pyads: %s", line)


# Backward compat alias — callers that used COE_SDO_OFFSET directly
COE_SDO_OFFSET = COE_SDO_OFFSETS

# Common memory areas for testing (loaded lazily to avoid import at module load)
_memory_areas_cache: dict = {}


def _get_memory_areas():
    """Get memory areas with lazily-loaded pyads constants."""
    if "areas" not in _memory_areas_cache:
        consts = _get_pyads_constants()
        _memory_areas_cache["areas"] = [
            {
                "group": consts["INDEXGROUP_MEMORYBYTE"],
                "name": "M-Area (Bytes)",
                "offset": 0,
                "size": 4,
            },
            {
                "group": consts["INDEXGROUP_MEMORYBIT"],
                "name": "M-Area (Bits)",
                "offset": 0,
                "size": 1,
            },
            {"group": consts["INDEXGROUP_DATA"], "name": "Data Area", "offset": 0, "size": 4},
            {"group": INDEXGROUP_IOIMAGE_RWIB, "name": "Input Image", "offset": 0, "size": 4},
            {"group": INDEXGROUP_IOIMAGE_RWOB, "name": "Output Image", "offset": 0, "size": 4},
        ]
    return _memory_areas_cache["areas"]

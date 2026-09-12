"""Regression tests for LonTalk network-management decoding.

Authority: ``tshark -G values`` (tshark 4.4.15) for ``lon.code``,
``lon.tpdu_type`` and ``lon.spdu_type``, which follow the ANSI/CEA-709.1
LonTalk protocol spec.

Three defects were confirmed here:

1. ``NM_COMMANDS`` was shifted by one from 0x69 onward (it claimed
   0x69=UpdateNVConfig, 0x6c=WriteMemory, 0x6e=Wink; the registry says
   0x69=UPDATE_GROUP_ADDR, 0x6c=SET_NODE_MODE, 0x6e=WRITE_MEMORY).
2. Because ``NM_WRITE_COMMANDS`` was built from those wrong numbers, a real
   NM_WRITE_MEMORY (0x6e) was classified as a *read* -- a device-memory write
   went unflagged -- while NM_QUERY_SNVT (0x72, a read) was flagged as a write.
3. ``get_write_operations()`` reported every node that received *any* NM
   command, including pure reads such as NM_QUERY_ID.
"""

import pytest

from oida.pcap.lontalk import (
    NM_COMMANDS,
    NM_WRITE_COMMANDS,
    SPDU_TYPES,
    TPDU_TYPES,
    LonTalkPassiveListener,
)


class _Lon:
    """Fake ``lon`` layer exposing only the fields _process_nm reads."""

    def __init__(self, **fields):
        self._layer_name = "lon"
        for key, value in fields.items():
            setattr(self, key, value)

    def get_field_value(self, name, raw=False):
        return getattr(self, name.replace(".", "_"), None)


def _listener():
    return LonTalkPassiveListener(interface="lo", timeout=1)


def _nm(listener, code_hex):
    """Run one NM command addressed at node 1/2; returns (name, rw)."""
    return listener._process_nm(_Lon(nm="1", code=code_hex), None, 1, 2, "now")


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------

TSHARK_LON_CODES = {
    0x61: "NM_QUERY_ID",
    0x62: "NM_RESPOND_TO_QUERY",
    0x63: "NM_UPDATE_DOMAIN",
    0x64: "NM_LEAVE_DOMAIN",
    0x65: "NM_UPDATE_KEY",
    0x66: "NM_UPDATE_ADDR",
    0x67: "NM_QUERY_ADDR",
    0x68: "NM_QUERY_NV_CNFG",
    0x69: "NM_UPDATE_GROUP_ADDR",
    0x6A: "NM_QUERY_DOMAIN",
    0x6B: "NM_UPDATE_NV_CNFG",
    0x6C: "NM_SET_NODE_MODE",
    0x6D: "NM_READ_MEMORY",
    0x6E: "NM_WRITE_MEMORY",
    0x6F: "NM_CHECKSUM_RECALC",
    0x70: "NM_WINK",
    0x71: "NM_MEMORY_REFRESH",
    0x72: "NM_QUERY_SNVT",
    0x73: "NM_NV_FETCH",
    0x7F: "NM_MANUAL_SERVICE_REQUEST",
}


def test_nm_command_codes_match_the_registry():
    assert set(NM_COMMANDS) == set(TSHARK_LON_CODES)


@pytest.mark.parametrize(
    "code,token",
    [
        (0x69, "GroupAddr"),
        (0x6A, "QueryDomain"),
        (0x6B, "NVConfig"),
        (0x6C, "NodeMode"),
        (0x6D, "ReadMemory"),
        (0x6E, "WriteMemory"),
        (0x6F, "Checksum"),
        (0x70, "Wink"),
        (0x71, "MemoryRefresh"),
        (0x72, "SNVT"),
        (0x73, "NVFetch"),
        (0x7F, "ServiceRequest"),
    ],
)
def test_shifted_codes_now_name_the_right_command(code, token):
    assert token.lower() in NM_COMMANDS[code].lower(), (
        f"0x{code:02x} is {TSHARK_LON_CODES[code]}, got {NM_COMMANDS[code]}"
    )


def test_tpdu_types_match_the_registry():
    assert TPDU_TYPES == {0: "ACKD", 1: "UnACKD_RPT", 2: "ACK", 4: "REMINDER", 5: "REM_MSG"}


def test_spdu_types_match_the_registry():
    assert SPDU_TYPES == {0: "REQUEST", 2: "RESPONSE", 4: "REMINDER", 5: "REM_MSG"}


# ---------------------------------------------------------------------------
# read/write classification
# ---------------------------------------------------------------------------


def test_write_memory_is_classified_as_a_write():
    """0x6e NM_WRITE_MEMORY -- the one that matters for a security alert."""
    assert 0x6E in NM_WRITE_COMMANDS
    name, rw = _nm(_listener(), "0x6e")
    assert rw == "write"
    assert "WriteMemory" in name


def test_read_memory_is_not_a_write():
    assert 0x6D not in NM_WRITE_COMMANDS
    _, rw = _nm(_listener(), "0x6d")
    assert rw == "read"


def test_query_snvt_is_not_a_write():
    """0x72 is NM_QUERY_SNVT, a read; it used to sit in the write set."""
    assert 0x72 not in NM_WRITE_COMMANDS
    _, rw = _nm(_listener(), "0x72")
    assert rw == "read"


def test_query_id_is_not_a_write():
    _, rw = _nm(_listener(), "0x61")
    assert rw == "read"


# ---------------------------------------------------------------------------
# get_write_operations() must count writes, not all NM traffic
# ---------------------------------------------------------------------------


def test_pure_reads_do_not_produce_a_write_operation():
    listener = _listener()
    _nm(listener, "0x61")  # NM_QUERY_ID
    _nm(listener, "0x6d")  # NM_READ_MEMORY
    assert listener.get_write_operations() == []


def test_write_operations_count_only_writes():
    listener = _listener()
    _nm(listener, "0x61")  # read
    _nm(listener, "0x6e")  # write
    _nm(listener, "0x63")  # write (update domain)
    ops = listener.get_write_operations()
    assert len(ops) == 1
    assert ops[0]["write_count"] == 2

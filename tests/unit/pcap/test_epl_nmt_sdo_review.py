"""Regression tests for the Ethernet POWERLINK (EPL) lookup tables.

Authorities:
- ``tshark -G values | grep '^V\\tepl.pres.stat'`` (tshark 4.4.15) for the NMT
  state codes.
- Upstream ``epan/dissectors/packet-epl.c`` for the SDO command IDs, the NMT
  command IDs and the ASnd service IDs (tshark registers no value_string for
  ``epl.asnd.svid`` / ``epl.asnd.nmtcommand.cid`` / ``epl.asnd.sdo.cmd``, so the
  dissector source is the authority).

Four defects were confirmed:

1. ``SDO_COMMANDS`` / ``SDO_WRITE_COMMANDS`` were exactly INVERTED. In EPL the
   odd command IDs are writes (0x01 Write by Index, 0x03 Write All by Index,
   0x05 Write by Name) and the even ones are reads. The listener named 0x01
   "InitReadByIndex" and put {0x02, 0x04, 0x06} -- the *read* set -- into
   ``SDO_WRITE_COMMANDS``. Every real object-dictionary write was therefore
   counted as a read and never surfaced by ``get_write_operations()``, while
   benign reads were reported as writes.
2. ``EPL_NMT_STATES`` was wrong for every state except Off (0x00) and
   Operational (0xFD) -- and wrong in the worst way, reusing real codes
   (0x19/0x1C/0x5D/0x6D) under the wrong names.
3. ``NMT_COMMANDS`` was a fabricated sequential 0x01..0x3A run; the real table
   is non-sequential (0x21 Start Node, 0x28 Reset Node, ...).
4. ``ASND_SERVICE_IDS`` had 0x06 as "UnspecifiedInvite" and 0x07 as
   "SyncResponse"; 0x06 *is* Sync Response and 0x07 is reserved.
"""

import pytest

from oida.pcap.epl import (
    ASND_SERVICE_IDS,
    EPL_NMT_STATES,
    NMT_COMMANDS,
    SDO_COMMANDS,
    SDO_WRITE_COMMANDS,
    EPLNode,
    EPLPassiveListener,
)


class _Epl:
    """Fake ``epl`` layer exposing only what _process_sdo reads."""

    def __init__(self, **fields):
        self._layer_name = "epl"
        for key, value in fields.items():
            setattr(self, key, value)

    def get_field_value(self, name, raw=False):
        return getattr(self, name.replace(".", "_"), None)


def _sdo(cmd_id):
    """Run one SDO command through the listener; returns (node, rw)."""
    listener = EPLPassiveListener(interface="lo", timeout=1)
    node = EPLNode(node_id=1)
    _, rw = listener._process_sdo(
        _Epl(
            asnd_sdo_cmd_command_id=str(cmd_id),
            asnd_sdo_cmd_data_index="0x1006",
            asnd_sdo_cmd_data_subindex="0",
        ),
        node,
    )
    return node, rw


# ---------------------------------------------------------------------------
# 1. SDO read/write polarity -- the security-relevant one
# ---------------------------------------------------------------------------

UPSTREAM_SDO_COMMANDS = {
    0x00: "NotInList",
    0x01: "WriteByIndex",
    0x02: "ReadByIndex",
    0x03: "WriteAllByIndex",
    0x04: "ReadAllByIndex",
    0x05: "WriteByName",
    0x06: "ReadByName",
    0x20: "FileWrite",
    0x21: "FileRead",
    0x31: "WriteMultipleParameterByIndex",
    0x32: "ReadMultipleParameterByIndex",
    0x70: "MaximumSegmentSize",
    0x71: "LinkNameToIndex",
}


def test_sdo_command_table_matches_the_dissector():
    assert SDO_COMMANDS == UPSTREAM_SDO_COMMANDS


def test_sdo_write_set_is_the_odd_write_verbs():
    assert SDO_WRITE_COMMANDS == {0x01, 0x03, 0x05, 0x20, 0x31}


@pytest.mark.parametrize("cmd_id", [0x01, 0x03, 0x05, 0x20, 0x31])
def test_real_writes_are_counted_as_writes(cmd_id):
    node, rw = _sdo(cmd_id)
    assert rw == "write", f"0x{cmd_id:02x} ({UPSTREAM_SDO_COMMANDS[cmd_id]}) must be a write"
    assert node.sdo_write_count == 1
    assert node.sdo_read_count == 0


@pytest.mark.parametrize("cmd_id", [0x02, 0x04, 0x06, 0x21, 0x32])
def test_real_reads_are_not_counted_as_writes(cmd_id):
    node, rw = _sdo(cmd_id)
    assert rw == "read", f"0x{cmd_id:02x} ({UPSTREAM_SDO_COMMANDS[cmd_id]}) must be a read"
    assert node.sdo_write_count == 0


def test_write_by_index_reaches_get_write_operations():
    """End-to-end: an OD write must surface in the write-ops table."""
    listener = EPLPassiveListener(interface="lo", timeout=1)
    node = EPLNode(node_id=7)
    listener.nodes[7] = node
    listener._process_sdo(_Epl(asnd_sdo_cmd_command_id="1"), node)
    ops = listener.get_write_operations()
    assert len(ops) == 1
    assert ops[0]["write_count"] == 1


# ---------------------------------------------------------------------------
# 2. NMT states
# ---------------------------------------------------------------------------

TSHARK_NMT_STATES = {
    0x00: "Off",
    0x19: "Initialising",
    0x1C: "NotActive",
    0x1D: "PreOperational1",
    0x1E: "BasicEthernet",
    0x29: "ResetApplication",
    0x39: "ResetCommunication",
    0x4D: "Stopped",
    0x5D: "PreOperational2",
    0x6D: "ReadyToOperate",
    0xFD: "Operational",
}


def test_nmt_state_table_matches_the_registry():
    assert EPL_NMT_STATES == TSHARK_NMT_STATES


@pytest.mark.parametrize(
    "code,name",
    [(0x19, "Initialising"), (0x1C, "NotActive"), (0x5D, "PreOperational2"), (0x6D, "ReadyToOperate")],
)
def test_reused_codes_now_carry_the_right_name(code, name):
    """These four codes were present but under the wrong state name."""
    assert EPL_NMT_STATES[code] == name


# ---------------------------------------------------------------------------
# 3. NMT commands
# ---------------------------------------------------------------------------


def test_nmt_command_table_is_the_real_non_sequential_one():
    for code, token in (
        (0x21, "StartNode"),
        (0x22, "StopNode"),
        (0x28, "ResetNode"),
        (0x29, "ResetCommunication"),
        (0x2A, "ResetConfiguration"),
        (0x2B, "SwReset"),
    ):
        assert code in NMT_COMMANDS, f"0x{code:02x} missing"
        assert token in NMT_COMMANDS[code], f"0x{code:02x} -> {NMT_COMMANDS[code]}, want {token}"


def test_fabricated_sequential_nmt_codes_are_gone():
    """0x01-0x08 were invented; no NMT command lives below 0x21."""
    assert not [c for c in NMT_COMMANDS if c < 0x21]


# ---------------------------------------------------------------------------
# 4. ASnd service IDs
# ---------------------------------------------------------------------------


def test_sync_response_is_service_id_6():
    assert ASND_SERVICE_IDS[0x06] == "SyncResponse"


def test_service_id_7_is_not_sync_response():
    assert ASND_SERVICE_IDS.get(0x07) != "SyncResponse"


def test_unspecified_invite_is_not_a_real_service_id():
    assert "UnspecifiedInvite" not in ASND_SERVICE_IDS.values()

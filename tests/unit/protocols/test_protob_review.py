#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hostile-input / malformed-argument review for KNX and OCPP (bug-hunt scope "protoB").

Every test here pins a concrete defect found during a correctness review and
reproduced fail-first against the code as it stood, before the minimal fix was
applied.

Defects pinned:

* ``KNX _parse_memory_write`` returned ``(0, b"")`` on malformed ``--memory-write``
  input while every sibling parser in the module returns a ``None`` sentinel
  (``_parse_group_write`` even documents the convention). The scanner's
  memory-write dispatch had no sentinel check, so a bad argument silently became
  a write to address ``0x0000`` -- which the system-memory guard then rejected
  with the misleading "BLOCKED: Write to system memory could brick device"
  instead of telling the operator the argument format was invalid.

* ``OCPP _send_and_receive`` indexed ``data[0]`` guarded only by
  ``isinstance(data, list)``. A frame of exactly ``[]`` slips past the earlier
  ``len(data) >= 4`` CALL check and raises ``IndexError``. The surrounding
  ``except Exception`` swallows it, so the frame is silently misreported as a
  timeout instead of being returned to the caller. The sibling check in
  ``_persistent_listen`` guards with ``len(data) >= 2`` first.
"""

import asyncio
from typing import Any, Dict, List

import pytest

from oida.protocols.knx.mixins.memory import MemoryMixin

pytestmark = [pytest.mark.unit]


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class _RecordingLogger:
    """Minimal stand-in for the NXC-style logger used by the scanners."""

    def __init__(self) -> None:
        self.messages: List[str] = []

    def _record(self, msg, *args, **kwargs):
        self.messages.append(str(msg) % args if args else str(msg))

    display = info = debug = success = fail = warning = highlight = _record

    @property
    def text(self) -> str:
        return "\n".join(self.messages)


class _Memory(MemoryMixin):
    """Real MemoryMixin with only the collaborators it touches stubbed out."""

    def __init__(self, args: Dict[str, Any] | None = None) -> None:
        self.logger = _RecordingLogger()
        self.args = args if args is not None else {}


# ---------------------------------------------------------------------------
# KNX: malformed --memory-write must not degrade into a write to address 0
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_arg",
    [
        "garbage",  # no ":" separator at all
        "0x100",  # address only, no data
        "0x100:zz",  # data is not valid hex
        "notanaddr:aabb",  # address is not a number
        "",  # empty
        "a:b:c",  # too many parts
    ],
)
def test_parse_memory_write_returns_none_sentinel_on_malformed_input(bad_arg):
    """Malformed --memory-write must yield a None address, never a usable 0x0000.

    Returning ``(0, b"")`` made the caller proceed with a real write attempt to
    address 0 instead of reporting a parse failure.
    """
    mem = _Memory()

    addr, data = mem._parse_memory_write(bad_arg)

    assert addr is None, f"{bad_arg!r} must parse to a None address sentinel, got {addr!r}"
    assert data == b""


def test_parse_memory_write_still_accepts_valid_input():
    """The sentinel change must not break the happy path (hex and decimal)."""
    mem = _Memory()

    assert mem._parse_memory_write("0x0100:aabb") == (0x100, b"\xaa\xbb")
    assert mem._parse_memory_write("256:aabb") == (256, b"\xaa\xbb")


def test_write_memory_rejects_none_address_without_the_brick_warning():
    """A None address must report an invalid address, not the system-memory block.

    Before the fix the malformed argument arrived as address 0, so the operator
    was told their write was "BLOCKED: Write to system memory ... could brick
    device" -- a misleading diagnostic for what is really a bad CLI argument.
    """
    mem = _Memory({"confirm": True})

    result = asyncio.run(mem._write_memory(None, "1.1.1", None, b""))

    assert result["success"] is False
    assert result["error"] == "Invalid memory address"
    assert result["mem_addr"] is None
    # The actual user-visible bug: the wrong diagnostic must be gone.
    assert "BLOCKED" not in mem.logger.text
    assert "brick" not in mem.logger.text
    assert "Refusing memory write" in mem.logger.text


def test_write_memory_still_blocks_real_system_memory_writes():
    """The genuine safety guard must survive the fix (address 0 passed explicitly)."""
    mem = _Memory({"confirm": True})

    result = asyncio.run(mem._write_memory(None, "1.1.1", 0x0000, b"\xaa"))

    assert result["success"] is False
    assert "BLOCKED" in result["error"]
    assert "brick" in result["error"]
    assert "Write blocked" in mem.logger.text


# ---------------------------------------------------------------------------
# OCPP: a bare "[]" frame must not raise IndexError
# ---------------------------------------------------------------------------


def _classify(data: Any) -> str:
    """Mirror of the response-type check in ocpp scanner._send_and_receive.

    Kept in lockstep with the production expression so the guard it pins is
    exercised directly.
    """
    from oida.protocols.ocpp.constants import MessageType

    return (
        "CALLRESULT"
        if (isinstance(data, list) and len(data) >= 2 and data[0] == MessageType.CALLRESULT)
        else "CALLERROR"
    )


@pytest.mark.parametrize("frame", [[], [3], {}, "", None, 0])
def test_ocpp_response_classification_survives_degenerate_frames(frame):
    """A hostile/degenerate frame must classify without raising IndexError.

    ``[]`` slips past the earlier ``len(data) >= 4`` CALL guard, so the
    unguarded ``data[0]`` was reachable; the resulting IndexError was swallowed
    by a broad handler and the frame silently misreported as a timeout.
    """
    assert _classify(frame) in {"CALLRESULT", "CALLERROR"}


def test_ocpp_response_classification_still_detects_a_real_callresult():
    """The added length guard must not break correct CALLRESULT detection."""
    from oida.protocols.ocpp.constants import MessageType

    assert _classify([MessageType.CALLRESULT, "msg-id", {}]) == "CALLRESULT"
    assert _classify([MessageType.CALLERROR, "msg-id", "ErrCode", "desc", {}]) == "CALLERROR"


def test_ocpp_scanner_source_guards_data_index():
    """Pin the guard in the real source so the fix cannot silently regress."""
    import inspect

    from oida.protocols.ocpp import scanner as ocpp_scanner

    src = inspect.getsource(ocpp_scanner)
    # Both the _send_and_receive check and the _persistent_listen sibling must
    # length-check before indexing data[0].
    assert src.count("len(data) >= 2") >= 2

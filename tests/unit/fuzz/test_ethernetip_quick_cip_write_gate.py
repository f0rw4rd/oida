"""
Offline tests for the EtherNet/IP Quick CIP coverage sweep write-gate.

The Phase-1 baseline sweep (Quick_CIP_Coverage) iterates a Group of CIP
service codes. Several of those services are state-changing/destructive
(RESET/START/STOP/CREATE/DELETE/SET_*/WRITE_*/FORWARD_OPEN/APPLY_ATTRIBUTES).
They must only be sent when --enable-write (protocol option "enable_write")
is set, mirroring the gating already applied to the dedicated Phase-3 write
requests. Without the gate the baseline sweep silently bypasses the
read-only safety default.

Regression guard: destructive CIP
services in the quick-coverage Service Group were not gated behind
enable_write.
"""

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols import PROTOCOL_FUZZERS
from tests.service_gate import require_service

pytestmark = pytest.mark.core

# CIP service codes that change device state / write data. The quick-coverage
# sweep must never emit these unless enable_write is True.
DESTRUCTIVE_CIP_SERVICES = {
    0x02,  # SET_ATTRIBUTES_ALL
    0x04,  # SET_ATTRIBUTE_LIST
    0x05,  # RESET
    0x06,  # START
    0x07,  # STOP
    0x08,  # CREATE
    0x09,  # DELETE
    0x0D,  # APPLY_ATTRIBUTES
    0x10,  # SET_ATTRIBUTE_SINGLE
    0x4D,  # WRITE_TAG
    0x53,  # WRITE_TAG_FRAGMENTED
    0x54,  # FORWARD_OPEN
}


def _make_config(enable_write):
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=0,
        protocol_type=ProtocolType.TCP,
        enumerate=False,
    )
    config.log_session = False
    config.console_output = False
    config.skip_pre_send_checks = True
    config.web_interface = False
    config.protocol_options = {"enable_write": enable_write}
    return config


def _build(config):
    fuzzer_class = PROTOCOL_FUZZERS["ethernetip"]
    if fuzzer_class is None:
        require_service("ethernetip fuzzer not available (optional dependency)")
    return fuzzer_class(config=config, connection_factory=MockConnectionFactory())


def _find(block, name):
    if getattr(block, "name", None) == name:
        return block
    for child in getattr(block, "stack", []) or []:
        found = _find(child, name)
        if found is not None:
            return found
    return None


def _quick_cip_service_codes(enable_write):
    """All CIP service codes the Quick_CIP_Coverage sweep can emit.

    boofuzz Group treats the first value as the (non-fuzzing) default and
    excludes it from .values, so the full emitted set is default + values.
    """
    fuzzer = _build(_make_config(enable_write))
    node = next(n for n in fuzzer.session.nodes.values() if n.name == "Quick_CIP_Coverage")
    group = _find(node, "Service")
    assert group is not None, "Service group not found in Quick_CIP_Coverage"
    emitted = list(group.values) + [group._default_value]
    return {b[0] for b in emitted}


def test_quick_cip_sweep_read_only_by_default():
    """Without enable_write, the baseline sweep emits NO destructive services."""
    codes = _quick_cip_service_codes(enable_write=False)
    leaked = codes & DESTRUCTIVE_CIP_SERVICES
    assert not leaked, (
        f"Quick CIP sweep emitted destructive services without enable_write: "
        f"{sorted(hex(c) for c in leaked)}"
    )


def test_quick_cip_sweep_includes_writes_when_enabled():
    """With enable_write, the destructive services are restored to the sweep."""
    codes = _quick_cip_service_codes(enable_write=True)
    assert DESTRUCTIVE_CIP_SERVICES <= codes, (
        f"Quick CIP sweep missing destructive services with enable_write: "
        f"{sorted(hex(c) for c in (DESTRUCTIVE_CIP_SERVICES - codes))}"
    )


def test_quick_cip_sweep_always_has_read_services():
    """Read-only services run regardless of the write gate (sweep stays useful)."""
    read_only = {0x01, 0x0E, 0x4C}  # GET_ATTRIBUTES_ALL, GET_ATTRIBUTE_SINGLE, READ_TAG
    for enable_write in (False, True):
        codes = _quick_cip_service_codes(enable_write)
        assert read_only <= codes, (
            f"Read-only services missing (enable_write={enable_write}): "
            f"{sorted(hex(c) for c in (read_only - codes))}"
        )

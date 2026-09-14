"""Regression tests: the fuzzer protocol registry is dependency-tolerant.

BUG-7 (wheel install): ``fuzz/protocols/__init__.py`` used to import every
protocol fuzzer eagerly and unconditionally, so ``import PROTOCOL_FUZZERS`` (and
therefore ``oida fuzz modbus``) transitively required the union of every
protocol's optional dependency -- asyncua, crc, python-can, pydicom, hl7, ... A
single missing one aborted the whole fuzz subsystem, and the CLI blamed it on
the ``fuzz`` extra (which does not even contain those libs).

The loader now imports each protocol independently: available protocols register
in ``PROTOCOL_FUZZERS``, and a protocol whose dependency is absent is recorded in
``PROTOCOL_IMPORT_ERRORS`` with a precise ``install_hint`` naming the right extra
-- one missing dep must not take out the rest.
"""

import importlib
import sys

import oida.fuzz.protocols as proto


def test_core_only_protocols_are_always_registered():
    """Protocols that need only the fuzz core (no scanner lib) must be present."""
    # tcp/echo/daytime/mutation ride entirely on boofuzz+scapy (the fuzz extra),
    # so if the fuzz core is importable at all, these must have registered.
    for key in ("tcp", "echo", "daytime", "mutation"):
        assert key in proto.PROTOCOL_FUZZERS, f"{key} should register on fuzz core alone"


def test_install_hint_names_the_protocol_extra():
    """The hint points at the *actual* extra, not a blanket ``[fuzz]``."""
    assert proto.install_hint("modbus") == 'pip install "oida[fuzz,modbus]"'
    assert proto.install_hint("s7comm") == 'pip install "oida[fuzz,snap7]"'
    assert proto.install_hint("snmpv2c") == 'pip install "oida[fuzz,snmp]"'
    # A core-only protocol only needs the fuzz extra.
    assert proto.install_hint("tcp") == 'pip install "oida[fuzz]"'


def test_one_missing_dependency_does_not_break_the_rest():
    """Simulate an absent optional dep: only that protocol drops out."""
    victim_mod = "oida.fuzz.protocols.opcua"
    saved = sys.modules.get(victim_mod)
    # A None entry in sys.modules makes ``import oida.fuzz.protocols.opcua``
    # raise ImportError -- exactly how a missing asyncua would surface.
    sys.modules[victim_mod] = None  # type: ignore[assignment]
    try:
        reloaded = importlib.reload(proto)

        # The crippled protocol is absent but recorded, not silently gone.
        assert "opcua" not in reloaded.PROTOCOL_FUZZERS
        assert reloaded.import_error_for("opcua") is not None

        # Everything else still works -- one bad dep is contained.
        assert "modbus" in reloaded.PROTOCOL_FUZZERS
        assert "tcp" in reloaded.PROTOCOL_FUZZERS
        # And the hint for the broken protocol is still precise.
        assert reloaded.install_hint("opcua") == 'pip install "oida[fuzz,opcua]"'
    finally:
        if saved is not None:
            sys.modules[victim_mod] = saved
        else:
            sys.modules.pop(victim_mod, None)
        importlib.reload(proto)


def test_unknown_protocol_has_no_recorded_import_error():
    """A truly unknown key is distinct from a known-but-unavailable one."""
    importlib.reload(proto)
    assert proto.import_error_for("not_a_real_protocol") is None
    assert "not_a_real_protocol" not in proto.PROTOCOL_FUZZERS

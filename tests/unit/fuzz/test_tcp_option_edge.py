"""
Offline tests for the two new TCP option-edge requests.

Adds coverage for:
  * TCP_Timestamp_ShiftUB      - Timestamp (kind=8, len=10) whose TSval high
                                 byte is >= 0x80, targeting stacks that rebuild
                                 the 32-bit TSval via a signed `byte << 24`.
  * TCP_Option_Length_Underflow - an option whose length byte is < 2 (or larger
                                 than the remaining region), driving the
                                 option-walk into advance-past-self / underflow.

The TCP fuzzer connects every request unconditionally in _define_protocol()
(per-request gating happens later in fuzz_all() via is_request_enabled), so
"selectable" is asserted two ways: the request is advertised AND wired into
the session, and is_request_enabled() honours --enable for it in isolation.

Everything is built offline with MockConnectionFactory -- no network / raw
socket / root. The TCP fuzzer defaults to raw-socket mode (ProtocolType.RAW),
which the mock factory satisfies without privileges.
"""

import pytest

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols import PROTOCOL_FUZZERS

pytestmark = pytest.mark.core

NEW_REQUESTS = {
    "TCP_Timestamp_ShiftUB",
    "TCP_Option_Length_Underflow",
}


def _make_config(**overrides):
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=0,
        protocol_type=ProtocolType.RAW,
        enumerate=False,
    )
    config.log_session = False
    config.console_output = False
    config.skip_pre_send_checks = True
    config.web_interface = False
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


def _build(config):
    fuzzer_class = PROTOCOL_FUZZERS["tcp"]
    if fuzzer_class is None:
        pytest.skip("tcp fuzzer not available (optional dependency)")
    return fuzzer_class(config=config, connection_factory=MockConnectionFactory())


def _advertised():
    return {d.name for d in PROTOCOL_FUZZERS["tcp"].get_request_definitions()}


def _connected_names(fuzzer):
    session = fuzzer.session
    return {node.name for node in session.nodes.values()} - {session.root.name}


def _find_node(fuzzer, name):
    for node in fuzzer.session.nodes.values():
        if node.name == name:
            return node
    raise AssertionError(f"request node {name!r} not connected")


def _find_child(node, name):
    """Depth-first search for a named primitive/block in a request tree."""
    if getattr(node, "name", None) == name:
        return node
    for child in getattr(node, "stack", []) or []:
        found = _find_child(child, name)
        if found is not None:
            return found
    return None


def test_new_requests_are_advertised():
    """Both new requests appear in --list-requests (get_request_definitions)."""
    assert NEW_REQUESTS <= _advertised()


def test_new_requests_are_connected():
    """Both new requests are wired into the boofuzz session under defaults."""
    connected = _connected_names(_build(_make_config()))
    assert NEW_REQUESTS <= connected
    # Nothing connected is unadvertised (catalog stays the single source of truth).
    assert connected <= _advertised()


@pytest.mark.parametrize("name", sorted(NEW_REQUESTS))
def test_new_request_individually_selectable(name):
    """--enable <name> gates to exactly that request in fuzz_all()."""
    fuzzer = _build(_make_config(enabled_requests=[name]))
    assert fuzzer.is_request_enabled(name)
    for other in NEW_REQUESTS - {name}:
        assert not fuzzer.is_request_enabled(other)
    # The node still has to exist so fuzz_node() can target it.
    assert name in _connected_names(fuzzer)


@pytest.mark.parametrize("name", sorted(NEW_REQUESTS))
def test_new_request_is_disableable(name):
    """--disable <name> excludes it while leaving a default request enabled."""
    fuzzer = _build(_make_config(disabled_requests=[name]))
    assert not fuzzer.is_request_enabled(name)
    assert fuzzer.is_request_enabled("TCP_Data")


def test_timestamp_shift_ub_renders_high_tsval():
    """Rendered TSval high byte is >= 0x80 for the baseline and every mutation.

    The option is well-formed (kind=8, length=10) so a parser reaches the
    TSval; every value carries bit 31, the signed `<<24` shift-UB trigger.
    """
    fuzzer = _build(_make_config())
    node = _find_node(fuzzer, "TCP_Timestamp_ShiftUB")

    rendered = node.render()
    idx = rendered.find(b"\x08\x0a")  # Timestamp kind + length
    assert idx >= 0, "Timestamp option (kind=8, len=10) not present in render"
    tsval_high = rendered[idx + 2]
    assert tsval_high >= 0x80, f"baseline TSval high byte {tsval_high:#x} < 0x80"

    # Every declared TSval mutation also sets bit 31.
    group = _find_child(node, "TS_ShiftUB_TSval")
    assert group is not None, "TSval Group primitive missing"
    mutation_values = list(group.mutations(None))
    assert mutation_values, "TSval Group produced no mutations"
    for value in mutation_values:
        assert value[0] >= 0x80, f"TSval mutation {value.hex()} high byte < 0x80"


def test_option_length_underflow_has_malformed_length():
    """The malformed length Group includes a byte < 2 and renders at kind=2."""
    fuzzer = _build(_make_config())
    node = _find_node(fuzzer, "TCP_Option_Length_Underflow")

    group = _find_child(node, "OptLenUnderflow_Length")
    assert group is not None, "option-length Group missing"
    length_values = [group.render()] + list(group.mutations(None))
    length_bytes = {v[0] for v in length_values if v}
    # At least one length is below the 2-byte option minimum (underflow class).
    assert any(b < 2 for b in length_bytes), f"no sub-minimum length in {length_bytes}"

    # Render the options block in isolation so header bytes (e.g. the 0x02 SYN
    # flag) can't be mistaken for the MSS option kind.
    options = _find_child(node, "OptLenUnderflow_Options")
    assert options is not None, "options block missing"
    rendered = options.render()
    assert rendered[0] == 0x02, f"option kind {rendered[0]:#x} != MSS (2)"
    # The byte after the kind is the malformed length (default Group value 0x00).
    assert rendered[1] < 2, f"length byte {rendered[1]:#x} not < 2"

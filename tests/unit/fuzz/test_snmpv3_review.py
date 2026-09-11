"""Regression test for snmpv3.py SNMPv3_USMAuthFuzz fuzzable-leaf bug.

Byte("MaxSize_Prefix", 0x00) at the top of the SNMPv3_USMAuthFuzz request body
was missing fuzzable=False (the identical primitive elsewhere in the file, e.g.
for SNMPv3_BERStructured, correctly sets it). Leaving it fuzzable meant this
"USM auth isolation" campaign -- meant to concentrate fuzzing on AuthParams/
PrivParams -- was instead mostly (112 of 122 leaves) mutating an unrelated BER
length-prefix padding byte.
"""

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols import PROTOCOL_FUZZERS


def _build_snmpv3_fuzzer():
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=161,
        protocol_type=ProtocolType.UDP,
        enumerate=False,
    )
    config.log_session = False
    config.console_output = False
    config.skip_pre_send_checks = True
    config.web_interface = False
    return PROTOCOL_FUZZERS["snmpv3"](config=config, connection_factory=MockConnectionFactory())


def _node(fz, name):
    return next(n for n in fz.session.nodes.values() if getattr(n, "name", "") == name)


def _fuzzable_leaf_names(node):
    # Request.walk() recursively yields every primitive/block on the request stack,
    # stepping into (but not yielding) FuzzableBlock containers -- so this gives us
    # the flat list of leaf primitives, matching how boofuzz enumerates mutation
    # targets during a real fuzzing run.
    return [item.name for item in node.walk() if getattr(item, "fuzzable", False)]


def test_usm_auth_fuzz_maxsize_prefix_is_not_fuzzable():
    fz = _build_snmpv3_fuzzer()
    node = _node(fz, "SNMPv3_USMAuthFuzz")
    fuzzable = _fuzzable_leaf_names(node)
    assert "MaxSize_Prefix" not in fuzzable


def test_usm_auth_fuzz_only_fuzzes_auth_priv_params():
    fz = _build_snmpv3_fuzzer()
    node = _node(fz, "SNMPv3_USMAuthFuzz")
    # The only fuzzable leaves must be the two USM parameter Groups:
    # AuthParams_Value (5 values) and PrivParams_Value (5 values) = 10 real
    # mutations for this "auth isolation" campaign.
    fuzzable = _fuzzable_leaf_names(node)
    assert set(fuzzable) == {"AuthParams_Value", "PrivParams_Value"}
    total_mutations = sum(
        len(item.values) for item in node.walk() if getattr(item, "fuzzable", False)
    )
    assert total_mutations == 10

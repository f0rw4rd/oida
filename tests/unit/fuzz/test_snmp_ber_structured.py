"""Structured ASN.1/BER codec-mutator tests for the SNMP fuzzers.

The ``ASN1Builder`` structured mutators in ``oida.fuzz.core.codecs.asn1``
(``fuzz_tag_variants`` / ``build_truncated`` / ``build_with_overflow`` /
``build_nested_depth``) previously had zero call sites. The new
``SNMPvX_BER_Structured`` requests wire them onto a single SNMP variable binding
via ``snmp_common.structured_ber_varbind_values``, adding varbind/PDU BER
parser-fuzzing coverage that the length-of-length / truncated-length nodes do
NOT provide: tag confusion, over-declared length (declared > actual), oversized
content, and deep SEQUENCE nesting (CVE-2019-9162 class parser attacks).

These tests build each fuzzer offline (MockConnectionFactory, recording session,
no network) and assert the new request is advertised + connected and that every
structured mutator's output actually reaches the rendered wire bytes.
"""

import pytest

from boofuzz.mutation_context import MutationContext

from src.oida.fuzz.core.config import FuzzerConfig, ProtocolType
from src.oida.fuzz.core.connections.base import MockConnectionFactory
from src.oida.fuzz.protocols.snmp_common import structured_ber_varbind_values
from src.oida.fuzz.protocols.snmpv1 import SNMPv1Fuzzer
from src.oida.fuzz.protocols.snmpv2 import SNMPv2cFuzzer
from src.oida.fuzz.protocols.snmpv3 import SNMPv3Fuzzer


# (fuzzer class, Structured request name, varbind OID the node fuzzes)
SNMP_FUZZERS = [
    (SNMPv1Fuzzer, "SNMP_BER_Structured", "1.3.6.1.2.1.1.1.0"),
    (SNMPv2cFuzzer, "SNMPv2c_BER_Structured", "1.3.6.1.2.1.1.1.0"),
    (SNMPv3Fuzzer, "SNMPv3_BER_Structured", "1.3.6.1.2.1.1.1.0"),
]


class _Collector:
    """Records connected Request objects without touching the network."""

    def __init__(self):
        self.requests = {}

    def connect(self, request, *args, **kwargs):
        self.requests[request.name] = request


def _connected_requests(cls, enable_set=True):
    """Build a fuzzer offline and return {name: Request} for every connected request."""
    config = FuzzerConfig(
        target_ip="192.168.1.100",
        target_port=161,
        protocol_type=ProtocolType.UDP,
    )
    config.protocol_options = {"enable_set": enable_set}

    fuzzer = cls(config, connection_factory=MockConnectionFactory())
    collector = _Collector()
    fuzzer._session = collector
    fuzzer._define_protocol()
    return collector.requests


def _all_renders(request):
    """Return base render plus every mutated render for a Request."""
    blobs = [request.render()]
    for mutation in request.mutations(None):
        blobs.append(request.render(MutationContext(mutation)))
    return blobs


# =============================================================================
# Helper sanity: the structured mutators are actually driven
# =============================================================================


class TestStructuredValues:
    def test_first_value_is_valid_baseline_sequence(self):
        """values[0] is a spec-valid varbind SEQUENCE (tag 0x30, honest length)."""
        vals = structured_ber_varbind_values("1.3.6.1.2.1.1.1.0")
        valid = vals[0]
        assert valid[0] == 0x30
        assert valid[1] == len(valid) - 2  # short-form length matches content

    def test_tag_confusion_present(self):
        """fuzz_tag_variants contributes a wrong / reserved leading tag byte."""
        vals = structured_ber_varbind_values("1.3.6.1.2.1.1.1.0")
        leading = {v[0] for v in vals}
        # invalid universal tags emitted by fuzz_tag_variants
        assert 0x00 in leading
        assert 0xFF in leading

    def test_overflow_present(self):
        """build_with_overflow contributes oversized 'A'-padded content."""
        vals = structured_ber_varbind_values("1.3.6.1.2.1.1.1.0", overflow_size=200)
        assert any(b"A" * 200 in v for v in vals)

    def test_deep_nesting_present(self):
        """build_nested_depth contributes a deeply nested SEQUENCE stack."""
        vals = structured_ber_varbind_values("1.3.6.1.2.1.1.1.0", nested_depth=100)
        # The nested value carries far more SEQUENCE tags than any other variant.
        assert max(v.count(0x30) for v in vals) >= 100

    def test_length_lie_over_declares(self):
        """build_truncated declares full length but withholds trailing content."""
        vals = structured_ber_varbind_values("1.3.6.1.2.1.1.1.0", truncate_by=1)
        valid = vals[0]
        content_len = len(valid) - 2
        truncated = b"\x30" + bytes([content_len])  # honest length, short content
        # A variant whose declared length is content_len but body is 1 byte short.
        assert any(v.startswith(truncated) and len(v) == content_len + 1 for v in vals)


# =============================================================================
# Advertised + connected
# =============================================================================


@pytest.mark.parametrize("cls,name,oid", SNMP_FUZZERS)
class TestStructuredRequestAdvertisedAndConnected:
    def test_advertised(self, cls, name, oid):
        """The structured request appears in get_request_definitions()."""
        names = {r.name for r in cls.get_request_definitions()}
        assert name in names

    def test_connected(self, cls, name, oid):
        """The structured request is connected to the session on a default run."""
        connected = _connected_requests(cls)
        assert name in connected

    def test_category_is_high_crash(self, cls, name, oid):
        """The structured request reuses the existing high_crash category."""
        by_name = {r.name: r for r in cls.get_request_definitions()}
        assert by_name[name].category == "high_crash"


# =============================================================================
# Every structured mutator's output reaches the wire
# =============================================================================


@pytest.mark.parametrize("cls,name,oid", SNMP_FUZZERS)
class TestStructuredMutatorsOnWire:
    def test_baseline_is_wellformed_snmp_message(self, cls, name, oid):
        """The unmutated baseline renders a valid outer SNMP SEQUENCE frame."""
        request = _connected_requests(cls)[name]
        base = request.render()
        assert base[0] == 0x30  # outer SEQUENCE
        # The valid baseline varbind must be embedded verbatim.
        valid_varbind = structured_ber_varbind_values(oid)[0]
        assert valid_varbind in base

    def test_request_produces_mutations(self, cls, name, oid):
        """The Group of structured variants generates mutations."""
        request = _connected_requests(cls)[name]
        assert request.num_mutations(None) >= 10

    def test_every_mutator_value_reaches_the_wire(self, cls, name, oid):
        """Each structured mutator output appears verbatim in some render."""
        request = _connected_requests(cls)[name]
        blobs = _all_renders(request)
        for value in structured_ber_varbind_values(oid):
            assert any(value in blob for blob in blobs), (
                f"{name}: structured varbind variant {value[:8].hex()}... never emitted"
            )

    def test_overflow_and_nesting_on_wire(self, cls, name, oid):
        """Overflow padding and deep nesting specifically reach the wire."""
        request = _connected_requests(cls)[name]
        blobs = _all_renders(request)
        # Overflow: a long run of 'A' padding.
        assert any(b"A" * 200 in blob for blob in blobs)
        # Deep nesting: a render carrying >= 100 SEQUENCE tags.
        assert any(blob.count(0x30) >= 100 for blob in blobs)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

"""Offline coverage test for the OPC UA structured-BER certificate mutation node.

The OPC UA fuzzer is otherwise a binary-encoding fuzzer, but the SenderCertificate
carried in OpenSecureChannel is X.509 DER — a genuine ASN.1/BER parse surface. The
``OPCUA_CertBERMutation`` request drives the shared ``ASN1Builder`` BER mutators
(previously dead code) against a valid DER SEQUENCE template:

  - fuzz_length_variants  (malformed BER length encodings)
  - fuzz_tag_variants     (invalid / long-form / multi-byte tags)
  - build_truncated       (length says full, content short)
  - build_with_overflow   (oversized content)
  - build_nested_depth    (deep nesting -> stack exhaustion)

These tests build the session fully offline via MockConnectionFactory and assert the
node is registered, wired into the boofuzz session graph, and produces real fuzzable
mutations — no network I/O.
"""

import pytest
from boofuzz import Request

from oida.fuzz.core.codecs.asn1 import ASN1Builder, ASN1Tag, ber_content
from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols.opcua import OPCUAFuzzer

pytestmark = pytest.mark.core

NODE_NAME = "OPCUA_CertBERAttack"
GROUP_NAME = "Cert_BER_Mutation"


def _make_fuzzer():
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=4840,
        protocol_type=ProtocolType.TCP,
        log_session=False,
        console_output=False,
        skip_pre_send_checks=True,
        web_interface=False,
        enumerate=False,
    )
    return OPCUAFuzzer(config=config, connection_factory=MockConnectionFactory())


def _requests(session):
    return {v.name: v for v in session.nodes.values() if isinstance(v, Request)}


def _find_primitive(request, name):
    for prim in request.walk():
        if prim.name == name:
            return prim
    return None


def test_cert_ber_mutation_registered_in_definitions():
    """The node must be advertised via get_request_definitions() (for --list-requests)."""
    names = {ri.name for ri in OPCUAFuzzer.get_request_definitions()}
    assert NODE_NAME in names


def test_cert_ber_mutation_node_in_session():
    """The node must be connected into the live boofuzz session graph."""
    fuzzer = _make_fuzzer()
    reqs = _requests(fuzzer.session)
    assert NODE_NAME in reqs


def test_cert_ber_mutation_group_has_fuzzable_values():
    """The DER-mutation Group must exist, be fuzzable, and carry many variants."""
    fuzzer = _make_fuzzer()
    node = _requests(fuzzer.session)[NODE_NAME]
    group = _find_primitive(node, GROUP_NAME)

    assert group is not None, f"{GROUP_NAME} Group not found in {NODE_NAME}"
    assert group.fuzzable
    # length(7) + tag(12) + truncated(2) + overflow(1) + nested(1) + baseline(1),
    # de-duplicated. Comfortably more than a hand-rolled handful.
    assert len(group.values) >= 15


def test_cert_ber_mutation_produces_mutations():
    """The node must generate real test cases (not a dead all-Static request)."""
    fuzzer = _make_fuzzer()
    node = _requests(fuzzer.session)[NODE_NAME]
    assert node.num_mutations(None) >= len(_find_primitive(node, GROUP_NAME).values)


def test_cert_ber_mutation_values_are_valid_der_derived():
    """The mutation set must actually exercise every wired ASN1Builder mutator.

    Rebuild the expected components independently and confirm the node's Group
    contains the systematic length/tag/truncation/overflow/nested outputs — i.e.
    the previously-dead mutators are genuinely reachable now.
    """
    fuzzer = _make_fuzzer()
    node = _requests(fuzzer.session)[NODE_NAME]
    group = _find_primitive(node, GROUP_NAME)
    # boofuzz Group uses values[0] as the (non-fuzzed) default; .values holds the
    # remaining mutation cases. Union the default in for membership checks.
    values = set(group.values)
    values.add(group._default_value)

    asn1 = ASN1Builder()
    seq_tag = ASN1Tag.SEQUENCE
    inner = asn1.build_integer(2) + asn1.build_integer(0x2A)
    cert_tlv = asn1.build_sequence(inner)
    content = ber_content(cert_tlv)

    # Baseline valid cert present.
    assert cert_tlv in values
    # Length variants (tag prepended) all present.
    for v in asn1.fuzz_length_variants(content):
        assert bytes([seq_tag]) + v in values
    # Tag variants all present.
    for v in asn1.fuzz_tag_variants(seq_tag, cert_tlv[1:]):
        assert v in values
    # Truncation, overflow, deep nesting present.
    assert asn1.build_truncated(seq_tag, content, truncate_by=1) in values
    assert asn1.build_with_overflow(seq_tag, content, overflow_size=512) in values
    assert asn1.build_nested_depth(seq_tag, content, depth=200) in values


def test_cert_ber_mutation_framing_size_prefixed():
    """SenderCertificate must be length-prefixed by a Size primitive so OPC UA
    framing stays valid for every mutated DER blob (only the DER layer is corrupt)."""
    from boofuzz import Size

    fuzzer = _make_fuzzer()
    node = _requests(fuzzer.session)[NODE_NAME]
    size_prim = _find_primitive(node, "SenderCertificate_Length")
    assert isinstance(size_prim, Size)

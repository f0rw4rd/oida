"""Correctness tests for the ASN.1 primitives' boofuzz render contract.

``ASN1Primitive.encode()`` and ``ASN1Sequence.encode()`` used to read
``mutation_context.mutation_index``.  boofuzz's ``MutationContext`` has no such
attribute (its public attributes are ``message_path``, ``mutations`` and
``protocol_session``), so rendering any ASN.1 primitive inside a real fuzzing
session raised ``AttributeError`` on the very first test case.

They also ignored the ``value`` argument, which is what actually carries the
mutation: ``Fuzzable.render()`` calls
``encode(value=self.get_value(mutation_context), mutation_context=...)``.

On top of that the two index spaces were off by one -- ``mutations()`` yields
``_mutations[1:]`` while ``encode()`` indexed ``_mutations[mutation_index]``,
where index 0 is the *valid* encoding.
"""

import pytest

boofuzz = pytest.importorskip("boofuzz")

from boofuzz import Request  # noqa: E402
from boofuzz.mutation_context import MutationContext  # noqa: E402

from oida.fuzz.primitives.asn1_blocks import (  # noqa: E402
    ASN1BitString,
    ASN1Boolean,
    ASN1Integer,
    ASN1Null,
    ASN1OctetString,
    ASN1OID,
    ASN1Sequence,
    ASN1VisibleString,
)


def _primitives():
    return [
        ("ASN1Integer", lambda: ASN1Integer("x", 5)),
        ("ASN1Boolean", lambda: ASN1Boolean("x", True)),
        ("ASN1OctetString", lambda: ASN1OctetString("x", b"test")),
        ("ASN1BitString", lambda: ASN1BitString("x", b"\x01\x02")),
        ("ASN1OID", lambda: ASN1OID("x", "1.0.9506.2.3")),
        ("ASN1Null", lambda: ASN1Null("x")),
        ("ASN1VisibleString", lambda: ASN1VisibleString("x", "abc")),
        ("ASN1Sequence", lambda: ASN1Sequence("x", children=[ASN1Integer("i", 1)])),
    ]


def test_mutation_context_really_has_no_mutation_index():
    """Guards the assumption this whole test module rests on."""
    assert not hasattr(MutationContext(), "mutation_index")


@pytest.mark.parametrize("label,factory", _primitives(), ids=[n for n, _ in _primitives()])
def test_rendering_a_real_mutation_context_does_not_raise(label, factory):
    primitive = factory()
    request = Request("r", children=(primitive,))

    # Must not raise AttributeError on mutation_index.
    for mutation in request.get_mutations():
        request.render(MutationContext(mutations=mutation))


@pytest.mark.parametrize("label,factory", _primitives(), ids=[n for n, _ in _primitives()])
def test_every_yielded_mutation_is_what_gets_rendered(label, factory):
    """encode() must honour ``value``, so the render equals the yielded bytes."""
    primitive = factory()
    request = Request("r", children=(primitive,))

    yielded = list(primitive.mutations(None))
    rendered = [request.render(MutationContext(mutations=m)) for m in request.get_mutations()]

    assert len(rendered) == len(yielded) == primitive.num_mutations()
    assert rendered == yielded


@pytest.mark.parametrize("label,factory", _primitives(), ids=[n for n, _ in _primitives()])
def test_unmutated_render_is_the_valid_encoding(label, factory):
    primitive = factory()
    request = Request("r", children=(primitive,))

    assert request.render() == primitive._mutations[0]
    assert primitive.original_value() == primitive._mutations[0]


def test_the_valid_encoding_is_not_re_emitted_as_a_mutation():
    """Index 0 is the valid encoding; it must not be served as mutation #0."""
    primitive = ASN1Integer("x", 5)
    request = Request("r", children=(primitive,))

    rendered = [request.render(MutationContext(mutations=m)) for m in request.get_mutations()]

    assert rendered[0] == primitive._mutations[1]
    # The final mutation must be reachable (it used to be off the end).
    assert rendered[-1] == primitive._mutations[-1]

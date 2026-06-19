#!/usr/bin/env python3
"""Tests for the default_credentials helper module.

Regression coverage for the shared-mutable-state finding
(CODE_REVIEW.md: default_credentials.py:144) — get_protocol_defaults() must
return a defensive copy so callers cannot mutate the module-level constants
or leak entries across aliased protocols.
"""

from oida.utils import default_credentials as dc
from oida.utils.default_credentials import get_protocol_defaults


def test_returns_expected_defaults():
    assert get_protocol_defaults("s7") == dc.SIEMENS_S7_DEFAULTS
    assert get_protocol_defaults("dnp3_sa") == dc.DNP3_SA_DEFAULTS
    assert get_protocol_defaults("unknown_protocol") == []


def test_returns_copy_not_reference():
    """The returned list must not be the module-level object itself."""
    result = get_protocol_defaults("s7")
    assert result is not dc.SIEMENS_S7_DEFAULTS
    assert result == dc.SIEMENS_S7_DEFAULTS


def test_mutation_does_not_corrupt_shared_state():
    """Mutating a returned list must not affect a subsequent call's result."""
    first = get_protocol_defaults("s7")
    original_len = len(first)

    first.append("INJECTED_PASSWORD")
    first.sort()

    second = get_protocol_defaults("s7")
    assert "INJECTED_PASSWORD" not in second
    assert len(second) == original_len
    # Module-level constant is untouched.
    assert "INJECTED_PASSWORD" not in dc.SIEMENS_S7_DEFAULTS


def test_mutation_does_not_leak_across_aliased_protocols():
    """s7/snap7/siemens alias the same constant; mutating one alias's result
    must not leak into the others."""
    s7 = get_protocol_defaults("s7")
    s7.append("LEAKED")

    assert "LEAKED" not in get_protocol_defaults("snap7")
    assert "LEAKED" not in get_protocol_defaults("siemens")

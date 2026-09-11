"""
Regression tests for src/oida/fuzz/primitives/dynamic.py.

Covers two verified bugs in SmartBytes():

1. (HIGH) The radamsa branch dropped ``size``, ``padding`` and ``fuzzable`` —
   they are named parameters of SmartBytes itself so they never fell through
   into ``**kwargs`` on the radamsa path. A caller passing
   ``fuzzable=False, size=N`` (e.g. icmp.py freezing reserved/checksum
   fields) got a mutable, unsized field once radamsa was globally enabled.

2. (MEDIUM) ``mutation_count = radamsa_mutation_count or get_radamsa_mutation_count()``
   discarded an explicit ``radamsa_mutation_count=0`` because 0 is falsy.

Both bugs are reachable via icmp.py / icmpv6.py call sites such as:
    SmartBytes("Unused", b"\\x00\\x00", size=2, fuzzable=False)
"""

import pytest
from boofuzz import Bytes as BoofuzzBytes

from oida.fuzz.core.mutation.config import get_mutation_config
from oida.fuzz.primitives.dynamic import SmartBytes
from oida.fuzz.primitives.radamsa_primitives import RadamsaBytes


@pytest.fixture
def mutation_config():
    """Give each test a clean global mutation config, and always restore it.

    Uses a try/finally (via fixture teardown) so a failing assertion inside a
    test can never leak use_radamsa/mutation_count state into later tests in
    the same pytest run.
    """
    cfg = get_mutation_config()
    cfg.reset()
    try:
        yield cfg
    finally:
        cfg.reset()


def enable_radamsa(cfg, mutation_count=200):
    cfg.use_radamsa = True
    cfg.radamsa_mutation_count = mutation_count


def disable_radamsa(cfg):
    cfg.use_radamsa = False


# ---------------------------------------------------------------------------
# Bug 1: fuzzable=False must be honoured on both paths
# ---------------------------------------------------------------------------


class TestFuzzableHonoured:
    def test_fuzzable_false_radamsa_enabled(self, mutation_config):
        enable_radamsa(mutation_config)
        p = SmartBytes("field", b"AAAA", fuzzable=False)
        assert isinstance(p, RadamsaBytes)
        assert p.fuzzable is False

    def test_fuzzable_false_radamsa_disabled(self, mutation_config):
        disable_radamsa(mutation_config)
        p = SmartBytes("field", b"AAAA", fuzzable=False)
        assert isinstance(p, BoofuzzBytes)
        assert p.fuzzable is False

    def test_fuzzable_true_default_radamsa_enabled(self, mutation_config):
        enable_radamsa(mutation_config)
        p = SmartBytes("field", b"AAAA")
        assert isinstance(p, RadamsaBytes)
        assert p.fuzzable is True

    def test_fuzzable_true_default_radamsa_disabled(self, mutation_config):
        disable_radamsa(mutation_config)
        p = SmartBytes("field", b"AAAA")
        assert isinstance(p, BoofuzzBytes)
        assert p.fuzzable is True


# ---------------------------------------------------------------------------
# Bug 1: size / padding must be honoured (rendered length) on both paths
# ---------------------------------------------------------------------------


class TestSizePaddingHonoured:
    def test_size_padding_honoured_radamsa_disabled(self, mutation_config):
        disable_radamsa(mutation_config)
        p = SmartBytes("field", b"AA", size=4, padding=b"\xff")
        assert isinstance(p, BoofuzzBytes)
        assert p.size == 4
        assert p.padding == b"\xff"
        # boofuzz's own _adjust_mutation_for_size enforces the fixed size on
        # generated mutations (not on the unmutated default render) - prove
        # size/padding actually take effect end to end.
        padded = p._adjust_mutation_for_size(b"A")
        assert padded == b"A\xff\xff\xff"
        assert len(padded) == 4

    def test_size_padding_honoured_radamsa_enabled(self, mutation_config):
        # With size set, radamsa cannot honour the fixed-size/padding
        # contract (RadamsaBytes has no size/padding enforcement at all: it
        # only knows how to truncate to max_len, not pad to a fixed size),
        # so SmartBytes must fall back to the boofuzz-backed primitive
        # rather than silently dropping size/padding.
        enable_radamsa(mutation_config)
        p = SmartBytes("field", b"AA", size=4, padding=b"\xff")
        assert isinstance(p, BoofuzzBytes)
        assert p.size == 4
        assert p.padding == b"\xff"
        padded = p._adjust_mutation_for_size(b"A")
        assert padded == b"A\xff\xff\xff"
        assert len(padded) == 4


# ---------------------------------------------------------------------------
# Bug 2: radamsa_mutation_count=0 must really mean zero mutations
# ---------------------------------------------------------------------------


class TestExplicitZeroMutationCount:
    def test_explicit_zero_not_replaced_by_global_default(self, mutation_config):
        enable_radamsa(mutation_config, mutation_count=999)
        p = SmartBytes("field", b"AAAA", radamsa_mutation_count=0)
        assert isinstance(p, RadamsaBytes)
        assert p.mutation_count == 0
        assert p.num_mutations(b"AAAA") == 0
        assert list(p.mutations(b"AAAA")) == []

    def test_explicit_nonzero_still_honoured(self, mutation_config):
        enable_radamsa(mutation_config, mutation_count=999)
        p = SmartBytes("field", b"AAAA", radamsa_mutation_count=7)
        assert p.mutation_count == 7

    def test_no_override_uses_global_default(self, mutation_config):
        enable_radamsa(mutation_config, mutation_count=999)
        p = SmartBytes("field", b"AAAA")
        assert p.mutation_count == 999


# ---------------------------------------------------------------------------
# Exact icmp.py call-site regression case
# ---------------------------------------------------------------------------


class TestIcmpRegressionCase:
    """Mirrors SmartBytes("Unused", b"\\x00\\x00", size=2, fuzzable=False)
    used throughout icmp.py/icmpv6.py to freeze reserved/checksum fields.
    """

    def test_frozen_field_radamsa_enabled(self, mutation_config):
        enable_radamsa(mutation_config)
        p = SmartBytes("Unused", b"\x00\x00", size=2, fuzzable=False)
        assert p.fuzzable is False
        rendered = p.render()
        assert len(rendered) == 2
        assert rendered == b"\x00\x00"

    def test_frozen_field_radamsa_disabled(self, mutation_config):
        disable_radamsa(mutation_config)
        p = SmartBytes("Unused", b"\x00\x00", size=2, fuzzable=False)
        assert isinstance(p, BoofuzzBytes)
        assert p.fuzzable is False
        rendered = p.render()
        assert len(rendered) == 2
        assert rendered == b"\x00\x00"


# ---------------------------------------------------------------------------
# Regression guard: with radamsa DISABLED, behaviour is unchanged from today
# ---------------------------------------------------------------------------


class TestBoofuzzPathUnchanged:
    """Captured from the CURRENT (pre-fix) code: the boofuzz branch already
    forwarded size/padding/fuzzable/max_len correctly, so none of this
    should move when the radamsa branch is fixed.
    """

    def test_plain_bytes_radamsa_disabled(self, mutation_config):
        disable_radamsa(mutation_config)
        p = SmartBytes("field", b"AAAA", size=8, padding=b"\x00", fuzzable=True, max_len=16)
        assert isinstance(p, BoofuzzBytes)
        assert p.fuzzable is True
        assert p.size == 8
        assert p.padding == b"\x00"
        # boofuzz's Bytes.__init__ itself overrides max_len to size whenever
        # size is set - that's pre-existing boofuzz behaviour, not something
        # SmartBytes controls.
        assert p.max_len == 8
        assert p._default_value == b"AAAA"

    def test_max_len_honoured_without_size_radamsa_disabled(self, mutation_config):
        disable_radamsa(mutation_config)
        p = SmartBytes("field", b"AAAA", max_len=16)
        assert isinstance(p, BoofuzzBytes)
        assert p.size is None
        assert p.max_len == 16

    def test_min_len_kwarg_is_dropped_radamsa_disabled(self, mutation_config):
        disable_radamsa(mutation_config)
        # min_len isn't supported by boofuzz Bytes; SmartBytes silently
        # drops it rather than erroring. This is pre-existing behaviour,
        # not part of either bug under review.
        p = SmartBytes("field", b"AAAA", min_len=2)
        assert isinstance(p, BoofuzzBytes)


# ---------------------------------------------------------------------------
# Global-state hygiene: prove the fixture actually restores state
# ---------------------------------------------------------------------------


class TestFixtureRestoresGlobalState:
    def test_state_is_disabled_before_each_test(self, mutation_config):
        # Whatever earlier tests in this module did, the fixture must have
        # reset the global singleton before this test started.
        assert mutation_config.use_radamsa is False

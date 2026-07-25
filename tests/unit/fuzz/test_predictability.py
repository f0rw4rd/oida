"""Unit tests for the predictable-value oracle (analysis/predictability.py).

The analyzer implements the black-box playbook's highest-severity purely-
observational check: capture many ISNs / IP-IDs / DNS-TXIDs and decide whether
the sequence is guessable. These tests drive each pattern branch with a
hand-built sequence and assert the verdict, plus the negative case (real
randomness must read as RANDOM, not a false positive).
"""

import random

import pytest

from oida.fuzz.analysis import (
    DNSTxidResult,
    DNSTxidSampler,
    ISNSampleResult,
    PredictabilityPattern,
    SequenceVerdict,
    classify_sequence,
)

pytestmark = pytest.mark.core


def test_constant_sequence_is_critical():
    v = classify_sequence([0x1234] * 16, bits=16)
    assert v.pattern is PredictabilityPattern.CONSTANT
    assert v.predictable is True
    assert v.severity == "critical"
    assert v.estimated_bits == 0.0


def test_low_cardinality_small_recycled_set():
    # 16 samples cycling only 3 distinct values.
    seq = [0xAAAA, 0xBBBB, 0xCCCC] * 6
    v = classify_sequence(seq[:16], bits=16)
    assert v.pattern is PredictabilityPattern.LOW_CARDINALITY
    assert v.predictable is True
    assert v.distinct == 3


def test_fixed_delta_global_counter():
    # Classic global IP-ID ++ counter.
    start = 1000
    seq = [(start + i) for i in range(20)]
    v = classify_sequence(seq, bits=16)
    assert v.pattern is PredictabilityPattern.FIXED_DELTA
    assert v.predictable is True
    assert v.params["delta"] == 1
    assert v.severity == "high"


def test_fixed_delta_wraps_modulo_field_width():
    # A +7 counter that wraps past 2**16 must still read as one fixed delta.
    seq = [(60000 + 7 * i) % (1 << 16) for i in range(20)]
    v = classify_sequence(seq, bits=16)
    assert v.pattern is PredictabilityPattern.FIXED_DELTA
    assert v.params["delta"] == 7


def test_lcg_weak_prng_is_recovered():
    # A real LCG (glibc-style multiplier) over 32 bits.
    a, c, m = 1103515245, 12345, 1 << 32
    x = 0xDEADBEEF
    seq = []
    for _ in range(24):
        x = (a * x + c) % m
        seq.append(x)
    v = classify_sequence(seq, bits=32)
    assert v.pattern is PredictabilityPattern.LCG
    assert v.predictable is True
    assert v.params["a"] == a
    assert v.params["c"] == c


def test_bounded_increment_time_based_clock():
    # Monotonic with small, jittered but tightly-bounded steps (a coarse clock).
    rng = random.Random(1)
    x = 500000
    seq = []
    for _ in range(24):
        x = (x + rng.randint(1, 8)) % (1 << 32)
        seq.append(x)
    v = classify_sequence(seq, bits=32)
    assert v.pattern is PredictabilityPattern.BOUNDED_INCREMENT
    assert v.predictable is True
    assert v.params["min_step"] >= 1
    assert v.params["max_step"] <= 8


def test_static_high_bits_narrow_effective_field():
    # Only the low 12 bits move; the top 20 bits of a 32-bit field are pinned.
    rng = random.Random(2)
    base = 0xAB000000
    seq = [base | rng.randint(0, 0xFFF) for _ in range(40)]
    v = classify_sequence(seq, bits=32)
    assert v.pattern is PredictabilityPattern.STATIC_HIGH_BITS
    assert v.predictable is True
    assert v.params["static_high_bits"] >= 16
    assert v.estimated_bits <= 16


def test_random_sequence_is_not_flagged():
    # A strong PRNG over 32 bits must NOT trip any predictable branch.
    rng = random.Random(1337)
    seq = [rng.getrandbits(32) for _ in range(64)]
    v = classify_sequence(seq, bits=32)
    assert v.pattern is PredictabilityPattern.RANDOM
    assert v.predictable is False
    assert v.severity == "info"


def test_random_16bit_txids_not_flagged():
    # DNS TXIDs: 64 strong-random 16-bit values should read as random.
    rng = random.Random(99)
    seq = [rng.getrandbits(16) for _ in range(64)]
    v = classify_sequence(seq, bits=16)
    assert v.predictable is False


def test_insufficient_samples_returns_no_verdict():
    v = classify_sequence([1, 2, 3, 4], bits=16)
    assert v.pattern is PredictabilityPattern.INSUFFICIENT
    assert v.predictable is False


def test_values_are_masked_to_field_width():
    # Oversized inputs are masked, not rejected: 0x1_0000 & 0xFFFF == 0.
    v = classify_sequence([0x10000] * 16, bits=16)
    assert v.pattern is PredictabilityPattern.CONSTANT
    assert v.params["value"] == 0


def test_invalid_bits_raises():
    with pytest.raises(ValueError):
        classify_sequence([1, 2, 3], bits=0)


def test_verdict_is_dataclass_with_expected_fields():
    v = classify_sequence([5] * 10, bits=16)
    assert isinstance(v, SequenceVerdict)
    assert v.samples == 10
    assert 0.0 <= v.confidence <= 1.0


# --------------------------------------------------------------------------- #
# Samplers -- classification wiring (no sockets; observations injected).
# --------------------------------------------------------------------------- #


def test_isn_sample_result_analyze_flags_counter_and_constant():
    r = ISNSampleResult(isns=list(range(1000, 1040)), ip_ids=[7] * 40)
    isn_v, ipid_v = r.analyze()
    assert isn_v.pattern is PredictabilityPattern.FIXED_DELTA  # ++ ISN
    assert ipid_v.pattern is PredictabilityPattern.CONSTANT  # pinned IP-ID


def test_dns_txid_sampler_flags_predictable_txid_via_observations():
    # A forwarder that increments its TXID and reuses one source port:
    obs = [(1000 + i, 33333) for i in range(32)]
    report = DNSTxidSampler().run(observations=obs)
    assert report is not None
    assert report["txid"].pattern is PredictabilityPattern.FIXED_DELTA
    assert report["txid"].predictable is True
    assert report["source_port"].pattern is PredictabilityPattern.CONSTANT


def test_dns_txid_sampler_passes_strong_random():
    rng = random.Random(7)
    obs = [(rng.getrandbits(16), rng.getrandbits(16)) for _ in range(64)]
    report = DNSTxidSampler().run(observations=obs)
    assert report["txid"].predictable is False
    assert report["source_port"].predictable is False


def test_dns_txid_result_16bit_masking():
    r = DNSTxidResult(txids=[0x10001] * 16, source_ports=[0x20000] * 16)
    txid_v, port_v = r.analyze()
    assert txid_v.params["value"] == 1  # 0x10001 & 0xFFFF
    assert port_v.params["value"] == 0  # 0x20000 & 0xFFFF


def test_dns_txid_sampler_empty_observations_returns_none():
    assert DNSTxidSampler().run(observations=[]) is None

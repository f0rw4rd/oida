"""Predictable-value oracle for black-box fuzzing.

``classify_sequence`` takes a list of unsigned integers a target emitted where a
value is *supposed* to be unpredictable -- TCP initial sequence numbers, IPv4
IP-IDs, DNS transaction IDs -- and reports whether the sequence follows a
guessable pattern.

This is the highest-severity purely-observational finding in the black-box
playbook: a predictable ISN enables off-path TCP injection/spoofing, a global
IP-ID counter enables idle-scanning and fragmentation attacks, and a predictable
DNS TXID enables cache poisoning -- all without any memory-corruption bug.

The analyzer is deliberately protocol-agnostic: it works on the raw integer
sequence plus the field width in bits (``bits=32`` for ISN, ``bits=16`` for
IP-ID / DNS TXID). Detection order (strongest/most-specific first):

1. CONSTANT             - every sample identical.
2. LOW_CARDINALITY      - only a handful of distinct values across the run.
3. FIXED_DELTA          - a global ``++N`` counter (first differences all equal).
4. LCG                  - a weak linear-congruential PRNG (x' = a*x + c mod 2^bits).
5. BOUNDED_INCREMENT    - monotonic with small, tightly-bounded steps (a coarse
                          time-based clock; guessable within a small window).
6. STATIC_HIGH_BITS     - the high bits never change, shrinking the search space
                          well below the nominal field width.
7. RANDOM               - none of the above; no pattern found.

Everything is pure Python with no third-party dependency, so it is exhaustively
unit-testable offline. The live sampler that feeds it (``ISNSampler``) lives in
``sampler.py`` and needs raw sockets; the analysis does not.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Sequence

# Below this many samples we refuse to call a verdict -- too few points make any
# "pattern" statistically meaningless (three colinear points prove nothing).
MIN_SAMPLES = 8

# A run is "low cardinality" when distinct values are <= this many OR <= this
# fraction of the samples. Either trips it: a target cycling 4 ISNs is broken
# whether you took 8 or 800 samples.
LOW_CARDINALITY_ABS = 4
LOW_CARDINALITY_FRAC = 0.35

# For BOUNDED_INCREMENT: monotonic steps whose spread stays under 2**(bits*this)
# are "small" -- a coarse clock, guessable within a narrow window.
BOUNDED_STEP_BITS_FRACTION = 0.5


class PredictabilityPattern(str, Enum):
    """The pattern class a sampled sequence was matched to."""

    INSUFFICIENT = "insufficient"  # not enough samples to judge
    CONSTANT = "constant"
    LOW_CARDINALITY = "low_cardinality"
    FIXED_DELTA = "fixed_delta"
    LCG = "lcg"
    BOUNDED_INCREMENT = "bounded_increment"
    STATIC_HIGH_BITS = "static_high_bits"
    RANDOM = "random"


# Severity per pattern -- how bad it is for the value to follow this shape.
_SEVERITY = {
    PredictabilityPattern.INSUFFICIENT: "info",
    PredictabilityPattern.CONSTANT: "critical",
    PredictabilityPattern.LOW_CARDINALITY: "critical",
    PredictabilityPattern.FIXED_DELTA: "high",
    PredictabilityPattern.LCG: "high",
    PredictabilityPattern.BOUNDED_INCREMENT: "medium",
    PredictabilityPattern.STATIC_HIGH_BITS: "medium",
    PredictabilityPattern.RANDOM: "info",
}


@dataclass
class SequenceVerdict:
    """The result of analysing one sampled sequence.

    Attributes:
        pattern: The matched :class:`PredictabilityPattern`.
        predictable: True for any pattern an attacker can exploit (everything
            except RANDOM and INSUFFICIENT).
        confidence: 0.0-1.0 rough confidence in the verdict.
        severity: "critical" / "high" / "medium" / "info".
        samples: Number of input values considered.
        distinct: Number of distinct input values.
        estimated_bits: Estimated effective entropy of the field in bits (log2 of
            the realistically reachable value space). Compare against ``bits`` to
            see how much randomness was actually lost.
        detail: Human-readable one-liner describing the finding.
        params: Pattern-specific parameters (e.g. the LCG ``a``/``c``, the fixed
            delta, or the static high-bit count) for reporting/repro.
    """

    pattern: PredictabilityPattern
    predictable: bool
    confidence: float
    severity: str
    samples: int
    distinct: int
    estimated_bits: float
    detail: str
    params: dict = field(default_factory=dict)


def _mask(bits: int) -> int:
    return (1 << bits) - 1


def _diffs(values: Sequence[int], modulus: int) -> List[int]:
    """First differences taken modulo the field width (wrap-aware)."""
    return [(values[i + 1] - values[i]) % modulus for i in range(len(values) - 1)]


def _shannon_bits(values: Sequence[int]) -> float:
    """Shannon entropy (in bits) of the empirical value distribution.

    Caps at log2(n): with n samples you can never observe more than n bits of
    entropy, so this is a floor on the true field entropy, not an estimate of it.
    """
    n = len(values)
    if n <= 1:
        return 0.0
    counts: dict = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    entropy = 0.0
    for c in counts.values():
        p = c / n
        entropy -= p * math.log2(p)
    return entropy


def _egcd(a: int, b: int):
    if a == 0:
        return (b, 0, 1)
    g, x, y = _egcd(b % a, a)
    return (g, y - (b // a) * x, x)


def _mod_inverse(a: int, modulus: int) -> Optional[int]:
    a %= modulus
    g, x, _ = _egcd(a, modulus)
    if g != 1:
        return None
    return x % modulus


def _static_high_bits(values: Sequence[int], bits: int) -> int:
    """Count the contiguous high-order bit positions that never change.

    A stack that only randomises the low 16 bits of a 32-bit ISN has 16 static
    high bits -- the effective search space is 2**16, not 2**32.
    """
    if len(values) < 2:
        return 0
    differing = 0
    for v in values[1:]:
        differing |= v ^ values[0]
    static = 0
    for pos in range(bits - 1, -1, -1):
        if differing & (1 << pos):
            break
        static += 1
    return static


def _detect_lcg(values: Sequence[int], bits: int) -> Optional[dict]:
    """Recover an LCG (x' = a*x + c mod 2**bits) that reproduces the whole run.

    Solves ``a`` from two consecutive differences using a modular inverse, then
    verifies the recovered (a, c) predicts every remaining sample. Returns the
    parameters on success, else None. The ``a == 1`` case is a fixed-delta
    counter and is handled by its own (stronger, simpler) detector first.
    """
    modulus = 1 << bits
    n = len(values)
    if n < 4:
        return None

    diffs = _diffs(values, modulus)
    # Need a step whose delta is invertible mod 2**bits (i.e. odd) to solve for a.
    for i in range(len(diffs) - 1):
        d0, d1 = diffs[i], diffs[i + 1]
        inv = _mod_inverse(d0, modulus)
        if inv is None:
            continue
        a = (d1 * inv) % modulus
        if a == 1:
            # Pure counter -- let the FIXED_DELTA detector own this.
            continue
        c = (values[i + 2] - a * values[i + 1]) % modulus
        # Verify (a, c) reproduces the entire sequence.
        ok = all((a * values[j] + c) % modulus == values[j + 1] for j in range(n - 1))
        if ok:
            return {"a": a, "c": c, "modulus": modulus}
    return None


def classify_sequence(values: Sequence[int], bits: int) -> SequenceVerdict:
    """Classify a sampled integer sequence for predictability.

    Args:
        values: The observed unsigned integers, in the order sampled.
        bits: Field width in bits (32 for TCP ISN, 16 for IP-ID / DNS TXID).

    Returns:
        A :class:`SequenceVerdict`. ``verdict.predictable`` is True for any
        exploitable pattern (CONSTANT, LOW_CARDINALITY, FIXED_DELTA, LCG,
        BOUNDED_INCREMENT, STATIC_HIGH_BITS).
    """
    if bits <= 0:
        raise ValueError("bits must be positive")

    modulus = 1 << bits
    values = [int(v) & _mask(bits) for v in values]
    n = len(values)
    distinct = len(set(values))

    def _verdict(pattern, predictable, confidence, est_bits, detail, params=None):
        return SequenceVerdict(
            pattern=pattern,
            predictable=predictable,
            confidence=confidence,
            severity=_SEVERITY[pattern],
            samples=n,
            distinct=distinct,
            estimated_bits=round(est_bits, 2),
            detail=detail,
            params=params or {},
        )

    if n < MIN_SAMPLES:
        return _verdict(
            PredictabilityPattern.INSUFFICIENT,
            False,
            0.0,
            _shannon_bits(values),
            f"only {n} samples (need >= {MIN_SAMPLES}) -- no verdict",
        )

    # 1. CONSTANT -- every value identical.
    if distinct == 1:
        return _verdict(
            PredictabilityPattern.CONSTANT,
            True,
            1.0,
            0.0,
            f"constant value 0x{values[0]:x} across all {n} samples",
            {"value": values[0]},
        )

    # 2. LOW_CARDINALITY -- a tiny recycled value set.
    if distinct <= LOW_CARDINALITY_ABS or distinct <= LOW_CARDINALITY_FRAC * n:
        return _verdict(
            PredictabilityPattern.LOW_CARDINALITY,
            True,
            0.9,
            math.log2(distinct),
            f"only {distinct} distinct values across {n} samples",
            {"distinct_values": sorted(set(values))},
        )

    diffs = _diffs(values, modulus)

    # 3. FIXED_DELTA -- a global ++N counter (IP-ID / naive ISN).
    if len(set(diffs)) == 1:
        delta = diffs[0]
        return _verdict(
            PredictabilityPattern.FIXED_DELTA,
            True,
            1.0,
            0.0,
            f"global counter: every step is +{delta} (mod 2^{bits})",
            {"delta": delta},
        )

    # 4. LCG -- a weak linear-congruential generator.
    lcg = _detect_lcg(values, bits)
    if lcg is not None:
        return _verdict(
            PredictabilityPattern.LCG,
            True,
            0.95,
            0.0,
            f"linear-congruential sequence: x' = {lcg['a']}*x + {lcg['c']} mod 2^{bits}",
            lcg,
        )

    # 5. BOUNDED_INCREMENT -- monotonic (wrap-aware) with tightly-bounded steps,
    #    the signature of a coarse time-based clock: guessable within a window.
    step_ceiling = 1 << int(bits * BOUNDED_STEP_BITS_FRACTION)
    if all(0 < d < step_ceiling for d in diffs):
        spread = max(diffs) - min(diffs)
        # Window an attacker must cover ~ number of candidate next-values.
        window_bits = math.log2(max(diffs)) if max(diffs) > 1 else 1.0
        return _verdict(
            PredictabilityPattern.BOUNDED_INCREMENT,
            True,
            0.7,
            window_bits,
            f"monotonic with bounded steps (min +{min(diffs)}, max +{max(diffs)}, "
            f"spread {spread}) -- time-based clock, guessable within a small window",
            {"min_step": min(diffs), "max_step": max(diffs)},
        )

    # 6. STATIC_HIGH_BITS -- the top bits never move; the field is effectively
    #    much narrower than its nominal width even if the low bits look random.
    static = _static_high_bits(values, bits)
    effective = bits - static
    if static > 0 and effective <= bits * 0.5:
        return _verdict(
            PredictabilityPattern.STATIC_HIGH_BITS,
            True,
            0.75,
            float(effective),
            f"top {static} of {bits} bits never change -- effective entropy <= {effective} bits",
            {"static_high_bits": static, "effective_bits": effective},
        )

    # 7. RANDOM -- no exploitable structure found.
    est = _shannon_bits(values)
    return _verdict(
        PredictabilityPattern.RANDOM,
        False,
        min(1.0, est / math.log2(n)),
        est,
        f"no pattern found across {n} samples ({distinct} distinct); "
        f"observed entropy >= {est:.1f} bits",
    )

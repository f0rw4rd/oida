"""Observational analysis for black-box fuzzing.

These helpers implement the *predictable-value* oracle from the black-box
protocol-fuzzing playbook: capture many outbound values a stack is supposed to
randomize (TCP ISNs, IP-IDs, DNS transaction IDs) and check the *sequence* for
a pattern. No crash is required -- a predictable ISN/IP-ID/TXID is a spoofing /
off-path-injection primitive and is the highest-severity purely-observational
finding class.
"""

from oida.fuzz.analysis.predictability import (
    PredictabilityPattern,
    SequenceVerdict,
    classify_sequence,
)
from oida.fuzz.analysis.sampler import DNSTxidResult, DNSTxidSampler, ISNSampleResult, ISNSampler

__all__ = [
    "PredictabilityPattern",
    "SequenceVerdict",
    "classify_sequence",
    "ISNSampler",
    "ISNSampleResult",
    "DNSTxidSampler",
    "DNSTxidResult",
]

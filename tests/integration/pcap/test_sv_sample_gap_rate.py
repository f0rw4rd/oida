"""Regression: SV sample-gap detection must not assume a 4000 wrap boundary.

smpRate is frequently absent from the SV ASDU (it lives in the config), so
the listener has no observed rate. The old code fell back to a hardcoded
max_cnt of 4000, which meant a 4800-sample (60 Hz) stream was flagged as a
gap every time smpCnt advanced past 4000 -- even for a perfectly contiguous
sequence. With the rate unknown, a monotonic +1 sequence must never be
counted as a gap, and a genuine forward skip still must.
"""

import pytest

from oida.pcap.sv import SVPassiveListener

pytestmark = [pytest.mark.integration]


def _mk():
    return SVPassiveListener(interface="lo", timeout=1)


def _update(listener, smp_cnt, smp_rate=0):
    return listener._update_stream(
        stream_key="k",
        src_mac="01:0c:cd:04:00:01",
        sv_id="MU01",
        appid=0x4000,
        dat_set="ds",
        smp_cnt=smp_cnt,
        conf_rev=1,
        smp_synch=2,
        smp_rate=smp_rate,
        simulated=False,
        quality_issues=[],
    )


def test_contiguous_60hz_no_rate_field_has_no_gaps():
    listener = _mk()
    # Contiguous counts crossing the old hardcoded 4000 boundary, no smpRate.
    for cnt in (3998, 3999, 4000, 4001, 4002):
        stream = _update(listener, cnt)
    assert stream.sample_gaps == 0, (
        "false gap: rate unknown, sequence is contiguous but crossed 4000"
    )


def test_wraparound_without_rate_is_not_a_gap():
    listener = _mk()
    _update(listener, 4798)
    _update(listener, 4799)
    stream = _update(listener, 0)  # wrap reset
    assert stream.sample_gaps == 0


def test_real_forward_skip_still_counts():
    listener = _mk()
    _update(listener, 10)
    stream = _update(listener, 15)  # skipped 11..14
    assert stream.sample_gaps == 1


def test_known_rate_path_unchanged():
    listener = _mk()
    # With smpRate=4000 present, 3999 -> 0 is a clean wrap, not a gap.
    _update(listener, 3999, smp_rate=4000)
    stream = _update(listener, 0, smp_rate=4000)
    assert stream.sample_gaps == 0

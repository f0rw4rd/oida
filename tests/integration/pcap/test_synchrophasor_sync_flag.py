"""Regression tests for the synchrophasor STAT sync-flag polarity.

STAT bit 13 (``synphasor.data.sync``) is set when synchronization is LOST:
the dissector's TFS reads "Synchronization lost" / "Clock is synchronized".
The listener used to flag UNSYNC on a *False* value, so every healthy frame
in a synchronized stream was reported as unsynchronized and genuinely
unsynchronized frames were never flagged at all.
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]

PCAP = "synchrophasor/C37.118_1PMU_TCP.pcap"


class TestSyncFlagPolarity:
    """UNSYNC must track 'synchronization lost', not its inverse."""

    def test_synchronized_stream_reports_no_unsync(self):
        """Every DATA frame in this capture has data.sync=False (clock OK)."""
        listener, _devices, _result = _run_listener_test(
            "synchrophasor",
            "SynchrophasorPassiveListener",
            "synphasor",
            PCAP,
            min_devices=0,
            min_interactions=0,
        )

        unsync_total = sum(pmu.unsync_count for pmu in listener.pmu_info.values())
        assert unsync_total == 0, (
            f"Fully synchronized capture reported {unsync_total} UNSYNC frames; "
            "the STAT bit-13 polarity is inverted."
        )

        flagged = [
            ix for ix in listener.interactions if "UNSYNC" in (ix.details.get("stat_flags") or [])
        ]
        assert not flagged, f"{len(flagged)} interactions carry a spurious UNSYNC flag"

    @pytest.mark.parametrize(
        "sync_value,expect_unsync",
        [("True", True), ("False", False), ("1", True), ("0", False)],
    )
    def test_data_frame_flags_only_when_sync_lost(self, sync_value, expect_unsync):
        """Drive the real _process_data_frame: UNSYNC iff data.sync is truthy."""
        from oida.pcap.synchrophasor import SynchrophasorPassiveListener

        listener = SynchrophasorPassiveListener(interface="lo", timeout=1)
        syn = _FakeSynLayer({"data_sync": sync_value})

        listener._process_data_frame(
            packet=_FakePacket(),
            syn=syn,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            flow_id="10.0.0.1:4712-10.0.0.2:5000",
            idcode=7,
            version=1,
            frsize=52,
            src_mac="00:11:22:33:44:55",
            dst_mac="66:77:88:99:aa:bb",
        )

        pmu = listener.pmu_info[7]
        assert pmu.data_frames_seen == 1
        assert pmu.unsync_count == (1 if expect_unsync else 0)

        flags = listener.interactions[-1].details.get("stat_flags") or []
        assert ("UNSYNC" in flags) is expect_unsync


class _FakeSynLayer:
    """Minimal stand-in for a pyshark synphasor layer."""

    def __init__(self, fields: dict):
        self._fields = fields

    def get_field(self, name):
        return self._fields.get(name)

    def __getattr__(self, name):
        try:
            return self._fields[name]
        except KeyError as exc:  # pragma: no cover - mirrors pyshark's behaviour
            raise AttributeError(name) from exc


class _FakePacket:
    """Minimal stand-in for a pyshark packet (timestamp only)."""

    sniff_timestamp = "1700000000.0"

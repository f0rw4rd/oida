"""Regression test: NMEA 0183 GPS-spoofing position-jump detection.

``NMEASource.last_lat`` /
``last_lon`` were declared but NEVER assigned anywhere in the file, so
``_check_position_jump()`` always returned at its ``last_lat is None`` guard.
``position_jumps`` could never increment and the headline "GPS SPOOFING
INDICATOR" alert in ``harvest()`` could never fire -- the listener's primary
security feature was inert. Additionally, ``_track_source`` (which creates the
source record) ran AFTER the sentence parsers, so even the first fix had no
source to attach to.

The fix (a) moves ``_track_source`` ahead of sentence parsing so the source
record exists, and (b) persists ``last_lat`` / ``last_lon`` at the end of
``_check_position_jump`` so consecutive fixes have a baseline to diff against.

These tests drive ``process_packet`` with lightweight fake packets (no pyshark
/ tshark needed), mirroring ``test_profinet_io_direction.py``.
"""

from oida.pcap.nmea0183 import MAX_POSITION_JUMP_NM, NMEA0183PassiveListener


class _Layer:
    """Minimal stand-in for a pyshark layer: attribute access only."""

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class _FakePacket:
    def __init__(self, src_ip, dst_ip, nmea_fields):
        self.eth = _Layer(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:02")
        self.ip = _Layer(src=src_ip, dst=dst_ip)
        self.nmea0183 = _Layer(**nmea_fields)

    def __contains__(self, item):  # pyshark layer membership ("ip" in packet)
        return hasattr(self, str(item).lower())


SRC_IP = "10.0.0.7"
DST_IP = "10.0.0.1"


def _gga(lat_deg, lat_min, lat_dir, lon_deg, lon_min, lon_dir):
    """Build a minimal GGA nmea0183 layer field dict."""
    return {
        "talker": "GP",
        "sentence": "GGA",
        "gga_latitude_degree": str(lat_deg),
        "gga_latitude_minute": str(lat_min),
        "gga_latitude_direction": lat_dir,
        "gga_longitude_degree": str(lon_deg),
        "gga_longitude_minute": str(lon_min),
        "gga_longitude_direction": lon_dir,
        "gga_quality": "1",
    }


def _make_listener():
    return NMEA0183PassiveListener(interface="lo", timeout=1)


def test_two_close_gga_fixes_no_position_jump():
    """Two GGA fixes a few hundred metres apart (< 5 NM) must NOT flag a jump,
    but the first fix MUST be persisted as the baseline (regression: it never
    was)."""
    listener = _make_listener()

    # ~52.0000 N, 4.0000 E
    listener.process_packet(_FakePacket(SRC_IP, DST_IP, _gga(52, 0.0, "N", 4, 0.0, "E")))
    source = listener.sources[SRC_IP]
    assert source.last_lat is not None, "first fix was never persisted as baseline"
    assert source.last_lon is not None

    # ~52.0050 N, 4.0050 E -- well under 5 NM away.
    listener.process_packet(_FakePacket(SRC_IP, DST_IP, _gga(52, 0.3, "N", 4, 0.3, "E")))
    assert listener.sources[SRC_IP].position_jumps == 0


def test_two_far_gga_fixes_flag_position_jump():
    """Two GGA fixes > 5 NM apart must increment position_jumps exactly once and
    surface the GPS-spoofing alert in harvest() (regression: stayed 0 forever)."""
    listener = _make_listener()

    # ~52.0 N, 4.0 E
    listener.process_packet(_FakePacket(SRC_IP, DST_IP, _gga(52, 0.0, "N", 4, 0.0, "E")))
    # ~53.0 N, 4.0 E -- ~60 NM north, far above the 5 NM threshold.
    listener.process_packet(_FakePacket(SRC_IP, DST_IP, _gga(53, 0.0, "N", 4, 0.0, "E")))

    assert listener.sources[SRC_IP].position_jumps == 1

    alerts = listener.harvest().get("alerts", [])
    spoof = [a for a in alerts if a.get("category") == "gps_spoofing"]
    assert len(spoof) == 1, f"expected one gps_spoofing alert, got: {alerts}"
    assert str(MAX_POSITION_JUMP_NM) in spoof[0]["message"]

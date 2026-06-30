"""Behavioral parse tests for the R-GOOSE passive listener.

R-GOOSE (Routable GOOSE over UDP, IEC 61850-8-2) wraps a standard GOOSE PDU in
a session header carried over UDP. ``RGOOSEPassiveListener`` reads both the
``rgoose.*`` session fields and the shared ``goose.*`` PDU fields off a single
pyshark ``goose`` layer.

These tests drive ``process_packet()`` / ``_update_publisher()`` / ``harvest()``
with lightweight fake pyshark layers -- no pyshark, tshark, or .pcap needed.
Each test asserts the parsed publisher state, recorded interaction details, the
human-readable summary, the device-data dict, and the security alerts emitted by
``harvest()`` against the exact field values fed in.
"""

from oida.pcap.rgoose import RGOOSEPassiveListener


class _Layer:
    """Minimal stand-in for a pyshark layer: attribute access only.

    Only fields explicitly passed exist; everything else falls through to
    getattr's default, like a dissector that did not emit them. A field set to
    a Python ``list`` models pyshark EK-mode multi-value fields.
    """

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class _FakePacket:
    """A fake R-GOOSE packet: eth + ip + udp + a shared goose layer."""

    def __init__(self, src_ip, dst_ip, goose_fields, *, src_port=102, dst_port=102):
        self.eth = _Layer(src="aa:bb:cc:00:00:01", dst="01:0c:cd:01:00:01")
        self.ip = _Layer(src=src_ip, dst=dst_ip)
        self.udp = _Layer(srcport=str(src_port), dstport=str(dst_port), stream="3")
        self.goose = _Layer(**goose_fields)


PUB_IP = "10.20.0.5"
SUB_IP = "10.20.0.255"  # multicast-style dst; src is what is tracked
GOCB = "IED1/LLN0$GO$GoCB01"
DATASET = "IED1/LLN0$DataSet01"


def _make_listener():
    return RGOOSEPassiveListener(interface="lo", timeout=1)


# ---------------------------------------------------------------------------
# process_packet: gating + core publisher tracking
# ---------------------------------------------------------------------------


def test_packet_without_goose_layer_is_ignored():
    listener = _make_listener()

    class _NoGoose:
        pass

    listener.process_packet(_NoGoose())
    assert listener.interactions == []
    assert listener.publishers == {}


def test_l2_goose_without_ip_is_dropped():
    """A plain L2 GOOSE packet (goose layer but no IP) must be rejected so the
    R-GOOSE listener does not double-count it during a combined-pcap run."""
    listener = _make_listener()

    class _L2Packet:
        goose = _Layer(gocbRef=GOCB, stNum="1", sqNum="0")
        # no .ip / .ipv6 attribute -> get_ip_info returns ("", "")

    listener.process_packet(_L2Packet())
    assert listener.interactions == []
    assert listener.publishers == {}


def test_first_frame_creates_publisher_and_interaction():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            PUB_IP,
            SUB_IP,
            {
                "gocbRef": GOCB,
                "datSet": DATASET,
                "goID": "GID1",
                "stNum": "5",
                "sqNum": "0",
                "confRev": "1",
                "appid": "0x0001",
                "spdu_num": "100",
                "timeAllowedtoLive": "2000",
                "numDatSetEntries": "3",
            },
        )
    )

    assert GOCB in listener.publishers
    pub = listener.publishers[GOCB]
    assert pub.src_ip == PUB_IP
    assert pub.gocb_ref == GOCB
    assert pub.appid == 1
    assert pub.total_frames == 1
    assert pub.max_st_num == 5
    assert pub.last_st_num == 5
    assert DATASET in pub.datasets
    assert 1 in pub.conf_revs

    ix = listener.interactions[-1]
    assert ix.direction == "request"  # R-GOOSE is publish-only
    assert ix.src_ip == PUB_IP and ix.dst_ip == SUB_IP
    assert ix.details["gocb_ref"] == GOCB
    assert ix.details["st_num"] == 5
    assert ix.details["sq_num"] == 0
    assert ix.details["spdu_num"] == 100
    assert ix.details["ttl_ms"] == 2000
    assert ix.details["num_entries"] == 3
    assert ix.details["appid"] == 1


def test_state_change_detected_after_first_frame():
    """SqNum==0 on a frame after the first marks a state change; StNum increase
    bumps the state_changes counter."""
    listener = _make_listener()
    base = {"gocbRef": GOCB, "appid": "0x0001"}

    # Frame 1: heartbeat baseline (StNum=1, SqNum=3)
    listener.process_packet(_FakePacket(PUB_IP, SUB_IP, {**base, "stNum": "1", "sqNum": "3"}))
    # Frame 2: state change (StNum=2, SqNum=0)
    listener.process_packet(_FakePacket(PUB_IP, SUB_IP, {**base, "stNum": "2", "sqNum": "0"}))

    pub = listener.publishers[GOCB]
    assert pub.total_frames == 2
    assert pub.max_st_num == 2
    assert pub.state_changes == 1

    last = listener.interactions[-1]
    assert last.operation == "state_change"
    assert "STATE_CHANGE StNum=2" in last.summary
    # short_ref derived from the GoCBRef tail
    assert "GoCB01" in last.summary


def test_st_num_rollback_flagged_as_replay():
    """StNum decreasing across frames signals a possible replay / IED restart."""
    listener = _make_listener()
    base = {"gocbRef": GOCB}
    listener.process_packet(_FakePacket(PUB_IP, SUB_IP, {**base, "stNum": "10", "sqNum": "1"}))
    listener.process_packet(_FakePacket(PUB_IP, SUB_IP, {**base, "stNum": "4", "sqNum": "1"}))

    pub = listener.publishers[GOCB]
    assert pub.st_num_rollbacks == 1
    assert pub.last_st_num == 4
    # max_st_num is not lowered by a rollback
    assert pub.max_st_num == 10


def test_fallback_publisher_key_when_no_gocbref():
    """Without a GoCBRef the publisher is keyed by src_ip:appid."""
    listener = _make_listener()
    listener.process_packet(_FakePacket(PUB_IP, SUB_IP, {"appid": "0x00ab", "stNum": "1"}))

    expected_key = f"{PUB_IP}:0x00ab"
    assert expected_key in listener.publishers
    assert listener.publishers[expected_key].gocb_ref == ""


# ---------------------------------------------------------------------------
# HMAC / authentication tracking
# ---------------------------------------------------------------------------


def test_hmac_present_marks_authenticated_frame():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            PUB_IP,
            SUB_IP,
            {"gocbRef": GOCB, "stNum": "1", "hmac": "0a:1b:2c:3d", "key_id": "7"},
        )
    )
    pub = listener.publishers[GOCB]
    assert pub.hmac_present == 1
    assert pub.hmac_absent == 0
    assert 7 in pub.key_ids

    ix = listener.interactions[-1]
    assert ix.details["has_hmac"] is True
    assert ix.details["key_id"] == 7
    assert "[HMAC]" in ix.summary


def test_hmac_absent_marks_unauthenticated_frame():
    listener = _make_listener()
    listener.process_packet(_FakePacket(PUB_IP, SUB_IP, {"gocbRef": GOCB, "stNum": "1"}))
    pub = listener.publishers[GOCB]
    assert pub.hmac_absent == 1
    assert pub.hmac_present == 0
    assert listener.interactions[-1].details["has_hmac"] is False


def test_empty_hmac_string_is_treated_as_absent():
    """A present-but-empty hmac field (``""`` / ``"None"``) must NOT count as
    authenticated."""
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(PUB_IP, SUB_IP, {"gocbRef": GOCB, "stNum": "1", "hmac": ""})
    )
    assert listener.publishers[GOCB].hmac_absent == 1
    assert listener.publishers[GOCB].hmac_present == 0


# ---------------------------------------------------------------------------
# Data value extraction (mirrors L2 GOOSE)
# ---------------------------------------------------------------------------


def test_extract_boolean_and_integer_values():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            PUB_IP,
            SUB_IP,
            {"gocbRef": GOCB, "stNum": "1", "boolean": "True", "integer": "42"},
        )
    )
    ix = listener.interactions[-1]
    assert "values" in ix.details
    vals = ix.details["values"]
    # boolean formatted to T, integer kept as-is
    assert "T" in vals
    assert "42" in vals
    assert "[T,42]" in ix.summary or "T,42" in ix.summary


def test_extract_multivalue_boolean_list_ek_mode():
    """EK mode delivers repeated GOOSE booleans as a Python list; each element
    must be collected and formatted."""
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            PUB_IP,
            SUB_IP,
            {"gocbRef": GOCB, "stNum": "1", "boolean": ["True", "False", "1"]},
        )
    )
    vals = listener.interactions[-1].details["values"]
    assert vals == ["T", "F", "T"]


def test_extract_float_value_formatted():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            PUB_IP,
            SUB_IP,
            {"gocbRef": GOCB, "stNum": "1", "float_value": "12.5"},
        )
    )
    vals = listener.interactions[-1].details["values"]
    assert "12.5" in vals


def test_format_bool_val_passthrough_for_unknown():
    assert RGOOSEPassiveListener._format_bool_val("maybe") == "maybe"
    assert RGOOSEPassiveListener._format_bool_val("0") == "F"
    assert RGOOSEPassiveListener._format_bool_val("1") == "T"


# ---------------------------------------------------------------------------
# Optional session header detail fields
# ---------------------------------------------------------------------------


def test_session_header_optional_fields_recorded():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            PUB_IP,
            SUB_IP,
            {
                "gocbRef": GOCB,
                "stNum": "1",
                "curr_key_t": "1000",
                "next_key_t": "2000",
                "init_v_len": "16",
                "payload_len": "128",
                "spdu_len": "200",
                "version": "1",
            },
        )
    )
    d = listener.interactions[-1].details
    assert d["curr_key_t"] == 1000
    assert d["next_key_t"] == 2000
    assert d["init_v_len"] == 16
    assert d["payload_len"] == 128
    assert d["spdu_len"] == 200
    assert d["rgoose_version"] == 1


# ---------------------------------------------------------------------------
# Test/simulation + commissioning flags
# ---------------------------------------------------------------------------


def test_simulation_flag_tracked_and_summarized():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(PUB_IP, SUB_IP, {"gocbRef": GOCB, "stNum": "1", "simulation": "True"})
    )
    pub = listener.publishers[GOCB]
    assert pub.test_frames == 1
    ix = listener.interactions[-1]
    assert ix.details["test"] is True
    assert "[TEST]" in ix.summary


def test_nds_com_flag_tracked():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(PUB_IP, SUB_IP, {"gocbRef": GOCB, "stNum": "1", "ndsCom": "True"})
    )
    assert listener.publishers[GOCB].nds_com_seen is True


# ---------------------------------------------------------------------------
# Device entry construction
# ---------------------------------------------------------------------------


def test_device_entry_built_with_publisher_data():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            PUB_IP,
            SUB_IP,
            {
                "gocbRef": GOCB,
                "datSet": DATASET,
                "goID": "GID1",
                "stNum": "1",
                "confRev": "1",
                "appid": "0x0001",
                "hmac": "ab:cd",
                "key_id": "5",
            },
        )
    )
    key = f"rgoose-ied:{PUB_IP}"
    assert key in listener.discovered_devices
    device = listener.discovered_devices[key]
    data = device.rgoose_passive_data
    assert data["role"] == "publisher"
    assert data["protocol"] == "R-GOOSE/UDP"
    assert GOCB in data["gocb_refs"]
    assert DATASET in data["datasets"]
    assert data["total_frames"] == 1
    assert data["hmac_authenticated"] is True
    assert 5 in data["key_ids"]


def test_invalid_src_ip_does_not_create_device():
    """A loopback / zero source IP is rejected by is_valid_discovered_ip, but
    the interaction and publisher are still recorded."""
    listener = _make_listener()
    listener.process_packet(_FakePacket("127.0.0.1", SUB_IP, {"gocbRef": GOCB, "stNum": "1"}))
    assert listener.interactions  # interaction recorded
    assert "rgoose-ied:127.0.0.1" not in listener.discovered_devices


# ---------------------------------------------------------------------------
# Column formatting
# ---------------------------------------------------------------------------


def test_format_protocol_columns():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            PUB_IP,
            SUB_IP,
            {
                "gocbRef": GOCB,
                "datSet": DATASET,
                "stNum": "7",
                "sqNum": "2",
                "simulation": "True",
                "hmac": "aa:bb",
                "spdu_num": "55",
            },
        )
    )
    cols = listener._format_protocol_columns(listener.interactions[-1])
    assert cols == [GOCB, DATASET, 7, 2, "YES", "HMAC", 55]


def test_format_protocol_columns_no_test_no_hmac():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(PUB_IP, SUB_IP, {"gocbRef": GOCB, "stNum": "1", "sqNum": "1"})
    )
    cols = listener._format_protocol_columns(listener.interactions[-1])
    assert cols[4] == ""  # test
    assert cols[5] == "none"  # hmac


# ---------------------------------------------------------------------------
# harvest(): security alerts
# ---------------------------------------------------------------------------


def _categories(result):
    return {a["category"] for a in result.get("alerts", [])}


def test_harvest_empty_when_nothing_seen():
    assert _make_listener().harvest() == {}


def test_harvest_no_auth_alert():
    listener = _make_listener()
    for _ in range(3):
        listener.process_packet(_FakePacket(PUB_IP, SUB_IP, {"gocbRef": GOCB, "stNum": "1"}))
    result = listener.harvest()
    cats = _categories(result)
    assert "rgoose_no_auth" in cats
    msg = next(a["message"] for a in result["alerts"] if a["category"] == "rgoose_no_auth")
    assert "3 frames without HMAC" in msg
    assert PUB_IP in msg


def test_harvest_test_mode_alert():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(PUB_IP, SUB_IP, {"gocbRef": GOCB, "stNum": "1", "simulation": "True"})
    )
    cats = _categories(listener.harvest())
    assert "rgoose_test_mode" in cats


def test_harvest_replay_alert():
    listener = _make_listener()
    listener.process_packet(_FakePacket(PUB_IP, SUB_IP, {"gocbRef": GOCB, "stNum": "9"}))
    listener.process_packet(_FakePacket(PUB_IP, SUB_IP, {"gocbRef": GOCB, "stNum": "2"}))
    cats = _categories(listener.harvest())
    assert "rgoose_replay" in cats


def test_harvest_mixed_auth_alert():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(PUB_IP, SUB_IP, {"gocbRef": GOCB, "stNum": "1", "hmac": "aa:bb"})
    )
    listener.process_packet(_FakePacket(PUB_IP, SUB_IP, {"gocbRef": GOCB, "stNum": "1"}))
    cats = _categories(listener.harvest())
    assert "rgoose_mixed_auth" in cats
    # mixed auth means the no-auth alert (which requires hmac_present==0) is absent
    assert "rgoose_no_auth" not in cats


def test_harvest_commissioning_alert():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(PUB_IP, SUB_IP, {"gocbRef": GOCB, "stNum": "1", "ndsCom": "True", "hmac": "aa"})
    )
    cats = _categories(listener.harvest())
    assert "rgoose_commissioning" in cats


def test_harvest_confrev_mismatch_alert():
    """Two frames for the same GoCBRef with different confRev values must raise
    a config-mismatch alert."""
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(PUB_IP, SUB_IP, {"gocbRef": GOCB, "stNum": "1", "confRev": "1", "hmac": "aa"})
    )
    listener.process_packet(
        _FakePacket(PUB_IP, SUB_IP, {"gocbRef": GOCB, "stNum": "1", "confRev": "2", "hmac": "aa"})
    )
    result = listener.harvest()
    cats = _categories(result)
    assert "rgoose_confrev_mismatch" in cats
    msg = next(a["message"] for a in result["alerts"] if a["category"] == "rgoose_confrev_mismatch")
    assert "[1, 2]" in msg

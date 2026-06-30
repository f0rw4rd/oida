"""Behavioral unit tests for the FOUNDATION Fieldbus HSE passive listener
(``oida.pcap.ff_hse``).

Drives ``FFHSEPassiveListener.process_packet`` with lightweight fake
pyshark-style layer objects (no pyshark / tshark needed). Each test crafts a
packet whose ``ff`` layer carries the underscore field names the listener reads
via ``get_field`` (e.g. ``hdr_srv_fda_service_id_confirm``,
``sm_id_rsp_dev_id``), then asserts on the parsed service identification,
session tracking, device discovery and reporting accessors.

The listener determines request/response direction from the ``confirm_flag``
boolean (a confirmed/response message), and identifies the protocol+service by
probing FDA/SM/FMS/LAN confirmed and unconfirmed service-id fields in order.
"""

from oida.pcap.ff_hse import (
    FF_WRITE_SERVICES,
    FFHSEPassiveListener,
)


# ---------------------------------------------------------------------------
# Fake pyshark layer / packet plumbing
# ---------------------------------------------------------------------------


class _Layer:
    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class _FakePacket:
    def __init__(
        self,
        src_ip,
        dst_ip,
        ff_fields,
        *,
        src_mac="aa:bb:cc:00:00:01",
        dst_mac="aa:bb:cc:00:00:02",
        src_port=49152,
        dst_port=1089,
    ):
        self.eth = _Layer(src=src_mac, dst=dst_mac)
        self.ip = _Layer(src=src_ip, dst=dst_ip)
        self.udp = _Layer(srcport=src_port, dstport=dst_port, stream="3")
        self.ff = _Layer(**ff_fields)


CLIENT_IP = "10.1.0.10"
SERVER_IP = "10.1.0.20"
CLIENT_MAC = "aa:bb:cc:00:00:01"
SERVER_MAC = "aa:bb:cc:00:00:02"


def _make_listener():
    return FFHSEPassiveListener(interface="lo", timeout=1)


def _feed(ff_fields, **pkt_kwargs):
    listener = _make_listener()
    listener.process_packet(_FakePacket(CLIENT_IP, SERVER_IP, ff_fields, **pkt_kwargs))
    ix = listener.interactions[-1] if listener.interactions else None
    return listener, ix


# ---------------------------------------------------------------------------
# Service identification: FDA / SM / FMS / LAN, confirmed + unconfirmed
# ---------------------------------------------------------------------------


def test_fda_confirmed_open_request():
    listener, ix = _feed(
        {
            "hdr_srv_fda_service_id_confirm": "1",  # FDA_Open
            "fda_open_sess_req_pd_tag": "TT-101",
            "fda_open_sess_req_sess_idx": "5",
        }
    )
    assert ix.details["protocol"] == "FDA"
    assert ix.details["service"] == "FDA_Open"
    assert ix.details["tag"] == "TT-101"
    assert "session=5" in ix.details["detail"]
    assert ix.direction == "request"  # no confirm flag -> request
    # FDA_Open sets rw="read" in _process_fda but read_count only increments for
    # services whose name contains Read/Identify/FindTag, so it stays 0 here.
    assert ix.details["rw"] == "read"
    session = listener.sessions[(CLIENT_IP, SERVER_IP)]
    assert session.pd_tag == "TT-101"
    assert "FDA_Open" in session.services_seen
    assert session.read_count == 0


def test_fda_write_is_flagged_and_alerted():
    listener, ix = _feed({"hdr_srv_fda_service_id_confirm": "4"})  # FDA_Write
    assert ix.details["service"] == "FDA_Write"
    assert ix.details["rw"] == "write"
    assert "FDA_Write" in FF_WRITE_SERVICES
    session = listener.sessions[(CLIENT_IP, SERVER_IP)]
    assert session.write_count == 1
    # base harvest emits a write alert for protocols exposing get_write_operations.
    result = listener.harvest()
    write_alerts = [a for a in result["alerts"] if a.get("category") == "write_alert"]
    assert len(write_alerts) == 1
    assert "FF_HSE WRITE" in write_alerts[0]["message"]


def test_fda_open_records_max_buffer_size():
    _, ix = _feed(
        {
            "hdr_srv_fda_service_id_confirm": "1",  # FDA_Open
            "fda_open_sess_rsp_max_buf_siz": "1024",
        }
    )
    assert "buf=1024" in ix.details["detail"]


def test_fda_unconfirmed_identify_request():
    _, ix = _feed({"hdr_srv_fda_service_id_unconfirm": "1"})  # FDA_Identify
    assert ix.details["protocol"] == "FDA"
    assert ix.details["service"] == "FDA_Identify"


def test_fda_unknown_confirmed_service_id_synthesizes_name():
    _, ix = _feed({"hdr_srv_fda_service_id_confirm": "99"})
    assert ix.details["service"] == "FDA_Svc99"


def test_sm_identify_response_extracts_device_identity():
    listener, ix = _feed(
        {
            "hdr_srv_sm_service_id_confirm": "1",  # SM_Identify
            "hdr_srv_confirm_flag": "True",  # response
            "sm_id_rsp_dev_id": "Emerson-3051",
            "sm_id_rsp_pd_tag": "PT-200",
            "sm_id_rsp_dev_idx": "12",
            "sm_id_rsp_operational_ip_addr": "10.1.0.20",
        }
    )
    assert ix.details["protocol"] == "SM"
    assert ix.details["service"] == "SM_Identify"
    assert ix.direction == "response"
    assert ix.details["device_id"] == "Emerson-3051"
    assert ix.details["tag"] == "PT-200"
    detail = ix.details["detail"]
    assert "device=Emerson-3051" in detail
    assert "tag=PT-200" in detail
    assert "idx=12" in detail
    assert "ip=10.1.0.20" in detail
    # device_info recorded against the src_ip (the responding device).
    assert listener._device_info[CLIENT_IP]["device_id"] == "Emerson-3051"
    # On a response, client=dst, server=src.
    session = listener.sessions[(SERVER_IP, CLIENT_IP)]
    assert session.device_id == "Emerson-3051"
    assert session.read_count == 1  # "Identify" counts as a read


def test_sm_find_tag_query():
    _, ix = _feed(
        {
            "hdr_srv_sm_service_id_unconfirm": "1",  # SM_FindTagQuery
            "sm_find_tag_query_req_tag": "FT-300",
        }
    )
    assert ix.details["service"] == "SM_FindTagQuery"
    assert ix.details["tag"] == "FT-300"
    assert "FindTag=FT-300" in ix.details["detail"]


def test_sm_find_tag_reply():
    _, ix = _feed(
        {
            "hdr_srv_sm_service_id_unconfirm": "2",  # SM_FindTagReply
            "sm_find_tag_reply_req_dev_id": "Yokogawa-EJX",
            "sm_find_tag_reply_req_pd_tag": "FT-300",
        }
    )
    assert ix.details["service"] == "SM_FindTagReply"
    assert ix.details["device_id"] == "Yokogawa-EJX"
    assert ix.details["tag"] == "FT-300"
    assert "TagReply device=Yokogawa-EJX" in ix.details["detail"]


def test_fms_read_and_write_rw_flag():
    _, ix_read = _feed({"hdr_srv_fms_service_id_confirm": "1"})  # FMS_Read
    assert ix_read.details["protocol"] == "FMS"
    assert ix_read.details["service"] == "FMS_Read"
    assert ix_read.details["rw"] == "read"

    listener, ix_write = _feed({"hdr_srv_fms_service_id_confirm": "2"})  # FMS_Write
    assert ix_write.details["rw"] == "write"
    assert listener.sessions[(CLIENT_IP, SERVER_IP)].write_count == 1


def test_fms_unconfirmed_information_report():
    _, ix = _feed({"hdr_srv_fms_service_id_unconfirm": "1"})  # FMS_InformationReport
    assert ix.details["service"] == "FMS_InformationReport"


def test_lan_diagnostic_message():
    _, ix = _feed(
        {
            "hdr_srv_lan_service_id_confirm": "4",  # LR_DiagnosticMsg
            "lr_diagnostic_msg_req_dev_idx": "7",
            "lr_diagnostic_msg_req_pd_tag": "LR-1",
        }
    )
    assert ix.details["protocol"] == "LAN"
    assert ix.details["service"] == "LR_DiagnosticMsg"
    assert "diag idx=7" in ix.details["detail"]
    assert "tag=LR-1" in ix.details["detail"]


# ---------------------------------------------------------------------------
# Error responses
# ---------------------------------------------------------------------------


def test_fda_open_session_error_decoded():
    listener, ix = _feed(
        {
            "fda_open_sess_err": "1",  # error marker present -> FDA_Error
            "fda_open_sess_err_err_class": "4",  # Access
            "fda_open_sess_err_err_code": "9",
        }
    )
    assert ix.details["service"] == "FDA_Error"
    assert "Error: Access/code-9" in ix.details["detail"]
    session = listener.sessions[(CLIENT_IP, SERVER_IP)]
    assert session.error_count == 1


def test_sm_error_unknown_class_uses_synthetic_name():
    _, ix = _feed(
        {
            "sm_id_err": "1",
            "sm_id_err_err_class": "42",  # not in FF_ERROR_CLASSES
            "sm_id_err_err_code": "3",
        }
    )
    assert ix.details["service"] == "SM_Error"
    assert "Error: class-42/code-3" in ix.details["detail"]


# ---------------------------------------------------------------------------
# Fallback / generic + trailer + fda address
# ---------------------------------------------------------------------------


def test_generic_service_id_fallback():
    _, ix = _feed({"hdr_srv_service_id": "55"})
    assert ix.details["protocol"] == "FF"
    assert ix.details["service"] == "Svc55"


def test_no_service_fields_yields_unknown_service():
    _, ix = _feed({"hdr_ver": "1"})
    assert ix.details["protocol"] == "FF"
    assert ix.details["service"] == "Unknown"


def test_fda_address_and_trailer_fields_recorded():
    _, ix = _feed(
        {
            "hdr_srv_fda_service_id_confirm": "1",
            "hdr_fda_addr": "0x10203040",
            "trailer_invoke_id": "77",
            "trailer_msg_num": "3",
        }
    )
    assert ix.details["fda_addr"] == "0x10203040"
    assert ix.details["invoke_id"] == 77
    assert ix.details["msg_num"] == 3


def test_summary_contains_protocol_service_tag_detail():
    _, ix = _feed(
        {
            "hdr_srv_fda_service_id_confirm": "1",
            "fda_open_sess_req_pd_tag": "TT-101",
            "fda_open_sess_req_sess_idx": "2",
        }
    )
    assert ix.summary.startswith("FDA FDA_Open")
    assert "tag=TT-101" in ix.summary
    assert "session=2" in ix.summary


# ---------------------------------------------------------------------------
# Packet guard branches
# ---------------------------------------------------------------------------


def test_packet_without_ff_layer_ignored():
    listener = _make_listener()
    pkt = _FakePacket(CLIENT_IP, SERVER_IP, {"hdr_srv_service_id": "1"})
    del pkt.ff
    listener.process_packet(pkt)
    assert listener.interactions == []


def test_packet_without_ips_ignored():
    listener = _make_listener()
    listener.process_packet(_FakePacket("", "", {"hdr_srv_service_id": "1"}))
    assert listener.interactions == []


# ---------------------------------------------------------------------------
# Device discovery + reporting accessors
# ---------------------------------------------------------------------------


def test_devices_created_for_both_endpoints():
    listener, _ = _feed({"hdr_srv_fda_service_id_confirm": "1"})
    assert f"ff_hse:{CLIENT_IP}" in listener.discovered_devices
    assert f"ff_hse:{SERVER_IP}" in listener.discovered_devices
    dev = listener.discovered_devices[f"ff_hse:{CLIENT_IP}"]
    assert dev.device_type == "FF-HSE Device"
    assert dev.ff_hse_passive_data["protocol"] == "FOUNDATION Fieldbus HSE"
    assert "FDA_Open" in dev.ff_hse_passive_data["services_seen"]


def test_invalid_endpoint_ip_is_skipped_in_device_discovery():
    # Loopback fails is_valid_discovered_ip -> that endpoint is skipped, but the
    # valid peer is still registered.
    listener = _make_listener()
    listener.process_packet(
        _FakePacket("127.0.0.1", SERVER_IP, {"hdr_srv_fda_service_id_confirm": "1"})
    )
    assert "ff_hse:127.0.0.1" not in listener.discovered_devices
    assert f"ff_hse:{SERVER_IP}" in listener.discovered_devices


def test_device_name_uses_pd_tag_from_identify():
    # SM Identify response stores device_info keyed on src_ip, then device name
    # prefers pd_tag.
    listener, _ = _feed(
        {
            "hdr_srv_sm_service_id_confirm": "1",
            "hdr_srv_confirm_flag": "True",
            "sm_id_rsp_dev_id": "Dev-X",
            "sm_id_rsp_pd_tag": "PT-200",
        }
    )
    dev = listener.discovered_devices[f"ff_hse:{CLIENT_IP}"]
    assert dev.name == "PT-200"


def test_get_write_operations_filters_to_writers():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(CLIENT_IP, SERVER_IP, {"hdr_srv_fda_service_id_confirm": "4"})  # write
    )
    listener.process_packet(
        _FakePacket(CLIENT_IP, SERVER_IP, {"hdr_srv_fda_service_id_confirm": "3"})  # read
    )
    writes = listener.get_write_operations()
    assert len(writes) == 1
    assert writes[0] == {"client": CLIENT_IP, "server": SERVER_IP, "write_count": 1}


def test_get_sessions_summary_aggregates_services():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(CLIENT_IP, SERVER_IP, {"hdr_srv_fda_service_id_confirm": "1"})  # FDA_Open
    )
    listener.process_packet(
        _FakePacket(CLIENT_IP, SERVER_IP, {"hdr_srv_fms_service_id_confirm": "2"})  # FMS_Write
    )
    summary = listener.get_sessions_summary()
    assert len(summary) == 1
    s = summary[0]
    assert s["client"] == CLIENT_IP
    assert s["server"] == SERVER_IP
    assert set(s["services"]) == {"FDA_Open", "FMS_Write"}
    assert s["write_count"] == 1
    # FDA_Open does not count as a read (name lacks Read/Identify/FindTag).
    assert s["read_count"] == 0


def test_format_protocol_columns_matches_details():
    listener, ix = _feed(
        {
            "hdr_srv_fda_service_id_confirm": "1",
            "fda_open_sess_req_pd_tag": "TT-101",
            "fda_open_sess_req_sess_idx": "5",
        }
    )
    cols = listener._format_protocol_columns(ix)
    assert cols[0] == "FDA"
    assert cols[1] == "FDA_Open"
    assert cols[2] == "TT-101"
    assert "session=5" in cols[3]

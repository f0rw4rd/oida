"""Behavioral unit tests for the CoAP passive listener (``oida.pcap.coap``).

These drive ``CoAPPassiveListener.process_packet`` with lightweight fake
pyshark-style layer objects (no pyshark / tshark needed). Each test crafts a
packet whose ``coap`` layer carries the underscore field names the listener
reads via ``get_field`` (e.g. ``opt_uri_path_recon``), then asserts on the
parsed interaction, session bookkeeping, security alerts and harvest output.

Field-name mapping note: the listener calls ``self.get_field(coap, "type")``
etc., which does ``getattr(layer, "type")``. ``get_field`` stringifies ints,
so fake fields may hold native ints or strings interchangeably.
"""

from oida.pcap.coap import (
    COAP_WRITE_METHODS,
    CoAPPassiveListener,
)


# ---------------------------------------------------------------------------
# Fake pyshark layer / packet plumbing
# ---------------------------------------------------------------------------


class _Layer:
    """Attribute-only stand-in for a pyshark layer.

    Only explicitly-passed fields exist; absent fields raise AttributeError
    through getattr's default (exactly like a dissector that did not emit them).
    """

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class _FakePacket:
    def __init__(self, src_ip, dst_ip, coap_fields, *, src_port=40000, dst_port=5683):
        self.ip = _Layer(src=src_ip, dst=dst_ip)
        self.udp = _Layer(srcport=src_port, dstport=dst_port, stream="7")
        self.coap = _Layer(**coap_fields)


CLIENT_IP = "10.0.0.20"
SERVER_IP = "10.0.0.50"
COAP_PORT = 5683
COAPS_PORT = 5684


def _make_listener():
    return CoAPPassiveListener(interface="lo", timeout=1)


def _get(coap_fields, **pkt_kwargs):
    """Build a listener, feed one packet, return (listener, last_interaction)."""
    listener = _make_listener()
    listener.process_packet(_FakePacket(CLIENT_IP, SERVER_IP, coap_fields, **pkt_kwargs))
    ix = listener.interactions[-1] if listener.interactions else None
    return listener, ix


# ---------------------------------------------------------------------------
# Request method decoding (code class 0)
# ---------------------------------------------------------------------------


def test_get_request_decodes_method_and_uri_path():
    listener, ix = _get(
        {"type": "0", "code": "1", "mid": "1234", "opt_uri_path_recon": "/sensors/temp"}
    )
    assert ix.direction == "request"
    assert ix.operation == "GET"
    assert ix.details["method"] == "GET"
    assert ix.details["msg_type"] == "CON"
    assert ix.details["code"] == 1
    assert ix.details["uri_path"] == "/sensors/temp"
    # GET is a read -> session read_count increments, no write alert
    session = listener.sessions[(CLIENT_IP, SERVER_IP)]
    assert session.read_count == 1
    assert session.write_count == 0
    assert "GET" in session.methods
    assert "/sensors/temp" in session.uri_paths


def test_uri_path_recon_falls_back_to_opt_uri_path():
    # No reconstructed path; only a single uri_path component is present.
    _, ix = _get({"type": "1", "code": "1", "opt_uri_path": "status"})
    assert ix.details["uri_path"] == "status"
    assert ix.details["msg_type"] == "NON"


def test_put_request_is_write_and_raises_write_alert():
    listener, ix = _get({"type": "0", "code": "3", "opt_uri_path_recon": "/actuators/relay"})
    assert ix.details["method"] == "PUT"
    assert 3 in COAP_WRITE_METHODS
    session = listener.sessions[(CLIENT_IP, SERVER_IP)]
    assert session.write_count == 1
    write_alerts = [a for a in listener._alerts if a["category"] == "coap_write"]
    assert len(write_alerts) == 1
    assert "PUT" in write_alerts[0]["message"]
    assert "/actuators/relay" in write_alerts[0]["message"]
    assert write_alerts[0]["level"] == "fail"


def test_post_and_delete_are_writes():
    for code, name in (("2", "POST"), ("4", "DELETE")):
        listener, ix = _get({"type": "0", "code": code})
        assert ix.details["method"] == name
        assert listener.sessions[(CLIENT_IP, SERVER_IP)].write_count == 1


def test_unknown_request_code_in_method_class_synthesizes_name():
    # code 5 = FETCH is known; use an unknown low code to hit the class.detail path.
    # Codes 0-7 are requests; code mappings cover 0-7, so pick code in response
    # range that is not in COAP_CODES to exercise the synthetic class.detail name.
    _, ix = _get({"type": "2", "code": "200"})
    # 200 >> 5 == 6, 200 & 0x1F == 8 -> "6.08"
    assert ix.details["method"] == "6.08"
    assert ix.details["code"] == 200


# ---------------------------------------------------------------------------
# Response code decoding
# ---------------------------------------------------------------------------


def test_content_response_decodes_named_code():
    _, ix = _get({"type": "2", "code": "69", "mid": "1234"})  # 2.05 Content
    assert ix.direction == "response"
    assert ix.details["method"] == "2.05 Content"
    assert ix.details["code"] == 69


def test_unauthorized_response_raises_unauth_alert():
    listener, ix = _get({"type": "2", "code": "129"})  # 4.01 Unauthorized
    assert ix.details["method"] == "4.01 Unauthorized"
    alerts = [a for a in listener._alerts if a["category"] == "coap_unauthorized"]
    assert len(alerts) == 1
    assert "4.01" in alerts[0]["message"]
    # 4.xx counts as an error in the (server, client) session.
    session = listener.sessions[(SERVER_IP, CLIENT_IP)]
    assert session.error_count == 1


def test_forbidden_response_raises_forbidden_alert():
    listener, _ = _get({"type": "2", "code": "131"})  # 4.03 Forbidden
    alerts = [a for a in listener._alerts if a["category"] == "coap_forbidden"]
    assert len(alerts) == 1
    assert "4.03 Forbidden" in alerts[0]["message"]


def test_server_error_response_increments_error_count():
    listener, ix = _get({"type": "2", "code": "160"})  # 5.00 Internal Server Error
    assert ix.details["method"] == "5.00 Internal Server Error"
    assert listener.sessions[(SERVER_IP, CLIENT_IP)].error_count == 1


def test_unknown_response_code_synthesizes_class_detail():
    _, ix = _get({"type": "2", "code": "70"})  # 2.06 not in table
    # 70 >> 5 == 2, 70 & 0x1F == 6 -> "2.06"
    assert ix.details["method"] == "2.06"


# ---------------------------------------------------------------------------
# Empty messages (code 0) and message types
#
# Note: code 0 satisfies ``is_request`` (0 <= code <= 7) BEFORE the is_empty
# branch, so an Empty message classifies as a request with method "Empty".
# ---------------------------------------------------------------------------


def test_empty_code_classifies_as_request_named_empty():
    _, ix = _get({"type": "2", "code": "0", "mid": "55"})
    assert ix.details["msg_type"] == "ACK"
    assert ix.details["code"] == 0
    assert ix.direction == "request"
    assert ix.details["method"] == "Empty"


def test_empty_con_message():
    _, ix = _get({"type": "0", "code": "0", "mid": "55"})
    assert ix.details["msg_type"] == "CON"
    assert ix.details["method"] == "Empty"


def test_rst_empty_message_type():
    _, ix = _get({"type": "3", "code": "0"})
    assert ix.details["msg_type"] == "RST"


def test_missing_code_field_defaults_to_negative_one():
    # No code field at all -> code_raw is None -> code_val stays -1, which falls
    # through to the final else (direction request, method "Code(-1)").
    _, ix = _get({"type": "0"})
    assert ix.details["code"] == -1
    assert ix.direction == "request"
    assert ix.details["method"] == "Code(-1)"


def test_unknown_message_type_is_passed_through():
    _, ix = _get({"type": "9", "code": "1"})
    assert ix.details["msg_type"] == "T9"


# ---------------------------------------------------------------------------
# Options: content-format, observe, block, proxy, oscore, query, max-age...
# ---------------------------------------------------------------------------


def test_content_format_numeric_maps_to_mime():
    _, ix = _get({"type": "0", "code": "1", "opt_ctype": "50"})
    assert ix.details["content_format"] == "application/json"
    assert listener_content(ix) == "application/json"


def listener_content(ix):
    return ix.details.get("content_format")


def test_unknown_content_format_passes_through_raw():
    _, ix = _get({"type": "0", "code": "1", "opt_ctype": "9999"})
    assert ix.details["content_format"] == "9999"


def test_observe_register_marks_operation():
    _, ix = _get({"type": "0", "code": "1", "opt_observe": "0", "opt_uri_path_recon": "/temp"})
    assert ix.operation == "OBSERVE Register"
    assert ix.details["observe"] == 0


def test_observe_deregister_marks_operation():
    _, ix = _get({"type": "0", "code": "1", "opt_observe": "1"})
    assert ix.operation == "OBSERVE Deregister"
    assert ix.details["observe"] == 1


def test_observe_notification_on_response():
    listener, ix = _get({"type": "1", "code": "69", "opt_observe": "42"})
    assert ix.operation == "OBSERVE Notification"
    assert ix.details["observe"] == 42


def test_observe_request_increments_session_observe_count():
    listener, _ = _get({"type": "0", "code": "1", "opt_observe": "0"})
    assert listener.sessions[(CLIENT_IP, SERVER_IP)].observe_count == 1


def test_block_options_recorded():
    _, ix = _get(
        {
            "type": "0",
            "code": "3",
            "opt_block_number": "2",
            "opt_block_mflag": "1",
            "opt_block_size": "64",
        }
    )
    assert ix.details["block_number"] == "2"
    assert ix.details["block_more"] == "1"
    assert ix.details["block_size"] == "64"


def test_proxy_uri_raises_proxy_alert():
    listener, ix = _get(
        {"type": "0", "code": "1", "opt_proxy_uri": "http://internal.example/admin"}
    )
    assert ix.details["proxy_uri"] == "http://internal.example/admin"
    alerts = [a for a in listener._alerts if a["category"] == "coap_proxy"]
    assert len(alerts) == 1
    assert "http://internal.example/admin" in alerts[0]["message"]


def test_oscore_presence_suppresses_unencrypted_alert():
    listener, ix = _get({"type": "0", "code": "1", "opt_object_security_kid": "a1:b2"})
    assert ix.details["oscore"] is True
    assert listener.sessions[(CLIENT_IP, SERVER_IP)].has_oscore is True
    # has_oscore short-circuits the unencrypted-on-5683 alert.
    assert not [a for a in listener._alerts if a["category"] == "coap_unencrypted"]


def test_oscore_via_partial_iv_field():
    listener, ix = _get({"type": "0", "code": "1", "opt_object_security_piv": "00:01"})
    assert ix.details["oscore"] is True


def test_uri_query_and_payload_and_token_recorded():
    _, ix = _get(
        {
            "type": "0",
            "code": "1",
            "opt_uri_query": "since=10",
            "payload_length": "128",
            "payload_desc": "sensor blob",
            "token": "de:ad",
            "opt_max_age": "60",
            "opt_accept": "application/json",
            "opt_if_match": "ff",
            "opt_hop_limit": "8",
        }
    )
    assert ix.details["uri_query"] == "since=10"
    assert ix.details["payload_length"] == 128
    assert ix.details["payload_desc"] == "sensor blob"
    assert ix.details["token"] == "de:ad"
    assert ix.details["max_age"] == "60"
    assert ix.details["accept"] == "application/json"
    assert ix.details["if_match"] == "ff"
    assert ix.details["hop_limit"] == "8"


# ---------------------------------------------------------------------------
# Encryption detection (port-based) + unencrypted alert
# ---------------------------------------------------------------------------


def test_plain_port_marks_unencrypted_and_alerts():
    listener, ix = _get({"type": "0", "code": "1"}, dst_port=COAP_PORT)
    assert ix.details["encrypted"] is False
    assert listener.sessions[(CLIENT_IP, SERVER_IP)].unencrypted is True
    alerts = [a for a in listener._alerts if a["category"] == "coap_unencrypted"]
    assert len(alerts) == 1
    assert alerts[0]["level"] == "highlight"


def test_coaps_port_marks_encrypted_no_unencrypted_alert():
    listener, ix = _get({"type": "0", "code": "1"}, dst_port=COAPS_PORT)
    assert ix.details["encrypted"] is True
    assert listener.sessions[(CLIENT_IP, SERVER_IP)].unencrypted is False
    assert not [a for a in listener._alerts if a["category"] == "coap_unencrypted"]


def test_alert_dedup_only_fires_once_per_key():
    listener = _make_listener()
    for _ in range(3):
        listener.process_packet(
            _FakePacket(CLIENT_IP, SERVER_IP, {"type": "0", "code": "3"}, dst_port=COAP_PORT)
        )
    # Same write alert key (write:src:dst:PUT) -> only one alert.
    assert len([a for a in listener._alerts if a["category"] == "coap_write"]) == 1
    # Unencrypted alert key (unencrypted:src:dst) -> only one alert.
    assert len([a for a in listener._alerts if a["category"] == "coap_unencrypted"]) == 1


# ---------------------------------------------------------------------------
# Packet rejection / guard branches
# ---------------------------------------------------------------------------


def test_packet_without_coap_layer_ignored():
    listener = _make_listener()
    pkt = _FakePacket(CLIENT_IP, SERVER_IP, {"type": "0", "code": "1"})
    del pkt.coap
    listener.process_packet(pkt)
    assert listener.interactions == []


def test_packet_without_ips_ignored():
    listener = _make_listener()
    pkt = _FakePacket("", "", {"type": "0", "code": "1"})
    listener.process_packet(pkt)
    assert listener.interactions == []


# ---------------------------------------------------------------------------
# Device discovery
# ---------------------------------------------------------------------------


def test_request_registers_server_and_client_devices():
    listener, _ = _get({"type": "0", "code": "1"})
    assert f"coap-server:{SERVER_IP}" in listener.discovered_devices
    assert f"coap-client:{CLIENT_IP}" in listener.discovered_devices
    server = listener.discovered_devices[f"coap-server:{SERVER_IP}"]
    assert server.device_type == "CoAP Server"
    assert server.coap_passive_data["role"] == "server"


def test_response_inverts_server_client_roles():
    # A response (code>=64) means src is the server, dst is the client.
    listener, _ = _get({"type": "2", "code": "69"})
    assert f"coap-server:{CLIENT_IP}" in listener.discovered_devices
    assert f"coap-client:{SERVER_IP}" in listener.discovered_devices


# ---------------------------------------------------------------------------
# Formatting + harvest + reporting accessors
# ---------------------------------------------------------------------------


def test_format_protocol_columns_for_observe_register():
    listener, ix = _get(
        {
            "type": "0",
            "code": "1",
            "opt_observe": "0",
            "opt_uri_path_recon": "/temp",
            "opt_ctype": "50",
            "opt_uri_query": "x=1",
        },
        dst_port=COAP_PORT,
    )
    cols = listener._format_protocol_columns(ix)
    method, uri, mtype, cf, observe, detail = cols
    assert method == "GET"
    assert uri == "/temp"
    assert mtype == "CON"
    assert cf == "application/json"
    assert observe == "register"
    assert "?x=1" in detail
    assert "[PLAIN]" in detail


def test_format_protocol_columns_observe_sequence_and_oscore_and_block():
    listener, ix = _get(
        {
            "type": "1",
            "code": "69",
            "opt_observe": "7",
            "opt_object_security_kid": "aa",
            "opt_block_number": "3",
            "opt_block_mflag": "1",
        },
        dst_port=COAPS_PORT,
    )
    cols = listener._format_protocol_columns(ix)
    observe, detail = cols[4], cols[5]
    assert observe == "seq=7"
    assert "[OSCORE]" in detail
    assert "blk=3+" in detail
    assert "[PLAIN]" not in detail  # encrypted (COAPS port)


def test_harvest_builds_resource_table_and_includes_alerts():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            CLIENT_IP,
            SERVER_IP,
            {"type": "0", "code": "3", "opt_uri_path_recon": "/cfg", "opt_ctype": "50"},
            dst_port=COAP_PORT,
        )
    )
    result = listener.harvest()
    # Alerts present (write + unencrypted).
    categories = {a["category"] for a in result["alerts"]}
    assert "coap_write" in categories
    assert "coap_unencrypted" in categories
    # Resource discovery table inserted at the front.
    res_table = result["tables"][0]
    assert res_table["headers"] == ["Server", "URI Path", "Method", "Content-Format"]
    assert res_table["rows"] == [[SERVER_IP, "/cfg", "PUT", "application/json"]]
    assert "CoAP Resources (1)" in res_table["title"]


def test_harvest_empty_when_no_traffic():
    listener = _make_listener()
    assert listener.harvest() == {}


def test_format_protocol_columns_blank_observe_and_proxy_and_payload():
    # Build a ProtocolInteraction-like details dict directly to drive the
    # observe==-1 / payload / proxy formatting branches of the column builder.
    from oida.pcap.pyshark_base import ProtocolInteraction

    ix = ProtocolInteraction(
        timestamp="t",
        src_ip=CLIENT_IP,
        dst_ip=SERVER_IP,
        direction="request",
        operation="GET",
        details={
            "method": "GET",
            "observe": -1,  # explicit -1 -> blank observe column
            "payload_length": 42,
            "proxy_uri": "http://relay",
            "encrypted": True,
        },
    )
    listener = _make_listener()
    cols = listener._format_protocol_columns(ix)
    assert cols[4] == ""  # observe blanked
    detail = cols[5]
    assert "len=42" in detail
    assert "proxy=http://relay" in detail


def test_format_protocol_columns_observe_deregister_label():
    from oida.pcap.pyshark_base import ProtocolInteraction

    ix = ProtocolInteraction(
        timestamp="t",
        src_ip=CLIENT_IP,
        dst_ip=SERVER_IP,
        direction="request",
        operation="GET",
        details={"method": "GET", "observe": 1, "encrypted": True},
    )
    listener = _make_listener()
    cols = listener._format_protocol_columns(ix)
    assert cols[4] == "deregister"


def test_harvest_returns_alerts_only_without_resource_table():
    # A response packet (no uri_path) on the plain port produces an unencrypted
    # alert but no URI rows -> harvest returns alerts but inserts no table.
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(SERVER_IP, CLIENT_IP, {"type": "2", "code": "69"}, dst_port=COAP_PORT)
    )
    result = listener.harvest()
    assert any(a["category"] == "coap_unencrypted" for a in result["alerts"])
    # No URI Path table since no uri_path was seen.
    assert not any(
        t.get("title", "").startswith("CoAP Resources") for t in result.get("tables", [])
    )


def test_get_write_operations_counts_writes():
    listener = _make_listener()
    for code in ("3", "3", "1"):  # PUT, PUT, GET
        listener.process_packet(
            _FakePacket(CLIENT_IP, SERVER_IP, {"type": "0", "code": code}, dst_port=COAP_PORT)
        )
    writes = listener.get_write_operations()
    assert len(writes) == 1
    assert writes[0] == {"client": CLIENT_IP, "server": SERVER_IP, "write_count": 2}


def test_get_sessions_summary_reports_counts_and_flags():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            CLIENT_IP,
            SERVER_IP,
            {"type": "0", "code": "1", "opt_uri_path_recon": "/temp", "opt_ctype": "50"},
            dst_port=COAP_PORT,
        )
    )
    summary = listener.get_sessions_summary()
    assert len(summary) == 1
    s = summary[0]
    assert s["client"] == CLIENT_IP
    assert s["server"] == SERVER_IP
    assert s["methods"] == ["GET"]
    assert s["uri_paths"] == ["/temp"]
    assert s["content_formats"] == ["application/json"]
    assert s["read_count"] == 1
    assert s["unencrypted"] is True


def test_build_summary_includes_all_decorations():
    summary = CoAPPassiveListener._build_summary(
        method="GET",
        uri_path="/temp",
        msg_type="CON",
        is_observe=True,
        observe_val=0,
        content_format="application/json",
        payload_len=12,
        is_encrypted=False,
    )
    assert "GET" in summary
    assert "/temp" in summary
    assert "[OBSERVE:register]" in summary
    assert "(application/json)" in summary
    assert "12B" in summary


def test_build_summary_observe_deregister_and_sequence():
    s_dereg = CoAPPassiveListener._build_summary("PUT", "", "CON", True, 1, "", 0, True)
    assert "[OBSERVE:deregister]" in s_dereg
    s_seq = CoAPPassiveListener._build_summary("GET", "", "NON", True, 99, "", 0, True)
    assert "[OBSERVE:seq=99]" in s_seq

"""Regression tests for c1222.py response-code and phantom-REGISTRATION bugs.

Bugs fixed (see task report):
  4. c1222.py only ever read the `cmd` field. Wireshark's packet-c1222.c
     writes service *requests* (code >= 0x20) to hf_c1222_cmd, but writes
     OK/error RESPONSE codes (0x00-0x12) to the separate hf_c1222_err field.
     Every real response PDU therefore resolved to cmd_code=None / "Unknown".
  5. cmd_code == 0x27 was treated as a "REGISTRATION" service. 0x27 is not a
     defined EPSEM command; real ANSI C12.22 registration is a WRITE to
     Table 55 (the file's own SENSITIVE_TABLES already documents table 55 as
     "Registration (ST-55)").
"""

from oida.pcap.c1222 import C1222PassiveListener, C1222_SERVICES, WRITE_SERVICES


class _Layer:
    def __init__(self, **fields):
        for key, value in fields.items():
            setattr(self, key, value)


class _Packet:
    def __init__(self, c1222_layer, sport=54321, dport=1153):
        self.c1222 = c1222_layer
        self.ip = _Layer(src="10.0.0.10", dst="10.0.0.20")
        self.tcp = _Layer(srcport=str(sport), dstport=str(dport), stream="0")
        self.eth = _Layer(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        self.transport_layer = "TCP"
        self.highest_layer = "C1222"

    def __contains__(self, item):
        return hasattr(self, str(item).lower())


def _make_listener():
    return C1222PassiveListener(interface="lo", timeout=1)


# --- Bug 4: response PDUs only carry the `err` field -----------------------------


def test_response_pdu_with_only_err_field_resolves_service_code():
    """A real C12.22 RESPONSE PDU carries `err`, not `cmd`. It must not resolve
    to cmd_code=None / service_name="Unknown"."""
    listener = _make_listener()
    layer = _Layer(err="0x00")  # 0x00 == OK, per C1222_SERVICES
    listener.process_packet(_Packet(layer))

    assert len(listener.interactions) == 1
    details = listener.interactions[0].details
    assert details["service_code"] == 0x00
    assert details["service_name"] == C1222_SERVICES[0x00]


def test_response_pdu_with_only_err_field_is_classified_as_response():
    listener = _make_listener()
    layer = _Layer(err="0x00")
    listener.process_packet(_Packet(layer))

    assert listener.interactions[0].direction == "response"


def test_request_pdu_with_cmd_field_still_works():
    """Sanity: a genuine service request (cmd >= 0x20) is unaffected."""
    listener = _make_listener()
    layer = _Layer(cmd="0x20")  # Identify
    listener.process_packet(_Packet(layer))

    details = listener.interactions[0].details
    assert details["service_code"] == 0x20
    assert details["service_name"] == C1222_SERVICES[0x20]
    assert listener.interactions[0].direction == "request"


# --- Bug 5: 0x27 "REGISTRATION" does not exist ------------------------------------


def test_write_to_table_55_is_classified_as_registration():
    listener = _make_listener()
    assert 0x40 in WRITE_SERVICES  # Full Write
    layer = _Layer(cmd="0x40", write_table="55")
    listener.process_packet(_Packet(layer))

    session = next(iter(listener.sessions.values()))
    assert session.registration_count == 1
    assert any(a["category"] == "c1222_registration" for a in listener._alerts)


def test_write_to_other_table_is_not_registration():
    listener = _make_listener()
    layer = _Layer(cmd="0x40", write_table="10")
    listener.process_packet(_Packet(layer))

    session = next(iter(listener.sessions.values()))
    assert session.registration_count == 0
    assert not any(a["category"] == "c1222_registration" for a in listener._alerts)


def test_phantom_0x27_command_is_not_registration():
    """0x27 is not a defined EPSEM service; it must not raise a false
    registration alert, and must not increment registration_count."""
    listener = _make_listener()
    layer = _Layer(cmd="0x27")
    listener.process_packet(_Packet(layer))

    details = listener.interactions[0].details
    assert details["service_code"] == 0x27
    assert details["service_name"] not in C1222_SERVICES.values()

    session = next(iter(listener.sessions.values()))
    assert session.registration_count == 0
    assert not any(a["category"] == "c1222_registration" for a in listener._alerts)

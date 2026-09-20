"""Regression tests for two iSCSI CHAP extraction bugs in
``_extract_chap()`` (src/oida/pcap/iscsi.py, ~line 578-648).

Bug 3 (latent-fallback, MEDIUM): the fallback candidate field-name tuple
included three names that can never resolve against a real tshark iscsi
layer -- "login_keyvalue" / "text_keyvalue" (the login/text KeyValue field
is always the single ``iscsi.keyvalue``), "data" and "datasegment" (no such
fields exist at all), and "ping_data" (the real field sanitizes to
"pingdata", not "ping_data"). Verified via
``tshark -G fields | grep -P '\\tiscsi\\.'`` -- the only byte-content
fields that exist are keyvalue, pingdata, immediatedata, asynceventdata,
vendorspecificdata. The primary "keyvalue" candidate normally resolves, so
this was a dead safety net, not a live outage.

Bug 4 (MEDIUM): ``self._chap_state`` accumulates per-flow CHAP key/value
pairs and was never cleared once a credential is captured, so it grows
unbounded across a long capture, and -- because RFC 7143 permits more than
one login phase per connection -- a second CHAP exchange on the same flow
that omits CHAP_N incorrectly inherited the stale username from the first
exchange.
"""

from oida.pcap.iscsi import ISCSIPassiveListener


class _Layer:
    """Minimal stand-in for a pyshark layer: attribute access only."""

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class _FakePacket:
    """A fake iSCSI packet: eth + ip + tcp + iscsi layers."""

    def __init__(self, src_ip, dst_ip, iscsi_fields, *, src_port=33000, dst_port=3260):
        self.eth = _Layer(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:02")
        self.ip = _Layer(src=src_ip, dst=dst_ip)
        self.tcp = _Layer(srcport=str(src_port), dstport=str(dst_port), stream="0")
        self.iscsi = _Layer(**iscsi_fields)


INIT_IP = "10.0.1.50"
TARGET_IP = "10.0.1.10"


def _make_listener():
    return ISCSIPassiveListener(interface="lo", timeout=1)


# ---------------------------------------------------------------------------
# Bug 3: fallback field names must resolve to real tshark iscsi.* fields
# ---------------------------------------------------------------------------


def test_chap_extracted_via_pingdata_fallback_when_keyvalue_absent():
    """ "ping_data" never matched (the real field sanitizes to "pingdata");
    with no working fallback, CHAP text carried in a non-keyvalue field was
    silently lost."""
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            INIT_IP,
            TARGET_IP,
            {
                "opcode": "0x03",
                "pingdata": "CHAP_A=5,CHAP_I=1,CHAP_N=admin,CHAP_C=cafebabe,CHAP_R=deadbeef",
            },
        )
    )
    assert len(listener.credentials) == 1
    cred = listener.credentials[0]
    assert cred.username == "admin"
    assert cred.response == "deadbeef"


# ---------------------------------------------------------------------------
# Bug 4: per-flow CHAP state must be cleared once a credential is captured
# ---------------------------------------------------------------------------


def test_chap_credential_captured_across_split_packets_same_flow():
    """Happy path: CHAP_N arrives in one PDU, CHAP_R/C in a later PDU of the
    SAME negotiation -- clearing state on capture must not break this."""
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            INIT_IP,
            TARGET_IP,
            {"opcode": "0x03", "keyvalue": "CHAP_A=5,CHAP_I=1,CHAP_N=admin"},
        )
    )
    assert len(listener.credentials) == 0  # no CHAP_R yet

    listener.process_packet(
        _FakePacket(
            INIT_IP,
            TARGET_IP,
            {"opcode": "0x03", "keyvalue": "CHAP_C=cafebabe,CHAP_R=deadbeef"},
        )
    )
    assert len(listener.credentials) == 1
    cred = listener.credentials[0]
    assert cred.username == "admin"
    assert cred.response == "deadbeef"
    assert cred.challenge == "cafebabe"

    # State must be cleared for the flow once the credential was captured.
    assert listener._chap_state == {}


def test_second_chap_negotiation_same_flow_does_not_inherit_stale_username():
    """RFC 7143 permits more than one login phase on the same connection.
    If the second exchange omits CHAP_N, the credential must NOT be paired
    with the first negotiation's username."""
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            INIT_IP,
            TARGET_IP,
            {
                "opcode": "0x03",
                "keyvalue": "CHAP_A=5,CHAP_I=1,CHAP_N=admin,CHAP_C=cafebabe,CHAP_R=deadbeef",
            },
        )
    )
    assert len(listener.credentials) == 1
    assert listener.credentials[0].username == "admin"

    # Second negotiation on the SAME flow -- no CHAP_N this time.
    listener.process_packet(
        _FakePacket(
            INIT_IP,
            TARGET_IP,
            {
                "opcode": "0x03",
                "keyvalue": "CHAP_A=5,CHAP_I=2,CHAP_C=f00dcafe,CHAP_R=0badf00d",
            },
        )
    )
    assert len(listener.credentials) == 2
    second = listener.credentials[1]
    assert second.response == "0badf00d"
    assert second.username != "admin"
    assert second.username == ""

"""Behavioral parse tests for the iSCSI passive listener.

iSCSI carries the SAN-discovery material -- target/initiator IQN, auth method
and session type -- as RFC 7143 ``key=value`` login/text text, which Wireshark
exposes as repeated ``iscsi.keyvalue`` fields (there are NO dedicated
``iscsi.login.target_name`` / ``initiator_name`` / ``auth_method`` /
``session_type`` fields).  The LUN lives on the SCSI layer as ``scsi.lun``, not
``iscsi.lun``.

These tests drive ``process_packet()`` with lightweight fake pyshark layers --
no pyshark, tshark, or .pcap needed -- and assert the corrected field paths so a
regression back to the dead ``iscsi.login.*`` / ``iscsi.lun`` reads is caught.

Regression guard: process_packet read
``iscsi.login.target_name`` / ``initiator_name`` / ``auth_method`` /
``session_type`` and ``iscsi.lun`` -- none of which the dissector emits -- so
target/initiator/auth/session/LUN extraction was entirely dead.
"""

from oida.pcap.iscsi import ISCSIPassiveListener


class _Layer:
    """Minimal stand-in for a pyshark layer: attribute access only.

    Only fields explicitly passed exist; a field set to a Python ``list`` models
    pyshark EK-mode multi-value fields (e.g. the repeated ``iscsi.keyvalue``).
    """

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class _FakePacket:
    """A fake iSCSI packet: eth + ip + tcp + iscsi (+ optional scsi) layers."""

    def __init__(
        self,
        src_ip,
        dst_ip,
        iscsi_fields,
        *,
        scsi_fields=None,
        src_port=33000,
        dst_port=3260,
    ):
        self.eth = _Layer(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:02")
        self.ip = _Layer(src=src_ip, dst=dst_ip)
        self.tcp = _Layer(srcport=str(src_port), dstport=str(dst_port), stream="0")
        self.iscsi = _Layer(**iscsi_fields)
        if scsi_fields is not None:
            self.scsi = _Layer(**scsi_fields)


INIT_IP = "10.0.1.50"
TARGET_IP = "10.0.1.10"
TARGET_IQN = "iqn.2024-01.com.storage:disk01"
INIT_IQN = "iqn.1991-05.com.microsoft:win10-pc"


def _make_listener():
    return ISCSIPassiveListener(interface="lo", timeout=1)


# ---------------------------------------------------------------------------
# keyvalue parsing helpers
# ---------------------------------------------------------------------------


def test_parse_login_keyvalues_splits_pairs():
    kv = ISCSIPassiveListener._parse_login_keyvalues(
        ["TargetName=iqn.a:b", "AuthMethod=CHAP,None", "SessionType=Normal"]
    )
    assert kv["TargetName"] == "iqn.a:b"
    # value that itself contains a comma (CHAP,None) is preserved intact
    assert kv["AuthMethod"] == "CHAP,None"
    assert kv["SessionType"] == "Normal"


def test_parse_login_keyvalues_ignores_non_pairs():
    assert ISCSIPassiveListener._parse_login_keyvalues(["novaluehere", ""]) == {}


def test_collect_keyvalues_ek_list_and_single_string():
    listener = _make_listener()
    # EK mode: repeated keyvalue fields arrive as a Python list.
    lst = _Layer(keyvalue=["TargetName=iqn.a:b", "SessionType=Discovery"])
    assert listener._collect_keyvalues(lst) == [
        "TargetName=iqn.a:b",
        "SessionType=Discovery",
    ]
    # Single keyvalue arrives as a bare string.
    one = _Layer(keyvalue="SendTargets=All")
    assert listener._collect_keyvalues(one) == ["SendTargets=All"]
    # No keyvalue field at all -> empty.
    assert listener._collect_keyvalues(_Layer()) == []


# ---------------------------------------------------------------------------
# process_packet: login-request extraction (the previously-dead capability)
# ---------------------------------------------------------------------------


def test_login_request_extracts_iqns_auth_and_session():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            INIT_IP,
            TARGET_IP,
            {
                "opcode": "0x03",  # Login Request
                "keyvalue": [
                    f"InitiatorName={INIT_IQN}",
                    f"TargetName={TARGET_IQN}",
                    "SessionType=Normal",
                    "AuthMethod=None",
                ],
            },
        )
    )
    assert listener.interactions, "login request should record an interaction"
    d = listener.interactions[-1].details
    assert d["target_name"] == TARGET_IQN
    assert d["initiator_name"] == INIT_IQN
    assert d["session_type"] == "Normal"
    assert d["auth_method"] == "None"

    # A login request is initiator -> target, so the target IQN is tracked
    # against the server (dst) and the initiator IQN against the client (src).
    assert TARGET_IQN in listener.target_names.get(TARGET_IP, set())
    assert INIT_IQN in listener.initiator_names.get(INIT_IP, set())
    assert "None" in listener.auth_methods.get(TARGET_IP, set())


def test_lun_read_from_scsi_layer_not_iscsi():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            INIT_IP,
            TARGET_IP,
            {"opcode": "0x01"},  # SCSI Command
            scsi_fields={"lun": "1"},
        )
    )
    assert listener.interactions[-1].details["lun"] == "1"


def test_lun_absent_when_no_scsi_layer():
    listener = _make_listener()
    listener.process_packet(_FakePacket(INIT_IP, TARGET_IP, {"opcode": "0x01"}))
    assert listener.interactions[-1].details["lun"] == ""


def test_iscsi_login_target_name_field_is_dead_and_not_read():
    """Regression: the dissector has no ``iscsi.login.target_name`` field. A
    packet that (impossibly) carried such an attribute must NOT be used as the
    IQN source -- extraction comes only from ``iscsi.keyvalue``."""
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            INIT_IP,
            TARGET_IP,
            {
                "opcode": "0x03",
                # bogus/non-existent fields the old code mistakenly read:
                "login_target_name": "SHOULD-NOT-APPEAR",
                "login_auth_method": "SHOULD-NOT-APPEAR",
                # the real source of the IQN:
                "keyvalue": [f"TargetName={TARGET_IQN}"],
            },
        )
    )
    d = listener.interactions[-1].details
    assert d["target_name"] == TARGET_IQN
    assert d["auth_method"] == ""  # no AuthMethod keyvalue -> empty, not the bogus field


def test_harvest_targets_table_populated_from_keyvalue():
    listener = _make_listener()
    listener.process_packet(
        _FakePacket(
            INIT_IP,
            TARGET_IP,
            {
                "opcode": "0x03",
                "keyvalue": [f"TargetName={TARGET_IQN}", "AuthMethod=CHAP"],
            },
        )
    )
    result = listener.harvest()
    titles = {t["title"] for t in result.get("tables", [])}
    assert "iSCSI Targets Discovered" in titles
    target_table = next(t for t in result["tables"] if t["title"] == "iSCSI Targets Discovered")
    rows_flat = [cell for row in target_table["rows"] for cell in row]
    assert TARGET_IQN in rows_flat
    assert any("CHAP" in str(cell) for cell in rows_flat)

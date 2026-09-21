"""Regression: C12.22 LOGON password arrives on a separate SECURITY PDU.

The LOGON (0x50) PDU exposes ``c1222.logon.id`` / ``c1222.logon.user``; the
password lives under the SECURITY (0x51) service as ``c1222.security.password``.
The credential append was gated to ``cmd_code == 0x50`` with no cross-PDU merge,
so:

- on the SECURITY packet ``cmd_code != 0x50`` -> no credential appended (the
  real password was dropped);
- on the LOGON packet the password field was empty -> a credential was recorded
  with ``password_value=""``.

The listener now stashes SECURITY passwords on the session and merges them into
the LOGON credential (in either arrival order).
"""

from oida.pcap.c1222 import C1222PassiveListener


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


def _logon_packet(username="field_ops"):
    return _Packet(_Layer(cmd="0x50", logon_id="17", logon_user=username))


def _security_packet(password="s3cret"):
    return _Packet(_Layer(cmd="0x51", security_password=password))


def test_security_after_logon_updates_empty_password():
    listener = _make_listener()
    listener.process_packet(_logon_packet())
    listener.process_packet(_security_packet())

    creds = [(c.username, c.password) for c in listener.credentials]
    assert creds == [("field_ops", "s3cret")]


def test_security_before_logon_supplies_password():
    listener = _make_listener()
    listener.process_packet(_security_packet())
    listener.process_packet(_logon_packet())

    creds = [(c.username, c.password) for c in listener.credentials]
    assert creds == [("field_ops", "s3cret")]


def test_logon_with_own_password_unchanged():
    """A LOGON PDU that carries its own password must not be altered by a
    later SECURITY password."""
    listener = _make_listener()
    listener.process_packet(
        _Packet(
            _Layer(cmd="0x50", logon_id="17", logon_user="field_ops", security_password="own_pw")
        )
    )
    listener.process_packet(_security_packet(password="later_pw"))

    creds = [(c.username, c.password) for c in listener.credentials]
    assert creds == [("field_ops", "own_pw")]

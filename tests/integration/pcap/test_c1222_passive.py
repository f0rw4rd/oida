"""Integration smoke test for the c1222 passive listener.

Loads the bundled reference pcap and asserts the listener completes
without crashing and yields the expected dict shapes from harvest().

Validation note: every bundled c1222 fixture has the EPSEM security flag
set (the C12.22 service block is encrypted) so the read/write/logon/
security service fields never decode -- even ``c1222.cmd`` does not
resolve. The bundled-pcap test below therefore only asserts no-crash.
The ``TestC1222FieldExtraction`` class closes that gap by driving
``process_packet`` directly with fake pyshark-style layers that expose
the *real* dissector field names (``c1222.read.table`` -> ``read_table``
after the layer prefix is stripped and dots become underscores). This
exercises the service-qualified field wiring that the previous dead
names (``c1222.table`` / ``c1222.user`` / ``c1222.auth_value``, none of
which exist in packet-c1222.c) silently failed to read.
"""

import pytest

from tests.integration.pcap.conftest import _run_listener_test
from oida.pcap.c1222 import C1222PassiveListener

pytestmark = [pytest.mark.integration]


class _FakeLayer:
    """Minimal stand-in for a pyshark layer: attribute access only."""

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class _FakeUDP:
    def __init__(self, srcport, dstport):
        self.srcport = srcport
        self.dstport = dstport


class _FakePacket:
    """Minimal stand-in for a pyshark packet for process_packet()."""

    def __init__(self, c1222, src_ip, dst_ip, srcport, dstport):
        self.c1222 = c1222
        self.ip = _FakeLayer(src=src_ip, dst=dst_ip)
        self.udp = _FakeUDP(srcport, dstport)

    def __contains__(self, item):  # not used, but harmless
        return hasattr(self, item)


class TestC1222PassiveEK:
    """c1222 listener smoke + harvest-shape assertions."""

    def test_c1222_no_crash(self):
        listener, devices, result = _run_listener_test(
            "c1222",
            "C1222PassiveListener",
            "c1222",
            "c1222/c1222_over_ipv6.pcap",
            min_devices=0,
            min_interactions=0,
        )
        assert isinstance(devices, dict)
        assert isinstance(result, dict)


class TestC1222FieldExtraction:
    """Validate the service-qualified dissector field names are wired up.

    Drives process_packet() with fake layers using the real pyshark
    attribute names; if the old dead field names were still in use these
    assertions would all fail (table/offset/count blank, no credential,
    no_auth firing on an authenticated request).
    """

    def _listener(self):
        return C1222PassiveListener(interface="lo", timeout=1)

    def test_read_sensitive_table_extracts_table_offset_count(self):
        listener = self._listener()
        # c1222.cmd=0x30 (READ), c1222.read.table=7 (sensitive ST-7),
        # c1222.read.offset=16, c1222.read.count=32, with an auth value.
        c1222 = _FakeLayer(
            cmd="0x30",
            read_table="7",
            read_offset="16",
            read_count="32",
            calling_authentication_value_octet_aligned="aa:bb:cc:dd",
            calling_ap_title="2.16.124.113620.1.22",
        )
        pkt = _FakePacket(c1222, "10.0.0.5", "10.0.0.7", 5000, 1153)
        listener.process_packet(pkt)

        assert len(listener.interactions) == 1
        d = listener.interactions[0].details
        assert d["table"] == 7
        assert d["offset"] == 16
        assert d["count"] == 32
        assert d["table_name"] == "Security Table (ST-7)"
        assert d["has_auth_value"] is True
        # Authenticated READ must NOT raise the no-auth alert.
        cats = {a["category"] for a in listener._alerts}
        assert "c1222_no_auth" not in cats
        # Sensitive-table read alert should fire.
        assert "c1222_sensitive_table" in cats

    def test_read_without_auth_flags_no_auth(self):
        listener = self._listener()
        c1222 = _FakeLayer(cmd="0x30", read_table="64", read_offset="0", read_count="8")
        pkt = _FakePacket(c1222, "10.0.0.5", "10.0.0.7", 5000, 1153)
        listener.process_packet(pkt)
        cats = {a["category"] for a in listener._alerts}
        assert "c1222_no_auth" in cats

    def test_write_table_uses_write_size_for_count(self):
        listener = self._listener()
        # WRITE uses c1222.write.table / c1222.write.offset / c1222.write.size.
        c1222 = _FakeLayer(
            cmd="0x40",
            write_table="0",
            write_offset="4",
            write_size="12",
        )
        pkt = _FakePacket(c1222, "10.0.0.5", "10.0.0.7", 5000, 1153)
        listener.process_packet(pkt)
        d = listener.interactions[0].details
        assert d["table"] == 0
        assert d["offset"] == 4
        assert d["count"] == 12
        cats = {a["category"] for a in listener._alerts}
        assert "c1222_write" in cats

    def test_logon_security_captures_credential(self):
        listener = self._listener()
        # LOGON (0x50) carries c1222.logon.id + c1222.logon.user; the
        # password is exposed via the SECURITY service field
        # c1222.security.password.
        c1222 = _FakeLayer(
            cmd="0x50",
            logon_id="3",
            logon_user="admin",
            security_password="s3cr3t",
        )
        pkt = _FakePacket(c1222, "10.0.0.5", "10.0.0.7", 5000, 1153)
        listener.process_packet(pkt)

        d = listener.interactions[0].details
        assert d["user_id"] == 3
        assert d["username"] == "admin"
        assert d["has_password"] is True

        assert len(listener.credentials) == 1
        cred = listener.credentials[0]
        assert cred.username == "admin"
        assert cred.password == "s3cr3t"

        cats = {a["category"] for a in listener._alerts}
        assert "c1222_logon" in cats
        assert "c1222_cleartext_password" in cats

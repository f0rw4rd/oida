"""Integration smoke test for the opcda passive listener.

Loads the bundled reference pcap and asserts the listener completes
without crashing and yields the expected dict shapes from harvest().
"""

import pytest

from tests.integration.pcap.conftest import _run_listener_test
from oida.pcap.opcda import OPCDAPassiveListener

pytestmark = [pytest.mark.integration]


# IIDs used by the greedy-guard regression test below.
_IOPCSERVER_IID = "39c13a4d-011e-11d0-9675-0020afd8adb3"  # real OPC DA interface
_IREMUNKNOWN_IID = "00000131-0000-0000-c000-000000000046"  # plain DCOM core iface


class _FakeLayer:
    """Minimal stand-in for a pyshark layer: attribute access only."""

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class _FakeTCP:
    def __init__(self, srcport, dstport):
        self.srcport = srcport
        self.dstport = dstport


class _FakePacket:
    """Minimal stand-in for a pyshark packet for process_packet()."""

    def __init__(self, dcom, src_ip, dst_ip, srcport, dstport):
        self.dcom = dcom
        self.ip = _FakeLayer(src=src_ip, dst=dst_ip)
        self.tcp = _FakeTCP(srcport, dstport)

    def __contains__(self, item):  # not used, but harmless
        return hasattr(self, item)


class TestOPCDAPassiveEK:
    """opcda listener smoke + harvest-shape assertions."""

    def test_opcda_no_crash(self):
        listener, devices, result = _run_listener_test(
            "opcda",
            "OPCDAPassiveListener",
            "dcom",
            "opcda/dcerpc-winreg-with-rpc-sec-verification-trailer.pcap",
            min_devices=0,
            min_interactions=0,
        )
        assert isinstance(devices, dict)
        assert isinstance(result, dict)


class TestOPCDAGreedyGuard:
    """Regression: plain (non-OPC-DA) DCOM must not be reported as OPC DA.

    REQUIRED_LAYERS=('dcom',) routes EVERY DCERPC/DCOM packet to this
    listener.  Microsoft DCOM is ubiquitous on Windows (WMI, IRemUnknown,
    IOXIDResolver).  Before the fix, process_packet() recorded an
    interaction and _update_devices() spawned 'DCOM Server'/'DCOM Client'
    devices for ANY such packet, so an ordinary Windows RPC-over-DCOM
    capture was falsely reported as OPC DA activity.  is_opcda gates
    recording: only packets resolving to a known OPC DA interface (by IID
    or via the IPID->iface mapping) should produce anything.
    """

    def _listener(self):
        return OPCDAPassiveListener(interface="lo", timeout=1)

    def test_plain_dcom_produces_nothing(self):
        listener = self._listener()
        # IRemUnknown::RemQueryInterface — pure DCOM plumbing, not OPC DA.
        dcom = _FakeLayer(iid=_IREMUNKNOWN_IID, opnum="3", ipid="aa-bb")
        pkt = _FakePacket(dcom, "10.0.0.5", "10.0.0.7", 50000, 49152)
        devices = listener.feed_packets(iter([pkt]))

        assert listener.interactions == [], "plain DCOM must not record interactions"
        assert devices == {}, "plain DCOM must not spawn devices"
        assert listener.sessions == {}, "plain DCOM must not create sessions"

    def test_real_opcda_still_recorded(self):
        listener = self._listener()
        # IOPCServer::AddGroup — genuine OPC DA request.
        dcom = _FakeLayer(iid=_IOPCSERVER_IID, opnum="0", ipid="cc-dd")
        pkt = _FakePacket(dcom, "10.0.0.5", "10.0.0.7", 50000, 49152)
        devices = listener.feed_packets(iter([pkt]))

        assert len(listener.interactions) == 1, "genuine OPC DA must be recorded"
        ix = listener.interactions[0]
        assert ix.details.get("is_opcda") is True
        assert ix.details.get("interface") == "IOPCServer"
        assert "IOPCServer" in ix.operation
        # A server device should have been spawned for the OPC DA endpoint.
        assert any("OPC DA" in (d.device_type or "") for d in devices.values())

    def test_ipid_resolution_records_followup(self):
        listener = self._listener()
        # First packet binds IPID -> IOPCSyncIO via the IID; recorded.
        bind = _FakeLayer(iid="39c13a52-011e-11d0-9675-0020afd8adb3", ipid="11-22")
        # Follow-up carries only the IPID + opnum (no IID) — must resolve to
        # IOPCSyncIO::Read via the mapping and still be recorded.
        followup = _FakeLayer(ipid="11-22", opnum="0")
        listener.feed_packets(
            iter(
                [
                    _FakePacket(bind, "10.0.0.5", "10.0.0.7", 50000, 49152),
                    _FakePacket(followup, "10.0.0.5", "10.0.0.7", 50000, 49152),
                ]
            )
        )
        assert len(listener.interactions) == 2
        assert any("Read" in ix.operation for ix in listener.interactions)

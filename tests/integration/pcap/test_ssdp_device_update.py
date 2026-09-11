"""Regression: SSDP device record must update on later packets, not freeze.

device.ssdp_data was written only when the device was first seen, so a later
NOTIFY with a changed LOCATION/USN was ignored and an ssdp:byebye left a
stale "alive" record indefinitely.
"""

import pytest

from oida.pcap.ssdp import SSDPPassiveListener

pytestmark = [pytest.mark.integration]


class _FakePacket:
    """Enough of a pyshark packet for SSDPPassiveListener.process_packet."""

    def __init__(self, src_ip):
        self._src_ip = src_ip
        self.sniff_timestamp = "1700000000.0"


def _listener_for(fields_by_call):
    listener = SSDPPassiveListener(interface="lo", timeout=1)
    calls = iter(fields_by_call)

    listener.get_ip_info = lambda pkt: (pkt._src_ip, "239.255.255.250")
    listener.get_flow_id = lambda pkt: "f"
    listener.get_port_info = lambda pkt: (1900, 1900)
    listener.get_stream_id = lambda pkt: 0
    listener.get_mac_info = lambda pkt: ("", "")
    listener._extract_ssdp_fields = lambda pkt: next(calls)
    return listener


def test_later_notify_updates_location_and_byebye_visible():
    src = "10.0.0.50"
    alive = {
        "msg_type": "NOTIFY",
        "server": "Linux/1.0 UPnP/1.0",
        "location": "http://10.0.0.50:80/desc.xml",
        "usn": "uuid:dev-1::rootdevice",
        "nt": "upnp:rootdevice",
        "nts": "ssdp:alive",
    }
    byebye = {
        "msg_type": "NOTIFY",
        "server": "",
        "location": "",
        "usn": "uuid:dev-1::rootdevice",
        "nt": "upnp:rootdevice",
        "nts": "ssdp:byebye",
    }
    listener = _listener_for([alive, byebye])

    listener.process_packet(_FakePacket(src))
    listener.process_packet(_FakePacket(src))

    device = next(iter(listener.discovered_devices.values()))
    assert device.ssdp_data["nts"] == "ssdp:byebye", (
        "byebye ignored -- device record frozen at first packet"
    )
    # location was empty in the byebye; prior non-empty value is retained.
    assert device.ssdp_data["location"] == "http://10.0.0.50:80/desc.xml"


def test_changed_location_is_reflected():
    src = "10.0.0.51"
    first = {"msg_type": "NOTIFY", "location": "http://old/desc.xml", "usn": "uuid:x"}
    second = {"msg_type": "NOTIFY", "location": "http://new/desc.xml", "usn": "uuid:x"}
    listener = _listener_for([first, second])

    listener.process_packet(_FakePacket(src))
    listener.process_packet(_FakePacket(src))

    device = next(iter(listener.discovered_devices.values()))
    assert device.ssdp_data["location"] == "http://new/desc.xml"

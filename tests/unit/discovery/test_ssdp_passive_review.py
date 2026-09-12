"""Regression tests for SSDPPassiveListener device-record updates.

`process_packet` used to only bump `last_seen` once a device key was known, so
the very first packet's headers were frozen for the lifetime of the run. A
device that announced `NOTIFY ssdp:byebye` kept being reported with
`nts == "ssdp:alive"`, and a changed LOCATION was silently dropped.
"""

import threading

import pytest

from tests.service_gate import require_import
from oida.protocols.discovery.ssdp import SSDPPassiveListener

scapy_all = require_import("scapy.all")
Ether = scapy_all.Ether
IP = scapy_all.IP
UDP = scapy_all.UDP
Raw = scapy_all.Raw

SRC_MAC = "aa:bb:cc:dd:ee:ff"
SRC_IP = "10.0.0.9"


@pytest.fixture
def listener():
    obj = SSDPPassiveListener.__new__(SSDPPassiveListener)
    obj.discovered_devices = {}
    obj._lock = threading.Lock()
    return obj


def _notify(nts, location="http://10.0.0.9:80/desc.xml", server="Linux/3.0 UPnP/1.0 Cam/1.0"):
    body = (
        "NOTIFY * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "NT: upnp:rootdevice\r\n"
        f"NTS: {nts}\r\n"
        "USN: uuid:abc::upnp:rootdevice\r\n"
        f"LOCATION: {location}\r\n"
        f"SERVER: {server}\r\n"
        "\r\n"
    ).encode()
    return (
        Ether(src=SRC_MAC)
        / IP(src=SRC_IP, dst="239.255.255.250")
        / UDP(sport=1900, dport=1900)
        / Raw(load=body)
    )


def _record(listener):
    return listener.discovered_devices[SRC_MAC]


def test_byebye_replaces_stale_alive_state(listener):
    listener.process_packet(_notify("ssdp:alive"))
    assert _record(listener).ssdp_data["nts"] == "ssdp:alive"

    listener.process_packet(_notify("ssdp:byebye"))

    assert _record(listener).ssdp_data["nts"] == "ssdp:byebye"


def test_later_notify_updates_changed_location(listener):
    listener.process_packet(_notify("ssdp:alive"))
    listener.process_packet(_notify("ssdp:alive", location="http://10.0.0.9:8080/new.xml"))

    assert _record(listener).ssdp_data["location"] == "http://10.0.0.9:8080/new.xml"


def test_fields_absent_from_a_later_packet_are_retained(listener):
    """A sparse follow-up packet must not blank out what we already learned."""
    listener.process_packet(_notify("ssdp:alive"))

    body = (
        "NOTIFY * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "NT: upnp:rootdevice\r\n"
        "NTS: ssdp:byebye\r\n"
        "USN: uuid:abc::upnp:rootdevice\r\n"
        "\r\n"
    ).encode()
    listener.process_packet(
        Ether(src=SRC_MAC)
        / IP(src=SRC_IP, dst="239.255.255.250")
        / UDP(sport=1900, dport=1900)
        / Raw(load=body)
    )

    data = _record(listener).ssdp_data
    assert data["nts"] == "ssdp:byebye"
    assert data["server"] == "Linux/3.0 UPnP/1.0 Cam/1.0"
    assert data["location"] == "http://10.0.0.9:80/desc.xml"


def test_repeat_packets_do_not_create_duplicate_records(listener):
    listener.process_packet(_notify("ssdp:alive"))
    first_seen = _record(listener).first_seen
    listener.process_packet(_notify("ssdp:alive"))

    assert len(listener.discovered_devices) == 1
    assert _record(listener).first_seen == first_seen


def test_last_seen_still_advances_on_repeat(listener):
    listener.process_packet(_notify("ssdp:alive"))
    listener.process_packet(_notify("ssdp:byebye"))

    record = _record(listener)
    assert record.last_seen >= record.first_seen

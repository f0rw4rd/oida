#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hostile-peer parsing review for the discovery protocol modules.

Every test here feeds a *malformed, truncated or hostile* frame to a real
parse routine in ``src/oida/protocols/discovery/`` and asserts the scanner
degrades gracefully instead of crashing (TypeError/IndexError/struct.error/
ValueError), hanging, or over-allocating.

Each test was written fail-first: it reproduced a concrete defect against the
code as it stood, and only then was the minimal fix applied.
"""

import pytest

pytestmark = [pytest.mark.unit]

scapy_all = pytest.importorskip("scapy.all")
Ether = scapy_all.Ether
ARP = scapy_all.ARP


# ---------------------------------------------------------------------------
# ARP -- ``hwlen``/``plen`` are peer-controlled. Scapy only decodes hwsrc/psrc
# into readable strings when they are 6/4 bytes; for any other length it hands
# back raw ``bytes``. ``normalize_mac()`` assumed ``str`` and blew up on
# ``mac.replace("-", ":")`` with
# ``TypeError: a bytes-like object is required, not 'str'``.
#
# Reachable two ways:
#   * ARPPassiveListener.process_packet() -- any LAN host can emit the frame,
#     it matches the ``arp`` BPF filter.
#   * ARPScanner.scan() -- the ``for sent, received in answered:`` loop sits
#     outside the try/except OSError, so a hostile ARP *reply* takes the whole
#     active scan down.
# ---------------------------------------------------------------------------

# hwtype=0x00bd ptype=0x0800 hwlen=0xff plen=0xff op=2 (is-at), truncated body.
HOSTILE_ARP_FRAME = bytes.fromhex(
    "0180c200000e001122334455"  # Ether dst/src
    "0806"  # ethertype ARP
    "00bd0800ffff0002"  # hwtype, ptype, hwlen=255, plen=255, op=2
    "0011223344550a000005000000000000"  # short body -> hwsrc decoded as bytes
)


def _hostile_arp_packet():
    packet = Ether(HOSTILE_ARP_FRAME)
    # Guard the premise of the test: scapy really does yield bytes here.
    assert isinstance(packet[ARP].hwsrc, (bytes, bytearray))
    return packet


def test_normalize_mac_survives_bytes_hwsrc():
    """normalize_mac() must not raise on a raw-bytes hwsrc from a bad ARP."""
    from oida.protocols.discovery.core import is_valid_mac, normalize_mac

    raw_hwsrc = _hostile_arp_packet()[ARP].hwsrc

    result = normalize_mac(raw_hwsrc)

    assert isinstance(result, str)
    # A 16-byte blob is not a MAC address; it must be rejected, not invented.
    assert not is_valid_mac(result)


def test_arp_passive_listener_survives_bad_hwlen():
    """A hostile ARP frame must not raise out of process_packet()."""
    from oida.protocols.discovery.arp import ARPPassiveListener

    listener = ARPPassiveListener(interface="lo", timeout=1)

    listener.process_packet(_hostile_arp_packet())  # must not raise

    # Graceful degradation: the junk MAC is dropped, not recorded.
    assert listener.discovered_devices == {}


def test_arp_active_scan_survives_bad_hwlen_reply():
    """ARPScanner's answered-loop runs outside try/except; a hostile reply
    with hwlen != 6 must not propagate out of the scan."""
    from oida.protocols.discovery import arp as arp_mod

    scanner = arp_mod.ARPScanner.__new__(arp_mod.ARPScanner)
    scanner.interface = "lo"
    scanner.subnet = "10.0.0.0/30"
    scanner.timeout = 0.1
    scanner.discovered_devices = {}

    received = _hostile_arp_packet()

    # Exercise exactly the per-answer body of ARPScanner.scan().
    ip = received[ARP].psrc
    mac = arp_mod.normalize_mac(received[ARP].hwsrc)  # must not raise
    assert not (arp_mod.is_valid_mac(mac) and ip)
    assert scanner.discovered_devices == {}


def test_normalize_mac_control_well_formed_inputs():
    """Pin the existing behaviour for well-formed input (no semantic change)."""
    from oida.protocols.discovery.core import is_valid_mac, normalize_mac

    assert normalize_mac("00:11:22:33:44:55") == "00:11:22:33:44:55"
    assert normalize_mac("00-11-22-33-44-55") == "00:11:22:33:44:55"
    assert normalize_mac("0011.2233.4455") == "00:11:22:33:44:55"
    assert normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
    assert normalize_mac("") == ""
    assert is_valid_mac("00:11:22:33:44:55")


def test_arp_passive_listener_control_well_formed_reply():
    """A well-formed ARP reply is still recorded exactly as before."""
    from oida.protocols.discovery.arp import ARPPassiveListener

    listener = ARPPassiveListener(interface="lo", timeout=1)
    packet = Ether(
        bytes(
            Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")
            / ARP(op=2, hwsrc="00:11:22:33:44:55", psrc="10.0.0.5", pdst="10.0.0.1")
        )
    )

    listener.process_packet(packet)

    assert "00:11:22:33:44:55" in listener.discovered_devices
    device = listener.discovered_devices["00:11:22:33:44:55"]
    assert device.ip_addresses == ["10.0.0.5"]

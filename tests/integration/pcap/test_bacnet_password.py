"""BACnet cleartext device-management password extraction.

Fixture ``bacnet/oida_bacnet_passwords.pcap`` was captured (tcpdump sidecar)
from the project's real bacnet-stack mock while the oida bacnet client sent a
ReinitializeDevice and a DeviceCommunicationControl request with known
passwords. BACnet sends these passwords in the clear, so a passive capture
recovers them directly (no hash/cracking):

  - ReinitializeDevice        -> OIDA-ReinitPw1
  - DeviceCommunicationControl -> OIDA-DccPw1

tshark dissects the password as an UNNAMED field; the listener recovers it from
the bacapp ``text`` ("Password: UTF-8 '...'") entry.
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


def test_bacnet_passwords_extracted():
    listener, _devices, _result = _run_listener_test(
        "bacnet",
        "BACnetPassiveListener",
        "bacapp",
        "bacnet/oida_bacnet_passwords.pcap",
        min_devices=0,
        min_interactions=0,
    )
    creds = {c["auth_method"]: c["password"] for c in listener.get_credentials_summary()}
    assert creds.get("BACnet/ReinitializeDevice") == "OIDA-ReinitPw1", creds
    assert creds.get("BACnet/DeviceCommunicationControl") == "OIDA-DccPw1", creds
    # Cleartext credentials, not hashes -> not in the hashcat export.
    for c in listener.get_credentials_summary():
        assert c["credential_type"] == "plaintext"

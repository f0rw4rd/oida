"""Regression tests for the DeviceNet CIP service-code table.

Authority: Wireshark's ``epan/dissectors/packet-devicenet.c``::

    static const value_string devicenet_service_code_vals[] = {
        GENERIC_SC_LIST
        { 0x4B, "Open Explicit Message Connection Request" },
        { 0x4C, "Close Connection Request" },
        { 0x4D, "Device Heartbeat Message" },
        { 0x4E, "Device Shutdown Message" },
        { 0, NULL }
    };

where ``GENERIC_SC_LIST`` (packet-cip.h) is 0x01 Get Attributes All ... 0x1C
Group Sync. Responses are flagged by the 0x80 bit on the service byte plus the
general-status field -- there is no "Error Response" service code.

The listener's table instead carried PCCC/Modbus-bridge/CIP-over-EtherNetIP
names (0x4B Execute PCCC, 0x4C Read Modify Write, 0x4D Read Tag, 0x4E Write
Tag, 0x52/0x53 Read/Write Tag Fragmented) plus a fabricated 0x14 "Error
Response", and was off by one at 0x18/0x19 (Nop is 0x17). Because
``DEVICENET_WRITE_SERVICES`` matched on those wrong codes, a Device Shutdown
frame (0x4E) rendered to the operator as "Write Tag [WRITE]" and a real
"Set Member" (0x19) was labelled "Get Member" and escaped the write set.
"""

import pytest

from oida.pcap.devicenet import (
    DEVICENET_SERVICES,
    DEVICENET_WRITE_SERVICES,
)

DISSECTOR_SERVICES = {
    0x01: "Get Attributes All",
    0x02: "Set Attributes All",
    0x03: "Get Attribute List",
    0x04: "Set Attribute List",
    0x05: "Reset",
    0x06: "Start",
    0x07: "Stop",
    0x08: "Create",
    0x09: "Delete",
    0x0A: "Multiple Service Packet",
    0x0D: "Apply Attributes",
    0x0E: "Get Attribute Single",
    0x10: "Set Attribute Single",
    0x11: "Find Next Object Instance",
    0x15: "Restore",
    0x16: "Save",
    0x17: "Nop",
    0x18: "Get Member",
    0x19: "Set Member",
    0x1A: "Insert Member",
    0x1B: "Remove Member",
    0x1C: "Group Sync",
    0x4B: "Open Explicit Message Connection Request",
    0x4C: "Close Connection Request",
    0x4D: "Device Heartbeat Message",
    0x4E: "Device Shutdown Message",
}


def test_service_table_matches_the_dissector():
    assert DEVICENET_SERVICES == DISSECTOR_SERVICES


@pytest.mark.parametrize(
    "code,name",
    [
        (0x4B, "Open Explicit"),
        (0x4C, "Close Connection"),
        (0x4D, "Device Heartbeat"),
        (0x4E, "Device Shutdown"),
        (0x17, "Nop"),
        (0x18, "Get Member"),
        (0x19, "Set Member"),
    ],
)
def test_previously_wrong_codes(code, name):
    assert name.lower() in DEVICENET_SERVICES[code].lower()


def test_no_fabricated_error_response_service():
    """0x14 is unassigned; responses are the 0x80 bit, not a service code."""
    assert DEVICENET_SERVICES.get(0x14) is None


def test_no_pccc_or_tag_service_names():
    """Those belong to CIP-over-EtherNetIP / PCCC / Modbus-bridge tables."""
    names = " ".join(DEVICENET_SERVICES.values()).lower()
    for alien in ("pccc", "read tag", "write tag", "modify write", "error response"):
        assert alien not in names, f"{alien!r} is not a DeviceNet service"


def test_device_shutdown_is_in_the_write_control_set():
    """0x4E is the destructive verb -- it must be flagged, not labelled
    'Write Tag'."""
    assert 0x4E in DEVICENET_WRITE_SERVICES


def test_set_member_is_in_the_write_set():
    assert 0x19 in DEVICENET_WRITE_SERVICES


def test_get_member_and_get_attribute_single_are_not_writes():
    assert 0x18 not in DEVICENET_WRITE_SERVICES
    assert 0x0E not in DEVICENET_WRITE_SERVICES
    assert 0x01 not in DEVICENET_WRITE_SERVICES


def test_write_set_contains_no_phantom_codes():
    assert DEVICENET_WRITE_SERVICES <= set(DEVICENET_SERVICES)

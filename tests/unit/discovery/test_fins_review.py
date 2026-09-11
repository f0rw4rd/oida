"""Regression tests for FINS end-code handling in discovery.fins.FINSScanner.

`_process_response` used to log a nonzero FINS end code and then fall straight
through into the Controller Data Read layout, decoding bytes 14..33 as the model
and 34..53 as the firmware version. Those bytes are only the controller-data
payload on a success reply (end code 0x0000); on an error reply they are echo /
error-detail bytes, so the operator was shown a fabricated model and firmware
string for a device that had actually refused the command.
"""

import threading

import pytest

from oida.protocols.discovery.fins import FINSScanner

# ICF, RSV, GCT, DNA, DA1, DA2, SNA, SA1, SA2, SID
FINS_HEADER = bytes([0xC0, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0A, 0x00, 0x00])
CONTROLLER_DATA_READ = bytes([0x05, 0x01])
PEER = ("10.0.0.20", 9600)
DEVICE_KEY = "ip:10.0.0.20"


def _respond(end_code: bytes, payload: bytes = b""):
    scanner = FINSScanner.__new__(FINSScanner)
    scanner.discovered_devices = {}
    scanner._lock = threading.Lock()
    scanner.subnet = None
    scanner._process_response(FINS_HEADER + CONTROLLER_DATA_READ + end_code + payload, PEER)
    return scanner.discovered_devices.get(DEVICE_KEY)


SUCCESS_PAYLOAD = b"CS1G-CPU44H       \x00\x00" + b"V3.00               "
ERROR_PAYLOAD = b"ILLEGAL-ECHO-DATA!!!" + b"NOT-A-VERSION-AT-ALL"


def test_success_response_yields_model_and_version():
    device = _respond(b"\x00\x00", SUCCESS_PAYLOAD)

    assert device is not None
    assert device.model == "CS1G-CPU44H"
    assert device.fins_data["controller_version"] == "V3.00"
    assert device.fins_data["end_code"] == "0000"


def test_error_response_does_not_invent_a_model():
    """An error reply's trailing bytes must not be decoded as model/version."""
    device = _respond(b"\x04\x01", ERROR_PAYLOAD)

    assert device is not None, "the device is still present, it just refused"
    assert device.model == ""
    assert device.fins_data["controller_model"] == ""
    assert device.fins_data["controller_version"] == ""
    assert "ILLEGAL" not in str(device.fins_data)


def test_error_response_surfaces_the_end_code():
    device = _respond(b"\x04\x01", ERROR_PAYLOAD)

    assert device.fins_data["end_code"] == "0401"


@pytest.mark.parametrize("end_code", [b"\x00\x01", b"\x01\x01", b"\x11\x01", b"\x04\x01"])
def test_any_nonzero_end_code_suppresses_controller_data(end_code):
    device = _respond(end_code, SUCCESS_PAYLOAD)

    assert device.model == ""
    assert device.fins_data["controller_version"] == ""


def test_sub_code_only_error_is_still_an_error():
    """Main code 0 with a nonzero sub code is still a failed command."""
    device = _respond(b"\x00\x01", SUCCESS_PAYLOAD)

    assert device.model == ""
    assert device.fins_data["end_code"] == "0001"


def test_response_too_short_for_an_end_code_is_rejected():
    """A 12-byte reply has no end code; it must not be indexed blindly."""
    scanner = FINSScanner.__new__(FINSScanner)
    scanner.discovered_devices = {}
    scanner._lock = threading.Lock()
    scanner.subnet = None

    scanner._process_response(FINS_HEADER + CONTROLLER_DATA_READ, PEER)

    assert scanner.discovered_devices == {}


def test_success_response_without_controller_payload_is_blank_not_garbage():
    device = _respond(b"\x00\x00")

    assert device is not None
    assert device.model == ""
    assert device.fins_data["end_code"] == "0000"

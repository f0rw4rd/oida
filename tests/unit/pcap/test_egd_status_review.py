"""Regression: EGD production-status decoding must match the real registry.

``EGD_STATUS`` in ``src/oida/pcap/egd.py`` was a 4-entry table whose values
contradict Wireshark's ``egd.stat`` value_string (packet-egd.c):

    code 1  -> code said "resource in use";   real: "No error currently exists"
    code 20 -> code said "producer suspended"; real: 20 is not a registered value
    code 2  -> absent;                         real: "No error, data consumed"

Compounding that, the listener treated *any* status other than "0" as a
producer fault (``if status.strip() not in ("", "0")``), so a producer
reporting the perfectly healthy status 1 or 2 was (a) mislabeled and (b)
escalated via ``logger.warning`` plus a ``STATUS=`` marker in the operator
summary -- a false-positive fault alert on entirely normal EGD traffic.

Authority: ``tshark -G values | grep egd.stat`` (tshark 4.4.15).
"""

import pytest

from oida.pcap.egd import EGD_HEALTHY_STATUS, EGD_STATUS, EGDPassiveListener

# Verbatim from `tshark -G values | grep egd.stat`
TSHARK_EGD_STATUS = {
    "0": "No new status event has occurred",
    "1": "No error currently exists",
    "2": "No error, data consumed",
    "3": "SNTP error",
    "4": "Specification error",
    "6": "Data refresh error",
    "7": "Data refresh period exceeded",
    "10": "IP Layer not currently initialized",
    "12": "Lack of resource error",
    "16": "Name Resolution in progress",
    "18": "Loss of Ethernet Interface error",
    "22": "Ethernet Interface does not support EGD",
    "26": "No Response from Ethernet Interface",
    "28": "Failed to create an exchange.",
    "30": "Configured exchange deleted.",
}


def test_status_table_matches_registry():
    assert EGD_STATUS == TSHARK_EGD_STATUS


def test_no_fabricated_status_20():
    """20 is not a registered egd.stat value."""
    assert "20" not in EGD_STATUS


def test_status_one_is_healthy_not_resource_in_use():
    assert EGD_STATUS["1"] == "No error currently exists"


@pytest.mark.parametrize("code", ["0", "1", "2", ""])
def test_healthy_codes_are_not_faults(code):
    assert not EGDPassiveListener._is_fault_status(code), (
        f"status {code!r} is a healthy EGD condition per the registry "
        "but was escalated as a producer fault"
    )


@pytest.mark.parametrize("code", ["3", "4", "12", "22", "26"])
def test_error_codes_are_faults(code):
    assert EGDPassiveListener._is_fault_status(code)


def test_healthy_set_is_consistent_with_table():
    assert EGD_HEALTHY_STATUS <= set(EGD_STATUS)


def test_healthy_status_does_not_log_warning(monkeypatch):
    """End-to-end through process_packet: status 1 must not warn.

    The listener logs through the project's ics_logger (own handler,
    propagate=False), so pytest's caplog sees nothing -- collect the call
    directly instead, otherwise the assertion would pass vacuously.
    """
    listener = EGDPassiveListener(interface="lo", timeout=1)
    warnings = []
    monkeypatch.setattr(listener.logger, "warning", warnings.append)
    listener.process_packet(_fake_packet(stat="1"))
    assert not warnings, f"healthy status 1 raised a producer-fault warning: {warnings}"
    ix = listener.interactions[0]
    assert ix.details["status_name"] == "No error currently exists"
    assert "STATUS=" not in ix.summary


def test_real_error_status_still_warns(monkeypatch):
    listener = EGDPassiveListener(interface="lo", timeout=1)
    warnings = []
    monkeypatch.setattr(listener.logger, "warning", warnings.append)
    listener.process_packet(_fake_packet(stat="12"))
    assert any("EGD non-zero status" in w for w in warnings), warnings
    assert listener.interactions[0].details["status_name"] == "Lack of resource error"


class _Layer:
    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class _Packet:
    def __init__(self, egd):
        self.egd = egd
        self.ip = _Layer(src="10.11.12.13", dst="10.11.12.255")
        self.udp = _Layer(srcport="18246", dstport="18246", stream="0")
        self.eth = _Layer(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")
        self.transport_layer = "UDP"
        self.highest_layer = "EGD"

    def __contains__(self, item):
        return hasattr(self, str(item).lower())


def _fake_packet(stat):
    return _Packet(
        _Layer(
            pid="10.11.12.13",
            exid="0x00000064",
            rid="1",
            type="1",
            ver="1",
            stat=stat,
            csig="0x0001",
            notime="0x0",
        )
    )

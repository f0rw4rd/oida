"""Regression tests for ADS fuzzer AMS port wiring.

Covers the MEDIUM finding that ``_create_ams_header`` (and several inline AMS
packet blocks) hardcoded the AMS Target_Port=851 / Source_Port=32768 literals
instead of honoring ``target_ams_port`` / ``source_ams_port`` from config.

These tests render the boofuzz Request objects the fuzzer builds and assert the
AMS header carries the operator-selected ports. They fail against the old
hardcoded literals and pass after the fix.
"""

import struct
from unittest.mock import MagicMock

import pytest

# AMS framing offsets (all little-endian):
#   AMS/TCP header: Reserved(2) + Length(4) = 6 bytes
#   AMS header:     Target_NetId(6) + Target_Port(2) + Source_NetId(6) + Source_Port(2) + ...
_TARGET_PORT_OFFSET = 6 + 6
_SOURCE_PORT_OFFSET = 6 + 6 + 2 + 6

# Non-default ports: 350 = SystemService, 40000 = arbitrary client port.
_TARGET_AMS_PORT = 350
_SOURCE_AMS_PORT = 40000


def _build_requests(target_ams_port, source_ams_port):
    """Run _define_protocol with custom AMS ports, capturing connected requests."""
    from oida.fuzz.core.config import FuzzerConfig, ProtocolType
    from oida.fuzz.core.connections.base import MockConnectionFactory
    from oida.fuzz.protocols.ads import ADSFuzzer

    config = FuzzerConfig(
        target_ip="192.0.2.10",
        target_port=48898,
        protocol_type=ProtocolType.TCP,
    )
    config.protocol_options = {
        "target_ams_port": target_ams_port,
        "source_ams_port": source_ams_port,
        # Enable write/auth so every request gets connected and is testable.
        "enable_write": True,
        "enable_auth": True,
    }
    fuzzer = ADSFuzzer(config, connection_factory=MockConnectionFactory())

    captured = {}

    def _connect(request, *args, **kwargs):
        captured[request.name] = request

    session = MagicMock()
    session.connect.side_effect = _connect
    fuzzer._session = session

    fuzzer._define_protocol()
    return captured


@pytest.fixture(scope="module")
def ads_requests():
    return _build_requests(_TARGET_AMS_PORT, _SOURCE_AMS_PORT)


def _ports_of(request):
    data = request.render()
    target = struct.unpack_from("<H", data, _TARGET_PORT_OFFSET)[0]
    source = struct.unpack_from("<H", data, _SOURCE_PORT_OFFSET)[0]
    return target, source


# Requests built via _create_ams_header() — both ports must follow config.
_HELPER_BUILT_REQUESTS = [
    "ADS_READ_DEVICE_INFO",
    "ADS_READ_STATE",
    "ADS_READ",
    "ADS_WRITE",
    "ADS_WRITE_CONTROL",
    "ADS_GET_HANDLE_BY_NAME",
    "ADS_ADD_NOTIFICATION",
    "ADS_SumReadWrite",
    "ADS_State_Auth",
]


@pytest.mark.parametrize("name", _HELPER_BUILT_REQUESTS)
def test_create_ams_header_uses_configured_ports(ads_requests, name):
    """_create_ams_header must emit the configured AMS ports, not 851/32768."""
    assert name in ads_requests, f"{name} not connected"
    target, source = _ports_of(ads_requests[name])
    assert target == _TARGET_AMS_PORT
    assert source == _SOURCE_AMS_PORT


# Inline AMS blocks with a non-fuzzed Target_Port (both ports configurable).
_INLINE_BOTH_PORTS = [
    "ADS_Quick_Coverage",
    "ADS_Oversized_Payload",
    "ADS_NetId_Boundary",
    "ADS_Command_ID_Boundary",
    "ADS_StateFlags_Boundary",
    "ADS_Data_Length_Mismatch",
]


@pytest.mark.parametrize("name", _INLINE_BOTH_PORTS)
def test_inline_blocks_use_configured_ports(ads_requests, name):
    assert name in ads_requests, f"{name} not connected"
    target, source = _ports_of(ads_requests[name])
    assert target == _TARGET_AMS_PORT
    assert source == _SOURCE_AMS_PORT


# Requests that deliberately fuzz/override Target_Port (port enumeration, port
# boundary, route manipulation) — only Source_Port must track config.
_SOURCE_ONLY_REQUESTS = [
    "ADS_Port_Boundary",
    "ADS_Port_Enumeration",
    "ADS_Route_Manipulation",
    "ADS_Route_Auth",
]


@pytest.mark.parametrize("name", _SOURCE_ONLY_REQUESTS)
def test_source_port_uses_config_when_target_is_fuzzed(ads_requests, name):
    assert name in ads_requests, f"{name} not connected"
    _, source = _ports_of(ads_requests[name])
    assert source == _SOURCE_AMS_PORT


def test_defaults_still_851_32768():
    """With no overrides, the helper-built header keeps Beckhoff defaults."""
    requests = _build_requests(851, 32768)
    target, source = _ports_of(requests["ADS_READ_STATE"])
    assert target == 851
    assert source == 32768

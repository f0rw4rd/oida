"""Regression test: PROFINET acyclic (PNIO-CM) request/response direction.

Direction was derived
as ``is_response = error_code is not None`` where
``error_code = self._parse_int(self.get_field(io_layer, ...))``. ``get_field``
returns None for an absent field, but ``_parse_int(None, default=0)`` returns 0,
NOT None -- so ``error_code`` was ALWAYS an int and ``error_code is not None``
was unconditionally True. Every acyclic PNIO packet was classified as a
``response``, inverting controller/device IP+MAC assignment, session ordering
and I&M attribution for genuine Connect/Read/Write *requests*.

The fix (a) tests field *presence* against the raw ``get_field`` value
(``is not None``), so an absent error_code yields direction ``request`` and a
present error_code (even 0) is treated as the response side, and (b) prefers
the authoritative DCE/RPC PDU type (``dcerpc.pkt_type``) when present -- a
status field cannot separate request from response because a successful
response carries ``error_code=0``.

These tests drive _process_io() with lightweight fake packets (no pyshark /
tshark needed).
"""

from oida.pcap.profinet import (
    DCERPC_PKT_TYPE_REQUEST,
    DCERPC_PKT_TYPE_RESPONSE,
    OPNUM_CONNECT,
    PROFINETPassiveListener,
)


class _Layer:
    """Minimal stand-in for a pyshark layer: attribute access only.

    Only the fields explicitly passed exist; absent fields raise AttributeError
    via getattr's default, exactly like a real dissector that did not emit them.
    """

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class _FakePacket:
    def __init__(self, src_ip, dst_ip, src_mac, dst_mac, pn_io_fields, dcerpc_fields=None):
        self.eth = _Layer(src=src_mac, dst=dst_mac)
        self.ip = _Layer(src=src_ip, dst=dst_ip)
        self.pn_io = _Layer(**pn_io_fields)
        if dcerpc_fields is not None:
            self.dcerpc = _Layer(**dcerpc_fields)


CONTROLLER_IP = "10.0.0.5"
DEVICE_IP = "10.0.0.10"
CONTROLLER_MAC = "aa:bb:cc:00:00:01"
DEVICE_MAC = "aa:bb:cc:00:00:02"


def _make_listener():
    return PROFINETPassiveListener(interface="lo", timeout=1)


def test_connect_request_without_error_code_is_a_request():
    """A Connect *request* carries NO error_code field. It must classify as a
    ``request`` (controller=src, device=dst) -- the regression made it a
    ``response`` with the roles inverted."""
    listener = _make_listener()

    # Controller -> device Connect request: opnum present, NO error_code field.
    listener.process_packet(
        _FakePacket(
            src_ip=CONTROLLER_IP,
            dst_ip=DEVICE_IP,
            src_mac=CONTROLLER_MAC,
            dst_mac=DEVICE_MAC,
            pn_io_fields={"opnum": OPNUM_CONNECT},
        )
    )

    ix = listener.interactions[-1]
    assert ix.direction == "request", (
        f"Connect request (no error_code) misclassified as: {ix.direction}"
    )
    assert ix.src_ip == CONTROLLER_IP and ix.dst_ip == DEVICE_IP

    session = next(iter(listener.sessions.values()))
    assert session.controller_ip == CONTROLLER_IP, "controller/device IP inverted on request"
    assert session.device_ip == DEVICE_IP
    assert session.controller_mac == CONTROLLER_MAC
    assert session.device_mac == DEVICE_MAC


def test_connect_response_with_error_code_is_a_response():
    """A Connect *response* (device -> controller) carries the error_code field
    -- even 0 on success. It must classify as a ``response`` with the device as
    src and controller as dst."""
    listener = _make_listener()

    listener.process_packet(
        _FakePacket(
            src_ip=DEVICE_IP,
            dst_ip=CONTROLLER_IP,
            src_mac=DEVICE_MAC,
            dst_mac=CONTROLLER_MAC,
            # Successful response: error_code present but 0.
            pn_io_fields={"opnum": OPNUM_CONNECT, "error_code": 0},
        )
    )

    ix = listener.interactions[-1]
    assert ix.direction == "response", (
        f"Connect response (error_code=0) misclassified as: {ix.direction}"
    )

    session = next(iter(listener.sessions.values()))
    assert session.controller_ip == CONTROLLER_IP
    assert session.device_ip == DEVICE_IP


def test_dcerpc_pkt_type_overrides_error_code_heuristic():
    """When the DCE/RPC PDU type is present it is authoritative: a request PDU
    classifies as a ``request`` even though a (success) error_code=0 field is
    also present, and a response PDU classifies as a ``response``."""
    listener = _make_listener()

    # Request PDU + error_code=0 present -> direction must be request.
    listener.process_packet(
        _FakePacket(
            src_ip=CONTROLLER_IP,
            dst_ip=DEVICE_IP,
            src_mac=CONTROLLER_MAC,
            dst_mac=DEVICE_MAC,
            pn_io_fields={"opnum": OPNUM_CONNECT, "error_code": 0},
            dcerpc_fields={"pkt_type": DCERPC_PKT_TYPE_REQUEST},
        )
    )
    assert listener.interactions[-1].direction == "request"

    # Response PDU + NO error_code field -> direction must be response.
    listener.process_packet(
        _FakePacket(
            src_ip=DEVICE_IP,
            dst_ip=CONTROLLER_IP,
            src_mac=DEVICE_MAC,
            dst_mac=CONTROLLER_MAC,
            pn_io_fields={"opnum": OPNUM_CONNECT},
            dcerpc_fields={"pkt_type": DCERPC_PKT_TYPE_RESPONSE},
        )
    )
    assert listener.interactions[-1].direction == "response"

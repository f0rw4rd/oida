"""Regression test: MongoDB OP_MSG replies must be classified as responses.

CODE_REVIEW finding `src/oida/pcap/mongodb.py:162-184`: direction
detection did ``is_reply = opcode_name == "OP_REPLY"`` and treated everything
else as a request. In MongoDB 3.6+ OP_MSG (2013) carries BOTH client commands
and server responses -- OP_REPLY is largely legacy. A server -> client OP_MSG
response therefore took the non-reply branch; on a non-standard port with the
server not yet in ``_known_servers`` it was recorded as a ``request`` with the
client/server roles swapped (the server registered as a MongoDB Client).

The fix also keys "reply" off a non-zero ``response_to`` for OP_MSG, so an
OP_MSG response is direction ``response`` and the responder is learned as a
server.

These tests drive process_packet() with lightweight fake packets (no pyshark /
tshark needed).
"""

from oida.pcap.mongodb import MongoDBPassiveListener


class _Layer:
    """Minimal stand-in for a pyshark layer: attribute access only."""

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class _FakePacket:
    """Minimal stand-in for a pyshark packet for MongoDB process_packet()."""

    def __init__(self, src_ip, dst_ip, src_port, dst_port, mongo_fields):
        self.ip = _Layer(src=src_ip, dst=dst_ip)
        self.tcp = _Layer(srcport=src_port, dstport=dst_port, stream="0")
        self.mongo = _Layer(**mongo_fields)


def _make_listener():
    return MongoDBPassiveListener(interface="lo", timeout=1)


CLIENT = "10.0.0.5"
SERVER = "10.0.0.10"
# Deliberately non-standard port so the MONGODB_PORTS heuristic cannot rescue
# the direction -- only the response_to-aware reply detection can.
NONSTD_PORT = 51234


def _roles(listener):
    """Return {ip: device_type} for the discovered MongoDB devices."""
    return {
        ip: dev.device_type
        for dev in listener.discovered_devices.values()
        for ip in dev.ip_addresses
    }


def test_opmsg_response_on_nonstandard_port_is_a_response():
    """An OP_MSG server -> client response (non-zero response_to) on a
    non-standard port must be a ``response`` with the responder learned as the
    server -- NOT a ``request`` with the roles swapped."""
    listener = _make_listener()

    # OP_MSG response: server -> client, response_to references the client's
    # request id. Source port is the (non-standard) server port.
    listener.process_packet(
        _FakePacket(
            src_ip=SERVER,
            dst_ip=CLIENT,
            src_port=NONSTD_PORT,
            dst_port=49000,
            mongo_fields={"opcode": 2013, "response_to": 7, "request_id": 8},
        )
    )

    ix = listener.interactions[-1]
    assert ix.details.get("opcode") == "OP_MSG"
    assert ix.direction == "response", (
        f"OP_MSG response on a non-standard port was misclassified: {ix.direction}"
    )

    roles = _roles(listener)
    assert roles.get(SERVER) == "MongoDB Server", (
        f"OP_MSG responder not learned as the server: {roles}"
    )
    assert roles.get(CLIENT) == "MongoDB Client", (
        f"OP_MSG response wrongly attributed the client as the server: {roles}"
    )


def test_opmsg_command_is_a_request():
    """An OP_MSG client command (response_to == 0) stays a ``request``."""
    listener = _make_listener()

    # OP_MSG command: client -> server on the standard port, response_to 0.
    listener.process_packet(
        _FakePacket(
            src_ip=CLIENT,
            dst_ip=SERVER,
            src_port=49000,
            dst_port=27017,
            mongo_fields={"opcode": 2013, "response_to": 0, "request_id": 8},
        )
    )

    ix = listener.interactions[-1]
    assert ix.details.get("opcode") == "OP_MSG"
    assert ix.direction == "request", (
        f"OP_MSG client command misclassified as a response: {ix.direction}"
    )

    roles = _roles(listener)
    assert roles.get(SERVER) == "MongoDB Server", f"server mislabeled: {roles}"
    assert roles.get(CLIENT) == "MongoDB Client", f"client mislabeled: {roles}"

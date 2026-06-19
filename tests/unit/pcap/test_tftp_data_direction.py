"""Regression test: TFTP DATA device attribution must follow the transfer type.

CODE_REVIEW finding `src/oida/pcap/passive/tftp.py:299,383-423`: ``_process_data``
called ``self._track_devices(..., server_is_src=True)`` unconditionally. That is
correct for an RRQ (download), where DATA flows server -> client, but TFTP DATA
also flows client -> server during a WRQ (upload): after the WRQ the uploading
client sends DATA blocks and the server ACKs them. Hardcoding ``server_is_src=True``
registered the uploading *client* as a "TFTP Server" device (and the receiving
server as a "TFTP Client"), inverting both roles on every upload.

The fix learns the server IP from the initial RRQ/WRQ (the request destination is
always the server) and attributes DATA direction by matching the DATA packet's
endpoints against the known server IP, regardless of the ephemeral TID port the
server replies from.

These tests drive process_packet() with lightweight fake packets (no pyshark /
tshark needed) and assert the device roles are correct for both transfer types.
"""

from oida.pcap.passive.tftp import TFTPPassiveListener


class _Layer:
    """Minimal stand-in for a pyshark layer: attribute access only."""

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


class _FakePacket:
    """Minimal stand-in for a pyshark packet for TFTP process_packet()."""

    def __init__(self, src_ip, dst_ip, src_port, dst_port, tftp_fields, src_mac="", dst_mac=""):
        self.ip = _Layer(src=src_ip, dst=dst_ip)
        self.udp = _Layer(srcport=src_port, dstport=dst_port, stream="0")
        self.tftp = _Layer(**tftp_fields)
        if src_mac or dst_mac:
            self.eth = _Layer(src=src_mac, dst=dst_mac)


def _make_listener():
    return TFTPPassiveListener(interface="lo", timeout=1)


CLIENT = "10.0.0.5"
SERVER = "10.0.0.10"


def _roles(listener):
    """Return {ip: device_type} for the discovered TFTP devices."""
    return {
        ip: dev.device_type
        for dev in listener.discovered_devices.values()
        for ip in dev.ip_addresses
    }


def test_wrq_upload_data_attributed_client_to_server():
    """WRQ (upload): client sends DATA. The client must stay the client and the
    server stay the server -- DATA must NOT flip the uploading client into a
    "TFTP Server"."""
    listener = _make_listener()

    # 1. WRQ: client -> server:69 (request to upload).
    listener.process_packet(
        _FakePacket(
            src_ip=CLIENT,
            dst_ip=SERVER,
            src_port=50000,
            dst_port=69,
            tftp_fields={"opcode": 2, "destination_file": "boot.cfg", "type": "octet"},
        )
    )

    # 2. DATA block 1: client -> server, from a new ephemeral TID port on the
    #    server side (server replied with ACK 0 from TID 40000; client now sends
    #    DATA there). DATA source is the CLIENT.
    listener.process_packet(
        _FakePacket(
            src_ip=CLIENT,
            dst_ip=SERVER,
            src_port=50000,
            dst_port=40000,
            tftp_fields={"opcode": 3, "blocknum": 1},
        )
    )

    roles = _roles(listener)
    assert roles.get(SERVER) == "TFTP Server", f"server mislabeled: {roles}"
    assert roles.get(CLIENT) == "TFTP Client", (
        f"upload DATA wrongly attributed the client as the server: {roles}"
    )


def test_rrq_download_data_stays_server_to_client():
    """RRQ (download): server sends DATA. The server must stay the server and the
    client stay the client (the pre-existing correct behaviour)."""
    listener = _make_listener()

    # 1. RRQ: client -> server:69 (request to download).
    listener.process_packet(
        _FakePacket(
            src_ip=CLIENT,
            dst_ip=SERVER,
            src_port=50000,
            dst_port=69,
            tftp_fields={"opcode": 1, "source_file": "image.bin", "type": "octet"},
        )
    )

    # 2. DATA block 1: server -> client, from the server's ephemeral TID port.
    #    DATA source is the SERVER.
    listener.process_packet(
        _FakePacket(
            src_ip=SERVER,
            dst_ip=CLIENT,
            src_port=40000,
            dst_port=50000,
            tftp_fields={"opcode": 3, "blocknum": 1},
        )
    )

    roles = _roles(listener)
    assert roles.get(SERVER) == "TFTP Server", f"download DATA mislabeled server: {roles}"
    assert roles.get(CLIENT) == "TFTP Client", f"download DATA mislabeled client: {roles}"

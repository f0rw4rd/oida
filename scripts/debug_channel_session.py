#!/usr/bin/env python3
"""Debug script to trace channel open and DATA_BLK exchange.

Captures exact packet bytes and field values to identify session error 394.
"""

import socket
import struct
import logging
import time

# Set up logging
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Target
HOST = "172.19.12.10"
PORT = 1105

# Frame constants (ME protocol uses [length 4B BE][payload] without magic)
MAGIC_DATAGRAM = 0xC5


def build_frame(payload: bytes) -> bytes:
    """Build ME transport frame (length prefix)."""
    # ME Frame: length(4B BE) + payload
    return struct.pack(">I", len(payload)) + payload


def parse_frame(data: bytes) -> bytes:
    """Extract payload from ME frame."""
    if len(data) < 4:
        return b""
    length = struct.unpack(">I", data[:4])[0]
    return data[4 : 4 + length]


def build_datagram(
    service_id: int,
    payload: bytes,
    msg_id: int = 1,
    dst_addr: bytes = b"",
    src_addr: bytes = b"",
    hop_count: int = 13,
    addr_type: int = 0,
) -> bytes:
    """Build datagram with given addresses.

    Args:
        service_id: Service ID (e.g., 0x03 for REQ_NETWORK)
        payload: Payload bytes
        msg_id: Message ID
        dst_addr: Destination (sender) address bytes
        src_addr: Source (receiver) address bytes
        hop_count: Hop count (default 13)
        addr_type: Address type (0=FULL, 1=RELATIVE)

    Returns:
        Complete datagram bytes
    """
    # header_len is always 3 (pointing to offset 6 where addresses start)
    # The server uses header_len=3 regardless of address size
    header_len = 3

    # hop_info: hop_count (5 bits), header_len (3 bits)
    hop_info = (hop_count << 3) | (header_len & 0x07)

    # packet_info: priority=1 (2 bits), signal=0, addr_type (1 bit), length_data_block=0
    packet_info = (1 << 6) | (addr_type << 4)

    # lengths: receiver_len (upper nibble), sender_len (lower nibble) - in 2-byte units
    receiver_len = len(src_addr) // 2
    sender_len = len(dst_addr) // 2
    lengths = (receiver_len << 4) | sender_len

    header = bytes([MAGIC_DATAGRAM, hop_info, packet_info, service_id, msg_id & 0xFF, lengths])

    # Address order: sender (dst) first, then receiver (src)
    dg = header + dst_addr + src_addr

    # Pad to 4-byte alignment
    padding_len = (4 - (len(dg) % 4)) % 4
    dg += b"\x00" * padding_len

    return dg + payload


def parse_datagram(data: bytes) -> tuple:
    """Parse datagram and return (header_info, payload)."""
    if len(data) < 6:
        return None, data

    magic = data[0]
    hop_info = data[1]
    packet_info = data[2]
    service_id = data[3]
    msg_id = data[4]
    lengths = data[5]

    hop_count = hop_info >> 3
    header_len = hop_info & 0x07
    receiver_len = lengths >> 4
    sender_len = lengths & 0x0F

    # Calculate header end
    address_start = header_len * 2
    offset = max(6, address_start)

    # Parse addresses
    dst_addr = b""
    src_addr = b""
    if sender_len > 0:
        dst_bytes = sender_len * 2
        dst_addr = data[offset : offset + dst_bytes]
        offset += dst_bytes
    if receiver_len > 0:
        src_bytes = receiver_len * 2
        src_addr = data[offset : offset + src_bytes]
        offset += src_bytes

    # Padding
    total_header = address_start + 2 * (sender_len + receiver_len)
    if total_header & 2:
        offset += 2

    info = {
        "service_id": service_id,
        "msg_id": msg_id,
        "hop_count": hop_count,
        "header_len": header_len,
        "dst_addr": dst_addr.hex() if dst_addr else "",
        "src_addr": src_addr.hex() if src_addr else "",
    }

    return info, data[offset:]


def build_open_channel_req(msg_id: int = None) -> bytes:
    """Build OPEN_CHANNEL_REQ PDU with checksum."""
    import zlib
    import random

    # Use random msg_id if not specified (like pcap does)
    if msg_id is None:
        msg_id = random.randint(0x10000000, 0xFFFFFFFF)

    # 0xC3 00 0201 00000000 msg_id max_send max_recv
    flags = 0x00
    version = 0x0102
    max_send = 0x001F4000  # 2MB
    max_recv = 6

    pdu = struct.pack("<BBHIIII", 0xC3, flags, version, 0, msg_id, max_send, max_recv)

    # Inject checksum at offset 4
    checksum = zlib.crc32(pdu) & 0xFFFFFFFF
    pdu = pdu[:4] + struct.pack("<I", checksum) + pdu[8:]

    return pdu


def parse_open_channel_res(data: bytes) -> dict:
    """Parse OPEN_CHANNEL_RES PDU (28 bytes extended format)."""
    if len(data) < 28:
        logger.warning(f"OPEN_CHANNEL_RES too short: {len(data)} bytes")
        return None

    (
        cmd,
        flags,
        version,
        checksum,
        msg_id,
        reason,
        channel_id,
        recv_buf_size,
        reserved,
        reserved2,
        comm,
    ) = struct.unpack("<BBHIIHHI HHI", data[:28])

    return {
        "cmd": cmd,
        "flags": flags,
        "version": version,
        "checksum": hex(checksum),
        "msg_id": msg_id,
        "reason": reason,
        "channel_id": channel_id,
        "recv_buf_size": recv_buf_size,
        "reserved": reserved,
        "reserved2": reserved2,
        "comm": comm,
    }


def build_data_blk(channel_id: int, comm: int, blk_id: int, ack_id: int, payload: bytes) -> bytes:
    """Build DATA_BLK first packet."""
    import zlib

    # cmd=0x01, flags=0x81 (request + first), channel_id, comm, blk_id, ack_id, remaining_size, checksum
    flags = 0x81  # Request + First
    remaining_size = len(payload)
    checksum = zlib.crc32(payload) & 0xFFFFFFFF

    header = struct.pack(
        "<BBHIIIII", 0x01, flags, channel_id, comm, blk_id, ack_id, remaining_size, checksum
    )

    return header + payload


def build_discovery() -> bytes:
    """Build discovery request matching pcap Frame 672 exactly.

    Pcap bytes: c5 74 40 03 00 10 7f 03 00 00 00 00 02 c2 00 04 [msg_id 4B]
    """
    msg_id = int(time.time()) & 0xFFFFFFFF

    # Copy exact pcap datagram structure (minus msg_id)
    # c5 74 40 03 00 10 7f 03 00 00 00 00 02 c2 00 04
    datagram_header = bytes(
        [
            0xC5,  # magic
            0x74,  # hop_info: hop_count=14, header_len=4
            0x40,  # packet_info: priority=1, addr_type=0
            0x03,  # service_id (REQ_NETWORK)
            0x00,  # msg_id
            0x10,  # lengths: receiver_len=1, sender_len=0
            0x7F,
            0x03,  # receiver address
            0x00,
            0x00,
            0x00,
            0x00,  # padding
            0x02,
            0xC2,  # sub_command (NAME_RESOLVE)
            0x00,
            0x04,  # version
        ]
    )

    # Add msg_id (little-endian)
    return datagram_header + struct.pack("<I", msg_id)


def build_discovery_with_addr(dst_addr: bytes = b"") -> bytes:
    """Build discovery request with destination address."""
    sub_command = 0xC202  # NAME_RESOLVE
    version = 0x0400
    msg_id = int(time.time()) & 0xFFFFFFFF

    payload = struct.pack("<HHI", sub_command, version, msg_id)
    return build_datagram(0x03, payload, msg_id=1, dst_addr=dst_addr)


def build_res_address() -> bytes:
    """Build RES_ADDRESS (service 0x02) response matching pcap Frame 668.

    Pcap shows: c5 0b 50 02 00 01 60 ff [42 bytes payload]
    - hop_info=0x0b: hop_count=1, header_len=3
    - packet_info=0x50: priority=1, addr_type=1 (RELATIVE!)
    - lengths=0x01: sender_len=1 (2 bytes)
    - sender=60 ff (broadcast)
    """
    # Copy exact pcap payload (42 bytes from Frame 668)
    # Note: This contains what looks like memory addresses - may need adjustment
    payload = bytes(
        [
            0x01,
            0x01,
            0x04,
            0x01,
            0x00,
            0x00,
            0x54,
            0x03,
            0xFC,
            0xFF,
            0xFF,
            0xFF,
            0xC0,
            0xF4,
            0x54,
            0x03,
            0x3D,
            0x65,
            0xEE,
            0x00,
            0xD8,
            0xF4,
            0x54,
            0x03,
            0x78,
            0xF4,
            0x54,
            0x03,
            0xCF,
            0xFA,
            0xED,
            0x00,
            0xEF,
            0xBA,
            0x60,
            0x95,
            0x78,
            0xF4,
            0x04,
            0x10,
            0x00,
            0x00,  # total 42 bytes
        ]
    )

    # Build datagram manually with exact pcap format
    # c5 0b 50 02 00 01 60 ff [payload]
    header = bytes(
        [
            0xC5,  # magic
            0x0B,  # hop_info: hop_count=1, header_len=3
            0x50,  # packet_info: priority=1, addr_type=1 (RELATIVE)
            0x02,  # service_id (RES_ADDRESS)
            0x00,  # msg_id
            0x01,  # lengths: sender_len=1 (2 bytes), receiver_len=0
            0x60,
            0xFF,  # sender (broadcast)
        ]
    )

    return header + payload


def build_ack_blk(channel_id: int, comm: int) -> bytes:
    """Build ACK_BLK (0x03) to acknowledge server's ACK."""
    # ACK_BLK: cmd(1), flags(1), channel_id(2), comm(4)
    return struct.pack("<BBHI", 0x03, 0x00, channel_id, comm)


def build_device_info() -> bytes:
    """Build CmpDevice.Info request with BTag payload.

    Per pcap Frame 682, the request includes a 16-byte BTag payload.
    """
    # Protocol ID 0xCD55 (HeaderTagProtocol) - written as "55 CD" on wire in little-endian
    protocol_id = 0xCD55
    header_len = 16
    service_id = 0x01  # CmpDevice
    cmd = 0x01  # Info
    session_id = 0

    # BTag payload from pcap Frame 682 (20 bytes total)
    # Service header content_len=16, but actual payload is 20 bytes (with trailing zeros)
    btag_payload = bytes(
        [
            0x00,
            0x00,
            0x00,
            0x00,  # padding/flags?
            0x01,
            0x8C,
            0x80,
            0x00,  # BTag: tag_id=0x01 with length
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,  # 4 trailing zeros
        ]
    )

    # content_len is 16 in pcap, even though btag_payload is 20 bytes
    # The extra 4 bytes appear to be trailing padding
    content_len = 16

    header = struct.pack(
        "<HHHHII", protocol_id, header_len, service_id, cmd, session_id, content_len
    )

    return header + btag_payload


def recv_frame(sock: socket.socket, timeout: float = 5.0) -> bytes:
    """Receive a complete ME frame."""
    sock.settimeout(timeout)
    # Read length header
    header = sock.recv(4)
    if len(header) < 4:
        return b""
    length = struct.unpack(">I", header)[0]
    if length == 0:
        return header  # Empty frame
    # Read payload
    payload = b""
    remaining = length
    while remaining > 0:
        chunk = sock.recv(min(remaining, 4096))
        if not chunk:
            break
        payload += chunk
        remaining -= len(chunk)
    return header + payload


def main():
    logger.info(f"Connecting to {HOST}:{PORT}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    sock.connect((HOST, PORT))
    logger.info("Connected!")

    server_addr = b""  # Will be learned from responses

    try:
        # Step 0: Send ME init frame (empty) to trigger server response
        logger.info("=== Step 0: Init Frame ===")
        init_frame = b"\x00\x00\x00\x00\x00\x00"  # Empty init frame
        logger.info(f"TX Init: {init_frame.hex()}")
        sock.sendall(init_frame)

        # Receive RES_ADDRESS (service 0x01)
        time.sleep(0.3)
        response = recv_frame(sock)
        logger.info(f"RX: {response.hex()}")

        if response:
            payload = parse_frame(response)
            dg_info, inner = parse_datagram(payload)
            logger.info(f"Datagram: {dg_info}")
            if dg_info and dg_info["src_addr"]:
                server_addr = bytes.fromhex(dg_info["src_addr"])
                logger.info(f"Server address from REQ_ADDRESS: {server_addr.hex()}")

        # Step 0.5: Send RES_ADDRESS TWICE (per pcap frames 668 and 670)
        logger.info("\n=== Step 0.5: Send RES_ADDRESS (x2 per pcap) ===")
        res_addr = build_res_address()
        res_frame = build_frame(res_addr)
        logger.info(f"TX RES_ADDRESS #1 ({len(res_addr)} bytes): {res_frame.hex()}")
        sock.sendall(res_frame)
        time.sleep(0.1)

        # Second RES_ADDRESS (pcap sends two)
        logger.info("TX RES_ADDRESS #2")
        sock.sendall(res_frame)
        time.sleep(0.2)

        # Step 1: Send discovery request (REQ_NETWORK) to get server's full address
        # Per pcap Frame 672, this uses header_len=4 and specific format
        logger.info("\n=== Step 1: Discovery (REQ_NETWORK) ===")
        discovery = build_discovery()
        disc_frame = build_frame(discovery)
        logger.info(f"TX Discovery: {disc_frame.hex()}")
        sock.sendall(disc_frame)

        # Receive device info (Frame 673 equivalent)
        time.sleep(0.5)
        try:
            sock.settimeout(3.0)
            disc_resp = recv_frame(sock)
            logger.info(f"RX Discovery: {disc_resp[:80].hex()}...")
            if disc_resp:
                payload = parse_frame(disc_resp)
                dg_info, inner = parse_datagram(payload)
                logger.info(f"Discovery response datagram: {dg_info}")
                # Extract server's full 6-byte address from response
                if dg_info and dg_info.get("src_addr"):
                    full_server_addr = bytes.fromhex(dg_info["src_addr"])
                    logger.info(f"Server full address: {full_server_addr.hex()}")
                    if len(full_server_addr) == 6:
                        server_addr = full_server_addr  # Use full 6-byte address
        except socket.timeout:
            logger.warning("No discovery response")

        # Step 2: Open Channel
        logger.info("\n=== Step 2: Open Channel ===")
        open_req = build_open_channel_req()  # Uses random msg_id
        logger.info(f"OPEN_CHANNEL_REQ PDU ({len(open_req)} bytes): {open_req.hex()}")

        # Per pcap, ME uses 0x60 prefix for internal addresses
        # Server announced 0x0001, full format: 00 00 60 01 00 05
        # The 60 appears to be a domain/routing prefix (also used in broadcast 60 ff)
        if len(server_addr) == 2:
            # Extract low byte of server address
            server_node = server_addr[1]  # 0x01 from 0x0001
            dst_addr_full = b"\x00\x00\x60" + bytes([server_node]) + b"\x00\x05"
        else:
            dst_addr_full = server_addr
        src_addr_short = b"\x00\x00"  # 2-byte source for client
        logger.info(f"Using dst_addr: {dst_addr_full.hex()}")
        # Datagram msg_id=0 for OPEN_CHANNEL per pcap
        dg_open = build_datagram(
            0x40, open_req, msg_id=0, dst_addr=dst_addr_full, src_addr=src_addr_short, hop_count=14
        )
        frame = build_frame(dg_open)
        logger.info(f"TX OPEN_CHANNEL: {frame.hex()}")
        sock.sendall(frame)

        # Receive response - check multiple times
        sock.settimeout(2.0)
        response = b""
        for _ in range(3):
            try:
                chunk = sock.recv(4096)
                if chunk:
                    response = chunk
                    break
                time.sleep(0.3)
            except socket.timeout:
                pass
        logger.info(f"RX: {response.hex()}")

        payload = parse_frame(response)
        dg_info, inner = parse_datagram(payload)
        logger.info(f"Datagram: {dg_info}")

        if inner and inner[0] == 0x83:  # OPEN_CHANNEL_RES
            res = parse_open_channel_res(inner)
            logger.info(f"OPEN_CHANNEL_RES: {res}")

            if res["reason"] == 0:
                channel_id = res["channel_id"]
                comm = res["comm"]
                logger.info(f"Channel opened! channel_id={hex(channel_id)}, comm={hex(comm)}")

                # Step 3: Send DATA_BLK
                logger.info("\n=== Step 3: Send DATA_BLK ===")

                # Build CmpDevice.Info request
                device_info = build_device_info()
                logger.info(f"Device.Info payload ({len(device_info)} bytes): {device_info.hex()}")

                # Build DATA_BLK - blk_id starts at 0 for first request
                blk_id = 0
                ack_id = 0
                data_blk = build_data_blk(channel_id, comm, blk_id, ack_id, device_info)
                logger.info(f"DATA_BLK PDU ({len(data_blk)} bytes): {data_blk.hex()}")

                # Datagram - use full 6-byte server address from discovery
                # Per pcap Frame 682: hop_count=14, src_addr="\x00\x00" (2-byte client addr)
                dg_data = build_datagram(
                    0x40,
                    data_blk,
                    msg_id=0,
                    dst_addr=dst_addr_full,
                    src_addr=b"\x00\x00",
                    hop_count=14,
                )
                frame = build_frame(dg_data)
                logger.info(f"TX DATA_BLK: {frame.hex()}")
                sock.sendall(frame)

                # Receive response - may get ACK_BLK (0x03) first, then DATA_BLK (0x01)
                sock.settimeout(3.0)
                ack_received = False
                for attempt in range(5):
                    try:
                        response = sock.recv(4096)
                        logger.info(f"RX: {response.hex()}")

                        payload = parse_frame(response)
                        dg_info, inner = parse_datagram(payload)
                        logger.info(f"Datagram: {dg_info}")

                        if inner:
                            cmd = inner[0]
                            logger.info(f"Response PDU type: 0x{cmd:02X}")
                            if cmd == 0x03:  # ACK_BLK
                                # Parse ACK: cmd(1), flags(1), channel_id(2), comm(4)
                                if len(inner) >= 8:
                                    _, flags, ch_id, ack_comm = struct.unpack("<BBHI", inner[:8])
                                    logger.info(
                                        f"ACK_BLK: channel={hex(ch_id)}, comm={hex(ack_comm)}"
                                    )
                                    ack_received = True
                                # Don't send ACK back - just wait for DATA_BLK response
                                continue
                            elif cmd == 0x84:  # CLOSE_CHANNEL_RES
                                if len(inner) >= 12:
                                    _, flags, version, checksum, ch_id, error = struct.unpack(
                                        "<BBHIHH", inner[:12]
                                    )
                                    logger.error(
                                        f"CLOSE_CHANNEL_RES: channel={hex(ch_id)}, error={error} (0x{error:03X})"
                                    )
                                break
                            elif cmd == 0x01 or cmd == 0x81:  # DATA_BLK response
                                logger.info(
                                    f"DATA_BLK response: {inner[:48].hex() if len(inner) >= 48 else inner.hex()}"
                                )
                                # Extract service response after DATA_BLK header (24 bytes)
                                if len(inner) > 24:
                                    service_data = inner[24:]
                                    logger.info(
                                        f"Service data ({len(service_data)} bytes): {service_data[:64].hex() if len(service_data) >= 64 else service_data.hex()}"
                                    )
                                break
                    except socket.timeout:
                        logger.warning(f"Timeout waiting for response (attempt {attempt + 1})")
            else:
                logger.error(f"Channel open rejected: reason={res['reason']}")
        else:
            logger.warning(f"Unexpected response: {inner[:10].hex() if inner else 'empty'}")

    finally:
        sock.close()
        logger.info("Connection closed")


if __name__ == "__main__":
    main()

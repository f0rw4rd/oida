#!/usr/bin/env python3
"""
IEC 61850 GOOSE Layer 2 Publisher - Mock service for testing GOOSE sniffers.

Publishes periodic GOOSE multicast frames (EtherType 0x88B8) on a network interface
using raw sockets. The GOOSE PDU is ASN.1 BER-encoded per IEC 61850-8-1 Annex A.

No external dependencies -- uses only Python stdlib (socket, struct, time).

Environment variables:
    GOOSE_INTERFACE       Network interface to publish on (default: eth0)
    GOOSE_APPID           Application ID, hex or decimal (default: 0x1000)
    GOOSE_GOCB_REF        GoCB reference string (default: simpleIOGenericIO/LLN0$GO$gcb01)
    GOOSE_DATASET_REF     Dataset reference string (default: simpleIOGenericIO/LLN0$dataset1)
    GOOSE_GO_ID           GOOSE ID string (defaults to GOOSE_GOCB_REF)
    GOOSE_CONF_REV        Configuration revision (default: 1)
    GOOSE_INTERVAL        Publish interval in seconds (default: 1.0)
    GOOSE_STATE_INTERVAL  Simulated state-change interval in seconds (default: 10.0)
"""

import logging
import os
import signal
import socket
import struct
import time

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [GOOSE-PUB] %(levelname)s %(message)s",
)
log = logging.getLogger("goose_publisher")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GOOSE_ETHERTYPE = 0x88B8
GOOSE_MULTICAST_DST = b"\x01\x0c\xcd\x01\x00\x00"  # Standard GOOSE multicast MAC


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_interface_mac(interface: str) -> bytes:
    """Return the 6-byte MAC address for *interface*.

    Tries, in order:
      1. Read /sys/class/net/<iface>/address  (Linux sysfs)
      2. scapy's get_if_hwaddr (if available)
      3. Fallback to 02:00:00:00:00:01
    """
    # 1. sysfs
    sysfs_path = f"/sys/class/net/{interface}/address"
    try:
        with open(sysfs_path) as fh:
            mac_str = fh.read().strip()
        if mac_str and mac_str != "00:00:00:00:00:00":
            return bytes.fromhex(mac_str.replace(":", ""))
    except (OSError, ValueError):
        pass

    # 2. scapy (optional)
    try:
        from scapy.all import get_if_hwaddr  # type: ignore[import-untyped]

        mac_str = get_if_hwaddr(interface)
        if mac_str and mac_str != "00:00:00:00:00:00":
            return bytes.fromhex(mac_str.replace(":", ""))
    except Exception:
        pass

    # 3. Locally-administered fallback
    log.warning("Could not determine MAC for %s -- using fallback 02:00:00:00:00:01", interface)
    return b"\x02\x00\x00\x00\x00\x01"


def _ber_tlv(tag: int, value: bytes) -> bytes:
    """Encode a BER TLV (tag-length-value) triple.

    Supports definite-form lengths up to 65535 bytes.
    """
    length = len(value)
    if length < 0x80:
        return bytes([tag, length]) + value
    elif length < 0x100:
        return bytes([tag, 0x81, length]) + value
    else:
        return bytes([tag, 0x82, (length >> 8) & 0xFF, length & 0xFF]) + value


# ---------------------------------------------------------------------------
# GOOSE PDU encoder
# ---------------------------------------------------------------------------


def encode_goose_pdu(
    gocb_ref: str,
    dataset_ref: str,
    go_id: str,
    st_num: int,
    sq_num: int,
    conf_rev: int,
    time_allowed_to_live: int = 2000,
    simulation: bool = False,
    nds_com: bool = False,
) -> bytes:
    """Build an ASN.1 BER-encoded GOOSE PDU per IEC 61850-8-1 Annex A.

    The GOOSE PDU (tag 0x61 = APPLICATION 1) contains:
      [0]  gocbRef              VisibleString
      [1]  timeAllowedToLive    INTEGER
      [2]  datSet               VisibleString
      [3]  goID                 VisibleString (optional, defaults to gocbRef)
      [4]  t                    UtcTime (8 bytes: 4s epoch + 3 fraction + 1 quality)
      [5]  stNum                INTEGER
      [6]  sqNum                INTEGER
      [7]  simulation           BOOLEAN
      [8]  confRev              INTEGER
      [9]  ndsCom               BOOLEAN
      [10] numDatSetEntries     INTEGER
      [11] allData              SEQUENCE (constructed, tag 0xAB)
    """

    fields = []

    # [0] gocbRef -- context tag 0x80 (primitive)
    fields.append(_ber_tlv(0x80, gocb_ref.encode("utf-8")))

    # [1] timeAllowedToLive -- context tag 0x81
    fields.append(_ber_tlv(0x81, _encode_unsigned(time_allowed_to_live)))

    # [2] datSet -- context tag 0x82
    fields.append(_ber_tlv(0x82, dataset_ref.encode("utf-8")))

    # [3] goID -- context tag 0x83
    fields.append(_ber_tlv(0x83, go_id.encode("utf-8")))

    # [4] t (UtcTime) -- context tag 0x84
    #     IEC 61850-8-1: 4 bytes seconds since 1970-01-01, 3 bytes fraction-of-second,
    #     1 byte timeQuality (0x00 = unspecified accuracy)
    now = time.time()
    secs = int(now)
    frac_24 = int((now - secs) * (1 << 24))
    t_bytes = struct.pack(">I", secs) + struct.pack(">I", frac_24)[1:] + b"\x00"
    fields.append(_ber_tlv(0x84, t_bytes))

    # [5] stNum -- context tag 0x85
    fields.append(_ber_tlv(0x85, _encode_unsigned(st_num)))

    # [6] sqNum -- context tag 0x86
    fields.append(_ber_tlv(0x86, _encode_unsigned(sq_num)))

    # [7] simulation -- context tag 0x87
    fields.append(_ber_tlv(0x87, b"\xff" if simulation else b"\x00"))

    # [8] confRev -- context tag 0x88
    fields.append(_ber_tlv(0x88, _encode_unsigned(conf_rev)))

    # [9] ndsCom -- context tag 0x89
    fields.append(_ber_tlv(0x89, b"\xff" if nds_com else b"\x00"))

    # [10] numDatSetEntries -- context tag 0x8A
    num_entries = 4
    fields.append(_ber_tlv(0x8A, _encode_unsigned(num_entries)))

    # [11] allData -- context tag 0xAB (constructed)
    #
    # Four simulated data members matching a typical protection IED dataset:
    #   - BOOLEAN  (XCBR position):  tag 0x83  (Data::boolean)
    #   - INT32    (tap position):   tag 0x85  (Data::integer)
    #   - FLOAT32  (measurement):    tag 0x87  (Data::floating-point, 1-byte exponent-width + 4-byte IEEE 754)
    #   - VisibleString (label):     tag 0x8A  (Data::visible-string)
    #
    # The values are toggled every state change to produce observable variation.
    breaker_open = st_num % 2 == 0
    data_bool = _ber_tlv(0x83, b"\xff" if breaker_open else b"\x00")
    data_int = _ber_tlv(0x85, struct.pack(">i", st_num * 10 + sq_num))
    data_float = _ber_tlv(0x87, b"\x08" + struct.pack(">f", 230.5 + (st_num % 5) * 0.1))
    data_str = _ber_tlv(0x8A, b"OIDA_MOCK_IED")

    all_data_content = data_bool + data_int + data_float + data_str
    fields.append(_ber_tlv(0xAB, all_data_content))

    # Wrap in APPLICATION 1 (tag 0x61, constructed)
    pdu_content = b"".join(fields)
    return _ber_tlv(0x61, pdu_content)


def _encode_unsigned(value: int) -> bytes:
    """Encode an unsigned integer as a minimal-length big-endian byte string.

    BER INTEGER encoding: the value is stored in the minimum number of octets
    with the high bit of the leading octet acting as a sign bit.  For unsigned
    values >= 0x80 we prepend a 0x00 pad byte to keep the value positive.
    """
    if value == 0:
        return b"\x00"
    # Determine minimal byte count
    byte_count = (value.bit_length() + 7) // 8
    raw = value.to_bytes(byte_count, byteorder="big")
    # BER sign-bit rule: if high bit set, prepend 0x00
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return raw


# ---------------------------------------------------------------------------
# Publisher
# ---------------------------------------------------------------------------


class GoosePublisher:
    """Publishes IEC 61850 GOOSE Ethernet frames on a raw socket."""

    def __init__(
        self,
        interface: str = "eth0",
        appid: int = 0x1000,
        gocb_ref: str = "simpleIOGenericIO/LLN0$GO$gcb01",
        dataset_ref: str = "simpleIOGenericIO/LLN0$dataset1",
        go_id: str | None = None,
        conf_rev: int = 1,
    ):
        self.interface = interface
        self.appid = appid
        self.gocb_ref = gocb_ref
        self.dataset_ref = dataset_ref
        self.go_id = go_id or gocb_ref
        self.conf_rev = conf_rev

        self.st_num = 1  # State number (incremented on value change)
        self.sq_num = 0  # Sequence number (incremented every publish, reset on state change)
        self.running = False

        self.src_mac = _get_interface_mac(self.interface)
        self.dst_mac = GOOSE_MULTICAST_DST

    # -----------------------------------------------------------------------

    def _build_frame(self) -> bytes:
        """Assemble a complete GOOSE Ethernet frame (no VLAN tag)."""

        goose_pdu = encode_goose_pdu(
            gocb_ref=self.gocb_ref,
            dataset_ref=self.dataset_ref,
            go_id=self.go_id,
            st_num=self.st_num,
            sq_num=self.sq_num,
            conf_rev=self.conf_rev,
        )

        # GOOSE header (IEC 61850-8-1, clause 8.1):
        #   AppID    (2 bytes)
        #   Length   (2 bytes)  -- from AppID to end of PDU (header + PDU)
        #   Reserved1 (2 bytes, 0x0000)
        #   Reserved2 (2 bytes, 0x0000)
        goose_payload_len = 8 + len(goose_pdu)  # 8 = header size
        goose_header = struct.pack(">HHHH", self.appid, goose_payload_len, 0, 0)

        # Ethernet II frame: dst(6) + src(6) + ethertype(2) + payload
        frame = (
            self.dst_mac
            + self.src_mac
            + struct.pack(">H", GOOSE_ETHERTYPE)
            + goose_header
            + goose_pdu
        )
        return frame

    # -----------------------------------------------------------------------

    def publish_loop(self, interval: float = 1.0, state_change_interval: float = 10.0) -> None:
        """Continuously publish GOOSE frames until stopped."""

        self.running = True
        last_state_change = time.monotonic()

        mac_str = ":".join(f"{b:02x}" for b in self.src_mac)
        dst_str = ":".join(f"{b:02x}" for b in self.dst_mac)
        log.info("Starting GOOSE L2 publisher")
        log.info("  Interface    : %s (src MAC %s)", self.interface, mac_str)
        log.info("  Dst MAC      : %s", dst_str)
        log.info("  AppID        : 0x%04X", self.appid)
        log.info("  GoCB Ref     : %s", self.gocb_ref)
        log.info("  Dataset Ref  : %s", self.dataset_ref)
        log.info("  GoID         : %s", self.go_id)
        log.info("  ConfRev      : %d", self.conf_rev)
        log.info("  Interval     : %.2fs", interval)
        log.info("  State change : every %.1fs", state_change_interval)

        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(GOOSE_ETHERTYPE))
            sock.bind((self.interface, 0))
        except (OSError, PermissionError) as exc:
            log.error("Cannot open raw socket on %s: %s", self.interface, exc)
            log.error("Container must be started with --cap-add=NET_RAW (or --privileged).")
            return

        published = 0
        try:
            while self.running:
                now = time.monotonic()

                # Simulate a state change (e.g. breaker trip)
                if now - last_state_change >= state_change_interval:
                    self.st_num += 1
                    self.sq_num = 0
                    last_state_change = now
                    log.info(
                        "State change -> stNum=%d  (next retransmission burst)",
                        self.st_num,
                    )

                frame = self._build_frame()
                sock.send(frame)
                self.sq_num += 1
                published += 1

                if published % 60 == 0:
                    log.info(
                        "Published %d frames (stNum=%d sqNum=%d)",
                        published,
                        self.st_num,
                        self.sq_num,
                    )

                time.sleep(interval)

        except KeyboardInterrupt:
            log.info("Interrupted by user")
        finally:
            sock.close()
            log.info("Publisher stopped after %d frames", published)

    def stop(self) -> None:
        self.running = False


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    interface = os.environ.get("GOOSE_INTERFACE", "eth0")
    appid = int(os.environ.get("GOOSE_APPID", "0x1000"), 0)
    gocb_ref = os.environ.get("GOOSE_GOCB_REF", "simpleIOGenericIO/LLN0$GO$gcb01")
    dataset_ref = os.environ.get("GOOSE_DATASET_REF", "simpleIOGenericIO/LLN0$dataset1")
    go_id = os.environ.get("GOOSE_GO_ID", gocb_ref)
    conf_rev = int(os.environ.get("GOOSE_CONF_REV", "1"))
    interval = float(os.environ.get("GOOSE_INTERVAL", "1.0"))
    state_interval = float(os.environ.get("GOOSE_STATE_INTERVAL", "10.0"))

    publisher = GoosePublisher(
        interface=interface,
        appid=appid,
        gocb_ref=gocb_ref,
        dataset_ref=dataset_ref,
        go_id=go_id,
        conf_rev=conf_rev,
    )

    signal.signal(signal.SIGTERM, lambda *_: publisher.stop())

    publisher.publish_loop(interval=interval, state_change_interval=state_interval)


if __name__ == "__main__":
    main()

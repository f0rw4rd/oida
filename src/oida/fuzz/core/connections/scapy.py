"""
Scapy-based Raw Socket Connection for Protocol Fuzzing

Provides a clean wrapper around Scapy for sending raw IP packets
with boofuzz-generated payloads. Scapy handles all IP layer complexity
(checksums, fragmentation, routing) while boofuzz handles fuzzing logic.
"""

from oida.utils.ics_logger import get_logger


class ScapyRawConnection:
    """
    Connection class that uses Scapy to send raw IP packets
    with boofuzz-generated TCP payloads.

    Architecture:
        Boofuzz -> Generates TCP bytes -> ScapyRawConnection -> Wraps in IP -> Scapy sends

    Benefits:
        - Scapy handles IP checksums automatically
        - Supports both IPv4 and IPv6
        - No manual header construction
        - Auto-detects source IP and routing
        - Battle-tested Scapy code

    Usage:
        conn = ScapyRawConnection(host="192.168.1.100", port=80)
        conn.open()
        conn.send(tcp_packet_bytes)
        conn.close()
    """

    def __init__(self, host: str, port: int = 0, source_ip: str = None, ipv6: bool = False):
        """
        Initialize Scapy raw connection

        Args:
            host: Target IP address (IPv4 or IPv6)
            port: Target port (for logging/info only)
            source_ip: Source IP address (auto-detected if None)
            ipv6: Use IPv6 instead of IPv4
        """
        self.host = host
        self.port = port
        self.source_ip = source_ip
        self.ipv6 = ipv6
        self._sock = None
        self._scapy_initialized = False
        self._log = get_logger("SCAPY", host, port)

    def _init_scapy(self):
        """Lazy initialization of Scapy (import only when needed)"""
        if self._scapy_initialized:
            return

        try:
            from scapy.all import IP, IPv6, TCP, Raw, send, conf

            self.IP = IP
            self.IPv6 = IPv6
            self.TCP = TCP
            self.Raw = Raw
            self.scapy_send = send  # Renamed to avoid shadowing our send() method
            self.conf = conf

            # Disable Scapy verbosity
            self.conf.verb = 0

            # Auto-detect source IP if not specified
            if self.source_ip is None:
                try:
                    # Get best route to destination
                    route_info = self.conf.route.route(self.host)
                    self.source_ip = route_info[1]  # Source IP
                    self._log.debug(f"Auto-detected source IP: {self.source_ip}")
                except Exception as e:
                    self._log.warning(f"Could not auto-detect source IP: {e}")
                    self.source_ip = "0.0.0.0" if not self.ipv6 else "::"

            self._scapy_initialized = True
            self._log.display(f"Scapy initialized for {self.info}")

        except ImportError as e:
            raise ImportError(
                "Scapy is required for raw socket mode. Install with: pip install oida-ics[fuzz]"
            ) from e

    def open(self):
        """Open the connection (initialize Scapy)"""
        self._init_scapy()
        self._sock = True  # Mark as open
        self._log.debug(f"ScapyRawConnection opened: {self.info}")

    def close(self):
        """Close the connection"""
        self._sock = None
        self._log.debug(f"ScapyRawConnection closed: {self.info}")

    def send(self, data: bytes) -> int:
        """
        Send raw packet wrapped in IP header via Scapy

        Args:
            data: Raw TCP/UDP/ICMP packet bytes from boofuzz

        Returns:
            Number of bytes sent (payload size)

        Raises:
            ConnectionError: If connection not open
        """
        if not self._sock:
            raise ConnectionError("Connection not open")

        if not self._scapy_initialized:
            self._init_scapy()

        try:
            # Parse the boofuzz bytes as a TCP segment so Scapy binds the IP
            # upper-layer protocol number (IPv4 proto=6 / IPv6 nh=6). A bare
            # Raw payload leaves proto=0 (IPv6 nh=59 "No Next Header"), so the
            # target silently drops every packet at IP demux and the fuzzer
            # tests nothing.
            try:
                transport = self.TCP(bytes(data))
                l3 = (
                    self.IPv6(src=self.source_ip, dst=self.host)
                    if self.ipv6
                    else self.IP(src=self.source_ip, dst=self.host)
                )
                self._fix_transport_checksum(transport)
                packet = l3 / transport
            except Exception:
                # A short/garbage mutation may not parse as a TCP header; keep
                # the exact bytes but still set the protocol number so the
                # segment reaches the target's TCP stack.
                if self.ipv6:
                    l3 = self.IPv6(src=self.source_ip, dst=self.host, nh=6)
                else:
                    l3 = self.IP(src=self.source_ip, dst=self.host, proto=6)
                packet = l3 / self.Raw(load=data)

            # Send via Scapy (handles routing, IP checksums, fragmentation)
            self.scapy_send(packet, verbose=False)

            self._log.debug(f"Sent {len(data)} bytes via Scapy to {self.host}")
            return len(data)

        except Exception as e:
            raise ConnectionError(f"Failed to send via Scapy: {e}") from e

    def _fix_transport_checksum(self, transport):
        """Recompute a zero transport checksum before send.

        The fuzzer's default TCP header carries chksum=0. Dissecting raw bytes
        with self.TCP(...) sets chksum to the literal 0 as an *explicit* field
        value, and Scapy only recomputes checksum fields left as None — so a
        dissected 0 ships as 0x0000 on the wire. A zero TCP checksum is INVALID
        for IPv4/IPv6 TCP (unlike UDP-over-IPv4, where 0 legally means "no
        checksum"), so mainstream stacks silently drop the segment at TCP input
        and the default `oida fuzz tcp` campaign reaches the target with zero
        coverage.

        We only null out a *zero* checksum. A mutation that deliberately sets a
        NON-zero bogus checksum is a legitimate fuzz case and must ship as-is;
        setting it to None would let Scapy "correct" it and destroy the test.
        Treat chksum == 0 as "unfuzzed default, recompute"; preserve everything
        else. UDP-over-IPv4's legal zero checksum is intentionally left alone —
        this path only handles TCP.
        """
        chksum = getattr(transport, "chksum", None)
        if chksum == 0:
            transport.chksum = None

    def recv(self, size: int = 65535) -> bytes:
        """
        Receive data (not implemented for raw mode)

        Raw sockets in fuzzing mode typically don't need to receive responses.
        If response analysis is needed, use a separate sniffer.

        Returns:
            Empty bytes
        """
        return b""

    # Compatibility methods for boofuzz interface
    def __enter__(self):
        self.open()
        return self

    def __exit__(self, _exc_type, _exc_val, _exc_tb):
        self.close()

    @property
    def alive(self) -> bool:
        """Check if connection is alive"""
        return self._sock is not None

    @property
    def info(self) -> str:
        """Connection info string for boofuzz logging"""
        proto = "ipv6" if self.ipv6 else "ipv4"
        return f"scapy-{proto}://{self.source_ip}->{self.host}:{self.port}"

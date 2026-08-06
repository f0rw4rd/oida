"""Network connectivity monitors for fuzzing."""

import platform
import socket
import ssl
from typing import Optional


from .base import ProtocolBaseline, ProtocolMonitor
from ...utils.ics_logger import get_logger
from ..core.session.commands import CommandRunner, RealCommandRunner
from ..core.config import FuzzerConfig


class PingMonitor(ProtocolMonitor):
    """
    ICMP ping-based health monitor.

    Uses system ping command to verify target is reachable at network level.
    Supports both Windows and Unix ping syntax.

    Note: This monitor uses subprocess for ping, which doesn't fit the typical
    socket-based ProtocolMonitor pattern, but still benefits from the common
    crash detection and retry logic.

    Args:
        host: Target hostname or IP
        retry_count: Number of retry attempts (default: 3)
        ping_count: Number of pings per attempt (default: 1)
        failure_threshold: Consecutive failures before reporting down (default: 2)
        command_runner: Command execution interface (default: RealCommandRunner)
    """

    def __init__(
        self,
        host,
        retry_count: int = 3,
        ping_count: int = 1,
        failure_threshold: int = 2,
        command_runner: Optional[CommandRunner] = None,
    ):
        # PingMonitor uses port=0 since it's ICMP-based
        super().__init__(
            host=host,
            port=0,
            timeout=2.0,
            check_interval=1,  # Check every test case
            retry_count=retry_count,
            failure_threshold=failure_threshold,
        )

        self.ping_count = str(ping_count)
        self.command_runner = command_runner or RealCommandRunner()

        # Adjust ping command based on OS
        if platform.system().lower() == "windows":
            self.ping_cmd = ["ping", "-n", self.ping_count]
        else:
            self.ping_cmd = ["ping", "-c", self.ping_count]

    def _check_alive_once(self, fuzz_data_logger=None) -> bool:
        """Execute ping command and check result"""
        try:
            cmd = self.ping_cmd + [self.host]
            self.logger.debug(f"Executing: {' '.join(cmd)}")
            response = self.command_runner.run(cmd, capture_output=True, timeout=2)
            if response.returncode == 0:
                self.logger.debug("Ping successful")
                return True
            else:
                self.logger.warning(f"Ping failed (exit code {response.returncode})")
                return False
        except Exception as e:
            self.logger.warning(f"Ping error: {e}")
            if fuzz_data_logger:
                fuzz_data_logger.log_info(f"PingMonitor: Ping error - {str(e)}")
            return False

    def pre_send(self, target=None, fuzz_data_logger=None, session=None):
        """Check with ping before sending"""
        return self._check_alive(fuzz_data_logger)

    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        """Check with ping after sending"""
        return self._check_alive(fuzz_data_logger)


class SocketHealthMonitor(ProtocolMonitor):
    """
    TCP socket connection health monitor.

    Attempts to establish a TCP connection to verify the target port is
    accepting connections. Does not send any protocol-specific data.

    Args:
        host: Target hostname or IP
        port: Target port
        retry_count: Number of retry attempts (default: 3)
        timeout: Connection timeout in seconds (default: 2)
        failure_threshold: Consecutive failures before reporting down (default: 2)
    """

    def __init__(self, host, port, retry_count=3, timeout=2, failure_threshold=2):
        super().__init__(
            host=host,
            port=int(port),
            timeout=float(timeout),
            check_interval=1,  # Check every test case
            retry_count=retry_count,
            failure_threshold=failure_threshold,
        )

    def _check_alive_once(self, fuzz_data_logger=None) -> bool:
        """Attempt TCP connection to target"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            self.logger.debug(f"Attempting TCP connect to {self.host}:{self.port}")
            sock.connect((self.host, self.port))
            self.logger.debug("TCP connection succeeded")
            return True
        except socket.timeout:
            self.logger.warning(f"TCP connect timeout ({self.timeout}s)")
            if fuzz_data_logger:
                fuzz_data_logger.log_info(f"Connection timeout - {self.timeout}s")
            return False
        except socket.error as e:
            self.logger.warning(f"TCP connection failed: {e}")
            if fuzz_data_logger:
                fuzz_data_logger.log_info(f"Connection failed - {e}")
            return False
        finally:
            if sock:
                try:
                    sock.close()
                except (OSError, AttributeError) as e:
                    self.logger.debug(f"Socket close error: {e}")

    def pre_send(self, target=None, fuzz_data_logger=None, session=None):
        """Check socket connectivity before sending"""
        return self._check_alive(fuzz_data_logger)

    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        """Check socket connectivity after sending"""
        return self._check_alive(fuzz_data_logger)


def _ber_len(n: int) -> bytes:
    """Encode a BER definite length (short or long form)."""
    if n < 0x80:
        return bytes([n])
    out = bytearray()
    while n:
        out.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)


def _ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


class SNMPHealthMonitor(ProtocolMonitor):
    """
    UDP SNMP liveness monitor.

    SNMP agents speak UDP/161, so a TCP connect (SocketHealthMonitor) always
    fails against them — that would make preflight abort every real run, or, if
    bypassed, flag every case as a false crash. This monitor instead sends a
    valid SNMP GET for sysDescr.0 (1.3.6.1.2.1.1.1.0) over UDP.

    Liveness decision (tuned to avoid false crashes):
      * any datagram reply           -> alive
      * ConnectionRefused / ICMP port unreachable (the agent socket is gone)
                                     -> down (real crash signal)
      * silent timeout (no reply, no ICMP error) -> treated as alive, since a
        live agent may simply not answer our community/version, and reporting
        it down would manufacture a crash on every case.

    Args:
        host: Target hostname or IP
        port: Target UDP port (default: 161)
        community: SNMP community for the v1/v2c probe (default: "public")
        version: SNMP version byte for the probe (0=v1, 1=v2c; default: 1)
        retry_count: Number of retry attempts (default: 3)
        timeout: Socket timeout in seconds (default: 2)
        failure_threshold: Consecutive failures before reporting down (default: 2)
    """

    def __init__(
        self,
        host,
        port=161,
        community="public",
        version=1,
        retry_count=3,
        timeout=2,
        failure_threshold=2,
    ):
        super().__init__(
            host=host,
            port=int(port),
            timeout=float(timeout),
            check_interval=1,
            retry_count=retry_count,
            failure_threshold=failure_threshold,
        )
        self.community = community
        self.version = int(version)

    def _build_get(self) -> bytes:
        """Build a minimal, valid SNMP GetRequest for sysDescr.0."""
        # OID 1.3.6.1.2.1.1.1.0 — first two arcs (1.3) collapse to 0x2b.
        sysdescr = bytes([0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
        varbind = _ber_tlv(0x30, _ber_tlv(0x06, sysdescr) + _ber_tlv(0x05, b""))
        pdu = _ber_tlv(
            0xA0,  # GetRequest
            _ber_tlv(0x02, b"\x01")  # request-id
            + _ber_tlv(0x02, b"\x00")  # error-status
            + _ber_tlv(0x02, b"\x00")  # error-index
            + _ber_tlv(0x30, varbind),  # varbind list
        )
        return _ber_tlv(
            0x30,
            _ber_tlv(0x02, bytes([self.version & 0xFF]))  # version
            + _ber_tlv(0x04, self.community.encode())  # community
            + pdu,
        )

    def _check_alive_once(self, fuzz_data_logger=None) -> bool:
        """Probe the SNMP agent over UDP."""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            # connect() (not sendto) so the kernel delivers ICMP port-unreachable
            # as ConnectionRefusedError on recv — an unconnected UDP socket
            # silently drops that ICMP error, which would make a crashed agent
            # look merely unresponsive (timeout) and defeat crash detection.
            self.logger.debug(f"Sending SNMP GET(sysDescr.0) to {self.host}:{self.port}/udp")
            sock.connect((self.host, self.port))
            sock.send(self._build_get())
            try:
                response = sock.recv(2048)
                self.logger.debug(f"SNMP agent replied ({len(response)} bytes)")
                return True
            except socket.timeout:
                # No reply and no ICMP error: agent may just not answer this
                # version/community. Treat as alive to avoid false crashes.
                self.logger.debug("SNMP probe timed out (no ICMP error) - treating as alive")
                return True
        except ConnectionRefusedError as e:
            # ICMP port unreachable: the agent socket is gone -> real crash.
            self.logger.warning(f"SNMP UDP port unreachable: {e}")
            if fuzz_data_logger:
                fuzz_data_logger.log_info(f"SNMP UDP port unreachable - {e}")
            return False
        except OSError as e:
            self.logger.warning(f"SNMP probe socket error: {e}")
            if fuzz_data_logger:
                fuzz_data_logger.log_info(f"SNMP probe socket error - {e}")
            return False
        finally:
            if sock:
                try:
                    sock.close()
                except (OSError, AttributeError) as e:
                    self.logger.debug(f"Socket close error: {e}")

    def pre_send(self, target=None, fuzz_data_logger=None, session=None):
        return self._check_alive(fuzz_data_logger)

    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        return self._check_alive(fuzz_data_logger)


class CustomSSLSocketMonitor(ProtocolMonitor):
    """
    SSL/TLS socket health monitor with custom configuration.

    Uses FuzzerConfig for target settings. Performs a TLS handshake without
    certificate verification (suitable for fuzzing self-signed targets).

    Built on ProtocolMonitor so it inherits the shared retry, failure-threshold,
    rate-limiting, and crash-detection logic instead of hand-rolling its own
    health gate (the previous BaseMonitor implementation reset its rate-limit
    timer in pre_send right before checking it in post_send, so the probe almost
    never ran, and it raised BoofuzzFailure on the very first connect blip).

    Args:
        config: FuzzerConfig with target_ip and target_port
    """

    def __init__(self, config: FuzzerConfig):
        super().__init__(
            host=config.target_ip,
            port=config.target_port,
            timeout=2.0,
            check_interval=1,  # Check every test case
        )
        self.fuzzer_config = config
        # Preserve the original "FUZZ-SSL" log tag (the base would derive
        # "FUZZ-CUSTOMSSLSOCKET" from the class name).
        self.logger = get_logger("FUZZ-SSL", config.target_ip, config.target_port)

    def _check_alive_once(self, fuzz_data_logger=None) -> bool:
        """Attempt a TLS handshake to verify the target is accepting connections."""
        sock = None
        secure_sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            secure_sock = context.wrap_socket(sock)

            secure_sock.connect((self.host, self.port))
            self.logger.debug("TLS handshake succeeded")
            return True
        except Exception as e:
            self.logger.warning(f"TLS connect failed: {e}")
            if fuzz_data_logger:
                fuzz_data_logger.log_info(f"CustomSSLSocketMonitor: connect failed - {e}")
            return False
        finally:
            if secure_sock:
                try:
                    secure_sock.close()
                except Exception as e:
                    self.logger.debug(f"secure_sock.close(): {e}")
            elif sock:
                try:
                    sock.close()
                except Exception as e:
                    self.logger.debug(f"sock.close(): {e}")

    def pre_send(self, target=None, fuzz_data_logger=None, session=None):
        """Check TLS connectivity before sending."""
        return self._check_alive(fuzz_data_logger)

    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        """Check TLS connectivity after sending."""
        return self._check_alive(fuzz_data_logger)


# HTTP/2 connection preface (RFC 7540 §3.5) and an empty SETTINGS frame.
# Frame header = length(3) + type(1) + flags(1) + stream_id(4). An empty
# SETTINGS is length 0, type 0x04, flags 0, stream 0.
_H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
_H2_SETTINGS_TYPE = 0x04
_H2_EMPTY_SETTINGS = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"


def _h2_reply_has_settings(data: bytes) -> bool:
    """Scan an HTTP/2 byte stream for a SETTINGS frame (type 0x04).

    Walks the concatenated 9-byte frame headers. A live h2c server's own
    connection preface is a SETTINGS frame sent immediately on connect, so a
    healthy target reliably yields one here.
    """
    offset = 0
    while offset + 9 <= len(data):
        length = int.from_bytes(data[offset : offset + 3], "big")
        ftype = data[offset + 3]
        if ftype == _H2_SETTINGS_TYPE:
            return True
        offset += 9 + length
    return False


class H2CSocketMonitor(ProtocolMonitor):
    """Cleartext HTTP/2 (h2c) preface health monitor.

    Plaintext analogue of :class:`CustomSSLSocketMonitor`. Real h2c targets
    (e.g. nghttp2 in prior-knowledge mode) never perform a TLS handshake, so a
    TLS-based preflight fails with "Target unreachable" against a perfectly
    healthy server. This monitor instead opens a plain TCP socket, sends the
    24-byte HTTP/2 connection preface plus an empty SETTINGS frame, and reads
    the reply.

    Liveness decision (tuned to avoid false crashes):
      * reply contains a SETTINGS frame (type 0x04) -> alive (confirmed h2c;
        a server sends its own SETTINGS as its connection preface)
      * any other non-empty reply (the preface exchange completed without the
        peer resetting or closing) -> alive
      * empty reply / connection closed / RST / refused / timeout -> down
        (real crash signal)

    Args:
        host: Target hostname or IP.
        port: Target TCP port.
        retry_count: Number of retry attempts (default: 3).
        timeout: Connect/recv timeout in seconds (default: 2).
        failure_threshold: Consecutive failures before reporting down (default: 2).
        recv_size: Max bytes to read from the reply (default: 4096).
    """

    def __init__(
        self,
        host,
        port,
        retry_count=3,
        timeout=2,
        failure_threshold=2,
        recv_size=4096,
        **kwargs,
    ):
        super().__init__(
            host=host,
            port=int(port),
            timeout=float(timeout),
            check_interval=1,  # Check every test case
            retry_count=retry_count,
            failure_threshold=failure_threshold,
            **kwargs,
        )
        self.recv_size = recv_size

    def _check_alive_once(self, fuzz_data_logger=None) -> bool:
        """Send the h2c preface + SETTINGS and confirm the target speaks back."""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            self.logger.debug(f"h2c preface probe to {self.host}:{self.port}")
            sock.connect((self.host, self.port))
            sock.sendall(_H2_PREFACE + _H2_EMPTY_SETTINGS)
            response = sock.recv(self.recv_size)
        except (ConnectionResetError, ConnectionRefusedError) as e:
            self.logger.warning(f"h2c preface probe reset/refused: {e}")
            if fuzz_data_logger:
                fuzz_data_logger.log_info(f"H2CSocketMonitor: reset/refused - {e}")
            return False
        except (socket.timeout, socket.error, OSError) as e:
            self.logger.warning(f"h2c preface probe failed: {e}")
            if fuzz_data_logger:
                fuzz_data_logger.log_info(f"H2CSocketMonitor: probe failed - {e}")
            return False
        finally:
            if sock:
                try:
                    sock.close()
                except (OSError, AttributeError) as e:
                    self.logger.debug(f"Socket close error: {e}")

        if not response:
            # Server accepted the TCP connection then closed without a reply:
            # a healthy h2c server always answers with its SETTINGS preface.
            self.logger.warning("h2c preface probe got empty reply (peer closed)")
            if fuzz_data_logger:
                fuzz_data_logger.log_info("H2CSocketMonitor: empty reply (peer closed)")
            return False

        if _h2_reply_has_settings(response):
            self.logger.debug("h2c server SETTINGS frame received - target alive")
            return True

        # Non-empty, non-SETTINGS reply: the preface exchange still completed
        # without a reset/close, so the target is up (may be plain HTTP/1.x).
        self.logger.debug(f"h2c probe got {len(response)}B non-SETTINGS reply - treating as alive")
        return True

    def pre_send(self, target=None, fuzz_data_logger=None, session=None):
        """Check h2c connectivity before sending."""
        return self._check_alive(fuzz_data_logger)

    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        """Check h2c connectivity after sending."""
        return self._check_alive(fuzz_data_logger)


class ValidCaseMonitor(ProtocolMonitor):
    """Protocol-agnostic "valid-case" health probe.

    Borrowed from Defensics' valid-case instrumentation: between fuzz cases, send
    a known-good request and check the target still answers it *correctly*. Unlike
    :class:`SocketHealthMonitor` (which only checks the port still accepts a TCP
    connection), this catches a target that is listening but has stopped servicing
    requests, or whose responses have become corrupted.

    Unlike the per-protocol monitors (ModbusMonitor, IEC104Monitor, ...), this works
    for *any* TCP protocol — including ones with no dedicated monitor — because the
    operator supplies the probe bytes.

    Verdict:
      - no/empty response, or connection refused/timeout -> dead
      - ``expect`` set    -> healthy iff that substring is in the response
                             (use this when responses vary, e.g. embedded timestamps)
      - ``expect`` unset  -> first good response becomes the baseline; later responses
                             must match it exactly (strict, catches corruption)

    Args:
        host: Target host.
        port: Target TCP port.
        probe: Known-good request bytes to send each check.
        expect: Optional substring that must appear in the response. If omitted,
                the monitor uses strict baseline matching.
        timeout: Connect/recv timeout in seconds (default 2.0).
        check_interval: Probe every N test cases (default 10).
        recv_size: Max bytes to read from the response (default 4096).
    """

    def __init__(
        self,
        host,
        port,
        probe: bytes,
        expect: Optional[bytes] = None,
        timeout: float = 2.0,
        check_interval: int = 10,
        recv_size: int = 4096,
        retry_count: int = 2,
        failure_threshold: int = 2,
        **kwargs,
    ):
        super().__init__(
            host=host,
            port=int(port),
            timeout=float(timeout),
            check_interval=check_interval,
            retry_count=retry_count,
            failure_threshold=failure_threshold,
            **kwargs,
        )
        if not probe:
            raise ValueError("ValidCaseMonitor requires a non-empty probe")
        self.probe = bytes(probe)
        self.expect = bytes(expect) if expect else None
        self.recv_size = recv_size

    def _check_alive_once(self, fuzz_data_logger=None) -> bool:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            sock.sendall(self.probe)
            response = sock.recv(self.recv_size)
        except (socket.timeout, socket.error) as e:
            self.logger.warning(f"Valid-case probe failed: {e}")
            if fuzz_data_logger:
                fuzz_data_logger.log_info(f"ValidCaseMonitor: probe failed - {e}")
            return False
        finally:
            if sock:
                try:
                    sock.close()
                except (OSError, AttributeError) as e:
                    self.logger.debug(f"Socket close error: {e}")

        if not response:
            self.logger.warning("Valid-case probe got empty response")
            if fuzz_data_logger:
                fuzz_data_logger.log_info("ValidCaseMonitor: empty response")
            return False

        if self.expect is not None:
            if self.expect in response:
                return True
            self.logger.warning("Valid-case response missing expected marker")
            if fuzz_data_logger:
                fuzz_data_logger.log_info("ValidCaseMonitor: expected marker missing")
            return False

        # Strict baseline mode: first good response defines the baseline.
        if not self.baseline_established:
            self.baseline = ProtocolBaseline(raw_response=response)
            self.baseline_established = True
            self.logger.display(f"Valid-case baseline established ({len(response)} bytes)")
            return True

        if response == self.baseline.raw_response:
            return True
        self.logger.warning(
            f"Valid-case response changed (baseline {len(self.baseline.raw_response)}B, "
            f"got {len(response)}B)"
        )
        if fuzz_data_logger:
            fuzz_data_logger.log_info("ValidCaseMonitor: response differs from baseline")
        return False


__all__ = [
    "PingMonitor",
    "SocketHealthMonitor",
    "CustomSSLSocketMonitor",
    "H2CSocketMonitor",
    "ValidCaseMonitor",
]

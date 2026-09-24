"""Live samplers for the predictable-value oracle.

These collect the observable-but-should-be-random values a target emits, then
hand the raw sequence to :func:`classify_sequence`. Sampling the *target's* TCP
ISN / IP-ID requires reading the SYN-ACK off the wire, which a normal kernel
socket hides -- so this uses scapy raw sockets and therefore needs root (or
CAP_NET_RAW). The analysis half has no such requirement and is tested
independently; this half degrades gracefully (returns None / raises a clear
error) when scapy is missing or the process lacks privilege.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from oida.fuzz.analysis.predictability import SequenceVerdict, classify_sequence
from oida.utils.ics_logger import get_logger


@dataclass
class ISNSampleResult:
    """Both observable sequences captured from a batch of SYN probes.

    A single SYN -> SYN-ACK exchange yields two independent predictable-value
    signals, so one sampling run tests both at once:
      * ``isns``   -- the target's TCP initial sequence numbers (32-bit).
      * ``ip_ids`` -- the IPv4 identification field of its replies (16-bit).
    """

    isns: List[int]
    ip_ids: List[int]

    def analyze(self):
        """Return ``(isn_verdict, ip_id_verdict)`` from :func:`classify_sequence`."""
        return (
            classify_sequence(self.isns, bits=32),
            classify_sequence(self.ip_ids, bits=16),
        )


class ISNSampler:
    """Collect a target's TCP ISNs and IP-IDs by firing repeated SYNs.

    Each probe sends a fresh ``IP()/TCP(flags="S")`` to ``host:port`` from a
    different ephemeral source port and records ``seq`` (the ISN) and ``id``
    (the IP-ID) from the SYN-ACK. RST/no-answer probes are skipped. The
    collected sequences are classified for predictability.

    Args:
        host: Target IP.
        port: Target TCP port (must be open so it answers SYN with SYN-ACK).
        count: Number of SYN probes to send (default 32).
        timeout: Per-probe reply timeout in seconds (default 1.0).
        source_port_base: First ephemeral source port; incremented per probe.
    """

    def __init__(
        self,
        host: str,
        port: int,
        count: int = 32,
        timeout: float = 1.0,
        source_port_base: int = 40000,
    ):
        self.host = host
        self.port = int(port)
        self.count = int(count)
        self.timeout = float(timeout)
        self.source_port_base = int(source_port_base)
        self._log = get_logger("PREDICT", host, port)

    def sample(self) -> Optional[ISNSampleResult]:
        """Fire the SYN probes and collect ISNs/IP-IDs. None if none answered."""
        try:
            from scapy.all import IP, TCP, sr1  # type: ignore
        except Exception as exc:  # pragma: no cover - env-dependent
            raise RuntimeError(
                "ISNSampler needs scapy (pip install scapy) and raw-socket "
                f"privilege (root / CAP_NET_RAW): {exc}"
            ) from exc

        isns: List[int] = []
        ip_ids: List[int] = []
        for i in range(self.count):
            sport = self.source_port_base + (i % 20000)
            syn = IP(dst=self.host) / TCP(sport=sport, dport=self.port, flags="S", seq=0)
            try:
                resp = sr1(syn, timeout=self.timeout, verbose=0)
            except PermissionError as exc:  # pragma: no cover - env-dependent
                raise RuntimeError(
                    "ISNSampler needs raw-socket privilege (root / CAP_NET_RAW)"
                ) from exc
            if resp is None or not resp.haslayer(TCP):
                continue
            tcp = resp.getlayer(TCP)
            # 0x12 == SYN+ACK; anything else (RST=0x14) is not an ISN we can use.
            if tcp.flags & 0x12 != 0x12:
                continue
            isns.append(int(tcp.seq))
            if resp.haslayer(IP):
                ip_ids.append(int(resp.getlayer(IP).id))

        if not isns:
            self._log.warning("No SYN-ACK replies collected; cannot judge predictability")
            return None
        self._log.display(f"Collected {len(isns)} ISNs / {len(ip_ids)} IP-IDs")
        return ISNSampleResult(isns=isns, ip_ids=ip_ids)

    def run(self) -> Optional[dict]:
        """Sample and classify. Returns a report dict, or None if no data.

        The report keys ``isn`` / ``ip_id`` each hold a
        :class:`~oida.fuzz.analysis.predictability.SequenceVerdict`.
        """
        result = self.sample()
        if result is None:
            return None
        isn_verdict, ip_id_verdict = result.analyze()
        self._report(isn_verdict, "TCP ISN")
        self._report(ip_id_verdict, "IPv4 IP-ID")
        return {"isn": isn_verdict, "ip_id": ip_id_verdict}

    def _report(self, verdict: SequenceVerdict, label: str) -> None:
        _report_verdict(self._log, verdict, label)


def _report_verdict(log, verdict: SequenceVerdict, label: str) -> None:
    """Log a predictability verdict at fail/success severity."""
    if verdict.predictable:
        log.fail(
            f"PREDICTABLE {label}: {verdict.pattern.value} [{verdict.severity}] -- {verdict.detail}"
        )
    else:
        log.success(f"{label}: {verdict.pattern.value} -- {verdict.detail}")


@dataclass
class DNSTxidResult:
    """The two predictable-value signals a DNS client/forwarder leaks upstream.

    Observing the queries a target emits (by being the resolver it asks) yields:
      * ``txids``        -- the DNS transaction IDs (16-bit). Predictable TXIDs
                            are the core DNS cache-poisoning primitive.
      * ``source_ports`` -- the UDP source ports of those queries (16-bit).
                            Source-port randomisation is the second entropy
                            source Kaminsky-era poisoning depends on; a fixed or
                            counter source port collapses the guess space.
    """

    txids: List[int]
    source_ports: List[int]

    def analyze(self):
        """Return ``(txid_verdict, source_port_verdict)`` from :func:`classify_sequence`."""
        return (
            classify_sequence(self.txids, bits=16),
            classify_sequence(self.source_ports, bits=16),
        )


class DNSTxidSampler:
    """Observe a DNS client/forwarder's outbound TXIDs + source ports.

    The target must send its queries to us -- i.e. we act as the resolver it is
    configured to use (rogue-resolver mode), or as the authoritative server it
    recurses to. Each received query contributes its transaction ID (first two
    header bytes) and UDP source port; the two sequences are classified for
    predictability with :func:`classify_sequence` at ``bits=16``.

    Collection is dependency-injectable for testability: pass ``observations`` (an
    iterable of ``(txid, source_port)`` tuples, e.g. parsed from a pcap) to
    :meth:`collect` / :meth:`run` and no socket is opened. Omit it to run the live
    UDP listen loop, which binds ``bind_port`` (53 needs root) and answers each
    query with a minimal response so the client keeps asking.

    Args:
        bind_host: Local address to listen on (default all interfaces).
        bind_port: UDP port to listen on (default 53).
        count: Number of queries to observe before classifying (default 32).
        timeout: Overall seconds to wait for the live loop (default 30).
    """

    def __init__(
        self,
        bind_host: str = "0.0.0.0",
        bind_port: int = 53,
        count: int = 32,
        timeout: float = 30.0,
    ):
        self.bind_host = bind_host
        self.bind_port = int(bind_port)
        self.count = int(count)
        self.timeout = float(timeout)
        self._log = get_logger("PREDICT-DNS", bind_host, bind_port)

    def collect(self, observations=None) -> Optional[DNSTxidResult]:
        """Gather ``(txid, source_port)`` pairs. Uses ``observations`` if given,
        else runs the live rogue-resolver loop. None if nothing was collected."""
        if observations is not None:
            txids, ports = [], []
            for txid, sport in observations:
                txids.append(int(txid) & 0xFFFF)
                ports.append(int(sport) & 0xFFFF)
            if not txids:
                return None
            return DNSTxidResult(txids=txids, source_ports=ports)
        return self._collect_live()

    def _collect_live(self) -> Optional[DNSTxidResult]:  # pragma: no cover - needs a live client
        import socket
        import time

        txids: List[int] = []
        ports: List[int] = []
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind((self.bind_host, self.bind_port))
        except PermissionError as exc:
            raise RuntimeError(
                f"DNSTxidSampler needs privilege to bind UDP {self.bind_port} (port 53 = root)"
            ) from exc
        except OSError as exc:
            raise RuntimeError(f"DNSTxidSampler could not bind {self.bind_port}: {exc}") from exc

        sock.settimeout(1.0)
        deadline = time.monotonic() + self.timeout
        try:
            while len(txids) < self.count and time.monotonic() < deadline:
                try:
                    data, addr = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                if len(data) < 2:
                    continue
                txids.append((data[0] << 8) | data[1])
                ports.append(int(addr[1]))
                # Reply with a minimal response (echo the ID, set QR) so the client keeps querying.
                if len(data) >= 12:
                    resp = bytearray(data[:12])
                    resp[2] |= 0x80  # QR=1 (response)
                    try:
                        sock.sendto(bytes(resp), addr)
                    except OSError:
                        pass
        finally:
            sock.close()

        if not txids:
            self._log.warning(
                "No DNS queries observed; cannot judge TXID/source-port predictability"
            )
            return None
        self._log.display(f"Observed {len(txids)} DNS queries")
        return DNSTxidResult(txids=txids, source_ports=ports)

    def run(self, observations=None) -> Optional[dict]:
        """Collect and classify. Returns a report dict, or None if no data.

        The report keys ``txid`` / ``source_port`` each hold a
        :class:`~oida.fuzz.analysis.predictability.SequenceVerdict`.
        """
        result = self.collect(observations)
        if result is None:
            return None
        txid_verdict, port_verdict = result.analyze()
        _report_verdict(self._log, txid_verdict, "DNS TXID")
        _report_verdict(self._log, port_verdict, "DNS query source-port")
        return {"txid": txid_verdict, "source_port": port_verdict}


__all__ = ["ISNSampler", "ISNSampleResult", "DNSTxidSampler", "DNSTxidResult"]

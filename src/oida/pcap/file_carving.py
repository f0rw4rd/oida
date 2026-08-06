"""
File Carving Module for network traffic (PyShark variant).

Extracts files from TCP/UDP streams using header-footer carving:
- JPEG images (FFD8FF ... FFD9)
- PNG images (89504E47 ... 49454E44AE426082)
- GIF images (47494638 ... 003B)
- PDF documents (25504446 ... 2525454F46)
- ZIP archives (504B0304 ... 504B0506)

Based on BruteShark's FileExtractingModule approach.

Uses PyShark (tshark wrapper) for packet dissection. Raw payload bytes
are extracted from PyShark's hex string fields (tcp.payload, data.data,
udp.payload).
"""

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, List, Optional, Set, Tuple

from .pyshark_base import PySharkListenerBase
from ..shared.file_carving_common import (
    ExtractedFile,
    FileCarvingMixin,
    StreamBuffer,
)

import logging

logger = logging.getLogger(__name__)


# Maximum stream buffer size before we stop accumulating
_STREAM_BUFFER_MAX = 100 * 1024 * 1024  # 100 MB

# Only attempt carving after this many new bytes
_CARVE_INTERVAL = 64 * 1024  # 64 KB

# Cap the number of concurrently tracked streams; the least-recently-used one is
# finalized (final carve) and freed when the cap is exceeded so a long capture
# with high connection churn cannot grow self._streams without bound.
_MAX_TRACKED_STREAMS = 4096


@dataclass
class _PendingCarve:
    """A header found in a stream whose footer has not yet arrived.

    ``footer_from`` is a per-header cursor that only advances, so footer bytes
    are never re-scanned; ``dead_footers`` records footer indices whose first
    occurrence was already rejected (size out of range), matching the base
    mixin's "first occurrence only" footer selection.
    """

    file_type: str
    header_pos: int
    content_start: int
    footer_from: int
    dead_footers: Set[int] = field(default_factory=set)


@dataclass
class _CarveStream(StreamBuffer):
    """StreamBuffer plus the incremental-carve cursors used by this listener."""

    scan_offset: int = 0  # bytes already searched for new headers
    pending: List[_PendingCarve] = field(default_factory=list)


# PyShark-specific file signatures (min_size to avoid GIF false positives)
FILE_SIGNATURES = {
    "JPEG": {
        "extension": ".jpg",
        "headers": [bytes.fromhex("FFD8FF")],
        "footers": [bytes.fromhex("FFD9")],
        "max_size": 50 * 1024 * 1024,
    },
    "PNG": {
        "extension": ".png",
        "headers": [bytes.fromhex("89504E470D0A1A0A")],
        "footers": [bytes.fromhex("49454E44AE426082")],
        "max_size": 50 * 1024 * 1024,
    },
    "GIF87a": {
        "extension": ".gif",
        "headers": [bytes.fromhex("474946383761")],
        # GIF trailer is 0x3B; anchor on the block-terminator 0x00 that always
        # precedes it (00 3B) so a bare 0x3B inside pixel/color-table/extension
        # data does not prematurely truncate the carved image.
        "footers": [bytes.fromhex("003B")],
        "max_size": 20 * 1024 * 1024,
        "min_size": 800,
    },
    "GIF89a": {
        "extension": ".gif",
        "headers": [bytes.fromhex("474946383961")],
        # See GIF87a: anchor the trailer on the preceding block terminator.
        "footers": [bytes.fromhex("003B")],
        "max_size": 20 * 1024 * 1024,
        "min_size": 800,
    },
    "PDF": {
        "extension": ".pdf",
        "headers": [bytes.fromhex("255044462D")],
        "footers": [bytes.fromhex("2525454F46")],
        "max_size": 100 * 1024 * 1024,
    },
    "ZIP": {
        "extension": ".zip",
        "headers": [bytes.fromhex("504B0304")],
        "footers": [bytes.fromhex("504B0506")],
        "max_size": 100 * 1024 * 1024,
    },
    "MPEG": {
        "extension": ".mpg",
        "headers": [bytes.fromhex("000001BA"), bytes.fromhex("000001B3")],
        "footers": [bytes.fromhex("000001B9"), bytes.fromhex("000001B7")],
        "max_size": 500 * 1024 * 1024,
    },
}


class FileCarvingListener(FileCarvingMixin, PySharkListenerBase):
    """Passive file carving listener for network traffic (PyShark).

    Extracts files from TCP/UDP streams using header-footer carving.
    """

    PROTOCOL_NAME = "file-carving"
    DISPLAY_FILTER = "data || tcp.payload || udp.payload"
    FILE_SIGNATURES = FILE_SIGNATURES

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
        output_dir: Optional[str] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self._streams: "OrderedDict[Tuple[str, str, str, int, int, str], _CarveStream]" = (
            OrderedDict()
        )
        self.files: List[ExtractedFile] = []
        self.output_dir = output_dir

        # Longest header/footer, used to size the overlap kept between
        # incremental scans so a signature straddling a chunk boundary is not
        # missed.
        all_headers = [h for s in self.FILE_SIGNATURES.values() for h in s["headers"]]
        all_footers = [f for s in self.FILE_SIGNATURES.values() for f in s["footers"]]
        self._max_header_len = max((len(h) for h in all_headers), default=1)
        self._max_footer_len = max((len(f) for f in all_footers), default=1)

    def should_process_packet(self, packet) -> bool:
        """Check if packet has a payload we can extract."""
        return hasattr(packet, "tcp") or hasattr(packet, "udp") or hasattr(packet, "data")

    def process_packet(self, packet) -> None:
        """Process packet and accumulate stream data."""
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        src_mac, dst_mac = self.get_mac_info(packet)
        src_mac = src_mac or ""
        dst_mac = dst_mac or ""

        payload = _extract_payload(packet)
        if not payload:
            return

        if hasattr(packet, "tcp"):
            protocol = "TCP"
        elif hasattr(packet, "udp"):
            protocol = "UDP"
        else:
            # A `data`-only packet (no TCP/UDP layer) passed should_process_packet
            # but has no connection tuple to key a stream on; the payload cannot
            # be attributed to a stream, so it is skipped.
            self.logger.debug(
                "file-carving: %d payload byte(s) from %s -> %s dropped "
                "(no TCP/UDP layer to classify the stream)",
                len(payload),
                src_ip,
                dst_ip,
            )
            return

        # (src_ip, dst_ip, protocol) alone merges every concurrent
        # connection between the same host pair into one buffer -- two
        # simultaneous transfers get their payload bytes interleaved,
        # producing spliced/corrupt carves. Add ports + the tshark
        # tcp.stream/udp.stream index so each connection gets its own
        # buffer.
        src_port, dst_port = self.get_port_info(packet)
        stream_id = self.get_stream_id(packet)
        stream_key = (src_ip, dst_ip, protocol, src_port, dst_port, stream_id)
        stream = self._streams.get(stream_key)
        if stream is None:
            if len(self._streams) >= _MAX_TRACKED_STREAMS:
                self._evict_lru_stream()
            stream = _CarveStream(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                src_mac=src_mac,
                dst_mac=dst_mac,
            )
            self._streams[stream_key] = stream
        else:
            # LRU touch: move to the end so the oldest untouched stream is the
            # eviction candidate.
            self._streams.move_to_end(stream_key)

        # Enforce maximum buffer size
        if not stream.capped:
            if len(stream.data) + len(payload) > _STREAM_BUFFER_MAX:
                self.logger.warning(
                    f"Stream buffer {stream_key} reached "
                    f"{_STREAM_BUFFER_MAX // (1024 * 1024)}MB cap, "
                    f"doing final carve and stopping accumulation"
                )
                stream.data.extend(payload)
                self._try_extract_files(stream, force=True)
                stream.capped = True
                # Free the (up to 100 MB) buffer now that it will never be
                # scanned again; capped streams short-circuit on the next packet.
                self._free_stream(stream)
            else:
                stream.data.extend(payload)
                stream.bytes_since_last_carve += len(payload)

                # Only attempt carving every _CARVE_INTERVAL bytes
                if stream.bytes_since_last_carve >= _CARVE_INTERVAL:
                    self._try_extract_files(stream)
                    stream.bytes_since_last_carve = 0

        # Finalize and evict streams whose connection has closed (FIN/RST) so
        # their buffers are freed promptly instead of lingering until the cap.
        if protocol == "TCP" and self._is_connection_close(packet):
            if not stream.capped:
                self._try_extract_files(stream, force=True)
            self._free_stream(stream)
            self._streams.pop(stream_key, None)

    def _is_connection_close(self, packet) -> bool:
        """True when the TCP packet carries a FIN or RST flag."""
        tcp = getattr(packet, "tcp", None)
        if tcp is None:
            return False
        fin = self.get_field(tcp, "flags_fin", None)
        if fin is None:
            fin = self.get_field(tcp, "flags.fin", None)
        rst = self.get_field(tcp, "flags_reset", None)
        if rst is None:
            rst = self.get_field(tcp, "flags.reset", None)
        return self._parse_bool(fin) or self._parse_bool(rst)

    @staticmethod
    def _free_stream(stream: _CarveStream) -> None:
        """Release a stream's buffered bytes (files are already recorded)."""
        stream.data = bytearray()
        stream.pending = []
        stream.scan_offset = 0

    def _evict_lru_stream(self) -> None:
        """Finalize and drop the least-recently-used stream to bound memory."""
        try:
            key = next(iter(self._streams))
        except StopIteration:
            return
        stream = self._streams.pop(key)
        if not stream.capped:
            self._try_extract_files(stream, force=True)
        self._free_stream(stream)
        self.logger.debug("file-carving: evicted LRU stream %s (tracked-stream cap)", key)

    def _try_extract_files(self, stream: _CarveStream, force: bool = False) -> None:
        """Incremental header/footer carving (linear over the total byte count).

        The base mixin re-copies the whole buffer and restarts every header and
        footer search from offset 0 on each 64 KB carve -- O(n^2) over a large
        transfer plus repeated 100 MB allocations. This override keeps a
        per-stream scan cursor: new headers are searched only in the freshly
        appended tail (minus a header-length overlap for signatures straddling
        the previous boundary), and each pending header advances its own footer
        cursor, so every byte is scanned a bounded number of times.
        """
        data = stream.data  # bytearray: find()/slicing avoid copying the buffer
        n = len(data)

        # 1) Discover new headers in the unscanned tail (with overlap).
        header_from = max(0, stream.scan_offset - self._max_header_len + 1)
        for file_type, sig_info in self.FILE_SIGNATURES.items():
            for header in sig_info["headers"]:
                pos = header_from
                while True:
                    hp = data.find(header, pos, n)
                    if hp == -1:
                        break
                    pos = hp + 1
                    if self._already_extracted(stream, hp):
                        continue
                    if any(p.file_type == file_type and p.header_pos == hp for p in stream.pending):
                        # Re-seen in the overlap region from a previous scan.
                        continue
                    stream.pending.append(
                        _PendingCarve(
                            file_type=file_type,
                            header_pos=hp,
                            content_start=hp + len(header),
                            footer_from=hp + len(header),
                        )
                    )
        stream.scan_offset = n

        # 2) Try to close out pending headers, searching only new footer bytes.
        stream.pending = [
            pend
            for pend in stream.pending
            if not self._resolve_pending(stream, pend, data, n, force)
        ]

    def _resolve_pending(
        self, stream: _CarveStream, pend: _PendingCarve, data: bytearray, n: int, force: bool
    ) -> bool:
        """Search for *pend*'s footer; return True once it is carved or abandoned."""
        sig = self.FILE_SIGNATURES[pend.file_type]
        footers = sig["footers"]
        max_size = sig["max_size"]
        min_size = sig.get("min_size", 100)

        hold = n  # don't advance the cursor past a held (incomplete-EOCD) footer
        for fi, footer in enumerate(footers):
            if fi in pend.dead_footers:
                continue
            fp = data.find(footer, pend.footer_from, n)
            if fp == -1:
                continue
            end_pos = fp + len(footer)
            if pend.file_type == "ZIP":
                eocd_fixed_end = fp + 22
                if eocd_fixed_end > n:
                    if not force:
                        # Fixed EOCD record not fully buffered yet; retry once
                        # more stream data arrives rather than carve a truncated
                        # archive, and keep the cursor before this footer.
                        hold = min(hold, fp)
                        continue
                    eocd_fixed_end = n
                    comment_len = 0
                else:
                    comment_len = int.from_bytes(data[fp + 20 : eocd_fixed_end], "little")
                end_pos = min(eocd_fixed_end + comment_len, n)

            file_size = end_pos - pend.header_pos
            if file_size > max_size or file_size < min_size:
                # Base mixin skips a footer type once its first occurrence is
                # out of range; mark it dead so it is not reconsidered.
                pend.dead_footers.add(fi)
                continue

            file_data = bytes(data[pend.header_pos : end_pos])
            self._record_file(stream, pend.file_type, sig["extension"], file_data)
            stream.extracted_offsets.append((pend.header_pos, end_pos))
            return True

        if len(pend.dead_footers) >= len(footers):
            # No footer type can ever match this header; stop tracking it.
            return True

        # Advance the footer cursor over the bytes just searched, keeping an
        # overlap for a footer straddling the boundary, never past a held footer.
        advance = min(hold, n - self._max_footer_len + 1)
        if advance > pend.footer_from:
            pend.footer_from = advance
        return False


def _extract_payload(packet) -> Optional[bytes]:
    """Extract raw payload bytes from a PyShark packet.

    Tries multiple PyShark fields to find raw data (data.data, tcp.payload,
    udp.payload). In EK mode (use_ek=True, the production pipeline) these
    FT_BYTES fields arrive as ``bytes``; in XML mode they are colon-separated
    hex strings. Both are handled — previously ``str(raw)`` on EK ``bytes``
    produced a non-hex ``b'...'`` repr and every payload was silently dropped.
    """
    raw = None

    if hasattr(packet, "data"):
        raw = getattr(packet.data, "data", None) or None

    if raw is None and hasattr(packet, "tcp"):
        raw = getattr(packet.tcp, "payload", None) or None

    if raw is None and hasattr(packet, "udp"):
        raw = getattr(packet.udp, "payload", None) or None

    if raw is None:
        return None

    # EK mode: already bytes -- use directly.
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)

    # XML mode: colon/space-separated hex string.
    try:
        cleaned = str(raw).replace(":", "").replace(" ", "")
        if not cleaned:
            return None
        return bytes.fromhex(cleaned)
    except ValueError as e:
        logger.debug(f"Failed to get cleaned: {e}")
        return None

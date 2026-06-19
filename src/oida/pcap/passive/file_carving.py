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

from typing import Any, Dict, List, Optional, Tuple

from .pyshark_base import PySharkListenerBase
from ...shared.file_carving_common import (
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
        self._streams: Dict[Tuple[str, str, str], StreamBuffer] = {}
        self.files: List[ExtractedFile] = []
        self.output_dir = output_dir

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
            return

        stream_key = (src_ip, dst_ip, protocol)
        if stream_key not in self._streams:
            self._streams[stream_key] = StreamBuffer(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                src_mac=src_mac,
                dst_mac=dst_mac,
            )

        stream = self._streams[stream_key]

        # Enforce maximum buffer size
        if stream.capped:
            return
        if len(stream.data) + len(payload) > _STREAM_BUFFER_MAX:
            self.logger.warning(
                f"Stream buffer {stream_key} reached {_STREAM_BUFFER_MAX // (1024 * 1024)}MB cap, "
                f"doing final carve and stopping accumulation"
            )
            stream.data.extend(payload)
            self._try_extract_files(stream, force=True)
            stream.capped = True
            return

        stream.data.extend(payload)
        stream.bytes_since_last_carve += len(payload)

        # Only attempt carving every _CARVE_INTERVAL bytes
        if stream.bytes_since_last_carve >= _CARVE_INTERVAL:
            self._try_extract_files(stream)
            stream.bytes_since_last_carve = 0


def _extract_payload(packet) -> Optional[bytes]:
    """Extract raw payload bytes from a PyShark packet.

    Tries multiple PyShark fields to find raw data:
    1. data.data - Generic data layer (colon-separated hex string)
    2. tcp.payload - TCP payload (colon-separated hex string)
    3. udp.payload - UDP payload (colon-separated hex string)
    """
    hex_str = None

    if hasattr(packet, "data"):
        raw = getattr(packet.data, "data", None)
        if raw:
            hex_str = str(raw)

    if hex_str is None and hasattr(packet, "tcp"):
        raw = getattr(packet.tcp, "payload", None)
        if raw:
            hex_str = str(raw)

    if hex_str is None and hasattr(packet, "udp"):
        raw = getattr(packet.udp, "payload", None)
        if raw:
            hex_str = str(raw)

    if not hex_str:
        return None

    try:
        cleaned = hex_str.replace(":", "").replace(" ", "")
        if not cleaned:
            return None
        return bytes.fromhex(cleaned)
    except ValueError as e:
        logger.debug(f"Failed to get cleaned: {e}")
        return None

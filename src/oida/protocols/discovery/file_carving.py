"""
File Carving Module for network traffic (Scapy variant).

Extracts files from TCP/UDP streams using header-footer carving:
- JPEG images (FFD8FF ... FFD9)
- PNG images (89504E47 ... 49454E44AE426082)
- GIF images (47494638 ... 003B)
- PDF documents (25504446 ... 2525454F46)
- ZIP archives (504B0304 ... 504B0506)

Based on BruteShark's FileExtractingModule approach.
"""

from typing import Any, Dict, List, Optional, Tuple

from oida.protocols.discovery.base import PassiveListenerBase
from oida.shared.file_carving_common import ExtractedFile, FileCarvingMixin, StreamBuffer
from oida.utils.ics_logger import get_module_logger
from oida.utils.lazy_import import lazy_import

_scapy_all = lazy_import("scapy.all", "discovery")

logger = get_module_logger(__name__)

# Maximum stream buffer size before we stop accumulating
_STREAM_BUFFER_MAX = 100 * 1024 * 1024  # 100 MB

# Scapy/discovery-specific signatures (different GIF footers, no min_size, extra PNG footer)
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
        # Only the IEND chunk terminates a PNG. A second "alternate" footer
        # (b"PNG\xff\xfc\xfd\xfe") used to be listed here; it is not a PNG
        # marker at all, so it could only ever truncate an image at a random
        # byte run that happened to match.
        "footers": [bytes.fromhex("49454E44AE426082")],
        "max_size": 50 * 1024 * 1024,
    },
    "GIF87a": {
        "extension": ".gif",
        "headers": [bytes.fromhex("474946383761")],
        # Block terminator 0x00 + trailer 0x3B, so a bare 0x3B inside pixel or
        # color-table data does not truncate the image.
        "footers": [bytes.fromhex("003B")],
        "max_size": 20 * 1024 * 1024,
        "min_size": 800,
    },
    "GIF89a": {
        "extension": ".gif",
        "headers": [bytes.fromhex("474946383961")],
        # Was "00003B", which demands a second zero byte that a conformant GIF
        # does not have -- no GIF89a was ever carved on this path.
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


class FileCarvingListener(FileCarvingMixin, PassiveListenerBase):
    """Passive file carving listener for network traffic (Scapy).

    Extracts files from TCP/UDP streams using header-footer carving.
    """

    PROTOCOL_NAME = "file-carving"
    BPF_FILTER = "tcp or udp"
    FILE_SIGNATURES = FILE_SIGNATURES

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
        output_dir: Optional[str] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        # PassiveListenerBase only sets self.nxc_logger; FileCarvingMixin needs
        # self.logger for _record_file/_save_file. Fall back to the module logger.
        self.logger = nxc_logger or logger
        self._streams: Dict[Tuple[str, str, str], StreamBuffer] = {}
        self.files: List[ExtractedFile] = []
        self.output_dir = output_dir

    def process_packet(self, packet) -> None:
        """Process packet and accumulate stream data."""
        if not _scapy_all.is_available:
            return
        scapy = _scapy_all()
        IP, TCP, UDP, Raw, Ether = scapy.IP, scapy.TCP, scapy.UDP, scapy.Raw, scapy.Ether

        if IP not in packet or Raw not in packet:
            return

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        src_mac = ""
        dst_mac = ""
        if Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst

        payload = bytes(packet[Raw].load)
        if not payload:
            return

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
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

        # Enforce maximum buffer size to bound memory and the O(n^2) re-scan.
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
        self._try_extract_files(stream)

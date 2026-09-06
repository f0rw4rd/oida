"""Regression tests for GIF trailer carving in pcap.file_carving.

The GIF trailer is a bare 0x3B byte. A naive footer of b"\\x3B" truncates a
carved GIF at the first 0x3B-valued byte inside pixel/color-table/extension
data. The fix anchors the trailer on the block-terminator 0x00 that always
precedes it (00 3B), matching the scapy discovery variant.
"""

import logging
import threading

from oida.pcap.file_carving import FILE_SIGNATURES
from oida.shared.file_carving_common import FileCarvingMixin, StreamBuffer


class _Carver(FileCarvingMixin):
    """Minimal harness exercising the shared carve loop with pcap signatures."""

    FILE_SIGNATURES = FILE_SIGNATURES

    def __init__(self):
        self.files = []
        self.output_dir = None
        self.logger = logging.getLogger("test-carver")
        self._lock = threading.Lock()
        self.discovered_devices = {}


def _build_gif(version: bytes) -> bytes:
    """Build a minimal GIF89a/87a containing inner 0x3B bytes before the trailer.

    Returns (full_gif_bytes). The body deliberately includes bare 0x3B bytes
    (which a naive carver would truncate on) and the canonical 00 3B trailer.
    """
    header = b"GIF" + version  # e.g. b"89a"
    # Body padded to clear the 800-byte min_size, with bare 0x3B bytes
    # sprinkled inside the data. Crucially the 00 3B two-byte sequence must
    # NOT appear in the body (so the fixed footer is unambiguous): each 0x3B
    # here is preceded by 0xFF, never 0x00.
    body = b"\xff\x3b" * 500  # 1000 bytes, contains 500 bare inner 0x3B
    # Canonical end of GIF: block terminator 0x00 followed by trailer 0x3B.
    trailer = b"\x00\x3b"
    return header + body + trailer


def test_gif89a_full_recovery_with_inner_3b():
    gif = _build_gif(b"89a")
    # Sanity: an inner bare 0x3B occurs well before the real end.
    assert gif.index(b"\x3b") < len(gif) - 2

    carver = _Carver()
    stream = StreamBuffer(src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol="TCP")
    stream.data.extend(gif)
    carver._try_extract_files(stream, force=True)

    assert len(carver.files) == 1
    carved = carver.files[0]
    assert carved.file_type == "GIF89a"
    # The carved file must reach the real trailer, not be truncated at an
    # inner 0x3B. With the buggy bare-0x3B footer this would be far shorter.
    assert carved.data == gif
    assert carved.data.endswith(b"\x00\x3b")


def test_gif87a_full_recovery_with_inner_3b():
    gif = _build_gif(b"87a")
    carver = _Carver()
    stream = StreamBuffer(src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol="TCP")
    stream.data.extend(gif)
    carver._try_extract_files(stream, force=True)

    assert len(carver.files) == 1
    assert carver.files[0].file_type == "GIF87a"
    assert carver.files[0].data == gif

"""Regression tests for the scapy discovery FILE_SIGNATURES table.

Two carvers share one carve loop (``FileCarvingMixin``) but keep separate
signature tables. The discovery table had drifted from the pcap one:

* GIF89a's footer was ``00 00 3B`` -- a conformant GIF ends with the single
  block terminator ``00`` followed by the trailer ``3B``, so no GIF89a (by far
  the common version) was ever carved on this path.
* PNG carried a second "alternate" footer ``b"PNG\\xff\\xfc\\xfd\\xfe"`` which
  is not a PNG marker; it could only truncate an image at a chance byte run.
* The GIF entries had no ``min_size``, so they fell back to the shared default
  of 100 bytes instead of the 800-byte false-positive guard used by pcap.

These tests pin the behaviour and keep the two tables in step.
"""

import logging
import threading

import pytest

from oida.pcap.file_carving import FILE_SIGNATURES as PCAP_SIGNATURES
from oida.protocols.discovery.file_carving import FILE_SIGNATURES as DISCOVERY_SIGNATURES
from oida.shared.file_carving_common import FileCarvingMixin, StreamBuffer


class _Carver(FileCarvingMixin):
    """Minimal harness exercising the shared carve loop with a given table."""

    def __init__(self, signatures):
        self.FILE_SIGNATURES = signatures
        self.files = []
        self.output_dir = None
        self.logger = logging.getLogger("test-carver")
        self._lock = threading.Lock()
        self.discovered_devices = {}


def _carve(signatures, blob):
    carver = _Carver(signatures)
    stream = StreamBuffer(src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol="TCP")
    stream.data.extend(blob)
    carver._try_extract_files(stream, force=True)
    return carver.files


def _build_gif(version: bytes) -> bytes:
    """A minimal GIF with inner bare 0x3B bytes and the canonical 00 3B end."""
    return b"GIF" + version + b"\xff\x3b" * 500 + b"\x00\x3b"


def _build_png() -> bytes:
    return b"\x89PNG\r\n\x1a\n" + b"\x41" * 1000 + bytes.fromhex("49454E44AE426082")


@pytest.mark.parametrize("version,file_type", [(b"87a", "GIF87a"), (b"89a", "GIF89a")])
def test_discovery_carves_both_gif_versions(version, file_type):
    """GIF89a used to be silently unrecoverable on the discovery path."""
    gif = _build_gif(version)
    files = _carve(DISCOVERY_SIGNATURES, gif)

    assert len(files) == 1, f"{file_type} was not carved"
    assert files[0].file_type == file_type
    # Not truncated at an inner bare 0x3B.
    assert files[0].data == gif


def test_discovery_carves_png_to_iend():
    png = _build_png()
    files = _carve(DISCOVERY_SIGNATURES, png)

    assert len(files) == 1
    assert files[0].file_type == "PNG"
    assert files[0].data == png


def test_png_footers_are_only_iend():
    """A non-marker "alternate" footer can only truncate images."""
    for table in (DISCOVERY_SIGNATURES, PCAP_SIGNATURES):
        assert table["PNG"]["footers"] == [bytes.fromhex("49454E44AE426082")]


@pytest.mark.parametrize("file_type", sorted(PCAP_SIGNATURES))
def test_signature_tables_agree(file_type):
    """The two carvers must not drift apart again."""
    assert file_type in DISCOVERY_SIGNATURES
    pcap = PCAP_SIGNATURES[file_type]
    disc = DISCOVERY_SIGNATURES[file_type]
    for key in ("extension", "headers", "footers", "max_size"):
        assert disc[key] == pcap[key], f"{file_type}.{key} differs between carvers"
    assert disc.get("min_size", 100) == pcap.get("min_size", 100)


@pytest.mark.parametrize(
    "table_name,table", [("pcap", PCAP_SIGNATURES), ("discovery", DISCOVERY_SIGNATURES)]
)
def test_signature_sizes_are_carvable(table_name, table):
    """min_size must leave room for a carve; footers must fit inside max_size."""
    for file_type, sig in table.items():
        min_size = sig.get("min_size", 100)
        assert min_size < sig["max_size"], f"{table_name}/{file_type}: min_size >= max_size"
        smallest = min(len(h) for h in sig["headers"]) + min(len(f) for f in sig["footers"])
        assert smallest <= min_size, f"{table_name}/{file_type}: header+footer exceeds min_size"

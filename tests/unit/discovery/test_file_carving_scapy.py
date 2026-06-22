"""Regression tests for the scapy discovery file-carving listener.

Covers two bugs in src/oida/protocols/discovery/file_carving.py:

1. FileCarvingListener inherits self.nxc_logger (not self.logger) from
   PassiveListenerBase, but FileCarvingMixin._record_file/_save_file call
   self.logger.*. Before the fix, every successful carve raised
   AttributeError (swallowed by _safe_process_packet), so no file was ever
   recorded. The first test feeds a complete JPEG and asserts a file IS
   recorded.

2. process_packet accumulated stream.data without a size cap, causing
   unbounded memory growth + O(n^2) re-scan. The second test asserts the
   _STREAM_BUFFER_MAX cap fires and stops further accumulation.

These drive the real listener via feed_packet() with constructed scapy
packets -- no pcap fixture needed.
"""

import pytest

from oida.protocols.discovery.file_carving import (
    _STREAM_BUFFER_MAX,
    FileCarvingListener,
)

scapy_all = pytest.importorskip("scapy.all")
IP = scapy_all.IP
TCP = scapy_all.TCP
Ether = scapy_all.Ether
Raw = scapy_all.Raw


def _jpeg_packet(payload: bytes):
    return (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=1234, dport=80)
        / Raw(load=payload)
    )


def test_complete_jpeg_is_recorded_without_logger_crash(tmp_path):
    """A header+footer JPEG must be fully carved without the missing-logger crash.

    _record_file appends to self.files BEFORE calling self.logger.info(), so a
    missing self.logger raises AttributeError *after* the append but *before*
    _update_devices() and _save_file() run. _safe_process_packet swallows that
    exception, so the observable symptom is: file is in self.files, but the
    device map was never updated and the file was never written to disk.

    Asserting on discovered_devices and the saved file therefore fails before
    the fix and passes after it.
    """
    # Minimal valid-looking JPEG: FFD8FF header ... FFD9 footer, padded over the
    # 100-byte default min_size.
    jpeg = bytes.fromhex("FFD8FF") + b"\x00" * 200 + bytes.fromhex("FFD9")

    output_dir = tmp_path / "carved"
    listener = FileCarvingListener(interface="lo", timeout=1, output_dir=str(output_dir))
    listener.feed_packet(_jpeg_packet(jpeg))

    assert len(listener.files) == 1
    carved = listener.files[0]
    assert carved.file_type == "JPEG"
    assert carved.data == jpeg

    # These only happen if _record_file ran past the self.logger.info() call.
    assert listener.discovered_devices, "device map not updated -- logger crash swallowed"
    saved = list(output_dir.glob(f"*{carved.extension}"))
    assert saved and saved[0].read_bytes() == jpeg, "file not saved -- logger crash swallowed"


def test_stream_buffer_is_capped():
    """Stream accumulation must stop once the buffer cap is exceeded."""
    listener = FileCarvingListener(interface="lo", timeout=1)

    chunk = b"\x00" * (10 * 1024 * 1024)  # 10 MB, no header/footer
    stream_key = ("10.0.0.1", "10.0.0.2", "TCP")

    # Feed past the cap.
    fed = 0
    while fed <= _STREAM_BUFFER_MAX:
        listener.feed_packet(_jpeg_packet(chunk))
        fed += len(chunk)

    stream = listener._streams[stream_key]
    assert stream.capped is True
    capped_len = len(stream.data)

    # Further packets must not grow the buffer.
    listener.feed_packet(_jpeg_packet(chunk))
    assert len(stream.data) == capped_len

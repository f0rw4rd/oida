#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Regression tests for FileCarvingMixin save-failure reporting.

Bug (core bug hunt): ``_save_file`` swallowed every failure at DEBUG level and
returned None, while ``_record_file`` had already appended the file and logged
"File carved". With an unwritable output_dir the operator saw a successful
carve, a full ``files`` list, and a files summary — and nothing on disk.

Reproduced before the fix (output_dir occupied by a regular file so makedirs
raises):
    RESULT files recorded in memory : 1
    RESULT get_files_summary() says : [{'file_type': 'PNG', ... }]
    RESULT anything on disk         : no dir
    (only a DEBUG log line mentioned the failure)
"""

import logging
import os
import tempfile
import threading
import unittest

from oida.shared.file_carving_common import FileCarvingMixin

PNG_HEADER = b"\x89PNG\r\n\x1a\n"
PNG_FOOTER = b"IEND\xaeB`\x82"
PAYLOAD = PNG_HEADER + b"B" * 100 + PNG_FOOTER


class _Probe(FileCarvingMixin):
    """Minimal concrete consumer of the mixin (no listener machinery)."""

    FILE_SIGNATURES = {
        "PNG": {
            "headers": [PNG_HEADER],
            "footers": [PNG_FOOTER],
            "extension": ".png",
            "max_size": 10_000_000,
            "min_size": 20,
        }
    }

    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.files = []
        self.logger = logging.getLogger("probe")
        self._lock = threading.Lock()
        self.discovered_devices = {}

    def _get_logger(self):
        return self.logger

    def _update_devices(self, extracted):
        pass


class _FakeStream:
    src_ip = "10.0.0.1"
    dst_ip = "10.0.0.2"
    src_mac = ""
    dst_mac = ""
    protocol = "TCP"

    def __init__(self, data):
        self.data = data
        # Per-instance: the mixin records carved ranges here, and a shared
        # class-level list would make the second test's carve look "already
        # extracted" from the first.
        self.extracted_offsets = []


class TestSaveFailureReporting(unittest.TestCase):
    def test_save_failure_is_logged_at_error_not_debug(self):
        """A carve that cannot be saved must be visible, not debug-level noise."""
        tmp = tempfile.mkdtemp()
        blocker = os.path.join(tmp, "blocked")
        open(blocker, "w").close()  # output_dir occupied -> makedirs raises

        probe = _Probe(blocker)
        with self.assertLogs("probe", level="ERROR") as logs:
            probe._try_extract_files(_FakeStream(PAYLOAD), force=True)
        self.assertTrue(any("Failed to save" in line for line in logs.output))

    def test_files_summary_marks_unsaved_files(self):
        tmp = tempfile.mkdtemp()
        blocker = os.path.join(tmp, "blocked")
        open(blocker, "w").close()

        probe = _Probe(blocker)
        probe._try_extract_files(_FakeStream(PAYLOAD), force=True)
        summary = probe.get_files_summary()
        self.assertEqual(len(summary), 1)
        self.assertFalse(summary[0]["saved"], "unsaved carve must be marked saved=False")

    def test_files_summary_marks_saved_files(self):
        tmp = tempfile.mkdtemp()
        probe = _Probe(os.path.join(tmp, "out"))
        probe._try_extract_files(_FakeStream(PAYLOAD), force=True)
        summary = probe.get_files_summary()
        self.assertEqual(len(summary), 1)
        self.assertTrue(summary[0]["saved"])

    def test_saved_file_actually_lands_on_disk(self):
        tmp = tempfile.mkdtemp()
        out = os.path.join(tmp, "out")
        probe = _Probe(out)
        probe._try_extract_files(_FakeStream(PAYLOAD), force=True)
        files_on_disk = os.listdir(out)
        self.assertEqual(len(files_on_disk), 1)
        self.assertTrue(files_on_disk[0].endswith(".png"))
        with open(os.path.join(out, files_on_disk[0]), "rb") as f:
            self.assertEqual(f.read(), PAYLOAD)

    def test_save_file_returns_bool(self):
        """_save_file reports success/failure instead of raising or returning None."""
        tmp = tempfile.mkdtemp()
        probe = _Probe(os.path.join(tmp, "out"))
        probe._try_extract_files(_FakeStream(PAYLOAD), force=True)
        self.assertEqual(len(probe.files), 1)

        # Saving again to a healthy dir returns True.
        self.assertTrue(probe._save_file(probe.files[0]))

        # Saving against a blocked dir returns False instead of raising.
        blocker = os.path.join(tmp, "blocked")
        open(blocker, "w").close()
        probe.output_dir = blocker
        self.assertFalse(probe._save_file(probe.files[0]))


if __name__ == "__main__":
    unittest.main()

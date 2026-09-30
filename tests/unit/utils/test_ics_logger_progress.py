"""Regression tests for the TTY progress/``_print`` interaction.

The shipped bug: ``progress()`` wrote in-place updates (``end=""``) on a TTY
but never told the module a progress line was pending, so the next printed
line appended straight after the counters instead of clearing first
(``...11 failed<PROTO host:port> [!] No encryption``). Only pcap/fuzzer set
the flag by hand; the sweep executor never did. ``progress()`` now owns the
flag: pending while in-place (``end=""``), cleared when the update ends with
a newline.

Treated as a renderer regression, not a fleet contract: it needs no network
or mocks, just a tty-backed stdout (pty or real terminal).
"""

from __future__ import annotations

import unittest
from io import StringIO
from unittest import mock

from oida.utils import ics_logger
from oida.utils.ics_logger import ICSLogger


def _new_logger() -> ICSLogger:
    """Fresh logger, bypassing the shared _logger_cache."""
    return ICSLogger("MMS", "127.0.0.1", 102)


class _TtyStringIO(StringIO):
    """StringIO that reports being a TTY, to drive the TTY render branches."""

    def isatty(self) -> bool:
        return True


class TestProgressTracksPendingLine(unittest.TestCase):
    def test_in_place_update_marks_progress_pending(self):
        logger = _new_logger()
        with mock.patch("sys.stdout", new=_TtyStringIO()) as fake_out:
            logger.progress(1, 254, 0, 1)  # end="" -> in-place TTY update
            self.assertEqual(ics_logger._progress_active, True)
            logger.display("No encryption")
            out = fake_out.getvalue()
        # The display line must have cleared the pending progress line first.
        self.assertIn("\r\x1b[K", out)
        self.assertIn("No encryption", out)

    def test_terminated_update_clears_pending_flag(self):
        logger = _new_logger()
        with mock.patch("sys.stdout", new=_TtyStringIO()) as fake_out:
            logger.progress(254, 254, 2, 252, end="\n")
            self.assertEqual(ics_logger._progress_active, False)
            logger.display("after")
        self.assertIn("after", fake_out.getvalue())


if __name__ == "__main__":
    unittest.main()

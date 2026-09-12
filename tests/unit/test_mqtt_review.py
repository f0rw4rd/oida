#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Regression tests from the G1 (coap+mqtt) bug-hunt review.

See .bughunt/catchall.md under "## G1 coap+mqtt" for the full writeup.
"""

import os
import tempfile
import unittest


class TestMqttTopicsFileBareHashWildcard(unittest.TestCase):
    """A `--topics FILE` whose only real entry is the bare `#` wildcard.

    `#` alone is a valid MQTT topic filter (subscribe to everything) per the
    MQTT 3.1.1/5.0 spec (section on Topic Filters) - it must be the sole
    matching part of the exact filter, but a lone `#` line is exactly that.
    The scanner's topics-file loader treated ANY line starting with "#" as a
    comment, which silently ate this legitimate wildcard-only topics file and
    left topics_list empty, so listen mode would subscribe to nothing.
    """

    def _make_topics_file(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".txt", text=True)
        with os.fdopen(fd, "w") as f:
            f.write(content)
        self.addCleanup(os.unlink, path)
        return path

    def test_bare_hash_wildcard_line_is_kept_as_a_topic(self):
        from oida.protocols.mqtt.scanner import MQTTScanner

        topics_file = self._make_topics_file("# full wildcard below\n#\n")

        args = {
            "rhost": "192.168.1.100",
            "rport": 1883,
            "topics": topics_file,
        }
        scanner = MQTTScanner(args)

        self.assertTrue(scanner.topics_from_file)
        self.assertEqual(
            scanner.topics_list,
            ["#"],
            "a bare '#' line is a valid MQTT topic filter and must not be "
            "treated as a comment / dropped from the loaded topics list",
        )

    def test_real_comment_lines_are_still_stripped(self):
        from oida.protocols.mqtt.scanner import MQTTScanner

        topics_file = self._make_topics_file(
            "# this is a comment\nsensors/#\n# another comment\nhomeassistant/#\n"
        )

        args = {
            "rhost": "192.168.1.100",
            "rport": 1883,
            "topics": topics_file,
        }
        scanner = MQTTScanner(args)

        self.assertEqual(scanner.topics_list, ["sensors/#", "homeassistant/#"])


if __name__ == "__main__":
    unittest.main()

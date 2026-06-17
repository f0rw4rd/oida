#!/usr/bin/env python3
"""
Unit tests for EtherNet/IP attack payloads and dangerous tag patterns.

Tests cover:
- Attack payload structure and content
- Attack type definitions
- Dangerous tag pattern matching
- Payload byte-level verification
"""

import re
import unittest

import pytest

pytestmark = pytest.mark.core

from oida.protocols.ethernetip.attacks import (
    ATTACK_CRASHCPU_PAYLOAD,
    ATTACK_CRASHETHER_PAYLOAD,
    ATTACK_RESETETHER_PAYLOAD,
    ATTACK_STOPCPU_PAYLOAD,
    DANGEROUS_TAG_PATTERNS,
)


class TestAttackPayloads(unittest.TestCase):
    """Test CIP attack payload definitions."""

    def test_stopcpu_payload_type(self):
        self.assertIsInstance(ATTACK_STOPCPU_PAYLOAD, bytes)

    def test_crashcpu_payload_type(self):
        self.assertIsInstance(ATTACK_CRASHCPU_PAYLOAD, bytes)

    def test_crashether_payload_type(self):
        self.assertIsInstance(ATTACK_CRASHETHER_PAYLOAD, bytes)

    def test_resetether_payload_type(self):
        self.assertIsInstance(ATTACK_RESETETHER_PAYLOAD, bytes)

    def test_payloads_non_empty(self):
        self.assertGreater(len(ATTACK_STOPCPU_PAYLOAD), 0)
        self.assertGreater(len(ATTACK_CRASHCPU_PAYLOAD), 0)
        self.assertGreater(len(ATTACK_CRASHETHER_PAYLOAD), 0)
        self.assertGreater(len(ATTACK_RESETETHER_PAYLOAD), 0)

    def test_stopcpu_starts_with_unconnected_data(self):
        """STOPCPU should start with CIP Unconnected Data item (0xB2)."""
        self.assertEqual(ATTACK_STOPCPU_PAYLOAD[0], 0xB2)

    def test_crashcpu_starts_with_unconnected_data(self):
        self.assertEqual(ATTACK_CRASHCPU_PAYLOAD[0], 0xB2)

    def test_crashether_starts_with_unconnected_data(self):
        self.assertEqual(ATTACK_CRASHETHER_PAYLOAD[0], 0xB2)

    def test_resetether_starts_with_unconnected_data(self):
        self.assertEqual(ATTACK_RESETETHER_PAYLOAD[0], 0xB2)

    def test_stopcpu_contains_magic_bytes(self):
        """STOPCPU payload should contain 0xDEADBEEFCAFE."""
        self.assertIn(b"\xde\xad\xbe\xef\xca\xfe", ATTACK_STOPCPU_PAYLOAD)

    def test_crashether_targets_tcp_ip_interface(self):
        """CRASHETHER targets TCP/IP Interface Object (0xF5)."""
        self.assertIn(b"\xf5", ATTACK_CRASHETHER_PAYLOAD)

    def test_resetether_targets_identity_object(self):
        """RESETETHER uses Identity Object (0x01) Reset service."""
        # Service 0x05 = Reset, Class 0x01 = Identity
        self.assertIn(b"\x05", ATTACK_RESETETHER_PAYLOAD)
        self.assertIn(b"\x01", ATTACK_RESETETHER_PAYLOAD)

    def test_payloads_are_distinct(self):
        """All payloads should be unique."""
        payloads = [
            ATTACK_STOPCPU_PAYLOAD,
            ATTACK_CRASHCPU_PAYLOAD,
            ATTACK_CRASHETHER_PAYLOAD,
            ATTACK_RESETETHER_PAYLOAD,
        ]
        self.assertEqual(len(payloads), len(set(payloads)))


class TestDangerousTagPatterns(unittest.TestCase):
    """Test dangerous tag pattern matching."""

    def test_patterns_are_list(self):
        self.assertIsInstance(DANGEROUS_TAG_PATTERNS, list)
        self.assertGreater(len(DANGEROUS_TAG_PATTERNS), 0)

    def test_patterns_are_valid_regex(self):
        for pattern in DANGEROUS_TAG_PATTERNS:
            try:
                re.compile(pattern)
            except re.error:
                self.fail(f"Invalid regex pattern: {pattern}")

    def test_safety_tag_matches(self):
        """Tags containing SAFETY should match."""
        matched = False
        for pattern in DANGEROUS_TAG_PATTERNS:
            if re.match(pattern, "SAFETY_RELAY_1", re.IGNORECASE):
                matched = True
                break
        self.assertTrue(matched)

    def test_estop_tag_matches(self):
        """Tags containing ESTOP should match."""
        matched = False
        for pattern in DANGEROUS_TAG_PATTERNS:
            if re.match(pattern, "ESTOP_ACTIVE", re.IGNORECASE):
                matched = True
                break
        self.assertTrue(matched)

    def test_emergency_tag_matches(self):
        matched = False
        for pattern in DANGEROUS_TAG_PATTERNS:
            if re.match(pattern, "EMERGENCY_SHUTDOWN", re.IGNORECASE):
                matched = True
                break
        self.assertTrue(matched)

    def test_motor_enable_matches(self):
        matched = False
        for pattern in DANGEROUS_TAG_PATTERNS:
            if re.match(pattern, "MOTOR_ENABLE_1", re.IGNORECASE):
                matched = True
                break
        self.assertTrue(matched)

    def test_valve_open_matches(self):
        matched = False
        for pattern in DANGEROUS_TAG_PATTERNS:
            if re.match(pattern, "VALVE_OPEN_CMD", re.IGNORECASE):
                matched = True
                break
        self.assertTrue(matched)

    def test_normal_tag_does_not_match(self):
        """A normal tag like 'TIMER_1' should not match dangerous patterns."""
        matched = False
        for pattern in DANGEROUS_TAG_PATTERNS:
            if re.match(pattern, "TIMER_1", re.IGNORECASE):
                matched = True
                break
        self.assertFalse(matched)


if __name__ == "__main__":
    unittest.main()

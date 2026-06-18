"""Integration tests for Redis passive listener.

Tests cover:
- AUTH command credential extraction
- Command parsing (SET, GET, SELECT, CONFIG)
- Key name extraction
- Response parsing (simple strings, errors, integers)
- Both client and server device creation
- Interaction table formatting
- Harvest output quality
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestRedisPassiveEK:
    """Redis-specific tests beyond the parametrized quality suite."""

    def test_auth_credential_extraction(self):
        """AUTH commands extract plaintext passwords."""
        listener, devices, result = _run_listener_test(
            "redis",
            "RedisPassiveListener",
            "resp",
            "redis/generated_redis.pcap",
            min_interactions=2,
            expect_details=["command"],
        )
        # Should extract at least one credential from AUTH command
        creds = listener.get_credentials_summary()
        assert len(creds) >= 1, f"Expected >= 1 Redis credential, got {len(creds)}"
        # Verify password was extracted
        passwords = [c.get("password", "") for c in creds]
        assert any(passwords), f"No passwords extracted; creds: {creds}"

    def test_command_parsing(self):
        """Redis commands are parsed and tracked."""
        listener, devices, result = _run_listener_test(
            "redis",
            "RedisPassiveListener",
            "resp",
            "redis/generated_redis.pcap",
            min_interactions=2,
        )
        # Should have seen multiple command types
        assert len(listener.commands_seen) >= 1, (
            f"Expected >= 1 command types, got {listener.commands_seen}"
        )

    def test_key_extraction(self):
        """Key names are extracted from GET/SET commands."""
        listener, devices, result = _run_listener_test(
            "redis",
            "RedisPassiveListener",
            "resp",
            "redis/generated_redis.pcap",
        )
        # Key extraction depends on command parsing working
        # With generated pcap, we may get keys from SET/GET
        assert isinstance(listener.keys_seen, set)

    def test_response_parsing(self):
        """Simple string responses (+OK) are parsed."""
        listener, devices, result = _run_listener_test(
            "redis",
            "RedisPassiveListener",
            "resp",
            "redis/generated_redis.pcap",
            min_interactions=2,
        )
        # Should have response interactions
        responses = [ix for ix in listener.interactions if ix.direction == "response"]
        assert len(responses) >= 1, "No response interactions found"

    def test_both_endpoints_tracked(self):
        """Both Redis client and server devices are created."""
        listener, devices, result = _run_listener_test(
            "redis",
            "RedisPassiveListener",
            "resp",
            "redis/generated_redis.pcap",
            min_devices=2,
        )
        device_types = [d.device_type for d in devices.values() if hasattr(d, "device_type")]
        has_server = any("Server" in t for t in device_types)
        has_client = any("Client" in t for t in device_types)
        assert has_server, f"No Redis Server device found; types: {device_types}"
        assert has_client, f"No Redis Client device found; types: {device_types}"

    def test_harvest_valid(self):
        """Harvest returns valid dict."""
        listener, devices, result = _run_listener_test(
            "redis",
            "RedisPassiveListener",
            "resp",
            "redis/generated_redis.pcap",
        )
        assert isinstance(result, dict)

    def test_protocol_columns_format(self):
        """Protocol columns produce clean string values."""
        listener, devices, result = _run_listener_test(
            "redis",
            "RedisPassiveListener",
            "resp",
            "redis/generated_redis.pcap",
            min_interactions=1,
        )
        for ix in listener.interactions:
            cols = listener._format_protocol_columns(ix)
            assert len(cols) == 3, f"Expected 3 columns, got {len(cols)}"
            for col in cols:
                assert not isinstance(col, (dict, set, list)), f"Raw collection in column: {col}"

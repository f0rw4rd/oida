"""
Unit tests for BruteForceMixin.

_test_community (which builds a real pysnmp session) is mocked; the orchestration
logic of _brute_communities / _test_communities is what we assert.
"""

from __future__ import annotations

from unittest.mock import patch


class TestBruteCommunities:
    def test_requires_confirm(self, scanner):
        scanner.confirm_brute = False
        scanner.brute_rate = 0
        out = scanner._brute_communities()
        assert out == []
        scanner.logger.fail.assert_called()

    def test_returns_first_valid_and_stops(self, scanner):
        scanner.confirm_brute = True
        scanner.brute_rate = 0
        # Make only the 3rd community succeed; ensure we stop after the first hit.
        tested = []

        def fake_test(community):
            tested.append(community)
            return community == "private"

        # Force a deterministic wordlist by patching load_passwords.
        with patch(
            "oida.utils.login_scanner.load_passwords",
            return_value=["public", "guest", "private", "secret"],
        ):
            with patch.object(scanner, "_test_community", side_effect=fake_test):
                out = scanner._brute_communities()

        assert out == ["private"]
        # Must short-circuit: "secret" never tried.
        assert "secret" not in tested
        assert tested == ["public", "guest", "private"]

    def test_no_valid_returns_empty(self, scanner):
        scanner.confirm_brute = True
        scanner.brute_rate = 0
        with patch(
            "oida.utils.login_scanner.load_passwords",
            return_value=["public", "private"],
        ):
            with patch.object(scanner, "_test_community", return_value=False):
                out = scanner._brute_communities()
        assert out == []


class TestTestCommunities:
    def test_collects_all_valid(self, scanner):
        scanner.brute_rate = 0
        with patch.object(scanner, "_test_community", side_effect=lambda c: c in ("a", "c")):
            out = scanner._test_communities(["a", "b", "c"])
        assert out == ["a", "c"]


class TestTestCommunitySession:
    def test_exception_returns_false(self, scanner):
        """A transport exception during the probe must be caught -> False."""
        with patch(
            "oida.protocols.snmp.mixins.brute_force.asyncio.run",
            side_effect=OSError("network down"),
        ):
            assert scanner._test_community("public") is False

    def test_successful_probe_returns_true(self, scanner):
        with patch("oida.protocols.snmp.mixins.brute_force.asyncio.run", return_value=True):
            assert scanner._test_community("public") is True

    def test_rejected_probe_returns_false(self, scanner):
        with patch("oida.protocols.snmp.mixins.brute_force.asyncio.run", return_value=False):
            assert scanner._test_community("wrong") is False

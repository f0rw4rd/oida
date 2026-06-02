"""Unit tests for ``format_wordlist_source``.

Pins the privacy contract so a regression that prints the full wordlist
path to logs would fail this test immediately, rather than silently leak
operator filesystem layout / client context to every JSON log line.
"""

import pytest

from oida.utils.login_scanner import format_wordlist_source


class TestFormatWordlistSource:
    def test_returns_default_label_when_none(self):
        assert format_wordlist_source(None) == "built-in defaults"

    def test_returns_default_label_when_empty(self):
        assert format_wordlist_source("") == "built-in defaults"

    def test_returns_basename_for_absolute_path(self):
        assert format_wordlist_source("/etc/passwords/rockyou.txt") == "rockyou.txt"

    def test_strips_engagement_sensitive_directory(self):
        path = "/home/pentester/clients/acmecorp/internal-creds.txt"
        result = format_wordlist_source(path)
        assert result == "internal-creds.txt"
        # Critical: directory components MUST NOT appear in the result.
        assert "pentester" not in result
        assert "acmecorp" not in result
        assert "clients" not in result

    def test_returns_basename_for_relative_path(self):
        assert format_wordlist_source("./wordlists/common.txt") == "common.txt"

    def test_returns_basename_for_dot_relative(self):
        assert format_wordlist_source("wordlists/common.txt") == "common.txt"

    def test_returns_name_when_no_directory(self):
        assert format_wordlist_source("common.txt") == "common.txt"

    def test_custom_default_label(self):
        assert format_wordlist_source(None, default_label="vendor defaults") == "vendor defaults"

    def test_basename_with_spaces_preserved(self):
        assert (
            format_wordlist_source("/tmp/Client Engagement/test list.txt")
            == "test list.txt"
        )

    def test_basename_with_extension_chain_preserved(self):
        assert format_wordlist_source("/tmp/list.txt.gz") == "list.txt.gz"

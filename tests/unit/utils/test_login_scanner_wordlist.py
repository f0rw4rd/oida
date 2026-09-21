"""Regression tests for login_scanner wordlist reading.

``_load_file_lines`` read wordlists in text mode. On the first non-UTF-8 byte
it raised UnicodeDecodeError; the caller's handler caught it, but iteration
had already stopped, so every entry after the offending line was silently
dropped from the brute-force (with a "0 errors" appearance).
"""

from oida.utils.login_scanner import _load_file_lines


def test_non_utf8_wordlist_is_read_completely(tmp_path):
    wordlist = tmp_path / "passwords.txt"
    wordlist.write_bytes(b"first\npa\xdfsword\nlast\n")

    lines = _load_file_lines(str(wordlist))

    # Every line survives; the undecodable one round-trips via latin-1.
    assert len(lines) == 3
    assert lines[0] == "first"
    assert lines[2] == "last"
    assert lines[1].encode("latin-1") == b"pa\xdfsword"


def test_comments_and_blank_lines_are_skipped(tmp_path):
    wordlist = tmp_path / "passwords.txt"
    wordlist.write_bytes(b"# comment\n\nadmin\n   \n# tail\nsecret\n")

    assert _load_file_lines(str(wordlist)) == ["admin", "secret"]


def test_missing_file_is_logged_not_raised(tmp_path):
    assert _load_file_lines(str(tmp_path / "nope.txt")) == []

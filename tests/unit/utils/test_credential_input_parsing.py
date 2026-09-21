"""Regression tests for parse_credential_input file handling.

Password lists off the internet are routinely not valid UTF-8. The reader used
text mode, so a single stray byte raised UnicodeDecodeError -- a ValueError,
which the (IOError, OSError) handler did not catch -- aborting the scan or, in
callers that wrap the call in `except Exception`, silently skipping the whole
authentication test. A credential containing a NUL byte crashed the same way
via open()'s "embedded null byte" ValueError.
"""

from oida.utils.default_credentials import load_credentials, parse_credential_input


def test_non_utf8_wordlist_is_read_completely(tmp_path):
    wordlist = tmp_path / "passwords.txt"
    wordlist.write_bytes(b"admin\npa\xdfsword\nroot\n")

    values, is_file = parse_credential_input(str(wordlist))

    assert is_file is True
    # Every line survives; the undecodable one falls back to latin-1 rather
    # than taking the rest of the list down with it.
    assert len(values) == 3
    assert values[0] == "admin"
    assert values[2] == "root"
    assert values[1].encode("latin-1") == b"pa\xdfsword"


def test_non_utf8_wordlist_reaches_load_credentials(tmp_path):
    wordlist = tmp_path / "passwords.txt"
    wordlist.write_bytes(b"one\ntw\xffo\n")

    creds = load_credentials(username="operator", password=str(wordlist))

    assert [u for u, _ in creds] == ["operator", "operator"]
    assert len(creds) == 2


def test_comments_and_blank_lines_are_skipped(tmp_path):
    wordlist = tmp_path / "passwords.txt"
    wordlist.write_bytes(b"# header\n\nadmin\n   \n#trailing\nroot\n")

    values, is_file = parse_credential_input(str(wordlist))

    assert (values, is_file) == (["admin", "root"], True)


def test_credential_with_nul_byte_is_treated_as_a_literal():
    values, is_file = parse_credential_input("pass\x00word")

    assert (values, is_file) == (["pass\x00word"], False)


def test_directory_path_is_treated_as_a_literal(tmp_path):
    values, is_file = parse_credential_input(str(tmp_path))

    assert (values, is_file) == ([str(tmp_path)], False)


def test_missing_path_is_treated_as_a_literal(tmp_path):
    missing = str(tmp_path / "nope.txt")

    assert parse_credential_input(missing) == ([missing], False)


def test_empty_input_yields_nothing():
    assert parse_credential_input(None) == ([], False)
    assert parse_credential_input("") == ([], False)
    assert parse_credential_input("   ") == ([], False)

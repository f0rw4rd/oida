"""Unit + CLI-integration tests for the crash bug-catcher (oida.utils.crash_report).

Covers:
- credential-flag argv redaction (permissive otherwise)
- $HOME stripping from traceback text
- fingerprint-based dedup across repeated record() calls
- URL-length truncation fallback + local crash-file write
- --no-bug-report / OIDA_NO_BUG_REPORT suppression
- end-to-end: cli.scan_target() wiring fires for genuine bugs, not for
  operational failures (ICSProtocolError / OSError / TimeoutError / ImportError)
"""

import argparse

import pytest

from oida import cli
from oida.utils import crash_report
from oida.utils.exceptions import ICSConnectionError


@pytest.fixture(autouse=True)
def _reset_crash_state(monkeypatch, tmp_path):
    # Isolate dedup state and the crash-file directory between tests.
    crash_report.reset_for_tests()
    monkeypatch.setattr(crash_report, "CRASH_REPORT_DIR", tmp_path / "crash_reports")
    yield
    crash_report.reset_for_tests()


class TestSanitizeArgv:
    def test_redacts_long_password_flag_value(self):
        out = crash_report.sanitize_argv(["modbus", "10.0.0.1", "--password", "hunter2"])
        assert out == ["modbus", "10.0.0.1", "--password", "***"]

    def test_redacts_long_flag_with_equals(self):
        out = crash_report.sanitize_argv(["modbus", "10.0.0.1", "--auth-token=abc123"])
        assert out == ["modbus", "10.0.0.1", "--auth-token=***"]

    def test_redacts_case_insensitively(self):
        out = crash_report.sanitize_argv(["--PASSWORD", "secretvalue"])
        assert out == ["--PASSWORD", "***"]

    def test_redacts_short_flag_dash_p_separate_token(self):
        out = crash_report.sanitize_argv(["modbus", "10.0.0.1", "-P", "hunter2"])
        assert out == ["modbus", "10.0.0.1", "-P", "***"]

    def test_redacts_short_flag_dash_p_attached(self):
        out = crash_report.sanitize_argv(["-Phunter2"])
        assert out == ["-P***"]

    def test_key_secret_and_generic_auth_flags_redacted(self):
        out = crash_report.sanitize_argv(
            ["--secret", "s1", "--api-key", "k1", "--auth", "a1", "--token", "t1"]
        )
        assert out == ["--secret", "***", "--api-key", "***", "--auth", "***", "--token", "***"]

    def test_leaves_targets_and_non_credential_flags_verbatim(self):
        argv = ["modbus", "192.168.1.1", "--unit-id", "1", "-u", "alice", "--scan-range", "0-100"]
        assert crash_report.sanitize_argv(argv) == argv

    def test_redacts_compound_credential_flags(self):
        # The whole-part matcher must catch credential words anywhere in a
        # hyphenated flag name, not just as a leading substring.
        out = crash_report.sanitize_argv(
            [
                "snmp",
                "10.0.0.1",
                "--snmp-priv-pass",
                "p1",
                "--snmp-auth-pass",
                "a1",
                "--psk",
                "k1",
                "--tls-pin",
                "abcd",
                "--default-creds",
                "admin:admin",
            ]
        )
        assert out == [
            "snmp",
            "10.0.0.1",
            "--snmp-priv-pass",
            "***",
            "--snmp-auth-pass",
            "***",
            "--psk",
            "***",
            "--tls-pin",
            "***",
            "--default-creds",
            "***",
        ]

    def test_redacts_plural_credential_flags(self):
        # Regression: --credentials and --passwords are real declared flags; the
        # [-_]-split whole-part matcher must catch the plural stems, not just
        # the singular ("cred"/"password") forms.
        out = crash_report.sanitize_argv(
            [" ", "--credentials", "admin:admin", "--passwords", "wordlist.txt"]
        )
        assert out == [" ", "--credentials", "***", "--passwords", "***"]

    def test_redacts_smashed_credential_flags(self):
        # No-separator credential spellings the split would otherwise miss.
        out = crash_report.sanitize_argv(
            ["--apikey", "k", "--secretkey", "s", "--keyfile", "id_rsa", "--authtoken", "t"]
        )
        assert out == [
            "--apikey",
            "***",
            "--secretkey",
            "***",
            "--keyfile",
            "***",
            "--authtoken",
            "***",
        ]

    def test_redacts_short_flag_dash_x(self):
        out = crash_report.sanitize_argv(["snmp", "10.0.0.1", "-X", "privpass"])
        assert out == ["snmp", "10.0.0.1", "-X", "***"]

    def test_store_true_flags_do_not_swallow_the_next_token(self):
        # Regression: a naive substring match ("pass" in "no-passive",
        # "pin" in "no-ping") would wrongly redact the token AFTER a boolean
        # store_true flag — here the scan target and a numeric unit id.
        argv = ["modbus", "--no-passive", "192.168.1.1", "--no-ping", "--unit-id", "5"]
        assert crash_report.sanitize_argv(argv) == argv

    def test_credential_named_store_true_flag_does_not_leak_following_secret(self):
        # HIGH regression: --test-reinit-pass (bacnet) and --default-creds (snmp)
        # are credential-NAMED store_true flags that take NO value. Arming
        # redact_next on them used to redact the *next flag's name* and leak the
        # real secret that came after it. The next token here starts with "-",
        # so it must be processed as its own flag, not consumed as a value.
        assert crash_report.sanitize_argv(["--test-reinit-pass", "--password", "hunter2"]) == [
            "--test-reinit-pass",
            "--password",
            "***",
        ]
        assert crash_report.sanitize_argv(["--default-creds", "--snmp-auth-pass", "s3cret"]) == [
            "--default-creds",
            "--snmp-auth-pass",
            "***",
        ]

    def test_credential_named_store_true_flag_preserves_following_boolean(self):
        # --default-creds followed by another boolean must leave it intact.
        assert crash_report.sanitize_argv(
            ["snmp", "192.168.1.1", "--default-creds", "--confirm"]
        ) == [
            "snmp",
            "192.168.1.1",
            "--default-creds",
            "--confirm",
        ]

    def test_dash_x_collision_with_non_credential_short_flag(self):
        # -X is the SNMPv3 privacy passphrase in snmp, but a non-credential
        # store_true short flag in hl7/pcap/iec104. The value-shape guard means
        # a following flag token (starts with "-") is not clobbered.
        argv = ["hl7", "10.0.0.5", "-X", "--extract-fields", "PID.3"]
        assert crash_report.sanitize_argv(argv) == argv


class TestSanitizeTraceback:
    def test_strips_home_directory(self, monkeypatch):
        monkeypatch.setenv("HOME", "/home/operator")
        tb = 'File "/home/operator/oida/src/oida/protocols/modbus/scanner.py", line 10'
        out = crash_report.sanitize_traceback(tb)
        assert "/home/operator" not in out
        assert out.startswith('File "~/')

    def test_leaves_ips_and_hostnames(self, monkeypatch):
        monkeypatch.setenv("HOME", "/home/operator")
        tb = "ConnectionError connecting to 10.20.30.40 (plc-01.corp.example.com)"
        out = crash_report.sanitize_traceback(tb)
        assert "10.20.30.40" in out
        assert "plc-01.corp.example.com" in out


class TestTruncateTraceback:
    def test_short_text_untouched(self):
        text = "short traceback"
        out, truncated = crash_report.truncate_traceback(text, 1000)
        assert out == text
        assert truncated is False

    def test_long_text_truncated_and_flagged(self):
        text = "\n".join(f"line {i}" for i in range(500))
        out, truncated = crash_report.truncate_traceback(text, 200)
        assert truncated is True
        assert len(out) <= 200 + len(
            "... (earlier traceback lines omitted; see local file for full details) ...\n"
        )
        # keeps the tail (closest to the failure), not the head
        assert "line 499" in out
        assert "line 0" not in out


class TestIsReportableException:
    @pytest.mark.parametrize(
        "exc",
        [
            AttributeError("boom"),
            TypeError("boom"),
            KeyError("boom"),
            RuntimeError("boom"),
            ValueError("boom"),
        ],
    )
    def test_bug_like_exceptions_are_reportable(self, exc):
        assert crash_report.is_reportable_exception(exc) is True

    @pytest.mark.parametrize(
        "exc",
        [
            ICSConnectionError("refused"),
            ConnectionRefusedError("refused"),
            TimeoutError("timed out"),
            PermissionError("denied"),
            ImportError("missing optional dep"),
            ModuleNotFoundError("no module"),
            KeyboardInterrupt(),
            SystemExit(1),
        ],
    )
    def test_operational_exceptions_are_not_reportable(self, exc):
        assert crash_report.is_reportable_exception(exc) is False


class TestIsSuppressed:
    def test_env_var_suppresses(self, monkeypatch):
        monkeypatch.setenv("OIDA_NO_BUG_REPORT", "1")
        assert crash_report.is_suppressed(None) is True

    def test_flag_suppresses(self, monkeypatch):
        monkeypatch.delenv("OIDA_NO_BUG_REPORT", raising=False)
        args = argparse.Namespace(no_bug_report=True)
        assert crash_report.is_suppressed(args) is True

    def test_neither_set_not_suppressed(self, monkeypatch):
        monkeypatch.delenv("OIDA_NO_BUG_REPORT", raising=False)
        args = argparse.Namespace(no_bug_report=False)
        assert crash_report.is_suppressed(args) is False
        assert crash_report.is_suppressed(None) is False


class TestRecordAndFlush:
    def test_dedup_same_fingerprint_fires_once(self):
        def _raise():
            raise AttributeError("same bug")

        for _ in range(5):
            try:
                _raise()
            except AttributeError as e:
                crash_report.record(e, protocol="modbus")

        n = crash_report.flush(print_fn=lambda _b: None)
        assert n == 1

    def test_distinct_fingerprints_each_fire(self):
        try:
            raise AttributeError("bug one")
        except AttributeError as e:
            crash_report.record(e, protocol="modbus")
        try:
            raise TypeError("bug two")
        except TypeError as e:
            crash_report.record(e, protocol="modbus")

        n = crash_report.flush(print_fn=lambda _b: None)
        assert n == 2

    def test_suppressed_never_queued(self, monkeypatch):
        monkeypatch.setenv("OIDA_NO_BUG_REPORT", "1")
        try:
            raise AttributeError("should not be reported")
        except AttributeError as e:
            crash_report.record(e, protocol="modbus")
        assert crash_report.flush(print_fn=lambda _b: None) == 0

    def test_operational_exception_never_queued(self):
        try:
            raise TimeoutError("target unreachable")
        except TimeoutError as e:
            crash_report.record(e, protocol="modbus")
        assert crash_report.flush(print_fn=lambda _b: None) == 0

    def test_block_contains_github_url_and_writes_crash_file(self):
        try:
            raise AttributeError("bug for url test")
        except AttributeError as e:
            crash_report.record(e, protocol="modbus", argv=["modbus", "10.0.0.1"])

        blocks = []
        crash_report.flush(print_fn=blocks.append)
        assert len(blocks) == 1
        assert "https://github.com/f0rw4rd/oida/issues/new" in blocks[0]

        files = list(crash_report.CRASH_REPORT_DIR.glob("oida-crash-*.txt"))
        assert len(files) == 1
        assert "AttributeError" in files[0].read_text(encoding="utf-8")

    def test_huge_traceback_stays_under_url_cap(self):
        def _make_deep_exception(depth):
            if depth <= 0:
                raise AttributeError("deep bug " + ("x" * 500))
            _make_deep_exception(depth - 1)

        try:
            _make_deep_exception(80)
        except AttributeError as e:
            crash_report.record(e, protocol="modbus")

        blocks = []
        crash_report.flush(print_fn=blocks.append)
        assert len(blocks) == 1
        # Extract the URL line and confirm it's under the cap.
        url_line = next(line for line in blocks[0].splitlines() if "github.com" in line)
        url = url_line.strip()
        assert len(url) <= crash_report.MAX_URL_LENGTH


class TestScanTargetIntegration:
    """End-to-end: the real oida.cli.scan_target() -> crash_report wiring."""

    @pytest.mark.parametrize(
        "exc_cls",
        [AttributeError, TypeError, KeyError, RuntimeError],
    )
    def test_bug_like_exception_fires_block(self, exc_cls):
        class FakeProto:
            def __init__(self, args, db, host):
                raise exc_cls("synthetic bug")

        args = argparse.Namespace(protocol="modbus")
        result = cli.scan_target(FakeProto, args, "10.0.0.1")
        assert result["success"] is False

        blocks = []
        n = crash_report.flush(print_fn=blocks.append)
        assert n == 1
        assert "github.com/f0rw4rd/oida/issues/new" in blocks[0]

    @pytest.mark.parametrize(
        "exc_cls,exc_args",
        [
            (ICSConnectionError, ("refused",)),
            (ConnectionRefusedError, ("refused",)),
            (OSError, ("os failure",)),
            (TimeoutError, ("timed out",)),
            (ModuleNotFoundError, ("no module",)),
        ],
    )
    def test_operational_failure_does_not_fire(self, exc_cls, exc_args):
        class FakeProto:
            def __init__(self, args, db, host):
                raise exc_cls(*exc_args)

        args = argparse.Namespace(protocol="modbus")
        result = cli.scan_target(FakeProto, args, "10.0.0.1")
        assert result["success"] is False

        assert crash_report.flush(print_fn=lambda _b: None) == 0

    def test_no_bug_report_flag_suppresses_in_scan_target(self):
        class FakeProto:
            def __init__(self, args, db, host):
                raise AttributeError("synthetic bug")

        args = argparse.Namespace(protocol="modbus", no_bug_report=True)
        cli.scan_target(FakeProto, args, "10.0.0.1")

        assert crash_report.flush(print_fn=lambda _b: None) == 0

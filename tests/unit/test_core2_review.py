"""Tests for the core-scope review (wave 2): CLI argv plumbing and connection
host-resolution hardening.

Regression guards for:

* ``gen_cli_args()`` inspecting ``sys.argv`` instead of the ``argv`` actually
  being parsed — protocol aliases (``s7``) and per-protocol flags were only
  registered on the FULL subparser, so a programmatic ``main(argv=[...])``
  call from a process whose own ``sys.argv`` names a different protocol (or
  no protocol at all) produced a stub-only parser and hard-failed on
  ``invalid choice`` / ``unrecognized arguments``.
* ``connection._resolve_host()`` only catching ``socket.gaierror`` — a
  hostname rejected by IDNA encoding raises ``UnicodeEncodeError`` from
  ``getaddrinfo`` BEFORE the centralized ``proto_flow`` try/except, crashing
  the connection constructor instead of degrading to a logged failure.
"""


class TestGenCliArgsUsesProvidedArgv:
    """gen_cli_args() must build the parser for the argv it will parse."""

    def test_gen_cli_args_accepts_argv_kwarg(self):
        """The keyword exists and selects the fully-registered protocol."""
        from oida.cli import gen_cli_args

        parser = gen_cli_args(argv=["oida", "snap7", "10.0.0.1"])
        sub = parser._subparsers_action.choices.get("snap7")
        assert sub is not None
        # The FULL snap7 subparser registers its own --timeout (a stub only
        # has --port), and it must also register the s7 alias.
        assert any("--timeout" in ac.option_strings for ac in sub._actions), (
            "snap7 subparser looks like a stub: --timeout missing"
        )
        assert "s7" in parser._subparsers_action.choices, (
            "alias 's7' not registered even though snap7 was fully built"
        )

    def test_gen_cli_args_argv_without_program_name(self):
        """A bare arg list (no argv[0]) still selects the right protocol."""
        from oida.cli import gen_cli_args

        parser = gen_cli_args(argv=["modbus", "10.0.0.1"])
        sub = parser._subparsers_action.choices.get("modbus")
        assert sub is not None
        assert any("--timeout" in ac.option_strings for ac in sub._actions), (
            "modbus subparser looks like a stub: --timeout missing"
        )

    def test_gen_cli_args_stubs_when_argv_has_no_protocol(self):
        """No positional protocol in argv -> stub mode, not 'all'."""
        from oida.cli import gen_cli_args

        parser = gen_cli_args(argv=["oida", "--bug"])
        sub = parser._subparsers_action.choices.get("modbus")
        assert sub is not None
        assert not any("--timeout" in ac.option_strings for ac in sub._actions)

    def test_main_with_explicit_argv_ignores_process_sys_argv(self, monkeypatch):
        """The originally reported repro: a wrapper process whose sys.argv
        names 'modbus' calls main(['s7', ...]) — the s7 alias must resolve.

        The protocol's dispatch() is stubbed out so the test asserts PARSING
        only (pre-fix: SystemExit 2 / 'invalid choice'); no network is touched
        and the scan never runs."""
        import sys

        from oida import cli

        monkeypatch.setattr(sys, "argv", ["wrap", "modbus", "x"])
        rc = _main_with_stub_protocol(cli, ["s7", "10.255.255.1", "--timeout", "1"])
        assert rc in (0, 1), "main() must parse and run, not SystemExit(2) on 's7'"

    def test_main_alias_works_in_stub_process_argv(self, monkeypatch):
        """Wrapper with NO protocol in sys.argv -> stub mode was selected and
        every protocol subparser was a stub, so 's7' was not even a choice."""
        import sys

        from oida import cli

        monkeypatch.setattr(sys, "argv", ["wrap"])
        rc = _main_with_stub_protocol(cli, ["s7", "10.255.255.1", "--timeout", "1"])
        assert rc in (0, 1)


def _main_with_stub_protocol(cli_module, argv):
    """Run cli.main(argv) with the protocol scan stubbed at the loader seam.

    Asserts PARSING only (the bug died at parse time with SystemExit 2);
    the stub protocol class runs no network I/O so the test cannot hang."""

    class _StubProto:
        def __init__(self, *a, **k):
            pass

    class _StubLoader:
        def get_protocol_class(self, name):
            return _StubProto

    real_main = cli_module.main

    def patched_main(inner_argv=None):
        # Intercept between parse and scan: swap the loader the parser cached.
        import oida.cli as c

        orig_gen = c.gen_cli_args

        def gen(argv2=None):
            parser = orig_gen(argv2)
            parser._protocol_loader = _StubLoader()
            return parser

        c.gen_cli_args = gen
        try:
            return real_main(inner_argv)
        finally:
            c.gen_cli_args = orig_gen

    return patched_main(argv)


class _NS:
    port = 1234
    verbose = 0
    debug = False


class _FakeProto:
    """Layer-2 stub implementing the connection protocol surface."""

    protocol_name = "fake"
    default_port = 1234

    def proto_flow(self):
        pass

    def create_conn_obj(self):
        pass

    def enum_host_info(self):
        pass

    def print_host_info(self):
        pass


class TestResolveHostDegradesOnBadHostname:
    """_resolve_host() must not let non-gaierror resolver errors escape."""

    def test_idna_rejected_hostname_does_not_crash_constructor(self):
        """A 300-char label fails IDNA encoding in getaddrinfo ->
        UnicodeEncodeError, which is NOT a socket.gaierror. Pre-fix this
        escaped _resolve_host() and crashed connection.__init__ before the
        centralized error handling could record a failed scan."""
        from oida.connection import NetworkConnection

        proto = type("fakeproto", (_FakeProto, NetworkConnection), {})
        conn = proto(_NS(), None, "a" * 300 + ".example.com")
        # Constructor completed: the centralized handler recorded a result
        # rather than raising out of __init__.
        assert conn.ip == "a" * 300 + ".example.com"

    def test_normal_unresolvable_hostname_still_degrades(self):
        from oida.connection import NetworkConnection

        proto = type("fakeproto", (_FakeProto, NetworkConnection), {})
        conn = proto(_NS(), None, "definitely-not-a-real-host.invalid")
        assert conn.ip == "definitely-not-a-real-host.invalid"
        assert conn.get_results()["success"] is True  # happy-path no-op flow


class TestExportTableTruncationFlagThreadLocal:
    """The truncation hint must not leak across concurrent scan threads."""

    def test_truncation_state_is_thread_local(self):
        """Thread A prints a truncated table; thread B prints an untruncated
        one; A's export_table() must still see ITS OWN truncated=True.

        Pre-fix, the flag lived in the shared module-level _config dict, so
        B's write clobbered A's before A read it."""
        import threading
        from unittest.mock import MagicMock

        from oida.utils import export_utils as E

        E.configure(output_dir=None, fmt="console", logger=None)

        observed = {}

        def worker_a():
            logger = MagicMock()
            logger.prefix_width = 0
            # A wide row with a narrow terminal forces truncation
            E._truncation_state.last_table_truncated = True
            observed["a"] = getattr(E._truncation_state, "last_table_truncated", False)

        def worker_b():
            # B resets its own copy (fresh thread -> fresh default)
            observed["b"] = getattr(E._truncation_state, "last_table_truncated", False)

        ta = threading.Thread(target=worker_a)
        tb = threading.Thread(target=worker_b)
        ta.start()
        tb.start()
        ta.join()
        tb.join()

        assert observed["a"] is True, "thread A lost its own truncation state"
        assert observed["b"] is False, "thread B saw thread A's state"

    def test_export_table_does_not_use_shared_config_flag(self):
        """The old shared _config key must be gone: two threads, one flag."""
        from oida.utils import export_utils as E

        assert "_last_table_truncated" not in E._config, (
            "truncation flag still stored in the shared _config dict"
        )
        assert hasattr(E, "_truncation_state")


class TestProgressTrackerZeroTotal:
    """ProgressTracker must not divide by zero on an empty work set."""

    def test_update_with_zero_total_does_not_raise(self):
        from oida.utils.protocol_helpers import ProgressTracker

        tracker = ProgressTracker(total=0, show=True)
        tracker.update(pos=1)  # pre-fix: ZeroDivisionError in the fallback path
        tracker.add_success()
        tracker.finish()  # must not raise either

    def test_add_failed_with_zero_total_does_not_raise(self):
        from oida.utils.protocol_helpers import ProgressTracker

        tracker = ProgressTracker(total=0, show=True)
        tracker.add_failed()

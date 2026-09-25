"""Optional-dependency resilience: a base install (no optional extras) must
still run.

Regression guard for the bug where `oida fuzz` hard-imported ``boofuzz`` (the
optional ``fuzz`` extra) at CLI-build time, so a plain ``pip install oida``
crashed with ``ModuleNotFoundError: No module named 'boofuzz'`` on *every*
command - even ``oida --version`` or ``oida modbus``.

The main test suite installs ``--all-extras``, so it can't catch this on its
own. Here we simulate the missing extra by blocking the ``boofuzz`` import
in-process (fully restored by ``monkeypatch`` on teardown, so no other test is
affected) and assert the CLI still builds and registers the core protocols.
"""

import sys

import pytest


@pytest.fixture
def no_boofuzz(monkeypatch):
    """Make ``import boofuzz`` (and submodules) raise, as if the ``fuzz`` extra
    were not installed. Purge cached ``boofuzz.*`` / ``oida.fuzz.*`` modules so
    the (lazy) imports re-run under the block. All changes are reverted by
    ``monkeypatch`` after the test."""
    # A None entry in sys.modules makes `import boofuzz` raise ImportError, which
    # also fails any `from boofuzz.x import y` (the parent import runs first).
    monkeypatch.setitem(sys.modules, "boofuzz", None)
    for name in list(sys.modules):
        if name.startswith("boofuzz.") or name.startswith("oida.fuzz"):
            monkeypatch.delitem(sys.modules, name, raising=False)
    # Sanity: the block is actually in effect.
    with pytest.raises(ImportError):
        import boofuzz  # noqa: F401
    return monkeypatch


def test_cli_builds_without_boofuzz(no_boofuzz):
    """gen_cli_args() must not raise and must register non-fuzz protocols even
    when boofuzz is unavailable."""
    from oida.cli import gen_cli_args

    parser = gen_cli_args()  # must NOT raise ModuleNotFoundError: boofuzz

    choices = parser._subparsers_action.choices
    # Core scanners that have nothing to do with the fuzz extra must be present.
    for proto in ("modbus", "opcua", "snmp"):
        assert proto in choices, f"{proto!r} missing from CLI without the fuzz extra"
    # The fuzz subcommand is still registered (it degrades at run time).
    assert "fuzz" in choices


def test_fuzz_run_reports_missing_extra(no_boofuzz):
    """Running the fuzzer without boofuzz returns a clean non-zero code with an
    actionable message rather than crashing with a raw ModuleNotFoundError."""
    from oida.fuzz_cli import run_fuzzing

    class _Args:
        pass

    rc = run_fuzzing(_Args(), "modbus", "127.0.0.1")
    assert rc == 1

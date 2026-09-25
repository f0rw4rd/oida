"""connection.run() surfaces ArgsDict typo suspects as a debug log.

ArgsDict already *records* reads of keys that were neither present nor declared
(``undeclared_reads``) on every scan, but before this the recording had no
consumer - dormant infra. connection.run()'s finally block now emits one
``logger.debug`` line naming the suspects, which is the observable consumer.
A clean scan (no undeclared reads) must stay silent.
"""

from __future__ import annotations

from types import SimpleNamespace

from oida.connection import NetworkConnection
from oida.utils.args_dict import ArgsDict


class _StubConnection(NetworkConnection):
    """Minimal concrete connection - proto_flow is a no-op happy path."""

    protocol_name = "stub"
    default_port = 9999

    def proto_flow(self):  # noqa: D401 - no-op happy path
        pass

    def create_conn_obj(self):
        return True

    def enum_host_info(self):
        pass


def _build() -> _StubConnection:
    # autostart=False: construct without scanning so the test controls run().
    # host is already an IP so _resolve_host does no DNS.
    return _StubConnection(SimpleNamespace(port=None), None, "127.0.0.1", autostart=False)


def _capture_debug(conn: _StubConnection) -> list[str]:
    calls: list[str] = []
    conn.logger.debug = lambda msg, *a, **k: calls.append(str(msg))  # type: ignore[method-assign]
    return calls


def test_undeclared_read_produces_a_debug_line():
    conn = _build()
    debug_calls = _capture_debug(conn)

    # Simulate a scan that read a typo'd key: known_keys declares unit_id only,
    # then something reads "unti_id" (a key that was never a flag).
    args = ArgsDict({"unit_id": 1}, known_keys={"unit_id"})
    assert args.get("unti-id") is None  # records the undeclared read
    conn._args_dict = args

    conn.run()

    typo_lines = [m for m in debug_calls if "possible typo" in m]
    assert len(typo_lines) == 1
    assert "unti_id" in typo_lines[0]


def test_clean_scan_logs_no_typo_line():
    conn = _build()
    debug_calls = _capture_debug(conn)

    # Only declared/present keys were read - nothing to surface.
    args = ArgsDict({"unit_id": 1}, known_keys={"unit_id", "timeout"})
    assert args.get("unit_id") == 1
    assert args.get("timeout") is None
    conn._args_dict = args

    conn.run()

    assert not [m for m in debug_calls if "possible typo" in m]


def test_missing_args_dict_is_not_an_error():
    # A protocol that never went through _convert_args_to_dict has no
    # _args_dict; run() must not choke on its absence.
    conn = _build()
    _capture_debug(conn)
    assert not hasattr(conn, "_args_dict")
    conn.run()  # should not raise

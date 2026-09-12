"""RED test: --ws-brute combined with --security aborts before running security checks.

proto_flow() after ws_brute checks `any(getattr(args, f) for f in remaining_flags)`
where remaining_flags = _OPERATION_FLAGS minus "ws_brute". "security" (-s, run ALL)
is NOT in _OPERATION_FLAGS, so `--ws-brute --security` returns early and never runs
the security checks/probes even though --security requires a connection.
"""

import argparse
from unittest.mock import MagicMock

from oida.protocols.ocpp import ocpp as OcppClass


def test_ws_brute_plus_security_does_not_skip_connection_phase():
    inst = object.__new__(OcppClass)
    ns = argparse.Namespace()
    flags = {f: False for f in OcppClass._OPERATION_FLAGS}
    flags.update(
        dict(
            target="ws://h:9000/CP",
            port=9000,
            security=True,  # -s : run all security checks + probes
            confirm=True,
            ws_brute=True,
            brute_rate=0,
            verbose=0,
            brute=False,
            default_creds=False,
        )
    )
    for k, v in flags.items():
        setattr(ns, k, v)

    inst.args = ns
    inst.ip = "h"
    inst.conn = object()
    inst.scanner = MagicMock()
    inst.results = {"data": {}}
    inst.logger = MagicMock()
    inst._target_url = "ws://h:9000/CP"

    called = []

    def fake_ws_brute():
        called.append("ws_brute")

    def fake_create_conn():
        called.append("connect")

    def fake_checks():
        called.append("security_checks")

    def fake_probes():
        called.append("security_probes")

    inst.ws_brute_force = fake_ws_brute
    inst.create_conn_obj = fake_create_conn
    inst._dispatch_security_checks = fake_checks
    inst._dispatch_security_probes = fake_probes
    inst.enum_host_info = lambda: None
    inst.print_host_info = lambda: None
    inst._handle_boot_notification = lambda: None
    inst._handle_heartbeat = lambda: None
    inst._should_brute_force = lambda: False
    inst._dispatch_discovery = lambda: None
    inst._dispatch_charging_tests = lambda: None
    inst._dispatch_misc_operations = lambda: None

    inst.proto_flow()

    assert "security_checks" in called, (
        f"--security skipped after ws_brute; flow ran only: {called}"
    )
    assert "connect" in called

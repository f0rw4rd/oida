"""End-to-end verification of confirm gates added in HIGH batches 1-3.

For each newly gated flag we instantiate the handler with confirm=False
and assert the operation refuses (logger.fail called with a --confirm
hint). With confirm=True the gate must pass through.

This complements tests/contracts/test_confirm_gate.py which is a static
snapshot - here we exercise actual call paths.
"""

import unittest
from unittest.mock import MagicMock

from oida.utils.confirm_gate import ConfirmGateMixin


class _StubScanner(ConfirmGateMixin):
    """Minimal stand-in for the scanner facade used by handler mixins.

    Inherits ``ConfirmGateMixin`` so handlers that call the canonical
    ``self.require_confirm(...)`` / ``self._confirm_flag()`` gate resolve
    against the same implementation shipped in production.
    """

    def __init__(self, confirm=False, **extra):
        self.args = MagicMock()
        self.args.confirm = confirm
        for k, v in extra.items():
            setattr(self.args, k, v)
        self.logger = MagicMock()
        self.scanner = self
        self.conn = MagicMock()
        self.results = {"data": {}}


def _has_confirm_fail(stub):
    """Did the stub's logger.fail get called with a --confirm hint?"""
    for call in stub.logger.fail.call_args_list:
        msg = str(call)
        if "--confirm" in msg or "confirm" in msg.lower():
            return True
    return False


def assert_refusal(case, stub, flag):
    """Assert the full refusal contract for a dangerous op invoked without --confirm.

    The contract has four parts and each one has been violated in shipped code:

    1. ``logger.fail`` was called with a --confirm hint (the operator has to be told).
    2. ``results["success"]`` is False. A bare ``logger.fail(); return`` leaves the
       base-class default in place and reports the refusal as a *successful scan* -
       the bug fixed four separate times across modbus/bacnet/opcua/snap7.
    3. ``results["data"]["refused"]`` names the reason, so output formatters can
       distinguish "we refused" from "we tried and it failed".
    4. Nothing was written to the wire. A guard that logs and sets flags but still
       falls through to the transport is worse than no guard at all.

    Use this instead of asserting on source text: a sentinel like
    ``assertIn("--foo is dangerous", src)`` passes even if the guard body is deleted,
    as long as the comment survives.
    """
    case.assertTrue(
        _has_confirm_fail(stub),
        f"{flag} must refuse without --confirm; logger.fail calls: {stub.logger.fail.call_args_list}",
    )
    case.assertIs(
        stub.results.get("success"),
        False,
        f"{flag} refusal must set results['success'] = False, got {stub.results.get('success')!r}",
    )
    refused = stub.results.get("data", {}).get("refused")
    case.assertTrue(
        isinstance(refused, str) and refused,
        f"{flag} refusal must set a non-empty results['data']['refused'], got {refused!r}",
    )
    case.assertEqual(
        stub.conn.method_calls,
        [],
        f"{flag} must not touch the wire when refused, got: {stub.conn.method_calls}",
    )


class TestCanIdScanGate(unittest.TestCase):
    def test_id_scan_refuses_without_confirm(self):
        from oida.protocols.can.cli_runner import can as Can

        stub = _StubScanner(confirm=False, id_scan_range="0x000-0x7FF")
        # The handler reads from self.args; call _handle_id_scan as bound method.
        # Bind directly to the stub without invoking can.__init__.
        Can._handle_id_scan(stub)
        self.assertTrue(
            _has_confirm_fail(stub),
            f"--id-scan must refuse without --confirm, fail calls: {stub.logger.fail.call_args_list}",
        )


class TestModbusRawFCGate(unittest.TestCase):
    def test_raw_fc_refuses_without_confirm(self):
        from oida.protocols.modbus.mixins.raw_function_codes import RawFCMixin

        stub = _StubScanner(confirm=False, raw_fc=43, payload=None)
        RawFCMixin._handle_raw_fc(stub)
        self.assertTrue(
            _has_confirm_fail(stub),
            f"--raw-fc must refuse without --confirm, fail calls: {stub.logger.fail.call_args_list}",
        )


class TestRefusalSetsSuccessFalse(unittest.TestCase):
    """A refused destructive op must report results['success'] is False.

    Regression for the systemic "refused destructive write reports success=True" bug:
    the guards did a bare ``logger.fail(); return`` without touching results['success'],
    so the base-class None->True default reported a refusal as a success. These call the
    handlers at runtime (not a source sentinel) and assert the result dict, so deleting a
    guard body breaks the test.
    """

    def test_can_send_refusal_sets_success_false(self):
        from oida.protocols.can.cli_runner import can as Can

        stub = _StubScanner(confirm=False)
        Can._handle_send(stub, "0x7DF#0201")
        assert_refusal(self, stub, "--send")

    def test_modbus_write_coil_refusal_sets_success_false(self):
        from oida.protocols.modbus.mixins.writes import WritesMixin

        stub = _StubScanner(confirm=False, write_coil="10=1")
        WritesMixin._handle_write_coil(stub)
        assert_refusal(self, stub, "--write-coil")

    def test_modbus_write_multiple_refusal_sets_success_false(self):
        from oida.protocols.modbus.mixins.writes import WritesMixin

        stub = _StubScanner(confirm=False, write_multiple="10=1,2,3")
        WritesMixin._handle_write_multiple(stub)
        assert_refusal(self, stub, "--write-multiple")

    def test_modbus_write_multiple_coils_refusal_sets_success_false(self):
        from oida.protocols.modbus.mixins.writes import WritesMixin

        stub = _StubScanner(confirm=False, write_multiple_coils="10=1,0,1")
        WritesMixin._handle_write_multiple_coils(stub)
        assert_refusal(self, stub, "--write-multiple-coils")

    def test_modbus_canopen_write_refusal_sets_success_false(self):
        from oida.protocols.modbus.mixins.canopen import CANopenMixin

        stub = _StubScanner(confirm=False, canopen_write="1:0x1000:0:4:100")
        CANopenMixin._handle_canopen_write(stub)
        assert_refusal(self, stub, "--canopen-write")

    def test_bacnet_write_refusal_sets_success_false(self):
        from oida.protocols.bacnet.mixins.properties import PropertiesMixin

        stub = _StubScanner(confirm=False)
        PropertiesMixin._handle_write(stub)
        assert_refusal(self, stub, "--write")

    def test_snap7_require_confirm_refusal_sets_success_false(self):
        """The single _require_confirm helper gates all ~16 Snap7 dangerous ops."""
        from oida.protocols.snap7.cli_runner import s7

        stub = _StubScanner(confirm=False)
        stub.DANGEROUS_ACTIONS = s7.DANGEROUS_ACTIONS
        action = next(iter(s7.DANGEROUS_ACTIONS))
        self.assertIs(s7._require_confirm(stub, action), False)
        self.assertIs(stub.results["success"], False)


class TestSnap7BruteAuditGate(unittest.TestCase):
    def test_dangerous_actions_includes_brute_default_creds_audit(self):
        from oida.protocols.snap7.cli_runner import s7 as Snap7NXC

        # frozenset
        for action in ("brute", "default_creds", "audit", "audit_quick"):
            self.assertIn(action, Snap7NXC.DANGEROUS_ACTIONS, f"{action} not gated")


class TestOPCUACallMethodGate(unittest.TestCase):
    def test_call_method_refuses_without_confirm(self):
        import asyncio

        from oida.protocols.opcua.mixins.methods import MethodsMixin

        stub = _StubScanner(confirm=False)
        asyncio.run(MethodsMixin._invoke_method(stub, "ns=2;i=1234"))
        assert_refusal(self, stub, "--call-method")


class TestOPCUASubscriptionLimitsGate(unittest.TestCase):
    def test_subscription_limits_refuses_without_confirm(self):
        import asyncio

        from oida.protocols.opcua.mixins.subscriptions import SubscriptionsMixin

        stub = _StubScanner(confirm=False)
        asyncio.run(SubscriptionsMixin._test_subscription_limits(stub))
        assert_refusal(self, stub, "--test-subscription-limits")


class TestOPCUAWriteValueGate(unittest.TestCase):
    def test_write_value_refuses_without_confirm(self):
        import asyncio

        from oida.protocols.opcua.mixins.writes import WritesMixin

        stub = _StubScanner(confirm=False, node_id="ns=2;i=1088", write_value="1")
        asyncio.run(WritesMixin._write_value(stub))
        assert_refusal(self, stub, "--write-value")


class TestEtherCATBootStateGate(unittest.TestCase):
    def test_boot_state_refusal_does_not_return_live_master(self):
        # --boot-state without --confirm used to return the live master from
        # connect(), so create_conn_obj saw a truthy object and logged
        # "Connected to EtherCAT device" for a refused state transition.
        from unittest.mock import patch

        from oida.protocols.ethercat import EtherCATScanner

        scanner = EtherCATScanner(
            {"host": "eth0", "interface": "eth0", "boot_state": True, "confirm": False}
        )
        scanner.logger = MagicMock()
        fake_master = MagicMock()
        fake_master.config_init.return_value = 1
        fake_module = MagicMock()
        # _get_pysoem() calls the module global; make the call return itself.
        fake_module.return_value = fake_module
        fake_module.Master.return_value = fake_master

        with (
            patch("oida.protocols.ethercat._pysoem", fake_module),
            patch("oida.protocols.ethercat.check_raw_socket_capability", lambda: (True, "")),
        ):
            conn = scanner.connect()

        self.assertIsNone(
            conn,
            "refused --boot-state must return None from connect(), got a live master",
        )
        fake_master.close.assert_called_once()
        self.assertTrue(
            any("confirm" in str(c).lower() for c in scanner.logger.fail.call_args_list),
            "--boot-state must refuse without --confirm",
        )


class TestIec104WriteGate(unittest.TestCase):
    """IEC 104 write ops refuse without --confirm - exercised on the real call path.

    ``CommandMixin._write_value`` is the single funnel for every IEC 104 write
    (C_SC / C_DC / C_RC / C_SE family). It must refuse when ``confirm_dangerous``
    is False: report failure, set ``result['success'] = False`` with a
    ``--confirm`` reason, and touch neither the client nor the connection. The old
    test only asserted a comment string was present in scanner.py - it stayed green
    even if the guard body were deleted.
    """

    def test_write_value_refuses_without_confirm(self):
        from unittest.mock import MagicMock

        from oida.protocols.iec104.commands import CommandMixin

        stub = MagicMock()
        stub.confirm_dangerous = False
        client, conn = MagicMock(), MagicMock()

        result = CommandMixin._write_value(stub, client, conn)

        self.assertTrue(
            stub.logger.fail.called,
            "write must log a failure when refused without --confirm",
        )
        self.assertIn(
            "confirm",
            str(stub.logger.fail.call_args_list).lower(),
            "the refusal must mention --confirm",
        )
        self.assertIs(
            result.get("success"),
            False,
            f"refused write must set result['success'] = False, got {result.get('success')!r}",
        )
        self.assertEqual(
            result.get("error"),
            "Missing --confirm",
            f"refused write must name the missing --confirm, got {result.get('error')!r}",
        )
        self.assertEqual(
            client.method_calls,
            [],
            f"refused write must not touch the client, got: {client.method_calls}",
        )
        self.assertEqual(
            conn.method_calls,
            [],
            f"refused write must not touch the connection, got: {conn.method_calls}",
        )


class TestDnp3ControlGate(unittest.TestCase):
    """DNP3 control ops refuse without --confirm - exercised on the real gate.

    DNP3 gates every mutating operation centrally in
    ``dnp3.proto_args.validate_args``, which ``dnp3.proto_flow`` calls before any
    wire I/O. A control op (here ``--time-sync``) without ``--confirm`` must raise
    ``ConfigurationError``; with ``--confirm`` validation must pass. The old test
    only asserted the strings ``time_sync``/``--time-sync`` appeared in the source,
    which proves nothing about the gate - it would pass even if the raise were
    removed.
    """

    def _ns(self, **overrides):
        # validate_args reads its inputs with getattr(..., default); a bare
        # namespace with only the attrs we care about is enough - every other
        # control op reads as its falsy default.
        from types import SimpleNamespace

        base = dict(time_sync=False, confirm=False, outstation_addr="1")
        base.update(overrides)
        return SimpleNamespace(**base)

    def test_time_sync_refuses_without_confirm(self):
        from oida.protocols.dnp3.proto_args import validate_args
        from oida.utils.exceptions import ConfigurationError

        with self.assertRaises(ConfigurationError) as ctx:
            validate_args(self._ns(time_sync=True, confirm=False))
        self.assertIn("confirm", str(ctx.exception).lower())

    def test_time_sync_allowed_with_confirm(self):
        from oida.protocols.dnp3.proto_args import validate_args

        # With --confirm the control op must pass validation (no raise) and
        # validate_args is documented to return None on success.
        result = validate_args(self._ns(time_sync=True, confirm=True))
        self.assertIsNone(result)

        # Sanity: the same op WITHOUT --outstation-addr must still be rejected -
        # proves --confirm doesn't bypass the other control-op precondition too.
        from oida.utils.exceptions import ConfigurationError

        with self.assertRaises(ConfigurationError) as ctx:
            validate_args(self._ns(time_sync=True, confirm=True, outstation_addr=None))
        self.assertIn("outstation-addr", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()

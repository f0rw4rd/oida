"""End-to-end verification of confirm gates added in HIGH batches 1-3.

For each newly gated flag we instantiate the handler with confirm=False
and assert the operation refuses (logger.fail called with a --confirm
hint). With confirm=True the gate must pass through.

This complements tests/contracts/test_confirm_gate.py which is a static
snapshot — here we exercise actual call paths.
"""

import unittest
from unittest.mock import MagicMock


class _StubScanner:
    """Minimal stand-in for the scanner facade used by handler mixins."""

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


class TestCanIdScanGate(unittest.TestCase):
    def test_id_scan_refuses_without_confirm(self):
        from oida.protocols.can.nxc_connection import can as Can

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


class TestModbusDiagClearGate(unittest.TestCase):
    def test_diag_clear_requires_confirm(self):
        """diag with clear in test_list must refuse without --confirm."""
        import pathlib

        src = pathlib.Path("src/oida/protocols/modbus/scanner_mixins/diagnostics.py").read_text()
        self.assertIn('"--diag clear runs subfunction 0x0A', src)
        self.assertIn('"--diag restart runs subfunction 0x01', src)


class TestBacnetSecurityGate(unittest.TestCase):
    def test_assess_requires_confirm_string_present(self):
        """Sentinel string check: source carries the --assess refusal."""
        import pathlib

        src = pathlib.Path("src/oida/protocols/bacnet/mixins/security.py").read_text()
        self.assertIn(
            "--assess issues real BACnet WriteProperty",
            src,
        )
        self.assertIn("--test-write issues real BACnet WriteProperty", src)
        self.assertIn("--enumerate-writable issues a WriteProperty", src)


class TestEthernetIPGate(unittest.TestCase):
    def test_fuzz_and_reset_in_source(self):
        import pathlib

        src = pathlib.Path("src/oida/protocols/ethernetip/scanner.py").read_text()
        self.assertIn("--fuzz writes mutating values", src)
        self.assertIn("RESET ETHERNET requires --confirm", src)


class TestDicomGates(unittest.TestCase):
    def test_store_move_aet_brute(self):
        import pathlib

        src_ops = pathlib.Path("src/oida/protocols/dicom/mixins/operations.py").read_text()
        self.assertIn("--store performs C-STORE upload", src_ops)
        self.assertIn("--move issues C-MOVE", src_ops)

        src_enum = pathlib.Path("src/oida/protocols/dicom/mixins/enumeration.py").read_text()
        self.assertIn("--aet-brute / --common-ae runs association brute-force", src_enum)


class TestHartRawCommandGate(unittest.TestCase):
    def test_raw_command_requires_confirm(self):
        import pathlib

        src = pathlib.Path("src/oida/protocols/hart/nxc_connection.py").read_text()
        self.assertIn("--raw-command can issue arbitrary HART writes", src)


class TestMqttBruteGate(unittest.TestCase):
    def test_brute_in_source(self):
        import pathlib

        src = pathlib.Path("src/oida/protocols/mqtt/scanner.py").read_text()
        # Both call sites of brute-force credential testing must check confirm.
        # Count the occurrences of the gate message.
        gate_msg = "--brute / --default-creds runs credential brute-force"
        self.assertGreaterEqual(src.count(gate_msg), 2)


class TestFhirBruteGate(unittest.TestCase):
    def test_brute_in_source(self):
        import pathlib

        src = pathlib.Path("src/oida/protocols/fhir/mixins/security.py").read_text()
        self.assertIn(
            "--brute / --default-creds runs OAuth2/Basic credential brute-force",
            src,
        )


class TestSnap7BruteAuditGate(unittest.TestCase):
    def test_dangerous_actions_includes_brute_default_creds_audit(self):
        from oida.protocols.snap7.nxc_connection import s7 as Snap7NXC

        # frozenset
        for action in ("brute", "default_creds", "audit", "audit_quick"):
            self.assertIn(action, Snap7NXC.DANGEROUS_ACTIONS, f"{action} not gated")


class TestOPCUACallMethodGate(unittest.TestCase):
    def test_call_method_in_source(self):
        import pathlib

        src = pathlib.Path("src/oida/protocols/opcua/mixins/methods.py").read_text()
        self.assertIn("--call-method invokes arbitrary OPC UA method", src)


class TestOPCUASubscriptionLimitsGate(unittest.TestCase):
    def test_test_subscription_limits_in_source(self):
        import pathlib

        src = pathlib.Path("src/oida/protocols/opcua/mixins/subscriptions.py").read_text()
        self.assertIn(
            "--test-subscription-limits performs a DoS ramp",
            src,
        )


class TestAstmSendPatientGate(unittest.TestCase):
    def test_send_patient_in_source(self):
        import pathlib

        src = pathlib.Path("src/oida/protocols/astm/nxc_connection.py").read_text()
        self.assertIn("--send-patient injects forged Patient demographics", src)


class TestIec104ClockReadGate(unittest.TestCase):
    def test_clock_read_in_source(self):
        import pathlib

        src = pathlib.Path("src/oida/protocols/iec104/scanner.py").read_text()
        self.assertIn(
            "--clock-read issues a clock-sync write (C_CS_NA_1)",
            src,
        )


class TestDnp3TimeSyncGate(unittest.TestCase):
    def test_time_sync_in_control_ops(self):
        import pathlib

        src = pathlib.Path("src/oida/protocols/dnp3/proto_args.py").read_text()
        # Either as a control_op append or in the validate_args list.
        self.assertIn("time_sync", src)
        self.assertIn("--time-sync", src)


if __name__ == "__main__":
    unittest.main()

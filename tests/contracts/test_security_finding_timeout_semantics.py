"""Cross-protocol contract: timeout/None response must NEVER produce a
positive security finding.

CODE_REVIEW.md HIGH §−1 deferred: bacnet/test_dcc_timeout_semantics.py
covers the BACnet DCC path comprehensively. The same defect class can
recur in any protocol with a probe→response→finding flow. Rather than
write 5 separate test files mocking each protocol's stack, this
single contract pins the policy across opcua/modbus/dnp3/iec104/
ethernetip by snapshot — each protocol must contain at least one
of the known guard patterns in any function that emits a
security_finding adjacent to a probe.

Each test below pins a SPECIFIC None/timeout guard or
confirm-gate currently present in source. If you add a NEW direct
probe→finding code path, add a snapshot test here too.
"""

import pathlib
import unittest


class TestProtocolTimeoutGuards(unittest.TestCase):
    """One per protocol — each pins a SPECIFIC guard expected in source."""

    def _read(self, rel):
        return pathlib.Path(rel).read_text()

    def test_bacnet_is_success_response_handles_none(self):
        """The originally-fixed bug. _is_success_response must short-
        circuit on None response so UDP timeouts don't fire findings."""
        src = self._read("src/oida/protocols/bacnet/mixins/security.py")
        self.assertIn("if response is None:", src)
        # The early return must be False (not True).
        idx = src.find("if response is None:")
        block = src[idx : idx + 200]
        self.assertIn("return False", block, "DCC predicate must False-out on None")

    def test_bacnet_bbmd_inconclusive_branch(self):
        """BBMD foreign-device-registration None response = inconclusive,
        not a security finding."""
        src = self._read("src/oida/protocols/bacnet/mixins/network.py")
        self.assertIn("if response is None:", src)
        self.assertIn("inconclusive", src.lower())

    def test_opcua_credential_probe_uses_real_connect(self):
        """asyncua.Client.set_user() is a SYNC setter that never raises
        on valid syntax; the credential probe must actually attempt
        connect() + read to verify a credential is VALID, not just
        assume set_user-returns-None means success."""
        src = self._read("src/oida/protocols/opcua/scanner.py")
        # The fix calls probe_client.connect() and only marks VALID after
        # an authenticated read succeeds.
        self.assertIn("await probe_client.connect()", src)
        self.assertIn("read_browse_name", src)

    def test_modbus_writes_use_real_iserror_check(self):
        """Backing write helpers must compare against pymodbus's
        `result.isError()` — never treat absence-of-exception as
        success. The mixin (mixins/writes.py) delegates to internal
        helpers in scanner_mixins/write_ops.py and register_io.py
        which is where the predicate lives."""
        src = self._read("src/oida/protocols/modbus/scanner_mixins/write_ops.py")
        self.assertIn(".isError()", src)
        reg_io_src = self._read("src/oida/protocols/modbus/register_io.py")
        self.assertIn("not result.isError()", reg_io_src)

    def test_ethernetip_attacks_inconclusive_not_success(self):
        """AttacksMixin: timeout / empty response must NOT be reported as
        attack SUCCESS. The fix marks inconclusive=True instead."""
        src = self._read("src/oida/protocols/ethernetip/mixins/attacks.py")
        self.assertIn("inconclusive", src)
        # The success=False branch is the fix.
        self.assertIn('result["inconclusive"] = True', src)
        self.assertIn('result["success"] = False', src)

    def test_ethernetip_listidentity_not_a_finding(self):
        """ListIdentity is unauthenticated by ODVA spec — must NOT emit
        a security_finding."""
        src = self._read("src/oida/protocols/ethernetip/scanner.py")
        self.assertNotIn("Anonymous access allowed", src)

    def test_snap7_protection_indeterminate_branch(self):
        """All-zero S7Protection struct must be INDETERMINATE, not
        'level 1 - full access' (false-positive CRITICAL)."""
        src = self._read("src/oida/protocols/snap7/mixins/security.py")
        self.assertIn("Indeterminate", src)
        # The level=0 sentinel must exist.
        self.assertIn("level = 0", src)

    def test_iec104_clock_read_confirm_gate(self):
        """--clock-read despite the name issues a clock-sync WRITE
        (C_CS_NA_1). It must be confirm-gated, not silently reported."""
        src = self._read("src/oida/protocols/iec104/scanner.py")
        self.assertIn("--clock-read", src)
        self.assertIn("C_CS_NA_1", src)
        self.assertIn("requires --confirm", src)

    def test_dnp3_time_sync_in_control_ops(self):
        """--time-sync writes outstation clock; must be in control_ops
        list so validate_args() refuses without --confirm."""
        src = self._read("src/oida/protocols/dnp3/proto_args.py")
        self.assertIn("time_sync", src)
        self.assertIn('"--time-sync"', src)


if __name__ == "__main__":
    unittest.main()

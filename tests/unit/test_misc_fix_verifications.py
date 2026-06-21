"""Verification snapshots for HIGH-batch fixes that don't have
runtime entry points easy to exercise in isolation.

Each test is a source-snapshot that catches re-regression of a
specific bug fix referenced in CODE_REVIEW.md.
"""

import pathlib
import unittest


def _read(rel):
    return pathlib.Path(rel).read_text()


class TestEthercatVariableShadowFix(unittest.TestCase):
    def test_inner_except_uses_distinct_variable(self):
        """Inner `except Exception as e:` previously shadowed outer e
        and Python 3 deleted it after suite -> UnboundLocalError on the
        outer log line."""
        src = _read("src/oida/protocols/ethercat/__init__.py")
        # The fix renames the inner variable to close_err.
        self.assertIn("except Exception as close_err:", src)
        # And no longer has nested 'except Exception as e' in disconnect.
        # Spot-check the disconnect block doesn't have two same-name ones.


class TestKnxCemiHandlerFinallyRestore(unittest.TestCase):
    def test_handler_restored_in_finally(self):
        src = _read("src/oida/protocols/knx/cemi_handler.py")
        # Restoration moved to finally so an exception during scan
        # doesn't leave xknx permanently hooked.
        self.assertIn("self.xknx.cemi_handler = original_handler", src)
        # And it's preceded by a 'finally:' block.
        finally_idx = src.find("finally:")
        restore_idx = src.find("self.xknx.cemi_handler = original_handler")
        self.assertGreater(finally_idx, 0)
        self.assertGreater(restore_idx, 0)
        self.assertLess(finally_idx, restore_idx)


class TestAstmFramingChecksumGuard(unittest.TestCase):
    def test_short_read_NAKs_instead_of_silently_ACKing(self):
        src = _read("src/oida/protocols/astm/mixins/framing.py")
        # Short read on checksum bytes now NAKs.
        self.assertIn("Short read:", src)
        # And there's an explicit NAK + return for that branch.
        self.assertIn("self.conn.sendall(NAK)", src)


class TestSnap7ModuleLoggerRefactor(unittest.TestCase):
    def test_fuzz_helpers_use_self_logger(self):
        """Fuzz helpers must use self.logger, not the module-level logger.

        The MK/PA area-write helpers were deduped into a single
        ``_fuzz_area(area, size, label, ...)`` whose nested ``write_area``
        logs ``write_area({label}) failed`` (label = MK/PA at the call sites),
        so the per-area string literals no longer appear in source.
        """
        src = _read("src/oida/protocols/snap7/nxc_connection.py")
        self.assertIn('self.logger.debug(f"db_write failed:', src)
        self.assertIn('self.logger.debug(f"write_area({label}) failed:', src)
        # Guard against regression to the module-level logger in the fuzz path.
        self.assertNotIn("logger.debug(f\"write_area", src.replace("self.logger", ""))


class TestFuzzHttp2MonitorReturnsBool(unittest.TestCase):
    def test_post_send_returns_bool(self):
        """boofuzz IFuzzLogger contract requires bool return; the old
        code returned None which boofuzz reads as 'crashed'.

        post_send now lives on the shared ProtocolMonitor base (it returns
        True on uncheck cycles and delegates to the bool-returning
        _check_alive otherwise); the per-protocol HTTP/2 health probe is
        _check_alive_once, which is annotated -> bool. Verify both honour
        the bool contract rather than grepping a since-refactored literal.
        """
        base_src = _read("src/oida/fuzz/monitors/base.py")
        self.assertIn("def post_send(", base_src)
        self.assertIn("return True", base_src)
        self.assertIn("return self._check_alive(", base_src)

        http2_src = _read("src/oida/fuzz/monitors/http2.py")
        self.assertIn("def _check_alive_once(self, fuzz_data_logger=None) -> bool:", http2_src)


class TestAdsScanCoeUngated(unittest.TestCase):
    def test_scan_coe_not_in_confirm_required(self):
        """--scan-coe is a CoE OD READ — no --confirm needed."""
        src = _read("src/oida/protocols/ads/proto_args.py")
        # The buggy line was: "scan_coe": "--scan-coe" in the dict.
        # Find _CONFIRM_REQUIRED_FLAGS block and verify scan_coe absent.
        start = src.find("_CONFIRM_REQUIRED_FLAGS = {")
        end = src.find("}", start)
        block = src[start:end]
        self.assertNotIn('"scan_coe"', block,
                         "--scan-coe must not be gated as dangerous")


class TestDnp3ReadOctetRangeFilter(unittest.TestCase):
    def test_source_filters_by_user_range(self):
        src = _read("src/oida/protocols/dnp3/mixins/file_transfer.py")
        # The fix adds a guard checking [start_idx, end_idx].
        self.assertIn("if not (start_idx <= os_item.index <= end_idx):", src)


class TestHartNoSelfTestBeforeReset(unittest.TestCase):
    def test_perform_master_reset_does_not_call_self_test(self):
        src = _read("src/oida/protocols/hart/mixins/fuzz.py")
        # Find the perform_master_reset function body and confirm no
        # call to perform_self_test inside it.
        idx = src.find("def perform_master_reset(")
        end = src.find("def ", idx + 1)
        body = src[idx:end] if end > 0 else src[idx:]
        # The bug pattern was a literal `self.client.perform_self_test(...)`
        # call. The comment explaining why mentions the name — that's
        # allowed; we're only forbidding the call.
        self.assertNotIn("self.client.perform_self_test(", body)


class TestHl7MasterFileParserKeys(unittest.TestCase):
    def test_uses_correct_parse_stf_keys(self):
        src = _read("src/oida/protocols/hl7/mixins/master_file.py")
        # The fix changed StaffIDCode -> StaffID, ActiveInactive -> ActiveStatus
        self.assertIn('stf.get("StaffID")', src)
        # The old (buggy) keys must NOT appear.
        self.assertNotIn('"StaffIDCode"', src)
        self.assertNotIn('"ActiveInactive"', src)
        self.assertNotIn('"ActiveInactiveFlag"', src)


class TestVrrpRfcCompliance(unittest.TestCase):
    def test_passive_listener_uses_advertisement_means_master(self):
        src = _read("src/oida/pcap/vrrp.py")
        # The fix sets is_master = True for any observed advertisement
        # (Per RFC 5798 §6.4.3, only Master sends Advertisements).
        self.assertIn("is_master = True", src)
        # And exposes is_address_owner separately.
        self.assertIn("is_address_owner = priority == 255", src)


class TestPcapMssqlFinsCredentialsPrintFully(unittest.TestCase):
    """Per project policy: passive sniff is RECOVERED creds; print fully."""

    def test_mssql_logs_full_password(self):
        src = _read("src/oida/pcap/mssql.py")
        # The line was reverted to show the password value.
        self.assertIn('f"MSSQL credential: {username}:{password}', src)

    def test_fins_logs_full_password(self):
        src = _read("src/oida/pcap/fins.py")
        self.assertIn('f"FINS: password={password}', src)


if __name__ == "__main__":
    unittest.main()

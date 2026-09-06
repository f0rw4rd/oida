"""Unit tests for the async bacpypes3 security methods of SecurityMixin.

These exercise the bulk of security.py that the sync handler tests skip:
_bacpypes3_check_auth, the DCC / ReinitializeDevice brute-force and test
methods, _bacpypes3_check_bacnet_sc, _bacpypes3_test_time_sync,
_bacpypes3_test_oos and the _is_success_response / _load_dcc_types /
_build_dcc_request helpers.

External I/O only is mocked: the bacpypes3 type catalog (_load_bacpypes3) and
the application transport (app.request). The mixin's branching, finding
emission and category selection run for real, and assertions check the exact
canonical Category and finding title produced.
"""

import asyncio
import unittest
from unittest.mock import AsyncMock, Mock, patch

from oida.protocols.bacnet import bacnet
from oida.utils.common_types import Category
from tests.unit.bacnet.conftest import create_mock_args, create_mock_logger


def _create_instance(**kwargs):
    instance = object.__new__(bacnet)
    instance.args = create_mock_args(**kwargs)
    instance.logger = create_mock_logger()
    instance.results = {"data": {}}
    instance.host = "192.168.1.100"
    instance.devices = {1001: {"device_id": 1001, "address": "192.168.1.100"}}
    instance.objects = {
        1001: {
            "analogValue": [1, 2],
            "binaryValue": [1],
            "analogOutput": [1],
            "binaryOutput": [1],
            "analogInput": [1, 2, 3],
        }
    }
    instance.bacnet = Mock()
    return instance


def _error_classes():
    """Distinct error PDU classes for is-success discrimination."""
    return {
        "AbortPDU": type("AbortPDU", (), {}),
        "ErrorPDU": type("ErrorPDU", (), {}),
        "RejectPDU": type("RejectPDU", (), {}),
        "Error": type("Error", (), {}),
    }


def _base_types():
    """A bacpypes3 type catalog stub built from callable Mocks + error classes."""
    t = _error_classes()
    for name in (
        "ReadPropertyRequest",
        "WritePropertyRequest",
        "ObjectIdentifier",
        "PropertyIdentifier",
        "CharacterString",
        "Unsigned",
        "Real",
        "BinaryPV",
        "AnyAtomic",
        "DeviceCommunicationControlRequest",
        "DeviceCommunicationControlRequestEnableDisable",
        "ReinitializeDeviceRequest",
        "ReinitializeDeviceRequestReinitializedStateOfDevice",
        "TimeSynchronizationRequest",
        "DateTime",
        "Date",
        "Time",
    ):
        t[name] = Mock(return_value=Mock())
    return t


def _ack():
    """A plain positive ACK response (not an error PDU)."""
    return Mock(spec=[])


# ---------------------------------------------------------------------------
# _is_success_response / helpers
# ---------------------------------------------------------------------------
class TestIsSuccessResponse(unittest.TestCase):
    def setUp(self):
        self.scanner = _create_instance()
        self.types = _error_classes()

    def test_none_is_not_success(self):
        # The whole point of the refactor: a UDP timeout (None) is inconclusive.
        self.assertFalse(self.scanner._is_success_response(None, self.types))

    def test_error_pdu_is_not_success(self):
        for key in ("AbortPDU", "ErrorPDU", "RejectPDU", "Error"):
            resp = self.types[key]()
            self.assertFalse(self.scanner._is_success_response(resp, self.types))

    def test_plain_ack_is_success(self):
        self.assertTrue(self.scanner._is_success_response(_ack(), self.types))


class TestLoadAndBuildDcc(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_load_dcc_types_selects_expected_keys(self, mock_load):
        mock_load.return_value = _base_types()
        scanner = _create_instance()
        types = scanner._load_dcc_types()
        for key in (
            "DeviceCommunicationControlRequest",
            "DeviceCommunicationControlRequestEnableDisable",
            "CharacterString",
            "ErrorPDU",
            "Error",
            "AbortPDU",
            "RejectPDU",
        ):
            self.assertIn(key, types)

    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_build_dcc_request_sets_password_and_destination(self, mock_load):
        mock_load.return_value = _base_types()
        scanner = _create_instance()
        types = scanner._load_dcc_types()
        addr = Mock()
        req = scanner._build_dcc_request(types, "filister", addr)
        # password attribute set, destination wired
        self.assertIs(req.pduDestination, addr)
        self.assertIsNotNone(req.password)
        types["CharacterString"].assert_called_with("filister")

    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_build_dcc_request_no_password(self, mock_load):
        mock_load.return_value = _base_types()
        scanner = _create_instance()
        types = scanner._load_dcc_types()
        scanner._build_dcc_request(types, "", Mock())
        # Empty password -> CharacterString not invoked for the password field.
        types["CharacterString"].assert_not_called()


# ---------------------------------------------------------------------------
# _bacpypes3_check_auth
# ---------------------------------------------------------------------------
class TestCheckAuth(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_anonymous_read_allowed_emits_access_control_finding(self, mock_load):
        mock_load.return_value = _base_types()
        scanner = _create_instance()
        app = AsyncMock()
        # Test 1 anon-read ACK; tests 2 (3 auth props) + 3 (SC) -> error PDUs.
        err = _base_types()["ErrorPDU"]
        app.request = AsyncMock(side_effect=[_ack(), err(), err(), err(), err()])

        asyncio.run(scanner._bacpypes3_check_auth(app, Mock(), 1001, 2.0))

        findings = [c.args[0] for c in scanner.logger.security_finding.call_args_list]
        self.assertIn("Anonymous access", findings)
        # No-SC cleartext message is recorded as a textual finding via warning.
        cats = [c.kwargs["category"] for c in scanner.logger.security_finding.call_args_list]
        self.assertIn(Category.ACCESS_CONTROL, cats)

    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_readable_password_property_is_flagged(self, mock_load):
        mock_load.return_value = _base_types()
        scanner = _create_instance()
        app = AsyncMock()
        err = _base_types()["ErrorPDU"]
        # anon read denied (err); password prop readable (ack), others err;
        # SC read err.
        app.request = AsyncMock(side_effect=[err(), _ack(), err(), err(), err()])

        asyncio.run(scanner._bacpypes3_check_auth(app, Mock(), 1001, 2.0))

        titles = [c.args[0] for c in scanner.logger.security_finding.call_args_list]
        self.assertIn("Insecure configuration", titles)

    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_all_denied_reports_no_weakness(self, mock_load):
        mock_load.return_value = _base_types()
        scanner = _create_instance()
        app = AsyncMock()
        # Every request raises -> all denied/filtered, SC read raises too.
        app.request = AsyncMock(side_effect=Exception("filtered"))

        asyncio.run(scanner._bacpypes3_check_auth(app, Mock(), 1001, 2.0))

        # SC failure path still appends the cleartext finding -> there IS a
        # findings summary, but no security_finding() for anon access.
        anon = [
            c
            for c in scanner.logger.security_finding.call_args_list
            if c.args[0] == "Anonymous access"
        ]
        self.assertEqual(anon, [])


# ---------------------------------------------------------------------------
# DCC / Reinit brute force
# ---------------------------------------------------------------------------
class TestBruteForceDcc(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_empty_password_hit_records_weak_password(self, mock_load):
        mock_load.return_value = _base_types()
        scanner = _create_instance()
        app = AsyncMock()
        # First password in the default list is "" — make it succeed (ACK).
        app.request = AsyncMock(return_value=_ack())

        result = asyncio.run(scanner._bacpypes3_brute_force_dcc(app, Mock(), 1001, 2.0))

        self.assertEqual(result, "")  # empty password matched
        call = scanner.logger.security_finding.call_args
        self.assertEqual(call.args[0], "Weak password")
        self.assertEqual(call.kwargs["category"], Category.AUTHENTICATION)
        self.assertIn("(empty)", call.kwargs["detail"])

    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_all_timeouts_finds_nothing(self, mock_load):
        mock_load.return_value = _base_types()
        scanner = _create_instance(password="onlyone")  # single-item list, fast
        app = AsyncMock()
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())

        result = asyncio.run(scanner._bacpypes3_brute_force_dcc(app, Mock(), 1001, 2.0))

        self.assertIsNone(result)
        scanner.logger.security_finding.assert_not_called()

    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_error_pdu_means_no_hit(self, mock_load):
        types = _base_types()
        mock_load.return_value = types
        scanner = _create_instance(password="wrong")
        app = AsyncMock()
        app.request = AsyncMock(return_value=types["ErrorPDU"]())

        result = asyncio.run(scanner._bacpypes3_brute_force_dcc(app, Mock(), 1001, 2.0))
        self.assertIsNone(result)
        scanner.logger.security_finding.assert_not_called()


class TestBruteForceReinit(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_hit_records_weak_password_authentication(self, mock_load):
        mock_load.return_value = _base_types()
        scanner = _create_instance(password="filister")
        app = AsyncMock()
        app.request = AsyncMock(return_value=_ack())

        result = asyncio.run(scanner._bacpypes3_brute_force_reinit(app, Mock(), 1001, 2.0))

        self.assertEqual(result, "filister")
        call = scanner.logger.security_finding.call_args
        self.assertEqual(call.args[0], "Weak password")
        self.assertEqual(call.kwargs["category"], Category.AUTHENTICATION)
        self.assertIn("ReinitializeDevice", call.kwargs["detail"])

    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_no_hit_on_error(self, mock_load):
        types = _base_types()
        mock_load.return_value = types
        scanner = _create_instance(password="nope")
        app = AsyncMock()
        app.request = AsyncMock(return_value=types["AbortPDU"]())

        result = asyncio.run(scanner._bacpypes3_brute_force_reinit(app, Mock(), 1001, 2.0))
        self.assertIsNone(result)


class TestBruteForceAll(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_runs_both_dcc_and_reinit(self, mock_load):
        mock_load.return_value = _base_types()
        scanner = _create_instance(password="x")
        app = AsyncMock()
        app.request = AsyncMock(side_effect=asyncio.TimeoutError())

        asyncio.run(scanner._bacpypes3_brute_force(app, Mock(), 1001, 2.0))

        # Both sub-routines print their headers.
        displayed = " ".join(str(c.args[0]) for c in scanner.logger.display.call_args_list)
        self.assertIn("DeviceCommunicationControl", displayed)
        self.assertIn("ReinitializeDevice", displayed)


# ---------------------------------------------------------------------------
# _bacpypes3_test_dcc / _bacpypes3_test_reinit
# ---------------------------------------------------------------------------
class TestTestDcc(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_accepted_dcc_records_weak_password(self, mock_load):
        mock_load.return_value = _base_types()
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=_ack())

        asyncio.run(scanner._bacpypes3_test_dcc(app, Mock(), 1001, 3.0))

        call = scanner.logger.security_finding.call_args
        self.assertEqual(call.args[0], "Weak password")
        self.assertEqual(call.kwargs["category"], Category.AUTHENTICATION)
        self.assertIn("DCC accepted", call.kwargs["detail"])

    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_service_not_supported_stops_early(self, mock_load):
        types = _base_types()
        mock_load.return_value = types
        scanner = _create_instance()
        app = AsyncMock()
        # An error PDU (built from the loaded catalog) whose str() carries the
        # "service ... not supported" signal so the loop breaks early.
        err_instance = types["ErrorPDU"]()
        type(err_instance).__str__ = lambda self: "service request denied: not supported"
        app.request = AsyncMock(return_value=err_instance)

        asyncio.run(scanner._bacpypes3_test_dcc(app, Mock(), 1001, 3.0))
        scanner.logger.security_finding.assert_not_called()


class TestTestReinit(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_accepted_reinit_warns_critical(self, mock_load):
        mock_load.return_value = _base_types()
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=_ack())

        asyncio.run(scanner._bacpypes3_test_reinit(app, Mock(), 1001, 3.0))

        warnings = " ".join(str(c.args[0]) for c in scanner.logger.warning.call_args_list)
        self.assertIn("CRITICAL", warnings)

    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_rejected_reinit_no_success(self, mock_load):
        types = _base_types()
        mock_load.return_value = types
        scanner = _create_instance(password="bad")
        app = AsyncMock()
        bad = types["ErrorPDU"]()
        type(bad).__str__ = lambda self: "password invalid"
        app.request = AsyncMock(return_value=bad)

        asyncio.run(scanner._bacpypes3_test_reinit(app, Mock(), 1001, 3.0))
        # No "accepted" success line.
        succ = " ".join(str(c.args[0]) for c in scanner.logger.success.call_args_list)
        self.assertNotIn("accepted", succ)


# ---------------------------------------------------------------------------
# _bacpypes3_check_bacnet_sc
# ---------------------------------------------------------------------------
class TestCheckBacnetSc(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_no_sc_support_emits_no_encryption_finding(self, mock_load):
        types = _base_types()
        mock_load.return_value = types
        scanner = _create_instance()
        app = AsyncMock()
        # Every SC property read returns an error -> sc_found False.
        app.request = AsyncMock(return_value=types["ErrorPDU"]())

        asyncio.run(scanner._bacpypes3_check_bacnet_sc(app, Mock(), 1001, 2.0))

        call = scanner.logger.security_finding.call_args
        self.assertEqual(call.args[0], "No encryption")
        self.assertEqual(call.kwargs["category"], Category.ENCRYPTION)

    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_sc_supported_no_finding(self, mock_load):
        mock_load.return_value = _base_types()
        scanner = _create_instance()
        app = AsyncMock()
        # First SC property read ACKs (sc_found True), rest can be anything.
        resp = Mock(spec=["propertyValue"])
        resp.propertyValue = None
        app.request = AsyncMock(return_value=resp)

        asyncio.run(scanner._bacpypes3_check_bacnet_sc(app, Mock(), 1001, 2.0))

        # SC found -> the No-encryption finding must NOT be raised.
        titles = [c.args[0] for c in scanner.logger.security_finding.call_args_list]
        self.assertNotIn("No encryption", titles)
        scanner.logger.success.assert_called()


# ---------------------------------------------------------------------------
# _bacpypes3_test_time_sync (out-of-band verification)
# ---------------------------------------------------------------------------
class TestTimeSync(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_clock_changed_emits_finding(self, mock_load):
        mock_load.return_value = _base_types()
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=_ack())

        # before -> ("d0","t0"); after -> ("d1","t1") (clock moved).
        before = ("date0", "time0")
        after = ("date1", "time1")
        scanner._read_device_local_time = AsyncMock(side_effect=[before, after])

        asyncio.run(scanner._bacpypes3_test_time_sync(app, Mock(), 1001, 2.0))

        call = scanner.logger.security_finding.call_args
        self.assertEqual(call.args[0], "Unauthenticated time synchronization")
        self.assertEqual(call.kwargs["category"], Category.ACCESS_CONTROL)

    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_clock_unchanged_no_finding(self, mock_load):
        mock_load.return_value = _base_types()
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=_ack())

        same = ("date0", "time0")
        scanner._read_device_local_time = AsyncMock(side_effect=[same, same])

        asyncio.run(scanner._bacpypes3_test_time_sync(app, Mock(), 1001, 2.0))

        scanner.logger.security_finding.assert_not_called()
        scanner.logger.success.assert_called()

    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_indeterminate_when_clock_unreadable(self, mock_load):
        mock_load.return_value = _base_types()
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=_ack())

        scanner._read_device_local_time = AsyncMock(side_effect=[None, None])

        asyncio.run(scanner._bacpypes3_test_time_sync(app, Mock(), 1001, 2.0))

        scanner.logger.security_finding.assert_not_called()
        displayed = " ".join(str(c.args[0]) for c in scanner.logger.display.call_args_list)
        self.assertIn("indeterminate", displayed.lower())


# ---------------------------------------------------------------------------
# _read_device_local_time
# ---------------------------------------------------------------------------
class TestReadDeviceLocalTime(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_returns_pair_on_success(self, mock_load):
        mock_load.return_value = _base_types()
        scanner = _create_instance()
        app = AsyncMock()
        r1 = Mock(spec=["propertyValue"])
        r1.propertyValue = "DATE"
        r2 = Mock(spec=["propertyValue"])
        r2.propertyValue = "TIME"
        app.request = AsyncMock(side_effect=[r1, r2])

        result = asyncio.run(scanner._read_device_local_time(app, Mock(), 1001, 2.0))
        self.assertEqual(result, ("DATE", "TIME"))

    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_returns_none_on_error(self, mock_load):
        types = _base_types()
        mock_load.return_value = types
        scanner = _create_instance()
        app = AsyncMock()
        app.request = AsyncMock(return_value=types["ErrorPDU"]())

        result = asyncio.run(scanner._read_device_local_time(app, Mock(), 1001, 2.0))
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# _bacpypes3_test_oos
# ---------------------------------------------------------------------------
class TestTestOos(unittest.TestCase):
    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_no_control_objects(self, mock_load):
        mock_load.return_value = _base_types()
        scanner = _create_instance()
        scanner.objects = {1001: {"analogValue": [1]}}  # none of the I/O types
        app = AsyncMock()

        asyncio.run(scanner._bacpypes3_test_oos(app, Mock(), 1001, 2.0))

        displayed = " ".join(str(c.args[0]) for c in scanner.logger.display.call_args_list)
        self.assertIn("No control I/O objects", displayed)

    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_writable_oos_emits_finding_with_confirm(self, mock_load):
        mock_load.return_value = _base_types()
        scanner = _create_instance(confirm=True)
        scanner.objects = {1001: {"analogOutput": [1]}}
        app = AsyncMock()
        # Read OOS -> ack (readable). Write OOS -> ack (writable).
        app.request = AsyncMock(return_value=_ack())

        asyncio.run(scanner._bacpypes3_test_oos(app, Mock(), 1001, 2.0))

        titles = [c.args[0] for c in scanner.logger.security_finding.call_args_list]
        cats = [c.kwargs["category"] for c in scanner.logger.security_finding.call_args_list]
        self.assertIn("Writable access", titles)
        self.assertIn(Category.ACCESS_CONTROL, cats)

    @patch("oida.protocols.bacnet.mixins.security._load_bacpypes3")
    def test_readonly_without_confirm_skips_write(self, mock_load):
        mock_load.return_value = _base_types()
        scanner = _create_instance(confirm=False)
        scanner.objects = {1001: {"analogOutput": [1]}}
        app = AsyncMock()
        app.request = AsyncMock(return_value=_ack())

        asyncio.run(scanner._bacpypes3_test_oos(app, Mock(), 1001, 2.0))

        # No write attempted -> no Writable finding.
        titles = [c.args[0] for c in scanner.logger.security_finding.call_args_list]
        self.assertNotIn("Writable access", titles)
        displayed = " ".join(str(c.args[0]) for c in scanner.logger.display.call_args_list)
        self.assertIn("--confirm", displayed)


if __name__ == "__main__":
    unittest.main()

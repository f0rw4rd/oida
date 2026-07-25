#!/usr/bin/env python3
"""Deep unit tests for MMSScanner orchestration / read / write / security paths.

Covers _get_server_info (identity + device count), _read_iec61850_attribute,
_read_data_objects (FC MX->ST fallback), the --test-write confirm / read-only
gates, _write_data_object CO->SP->MX probe order, _analyze_security concern
emission, _report_findings vuln emission, connect() success/failure, and
discover() dispatch (--identify / --variable).

The scanner runs on the high-level MMSClient: discovery/read tests pass a
MagicMock() connection and stub its high-level methods; the FC / ReadError /
MmsType surfaces are mocked at the _Lib boundary, and the write probe order is
asserted by patching the module-level ``_write_under_fc`` shim.
"""

from enum import IntEnum
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from oida.protocols.mms import MMSScanner, _Lib


class _FC(IntEnum):
    """Stand-in for pyiec61850.mms.FC."""

    ST = 0
    MX = 1
    SP = 2
    DC = 5
    CO = 12


class _MmsType(IntEnum):
    """Stand-in for pyiec61850.mms.MmsType (tags _normalize_read consults)."""

    ARRAY = 0
    STRUCTURE = 1
    DATA_ACCESS_ERROR = 15


class _ReadError(Exception):
    """Stand-in for pyiec61850.mms.ReadError."""


class _ConnectionFailed(Exception):
    """Stand-in for pyiec61850.mms.ConnectionFailedError."""


def _scanner(**extra):
    base = {"rhost": "127.0.0.1", "rport": 102, "timeout": 5}
    base.update(extra)
    return MMSScanner(base)


class TestTlsConfig:
    """--tls builds a TLSConfig with validation OFF by default (pentest default)."""

    def test_no_tls_returns_none(self):
        assert _scanner()._build_tls_config() is None
        assert _scanner(tls=False)._build_tls_config() is None

    def test_tls_default_disables_validation(self):
        cfg = _scanner(tls=True)._build_tls_config()
        assert cfg is not None
        # Encrypted but unauthenticated: insecure=True, no CA/pin.
        assert cfg.insecure is True

    def test_tls_ca_enables_validation(self):
        cfg = _scanner(tls=True, **{"tls-ca": "ca.crt"})._build_tls_config()
        assert cfg.insecure is False
        assert cfg.ca_certs == ["ca.crt"]

    def test_tls_pin_enables_validation(self):
        cfg = _scanner(tls=True, **{"tls-pin": "server.crt"})._build_tls_config()
        assert cfg.insecure is False

    def test_tls_client_cert_sets_mutual(self):
        cfg = _scanner(
            tls=True, **{"tls-client-cert": "cl.crt", "tls-client-key": "cl.key"}
        )._build_tls_config()
        assert cfg.own_cert == "cl.crt" and cfg.own_key == "cl.key"
        assert cfg.insecure is True  # still no server validation without CA/pin

    def test_connect_uses_tls_port_and_passes_config(self):
        # --tls switches the default plaintext port (102) to the TLS port and
        # threads the TLSConfig into MMSClient.
        s = _scanner(tls=True)
        client = MagicMock()
        client.connect.return_value = True
        with (
            patch.object(_Lib, "require"),
            patch.object(_Lib, "MMSClient", return_value=client) as ctor,
        ):
            s.connect()
        assert ctor.call_args.kwargs.get("tls") is not None
        # connect() called with the TLS port (3782), not 102.
        called_port = client.connect.call_args.args[1]
        assert called_port == 3782


# --------------------------------------------------------------------------- #
# __init__ flag/gate behaviour
# --------------------------------------------------------------------------- #
class TestInitGates:
    def test_test_write_without_confirm_is_disabled(self):
        s = _scanner(**{"test-write": True})
        assert s.test_write is False  # gated off
        assert s.read_only is True  # guard NOT cleared

    def test_test_write_with_confirm_clears_read_only(self):
        s = _scanner(**{"test-write": True, "confirm": True})
        assert s.test_write is True
        assert s.read_only is False

    def test_single_action_selectors_parsed(self):
        s = _scanner(identify=True, **{"get-name-list": True}, variable="LD0/MMXU")
        assert s.identify is True
        assert s.get_name_list is True
        assert s.variable == "LD0/MMXU"

    def test_blank_variable_normalized_to_none(self):
        s = _scanner(variable="")
        assert s.variable is None


# --------------------------------------------------------------------------- #
# connect()
# --------------------------------------------------------------------------- #
class TestConnect:
    def test_connect_success_returns_client(self):
        s = _scanner()
        s.logger = MagicMock()
        client = MagicMock()
        with (
            patch.object(_Lib, "require"),
            patch.object(_Lib, "MMSClient", return_value=client) as ctor,
        ):
            assert s.connect() is client
        ctor.assert_called_once_with(timeout=s.timeout * 1000)
        client.connect.assert_called_once_with("127.0.0.1", 102)
        # cleartext-transport finding emitted on a successful association
        s.logger.security_finding.assert_called_once()

    def test_connect_returns_none_on_connection_failed(self):
        s = _scanner()
        s.logger = MagicMock()
        client = MagicMock()
        client.connect.side_effect = _ConnectionFailed("refused")
        with (
            patch.object(_Lib, "require"),
            patch.object(_Lib, "ConnectionFailedError", _ConnectionFailed),
            patch.object(_Lib, "MMSClient", return_value=client),
        ):
            assert s.connect() is None
        s.logger.security_finding.assert_not_called()

    def test_connect_returns_none_on_unexpected_error(self):
        s = _scanner()
        s.logger = MagicMock()
        client = MagicMock()
        client.connect.side_effect = RuntimeError("boom")
        with (
            patch.object(_Lib, "require"),
            patch.object(_Lib, "ConnectionFailedError", _ConnectionFailed),
            patch.object(_Lib, "MMSClient", return_value=client),
        ):
            assert s.connect() is None


# --------------------------------------------------------------------------- #
# _get_server_info
# --------------------------------------------------------------------------- #
class TestGetServerInfo:
    def test_identity_fields_and_device_count(self):
        s = _scanner()
        connection = MagicMock()
        connection.get_logical_devices.return_value = ["LD0", "LD1", "LD2"]
        connection.get_server_identity.return_value = SimpleNamespace(
            vendor="ACME", model="M1", revision="R2"
        )

        info = s._get_server_info(connection)

        assert info["vendor"] == "ACME"
        assert info["model"] == "M1"
        assert info["revision"] == "R2"
        assert info["logical_device_count"] == 3
        assert info["supports_get_server_directory"] is True

    def test_blank_identity_omits_fields(self):
        s = _scanner()
        connection = MagicMock()
        connection.get_logical_devices.return_value = ["LD0"]
        connection.get_server_identity.return_value = SimpleNamespace(
            vendor=None, model=None, revision=None
        )

        info = s._get_server_info(connection)

        assert "vendor" not in info
        assert "model" not in info
        assert "revision" not in info
        assert info["logical_device_count"] == 1
        assert info["supports_get_server_directory"] is True

    def test_device_count_failure_still_returns_directory_flag(self):
        s = _scanner()
        connection = MagicMock()
        connection.get_server_identity.return_value = SimpleNamespace(
            vendor=None, model=None, revision=None
        )
        connection.get_logical_devices.side_effect = RuntimeError("link down")

        info = s._get_server_info(connection)

        assert info["supports_get_server_directory"] is True
        assert "logical_device_count" not in info


# --------------------------------------------------------------------------- #
# discovery list builders
# --------------------------------------------------------------------------- #
class TestDiscoveryBuilders:
    def test_discover_logical_devices_builds_dicts(self):
        s = _scanner()
        connection = MagicMock()
        connection.get_logical_devices.return_value = ["LD0", "LD1"]
        devs = s._discover_logical_devices(connection)
        assert [d["name"] for d in devs] == ["LD0", "LD1"]
        assert all(d["accessible"] for d in devs)

    def test_get_logical_nodes_builds_full_reference(self):
        s = _scanner()
        connection = MagicMock()
        connection.get_logical_nodes.return_value = ["LLN0", "MMXU1"]
        nodes = s._get_logical_nodes(connection, "LD0")
        connection.get_logical_nodes.assert_called_once_with("LD0")
        assert nodes[0]["full_reference"] == "LD0/LLN0"
        assert nodes[1]["full_reference"] == "LD0/MMXU1"

    def test_get_data_objects_builds_dotted_reference(self):
        s = _scanner()
        connection = MagicMock()
        connection.get_data_objects.return_value = ["Mod", "Beh"]
        objs = s._get_data_objects(connection, "LD0", "LLN0")
        connection.get_data_objects.assert_called_once_with("LD0", "LLN0")
        assert objs[0]["full_reference"] == "LD0/LLN0.Mod"
        assert objs[0]["readable"] is False
        assert objs[1]["full_reference"] == "LD0/LLN0.Beh"

    def test_discover_data_model_respects_max_objects(self):
        s = _scanner(**{"max-objects": 1})
        s._get_logical_nodes = MagicMock(return_value=[{"name": "LLN0", "data_objects": []}])
        # each LN yields 2 data objects -> limit (1) hit after first LN
        s._get_data_objects = MagicMock(return_value=[{"name": "A"}, {"name": "B"}])
        devices = [{"name": "LD0"}, {"name": "LD1"}]
        res = s._discover_data_model(MagicMock(), devices)
        # second device skipped because limit reached
        assert s._get_logical_nodes.call_count == 1
        assert len(res["data_objects"]) == 2


# --------------------------------------------------------------------------- #
# _read_iec61850_attribute / _read_data_objects
# --------------------------------------------------------------------------- #
class TestReadPaths:
    def test_read_attribute_dollar_to_dot_and_value(self):
        s = _scanner()
        connection = MagicMock()
        connection.read_value.return_value = "SIEMENS"
        with (
            patch.object(_Lib, "FC", _FC),
            patch.object(_Lib, "ReadError", _ReadError),
            patch.object(_Lib, "MmsType", _MmsType),
        ):
            val = s._read_iec61850_attribute(connection, "LD0", "LPHD$DC$PhyNam$vendor")
        assert val == "SIEMENS"
        # the reference must have $ replaced with . and be read under FC_DC
        ref_used = connection.read_value.call_args[0][0]
        assert ref_used == "LD0/LPHD.DC.PhyNam.vendor"
        assert connection.read_value.call_args.kwargs["fc"] == _FC.DC

    def test_read_attribute_read_error_returns_none(self):
        s = _scanner()
        connection = MagicMock()
        connection.read_value.side_effect = _ReadError("denied")
        with (
            patch.object(_Lib, "FC", _FC),
            patch.object(_Lib, "ReadError", _ReadError),
            patch.object(_Lib, "MmsType", _MmsType),
        ):
            assert s._read_iec61850_attribute(connection, "LD0", "x") is None

    def test_read_data_objects_success_and_failure_buckets(self):
        s = _scanner()
        objs = [
            {"full_reference": "LD0/MMXU1.A"},
            {"full_reference": "LD0/MMXU1.B"},
        ]

        # obj A reads 42 under FC_MX; obj B returns the DATA_ACCESS_ERROR
        # placeholder (normalized to None) under both MX and ST -> failed bucket.
        err_placeholder = f"<MmsValue type={int(_MmsType.DATA_ACCESS_ERROR)}>"

        def read_value(ref, fc):
            if ref == "LD0/MMXU1.A":
                return 42
            return err_placeholder

        connection = MagicMock()
        connection.read_value.side_effect = read_value

        with (
            patch.object(_Lib, "FC", _FC),
            patch.object(_Lib, "ReadError", _ReadError),
            patch.object(_Lib, "MmsType", _MmsType),
        ):
            res = s._read_data_objects(connection, objs)

        assert res["total_tested"] == 2
        assert len(res["successful_reads"]) == 1
        assert res["successful_reads"][0]["reference"] == "LD0/MMXU1.A"
        assert res["successful_reads"][0]["value"] == 42
        assert res["successful_reads"][0]["data_type"] == "integer"
        assert len(res["failed_reads"]) == 1
        assert res["failed_reads"][0]["reference"] == "LD0/MMXU1.B"
        # the read result is written back onto the object dict
        assert objs[0]["readable"] is True
        assert objs[0]["value"] == 42

    def test_read_data_objects_mx_falls_back_to_st(self):
        # MX raises ReadError; ST returns a value -> success under ST.
        s = _scanner()
        objs = [{"full_reference": "LD0/MMXU1.A"}]

        def read_value(ref, fc):
            if fc == _FC.MX:
                raise _ReadError("not measurement")
            return 7  # FC_ST

        connection = MagicMock()
        connection.read_value.side_effect = read_value

        with (
            patch.object(_Lib, "FC", _FC),
            patch.object(_Lib, "ReadError", _ReadError),
            patch.object(_Lib, "MmsType", _MmsType),
        ):
            res = s._read_data_objects(connection, objs)

        assert len(res["successful_reads"]) == 1
        assert res["successful_reads"][0]["value"] == 7

    def test_read_data_objects_records_exception(self):
        s = _scanner()
        objs = [{"full_reference": "LD0/MMXU1.A"}]
        connection = MagicMock()
        connection.read_value.side_effect = RuntimeError("link down")
        with (
            patch.object(_Lib, "FC", _FC),
            patch.object(_Lib, "ReadError", _ReadError),
            patch.object(_Lib, "MmsType", _MmsType),
        ):
            res = s._read_data_objects(connection, objs)
        assert len(res["failed_reads"]) == 1
        assert "link down" in res["failed_reads"][0]["error"]


# --------------------------------------------------------------------------- #
# write path
# --------------------------------------------------------------------------- #
class TestWritePaths:
    def test_test_write_skipped_in_read_only(self):
        s = _scanner()  # read_only defaults True
        assert s.read_only is True
        res = s._test_write_access(MagicMock(), [])
        assert res == {"successful_writes": [], "failed_writes": [], "total_tested": 0}

    def test_test_write_requires_confirm(self):
        # read_only cleared manually but confirm False -> still refused
        s = _scanner()
        s.read_only = False
        s.confirm = False
        res = s._test_write_access(MagicMock(), [{"readable": True, "value": 1}])
        assert res["total_tested"] == 0

    def test_test_write_only_targets_readable_objects(self):
        s = _scanner(**{"test-write": True, "confirm": True})
        assert s.read_only is False and s.confirm is True
        objs = [
            {"full_reference": "LD0/A", "readable": True, "value": 5},
            {"full_reference": "LD0/B", "readable": False, "value": 1},  # skipped
            {"full_reference": "LD0/C", "readable": True, "value": None},  # unreadable on demand
        ]
        # Objects without a cached value are read on demand; make those reads
        # return nothing so LD0/C stays unwritable (isolates the filter).
        conn = MagicMock()
        conn.read_value.return_value = None
        with (
            patch.object(_Lib, "FC", _FC),
            patch.object(s, "_write_data_object", return_value=True) as w,
        ):
            res = s._test_write_access(conn, objs)
        assert res["total_tested"] == 1
        assert res["successful_writes"][0]["reference"] == "LD0/A"
        assert objs[0]["writable"] is True
        w.assert_called_once()

    def test_test_write_reads_values_on_demand(self):
        # --test-write must work without a prior --read-values pass: an object
        # with no cached value is read on demand and then written.
        s = _scanner(**{"test-write": True, "confirm": True})
        objs = [{"full_reference": "LD0/X", "readable": False, "value": None}]
        conn = MagicMock()
        conn.read_value.return_value = 42
        with (
            patch.object(_Lib, "FC", _FC),
            patch.object(s, "_write_data_object", return_value=True) as w,
        ):
            res = s._test_write_access(conn, objs)
        assert res["total_tested"] == 1
        assert objs[0]["value"] == 42 and objs[0]["readable"] is True
        w.assert_called_once()

    def test_test_write_records_failed_write(self):
        s = _scanner(**{"test-write": True, "confirm": True})
        objs = [{"full_reference": "LD0/A", "readable": True, "value": 5}]
        with patch.object(s, "_write_data_object", return_value=False):
            res = s._test_write_access(MagicMock(), objs)
        assert res["failed_writes"][0]["reference"] == "LD0/A"
        assert len(res["successful_writes"]) == 0

    def test_write_data_object_probes_co_sp_mx_in_order(self):
        # CO and SP rejected, MX accepted -> True, and the probe order is exactly
        # CO -> SP -> MX (impact order).
        s = _scanner()
        conn = MagicMock()

        accepted = {_FC.MX}

        def fake_write(client, reference, value, fc):
            assert client is conn
            assert reference == "LD0/A"
            assert value == 5
            return fc in accepted

        with (
            patch.object(_Lib, "FC", _FC),
            patch("oida.protocols.mms._write_under_fc", side_effect=fake_write) as wuf,
        ):
            assert s._write_data_object(conn, "LD0/A", 5) is True

        probed_fcs = [c.args[3] for c in wuf.call_args_list]
        assert probed_fcs == [_FC.CO, _FC.SP, _FC.MX]

    def test_write_data_object_returns_on_first_success(self):
        # CO accepted -> SP/MX never probed.
        s = _scanner()
        with (
            patch.object(_Lib, "FC", _FC),
            patch("oida.protocols.mms._write_under_fc", return_value=True) as wuf,
        ):
            assert s._write_data_object(MagicMock(), "LD0/A", 5) is True
        assert wuf.call_count == 1
        assert wuf.call_args.args[3] == _FC.CO

    def test_write_data_object_all_fc_fail(self):
        s = _scanner()
        with (
            patch.object(_Lib, "FC", _FC),
            patch("oida.protocols.mms._write_under_fc", return_value=False) as wuf,
        ):
            assert s._write_data_object(MagicMock(), "LD0/A", 5) is False
        # all three constraints attempted
        assert wuf.call_count == 3


# --------------------------------------------------------------------------- #
# security analysis + reporting
# --------------------------------------------------------------------------- #
class TestSecurityAndReport:
    def test_analyze_security_concerns_listed(self):
        # Benign discovery counts (logical devices, data objects, reads) are
        # informational, not vulnerabilities, and must NOT appear in
        # concerns. Only the write-without-auth finding (and the underlying
        # missing-auth/encryption/integrity issues) should be reported.
        s = _scanner()
        results = {
            "logical_devices": [{"name": "LD0"}, {"name": "LD1"}],
            "data_objects": [{"name": "x"}, {"name": "y"}, {"name": "z"}],
            "read_test_results": {"successful_reads": [{"reference": "a"}]},
            "write_test_results": {"successful_writes": [{"reference": "b"}]},
        }
        analysis = s._analyze_security(results)
        concerns = analysis["concerns"]
        assert "2 logical devices accessible" not in concerns
        assert "3 data objects discovered" not in concerns
        assert "1 data objects readable" not in concerns
        assert "1 data objects writable without authentication" in concerns
        # Real auth/encryption issues from the assessor are surfaced too.
        assert any("authentication" in c.lower() for c in concerns)
        assert any("encryption" in c.lower() for c in concerns)

    def test_analyze_security_access_control_flag(self):
        s = _scanner()
        # no writable objects -> access_control True was passed to assessor,
        # so "Missing access control" is not among the issues; the other
        # missing-auth/encryption/integrity issues still are.
        no_write = s._analyze_security({"write_test_results": {"successful_writes": []}})
        assert isinstance(no_write, dict)
        assert not any("writable" in c.lower() for c in no_write["concerns"])
        assert not any("access control" in c.lower() for c in no_write["concerns"])
        assert any("authentication" in c.lower() for c in no_write["concerns"])

    def test_report_findings_emits_vuln_per_concern(self):
        s = _scanner()
        results = {
            "logical_devices": [{"name": "LD0"}],
            "security_analysis": {
                "concerns": ["1 logical devices accessible", "5 data objects discovered"]
            },
        }
        with (
            patch.object(s, "report_host_info") as host_info,
            patch.object(s, "report_service_info") as svc_info,
            patch.object(s, "report_vulnerability") as vuln,
        ):
            s._report_findings(results)
        host_info.assert_called_once()
        svc_info.assert_called_once()
        assert vuln.call_count == 2
        # vuln name carried through
        assert vuln.call_args_list[0][0][1] == "iec61850_security"


# --------------------------------------------------------------------------- #
# discover() dispatch
# --------------------------------------------------------------------------- #
class TestDiscoverDispatch:
    def test_identify_forces_fresh_server_info(self):
        s = _scanner(identify=True)
        s.scan_mode = "discovery"
        with (
            patch.object(s, "_get_server_info", return_value={"vendor": "FRESH"}) as gsi,
            patch.object(s, "_discover_logical_devices", return_value=[]),
            patch.object(
                s, "_discover_data_model", return_value={"logical_nodes": [], "data_objects": []}
            ),
            patch.object(s, "_fingerprint_device", return_value=None),
            patch.object(s, "_report_findings"),
        ):
            res = s.discover(MagicMock(), server_info={"vendor": "CACHED"})
        gsi.assert_called_once()
        assert res["server_info"]["vendor"] == "FRESH"

    def test_cached_server_info_reused_without_identify(self):
        s = _scanner()  # identify False
        s.scan_mode = "discovery"
        with (
            patch.object(s, "_get_server_info") as gsi,
            patch.object(s, "_discover_logical_devices", return_value=[]),
            patch.object(
                s, "_discover_data_model", return_value={"logical_nodes": [], "data_objects": []}
            ),
            patch.object(s, "_fingerprint_device", return_value=None),
            patch.object(s, "_report_findings"),
        ):
            res = s.discover(MagicMock(), server_info={"vendor": "CACHED"})
        gsi.assert_not_called()
        assert res["server_info"]["vendor"] == "CACHED"

    def test_variable_reads_only_matching_objects(self):
        s = _scanner(variable="mmxu1.a")
        s.scan_mode = "none"  # variable forces discovery anyway
        data_objects = [
            {"full_reference": "LD0/MMXU1.A"},
            {"full_reference": "LD0/XCBR1.Pos"},
        ]
        with (
            patch.object(s, "_get_server_info", return_value={}),
            patch.object(s, "_discover_logical_devices", return_value=[{"name": "LD0"}]),
            patch.object(
                s,
                "_discover_data_model",
                return_value={"logical_nodes": [], "data_objects": data_objects},
            ),
            patch.object(s, "_fingerprint_device", return_value=None),
            patch.object(s, "_report_findings"),
            patch.object(
                s, "_read_data_objects", return_value={"successful_reads": ["hit"]}
            ) as rdo,
        ):
            res = s.discover(MagicMock(), server_info=None)
        # only the matching object was passed to the reader
        passed = rdo.call_args[0][1]
        assert [o["full_reference"] for o in passed] == ["LD0/MMXU1.A"]
        assert res["read_test_results"]["successful_reads"] == ["hit"]

    def test_discover_captures_exception_as_error(self):
        s = _scanner(identify=True)
        s.scan_mode = "discovery"
        with patch.object(s, "_get_server_info", side_effect=RuntimeError("kaboom")):
            res = s.discover(MagicMock(), server_info=None)
        assert "kaboom" in res["error"]


# --------------------------------------------------------------------------- #
# _fingerprint_device / _report_fingerprint
# --------------------------------------------------------------------------- #
class TestFingerprint:
    def test_no_logical_devices_returns_none(self):
        s = _scanner()
        assert s._fingerprint_device(MagicMock(), []) is None

    def test_fingerprint_uses_read_attribute_closure(self):
        from oida.protocols.mms.fingerprint import FingerprintMatch

        s = _scanner()
        devices = [{"name": "SIPApplication"}]
        match = FingerprintMatch(fingerprint_name="Siemens", vendor_id="siemens", vendor="SIEMENS")

        # Stub the matcher: load succeeds, fingerprint_device drives read_attribute.
        with patch("oida.protocols.mms.FingerprintMatcher") as MM:
            matcher = MM.return_value
            matcher.load_fingerprints.return_value = True

            def fake_fp(domains, read_func):
                # exercise the closure so _read_iec61850_attribute is invoked
                read_func(domains[0], "LPHD0$DC$PhyNam$vendor")
                return match

            matcher.fingerprint_device.side_effect = fake_fp

            with patch.object(s, "_read_iec61850_attribute", return_value="SIEMENS") as rd:
                result = s._fingerprint_device(MagicMock(), devices)

        assert result is match
        rd.assert_called_once()
        assert rd.call_args[0][1] == "SIPApplication"

    def test_fingerprint_load_failure_returns_none(self):
        s = _scanner()
        with patch("oida.protocols.mms.FingerprintMatcher") as MM:
            MM.return_value.load_fingerprints.return_value = False
            assert s._fingerprint_device(MagicMock(), [{"name": "LD0"}]) is None

    def test_report_fingerprint_emits_all_fields(self):
        from oida.protocols.mms.fingerprint import FingerprintMatch

        s = _scanner()
        s.logger = MagicMock()
        fp = FingerprintMatch(
            fingerprint_name="Siemens SIPROTEC",
            vendor_id="siemens",
            vendor="SIEMENS",
            model="7SJ80",
            serial="SN123",
            firmware="V4.7",
            hardware_rev="RevB",
            custom={"order_number": "7SJ8011"},
        )
        s._report_fingerprint(fp)
        emitted = " ".join(
            c.args[0] for c in (s.logger.success.call_args_list + s.logger.display.call_args_list)
        )
        assert "Siemens SIPROTEC" in emitted
        assert "Vendor: SIEMENS" in emitted
        assert "Model: 7SJ80" in emitted
        assert "Serial: SN123" in emitted
        assert "Firmware: V4.7" in emitted
        assert "Hardware Rev: RevB" in emitted
        assert "order_number: 7SJ8011" in emitted

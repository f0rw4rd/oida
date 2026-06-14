"""
Unit tests for oida.protocols.modbus.device_db -- the pure-logic device
identification / function-code / exception fingerprint database
(was ~33% covered, no network involved).

Covers:
- load_database / get_product_count / get_vendor_list (real bundled DB).
- identify_vendor (alias + fuzzy), identify_product, identify_device confidence.
- get_function_code_info: standard / vendor-specific / user-defined / reserved.
- detect_custom_function_codes: bucketing + vendor hint + security findings.
- is_security_sensitive_fc: write FCs, vendor security_note, user range, safe FC.
- get_exception_info / get_exception_name / analyze_exception_response per code.
- fingerprint_by_exceptions: UMAS (FC 90), legacy Modicon (FC 66/70), device-type
  classification, support bucketing.
- get_mei_object_name ranges; fuzzy_vendor_match patterns; format_device_info.
"""

import pytest

try:
    import pymodbus  # noqa: F401

    PYMODBUS_AVAILABLE = True
except ImportError:
    PYMODBUS_AVAILABLE = False

# device_db is pure data + stdlib, but keep the suite consistent with the rest
pytestmark = pytest.mark.skipif(not PYMODBUS_AVAILABLE, reason="pymodbus library not installed")

from oida.protocols.modbus import device_db as d


# ---------------------------------------------------------------------------
# database load / counts
# ---------------------------------------------------------------------------


class TestDatabaseLoad:
    def test_product_count_nonzero(self):
        vc, pc = d.get_product_count()
        assert vc > 0 and pc > 0

    def test_vendor_list_sorted_unique(self):
        vlist = d.get_vendor_list()
        assert vlist == sorted(vlist)
        assert "Schneider Electric" in vlist


# ---------------------------------------------------------------------------
# vendor / product / device identification
# ---------------------------------------------------------------------------


class TestIdentify:
    def test_identify_vendor_exact(self):
        info = d.identify_vendor("Schneider Electric")
        assert info is not None
        assert info["vendor_name"] == "Schneider Electric"

    def test_identify_vendor_unknown(self):
        assert d.identify_vendor("Totally Made Up Vendor 9000") is None

    def test_identify_device_vendor_only_medium(self):
        res = d.identify_device({"VendorName": "Schneider Electric"})
        assert res["vendor"] is not None
        assert res["confidence"] in ("medium", "high")

    def test_identify_device_no_vendor_unknown(self):
        res = d.identify_device({})
        assert res["vendor"] is None
        assert res["confidence"] == "unknown"
        assert res["raw_mei"] == {}


# ---------------------------------------------------------------------------
# function code info
# ---------------------------------------------------------------------------


class TestFunctionCodeInfo:
    def test_standard_fc(self):
        info = d.get_function_code_info(6)
        assert info["type"] == "standard"
        assert "Write" in info["name"]

    def test_vendor_specific_fc(self):
        info = d.get_function_code_info(66)
        assert info["type"] == "vendor_specific"

    def test_user_defined_range(self):
        # FC 65 is in the user-defined range and absent from the vendor table
        info = d.get_function_code_info(65)
        assert info["type"] == "user_defined"

    def test_reserved_above_127(self):
        info = d.get_function_code_info(200)
        assert info["type"] == "reserved"

    def test_unknown_returns_none(self):
        # FC 9 is not standard, not in user/vendor ranges
        assert d.get_function_code_info(9) is None


# ---------------------------------------------------------------------------
# detect_custom_function_codes
# ---------------------------------------------------------------------------


class TestDetectCustomFCs:
    def test_buckets_standard_vendor_user(self):
        res = d.detect_custom_function_codes([3, 6, 66, 65])
        std = [x["code"] for x in res["standard"]]
        vendor = [x["code"] for x in res["vendor_specific"]]
        user = [x["code"] for x in res["user_defined"]]
        assert 3 in std and 6 in std
        assert 66 in vendor
        assert 65 in user

    def test_vendor_hint_and_security_findings(self):
        # FC 66 carries vendor + security_note
        res = d.detect_custom_function_codes([66])
        assert res["possible_vendor"] is not None
        assert any(f["code"] == 66 for f in res["security_findings"])


# ---------------------------------------------------------------------------
# is_security_sensitive_fc
# ---------------------------------------------------------------------------


class TestSecuritySensitiveFC:
    def test_write_fc_sensitive(self):
        sensitive, reason = d.is_security_sensitive_fc(16)
        assert sensitive is True
        assert reason

    def test_read_fc_not_sensitive(self):
        assert d.is_security_sensitive_fc(3) == (False, None)

    def test_vendor_security_note(self):
        sensitive, reason = d.is_security_sensitive_fc(66)
        assert sensitive is True
        assert reason

    def test_user_range_sensitive(self):
        sensitive, reason = d.is_security_sensitive_fc(105)
        assert sensitive is True


# ---------------------------------------------------------------------------
# exception info / analysis
# ---------------------------------------------------------------------------


class TestExceptionAnalysis:
    def test_exception_name_known(self):
        assert d.get_exception_name(1) is not None

    def test_exception_info_unknown(self):
        assert d.get_exception_info(99) is None

    def test_analyze_illegal_function_means_unsupported(self):
        res = d.analyze_exception_response(70, 1)
        assert res["function_supported"] is False
        assert "NOT supported" in res["interpretation"]

    def test_analyze_illegal_data_address_means_supported(self):
        res = d.analyze_exception_response(3, 2)
        assert res["function_supported"] is True
        assert "supported" in res["interpretation"].lower()

    def test_analyze_server_failure_flags_dos(self):
        res = d.analyze_exception_response(6, 4)
        assert res["security_relevance"] is not None

    def test_analyze_gateway_errors(self):
        res = d.analyze_exception_response(3, 11)
        assert "gateway" in res["interpretation"].lower()

    def test_analyze_vendor_fc_security_relevance(self):
        res = d.analyze_exception_response(66, 2)
        assert "Vendor-specific" in (res["security_relevance"] or "")


# ---------------------------------------------------------------------------
# fingerprint_by_exceptions
# ---------------------------------------------------------------------------


class TestFingerprintByExceptions:
    def test_umas_detected(self):
        # FC 90 supported (None == no exception) -> Schneider UMAS match
        res = d.fingerprint_by_exceptions({90: None})
        assert any("Schneider" in m["vendor"] for m in res["vendor_matches"])
        assert any("UMAS" in n for n in res["notes"])

    def test_legacy_modicon_fc66(self):
        res = d.fingerprint_by_exceptions({66: None})
        assert any("Modicon" in m["vendor"] for m in res["vendor_matches"])

    def test_fc70_legacy_download_note(self):
        res = d.fingerprint_by_exceptions({70: None})
        assert any("download" in n.lower() for n in res["notes"])

    def test_support_bucketing(self):
        res = d.fingerprint_by_exceptions({3: None, 4: 1, 6: 2})
        assert 3 in res["supported_fcs"]
        assert 4 in res["unsupported_fcs"]
        # exc 2 -> supported AND partial
        assert 6 in res["supported_fcs"]
        assert 6 in res["partial_support_fcs"]

    def test_meter_device_type(self):
        # FC 4 only + few supported -> Power/Energy Meter heuristic
        res = d.fingerprint_by_exceptions({4: None})
        assert res["device_type"] == "Power/Energy Meter"

    def test_plc_device_type(self):
        res = d.fingerprint_by_exceptions({90: None})
        assert res["device_type"] == "PLC/Controller"

    def test_gateway_device_type(self):
        res = d.fingerprint_by_exceptions({3: 11})
        assert res["device_type"] == "Gateway/Bridge"


# ---------------------------------------------------------------------------
# MEI object names / fuzzy vendor / format
# ---------------------------------------------------------------------------


class TestMeiAndFuzzy:
    def test_mei_known_object(self):
        assert d.get_mei_object_name(0) == "VendorName"

    def test_mei_reserved_range(self):
        assert d.get_mei_object_name(0x10) == "Reserved"

    def test_mei_vendor_private_range(self):
        assert d.get_mei_object_name(0x90) == "Vendor Defined Private Object"

    def test_fuzzy_schneider_variants(self):
        assert d.fuzzy_vendor_match("SCHNEIDER ELEC") == "Schneider Electric"
        assert d.fuzzy_vendor_match("Modicon M340") == "Schneider Electric"

    def test_fuzzy_allen_bradley(self):
        assert d.fuzzy_vendor_match("Allen-Bradley") == "Rockwell Automation"

    def test_fuzzy_no_match(self):
        assert d.fuzzy_vendor_match("Nonexistent Brand") is None

    def test_format_device_info_returns_string(self):
        ident = d.identify_device({"VendorName": "Schneider Electric", "ProductCode": "PM5100"})
        out = d.format_device_info(ident)
        assert isinstance(out, str)
        assert len(out) > 0

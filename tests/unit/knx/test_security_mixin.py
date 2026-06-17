"""Unit tests for oida.protocols.knx.mixins.security.SecurityMixin.

Exercises BCU key brute-force level logic, read/write access probing,
the not-implemented key-write validator, and the security analysis /
finding-emission paths.  Network and xknx are mocked via the shared
``conftest`` harness.
"""

import asyncio

from tests.unit.knx._harness import FakeP2P, make_knx, make_response


# ---------------------------------------------------------------------------
# _brute_bcu_auth
# ---------------------------------------------------------------------------


def _auth_resp(level):
    return make_response(level=level)


class TestBruteBcuAuth:
    def test_finds_first_valid_key_and_stops(self, host, patch_xknx_cls):
        # level 3/15 == no access; level 0 == full access (valid key)
        p2p = FakeP2P([_auth_resp(15), _auth_resp(0), _auth_resp(2)])
        knx = make_knx(p2p)

        res = asyncio.run(host._brute_bcu_auth(knx, "1.1.2", ["00000000", "DEADBEEF", "11111111"]))

        # stopped after the second key (the first valid one)
        assert res["keys_tested"] == 2
        assert len(res["valid_keys"]) == 1
        assert res["valid_keys"][0] == {"key": "DEADBEEF", "level": 0}
        # third key never sent
        assert p2p.call_count == 2

    def test_continue_on_success_tests_all_keys(self, host, patch_xknx_cls):
        p2p = FakeP2P([_auth_resp(0), _auth_resp(1)])
        knx = make_knx(p2p)

        res = asyncio.run(
            host._brute_bcu_auth(knx, "1.1.2", ["AAAAAAAA", "BBBBBBBB"], continue_on_success=True)
        )
        assert res["keys_tested"] == 2
        assert [v["key"] for v in res["valid_keys"]] == ["AAAAAAAA", "BBBBBBBB"]

    def test_level_15_treated_as_no_access(self, host, patch_xknx_cls):
        p2p = FakeP2P([_auth_resp(3), _auth_resp(15)])
        knx = make_knx(p2p)
        res = asyncio.run(host._brute_bcu_auth(knx, "1.1.2", ["1", "2"]))
        assert res["valid_keys"] == []
        assert res["keys_tested"] == 2

    def test_per_key_exception_recorded_not_fatal(self, host, patch_xknx_cls):
        p2p = FakeP2P([RuntimeError("timeout"), _auth_resp(0)])
        knx = make_knx(p2p)
        res = asyncio.run(host._brute_bcu_auth(knx, "1.1.2", ["1", "2"]))
        # first key errored, second succeeded
        assert any("timeout" in e for e in res["errors"])
        assert len(res["valid_keys"]) == 1

    def test_connection_failure_recorded(self, host, patch_xknx_cls):
        knx = make_knx(connection_error=OSError("no route"))
        res = asyncio.run(host._brute_bcu_auth(knx, "1.1.2", ["1"]))
        assert res["valid_keys"] == []
        assert any("no route" in e for e in res["errors"])
        assert host.logger.records["fail"]


# ---------------------------------------------------------------------------
# _write_bcu_key  (documented as NOT IMPLEMENTED)
# ---------------------------------------------------------------------------


class TestWriteBcuKey:
    def test_not_implemented_but_parses_valid_format(self, host):
        res = asyncio.run(host._write_bcu_key(None, "1.1.2", "FFFFFFFF:0"))
        assert res["success"] is False
        assert "not implemented" in res["error"].lower()
        # user told it is unimplemented
        assert any("NOT IMPLEMENTED" in m for m in host.logger.records["fail"])

    def test_bad_format_rejected(self, host):
        res = asyncio.run(host._write_bcu_key(None, "1.1.2", "FFFFFFFF"))
        assert "KEY:LEVEL" in res["error"]

    def test_invalid_hex_key(self, host):
        res = asyncio.run(host._write_bcu_key(None, "1.1.2", "ZZZZ:0"))
        assert "Invalid key/level" in res["error"]


# ---------------------------------------------------------------------------
# _test_read_access
# ---------------------------------------------------------------------------


class TestReadAccess:
    def test_collects_readable_memory(self, host, patch_xknx_cls):
        # 6 test addresses queried; alternate data / empty
        responses = [
            make_response(data=b"\xab\xcd"),
            make_response(data=None),
            make_response(data=b"\x01\x02"),
            make_response(data=None),
            make_response(data=None),
            make_response(data=None),
        ]
        p2p = FakeP2P(responses)
        knx = make_knx(p2p)
        devices = [{"address": "1.1.5", "accessible": True}]

        res = asyncio.run(host._test_read_access(knx, devices))
        readable = res["1.1.5"]["readable_addresses"]
        assert len(readable) == 2
        assert readable[0]["data"] == "abcd"
        assert readable[0]["length"] == 2
        assert readable[0]["address"] == hex(0x0100)

    def test_skips_inaccessible_devices(self, host, patch_xknx_cls):
        knx = make_knx(FakeP2P([]))
        res = asyncio.run(host._test_read_access(knx, [{"address": "1.1.9", "accessible": False}]))
        assert res == {}

    def test_memory_read_error_captured(self, host, patch_xknx_cls):
        p2p = FakeP2P([ValueError("nak")] * 6)
        knx = make_knx(p2p)
        res = asyncio.run(host._test_read_access(knx, [{"address": "1.1.5", "accessible": True}]))
        assert res["1.1.5"]["readable_addresses"] == []
        assert len(res["1.1.5"]["errors"]) == 6


# ---------------------------------------------------------------------------
# _test_write_access
# ---------------------------------------------------------------------------


class TestWriteAccess:
    def test_read_only_short_circuits(self, host, patch_xknx_cls):
        host.read_only = True
        knx = make_knx(FakeP2P([]))
        res = asyncio.run(host._test_write_access(knx, [{"address": "1.1.5", "accessible": True}]))
        assert res == {}
        assert any("read-only" in m for m in host.logger.records["display"])

    def test_writeback_marks_writable(self, host, patch_xknx_cls):
        host.read_only = False
        # first response = original read, second = write echo
        p2p = FakeP2P([make_response(data=b"\x42"), make_response(data=b"\x42")])
        knx = make_knx(p2p)
        res = asyncio.run(host._test_write_access(knx, [{"address": "1.1.5", "accessible": True}]))
        writable = res["1.1.5"]["writable_addresses"]
        assert len(writable) == 1
        assert writable[0]["writable"] is True
        assert writable[0]["original_data"] == "42"

    def test_no_original_data_skips_write(self, host, patch_xknx_cls):
        host.read_only = False
        p2p = FakeP2P([make_response(data=None)])
        knx = make_knx(p2p)
        res = asyncio.run(host._test_write_access(knx, [{"address": "1.1.5", "accessible": True}]))
        assert res["1.1.5"]["writable_addresses"] == []


# ---------------------------------------------------------------------------
# _analyze_security  /  _report_findings
# ---------------------------------------------------------------------------


class TestAnalyzeSecurity:
    def test_emits_baseline_findings(self, host):
        analysis = host._analyze_security({"devices": [], "write_test_results": {}})
        findings = [t for t, _ in host.logger.findings()]
        assert "No encryption" in findings
        assert "No authentication" in findings
        assert "concerns" in analysis

    def test_writable_devices_raise_concern_and_finding(self, host):
        results = {
            "devices": [{"address": "1.1.1"}, {"address": "1.1.2"}],
            "write_test_results": {
                "1.1.1": {"writable_addresses": [{"address": "0x116"}]},
                "1.1.2": {"writable_addresses": []},
            },
        }
        analysis = host._analyze_security(results)
        concerns = " ".join(analysis["concerns"])
        assert "2 accessible devices found" in concerns
        assert "1 devices with write access" in concerns
        findings = [t for t, _ in host.logger.findings()]
        assert "Writable access" in findings

    def test_routing_supported_flags_insecure_config(self, host):
        analysis = host._analyze_security({"routing_test": {"routing_supported": True}})
        assert "KNX routing is accessible" in analysis["concerns"]
        findings = [t for t, _ in host.logger.findings()]
        assert "Insecure configuration" in findings

    def test_report_findings_reports_host_service_and_vulns(self, host):
        results = {
            "security_analysis": {"concerns": ["thing A", "thing B"]},
        }
        host._report_findings(results)
        assert host.reported_hosts == ["10.0.0.5"]
        assert host.reported_services[0] == ("10.0.0.5", 3671, "knx", "udp")
        descs = [d for _, _, d in host.reported_vulns]
        assert descs == ["thing A", "thing B"]

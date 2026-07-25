"""
Unit tests for CoAP scanner (CoAPScanner) methods.

Tests connection handling, resource discovery, LwM2M fingerprinting,
method testing, security assessment, and the full discover() orchestration.
All tests use mocks -- no real network connections required.
"""

from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helper to create a mock scanner instance without triggering real init
# ---------------------------------------------------------------------------


def _make_scanner(args=None):
    """Create a CoAPScanner with mocked internals."""
    with patch("oida.protocols.coap.scanner._aiocoap") as mock_dep:
        mock_dep.is_available = True
        from oida.protocols.coap.scanner import CoAPScanner

        default_args = {
            "host": "192.168.1.100",
            "rhost": "192.168.1.100",
            "port": 5683,
            "rport": 5683,
            "timeout": 5,
            "block_size": 512,
        }
        if args:
            default_args.update(args)
        scanner = CoAPScanner(default_args)
    return scanner


# ---------------------------------------------------------------------------
# Protocol metadata
# ---------------------------------------------------------------------------


class TestCoAPScannerMetadata:
    """Test basic scanner metadata and dependency check."""

    def test_get_protocol_name(self):
        scanner = _make_scanner()
        assert scanner.get_protocol_name() == "CoAP"

    def test_get_default_port(self):
        scanner = _make_scanner()
        assert scanner.get_default_port() == 5683

    def test_check_dependencies_available(self):
        with patch("oida.protocols.coap.scanner._aiocoap") as m:
            m.is_available = True
            scanner = _make_scanner()
            assert scanner.check_dependencies() is True

    def test_check_dependencies_missing(self):
        with patch("oida.protocols.coap.scanner._aiocoap") as m:
            m.is_available = False
            scanner = _make_scanner()
            assert scanner.check_dependencies() is False

    def test_block_size_from_args(self):
        scanner = _make_scanner({"block_size": 256})
        assert scanner._block_size == 256

    def test_block_size_default(self):
        scanner = _make_scanner()
        assert scanner._block_size == 512


# ---------------------------------------------------------------------------
# Connection handling
# ---------------------------------------------------------------------------


class TestConnect:
    """Test CoAPScanner.connect() with various scenarios."""

    @patch("oida.protocols.coap.scanner.run_async")
    @patch("oida.protocols.coap.scanner.create_context")
    @patch("oida.protocols.coap.scanner.coap_ping")
    def test_connect_ping_success(self, mock_ping, mock_create_ctx, mock_run):
        """Successful ping leads to context creation."""
        mock_ping.return_value = True
        mock_ctx = MagicMock()
        mock_run.return_value = mock_ctx  # create_context result

        scanner = _make_scanner()
        result = scanner.connect()

        assert result is mock_ctx
        mock_ping.assert_called_once()

    @patch("oida.protocols.coap.scanner.run_async")
    @patch("oida.protocols.coap.scanner.shutdown_context")
    @patch("oida.protocols.coap.scanner.coap_get")
    @patch("oida.protocols.coap.scanner.create_context")
    @patch("oida.protocols.coap.scanner.coap_ping")
    def test_connect_ping_fails_get_fallback_success(
        self, mock_ping, mock_create_ctx, mock_get, mock_shutdown, mock_run
    ):
        """When ping fails, fallback GET succeeds."""
        mock_ping.return_value = False
        mock_ctx = MagicMock()

        call_count = 0

        def run_side_effect(coro):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return mock_ctx  # create_context
            elif call_count == 2:
                return ("2.05", b"links")  # coap_get
            return None

        mock_run.side_effect = run_side_effect

        scanner = _make_scanner()
        result = scanner.connect()

        assert result is mock_ctx

    @patch("oida.protocols.coap.scanner.run_async")
    @patch("oida.protocols.coap.scanner.create_context")
    @patch("oida.protocols.coap.scanner.coap_ping")
    def test_connect_ping_fails_get_fallback_fails(self, mock_ping, mock_create_ctx, mock_run):
        """When both ping and fallback GET fail, returns None."""
        mock_ping.return_value = False
        mock_ctx = MagicMock()

        call_count = 0

        def run_side_effect(coro):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return mock_ctx  # create_context
            elif call_count == 2:
                return ("timeout", b"")  # coap_get failed
            elif call_count == 3:
                return None  # shutdown_context
            return None

        mock_run.side_effect = run_side_effect

        scanner = _make_scanner()
        result = scanner.connect()

        assert result is None

    @patch("oida.protocols.coap.scanner.run_async")
    @patch("oida.protocols.coap.scanner.create_context")
    @patch("oida.protocols.coap.scanner.coap_ping")
    def test_connect_fallback_get_exception(self, mock_ping, mock_create_ctx, mock_run):
        """When fallback GET raises an exception, connect returns None."""
        mock_ping.return_value = False
        mock_run.side_effect = Exception("network error")

        scanner = _make_scanner()
        result = scanner.connect()

        assert result is None


class TestDisconnect:
    """Test CoAPScanner.disconnect()."""

    @patch("oida.protocols.coap.scanner.run_async")
    def test_disconnect_with_context(self, mock_run):
        scanner = _make_scanner()
        mock_ctx = MagicMock()

        scanner.disconnect(mock_ctx)

        mock_run.assert_called_once()

    @patch("oida.protocols.coap.scanner.run_async")
    def test_disconnect_with_none(self, mock_run):
        scanner = _make_scanner()
        scanner.disconnect(None)
        mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# Resource discovery
# ---------------------------------------------------------------------------


class TestDiscoverResources:
    """Test CoAPScanner._discover_resources()."""

    @patch("oida.protocols.coap.scanner.run_async")
    def test_discover_resources_success(self, mock_run):
        """Successful .well-known/core discovery returns parsed resources."""
        link_format = b'</sensor/temp>;obs;rt="temperature",</actuator/led>'
        mock_run.return_value = ("2.05", link_format, False)

        scanner = _make_scanner()
        ctx = MagicMock()
        resources = scanner._discover_resources(ctx)

        assert len(resources) == 2
        assert resources[0]["path"] == "/sensor/temp"
        assert resources[0].get("obs") is True
        assert resources[1]["path"] == "/actuator/led"

    @patch("oida.protocols.coap.scanner.run_async")
    def test_discover_resources_not_found(self, mock_run):
        """404 on .well-known/core returns empty list."""
        mock_run.return_value = ("4.04", b"", False)

        scanner = _make_scanner()
        resources = scanner._discover_resources(MagicMock())

        assert resources == []

    @patch("oida.protocols.coap.scanner.run_async")
    def test_discover_resources_timeout(self, mock_run):
        """Timeout on .well-known/core returns empty list."""
        mock_run.return_value = ("timeout", b"", False)

        scanner = _make_scanner()
        resources = scanner._discover_resources(MagicMock())

        assert resources == []

    @patch("oida.protocols.coap.scanner.run_async")
    def test_discover_resources_blockwise_retry_on_413(self, mock_run):
        """4.13 triggers blockwise retry."""
        call_count = 0

        def side_effect(coro):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return ("4.13", b"", False)  # first GET returns 4.13
            else:
                return ("2.05", b"</sensor/temp>")  # blockwise retry succeeds

        mock_run.side_effect = side_effect

        scanner = _make_scanner()
        resources = scanner._discover_resources(MagicMock())

        assert len(resources) == 1
        assert resources[0]["path"] == "/sensor/temp"
        assert call_count == 2

    @patch("oida.protocols.coap.scanner.run_async")
    def test_discover_resources_blockwise_retry_on_block2_more(self, mock_run):
        """A response with Block2 more=True triggers blockwise retry."""
        call_count = 0

        def side_effect(coro):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return ("2.05", b"</a>", True)  # truncated: block2.more=True
            else:
                return ("2.05", b"</sensor/temp>")

        mock_run.side_effect = side_effect

        scanner = _make_scanner()
        scanner._discover_resources(MagicMock())

        # Should have retried with blockwise
        assert call_count == 2

    @patch("oida.protocols.coap.scanner.run_async")
    def test_discover_resources_large_complete_payload_no_retry(self, mock_run):
        """A large but fully-reassembled payload (block2_more=False) must NOT
        trigger a redundant duplicate GET -- payload size alone is not a
        truncation signal since aiocoap already reassembles Block2 transfers
        transparently before coap_get_checked() returns."""
        call_count = 0
        large_payload = b"</a>" * 200  # 800 bytes > 512 block_size, but complete

        def side_effect(coro):
            nonlocal call_count
            call_count += 1
            return ("2.05", large_payload, False)

        mock_run.side_effect = side_effect

        scanner = _make_scanner()
        scanner._discover_resources(MagicMock())

        # Must NOT have retried -- only the single GET.
        assert call_count == 1


class TestProbeCommonPaths:
    """Test CoAPScanner._probe_common_paths()."""

    @patch("oida.protocols.coap.scanner.run_async")
    def test_probe_finds_some_paths(self, mock_run):
        """Found paths are returned with metadata."""
        call_count = 0

        def side_effect(coro):
            nonlocal call_count
            call_count += 1
            # First path found, rest not found
            if call_count == 1:
                return {"code": "2.05", "payload": b"hello", "content_format": 0}
            return {"code": "4.04", "payload": b""}

        mock_run.side_effect = side_effect

        scanner = _make_scanner()
        found = scanner._probe_common_paths(MagicMock())

        assert len(found) == 1
        assert found[0]["path"] == "/.well-known/core"
        assert found[0]["size"] == 5

    @patch("oida.protocols.coap.scanner.run_async")
    def test_probe_finds_no_paths(self, mock_run):
        """No paths found returns empty list."""
        mock_run.return_value = {"code": "4.04", "payload": b""}

        scanner = _make_scanner()
        found = scanner._probe_common_paths(MagicMock())

        assert found == []


# ---------------------------------------------------------------------------
# LwM2M fingerprinting
# ---------------------------------------------------------------------------


class TestFingerprintLwM2M:
    """Test CoAPScanner._fingerprint_lwm2m()."""

    @patch("oida.protocols.coap.scanner.run_async")
    def test_fingerprint_all_fields(self, mock_run):
        """All 4 LwM2M Device fields are readable."""
        responses = {
            0: b"OIDA Corp",
            1: b"Sensor-X100",
            2: b"SN-12345",
            3: b"1.2.3",
        }
        call_count = 0

        def side_effect(coro):
            nonlocal call_count
            payload = responses.get(call_count, b"")
            call_count += 1
            return ("2.05", payload)

        mock_run.side_effect = side_effect

        scanner = _make_scanner()
        info = scanner._fingerprint_lwm2m(MagicMock())

        assert info["manufacturer"] == "OIDA Corp"
        assert info["model"] == "Sensor-X100"
        assert info["serial"] == "SN-12345"
        assert info["firmware"] == "1.2.3"

    @patch("oida.protocols.coap.scanner.run_async")
    def test_fingerprint_partial_fields(self, mock_run):
        """Only some LwM2M fields return data."""
        call_count = 0

        def side_effect(coro):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return ("2.05", b"OIDA Corp")
            return ("4.04", b"")

        mock_run.side_effect = side_effect

        scanner = _make_scanner()
        info = scanner._fingerprint_lwm2m(MagicMock())

        assert info["manufacturer"] == "OIDA Corp"
        assert "model" not in info

    @patch("oida.protocols.coap.scanner.run_async")
    def test_fingerprint_no_lwm2m(self, mock_run):
        """All fields return 4.04."""
        mock_run.return_value = ("4.04", b"")

        scanner = _make_scanner()
        info = scanner._fingerprint_lwm2m(MagicMock())

        assert info == {}


class TestEnumerateLwM2MObjects:
    """Test CoAPScanner._enumerate_lwm2m_objects()."""

    @patch("oida.protocols.coap.scanner.run_async")
    def test_enumerate_finds_device_object(self, mock_run):
        """Device object /3/0 is accessible and returns resources."""

        def side_effect(coro):
            # Simulate: only /3/0 accessible; its resources are readable
            return ("2.05", b"some-value")

        mock_run.side_effect = side_effect

        scanner = _make_scanner()
        found = scanner._enumerate_lwm2m_objects(MagicMock())

        # Should find at least object 3 (Device)
        assert 3 in found
        assert found[3]["name"] == "Device"
        assert found[3]["accessible"] is True

    @patch("oida.protocols.coap.scanner.run_async")
    def test_enumerate_none_accessible(self, mock_run):
        """All objects return 4.04."""
        mock_run.return_value = ("4.04", b"")

        scanner = _make_scanner()
        found = scanner._enumerate_lwm2m_objects(MagicMock())

        assert found == {}


# ---------------------------------------------------------------------------
# Method testing
# ---------------------------------------------------------------------------


class TestMethodTesting:
    """Test CoAPScanner._test_methods()."""

    @patch("oida.protocols.coap.scanner.run_async")
    def test_methods_all_successful(self, mock_run):
        """All methods return 2.05 for a resource (when --confirm passed)."""
        mock_run.return_value = {"code": "2.05", "success": True, "payload": b"ok"}

        scanner = _make_scanner()
        resources = [{"path": "/test"}]
        matrix = scanner._test_methods(MagicMock(), resources, confirm=True)

        assert "/test" in matrix
        assert set(matrix["/test"].keys()) == {
            "GET",
            "PUT",
            "POST",
            "DELETE",
            "FETCH",
            "PATCH",
            "IPATCH",
        }
        for code in matrix["/test"].values():
            assert code == "2.05"

    @patch("oida.protocols.coap.scanner.run_async")
    def test_methods_default_safe_skips_writes(self, mock_run):
        """Without --confirm: GET/FETCH only; write methods carry sentinel string."""
        mock_run.return_value = {"code": "2.05", "success": True, "payload": b"ok"}

        scanner = _make_scanner()
        resources = [{"path": "/test"}]
        matrix = scanner._test_methods(MagicMock(), resources)  # default confirm=False

        assert matrix["/test"]["GET"] == "2.05"
        assert matrix["/test"]["FETCH"] == "2.05"
        for write_m in ("PUT", "POST", "DELETE", "PATCH", "IPATCH"):
            assert matrix["/test"][write_m] == "not-tested-without-confirm"

    @patch("oida.protocols.coap.scanner.run_async")
    def test_methods_mixed_results(self, mock_run):
        """GET succeeds, writes return 4.05 (when --confirm passed)."""
        call_count = 0

        def side_effect(coro):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {"code": "2.05", "success": True, "payload": b"ok"}
            return {"code": "4.05", "success": False, "payload": b""}

        mock_run.side_effect = side_effect

        scanner = _make_scanner()
        resources = [{"path": "/sensor/temp"}]
        matrix = scanner._test_methods(MagicMock(), resources, confirm=True)

        assert matrix["/sensor/temp"]["GET"] == "2.05"
        assert matrix["/sensor/temp"]["PUT"] == "4.05"

    @patch("oida.protocols.coap.scanner.run_async")
    def test_methods_empty_path_skipped(self, mock_run):
        """Resources without a path are skipped."""
        mock_run.return_value = {"code": "2.05", "success": True, "payload": b""}

        scanner = _make_scanner()
        resources = [{"path": ""}, {"path": "/valid"}]
        matrix = scanner._test_methods(MagicMock(), resources)

        assert "" not in matrix
        assert "/valid" in matrix

    @patch("oida.protocols.coap.scanner.run_async")
    def test_methods_empty_resources(self, mock_run):
        """Empty resource list returns empty matrix."""
        scanner = _make_scanner()
        matrix = scanner._test_methods(MagicMock(), [])

        assert matrix == {}
        mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# Security assessment
# ---------------------------------------------------------------------------


class TestCheckSecurity:
    """Test CoAPScanner._check_security()."""

    @patch("oida.protocols.coap.scanner.run_async")
    def test_dtls_available_with_coaps_scheme(self, mock_run):
        """dtls_available is True when _scheme is coaps (via -D flag)."""
        mock_run.return_value = ("4.04", b"")

        scanner = _make_scanner({"dtls": True})
        findings = scanner._check_security(MagicMock(), [], confirm=False)

        assert findings["dtls_available"] is True
        assert findings["dtls_port"] == 5683

    @patch("oida.protocols.coap.scanner.run_async")
    def test_dtls_not_available_without_flag(self, mock_run):
        """dtls_available is False when -D is not passed (plain CoAP)."""
        mock_run.return_value = ("4.04", b"")

        scanner = _make_scanner()
        findings = scanner._check_security(MagicMock(), [], confirm=False)

        assert findings["dtls_available"] is False

    @patch("oida.protocols.coap.scanner.run_async")
    def test_nosec_mode_detected(self, mock_run):
        """LwM2M Security Mode 3 (NoSec) is detected."""
        mock_run.return_value = ("2.05", b"3")  # security mode = NoSec

        scanner = _make_scanner()
        findings = scanner._check_security(MagicMock(), [], confirm=False)

        assert findings["lwm2m_security_mode"] == "NoSec"
        assert findings["nosec"] is True

    @patch("oida.protocols.coap.scanner.run_async")
    def test_psk_mode_detected(self, mock_run):
        """LwM2M Security Mode 0 (PSK) is detected."""
        mock_run.return_value = ("2.05", b"0")

        scanner = _make_scanner()
        findings = scanner._check_security(MagicMock(), [], confirm=False)

        assert findings["lwm2m_security_mode"] == "PSK"
        assert "nosec" not in findings

    @patch("oida.protocols.coap.scanner.run_async")
    def test_unauthenticated_write_with_confirm(self, mock_run):
        """Write probes are sent when confirm=True AND --methods is set."""
        call_count = 0

        def side_effect(coro):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return ("4.04", b"")  # security object not found
            # PUT probe succeeds
            return {"code": "2.04", "success": True}

        mock_run.side_effect = side_effect

        scanner = _make_scanner({"methods": True})
        resources = [{"path": "/actuator/led"}]
        findings = scanner._check_security(MagicMock(), resources, confirm=True)

        assert "/actuator/led" in findings.get("unauthenticated_writes", [])

    @patch("oida.protocols.coap.scanner.run_async")
    def test_no_write_probes_without_confirm(self, mock_run):
        """Write probes are NOT sent when confirm=False."""
        mock_run.return_value = ("4.04", b"")

        scanner = _make_scanner({"methods": True})
        resources = [{"path": "/actuator/led"}]
        findings = scanner._check_security(MagicMock(), resources, confirm=False)

        assert "unauthenticated_writes" not in findings

    @patch("oida.protocols.coap.scanner.run_async")
    def test_no_write_probes_confirm_without_methods(self, mock_run):
        """A bare --confirm (no --methods) must NOT fire actuator writes: the
        write probe requires explicit write-testing intent, not just --confirm."""
        mock_run.return_value = ("4.04", b"")

        scanner = _make_scanner()  # --methods not set
        resources = [{"path": "/actuator/led"}]
        findings = scanner._check_security(MagicMock(), resources, confirm=True)

        assert "unauthenticated_writes" not in findings
        # Only the security-object read should have run — no PUT probe.
        assert mock_run.call_count == 1

    @patch("oida.protocols.coap.scanner.run_async")
    def test_write_probe_denied(self, mock_run):
        """Write probe returns 4.01 (denied)."""
        call_count = 0

        def side_effect(coro):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return ("4.04", b"")  # security object not found
            return {"code": "4.01", "success": False}

        mock_run.side_effect = side_effect

        scanner = _make_scanner({"methods": True})
        resources = [{"path": "/actuator/led"}]
        findings = scanner._check_security(MagicMock(), resources, confirm=True)

        assert "unauthenticated_writes" not in findings

    @patch("oida.protocols.coap.scanner.run_async")
    def test_write_fallback_to_any_resource(self, mock_run):
        """When no /actuator paths, falls back to first available resource."""
        call_count = 0

        def side_effect(coro):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return ("4.04", b"")  # security object
            return {"code": "2.04", "success": True}

        mock_run.side_effect = side_effect

        scanner = _make_scanner({"methods": True})
        resources = [{"path": "/sensor/temp"}]
        findings = scanner._check_security(MagicMock(), resources, confirm=True)

        assert "/sensor/temp" in findings.get("unauthenticated_writes", [])


# ---------------------------------------------------------------------------
# Full discovery orchestration
# ---------------------------------------------------------------------------


class TestDiscover:
    """Test CoAPScanner.discover() orchestration."""

    @patch("oida.protocols.coap.scanner.CoAPScanner._check_security")
    @patch("oida.protocols.coap.scanner.CoAPScanner._fingerprint_lwm2m")
    @patch("oida.protocols.coap.scanner.CoAPScanner._discover_resources")
    def test_discover_all_phases(self, mock_discover, mock_lwm2m, mock_security):
        """discover() calls all three phases and assembles results."""
        mock_discover.return_value = [{"path": "/test"}]
        mock_lwm2m.return_value = {"manufacturer": "OIDA"}
        mock_security.return_value = {"dtls_available": False}

        scanner = _make_scanner()
        ctx = MagicMock()
        results = scanner.discover(ctx, confirm=False)

        assert "resources" in results
        assert len(results["resources"]) == 1
        assert results["lwm2m"]["manufacturer"] == "OIDA"
        assert results["security"]["dtls_available"] is False
        mock_discover.assert_called_once_with(ctx)
        mock_lwm2m.assert_called_once_with(ctx)
        mock_security.assert_called_once()

    @patch("oida.protocols.coap.scanner.CoAPScanner._check_security")
    @patch("oida.protocols.coap.scanner.CoAPScanner._fingerprint_lwm2m")
    @patch("oida.protocols.coap.scanner.CoAPScanner._discover_resources")
    def test_discover_empty_lwm2m_omitted(self, mock_discover, mock_lwm2m, mock_security):
        """Empty LwM2M result is not included in results dict."""
        mock_discover.return_value = []
        mock_lwm2m.return_value = {}
        mock_security.return_value = {"dtls_available": False}

        scanner = _make_scanner()
        results = scanner.discover(MagicMock(), confirm=False)

        assert "lwm2m" not in results

    @patch("oida.protocols.coap.scanner.CoAPScanner._check_security")
    @patch("oida.protocols.coap.scanner.CoAPScanner._fingerprint_lwm2m")
    @patch("oida.protocols.coap.scanner.CoAPScanner._discover_resources")
    def test_discover_with_confirm(self, mock_discover, mock_lwm2m, mock_security):
        """confirm=True is passed through to _check_security."""
        mock_discover.return_value = [{"path": "/test"}]
        mock_lwm2m.return_value = {}
        mock_security.return_value = {}

        scanner = _make_scanner()
        scanner.discover(MagicMock(), confirm=True)

        # Verify confirm was passed to _check_security
        call_args = mock_security.call_args
        assert call_args[1].get("confirm") is True or call_args[0][2] is True


# ---------------------------------------------------------------------------
# Observe resources
# ---------------------------------------------------------------------------


class TestObserveResources:
    """Test CoAPScanner._observe_resources()."""

    @patch("oida.protocols.coap.scanner.run_async")
    def test_no_observable_resources(self, mock_run):
        """No observable resources returns empty list."""
        scanner = _make_scanner()
        result = scanner._observe_resources(MagicMock(), [{"path": "/test"}], max_notifications=3)

        assert result == []
        mock_run.assert_not_called()

    @patch("oida.protocols.coap.scanner.run_async")
    def test_empty_resource_list(self, mock_run):
        """Empty resource list returns empty list."""
        scanner = _make_scanner()
        result = scanner._observe_resources(MagicMock(), [], max_notifications=3)

        assert result == []

    @patch("oida.protocols.coap.scanner.run_async")
    def test_observable_resource_with_empty_path_skipped(self, mock_run):
        """Observable resource with empty path is skipped."""
        scanner = _make_scanner()
        result = scanner._observe_resources(MagicMock(), [{"path": "", "obs": True}])

        assert result == []

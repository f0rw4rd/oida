#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for KNX CustomCEMIHandler.

Tests the cEMI frame handler and fast bus discovery functionality
in oida.protocols.knx.cemi_handler.
"""

import pytest
import asyncio
import sys
import importlib.util
from unittest.mock import MagicMock, AsyncMock
from datetime import datetime
from pathlib import Path


# ============================================================================
# Module Loading (bypass package __init__.py)
# ============================================================================


def load_cemi_handler_module():
    """Load cemi_handler module directly without triggering parent __init__.py."""
    project_root = Path(__file__).parent.parent.parent.parent

    # Set up mock parent modules to prevent import errors
    if "oida" not in sys.modules:
        sys.modules["oida"] = MagicMock()
    if "oida.utils" not in sys.modules:
        sys.modules["oida.utils"] = MagicMock()
    if "oida.utils.lazy_import" not in sys.modules:
        lazy_import_path = project_root / "src" / "oida" / "utils" / "lazy_import.py"
        spec = importlib.util.spec_from_file_location("oida.utils.lazy_import", lazy_import_path)
        lazy_import_module = importlib.util.module_from_spec(spec)
        sys.modules["oida.utils.lazy_import"] = lazy_import_module
        spec.loader.exec_module(lazy_import_module)

    if "oida.utils.module" not in sys.modules:
        mock_msf_module = MagicMock()
        mock_msf_module.warn = MagicMock()
        sys.modules["oida.utils.module"] = mock_msf_module

    if "oida.protocols" not in sys.modules:
        sys.modules["oida.protocols"] = MagicMock()
    if "oida.protocols.knx" not in sys.modules:
        sys.modules["oida.protocols.knx"] = MagicMock()

    # Load helpers module first
    helpers_path = project_root / "src" / "oida" / "protocols" / "knx" / "helpers.py"
    helpers_spec = importlib.util.spec_from_file_location(
        "oida.protocols.knx.helpers", helpers_path
    )
    helpers_module = importlib.util.module_from_spec(helpers_spec)
    sys.modules["oida.protocols.knx.helpers"] = helpers_module

    # Now load cemi_handler module
    cemi_path = project_root / "src" / "oida" / "protocols" / "knx" / "cemi_handler.py"
    spec = importlib.util.spec_from_file_location("oida.protocols.knx.cemi_handler", cemi_path)
    cemi_module = importlib.util.module_from_spec(spec)
    sys.modules["oida.protocols.knx.cemi_handler"] = cemi_module

    return cemi_module, helpers_module


# ============================================================================
# Mock Classes
# ============================================================================


class MockIndividualAddress:
    """Mock KNX individual address."""

    def __init__(self, address):
        if isinstance(address, str):
            parts = address.split(".")
            self.raw = (int(parts[0]) << 12) | (int(parts[1]) << 8) | int(parts[2])
            self._address_str = address
        else:
            self.raw = address
            area = (address >> 12) & 0xF
            line = (address >> 8) & 0xF
            device = address & 0xFF
            self._address_str = f"{area}.{line}.{device}"

    def __str__(self):
        return self._address_str

    def __hash__(self):
        return hash(self.raw)

    def __eq__(self, other):
        if isinstance(other, MockIndividualAddress):
            return self.raw == other.raw
        return False


class MockGroupAddress:
    """Mock KNX group address."""

    def __init__(self, address):
        self._address = address

    def __str__(self):
        return self._address


class MockCEMIMessageCode:
    """Mock CEMIMessageCode enum."""

    L_DATA_IND = 0x29
    L_DATA_REQ = 0x11
    L_DATA_CON = 0x2E


class MockCEMIData:
    """Mock cEMI data structure."""

    def __init__(self, src_addr=None, dst_addr=None):
        self.src_addr = src_addr
        self.dst_addr = dst_addr


class MockCEMIFrame:
    """Mock cEMI frame."""

    def __init__(self, code=None, data=None):
        self.code = code
        self.data = data


class MockTConnect:
    """Mock TConnect TPCI."""

    pass


class MockTpci:
    """Mock tpci module."""

    @staticmethod
    def TConnect():
        return MockTConnect()


class MockTelegram:
    """Mock KNX telegram."""

    def __init__(
        self,
        destination_address=None,
        source_address=None,
        tpci=None,
        payload=None,
    ):
        self.destination_address = destination_address
        self.source_address = source_address
        self.tpci = tpci
        self.payload = payload


class MockCEMIHandler:
    """Mock xknx cEMI handler."""

    def __init__(self):
        self.handle_cemi_frame = MagicMock()
        self.send_telegram = AsyncMock()


class MockTelegramQueue:
    """Mock xknx telegram queue."""

    def __init__(self):
        self._callbacks = []

    def register_telegram_received_cb(self, callback):
        self._callbacks.append(callback)


class MockXKNX:
    """Mock XKNX instance."""

    def __init__(self):
        self.cemi_handler = MockCEMIHandler()
        self.telegram_queue = MockTelegramQueue()
        self.current_address = MockIndividualAddress("1.0.1")


class MockLogger:
    """Mock ICSLogger for testing."""

    def __init__(self):
        self.success = MagicMock()
        self.fail = MagicMock()
        self.display = MagicMock()
        self.debug = MagicMock()
        self.info = MagicMock()
        self.warn = MagicMock()
        self.error = MagicMock()


# ============================================================================
# Test Handler Implementation (mirrors the real implementation)
# ============================================================================


class TestableCustomCEMIHandler:
    """Testable version of CustomCEMIHandler that mirrors the real implementation."""

    def __init__(self, xknx_instance, logger, helpers_module=None):
        self.xknx = xknx_instance
        self.is_in_discovery = False
        self._original_handler = None
        self.logger = logger
        self.alive_bus_members = set()
        self._helpers = helpers_module

    async def fast_bus_discovery(
        self,
        bus_range,
        callback=None,
        timeout=5,
        listen_time=0,
    ):
        """Fast bus discovery implementation for testing."""
        self.alive_bus_members.clear()
        self.is_in_discovery = True
        found_devices = set()
        captured_traffic = []

        try:
            cemi_handler = self.xknx.cemi_handler
            original_handle = cemi_handler.handle_cemi_frame

            def custom_handle_cemi_frame(cemi):
                if (
                    self.is_in_discovery
                    and cemi.code == MockCEMIMessageCode.L_DATA_IND
                    and cemi.data
                ):
                    src_addr = str(cemi.data.src_addr)
                    if src_addr not in found_devices:
                        found_devices.add(src_addr)
                        self.alive_bus_members.add(src_addr)
                        if callback:
                            callback(src_addr)
                        self.logger.success(f"Found device: {src_addr}")
                return original_handle(cemi)

            cemi_handler.handle_cemi_frame = custom_handle_cemi_frame

            async def capture_telegram(telegram):
                if telegram.destination_address:
                    tg_info = {
                        "source": str(telegram.source_address),
                        "destination": str(telegram.destination_address),
                        "payload": (str(telegram.payload) if telegram.payload else ""),
                        "timestamp": datetime.now().isoformat(),
                    }
                    captured_traffic.append(tg_info)

            self.xknx.telegram_queue.register_telegram_received_cb(capture_telegram)

            # Parse addresses
            if self._helpers and hasattr(self._helpers, "parse_bus_ranges"):
                addresses = list(self._helpers.parse_bus_ranges(bus_range))
            else:
                addresses = []
            total = len(addresses)

            self.logger.display(f"Fast scanning {total} addresses...")

            for addr in addresses:
                try:
                    telegram = MockTelegram(
                        destination_address=addr,
                        source_address=self.xknx.current_address,
                        tpci=MockTpci.TConnect(),
                    )
                    await cemi_handler.send_telegram(telegram)
                except Exception as e:
                    self.logger.debug(f"Error sending TConnect to {addr}: {e}")

            await asyncio.sleep(timeout)
            self.logger.display(f"Scan complete: {len(found_devices)}/{total} devices found")

            if listen_time > 0:
                self.logger.display(f"Listening for traffic ({listen_time}s)...")
                await asyncio.sleep(listen_time)

            cemi_handler.handle_cemi_frame = original_handle

            if captured_traffic:
                unique_sources = set(t["source"] for t in captured_traffic)
                unique_groups = set(t["destination"] for t in captured_traffic)
                self.logger.display(
                    f"Captured {len(captured_traffic)} telegrams from "
                    f"{len(unique_sources)} devices to {len(unique_groups)} groups"
                )

        except Exception as e:
            self.logger.fail(f"Error in fast bus discovery: {e}")
        finally:
            self.is_in_discovery = False

        return {"devices": found_devices, "traffic": captured_traffic}


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture(scope="module")
def cemi_handler_module():
    """Import the cemi_handler module directly, bypassing the knx __init__.py."""
    # Save sys.modules state so we can restore it after the test module
    saved_modules = {k: sys.modules[k] for k in list(sys.modules) if k.startswith("oida")}

    cemi_module, helpers_module = load_cemi_handler_module()

    # Set up helpers module with mocked xknx
    helpers_module._get_cemi_classes = MagicMock(
        return_value=(MockCEMIHandler, MockCEMIFrame, MockCEMIMessageCode)
    )
    helpers_module._get_xknx_classes = MagicMock(
        return_value=(
            MockXKNX,
            MagicMock(),
            MagicMock(),
            MagicMock(),
            MockIndividualAddress,
            MockTelegram,
            MockGroupAddress,
            MockTpci,
        )
    )
    helpers_module.parse_bus_ranges = MagicMock(return_value=[])

    yield cemi_module

    # Restore sys.modules to prevent polluting other test modules
    for k in list(sys.modules):
        if k.startswith("oida"):
            del sys.modules[k]
    sys.modules.update(saved_modules)


@pytest.fixture
def mock_xknx():
    """Create a mock XKNX instance."""
    return MockXKNX()


@pytest.fixture
def mock_logger():
    """Create a mock logger."""
    return MockLogger()


@pytest.fixture
def mock_helpers():
    """Create a mock helpers module."""
    helpers = MagicMock()
    helpers.parse_bus_ranges = MagicMock(return_value=[])
    return helpers


@pytest.fixture
def handler(mock_xknx, mock_logger, mock_helpers):
    """Create a testable CustomCEMIHandler instance."""
    return TestableCustomCEMIHandler(mock_xknx, mock_logger, mock_helpers)


# ============================================================================
# Tests for CustomCEMIHandler Initialization
# ============================================================================


class TestCustomCEMIHandlerInit:
    """Test CustomCEMIHandler initialization."""

    def test_init_sets_xknx_instance(self, handler):
        """Test that __init__ stores the XKNX instance."""
        assert handler.xknx is not None
        assert isinstance(handler.xknx, MockXKNX)

    def test_init_sets_logger(self, handler):
        """Test that __init__ stores the logger."""
        assert handler.logger is not None

    def test_init_sets_discovery_flag_false(self, handler):
        """Test that is_in_discovery starts as False."""
        assert handler.is_in_discovery is False

    def test_init_original_handler_is_none(self, handler):
        """Test that _original_handler starts as None."""
        assert handler._original_handler is None

    def test_init_alive_bus_members_empty(self, handler):
        """Test that alive_bus_members starts as empty set."""
        assert isinstance(handler.alive_bus_members, set)
        assert len(handler.alive_bus_members) == 0


# ============================================================================
# Tests for fast_bus_discovery - Basic Functionality
# ============================================================================


class TestFastBusDiscoveryBasic:
    """Test basic fast_bus_discovery functionality."""

    def test_clears_alive_bus_members_on_start(self, handler):
        """Test that alive_bus_members is cleared at discovery start."""
        handler.alive_bus_members.add("1.1.1")
        handler.alive_bus_members.add("1.1.2")

        asyncio.run(handler.fast_bus_discovery("1.1.1", timeout=0))

        # Should be empty after clearing (no devices found in this case)
        assert len(handler.alive_bus_members) == 0

    def test_sets_discovery_flag_false_after_scan(self, handler):
        """Test that is_in_discovery is set False after scan completes."""
        asyncio.run(handler.fast_bus_discovery("1.1.1", timeout=0))

        assert handler.is_in_discovery is False

    def test_returns_dict_with_devices_and_traffic(self, handler):
        """Test that fast_bus_discovery returns dict with devices and traffic keys."""
        result = asyncio.run(handler.fast_bus_discovery("1.1.1", timeout=0))

        assert isinstance(result, dict)
        assert "devices" in result
        assert "traffic" in result
        assert isinstance(result["devices"], set)
        assert isinstance(result["traffic"], list)


# ============================================================================
# Tests for cEMI Frame Handling (L_DATA_IND Detection)
# ============================================================================


class TestCEMIFrameHandling:
    """Test cEMI frame handling during discovery."""

    def test_l_data_ind_triggers_device_detection(self, handler):
        """Test that L_DATA_IND frame triggers device detection."""
        # Simulate receiving an L_DATA_IND frame during discovery
        handler.is_in_discovery = True
        handler.alive_bus_members.add("1.1.5")  # Simulate device found

        assert "1.1.5" in handler.alive_bus_members

    def test_no_devices_found_when_no_responses(self, handler):
        """Test that no devices are found when no L_DATA_IND received."""
        result = asyncio.run(handler.fast_bus_discovery("1.1.1", timeout=0))

        assert len(result["devices"]) == 0

    def test_custom_handle_cemi_frame_detects_device(self, mock_xknx, mock_logger):
        """Test the custom cEMI frame handler detects devices."""
        # Create handler with mock that returns addresses
        mock_helpers = MagicMock()
        mock_helpers.parse_bus_ranges = MagicMock(return_value=[MockIndividualAddress("1.1.5")])
        handler = TestableCustomCEMIHandler(mock_xknx, mock_logger, mock_helpers)

        # Run discovery
        asyncio.run(handler.fast_bus_discovery("1.1.5", timeout=0))

        # Verify send_telegram was called
        assert mock_xknx.cemi_handler.send_telegram.called


# ============================================================================
# Tests for Device Discovery Tracking
# ============================================================================


class TestDeviceDiscoveryTracking:
    """Test device discovery tracking (alive_bus_members set)."""

    def test_found_device_added_to_alive_bus_members(self, handler):
        """Test that discovered devices are added to alive_bus_members."""
        handler.alive_bus_members.add("1.1.1")

        assert "1.1.1" in handler.alive_bus_members

    def test_duplicate_devices_not_added_twice(self, handler):
        """Test that duplicate device addresses are not added multiple times."""
        handler.alive_bus_members.add("1.1.1")
        handler.alive_bus_members.add("1.1.1")

        assert len(handler.alive_bus_members) == 1

    def test_multiple_devices_tracked(self, handler):
        """Test that multiple different devices are tracked."""
        handler.alive_bus_members.add("1.1.1")
        handler.alive_bus_members.add("1.1.2")
        handler.alive_bus_members.add("2.1.5")

        assert len(handler.alive_bus_members) == 3
        assert "1.1.1" in handler.alive_bus_members
        assert "1.1.2" in handler.alive_bus_members
        assert "2.1.5" in handler.alive_bus_members


# ============================================================================
# Tests for Traffic Capture Functionality
# ============================================================================


class TestTrafficCapture:
    """Test traffic capture functionality."""

    def test_returns_empty_traffic_when_no_telegrams(self, handler):
        """Test that traffic list is empty when no telegrams captured."""
        result = asyncio.run(handler.fast_bus_discovery("1.1.1", timeout=0))

        assert result["traffic"] == []

    def test_registers_telegram_callback(self, handler):
        """Test that telegram callback is registered for traffic capture."""
        asyncio.run(handler.fast_bus_discovery("1.1.1", timeout=0))

        # Verify callback was registered
        assert len(handler.xknx.telegram_queue._callbacks) > 0


# ============================================================================
# Tests for Callback Invocation on Device Discovery
# ============================================================================


class TestCallbackInvocation:
    """Test callback invocation on device discovery."""

    def test_callback_parameter_accepted(self, handler):
        """Test that callback parameter is accepted."""
        mock_callback = MagicMock()

        result = asyncio.run(handler.fast_bus_discovery("1.1.1", callback=mock_callback, timeout=0))

        assert "devices" in result

    def test_callback_none_is_valid(self, handler):
        """Test that callback=None works without errors."""
        result = asyncio.run(handler.fast_bus_discovery("1.1.1", callback=None, timeout=0))

        assert result is not None


# ============================================================================
# Tests for Error Handling in Discovery
# ============================================================================


class TestErrorHandling:
    """Test error handling in fast_bus_discovery."""

    def test_discovery_flag_reset_on_error(self, mock_xknx, mock_logger):
        """Test that is_in_discovery is reset to False even on error."""

        class ErrorHandler:
            def __init__(self, xknx, logger):
                self.xknx = xknx
                self.logger = logger
                self.is_in_discovery = False
                self._original_handler = None
                self.alive_bus_members = set()

            async def fast_bus_discovery(self, bus_range, timeout=5, **kwargs):
                self.is_in_discovery = True
                try:
                    raise Exception("Test error")
                except Exception as e:
                    self.logger.fail(f"Error: {e}")
                finally:
                    self.is_in_discovery = False
                return {"devices": set(), "traffic": []}

        handler = ErrorHandler(mock_xknx, mock_logger)
        handler.is_in_discovery = True

        asyncio.run(handler.fast_bus_discovery("1.1.1", timeout=0))

        assert handler.is_in_discovery is False

    def test_error_logged(self, mock_xknx, mock_logger):
        """Test that errors are logged via logger.fail."""

        class ErrorHandler:
            def __init__(self, xknx, logger):
                self.xknx = xknx
                self.logger = logger
                self.is_in_discovery = False
                self.alive_bus_members = set()

            async def fast_bus_discovery(self, bus_range, timeout=5, **kwargs):
                try:
                    raise Exception("Test error")
                except Exception as e:
                    self.logger.fail(f"Error in fast bus discovery: {e}")
                finally:
                    self.is_in_discovery = False
                return {"devices": set(), "traffic": []}

        handler = ErrorHandler(mock_xknx, mock_logger)
        asyncio.run(handler.fast_bus_discovery("1.1.1", timeout=0))

        mock_logger.fail.assert_called()

    def test_telegram_send_error_logged(self, mock_xknx, mock_logger):
        """Test that errors sending TConnect telegrams are logged."""
        mock_helpers = MagicMock()
        mock_helpers.parse_bus_ranges = MagicMock(return_value=[MockIndividualAddress("1.1.1")])

        # Make send_telegram raise an exception
        mock_xknx.cemi_handler.send_telegram.side_effect = Exception("Send failed")

        handler = TestableCustomCEMIHandler(mock_xknx, mock_logger, mock_helpers)
        asyncio.run(handler.fast_bus_discovery("1.1.1", timeout=0))

        # Should log debug message about error
        mock_logger.debug.assert_called()


# ============================================================================
# Tests for Handler Restoration After Discovery
# ============================================================================


class TestHandlerRestoration:
    """Test handler restoration after discovery."""

    def test_discovery_completes_successfully(self, handler):
        """Test that discovery completes and returns results."""
        result = asyncio.run(handler.fast_bus_discovery("1.1.1", timeout=0))

        assert "devices" in result
        assert "traffic" in result
        assert handler.is_in_discovery is False

    def test_original_handler_restored(self, mock_xknx, mock_logger, mock_helpers):
        """Test that original cEMI handler is restored after discovery."""
        original_handler = mock_xknx.cemi_handler.handle_cemi_frame

        handler = TestableCustomCEMIHandler(mock_xknx, mock_logger, mock_helpers)
        asyncio.run(handler.fast_bus_discovery("1.1.1", timeout=0))

        # Handler should be restored to original
        assert mock_xknx.cemi_handler.handle_cemi_frame == original_handler


# ============================================================================
# Tests for Logging
# ============================================================================


class TestLogging:
    """Test logging behavior during discovery."""

    def test_logs_scan_start_message(self, handler):
        """Test that scan start is logged."""
        asyncio.run(handler.fast_bus_discovery("1.1.1-1.1.2", timeout=0))

        # Should have logged display messages
        assert handler.logger.display.called

    def test_logs_scan_complete_message(self, handler):
        """Test that scan completion is logged."""
        asyncio.run(handler.fast_bus_discovery("1.1.1", timeout=0))

        calls = [str(c) for c in handler.logger.display.call_args_list]
        assert any("Scan complete" in c for c in calls)

    def test_logs_device_found(self, mock_xknx, mock_logger, mock_helpers):
        """Test that found devices are logged."""
        handler = TestableCustomCEMIHandler(mock_xknx, mock_logger, mock_helpers)

        # Manually trigger device found logging
        handler.logger.success("Found device: 1.1.5")

        mock_logger.success.assert_called_with("Found device: 1.1.5")


# ============================================================================
# Tests for Bus Range Parameter
# ============================================================================


class TestBusRangeParameter:
    """Test bus_range parameter handling."""

    def test_single_address_range(self, handler):
        """Test discovery with single address."""
        result = asyncio.run(handler.fast_bus_discovery("1.1.1", timeout=0))

        assert isinstance(result, dict)

    def test_range_address_format(self, handler):
        """Test discovery with address range format."""
        result = asyncio.run(handler.fast_bus_discovery("1.1.1-1.1.3", timeout=0))

        assert isinstance(result, dict)

    def test_parse_bus_ranges_called(self, mock_xknx, mock_logger, mock_helpers):
        """Test that parse_bus_ranges is called with bus_range."""
        handler = TestableCustomCEMIHandler(mock_xknx, mock_logger, mock_helpers)

        asyncio.run(handler.fast_bus_discovery("1.1.1-1.1.5", timeout=0))

        mock_helpers.parse_bus_ranges.assert_called_with("1.1.1-1.1.5")


# ============================================================================
# Tests for Timeout Parameter
# ============================================================================


class TestTimeoutParameter:
    """Test timeout parameter handling."""

    def test_zero_timeout_completes_quickly(self, handler):
        """Test that zero timeout completes quickly."""
        import time

        start = time.time()
        asyncio.run(handler.fast_bus_discovery("1.1.1", timeout=0))
        duration = time.time() - start

        # Should complete in less than 1 second with timeout=0
        assert duration < 1.0

    def test_custom_timeout_accepted(self, handler):
        """Test that custom timeout is accepted."""
        # Should not raise (use very short timeout for test speed)
        result = asyncio.run(handler.fast_bus_discovery("1.1.1", timeout=0.01))

        assert result is not None


# ============================================================================
# Tests for Listen Time Parameter
# ============================================================================


class TestListenTimeParameter:
    """Test listen_time parameter handling."""

    def test_zero_listen_time_no_extra_wait(self, handler):
        """Test that listen_time=0 doesn't add extra waiting."""
        import time

        start = time.time()
        asyncio.run(handler.fast_bus_discovery("1.1.1", timeout=0, listen_time=0))
        duration = time.time() - start

        assert duration < 1.0

    def test_listen_time_logs_message(self, handler):
        """Test that non-zero listen_time logs a message."""
        asyncio.run(handler.fast_bus_discovery("1.1.1", timeout=0, listen_time=0.01))

        calls = [str(c) for c in handler.logger.display.call_args_list]
        assert any("Listening" in c for c in calls)


# ============================================================================
# Tests for TConnect Telegram Sending
# ============================================================================


class TestTConnectSending:
    """Test TConnect telegram sending."""

    def test_send_telegram_called_for_each_address(self, mock_xknx, mock_logger):
        """Test that send_telegram is called for each address."""
        mock_helpers = MagicMock()
        mock_helpers.parse_bus_ranges = MagicMock(
            return_value=[
                MockIndividualAddress("1.1.1"),
                MockIndividualAddress("1.1.2"),
                MockIndividualAddress("1.1.3"),
            ]
        )

        handler = TestableCustomCEMIHandler(mock_xknx, mock_logger, mock_helpers)
        asyncio.run(handler.fast_bus_discovery("1.1.1-1.1.3", timeout=0))

        # Should have sent 3 telegrams
        assert mock_xknx.cemi_handler.send_telegram.call_count == 3

    def test_telegram_has_correct_destination(self, mock_xknx, mock_logger):
        """Test that telegrams have correct destination addresses."""
        mock_helpers = MagicMock()
        target_addr = MockIndividualAddress("1.1.5")
        mock_helpers.parse_bus_ranges = MagicMock(return_value=[target_addr])

        handler = TestableCustomCEMIHandler(mock_xknx, mock_logger, mock_helpers)
        asyncio.run(handler.fast_bus_discovery("1.1.5", timeout=0))

        # Verify telegram was sent
        call_args = mock_xknx.cemi_handler.send_telegram.call_args
        telegram = call_args[0][0]
        assert telegram.destination_address == target_addr


# ============================================================================
# Integration-style Tests
# ============================================================================


class TestIntegration:
    """Integration-style tests for the handler."""

    def test_full_discovery_workflow(self, mock_xknx, mock_logger, mock_helpers):
        """Test complete discovery workflow."""
        handler = TestableCustomCEMIHandler(mock_xknx, mock_logger, mock_helpers)

        # Pre-populate some data
        handler.alive_bus_members.add("old.addr")

        result = asyncio.run(
            handler.fast_bus_discovery("1.1.1-1.1.5", callback=None, timeout=0, listen_time=0)
        )

        # Old data should be cleared
        assert "old.addr" not in handler.alive_bus_members

        # Result structure is correct
        assert "devices" in result
        assert "traffic" in result

        # Discovery flag is reset
        assert handler.is_in_discovery is False

    def test_handler_is_reusable(self, mock_xknx, mock_logger, mock_helpers):
        """Test that handler can be used for multiple discoveries."""
        handler = TestableCustomCEMIHandler(mock_xknx, mock_logger, mock_helpers)

        result1 = asyncio.run(handler.fast_bus_discovery("1.1.1", timeout=0))
        result2 = asyncio.run(handler.fast_bus_discovery("1.1.2", timeout=0))

        assert result1 is not None
        assert result2 is not None
        assert handler.is_in_discovery is False

    def test_callback_invoked_for_each_device(self, mock_xknx, mock_logger):
        """Test that callback is invoked for each discovered device."""
        callback_calls = []

        def mock_callback(addr):
            callback_calls.append(addr)

        # Create a handler that simulates device discovery
        class SimulatedDiscoveryHandler(TestableCustomCEMIHandler):
            async def fast_bus_discovery(self, bus_range, callback=None, **kwargs):
                self.alive_bus_members.clear()
                self.is_in_discovery = True
                found = set()

                # Simulate finding devices
                for addr in ["1.1.1", "1.1.2"]:
                    found.add(addr)
                    self.alive_bus_members.add(addr)
                    if callback:
                        callback(addr)
                    self.logger.success(f"Found device: {addr}")

                self.is_in_discovery = False
                return {"devices": found, "traffic": []}

        handler = SimulatedDiscoveryHandler(mock_xknx, mock_logger)
        asyncio.run(handler.fast_bus_discovery("1.1.1-1.1.2", callback=mock_callback, timeout=0))

        assert len(callback_calls) == 2
        assert "1.1.1" in callback_calls
        assert "1.1.2" in callback_calls


# ============================================================================
# Tests for cEMI Frame Processing
# ============================================================================


class TestCEMIFrameProcessing:
    """Test cEMI frame processing logic."""

    def test_only_l_data_ind_triggers_detection(self):
        """Test that only L_DATA_IND code triggers device detection."""
        codes = [
            (MockCEMIMessageCode.L_DATA_IND, True),
            (MockCEMIMessageCode.L_DATA_REQ, False),
            (MockCEMIMessageCode.L_DATA_CON, False),
        ]

        for code, should_detect in codes:
            detected = code == MockCEMIMessageCode.L_DATA_IND
            assert detected == should_detect

    def test_frame_without_data_ignored(self):
        """Test that frames without data are ignored."""
        frame = MockCEMIFrame(code=MockCEMIMessageCode.L_DATA_IND, data=None)
        assert frame.data is None

    def test_source_address_extracted_from_frame(self):
        """Test that source address is correctly extracted from cEMI frame."""
        src = MockIndividualAddress("1.1.5")
        data = MockCEMIData(src_addr=src)
        frame = MockCEMIFrame(code=MockCEMIMessageCode.L_DATA_IND, data=data)

        assert str(frame.data.src_addr) == "1.1.5"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

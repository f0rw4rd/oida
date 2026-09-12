"""
Tier 2: "Monitor baseline" integration tests.

For P0 protocols, run fuzzer for ~20 iterations with the protocol monitor
enabled. Assert the monitor actually ran checks and did not immediately fail.

This catches monitors that fail silently or crash when receiving real
protocol responses.
"""

import pytest

from tests.service_gate import require_import, require_service

from .conftest import FuzzTimeout, create_fuzzer_config, run_fuzz_with_timeout
from .mock_servers import (
    iec104_server,
    mms_server,
    modbus_server,
    mqtt_server,
    opcua_server,
)

pytestmark = pytest.mark.integration_fuzzers


# ============================================================================
# Modbus Monitor Baseline
# ============================================================================


class TestModbusMonitorBaseline:
    """Verify ModbusMonitor works against a real Modbus server."""

    def test_monitor_runs_checks(self, tmp_path):
        """Monitor should perform at least one check during a short fuzz run."""
        boofuzz = require_import("boofuzz")  # noqa: F841
        from oida.fuzz.core.config import MonitorConfig
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get("modbus")
        if not fuzzer_class:
            require_service("Modbus fuzzer not available")

        with modbus_server() as server:
            config = create_fuzzer_config(
                server.host,
                server.port,
                "modbus",
                str(tmp_path / "session"),
                index_end=20,
                monitor_config=MonitorConfig.parse("modbus:5,socket"),
                monitor_check_interval=5,
                skip_pre_send_checks=False,
            )
            try:
                fuzzer = fuzzer_class(config=config)
                run_fuzz_with_timeout(fuzzer.fuzz_all, timeout_seconds=20)
            except (FuzzTimeout, ConnectionError, OSError):
                pass
            except ImportError as e:
                require_service(f"Missing dependency: {e}")

            # The monitor should have run at least one check
            if hasattr(fuzzer, "monitor") and fuzzer.monitor:
                assert fuzzer.monitor.actual_check_count >= 1, (
                    f"Monitor should have performed at least 1 check, "
                    f"got {fuzzer.monitor.actual_check_count}"
                )


# ============================================================================
# IEC 104 Monitor Baseline
# ============================================================================


class TestIEC104MonitorBaseline:
    """Verify IEC104Monitor works against a real IEC 104 server."""

    def test_monitor_runs_checks(self, tmp_path):
        boofuzz = require_import("boofuzz")  # noqa: F841
        from oida.fuzz.core.config import MonitorConfig
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get("iec104")
        if not fuzzer_class:
            require_service("IEC 104 fuzzer not available")

        with iec104_server() as server:
            config = create_fuzzer_config(
                server.host,
                server.port,
                "iec104",
                str(tmp_path / "session"),
                index_end=20,
                monitor_config=MonitorConfig.parse("iec104:5,socket"),
                monitor_check_interval=5,
                skip_pre_send_checks=False,
            )
            try:
                fuzzer = fuzzer_class(config=config)
                run_fuzz_with_timeout(fuzzer.fuzz_all, timeout_seconds=20)
            except (FuzzTimeout, ConnectionError, OSError):
                pass
            except ImportError as e:
                require_service(f"Missing dependency: {e}")

            if hasattr(fuzzer, "monitor") and fuzzer.monitor:
                assert fuzzer.monitor.actual_check_count >= 1, (
                    f"IEC 104 monitor should have checked at least once, "
                    f"got {fuzzer.monitor.actual_check_count}"
                )


# ============================================================================
# MMS Monitor Baseline
# ============================================================================


class TestMMSMonitorBaseline:
    """Verify MMSMonitor works against a real MMS server."""

    def test_monitor_runs_checks(self, tmp_path):
        boofuzz = require_import("boofuzz")  # noqa: F841
        from oida.fuzz.core.config import MonitorConfig
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get("mms")
        if not fuzzer_class:
            require_service("MMS fuzzer not available")

        with mms_server() as server:
            config = create_fuzzer_config(
                server.host,
                server.port,
                "mms",
                str(tmp_path / "session"),
                index_end=20,
                monitor_config=MonitorConfig.parse("mms:5,socket"),
                monitor_check_interval=5,
                skip_pre_send_checks=False,
            )
            try:
                fuzzer = fuzzer_class(config=config)
                run_fuzz_with_timeout(fuzzer.fuzz_all, timeout_seconds=20)
            except (FuzzTimeout, ConnectionError, OSError):
                pass
            except ImportError as e:
                require_service(f"Missing dependency: {e}")

            if hasattr(fuzzer, "monitor") and fuzzer.monitor:
                assert fuzzer.monitor.actual_check_count >= 1, (
                    f"MMS monitor should have checked at least once, "
                    f"got {fuzzer.monitor.actual_check_count}"
                )


# ============================================================================
# MQTT Monitor Baseline
# ============================================================================


class TestMQTTMonitorBaseline:
    """Verify MQTTMonitor works against a real MQTT broker."""

    def test_monitor_runs_checks(self, tmp_path):
        boofuzz = require_import("boofuzz")  # noqa: F841
        from oida.fuzz.core.config import MonitorConfig
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get("mqtt")
        if not fuzzer_class:
            require_service("MQTT fuzzer not available")

        with mqtt_server() as server:
            config = create_fuzzer_config(
                server.host,
                server.port,
                "mqtt",
                str(tmp_path / "session"),
                index_end=20,
                monitor_config=MonitorConfig.parse("mqtt,socket"),
                monitor_check_interval=5,
                skip_pre_send_checks=False,
            )
            try:
                fuzzer = fuzzer_class(config=config)
                run_fuzz_with_timeout(fuzzer.fuzz_all, timeout_seconds=20)
            except (FuzzTimeout, ConnectionError, OSError):
                pass
            except ImportError as e:
                require_service(f"Missing dependency: {e}")

            if hasattr(fuzzer, "monitor") and fuzzer.monitor:
                assert fuzzer.monitor.actual_check_count >= 1, (
                    f"MQTT monitor should have checked at least once, "
                    f"got {fuzzer.monitor.actual_check_count}"
                )


# ============================================================================
# OPC UA Monitor Baseline
# ============================================================================


class TestOPCUAMonitorBaseline:
    """Verify OPCUAMonitor works against a real OPC UA server."""

    def test_monitor_runs_checks(self, tmp_path):
        boofuzz = require_import("boofuzz")  # noqa: F841
        from oida.fuzz.core.config import MonitorConfig
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get("opcua")
        if not fuzzer_class:
            require_service("OPC UA fuzzer not available")

        with opcua_server() as server:
            config = create_fuzzer_config(
                server.host,
                server.port,
                "opcua",
                str(tmp_path / "session"),
                index_end=20,
                monitor_config=MonitorConfig.parse("opcua,socket"),
                monitor_check_interval=5,
                skip_pre_send_checks=False,
            )
            try:
                fuzzer = fuzzer_class(config=config)
                run_fuzz_with_timeout(fuzzer.fuzz_all, timeout_seconds=20)
            except (FuzzTimeout, ConnectionError, OSError):
                pass
            except ImportError as e:
                require_service(f"Missing dependency: {e}")

            if hasattr(fuzzer, "monitor") and fuzzer.monitor:
                assert fuzzer.monitor.actual_check_count >= 1, (
                    f"OPC UA monitor should have checked at least once, "
                    f"got {fuzzer.monitor.actual_check_count}"
                )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--timeout=120"])

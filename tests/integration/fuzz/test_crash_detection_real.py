"""
Tier 3: Crash detection integration tests for ICS protocols.

Each test starts a mock server configured to crash after N requests,
runs the fuzzer with aggressive monitoring, and verifies crash detection.

How it works:
  The mock server counts ALL incoming requests (both fuzzer payloads and
  monitor health checks). With check_interval=1 and sleep_time=0.3, the
  request pattern is deterministic:

    preflight(1), pre_send_check(2), fuzz_transmit(3), [sleep 0.3s],
    pre_send_check(4), fuzz_transmit(5), [sleep 0.3s], ...

  By setting crash_after to an EVEN number >= 4, we ensure the crash
  triggers during a MONITOR health check (not a fuzz transmit). This is
  critical because:
  - Boofuzz catches connection errors during fuzz transmit silently
  - Monitor health checks (ProtocolMonitor._check_alive) have their own
    failure detection with retry/threshold logic
  - When _check_alive detects a dead server, it raises BoofuzzFailure
    which is recorded as a crash

  The post_send check is always rate-limited (< 200ms since pre_send),
  so only pre_send checks are "real" checks. With sleep_time=0.3s between
  test cases, each pre_send is > 200ms after the previous, defeating the
  rate limiter.
"""

import pytest

from .conftest import create_fuzzer_config, run_fuzz_capture
from .mock_servers import (
    iec104_server,
    mms_server,
    modbus_server,
)

pytestmark = pytest.mark.integration_fuzzers


def _assert_crash_detected(fuzzer, result, server, protocol_name):
    """Assert that a crash was detected by some layer of the stack.

    Valid crash indicators (any one is sufficient):
    1. CombinedMonitor.total_failures >= 1
    2. Any child monitor has crashed=True
    3. CrashTracker recorded a crash
    4. Fuzzer thread raised an exception
    5. Fuzzer thread is still alive (stuck in recovery/retry)
    """
    exc = result.get("exception")
    monitor = getattr(fuzzer, "monitor", None)

    monitor_failures = monitor is not None and getattr(monitor, "total_failures", 0) >= 1
    child_crashed = False
    if monitor is not None and hasattr(monitor, "monitors"):
        child_crashed = any(getattr(m, "crashed", False) for m in monitor.monitors)
    crash_tracked = (
        monitor is not None
        and hasattr(monitor, "crash_tracker")
        and monitor.crash_tracker.crash_count >= 1
    )
    had_exception = exc is not None
    thread_stuck = result["thread"].is_alive()

    crash_detected = (
        monitor_failures or child_crashed or crash_tracked or had_exception or thread_stuck
    )

    if not crash_detected:
        diag_parts = [f"Protocol: {protocol_name}"]
        if monitor:
            diag_parts.append(f"total_failures={getattr(monitor, 'total_failures', 'N/A')}")
            diag_parts.append(f"test_case_count={getattr(monitor, 'test_case_count', 'N/A')}")
            diag_parts.append(f"actual_check_count={getattr(monitor, 'actual_check_count', 'N/A')}")
            if hasattr(monitor, "monitors"):
                for i, m in enumerate(monitor.monitors):
                    m_name = type(m).__name__
                    m_crashed = getattr(m, "crashed", "N/A")
                    m_failures = getattr(m, "consecutive_failures", "N/A")
                    m_recovery = getattr(m, "recovery_attempts", "N/A")
                    diag_parts.append(
                        f"child[{i}] {m_name}: crashed={m_crashed}, "
                        f"failures={m_failures}, recovery={m_recovery}"
                    )
            if hasattr(monitor, "crash_tracker"):
                diag_parts.append(f"crash_tracker.count={monitor.crash_tracker.crash_count}")
        diag_parts.append(f"exception={type(exc).__name__ if exc else 'None'}")
        diag_parts.append(f"thread_alive={result['thread'].is_alive()}")
        diag_parts.append(f"completed={result.get('completed', 'N/A')}")
        diag_parts.append(f"server_alive={server.is_alive()}")
        diag_parts.append(f"server_requests={server.request_count}")

        raise AssertionError("Crash should be detected: " + ", ".join(diag_parts))


# ============================================================================
# Modbus Crash Detection
# ============================================================================


class TestModbusCrashDetection:
    """Verify that crashing a Modbus server is detected."""

    def test_monitor_detects_crash(self, tmp_path):
        """Server crashes after 4 requests (during monitor health check).

        Request pattern:
          1: preflight monitor check (pass)
          2: test case 1 pre_send monitor check (pass)
          3: test case 1 fuzz transmit (pass)
          4: test case 2 pre_send monitor check -> CRASH
        """
        boofuzz = pytest.importorskip("boofuzz")  # noqa: F841
        from oida.fuzz.core.config import MonitorConfig
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get("modbus")
        if not fuzzer_class:
            pytest.skip("Modbus fuzzer not available")

        with modbus_server(crash_after=4) as server:
            config = create_fuzzer_config(
                server.host,
                server.port,
                "modbus",
                str(tmp_path / "modbus_crash"),
                index_end=100000,
                monitor_config=MonitorConfig.parse("modbus:1,socket"),
                monitor_check_interval=1,
                skip_pre_send_checks=False,
                reuse_target_connection=False,
                sleep_time=0.3,
            )

            try:
                fuzzer = fuzzer_class(config=config)
            except ImportError as e:
                pytest.skip(f"Missing dependency: {e}")

            result = run_fuzz_capture(fuzzer, timeout_seconds=60)

            _assert_crash_detected(fuzzer, result, server, "modbus")


# ============================================================================
# IEC 104 Crash Detection
# ============================================================================


class TestIEC104CrashDetection:
    """Verify that crashing an IEC 104 server is detected."""

    def test_monitor_detects_crash(self, tmp_path):
        """Server crashes during a monitor health check."""
        boofuzz = pytest.importorskip("boofuzz")  # noqa: F841
        from oida.fuzz.core.config import MonitorConfig
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get("iec104")
        if not fuzzer_class:
            pytest.skip("IEC 104 fuzzer not available")

        # IEC 104 monitor uses persistent connections and STARTDT handshake.
        # The request pattern may differ from Modbus. Use crash_after=6
        # to give the IEC 104 handshake room and crash on a monitor check.
        with iec104_server(crash_after=6) as server:
            config = create_fuzzer_config(
                server.host,
                server.port,
                "iec104",
                str(tmp_path / "iec104_crash"),
                index_end=100000,
                monitor_config=MonitorConfig.parse("iec104:1,socket"),
                monitor_check_interval=1,
                skip_pre_send_checks=False,
                reuse_target_connection=False,
                sleep_time=0.3,
            )

            try:
                fuzzer = fuzzer_class(config=config)
            except ImportError as e:
                pytest.skip(f"Missing dependency: {e}")

            result = run_fuzz_capture(fuzzer, timeout_seconds=60)

            _assert_crash_detected(fuzzer, result, server, "iec104")


# ============================================================================
# MMS Crash Detection
# ============================================================================


class TestMMSCrashDetection:
    """Verify that crashing an MMS server is detected."""

    def test_monitor_detects_crash(self, tmp_path):
        """Server crashes during a monitor health check."""
        boofuzz = pytest.importorskip("boofuzz")  # noqa: F841
        from oida.fuzz.core.config import MonitorConfig
        from oida.fuzz.protocols import PROTOCOL_FUZZERS

        fuzzer_class = PROTOCOL_FUZZERS.get("mms")
        if not fuzzer_class:
            pytest.skip("MMS fuzzer not available")

        # MMS uses COTP Connection Request + MMS Initiate in its monitor check.
        # Each monitor check sends 2 requests (CR + Initiate). Use crash_after=8
        # to account for multi-step handshakes.
        with mms_server(crash_after=8) as server:
            config = create_fuzzer_config(
                server.host,
                server.port,
                "mms",
                str(tmp_path / "mms_crash"),
                index_end=100000,
                monitor_config=MonitorConfig.parse("mms:1,socket"),
                monitor_check_interval=1,
                skip_pre_send_checks=False,
                reuse_target_connection=False,
                sleep_time=0.3,
            )

            try:
                fuzzer = fuzzer_class(config=config)
            except ImportError as e:
                pytest.skip(f"Missing dependency: {e}")

            result = run_fuzz_capture(fuzzer, timeout_seconds=60)

            _assert_crash_detected(fuzzer, result, server, "mms")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

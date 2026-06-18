"""Fuzzing monitors for service health checking.

This package provides monitors that check service responsiveness during fuzzing
to detect crashes, hangs, and behavioral changes.

All imports are lazy to avoid pulling in boofuzz at CLI startup time.
The actual monitor classes and CombinedMonitor are loaded on first access.
"""

from typing import List


def _load_combined_monitor():
    """Load the CombinedMonitor class (requires boofuzz)."""
    # Import everything that CombinedMonitor needs
    from boofuzz.exception import BoofuzzFailure
    from boofuzz.monitors import BaseMonitor
    from .base import CrashTracker
    from .network import PingMonitor, SocketHealthMonitor

    class CombinedMonitor(BaseMonitor):
        """Combined monitor that runs multiple monitors in sequence.

        Supports AND/OR logic for combining monitor results:
        - AND (default): ALL monitors must pass for the check to succeed
        - OR: ANY monitor must pass for the check to succeed

        Graceful degradation:
        - When graceful_degradation=True, failed monitors are disabled instead of
          stopping the entire fuzzing session. Fuzzing continues with remaining monitors.
        - When graceful_degradation=False (default), a monitor failure stops fuzzing.
        """

        def __init__(
            self,
            host,
            port=None,
            monitors: List[BaseMonitor] = None,
            skip_pre_send: bool = True,
            check_interval: int = 3,
            logic: str = "and",
            session_filename: str = None,
            graceful_degradation: bool = False,
        ):
            self.host = host
            self.port = port
            self.skip_pre_send = skip_pre_send
            self.check_interval = max(1, check_interval)
            self.logic = logic.lower()  # "and" or "or"
            self.session_filename = session_filename
            self.graceful_degradation = graceful_degradation
            self.test_case_count = 0
            self.actual_check_count = 0
            self.consecutive_failures = 0
            self.total_failures = 0
            self._disabled_monitors: set = set()

            self.crash_tracker = CrashTracker(target=f"{host}:{port}" if port else host)

            if monitors is None:
                monitors = [PingMonitor(host)]
                if port is not None:
                    monitors.append(SocketHealthMonitor(host, port))

            self.set_monitors(monitors)

        def __repr__(self):
            monitor_types = []
            if hasattr(self, "monitors") and self.monitors:
                for monitor in self.monitors:
                    status = " (disabled)" if monitor in self._disabled_monitors else ""
                    monitor_types.append(f"{monitor.__class__.__name__}{status}")

            port_info = f":{self.port}" if self.port else ""
            skip_info = "pre-send disabled" if self.skip_pre_send else "pre-send enabled"
            logic_info = f"logic={self.logic.upper()}"
            degradation_info = "graceful" if self.graceful_degradation else "strict"

            return (
                f"CombinedMonitor(target={self.host}{port_info}, "
                f"monitors=[{', '.join(monitor_types)}], "
                f"check_interval={self.check_interval}, "
                f"{logic_info}, {skip_info}, mode={degradation_info}, "
                f"test_cases={self.test_case_count})"
            )

        def __str__(self):
            monitor_count = len(self.monitors) if hasattr(self, "monitors") and self.monitors else 0
            port_info = f" port {self.port}" if self.port else ""
            return (
                f"CombinedMonitor monitoring {self.host}{port_info} with {monitor_count} monitors"
            )

        @property
        def crash_count(self) -> int:
            return self.crash_tracker.crash_count

        @property
        def is_crashed(self) -> bool:
            return self.crash_tracker.is_crashed

        def get_crash_summary(self) -> dict:
            summary = self.crash_tracker.get_crash_summary()
            summary["disabled_monitors"] = len(self._disabled_monitors)
            summary["active_monitors"] = len(self.get_active_monitors())
            summary["total_failures"] = self.total_failures
            return summary

        def set_monitors(self, monitors: List[BaseMonitor]):
            if monitors is not None:
                self.monitors = monitors
                self.monitor_count = len(self.monitors)
                self._disabled_monitors = set()
                for monitor in self.monitors:
                    if self.session_filename and hasattr(monitor, "session_filename"):
                        monitor.session_filename = self.session_filename
                    if hasattr(monitor, "crash_tracker"):
                        monitor.crash_tracker = self.crash_tracker

        def mark_monitor_failed(self, monitor: BaseMonitor, reason: str = ""):
            if monitor in self._disabled_monitors:
                return

            self._disabled_monitors.add(monitor)
            monitor_name = type(monitor).__name__
            active_count = len(self.monitors) - len(self._disabled_monitors)

            from ...utils.ics_logger import get_logger

            log = get_logger("MONITOR", self.host, self.port or 0)

            if reason:
                log.warning(f"Monitor {monitor_name} disabled: {reason}")
            else:
                log.warning(f"Monitor {monitor_name} disabled due to persistent failure")

            if active_count > 0:
                log.display(f"Continuing with {active_count} active monitor(s)")
            else:
                log.fail("All monitors disabled - no health checking active")

        def get_active_monitors(self) -> List[BaseMonitor]:
            return [m for m in self.monitors if m not in self._disabled_monitors]

        def _any_child_needs_check(self) -> bool:
            if not self.monitors:
                return False
            for monitor in self.monitors:
                if monitor in self._disabled_monitors:
                    continue
                if monitor.crashed or monitor.consecutive_failures > 0:
                    return True
            return False

        def pre_send(self, target=None, fuzz_data_logger=None, session=None):
            if self.skip_pre_send:
                return True
            if self._any_child_needs_check():
                return self._check_monitors(target, fuzz_data_logger, session, "pre-send")
            if self.test_case_count % self.check_interval != 0:
                return True
            return self._check_monitors(target, fuzz_data_logger, session, "pre-send")

        def post_send(self, target=None, fuzz_data_logger=None, session=None):
            self.test_case_count += 1
            if self._any_child_needs_check():
                return self._check_monitors(target, fuzz_data_logger, session, "post-send")
            if self.test_case_count % self.check_interval != 0:
                return True
            return self._check_monitors(target, fuzz_data_logger, session, "post-send")

        def _check_monitors(self, target, fuzz_data_logger, session, check_type):
            active_monitors = self.get_active_monitors()

            if not active_monitors:
                return True

            self.actual_check_count += 1
            results = []

            test_case_name = None
            test_case_id = self.test_case_count
            if session:
                test_case_id = session.total_mutant_index
                if session.fuzz_node:
                    test_case_name = session.fuzz_node.name

            active_count = len(active_monitors)
            for i, monitor in enumerate(active_monitors):
                try:
                    monitor.test_case_count = test_case_id
                    monitor.test_case_name = test_case_name
                    result = monitor._check_alive(fuzz_data_logger)
                    if result is None:
                        result = False
                    results.append(result)
                    if not result and fuzz_data_logger:
                        fuzz_data_logger.log_info(
                            f"Monitor {i + 1}/{active_count} ({type(monitor).__name__}) "
                            f"failed {check_type} check"
                        )
                except BoofuzzFailure as e:
                    if self.graceful_degradation:
                        self.mark_monitor_failed(monitor, str(e))
                        results.append(False)
                        if fuzz_data_logger:
                            fuzz_data_logger.log_info(
                                f"Monitor {i + 1}/{active_count} ({type(monitor).__name__}) "
                                f"disabled due to max recovery attempts"
                            )
                    else:
                        raise
                except Exception as e:
                    results.append(False)
                    if fuzz_data_logger:
                        fuzz_data_logger.log_info(
                            f"Monitor {i + 1}/{active_count} ({type(monitor).__name__}) "
                            f"failed with exception: {str(e)}"
                        )

            if not results:
                return True

            if self.logic == "or":
                passed = any(results)
            else:
                passed = all(results)

            failures = results.count(False)
            if not passed:
                self.consecutive_failures += 1
                self.total_failures += 1
                if fuzz_data_logger:
                    logic_str = self.logic.upper()
                    disabled_info = (
                        f", {len(self._disabled_monitors)} disabled"
                        if self._disabled_monitors
                        else ""
                    )
                    fuzz_data_logger.log_fail(
                        f"{failures}/{active_count} monitors failed {check_type} check "
                        f"(logic={logic_str}, consecutive_failures={self.consecutive_failures}{disabled_info})"
                    )
            else:
                self.consecutive_failures = 0

            return passed

    return CombinedMonitor


# Cache for loaded classes
_cache = {}


def __getattr__(name):
    """Lazy imports for all monitor classes (requires boofuzz)."""
    if name in _cache:
        return _cache[name]

    _base_attrs = {"CrashEvent", "CrashTracker", "ProtocolBaseline", "ProtocolMonitor"}
    _network_attrs = {"PingMonitor", "SocketHealthMonitor", "CustomSSLSocketMonitor"}
    _industrial_attrs = {
        "IEC104States",
        "ModbusMonitor",
        "ModbusRTUMonitor",
        "IEC104Monitor",
        "MMSMonitor",
        "MQTTMonitor",
        "OPCUAMonitor",
    }
    _application_attrs = {
        "HTTPGetMonitor",
        "FTPCommandMonitor",
        "SMTPCommandMonitor",
        "DNSQueryMonitor",
    }
    _infrastructure_attrs = {"DHCPDiscoverMonitor", "TFTPReadMonitor"}
    _medical_attrs = {"HL7Monitor"}
    _http2_attrs = {"HTTP2Monitor"}
    _registry_attrs = {
        "MonitorInfo",
        "MONITOR_REGISTRY",
        "register_monitor",
        "get_monitor",
        "get_available_monitors",
        "create_monitor",
    }
    _boofuzz_attrs = {"BaseMonitor", "BoofuzzFailure"}

    if name in _base_attrs:
        from .base import CrashEvent, CrashTracker, ProtocolBaseline, ProtocolMonitor

        _cache.update(
            {
                "CrashEvent": CrashEvent,
                "CrashTracker": CrashTracker,
                "ProtocolBaseline": ProtocolBaseline,
                "ProtocolMonitor": ProtocolMonitor,
            }
        )
        return _cache[name]

    if name in _network_attrs:
        from .network import PingMonitor, SocketHealthMonitor, CustomSSLSocketMonitor

        _cache.update(
            {
                "PingMonitor": PingMonitor,
                "SocketHealthMonitor": SocketHealthMonitor,
                "CustomSSLSocketMonitor": CustomSSLSocketMonitor,
            }
        )
        return _cache[name]

    if name in _industrial_attrs:
        from .industrial import (
            IEC104States,
            ModbusMonitor,
            ModbusRTUMonitor,
            IEC104Monitor,
            MMSMonitor,
            MQTTMonitor,
            OPCUAMonitor,
        )

        _cache.update(
            {
                "IEC104States": IEC104States,
                "ModbusMonitor": ModbusMonitor,
                "ModbusRTUMonitor": ModbusRTUMonitor,
                "IEC104Monitor": IEC104Monitor,
                "MMSMonitor": MMSMonitor,
                "MQTTMonitor": MQTTMonitor,
                "OPCUAMonitor": OPCUAMonitor,
            }
        )
        return _cache[name]

    if name in _application_attrs:
        from .application import (
            HTTPGetMonitor,
            FTPCommandMonitor,
            SMTPCommandMonitor,
            DNSQueryMonitor,
        )

        _cache.update(
            {
                "HTTPGetMonitor": HTTPGetMonitor,
                "FTPCommandMonitor": FTPCommandMonitor,
                "SMTPCommandMonitor": SMTPCommandMonitor,
                "DNSQueryMonitor": DNSQueryMonitor,
            }
        )
        return _cache[name]

    if name in _infrastructure_attrs:
        from .infrastructure import DHCPDiscoverMonitor, TFTPReadMonitor

        _cache.update(
            {"DHCPDiscoverMonitor": DHCPDiscoverMonitor, "TFTPReadMonitor": TFTPReadMonitor}
        )
        return _cache[name]

    if name in _medical_attrs:
        from .medical import HL7Monitor

        _cache.update({"HL7Monitor": HL7Monitor})
        return _cache[name]

    if name in _http2_attrs:
        from .http2 import HTTP2Monitor

        _cache["HTTP2Monitor"] = HTTP2Monitor
        return HTTP2Monitor

    if name in _registry_attrs:
        from .registry import (
            MonitorInfo,
            MONITOR_REGISTRY,
            register_monitor,
            get_monitor,
            get_available_monitors,
            create_monitor,
        )

        _cache.update(
            {
                "MonitorInfo": MonitorInfo,
                "MONITOR_REGISTRY": MONITOR_REGISTRY,
                "register_monitor": register_monitor,
                "get_monitor": get_monitor,
                "get_available_monitors": get_available_monitors,
                "create_monitor": create_monitor,
            }
        )
        return _cache[name]

    if name == "BaseMonitor":
        from boofuzz.monitors import BaseMonitor

        _cache["BaseMonitor"] = BaseMonitor
        return BaseMonitor

    if name == "BoofuzzFailure":
        from boofuzz.exception import BoofuzzFailure

        _cache["BoofuzzFailure"] = BoofuzzFailure
        return BoofuzzFailure

    if name == "CombinedMonitor":
        cls = _load_combined_monitor()
        _cache["CombinedMonitor"] = cls
        return cls

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    # Base
    "BaseMonitor",
    "CrashEvent",
    "CrashTracker",
    "ProtocolBaseline",
    "ProtocolMonitor",
    "IEC104States",
    # Network monitors
    "PingMonitor",
    "SocketHealthMonitor",
    "CustomSSLSocketMonitor",
    # Industrial monitors
    "ModbusMonitor",
    "ModbusRTUMonitor",
    "IEC104Monitor",
    "MMSMonitor",
    "MQTTMonitor",
    "OPCUAMonitor",
    # Application monitors
    "HTTPGetMonitor",
    "FTPCommandMonitor",
    "SMTPCommandMonitor",
    "DNSQueryMonitor",
    # Infrastructure monitors
    "DHCPDiscoverMonitor",
    "TFTPReadMonitor",
    # Medical monitors
    "HL7Monitor",
    # HTTP/2 monitor
    "HTTP2Monitor",
    # Combined
    "CombinedMonitor",
    # Registry
    "MonitorInfo",
    "MONITOR_REGISTRY",
    "register_monitor",
    "get_monitor",
    "get_available_monitors",
    "create_monitor",
]

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DNP3 Scanner (yadnp3 / opendnp3)

Production-quality DNP3 master implementation for security assessment.
Uses the yadnp3 Python bindings (opendnp3 C++ library).

Supports:
- Device discovery and fingerprinting
- Integrity polls (Class 0/1/2/3)
- Class-specific reads
- Specific group/variation reads
- Device attribute reads (Group 0)
- Select-Before-Operate and Direct Operate control (Binary and Analog outputs)
- Analog output control (Group 41 - int16/int32/float/double)
- File transfer operations (Group 70 - directory, read, info, write)
- Point enumeration from device attributes
- Unsolicited response enable/disable
- Dead band configuration (Group 34)
- Time synchronization (LAN/non-LAN)
- Cold/warm restart commands
- TLS channel support
- Serial and UDP transport
- Secure Authentication v5 (SA5)
- Channel retry tuning
- Security statistics (Group 121)
- Proper result reporting via ScanResults/DeviceInfo
"""

import time
import threading
from functools import cached_property
from typing import Dict, Any, List, Optional
from datetime import datetime

from ...utils import (
    register_protocol,
    NetworkScanner,
    ProgressTracker,
)
from ...utils.lazy_import import lazy_import
from ...utils.exceptions import ICSConnectionError

from .constants import KNOWN_ATTRIBUTES, DNP3_GROUP_NAMES, protocol_options
from .mixins import PollingMixin, ControlMixin, FileTransferMixin

__all__ = ["DNP3Scanner", "KNOWN_ATTRIBUTES", "DNP3_GROUP_NAMES", "protocol_options", "_yadnp3"]

# Lazy import for yadnp3 (opendnp3)
_yadnp3 = lazy_import("opendnp3", "DNP3")


# ------------------------------------------------------------------
# Type map for ISOEHandler.Process() dispatch (built lazily)
# ------------------------------------------------------------------

_cache: dict = {}


def _get_type_map():
    """Lazily build and return the opendnp3 type -> handler-key mapping dict."""
    if "type_map" in _cache:
        return _cache["type_map"]
    import opendnp3 as dnp3

    _cache["type_map"] = {
        dnp3.Binary: "binary_inputs",
        dnp3.DoubleBitBinary: "double_bit_binary_inputs",
        dnp3.BinaryOutputStatus: "binary_output_statuses",
        dnp3.Counter: "counters",
        dnp3.FrozenCounter: "frozen_counters",
        dnp3.Analog: "analog_inputs",
        dnp3.AnalogOutputStatus: "analog_output_statuses",
        dnp3.OctetString: "octet_strings",
        dnp3.SecurityStat: "security_stats",
    }
    return _cache["type_map"]


# ------------------------------------------------------------------
# Helper classes for opendnp3 callback API
# ------------------------------------------------------------------


class _ScanHandler:
    """Factory for creating an ISOEHandler subclass that collects data points."""

    @staticmethod
    def create():
        """Create and return an ISOEHandler instance that collects points."""
        import opendnp3 as dnp3

        class ScanHandler(dnp3.ISOEHandler):
            def __init__(self):
                super().__init__()
                self.binary_inputs = []
                self.double_bit_binary_inputs = []
                self.binary_output_statuses = []
                self.counters = []
                self.frozen_counters = []
                self.analog_inputs = []
                self.analog_output_statuses = []
                self.octet_strings = []
                self.security_stats = []
                self.string_attrs = []
                self.iin = None
                self._lock = threading.Lock()

            def BeginFragment(self, _response_info):
                pass

            def EndFragment(self, _response_info):
                pass

            def Process(self, info, values):
                type_map = _get_type_map()
                with self._lock:
                    for indexed_val in values:
                        val_obj = indexed_val.value
                        val_type = type(val_obj)
                        key = type_map.get(val_type)
                        if key is None:
                            continue
                        target = getattr(self, key)
                        target.append(indexed_val)

            def OnDeviceAttribute(self, info, variation, attr_value):
                with self._lock:
                    entry = {
                        "variation": variation,
                        "set": 0,
                        "value": self._extract_value(attr_value),
                    }
                    self.string_attrs.append(entry)

            @staticmethod
            def _extract_value(attr_value):
                """Extract a Python value from a DeviceAttributeValue."""
                import opendnp3 as _dnp3

                t = attr_value.type
                if t == _dnp3.DeviceAttrType.VISIBLE_STRING:
                    return attr_value.stringValue
                elif t == _dnp3.DeviceAttrType.UNSIGNED_INT:
                    return attr_value.unsignedValue
                elif t == _dnp3.DeviceAttrType.SIGNED_INT:
                    return attr_value.signedValue
                elif t == _dnp3.DeviceAttrType.FLOATING_POINT:
                    return attr_value.floatValue
                elif t == _dnp3.DeviceAttrType.OCTET_STRING:
                    raw = attr_value.rawValue
                    return raw.hex() if isinstance(raw, (bytes, bytearray)) else str(raw)
                elif t == _dnp3.DeviceAttrType.DNP3_TIME:
                    return str(attr_value.timeValue)
                else:
                    return str(attr_value.rawValue)

            def clear(self):
                """Reset all collected data."""
                with self._lock:
                    self.binary_inputs.clear()
                    self.double_bit_binary_inputs.clear()
                    self.binary_output_statuses.clear()
                    self.counters.clear()
                    self.frozen_counters.clear()
                    self.analog_inputs.clear()
                    self.analog_output_statuses.clear()
                    self.octet_strings.clear()
                    self.security_stats.clear()
                    self.string_attrs.clear()
                    self.iin = None

        return ScanHandler()


class _MasterApp:
    """Factory for creating an IMasterApplication subclass."""

    @staticmethod
    def create():
        """Create and return an IMasterApplication instance."""
        import opendnp3 as dnp3

        class MasterApp(dnp3.IMasterApplication):
            def __init__(self):
                super().__init__()
                self.iin = None
                self._task_event = threading.Event()
                self._task_result = None
                self._lock = threading.Lock()

            def OnReceiveIIN(self, iin):
                with self._lock:
                    self.iin = iin

            def OnTaskStart(self, _task_type, _task_id):
                pass

            def OnTaskComplete(self, info):
                with self._lock:
                    self._task_result = info
                self._task_event.set()

            def OnOpen(self):
                pass

            def OnClose(self):
                pass

            def AssignClassDuringStartup(self):
                return False

            def wait_for_task(self, timeout):
                """Wait for the next task completion, return TaskInfo or None."""
                self._task_event.clear()
                got = self._task_event.wait(timeout=timeout)
                if got:
                    with self._lock:
                        return self._task_result
                return None

        return MasterApp()


class _ChannelListener:
    """Factory for creating an IChannelListener subclass."""

    @staticmethod
    def create():
        """Create and return an IChannelListener instance."""
        import opendnp3 as dnp3

        class ChannelListener(dnp3.IChannelListener):
            def __init__(self):
                super().__init__()
                self.state = dnp3.ChannelState.CLOSED
                self._open_event = threading.Event()
                self._lock = threading.Lock()

            def OnStateChange(self, state):
                with self._lock:
                    self.state = state
                if state == dnp3.ChannelState.OPEN:
                    self._open_event.set()

            def wait_for_open(self, timeout):
                """Wait for channel to reach OPEN state."""
                with self._lock:
                    if self.state == dnp3.ChannelState.OPEN:
                        return True
                return self._open_event.wait(timeout=timeout)

        return ChannelListener()


class _LogHandler:
    """Factory for creating an ILogHandler subclass."""

    @staticmethod
    def create(logger=None, debug=False):
        """Create and return an ILogHandler instance."""
        import opendnp3 as dnp3

        class LogHandler(dnp3.ILogHandler):
            def __init__(self, _logger, _debug):
                super().__init__()
                self._logger = _logger
                self._debug = _debug

            def log(self, _module, _id, _level, location, message):
                if self._debug and self._logger:
                    self._logger.debug(f"[dnp3-lib] {message}")

        return LogHandler(logger, debug)


@register_protocol(
    name="DNP3 Scanner",
    description="""DNP3 scanner using yadnp3 (opendnp3 C++ library).

Features:
- High-reliability connection via production opendnp3 stack
- Integrity polling (Class 0/1/2/3)
- Specific group/variation reads
- Device attribute enumeration (Group 0)
- Point enumeration (discover available data points)
- Binary output control (SBO and Direct Operate)
- Analog output control (Group 41 - int16/int32/float/double)
- File transfer operations (Group 70 - directory, read, info, write)
- Unsolicited response enable/disable
- Dead band configuration (Group 34)
- Time synchronization (LAN/non-LAN)
- Cold/warm restart commands
- TLS encrypted channel support
- Serial and UDP transport
- Secure Authentication v5 (SA5)
- Channel retry tuning
- Security statistics (Group 121)""",
    default_port=20000,
    authors=["f0rw4rd"],
    references=[
        {"type": "url", "ref": "https://github.com/f0rw4rd/opendnp3"},
        {"type": "url", "ref": "https://www.dnp.org/"},
    ],
    protocol_options=protocol_options,
)
class DNP3Scanner(PollingMixin, ControlMixin, FileTransferMixin, NetworkScanner):
    """DNP3 Scanner using yadnp3 (opendnp3 C++ library)."""

    def __init__(self, args: Dict[str, Any]):
        super().__init__(args)

        # DNP3 addressing
        self.master_address = int(args.get("master-address", 1))
        self.outstation_address = int(args.get("outstation-address", 1024))

        # Operation settings
        self.op_timeout = int(args.get("timeout", 10))
        self._read_class_setting = args.get("read-class", "all")
        self._read_variation_setting = args.get("read-variation", None)
        self.device_attributes = args.get("device-attributes", False)
        self.skip_device_attrs = args.get("skip-device-attrs", False)

        # Binary output control settings
        self.control_mode = args.get("control", None)
        self.sbo_mode = args.get("sbo", None)
        self.control_code = int(args.get("control-code", 3))

        # Analog output control settings (Group 41)
        self.ao_direct = args.get("ao-direct", None)
        self.ao_sbo = args.get("ao-sbo", None)
        self.ao_value = args.get("ao-value", None)
        self.ao_type = args.get("ao-type", "float")

        # File transfer settings (Group 70)
        self.list_dir = args.get("list-dir", None)
        self.read_file = args.get("read-file", None)
        self.file_info = args.get("file-info", None)
        self.save_file = args.get("save-file", None)

        # File write settings
        self.write_file = args.get("write-file", None)
        self.write_data = args.get("write-data", None)
        self.file_auth = args.get("file-auth", None)

        # Point enumeration
        self.enumerate_points = args.get("enumerate-points", False)

        # Unsolicited response control
        self.enable_unsol = args.get("enable-unsol", False)
        self.disable_unsol = args.get("disable-unsol", False)

        # Dead band configuration (Group 34). The opendnp3 binding always emits
        # G34V3 (float) on the wire; deadband_type is recorded as metadata only.
        self.write_deadband = args.get("write-deadband", None)
        self.deadband_type = args.get("deadband-type", "float")

        # Time sync
        self.time_sync = args.get("time-sync", None)

        # Restart
        self.restart_mode = args.get("restart", None)

        # TLS
        self.use_tls = args.get("tls", False)
        self.tls_cert = args.get("tls-cert", None)
        self.tls_key = args.get("tls-key", None)

        # Transport (tcp/serial/udp)
        self.transport = args.get("transport", "tcp")
        self.serial_device = args.get("serial-device", None)
        self.baud = int(args.get("baud", 9600))
        self.data_bits = int(args.get("data-bits", 8))
        self.stop_bits = int(args.get("stop-bits", 1))
        self.parity = args.get("parity", "none")

        # Secure Authentication v5
        self.sa_enabled = args.get("sa", False)
        self.sa_user = int(args.get("sa-user", 1))
        self.sa_key = args.get("sa-key", None)

        # Channel retry tuning
        self.retry_min = args.get("retry-min", None)
        self.retry_max = args.get("retry-max", None)
        self.no_reconnect = args.get("no-reconnect", False)

        # Address scanning
        self.scan_range = args.get("scan-range", None)

        # Diagnostic/stealth: prefer no-ack (NR) variants where the stack
        # supports them. opendnp3 only exposes NR for freeze, so --no-ack
        # implies --freeze-no-ack rather than being a dead flag.
        self.no_ack_mode = args.get("no-ack", False)

        # Freeze operations
        self.freeze_immediate = args.get("freeze-immediate", False)
        self.freeze_clear = args.get("freeze-clear", False)
        self.freeze_at_time = args.get("freeze-at-time", None)
        self.freeze_no_ack = args.get("freeze-no-ack", False) or self.no_ack_mode

        # Application control
        self.stop_app = args.get("stop-app", False)
        self.start_app = args.get("start-app", False)
        self.init_data = args.get("init-data", False)
        self.init_app = args.get("init-app", False)

        # Configuration management
        self.save_config = args.get("save-config", False)
        self.activate_config = args.get("activate-config", False)

        # File delete
        self.delete_file = args.get("delete-file", None)

        # Diagnostic operations
        self.delay_measure = args.get("delay-measure", False)

        # Security statistics
        self.security_stats = args.get("security-stats", False)

        # Assign Class operation
        self.assign_class = args.get("assign-class", None)

        # Record Current Time
        self.record_time = args.get("record-time", False)

        # Octet String operations
        self.read_octet = args.get("read-octet", None)

        # Probe objects
        self.probe_objects = args.get("probe-objects", False)

        # State (opendnp3 objects)
        self._manager = None
        self._channel = None
        self._master = None
        self._scan_handler = None
        self._app = None
        self._chan_listener = None
        self._log_handler = None
        self._connected = False

        # Alias for backward compat with mixins that reference self._handler
        self._handler = None

    @cached_property
    def _dnp3(self):
        """Return the opendnp3 module, imported once and cached."""
        import opendnp3

        return opendnp3

    def get_protocol_name(self) -> str:
        return "DNP3"

    def get_default_port(self) -> int:
        return 20000

    def check_dependencies(self) -> bool:
        return _yadnp3.is_available

    # ------------------------------------------------------------------
    # Synchronous wrappers for opendnp3's callback-based async API
    # ------------------------------------------------------------------

    def _sync_scan(self, scan_fn, timeout=None):
        """Execute a scan function and wait for task completion.

        scan_fn is called with (master, handler, config) and should invoke
        one of the IMaster scan methods. Returns True on SUCCESS.
        """
        if timeout is None:
            timeout = float(self.op_timeout)
        dnp3 = self._dnp3
        config = dnp3.TaskConfig.Default()
        scan_fn(self._master, self._scan_handler, config)
        info = self._app.wait_for_task(timeout + 2.0)
        if info is None:
            return False
        return info.result == dnp3.TaskCompletion.SUCCESS

    def _sync_task(self, task_fn, timeout=None):
        """Execute a task function and wait for completion.

        task_fn is called with (master, config) and should invoke an
        IMaster method that takes a TaskConfig. Returns True on SUCCESS.
        """
        if timeout is None:
            timeout = float(self.op_timeout)
        dnp3 = self._dnp3
        config = dnp3.TaskConfig.Default()
        task_fn(self._master, config)
        info = self._app.wait_for_task(timeout + 2.0)
        if info is None:
            return False
        return info.result == dnp3.TaskCompletion.SUCCESS

    def _sync_callback(self, method_fn, timeout=None):
        """Execute an IMaster method that takes a callback and wait for result.

        method_fn is called with (master, callback, config). The callback
        receives the result object. Returns the result object or None on timeout.
        """
        if timeout is None:
            timeout = float(self.op_timeout)
        dnp3 = self._dnp3
        config = dnp3.TaskConfig.Default()
        result_holder = [None]
        event = threading.Event()

        def callback(result):
            result_holder[0] = result
            event.set()

        method_fn(self._master, callback, config)
        event.wait(timeout=timeout + 2.0)
        return result_holder[0]

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def _check_tls_certificate(self, host: str, port: int) -> None:
        """Probe the TLS endpoint to retrieve and check the server certificate."""
        from ...utils.socket_helpers import check_tls_certificate

        check_tls_certificate(
            host=host,
            port=port,
            logger=self.logger,
            protocol="dnp3",
            timeout=self.op_timeout,
            verbose=self.debug,
            certfile=self.tls_cert,
            keyfile=self.tls_key,
        )

    def _build_log_levels(self):
        """Build log levels object based on debug setting."""
        dnp3 = self._dnp3
        if self.debug:
            return dnp3.LogLevels.everything()
        return dnp3.LogLevels.none()

    def _build_channel_retry(self):
        """Build channel retry configuration from CLI args.

        Returns an opendnp3.ChannelRetry or None if defaults are fine.
        """
        if self.retry_min is None and self.retry_max is None and not self.no_reconnect:
            return None
        dnp3 = self._dnp3
        min_delay = (
            dnp3.TimeDuration.Seconds(int(self.retry_min))
            if self.retry_min
            else dnp3.TimeDuration.Seconds(1)
        )
        max_delay = (
            dnp3.TimeDuration.Seconds(int(self.retry_max))
            if self.retry_max
            else dnp3.TimeDuration.Seconds(30)
        )
        retry = dnp3.ChannelRetry(min_delay, max_delay)
        return retry

    def _build_sa_config(self):
        """Build Secure Authentication v5 configuration."""
        if not self.sa_enabled:
            return None
        sa_config = {"user_id": self.sa_user}
        if self.sa_key:
            sa_config["update_key"] = bytes.fromhex(self.sa_key)
        return sa_config

    def _build_master_stack_config(self):
        """Build MasterStackConfig (or MasterAuthStackConfig for SA)."""
        dnp3 = self._dnp3
        sa_config = self._build_sa_config()

        if sa_config:
            stack_config = dnp3.MasterAuthStackConfig()
        else:
            stack_config = dnp3.MasterStackConfig()

        # Link layer config
        stack_config.link.LocalAddr = self.master_address
        stack_config.link.RemoteAddr = self.outstation_address
        stack_config.link.KeepAliveTimeout = dnp3.TimeDuration.Seconds(60)

        # Master params
        stack_config.master.responseTimeout = dnp3.TimeDuration.Seconds(self.op_timeout)
        stack_config.master.disableUnsolOnStartup = True

        # Time sync mode (set at creation, cannot be changed after)
        ts_mode_str = (self.time_sync or "").lower()
        if ts_mode_str == "lan":
            stack_config.master.timeSyncMode = dnp3.TimeSyncMode.LAN
        elif ts_mode_str in ("non-lan", "nonlan", "serial"):
            stack_config.master.timeSyncMode = dnp3.TimeSyncMode.NonLAN
        else:
            stack_config.master.timeSyncMode = getattr(dnp3.TimeSyncMode, "None")

        return stack_config

    def _connect_tcp(self, levels, retry, host, port):
        """Create a TCP channel."""
        dnp3 = self._dnp3
        endpoint = dnp3.IPEndpoint(host, port)
        self.logger.debug(f"Creating TCP channel to {host}:{port}")
        return self._manager.AddTCPClient(
            "dnp3-master-tcp",
            levels,
            retry,
            [endpoint],
            "0.0.0.0",
            self._chan_listener,
        )

    def _connect_tls(self, levels, retry, host, port):
        """Create a TLS channel."""
        dnp3 = self._dnp3
        self.logger.debug("Creating TLS channel")
        self._check_tls_certificate(host, port)
        tls_config = dnp3.TLSConfig(
            peerCertFilePath=self.tls_cert or "",
            localCertFilePath=self.tls_cert or "",
            privateKeyFilePath=self.tls_key or "",
        )
        endpoint = dnp3.IPEndpoint(host, port)
        return self._manager.AddTLSClient(
            "dnp3-master-tls",
            levels,
            retry,
            [endpoint],
            "0.0.0.0",
            tls_config,
            self._chan_listener,
        )

    def _connect_serial(self, levels, retry):
        """Create a serial channel."""
        dnp3 = self._dnp3
        if not self.serial_device:
            raise ICSConnectionError(
                "--serial-device is required for serial transport",
                protocol="DNP3",
            )
        self.logger.debug(
            f"Creating serial channel: {self.serial_device} "
            f"baud={self.baud} data={self.data_bits} stop={self.stop_bits} parity={self.parity}"
        )
        settings = dnp3.SerialSettings()
        settings.deviceName = self.serial_device
        settings.baud = self.baud
        settings.dataBits = self.data_bits
        # opendnp3's "None" parity member collides with the Python keyword, so
        # it's only reachable via getattr — dnp3.Parity.None_ does not exist and
        # crashed every serial scan regardless of --parity.
        none_parity = getattr(dnp3.Parity, "None")
        parity_map = {"none": none_parity, "even": dnp3.Parity.Even, "odd": dnp3.Parity.Odd}
        settings.parity = parity_map.get(self.parity, none_parity)
        stop_map = {1: dnp3.StopBits.One, 2: dnp3.StopBits.Two}
        settings.stopBits = stop_map.get(self.stop_bits, dnp3.StopBits.One)
        return self._manager.AddSerial(
            "dnp3-master-serial",
            levels,
            retry,
            settings,
            self._chan_listener,
        )

    def _connect_udp(self, levels, retry, host, port):
        """Create a UDP channel."""
        dnp3 = self._dnp3
        self.logger.debug(f"Creating UDP channel to {host}:{port}")
        local_ep = dnp3.IPEndpoint("0.0.0.0", 0)
        remote_ep = dnp3.IPEndpoint(host, port)
        return self._manager.AddUDPChannel(
            "dnp3-master-udp",
            levels,
            retry,
            local_ep,
            remote_ep,
            self._chan_listener,
        )

    def connect(self) -> Any:
        """Establish DNP3 master connection using opendnp3 DNP3Manager."""
        try:
            dnp3 = self._dnp3

            host, port = self.get_target_info()
            self.logger.debug(f"Connecting to DNP3 outstation at {host}:{port}")

            # Create log handler
            self._log_handler = _LogHandler.create(logger=self.logger, debug=self.debug)

            # Create manager
            self._manager = dnp3.DNP3Manager(4, self._log_handler)

            # Create helper objects
            self._scan_handler = _ScanHandler.create()
            self._handler = self._scan_handler  # backward compat alias
            self._app = _MasterApp.create()
            self._chan_listener = _ChannelListener.create()

            # Build configs
            levels = self._build_log_levels()
            retry = self._build_channel_retry()
            if retry is None:
                retry = dnp3.ChannelRetry.Default()

            stack_config = self._build_master_stack_config()

            # Create channel based on transport
            if self.use_tls and self.tls_cert and self.tls_key:
                self._channel = self._connect_tls(levels, retry, host, port)
            elif self.transport == "serial":
                self._channel = self._connect_serial(levels, retry)
            elif self.transport == "udp":
                self._channel = self._connect_udp(levels, retry, host, port)
            else:
                self._channel = self._connect_tcp(levels, retry, host, port)

            # Add master to channel
            self._master = self._channel.AddMaster(
                "master",
                self._scan_handler,
                self._app,
                stack_config,
            )

            # Enable the master
            self._master.Enable()

            # Wait for channel to open
            connected = self._chan_listener.wait_for_open(timeout=self.op_timeout)
            if not connected:
                time.sleep(2.0)
                if not self._chan_listener.wait_for_open(timeout=1.0):
                    raise ICSConnectionError(
                        f"Failed to connect to {host}:{port} within {self.op_timeout}s",
                        protocol="DNP3",
                    )

            self._connected = True
            return self._master

        except ICSConnectionError:
            self._teardown_partial_connection()
            raise
        except Exception as e:
            self._teardown_partial_connection()
            raise ICSConnectionError(str(e), protocol="DNP3")

    def _teardown_partial_connection(self) -> None:
        """Shut down any opendnp3 objects created before connect() failed.

        Without this the DNP3Manager's worker threads (and the channel) leak on
        every failed connect, which accumulates badly under range scanning.
        """
        for name in ("_master", "_channel", "_manager"):
            obj = getattr(self, name, None)
            if obj is not None:
                try:
                    obj.Shutdown()
                except Exception as e:
                    self.logger.debug(f"Error shutting down {name} after connect failure: {e}")
                setattr(self, name, None)
        self._connected = False
        self._scan_handler = None
        self._handler = None
        self._app = None
        self._chan_listener = None
        self._log_handler = None

    def disconnect(self, _connection: Any) -> None:
        """Clean up DNP3 connection resources."""
        # Shut down in reverse order: master -> channel -> manager.
        # Always clear the reference even if Shutdown() raises.
        master, self._master = self._master, None
        channel, self._channel = self._channel, None
        manager, self._manager = self._manager, None

        for name, obj in (("master", master), ("channel", channel), ("manager", manager)):
            if obj is not None:
                try:
                    obj.Shutdown()
                except Exception as e:
                    self.logger.debug(f"Error shutting down {name}: {e}")

        self._connected = False
        self._scan_handler = None
        self._handler = None
        self._app = None
        self._chan_listener = None
        self._log_handler = None

    # ------------------------------------------------------------------
    # Discovery orchestrator
    # ------------------------------------------------------------------

    def discover(self, _connection: Any) -> Dict[str, Any]:
        """Perform DNP3 discovery and data collection."""
        results = {
            "connection": {
                "master_address": self.master_address,
                "outstation_address": self.outstation_address,
                "tls_enabled": self.use_tls,
                "transport": self.transport,
                "timestamp": datetime.now().isoformat(),
            },
            "data_points": {},
            "device_attributes": {},
            "iin": None,
            "operations": {},
        }

        if not self._connected or not self._scan_handler or not self._master:
            self.logger.fail("Not connected - cannot discover")
            return results

        self._perform_integrity_poll(results)
        if self._read_class_setting and self._read_class_setting != "all":
            self._perform_class_read(results, self._read_class_setting)
        if self._read_variation_setting:
            self._perform_variation_read(results, self._read_variation_setting)
        if not self.skip_device_attrs:
            self._read_device_attributes(results)
        if self.control_mode is not None:
            self._perform_control(results, "direct_operate")
        if self.sbo_mode is not None:
            self._perform_control(results, "sbo")
        if self.ao_direct is not None:
            self._perform_analog_control(results, "direct_operate")
        if self.ao_sbo is not None:
            self._perform_analog_control(results, "sbo")
        if self.file_auth:
            self._authenticate_file(results)
        if self.list_dir:
            self._list_directory(results)
        if self.read_file:
            self._read_file(results)
        if self.file_info:
            self._get_file_info(results)
        if self.write_file:
            self._write_file(results)
        if self.enumerate_points:
            self._enumerate_points(results)
        if self.enable_unsol:
            self._control_unsolicited(results, enable=True)
        if self.disable_unsol:
            self._control_unsolicited(results, enable=False)
        if self.write_deadband:
            self._write_dead_bands(results)
        if self.time_sync:
            self._perform_time_sync(results)
        if self.restart_mode:
            self._perform_restart(results)
        if self.freeze_immediate or self.freeze_clear or self.freeze_at_time:
            self._perform_freeze(results)
        if self.stop_app or self.start_app or self.init_data or self.init_app:
            self._control_application(results)
        if self.save_config:
            self._save_configuration(results)
        if self.activate_config:
            self._activate_configuration(results)
        if self.delete_file:
            self._delete_remote_file(results)
        if self.delay_measure:
            self._measure_delay(results)
        if self.security_stats:
            self._read_security_stats(results)
        if self.assign_class:
            self._assign_class(results)
        if self.record_time:
            self._record_current_time(results)
        if self.read_octet is not None:
            self._read_octet_string(results)
        if self.probe_objects:
            self._probe_supported_groups(results)

        return results

    # ------------------------------------------------------------------
    # IIN (Internal Indications) helpers
    # ------------------------------------------------------------------

    _IIN_ERROR_BITS = {
        "FUNC_NOT_SUPPORTED": "function code not supported",
        "OBJECT_UNKNOWN": "object unknown",
        "PARAM_ERROR": "parameter error",
        "EVENT_BUFFER_OVERFLOW": "event buffer overflow",
        "CONFIG_CORRUPT": "configuration corrupt",
        "ALREADY_EXECUTING": "already executing",
    }

    _IIN_WARNING_BITS = {
        "DEVICE_TROUBLE": "device trouble",
        "DEVICE_RESTART": "device restart",
        "NEED_TIME": "needs time sync",
        "LOCAL_CONTROL": "local control active",
    }

    def _iin_error_str(self, include_warnings: bool = True) -> Optional[str]:
        """Read IIN from the app and return human-readable error/warning text."""
        dnp3 = self._dnp3
        iin = getattr(self._app, "iin", None) if self._app else None
        if iin is None:
            return None
        parts = []
        for bit_name, desc in self._IIN_ERROR_BITS.items():
            bit = getattr(dnp3.IINBit, bit_name, None)
            if bit is not None and iin.IsSet(bit):
                parts.append(desc)
        if include_warnings:
            for bit_name, desc in self._IIN_WARNING_BITS.items():
                bit = getattr(dnp3.IINBit, bit_name, None)
                if bit is not None and iin.IsSet(bit):
                    parts.append(desc)
        if not parts:
            return None
        return "IIN: " + ", ".join(parts)

    def _error_detail(self, result=None) -> str:
        """Human-readable description of the last operation error."""
        if result is not None:
            # Check for TaskCompletion enum on result objects
            summary = getattr(result, "summary", None) or getattr(result, "result", None)
            if summary is not None:
                dnp3 = self._dnp3
                if summary == dnp3.TaskCompletion.FAILURE_BAD_RESPONSE:
                    iin_err = self._iin_error_str()
                    return (
                        f"bad response ({iin_err})" if iin_err else "bad response from outstation"
                    )
                elif summary == dnp3.TaskCompletion.FAILURE_RESPONSE_TIMEOUT:
                    return "response timeout"
                elif summary == dnp3.TaskCompletion.FAILURE_NO_COMMS:
                    return "no communications"
                elif summary == dnp3.TaskCompletion.FAILURE_START_TIMEOUT:
                    return "task start timeout"
                elif summary != dnp3.TaskCompletion.SUCCESS:
                    iin_err = self._iin_error_str()
                    return f"{summary} ({iin_err})" if iin_err else str(summary)
        iin_err = self._iin_error_str()
        if iin_err:
            return iin_err
        return "unknown reason"

    @property
    def _last_error(self) -> str:
        """Human-readable description of the last channel operation error."""
        return self._error_detail()

    def _op_result(self, success: bool, result=None) -> str:
        """Return a human-readable result string for a DNP3 operation."""
        if success:
            return "SUCCESS"
        return f"FAILED ({self._error_detail(result)})"

    # ------------------------------------------------------------------
    # Address range scanning
    # ------------------------------------------------------------------

    def scan_address_range(
        self, start: int, end: int, timeout_per_addr: float = 0.5
    ) -> List[Dict[str, Any]]:
        """Scan a range of outstation addresses."""
        dnp3 = self._dnp3

        found = []
        host, port = self.get_target_info()
        total = end - start + 1
        self.logger.display(f"Scanning addresses {start}-{end} on {host}:{port}...")
        progress = ProgressTracker(total, logger=self.logger, show=True)
        interrupted = False
        current_manager = None
        current_channel = None
        current_master = None

        for addr in range(start, end + 1):
            if interrupted:
                break
            progress.update()
            try:
                log_handler = _LogHandler.create(logger=self.logger, debug=self.debug)
                current_manager = dnp3.DNP3Manager(2, log_handler)

                scan_handler = _ScanHandler.create()
                app = _MasterApp.create()
                chan_listener = _ChannelListener.create()

                levels = dnp3.LogLevels.none()
                retry = dnp3.ChannelRetry.Default()
                endpoint = dnp3.IPEndpoint(host, port)

                current_channel = current_manager.AddTCPClient(
                    f"scan-{addr}",
                    levels,
                    retry,
                    [endpoint],
                    "0.0.0.0",
                    chan_listener,
                )

                stack_config = dnp3.MasterStackConfig()
                stack_config.link.LocalAddr = self.master_address
                stack_config.link.RemoteAddr = addr
                stack_config.master.responseTimeout = dnp3.TimeDuration.Milliseconds(
                    int(timeout_per_addr * 1000)
                )
                stack_config.master.timeSyncMode = getattr(dnp3.TimeSyncMode, "None")
                stack_config.master.disableUnsolOnStartup = True

                current_master = current_channel.AddMaster(
                    f"master-{addr}",
                    scan_handler,
                    app,
                    stack_config,
                )
                current_master.Enable()

                connected = chan_listener.wait_for_open(timeout=timeout_per_addr)
                if connected:
                    # Do a Class 0 scan
                    class_field = dnp3.ClassField(True, False, False, False)  # Class 0 only
                    config = dnp3.TaskConfig.Default()
                    current_master.ScanClasses(class_field, scan_handler, config)
                    info = app.wait_for_task(timeout_per_addr + 1.0)

                    if info and info.result == dnp3.TaskCompletion.SUCCESS:
                        bi_count = len(scan_handler.binary_inputs)
                        ai_count = len(scan_handler.analog_inputs)
                        ct_count = len(scan_handler.counters)
                        bo_count = len(scan_handler.binary_output_statuses)
                        ao_count = len(scan_handler.analog_output_statuses)
                        result_info = {
                            "address": addr,
                            "binary_inputs": bi_count,
                            "analog_inputs": ai_count,
                            "counters": ct_count,
                            "binary_outputs": bo_count,
                            "analog_outputs": ao_count,
                        }
                        found.append(result_info)
                        total_points = bi_count + ai_count + ct_count + bo_count + ao_count
                        self.logger.display(
                            f"  Address {addr}: {bi_count} BI, "
                            f"{ai_count} AI, {ct_count} CT, "
                            f"{bo_count} BO, {ao_count} AO "
                            f"({total_points} total)"
                        )

                # Cleanup per-address resources
                try:
                    if current_master:
                        current_master.Shutdown()
                        current_master = None
                except Exception as e:
                    self.logger.debug(f"if current_master:: {e}")
                try:
                    if current_channel:
                        current_channel.Shutdown()
                        current_channel = None
                except Exception as e:
                    self.logger.debug(f"if current_channel:: {e}")
                try:
                    if current_manager:
                        current_manager.Shutdown()
                        current_manager = None
                except Exception as e:
                    self.logger.debug(f"if current_manager:: {e}")

            except KeyboardInterrupt:
                self.logger.warning("Scan interrupted by user")
                interrupted = True
                for obj in (current_master, current_channel, current_manager):
                    if obj:
                        try:
                            obj.Shutdown()
                        except Exception as e:
                            self.logger.debug(f"obj.Shutdown(): {e}")
                break
            except Exception as e:
                self.logger.debug(f"Address {addr}: exception {type(e).__name__}: {e}")
                for obj in (current_master, current_channel, current_manager):
                    if obj:
                        try:
                            obj.Shutdown()
                        except Exception as e:
                            self.logger.debug(f"obj.Shutdown(): {e}")
                current_master = None
                current_channel = None
                current_manager = None
                continue

        self.logger.display(f"Scan complete: {len(found)} outstation(s) found")
        return found

    # ------------------------------------------------------------------
    # Public convenience methods (unique logic only)
    # ------------------------------------------------------------------

    def integrity_poll(self) -> Dict[str, Any]:
        """Perform an integrity poll and return collected data."""
        results = {}
        self._perform_integrity_poll(results)
        return results

    def read_class(self, class_num: int) -> Dict[str, Any]:
        """Read a specific class and return data."""
        results = {}
        self._perform_class_read(results, str(class_num))
        return results

    def read_variation(self, group: int, var: int = 0) -> Dict[str, Any]:
        """Read a specific group/variation."""
        results = {}
        self._perform_variation_read(results, f"{group}.{var}")
        return results

    def read_attributes(self) -> Dict[str, Any]:
        """Read device attributes (Group 0)."""
        results = {}
        self._read_device_attributes(results)
        return results

    def cold_restart(self) -> Optional[int]:
        """Send cold restart, return delay in ms or None."""
        dnp3 = self._dnp3
        result = self._sync_callback(
            lambda master, callback, config: master.Restart(dnp3.RestartType.COLD, callback, config)
        )
        if result is not None:
            summary = getattr(result, "summary", None)
            if summary == dnp3.TaskCompletion.SUCCESS:
                return getattr(result, "restartTime", 0)
        return None

    def warm_restart(self) -> Optional[int]:
        """Send warm restart, return delay in ms or None."""
        dnp3 = self._dnp3
        result = self._sync_callback(
            lambda master, callback, config: master.Restart(dnp3.RestartType.WARM, callback, config)
        )
        if result is not None:
            summary = getattr(result, "summary", None)
            if summary == dnp3.TaskCompletion.SUCCESS:
                return getattr(result, "restartTime", 0)
        return None

    def check_link_status(self) -> bool:
        """Check link status with outstation."""
        event = threading.Event()
        result_holder = [False]

        def callback(result):
            result_holder[0] = True
            event.set()

        self._master.CheckLinkStatus(callback)
        event.wait(timeout=float(self.op_timeout) + 2.0)
        return result_holder[0]

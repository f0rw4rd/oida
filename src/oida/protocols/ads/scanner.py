#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ADS Scanner (Layer 1) -- Traditional scanner using BaseScanner pattern.

Provides the ADSScanner class for standalone library usage with
explicit run_scan() calls.

EtherCAT bridge operations are provided by EtherCATOpsMixin
(see ethercat_ops.py).
"""

import ctypes
import re
import struct
import threading
from datetime import datetime
from typing import Dict, Any

from oida.utils import NetworkScanner, SecurityAnalyzer, ProgressTracker, safe_int_conversion
from oida.utils.exceptions import DependencyError

# ADS protocol constants (shared with passive listener)
from oida.protocols.ads.constants import (
    ADS_IDX_GRP,
    ADS_PORT_MAP,
    ADS_STATE_MAP,
    ADS_TIMEOUT_MS,
    ADS_TLS_TIMEOUT,
    ADS_TRANSPORT,
    ADS_UDP_MAGIC,
    ADS_UDP_SVC_IDENTIFY,
    ADS_UDP_TAG,
    ADS_UDP_TIMEOUT,
)

# Shared helpers
from oida.protocols.ads.helpers import (
    _pyads,
    _get_pyads,
    _validate_ams_netid,
    _get_memory_areas,
    _read_raw,
    _probe_netid,
    _capture_pyads_stderr,
)

# EtherCAT operations mixin
from oida.protocols.ads.ethercat_ops import EtherCATOpsMixin

# Upper bound for the device-reported I/O device count. The value is read
# straight from the target response and drives a ctypes buffer allocation of
# (count + 1) * 2 bytes; a device reporting 0xFFFFFFFF would force a ~8 GB
# allocation (self-DoS). Clamp to a plausible maximum, consistent with the
# MAX_SLAVE_PORTS clamp in ethercat_ops.py.
MAX_IO_DEVICES = 4096

# pyads exposes a single PROCESS-GLOBAL TwinCAT message-router port via the
# module-level open_port() / set_local_address() / close_port() API. The CLI
# scans targets concurrently (ThreadPoolExecutor in cli.py), so without
# serialization one thread's set_local_address()/close_port() races another
# thread's in-flight connect() -- corrupting the global local AMS address or
# tearing the shared router port down mid-handshake (a failed connect closing
# the port out from under a live one). Serialize the whole connect handshake and
# the paired close_port() cleanup on this lock. ADS scans are typically a handful
# of PLCs, so serializing the brief handshake (each bounded by --timeout) is an
# acceptable cost for correct, non-racy connections.
_ADS_GLOBAL_PORT_LOCK = threading.RLock()

protocol_options = {
    "netid-ext": {
        "type": "string",
        "description": "AMS Net ID extension appended to target IP (e.g., '2.1'). Default: 1.1",
        "required": False,
        "default": "1.1",
    },
    "ams-netid": {
        "type": "string",
        "description": "Full AMS Net ID (overrides netid-ext)",
        "required": False,
        "default": "",
    },
    "local-netid": {
        "type": "string",
        "description": "Local AMS Net ID (auto-configured if empty)",
        "required": False,
        "default": "",
    },
    "port-type": {
        "type": "enum",
        "description": "ADS runtime port type",
        "values": list(ADS_PORT_MAP.keys()),
        "required": False,
        "default": "TC3PLC1",
    },
    "max-symbols": {
        "type": "int",
        "description": "Maximum number of symbols to process",
        "required": False,
        "default": 1000,
    },
}


class ADSScanner(EtherCATOpsMixin, NetworkScanner):
    """Beckhoff ADS Scanner implementing the base scanner interface"""

    def __init__(self, args: Dict[str, Any]):
        super().__init__(args)

        # AMS Net ID configuration
        # --ams-netid takes priority (full Net ID), then --netid-ext (appended to IP)
        self.ams_netid = args.get("ams-netid") or args.get("ams_netid", "")
        self.local_netid = args.get("local-netid") or args.get("local_netid", "")

        # Port configuration
        self.port_type = args.get("port-type") or args.get("port_type", "TC3PLC1")
        self.ads_port = args.get("ads-port") or args.get("ads_port")

        # Timeouts
        self.ads_timeout_ms = safe_int_conversion(
            args.get("ads-timeout") or args.get("ads_timeout"), ADS_TIMEOUT_MS
        )

        # Symbol limits
        self.max_symbols = safe_int_conversion(
            args.get("max-symbols") or args.get("max_symbols"), 1000
        )

        # Build AMS Net ID: --ams-netid overrides, else {host}.{netid-ext}, else {host}.1.1
        if not self.ams_netid:
            netid_ext = args.get("netid-ext") or args.get("netid_ext", "")
            self.ams_netid = f"{self.host}.{netid_ext}" if netid_ext else f"{self.host}.1.1"
        # Validate AMS Net ID format (must be exactly 6 dot-separated integers, e.g. 192.168.1.1.1.1)
        _validate_ams_netid(self.ams_netid)
        if not self.local_netid:
            from oida.utils.socket_helpers import get_local_ip

            local_ip, err = get_local_ip(self.host, fallback="127.0.0.1")
            if err is not None:
                # Local IP detection failed (offline, no route, etc.). 127.0.0.1
                # is intentionally non-routable so it can't collide with a real
                # device's AMS Net ID.
                self.logger.warning(
                    "ADS: could not detect local IP for AMS Net ID (%s); pass --local-netid "
                    "to set it explicitly (e.g. --local-netid 10.0.0.1.1.1).",
                    err,
                )
            self.local_netid = f"{local_ip}.1.1"

    def get_protocol_name(self) -> str:
        return "ADS"

    def get_default_port(self) -> int:
        return 48898

    def check_dependencies(self) -> bool:
        """Check if pyads is available"""
        return _pyads.is_available

    def _get_ads_port(self) -> int:
        """Get ADS port number based on port type or explicit setting"""
        if self.ads_port:
            return int(self.ads_port)
        return ADS_PORT_MAP.get(self.port_type, 851)

    def connect(self) -> Any:
        """Establish ADS connection"""
        import concurrent.futures

        # Serialize the whole handshake: set_local_address() writes the shared
        # global local AMS address that Connection.open() then consumes, so a
        # concurrent connect in another thread would overwrite it mid-open (and
        # its close_port() would tear down the shared port). See
        # _ADS_GLOBAL_PORT_LOCK. The handshake is bounded by --timeout, so a
        # single stuck target holds the lock for at most that long.
        with _ADS_GLOBAL_PORT_LOCK:
            try:
                pyads = _get_pyads()

                # Set local AMS Net ID
                pyads.open_port()
                pyads.set_local_address(self.local_netid)

                # Create connection
                ads_port = self._get_ads_port()
                connection = pyads.Connection(self.ams_netid, ads_port)

                # Use timeout for connection.open() as pyads can block indefinitely
                timeout = self.timeout

                def do_connect():
                    connection.open()

                # Manage the executor explicitly rather than via `with`: its __exit__
                # calls shutdown(wait=True), which would block until the (possibly
                # stuck) open() returns, defeating the timeout this guard exists for.
                # shutdown(wait=False) returns promptly; on timeout the worker thread
                # and its stuck open()/connection are left to leak intentionally.
                executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
                future = executor.submit(do_connect)
                try:
                    future.result(timeout=timeout)
                except concurrent.futures.TimeoutError as e:
                    self.logger.debug("do connect failed: %s", e)
                    self.logger.fail(f"Connection timed out after {timeout}s")
                    pyads.close_port()
                    executor.shutdown(wait=False)
                    return None
                executor.shutdown(wait=False)

                self.logger.display(f"Connected to {self.ams_netid} (AMS port {ads_port})")
                return connection

            except DependencyError:
                raise
            except Exception as e:
                self.logger.debug("do connect failed: %s", e)
                self.logger.fail(f"Connection failed: {e}")
                # If open_port() succeeded but a later step (set_local_address /
                # Connection) raised, the global AMS router port would leak; repeated
                # failed connects in a threaded library context exhaust ports.
                try:
                    pyads.close_port()
                except Exception as ce:
                    self.logger.debug("close_port() after failed connect: %s", ce)
                return None

    def disconnect(self, connection: Any) -> None:
        """Close ADS connection"""
        if connection:
            # close_port() acts on the shared global router port, so take the
            # same lock connect() uses to keep the teardown from racing another
            # thread's in-flight handshake.
            try:
                pyads = _get_pyads()
                with _ADS_GLOBAL_PORT_LOCK, _capture_pyads_stderr(self.logger):
                    connection.close()
                    pyads.close_port()
            except Exception as e:
                self.logger.debug(f"Disconnect error: {e}")

    def discover(self, connection: Any) -> Dict[str, Any]:
        """Perform ADS discovery"""
        results = {
            "device_info": {},
            "state": {},
            "symbols": {},
            "routes": {},
            "memory_access": {},
            "security_analysis": {},
        }

        # Always get device info and state
        results["device_info"] = self._get_device_info(connection)
        results["state"] = self._get_state(connection)

        # Symbol discovery based on scan mode
        if self.scan_mode in ["symbols", "all"]:
            results["symbols"] = self._discover_symbols(connection)

        # Route scanning
        if self.scan_mode in ["routes", "all"]:
            results["routes"] = self._scan_routes(connection)

        # Memory access testing
        results["memory_access"] = self._test_memory_access(connection)

        # Security analysis
        results["security_analysis"] = self._analyze_security(results)

        # Report findings
        self._report_findings(results)

        return results

    def _get_device_info(self, connection: Any) -> Dict[str, Any]:
        """Get device information"""
        info = {
            "ams_netid": self.ams_netid,
            "ads_port": self._get_ads_port(),
            "port_type": self.port_type,
            "connected": True,
            "timestamp": datetime.now().isoformat(),
        }

        try:
            dev_name, dev_version = connection.read_device_info()
            info["device_name"] = dev_name
            info["version"] = f"{dev_version.version}.{dev_version.revision}.{dev_version.build}"
            info["major_version"] = dev_version.version
            info["minor_version"] = dev_version.revision
            info["build"] = dev_version.build

            self.logger.display(f"Device: {dev_name} v{info['version']}")

        except Exception as e:
            info["error"] = str(e)
            self.logger.debug(f"Error getting device info: {e}")

        return info

    def _get_state(self, connection: Any) -> Dict[str, Any]:
        """Get PLC state"""
        state_info = {
            "ads_state": None,
            "ads_state_name": None,
            "device_state": None,
        }

        try:
            ads_state, device_state = connection.read_state()
            state_info["ads_state"] = ads_state
            state_info["ads_state_name"] = ADS_STATE_MAP.get(ads_state, f"UNKNOWN({ads_state})")
            state_info["device_state"] = device_state

            self.logger.display(f"State: {state_info['ads_state_name']} (device: {device_state})")

        except Exception as e:
            state_info["error"] = str(e)
            self.logger.debug(f"Error getting state: {e}")

        return state_info

    def _discover_symbols(self, connection: Any) -> Dict[str, Any]:
        """Discover ADS symbols"""
        symbols_result: Dict[str, Any] = {
            "total": 0,
            "processed": 0,
            "readable": 0,
            "writable": 0,
            "symbols": {},
        }

        try:
            self.logger.display("Discovering symbols...")
            symbol_list = connection.get_all_symbols()
            symbols_result["total"] = len(symbol_list)

            # Limit processing
            to_process = min(len(symbol_list), self.max_symbols)
            progress = ProgressTracker(to_process, logger=self.logger)

            for i, symbol in enumerate(symbol_list[:to_process]):
                progress.update(msg=f"Symbol {symbol.name[:30]}...")

                symbol_info = self._process_symbol(connection, symbol)
                symbols_result["symbols"][symbol.name] = symbol_info
                symbols_result["processed"] += 1

                if symbol_info.get("readable"):
                    symbols_result["readable"] += 1
                if symbol_info.get("writable"):
                    symbols_result["writable"] += 1

            self.logger.display(
                f"Symbols: {symbols_result['processed']}/{symbols_result['total']} "
                f"({symbols_result['readable']} readable, {symbols_result['writable']} writable)"
            )

        except Exception as e:
            symbols_result["error"] = str(e)
            self.logger.debug(f"Error discovering symbols: {e}")

        return symbols_result

    def _process_symbol(self, connection: Any, symbol) -> Dict[str, Any]:
        """Process a single symbol"""
        info = {
            "name": symbol.name,
            "type": str(symbol.symbol_type),
            # pyads AdsSymbol has no .size attribute — derive it from the
            # ctypes plc_type. The old symbol.size raised AttributeError on
            # the first symbol and aborted the whole enumeration loop.
            "size": ctypes.sizeof(symbol.plc_type) if symbol.plc_type else None,
            "readable": False,
            "writable": False,
        }

        # Test read
        try:
            value = connection.read_by_name(symbol.name)
            info["readable"] = True
            info["value"] = self._format_value(value)

            # Writability probe -- writes the just-read value straight back, so
            # it is a same-value (non-mutating) round-trip. It only runs when a
            # caller explicitly disables read-only mode, which is the Layer-1
            # opt-in equivalent of the Layer-2 --confirm gate.
            if not self.read_only:
                try:
                    connection.write_by_name(symbol.name, value)
                    info["writable"] = True
                except Exception as e:
                    self.logger.debug("process symbol failed: %s", e)

        except Exception as e:
            self.logger.debug("process symbol failed: %s", e)
            info["read_error"] = str(e)

        return info

    def _format_value(self, value) -> str:
        """Format a symbol value for display"""
        return value.hex() if isinstance(value, bytes) else str(value)

    def _scan_routes(self, connection: Any) -> Dict[str, Any]:
        """Scan AMS routing table via system service.

        Uses index group 0x323 on port 10000 (SystemService) to enumerate
        all configured AMS routes. Falls back to Net ID extension sweep if
        the SystemService is not accessible.
        """
        routes = {
            "local": {"netid": self.local_netid, "type": "Local"},
            "target": {"netid": self.ams_netid, "type": "Remote", "accessible": True},
            "discovered": [],
        }

        self.logger.display("Scanning routes via SystemService (port 10000)...")
        pyads = _get_pyads()
        sysservice_failed = False

        try:
            # Connect to SystemService port for route enumeration
            sys_conn = pyads.Connection(self.ams_netid, 10000)
            sys_conn.open()
            sys_conn.set_timeout(self.ads_timeout_ms)

            try:
                max_routes = 50
                consecutive_errors = 0
                for index in range(max_routes):
                    try:
                        # Read route entry (index group 0x323, varying offset)
                        data = _read_raw(sys_conn, ADS_IDX_GRP["ROUTE_LIST"], index, 0x0800)
                        consecutive_errors = 0  # Reset on success
                        if data and len(data) > 44:
                            # Parse route data (44 byte header + route string)
                            route_bytes = data[44:]
                            # First null-terminated string is route name
                            route_str = route_bytes.split(b"\x00")[0].decode(
                                "utf-8", errors="ignore"
                            )
                            if route_str:
                                routes["discovered"].append(
                                    {
                                        "index": index,
                                        "name": route_str,
                                        "raw_length": len(data),
                                    }
                                )
                                self.logger.display(f"  Route {index}: {route_str}")
                    except Exception as e:
                        self.logger.debug("scan routes failed: %s", e)
                        # ADS error code 1814 (0x716) = no more entries
                        err_str = str(e)
                        if "1814" in err_str or "0x716" in err_str.lower():
                            break
                        consecutive_errors += 1
                        if consecutive_errors >= 3:
                            self.logger.debug(
                                "Stopping route scan after %d consecutive errors",
                                consecutive_errors,
                            )
                            sysservice_failed = True
                            break
            finally:
                sys_conn.close()

        except Exception as e:
            self.logger.debug(f"Route enumeration failed: {e}")
            routes["error"] = str(e)
            sysservice_failed = True

        self.logger.display(f"Found {len(routes['discovered'])} routes")

        # Fallback: if SystemService denied access or returned nothing,
        # probe common Net ID extensions to discover active AMS endpoints
        if sysservice_failed or not routes["discovered"]:
            fallback = self._probe_netid_extensions(pyads)
            if fallback:
                routes["discovered_by_probe"] = fallback

        return routes

    def _probe_netid_extensions(self, pyads) -> list:
        """Probe common AMS Net ID extensions to discover active endpoints.

        Uses the central ``_probe_netid()`` function which runs a tiered
        check: read_device_info → CoE SDO probe.  This replaces the old
        M-area read fallback which produced false positives (the AMS
        router answers M-area reads for any port).
        """
        self.logger.display("Route table not accessible, falling back to Net ID probe...")

        # Common TwinCAT Net ID extensions:
        # x.1 = PLC/runtime, x.2 = NC/motion, x.3 = IO
        # 1.x = first adapter, 2.x = second adapter/EtherCAT
        extensions = [
            "1.1",
            "1.2",
            "1.3",
            "1.4",
            "2.1",
            "2.2",
            "2.3",
            "2.4",
            "3.1",
            "3.2",
            "4.1",
        ]

        current_ext = ".".join(self.ams_netid.split(".")[-2:])
        active = []
        probe_port = self._get_ads_port()

        for ext in extensions:
            if ext == current_ext:
                continue

            netid = f"{self.host}.{ext}"
            result = _probe_netid(pyads, netid, probe_port, timeout_ms=self.ads_timeout_ms)

            if result["type"] == "broken":
                self.logger.debug("AMS router connection lost, stopping probe")
                break

            if result["active"]:
                active.append(
                    {
                        "netid": netid,
                        "ext": ext,
                        "status": result["detail"],
                    }
                )
                self.logger.success(f"  {netid} - active: {result['detail']} ({result['type']})")
            else:
                self.logger.debug(f"  {netid} - inactive ({result['detail']})")

        if active:
            self.logger.display(f"Probe found {len(active)} active Net ID(s)")
        else:
            self.logger.display("Probe found no additional active Net IDs")

        return active

    def _get_target_desc(self, connection: Any) -> Dict[str, Any]:
        """Get XML device description via system service.

        Uses index group 0x2BC on port 10000 (SystemService) to retrieve
        an XML description of the PLC configuration.
        """
        result = {
            "success": False,
            "xml": None,
            "parsed": {},
        }

        self.logger.display("Getting target description via SystemService (port 10000)...")
        pyads = _get_pyads()

        try:
            # Connect to SystemService port
            sys_conn = pyads.Connection(self.ams_netid, 10000)
            sys_conn.open()
            sys_conn.set_timeout(self.ads_timeout_ms)

            try:
                # First read to get length (4 bytes)
                length_data = _read_raw(sys_conn, ADS_IDX_GRP["TC_XML"], 0x00000001, 4)
                if length_data:
                    xml_length = struct.unpack("<I", length_data)[0]
                    self.logger.debug(f"XML description length: {xml_length}")

                    if xml_length > 0 and xml_length < 1000000:  # Sanity check
                        # Read full XML
                        xml_data = _read_raw(
                            sys_conn, ADS_IDX_GRP["TC_XML"], 0x00000001, xml_length
                        )
                        if xml_data:
                            xml_str = xml_data.decode("utf-8", errors="ignore").rstrip("\x00")
                            result["success"] = True
                            result["xml"] = xml_str

                            # Try to parse key fields
                            name_match = re.search(r"<Name>([^<]+)</Name>", xml_str)
                            if name_match:
                                result["parsed"]["name"] = name_match.group(1)
                            version_match = re.search(r"<Version>([^<]+)</Version>", xml_str)
                            if version_match:
                                result["parsed"]["version"] = version_match.group(1)

                            self.logger.success(f"Retrieved XML description ({len(xml_str)} bytes)")
            finally:
                sys_conn.close()

        except Exception as e:
            self.logger.debug(f"Target description failed: {e}")
            result["error"] = str(e)

        return result

    def _check_secure_ads(self, quiet: bool = False) -> Dict[str, Any]:
        """Check for Secure ADS (TLS) availability on port 8016.

        Secure ADS wraps standard ADS protocol in TLS 1.2 tunnel.
        Note: This provides transport encryption only, not authentication.
        The underlying ADS protocol remains unauthenticated.
        """
        import socket
        import ssl

        result: Dict[str, Any] = {
            "available": False,
            "port": ADS_TRANSPORT["TLS"],
            "tls_version": None,
            "issues": [],
        }

        if not quiet:
            self.logger.display(f"Checking Secure ADS on port {result['port']}...")

        try:
            # Try TLS connection to port 8016
            from oida.utils.socket_helpers import build_tls_context

            context = build_tls_context({}, logger=self.logger)

            sock = socket.create_connection((self.host, result["port"]), timeout=ADS_TLS_TIMEOUT)
            try:
                tls_sock = context.wrap_socket(sock, server_hostname=self.host)

                result["available"] = True
                result["tls_version"] = tls_sock.version()
                self.logger.success(f"Secure ADS available ({result['tls_version']})")

                # Get certificate for analysis using central display function
                cert_der = tls_sock.getpeercert(binary_form=True)
                if cert_der:
                    from oida.utils.security_findings import display_cert_info

                    info = display_cert_info(
                        logger=self.logger,
                        cert=cert_der,
                        protocol="ads-secure",
                        target=f"{self.host}:{result['port']}",
                        verbose=getattr(self.args, "verbose", 0) > 0,
                    )
                    result["issues"].extend(info.get("issues", []))

                tls_sock.close()
            except ssl.SSLError as e:
                self.logger.debug(f"TLS handshake failed: {e}")
                result["error"] = f"TLS error: {e}"
            finally:
                sock.close()

        except TimeoutError:
            self.logger.debug("Secure ADS port not responding")
            result["error"] = "Connection timeout"
        except ConnectionRefusedError:
            self.logger.debug("Secure ADS port closed")
            result["error"] = "Connection refused"
        except Exception as e:
            self.logger.debug(f"Secure ADS check failed: {e}")
            result["error"] = str(e)

        return result

    def _query_license_info(self, connection: Any) -> Dict[str, Any]:
        """Query TwinCAT license information via License Service (port 30).

        Uses index groups:
        - 0x01010004: Device info (SystemID, PlatformID, VolumeNo)
        - 0x01010006: License count
        """
        result = {
            "success": False,
            "system_id": None,
            "platform_id": None,
            "volume_no": None,
        }

        self.logger.display("Querying license information (port 30)...")
        pyads = _get_pyads()

        try:
            # Connect to License Service port (30)
            lic_conn = pyads.Connection(self.ams_netid, 30)
            lic_conn.open()
            lic_conn.set_timeout(self.ads_timeout_ms)

            try:
                # Query SystemID (offset 0x1)
                try:
                    data = _read_raw(lic_conn, ADS_IDX_GRP["LIC_DEV_INFO"], 0x1, 16)
                    if data and len(data) >= 16:
                        # GUID format
                        result["system_id"] = data.hex()
                        self.logger.display(
                            f"  SystemID: {data[:4].hex()}-{data[4:6].hex()}-"
                            f"{data[6:8].hex()}-{data[8:10].hex()}-{data[10:16].hex()}"
                        )
                except Exception as e:
                    self.logger.debug(f"SystemID query failed: {e}")

                # Query PlatformID (offset 0x2)
                try:
                    data = _read_raw(lic_conn, ADS_IDX_GRP["LIC_DEV_INFO"], 0x2, 2)
                    if data and len(data) >= 2:
                        result["platform_id"] = struct.unpack("<H", data)[0]
                        self.logger.display(f"  PlatformID: {result['platform_id']}")
                except Exception as e:
                    self.logger.debug(f"PlatformID query failed: {e}")

                # Query VolumeNo (offset 0x5)
                try:
                    data = _read_raw(lic_conn, ADS_IDX_GRP["LIC_DEV_INFO"], 0x5, 4)
                    if data and len(data) >= 4:
                        result["volume_no"] = struct.unpack("<I", data)[0]
                        self.logger.display(f"  VolumeNo: {result['volume_no']}")
                except Exception as e:
                    self.logger.debug(f"VolumeNo query failed: {e}")

                # Query license count and info
                try:
                    count_data = _read_raw(lic_conn, ADS_IDX_GRP["LIC_ONLINE"], 0x0, 4)
                    if count_data and len(count_data) >= 4:
                        license_count = struct.unpack("<I", count_data)[0]
                        self.logger.display(f"  Licenses: {license_count}")
                        result["license_count"] = license_count
                        result["success"] = True
                except Exception as e:
                    self.logger.debug(f"License count query failed: {e}")

            finally:
                lic_conn.close()

        except Exception as e:
            self.logger.debug(f"License service connection failed: {e}")
            result["error"] = str(e)

        return result

    def _enumerate_io_devices(self, connection: Any) -> Dict[str, Any]:
        """Enumerate I/O devices via IO port (port 300).

        Uses index group 0x5000 (IO_DEV_STATE) with offsets:
        - 0x1: Device IDs
        - 0x2: Device count
        - 0x5: Device NetID
        - 0x7: Device type
        """
        result = {
            "success": False,
            "device_count": 0,
            "devices": [],
        }

        self.logger.display("Enumerating I/O devices (port 300)...")
        pyads = _get_pyads()

        try:
            # I/O device enumeration (ig=0x5000) is only available on the PLC
            # runtime NetID (.1.1).  When targeting another subsystem (e.g. .2.1
            # EtherCAT), transparently redirect to the .1.1 NetID.
            io_netid = self.ams_netid
            current_ext = ".".join(self.ams_netid.split(".")[-2:])
            if current_ext != "1.1":
                base = ".".join(self.ams_netid.split(".")[:-2])
                io_netid = f"{base}.1.1"
                self.logger.debug(f"I/O enumeration redirected from {self.ams_netid} to {io_netid}")

            # Connect to I/O port (300)
            io_conn = pyads.Connection(io_netid, 300)
            io_conn.open()
            io_conn.set_timeout(self.ads_timeout_ms)

            try:
                # Get device count
                count_data = _read_raw(io_conn, ADS_IDX_GRP["IO_DEV_STATE"], 0x2, 4)
                if count_data and len(count_data) >= 4:
                    device_count = struct.unpack("<I", count_data)[0]
                    result["device_count"] = device_count
                    self.logger.display(f"  Found {device_count} I/O devices")

                    # Clamp the attacker-controlled count before it drives the
                    # (device_count + 1) * 2 ctypes allocation below.
                    if device_count > MAX_IO_DEVICES:
                        self.logger.warning(
                            f"  Device reported {device_count} I/O devices — clamping "
                            f"enumeration to {MAX_IO_DEVICES} (implausible count, possible spoofing)"
                        )
                        device_count = MAX_IO_DEVICES

                    if device_count > 0:
                        # Get device IDs
                        id_data = _read_raw(
                            io_conn, ADS_IDX_GRP["IO_DEV_STATE"], 0x1, (device_count + 1) * 2
                        )
                        if id_data:
                            # First 2 bytes are count, then device IDs
                            for i in range(device_count):
                                offset = 2 + (i * 2)
                                if offset + 2 <= len(id_data):
                                    dev_id = struct.unpack("<H", id_data[offset : offset + 2])[0]

                                    # Query device details
                                    dev_info = {"id": dev_id}
                                    try:
                                        # Read device type
                                        type_data = _read_raw(
                                            io_conn, ADS_IDX_GRP["IO_DEV_STATE"] + dev_id, 0x7, 2
                                        )
                                        if type_data:
                                            dev_info["type"] = struct.unpack("<H", type_data)[0]

                                        # Read device name
                                        name_data = _read_raw(
                                            io_conn, ADS_IDX_GRP["IO_DEV_STATE"] + dev_id, 0x1, 255
                                        )
                                        if name_data:
                                            dev_info["name"] = name_data.rstrip(b"\x00").decode(
                                                "utf-8", errors="ignore"
                                            )

                                    except Exception as e:
                                        self.logger.debug(f"Error reading device {dev_id}: {e}")

                                    result["devices"].append(dev_info)
                                    self.logger.display(
                                        f"    Device {dev_id}: {dev_info.get('name', 'Unknown')}"
                                    )

                        result["success"] = True

            finally:
                io_conn.close()

        except Exception as e:
            self.logger.debug(f"I/O device enumeration failed: {e}")
            result["error"] = str(e)

        return result

    def _udp_discovery(
        self, target: str = None, timeout: float = ADS_UDP_TIMEOUT, quiet: bool = False
    ) -> Dict[str, Any]:
        """Perform UDP discovery to find ADS devices.

        Uses UDP port 48899 with Beckhoff discovery protocol:
        - Magic: 0x71146603
        - Service 1: Identify (query device info)
        - Service 6: Add route
        """
        import socket

        result = {
            "success": False,
            "devices": [],
        }

        target_ip = target or self.host
        if not quiet:
            self.logger.display(f"UDP discovery on {target_ip}:{ADS_TRANSPORT['UDP']}...")

        # TODO: Raw UDP broadcast for ADS discovery — pyads has no broadcast
        # API, so this is intentional. Extract into a shared helper if more
        # protocols need UDP broadcast probes (see also EtherNet/IP, KNX).
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.settimeout(timeout)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

                # Build discovery request (Identify service)
                # Format: magic(4) + invoke_id(4) + operation(4) + reserved(16) = 28 bytes
                invoke_id = 0x00000001
                operation = ADS_UDP_SVC_IDENTIFY  # 1 = Identify
                request = struct.pack("<III", ADS_UDP_MAGIC, invoke_id, operation) + b"\x00" * 16

                # Send to specific target or broadcast
                dest = (target_ip, ADS_TRANSPORT["UDP"])
                sock.sendto(request, dest)

                # Collect responses (cap at 256 to prevent runaway loops)
                max_responses = 256
                while len(result["devices"]) < max_responses:
                    try:
                        data, addr = sock.recvfrom(1024)
                        if len(data) >= 12:
                            magic = struct.unpack("<I", data[:4])[0]
                            if magic == ADS_UDP_MAGIC:
                                device = {
                                    "ip": addr[0],
                                }

                                # Parse TLV data after header
                                self._parse_udp_response(data[12:], device)
                                result["devices"].append(device)
                                if not quiet:
                                    self.logger.success(
                                        f"  Found: {addr[0]} - {device.get('hostname', 'Unknown')}"
                                    )

                    except TimeoutError as e:
                        self.logger.debug("udp discovery failed: %s", e)
                        break
            finally:
                sock.close()
            result["success"] = len(result["devices"]) > 0

        except Exception as e:
            self.logger.debug(f"UDP discovery failed: {e}")
            result["error"] = str(e)

        if not quiet:
            self.logger.display(f"  Discovered {len(result['devices'])} device(s)")
        return result

    def _parse_udp_response(self, data: bytes, device: Dict[str, Any]) -> None:
        """Parse a UDP identify response body (everything after the 12-byte header).

        Real layout (cross-checked against pyads ``adsGetNetIdForPLC`` and
        ICSSecurityScripts BeckhoffScan.py), offsets relative to *data*:
        -   0.. 6: device AMS NetID (6 bytes)
        -   6.. 8: device AMS port (LE, typically 0x2710 = 10000)
        -   8..14: static block
        -  14..16: hostname length (LE, NUL included)
        -  16..16+len: hostname + NUL
        -  20+len: Windows kernel version (3 LE DWORDs), then TwinCAT version
        -  later: <HH> TLV blocks (tag/len LE) — fingerprint etc.

        The old implementation walked TLV tags from offset 0, misreading the
        NetID + port as tag=0xA840/len=0x6401 and losing every field.
        """
        try:
            # Fixed header: NetID at bytes 0..6 (pyads reads datagram[12:18],
            # i.e. slice[0:6]) and AMS port at slice[6:8].
            if len(data) >= 6:
                device["netid"] = ".".join(str(b) for b in data[:6])

            name_len = 0
            if len(data) >= 16:
                (name_len,) = struct.unpack_from("<H", data, 14)
                hostname = data[16 : 16 + name_len].rstrip(b"\x00").decode("utf-8", errors="ignore")
                if hostname:
                    device["hostname"] = hostname

            # Fixed region after the hostname: reserved 4 bytes, Windows kernel
            # version (3 LE DWORDs = the OS version), then TwinCAT version.
            base = 16 + name_len + 4
            if len(data) >= base + 12 and "os_version" not in device:
                a, b, c = struct.unpack_from("<III", data, base)
                if a and b < 100 and c < 100000:
                    device["os_version"] = f"{a}.{b}.{c}"
            tlv_start = base + 12
            if len(data) >= tlv_start + 4 and "tc_version" not in device:
                tc = data[tlv_start : tlv_start + 4]
                device["tc_version"] = f"{tc[0]}.{tc[1]}.{struct.unpack('<H', tc[2:4])[0]}"
            tlv_start += 4

            pos = tlv_start
        except Exception as e:
            self.logger.debug("parse udp response failed: %s", e)
            return

        while pos + 4 <= len(data):
            try:
                tag_type, tag_len = struct.unpack("<HH", data[pos : pos + 4])
                pos += 4

                if tag_len == 0 or pos + tag_len > len(data):
                    break

                tag_data = data[pos : pos + tag_len]
                pos += tag_len

                if tag_type == ADS_UDP_TAG["HOSTNAME"]:
                    device["hostname"] = tag_data.rstrip(b"\x00").decode("utf-8", errors="ignore")
                elif tag_type == ADS_UDP_TAG["NETID"]:
                    if len(tag_data) >= 6:
                        device["netid"] = ".".join(str(b) for b in tag_data[:6])
                elif tag_type == ADS_UDP_TAG["TC_VERSION"]:
                    if len(tag_data) >= 4:
                        device["tc_version"] = (
                            f"{tag_data[0]}.{tag_data[1]}.{struct.unpack('<H', tag_data[2:4])[0]}"
                        )
                elif tag_type == ADS_UDP_TAG["OS_VERSION"]:
                    device["os_version"] = tag_data.rstrip(b"\x00").decode("utf-8", errors="ignore")
                elif tag_type == ADS_UDP_TAG["FINGERPRINT"]:
                    device["fingerprint"] = tag_data.hex()

            except Exception as e:
                self.logger.debug("parse udp response failed: %s", e)
                break

    def _test_memory_access(self, connection: Any) -> Dict[str, Any]:
        """Test direct memory access"""
        results = {
            "areas_tested": 0,
            "accessible": [],
            "denied": [],
        }

        self.logger.display("Testing memory access...")

        for area in _get_memory_areas():
            results["areas_tested"] += 1
            try:
                data = _read_raw(connection, area["group"], area["offset"], area["size"])
                results["accessible"].append(
                    {
                        "name": area["name"],
                        "group": hex(area["group"]),
                        "offset": area["offset"],
                        "size": area["size"],
                        "data": data.hex() if data else None,
                    }
                )
            except Exception as e:
                self.logger.debug("test memory access failed: %s", e)
                results["denied"].append(
                    {
                        "name": area["name"],
                        "group": hex(area["group"]),
                        "error": str(e),
                    }
                )

        accessible_count = len(results["accessible"])
        self.logger.display(
            f"Memory access: {accessible_count}/{results['areas_tested']} areas accessible"
        )

        return results

    def _detect_twincat_version(self, device_info: Dict[str, Any]) -> int:
        """Detect TwinCAT major version from device info.

        Returns:
            2 for TwinCAT 2.x (clear text)
            3 for TwinCAT 3.x (AES-128 with fixed key)
            0 if unknown
        """
        device_name = device_info.get("device_name", "").lower()
        major_version = device_info.get("major_version", 0)

        # Check device name for TwinCAT version hints
        if "twincat 3" in device_name or "tc3" in device_name:
            return 3
        if "twincat 2" in device_name or "tc2" in device_name:
            return 2

        # Check version number (TwinCAT 3 typically has major version 3.x)
        if major_version >= 3:
            return 3
        if major_version == 2:
            return 2

        # Default to TC3 as it's more common in modern deployments
        return 3

    def _analyze_security(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze ADS security posture.

        Known protocol weaknesses:
        - No authentication mechanism in base protocol
        - TwinCAT 3.x credential encryption uses static key
        - Credential sniffing and replay attacks possible
        """
        symbols = results.get("symbols", {}).get("symbols", {})
        memory = results.get("memory_access", {})
        device_info = results.get("device_info", {})

        readable_count = sum(1 for s in symbols.values() if s.get("readable"))
        writable_count = sum(1 for s in symbols.values() if s.get("writable"))
        accessible_memory = len(memory.get("accessible", []))

        issues = []

        # Detect TwinCAT version for encryption assessment
        tc_version = self._detect_twincat_version(device_info)

        # ADS has no authentication by design
        issues.append("No authentication mechanism (ADS protocol limitation)")
        self.logger.security_finding(
            "No authentication",
            detail="ADS protocol has no authentication mechanism",
        )

        # Encryption assessment based on TwinCAT version
        if tc_version >= 3:
            # TwinCAT 3.x has "encryption" but with static key
            issues.append("Weak encryption: TwinCAT 3.x uses static encryption key")
            self.logger.security_finding(
                "Insecure configuration",
                detail="TwinCAT 3.x credential encryption uses static key - traffic decryptable",
            )
            # Credential sniffing possible
            issues.append("Credentials can be sniffed and decrypted")
            self.logger.security_finding(
                "[CREDENTIALS] Credential exposure",
                detail="Login credentials use static encryption key - sniffing/replay attacks possible",
            )
        else:
            # TwinCAT 2.x - clear text
            issues.append("No encryption support (TwinCAT 2.x clear text protocol)")
            self.logger.security_finding(
                "No encryption",
                detail="TwinCAT 2.x communicates in clear text",
            )

        if readable_count > 0:
            issues.append(f"{readable_count} symbols readable without authentication")
            self.logger.security_finding(
                "Anonymous access allowed",
                detail=f"{readable_count} symbols readable without authentication",
            )
        if writable_count > 0:
            issues.append(f"{writable_count} symbols writable without authentication")
            self.logger.security_finding(
                "Writable access",
                detail=f"{writable_count} symbols writable without authentication",
            )
        if accessible_memory > 0:
            issues.append(f"{accessible_memory} memory areas directly accessible")
            # Directly-readable memory without auth is an access-control exposure.
            # It must NOT reuse ("Insecure configuration", CONFIGURATION): the
            # TwinCAT-static-key finding above already claims that (title, category)
            # key, and security_finding() de-dups on that pair, which silently
            # dropped this distinct memory finding. ACCESS_CONTROL is both the
            # correct class and a unique key.
            self.logger.security_finding(
                "Insecure configuration",
                detail=f"{accessible_memory} memory areas directly accessible",
                category="ACCESS_CONTROL",
            )

        analysis = SecurityAnalyzer.assess_protocol_security(
            {
                "authentication": False,
                "authorization": False,
                "encryption": False,
                "integrity_check": False,
                "access_control": writable_count == 0 and accessible_memory == 0,
            }
        )
        analysis["issues"] = issues

        return analysis

    def _report_findings(self, results: Dict[str, Any]) -> None:
        """Report scan findings"""
        device_info = results.get("device_info", {})
        state = results.get("state", {})
        symbols = results.get("symbols", {})
        security = results.get("security_analysis", {})

        # Report host info
        self.report_host_info(
            self.host,
            server_type="Beckhoff TwinCAT",
            device_name=device_info.get("device_name", "Unknown"),
            version=device_info.get("version", "Unknown"),
        )

        # Report service
        self.report_service_info(
            self.host,
            port=self.port,
            name="ads",
            product="Beckhoff ADS",
            version=device_info.get("version", "Unknown"),
            state=state.get("ads_state_name", "Unknown"),
            symbols=symbols.get("processed", 0),
        )

        # Report vulnerabilities
        for issue in security.get("issues", []):
            severity = (
                "high" if "writable" in issue.lower() or "memory" in issue.lower() else "medium"
            )
            self.report_vulnerability(
                self.host, "ads_security_issue", description=issue, severity=severity
            )

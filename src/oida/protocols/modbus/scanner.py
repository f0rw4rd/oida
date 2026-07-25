#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
from datetime import datetime
from typing import Dict, List, Any

from ...utils import (
    NetworkScanner,
    register_protocol,
    create_protocol_module,
    ProtocolParser,
    ProgressTracker,
    parse_bool,
)
from ...utils.cli import run as cli_run
from ...utils.lazy_import import lazy_import

# Lazy import for pymodbus - only loads when actually used.
# lazy_import() already memoizes the imported module, so no extra caching needed.
_pymodbus = lazy_import("pymodbus", "Modbus")

_pymodbus_version: int | None = None


def _get_pymodbus():
    """Get pymodbus module, raising DependencyError if not available."""
    return _pymodbus()


def _get_pymodbus_version():
    """Get pymodbus major version number (cached)."""
    global _pymodbus_version
    if _pymodbus_version is None:
        _pymodbus_version = int(_get_pymodbus().__version__.split(".")[0])
    return _pymodbus_version


def _get_modbus_tcp_client():
    """Get ModbusTcpClient class lazily."""
    _get_pymodbus()
    from pymodbus.client import ModbusTcpClient

    return ModbusTcpClient


def _get_modbus_serial_client():
    """Get ModbusSerialClient class lazily."""
    _get_pymodbus()
    from pymodbus.client import ModbusSerialClient

    return ModbusSerialClient


def _get_modbus_udp_client():
    """Get ModbusUdpClient class lazily (may not exist in all versions)."""
    _get_pymodbus()
    try:
        from pymodbus.client import ModbusUdpClient

        return ModbusUdpClient
    except (ImportError, AttributeError) as e:
        logger.debug("get modbus udp client failed: %s", e)
        return None


def _get_modbus_tls_client():
    """Get ModbusTlsClient class lazily (may not exist in all versions)."""
    _get_pymodbus()
    try:
        from pymodbus.client import ModbusTlsClient

        return ModbusTlsClient
    except (ImportError, AttributeError) as e:
        logger.debug("get modbus tls client failed: %s", e)
        return None


def _get_framer_type():
    """Get FramerType enum lazily (pymodbus 3.x only)."""
    _get_pymodbus()
    if _get_pymodbus_version() < 3:
        return None
    try:
        from pymodbus.framer import FramerType

        return FramerType
    except (ImportError, AttributeError) as e:
        logger.debug("get framer type failed: %s", e)
        return None


def _get_file_record_classes():
    """Get FileRecord and ReadFileRecordRequest classes lazily."""
    _get_pymodbus()
    from pymodbus.pdu.file_message import (
        FileRecord,
        ReadFileRecordRequest,
        WriteFileRecordRequest,
    )

    return FileRecord, ReadFileRecordRequest, WriteFileRecordRequest


def execute_pdu(client, pdu, unit_id=0):
    """Execute a PDU with pymodbus version compatibility.

    pymodbus 3.x changed the execute() signature:
      - 2.x: client.execute(pdu, unit=unit_id)
      - 3.x: client.execute(no_response_expected, pdu) with dev_id in PDU
    """
    version = _get_pymodbus_version()
    if version >= 3:
        # pymodbus 3.x: set dev_id on PDU and use new signature
        pdu.dev_id = unit_id
        return client.execute(False, pdu)
    else:
        # pymodbus 2.x: pass unit as keyword argument
        return client.execute(pdu, unit=unit_id)


from ...utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)

# Re-export constants for backwards compatibility (tests import from scanner)
from .constants import (  # noqa: F401
    ModbusFunctionCode,
    ModbusExceptionCode,
    MEIType,
    MEIReadDeviceIdCode,
    MEIObjectId,
    MEI_OBJECT_NAMES,
    DiagnosticSubfunction,
    DIAGNOSTIC_SUBFUNCTIONS,
    RegisterType,
    FUNCTION_CODES,
    EXCEPTION_CODES,
    DISCOVERY_FUNCTION_CODES,
)

from .scanner_mixins import (
    ScannerIdentificationMixin,
    ScannerDiscoveryMixin,
    ScannerDiagnosticsMixin,
    ScannerCommEventsMixin,
    ScannerFileOpsMixin,
    ScannerWriteOpsMixin,
    ScannerReportingMixin,
    ScannerCustomFCMixin,
)


# Import protocol options from canonical location in constants.py
from .constants import PROTOCOL_OPTIONS as protocol_options  # noqa: N811


@register_protocol(
    name="Modbus Scanner",
    description="""
        This module scans Modbus TCP/RTU devices to discover supported function codes,
        read register values, and test write access.
    """,
    default_port=502,
    authors=["f0rw4rd"],
    references=[
        {"type": "url", "ref": "https://modbus.org/specs.php"},
        {"type": "url", "ref": "https://github.com/riptideio/pymodbus"},
    ],
    protocol_options=protocol_options,
)
class ModbusScanner(
    ScannerIdentificationMixin,
    ScannerDiscoveryMixin,
    ScannerDiagnosticsMixin,
    ScannerCommEventsMixin,
    ScannerFileOpsMixin,
    ScannerWriteOpsMixin,
    ScannerReportingMixin,
    ScannerCustomFCMixin,
    NetworkScanner,
):
    """Modbus TCP/RTU Scanner implementing the base scanner interface"""

    def __init__(self, args: Dict[str, Any]):
        super().__init__(args)
        self.unit_id = int(args.get("unit-id", 1))
        self.scan_range = args.get("scan-range")
        self.register_type = args.get("register-type", "all")
        # If scan_range explicitly provided, include register scanning
        if self.scan_range:
            self.scan_mode = "all"
        self.discover_units = parse_bool(args.get("discover-units", False))
        self.unit_range = args.get("unit-range", "0-254")
        self.fc_range = args.get("fc-range") or args.get(
            "function-range", "1-8,11,12,15-17,20-23,43"
        )
        self.fc_all = args.get("fc-all", False)
        self.scan_fc = args.get("scan-fc", False)
        self.serial_port = args.get("serial-port", "")
        self.baudrate = int(args.get("baudrate", 9600))
        self.get_device_id = parse_bool(args.get("get-device-id", False))
        self.decode_all = parse_bool(args.get("decode-all", False))
        self.decode_type = args.get("decode") or args.get("d")  # -d TYPE
        self.endian = args.get("endian", "big")
        self.decode_width = args.get("decode-width") or args.get(
            "decode_width"
        )  # Custom register width
        self.filter_zero = parse_bool(args.get("filter-zero", False))
        self.output_dir = args.get("output-dir") or args.get("output")

    def get_protocol_name(self) -> str:
        return "Modbus"

    def get_default_port(self) -> int:
        return 502

    def check_dependencies(self) -> bool:
        return _pymodbus.is_available

    def connect(self) -> Any:
        """
        Establish Modbus connection with multiple transport support

        Supports:
            - TCP: Standard Modbus/TCP
            - TLS: Modbus/TCP with TLS encryption
            - UDP: Modbus over UDP
            - RTU-over-TCP: RTU framing over TCP connection
            - Serial: Modbus RTU/ASCII over serial port
        """
        # Get client classes from lazy loaders
        ModbusTcpClient = _get_modbus_tcp_client()
        ModbusSerialClient = _get_modbus_serial_client()
        ModbusTlsClient = _get_modbus_tls_client()
        ModbusUdpClient = _get_modbus_udp_client()
        FramerType = _get_framer_type()

        transport = self.args.get("transport", "tcp")
        use_tls = self.args.get("tls", False) or transport == "tls"
        use_udp = self.args.get("udp", False) or transport == "udp"
        use_rtu_tcp = self.args.get("rtu-over-tcp", False) or transport == "rtu-tcp"
        use_ascii_tcp = self.args.get("ascii-over-tcp", False) or transport == "ascii-tcp"
        use_ascii_serial = self.args.get("ascii", False)

        client = None

        # Serial connection (RTU or ASCII)
        if self.serial_port or transport == "serial":
            framing = "ASCII" if use_ascii_serial else "RTU"
            self.logger.debug(f"Connecting via Serial/{framing}: {self.serial_port}")

            client_kwargs = {
                "port": self.serial_port,
                "baudrate": self.baudrate,
                "timeout": self.timeout,
                "parity": self.args.get("parity", "N"),
                "stopbits": int(self.args.get("stopbits", 1)),
                "bytesize": int(self.args.get("bytesize", 8)),
            }

            # Set framer for ASCII mode
            if use_ascii_serial:
                if FramerType is not None:
                    client_kwargs["framer"] = FramerType.ASCII
                else:
                    client_kwargs["framer"] = "ascii"

            # Flow control: pymodbus 3.x ModbusSerialClient has no rtscts/dsrdtr
            # constructor params (and no **kwargs), so passing them raised
            # TypeError and broke serial connection entirely. Apply them to the
            # underlying pyserial object after construction instead.
            want_rtscts = bool(self.args.get("rtscts", False))
            want_dsrdtr = bool(self.args.get("dsrdtr", False))

            try:
                client = ModbusSerialClient(**client_kwargs)
                if want_rtscts or want_dsrdtr:
                    serial_obj = getattr(client, "socket", None) or getattr(client, "comm", None)
                    if serial_obj is not None:
                        if want_rtscts:
                            serial_obj.rtscts = True
                        if want_dsrdtr:
                            serial_obj.dsrdtr = True
                    else:
                        self.logger.debug(
                            "rtscts/dsrdtr requested but pyserial object not exposed yet"
                        )
            except Exception as e:
                self.logger.debug("connect failed: %s", e)
                self.logger.fail(f"Failed to create serial client: {e}")
                return None

        # TLS connection
        elif use_tls:
            self.logger.debug(f"Connecting via TLS: {self.host}:{self.port}")

            if ModbusTlsClient is None:
                self.logger.fail("TLS support requires pymodbus >= 3.0")
                return None

            # Build SSL context using central TLS function
            from ...utils.socket_helpers import build_tls_context

            ssl_context = build_tls_context(self.args, logger=self.logger)

            try:
                client = ModbusTlsClient(
                    host=self.host,
                    port=self.port or 802,  # Default TLS port
                    timeout=self.timeout,
                    retries=0,
                    sslctx=ssl_context,
                )
            except Exception as e:
                self.logger.debug("connect failed: %s", e)
                self.logger.fail(f"Failed to create TLS client: {e}")
                return None

        # UDP connection
        elif use_udp:
            self.logger.debug(f"Connecting via UDP: {self.host}:{self.port}")

            if ModbusUdpClient is None:
                self.logger.fail("UDP support requires pymodbus >= 3.0")
                return None

            try:
                client = ModbusUdpClient(
                    host=self.host, port=self.port, timeout=self.timeout, retries=0
                )
            except Exception as e:
                self.logger.debug("connect failed: %s", e)
                self.logger.fail(f"Failed to create UDP client: {e}")
                return None

        # RTU-over-TCP connection
        elif use_rtu_tcp:
            self.logger.debug(f"Connecting via RTU-over-TCP: {self.host}:{self.port}")

            try:
                # pymodbus 3.x uses framer parameter
                if FramerType is not None:
                    client = ModbusTcpClient(
                        host=self.host,
                        port=self.port,
                        timeout=self.timeout,
                        retries=0,
                        framer=FramerType.RTU,
                    )
                else:
                    # Older pymodbus - try framer string
                    client = ModbusTcpClient(
                        host=self.host,
                        port=self.port,
                        timeout=self.timeout,
                        retries=0,
                        framer="rtu",
                    )
            except Exception as e:
                self.logger.debug("connect failed: %s", e)
                self.logger.fail(f"Failed to create RTU-over-TCP client: {e}")
                return None

        # ASCII-over-TCP connection
        elif use_ascii_tcp:
            self.logger.debug(f"Connecting via ASCII-over-TCP: {self.host}:{self.port}")

            try:
                # pymodbus 3.x uses framer parameter
                if FramerType is not None:
                    client = ModbusTcpClient(
                        host=self.host,
                        port=self.port,
                        timeout=self.timeout,
                        retries=0,
                        framer=FramerType.ASCII,
                    )
                else:
                    # Older pymodbus - try framer string
                    client = ModbusTcpClient(
                        host=self.host,
                        port=self.port,
                        timeout=self.timeout,
                        retries=0,
                        framer="ascii",
                    )
            except Exception as e:
                self.logger.debug("connect failed: %s", e)
                self.logger.fail(f"Failed to create ASCII-over-TCP client: {e}")
                return None

        # Standard TCP connection
        else:
            self.logger.debug(f"Connecting via TCP: {self.host}:{self.port}")
            client = ModbusTcpClient(
                host=self.host, port=self.port, timeout=self.timeout, retries=0
            )

        # Connect
        if client:
            try:
                if client.connect():
                    # Check TLS certificate using central validation
                    if use_tls:
                        self._check_tls_certificate(client)
                    return client
                else:
                    self.logger.debug(
                        f"Failed to connect to Modbus server at {self.host}:{self.port}"
                    )
            except Exception as e:
                self.logger.debug("connect failed: %s", e)
                self.logger.fail(f"Connection error: {e}")

        return None

    def _check_tls_certificate(self, client: Any) -> None:
        """Check TLS certificate using central certificate validation.

        Tries to extract the cert from the pymodbus client socket first,
        falls back to a standalone TLS probe via the central helper.
        """
        from ...utils.security_findings import display_cert_info
        from ...utils.socket_helpers import check_tls_certificate

        cert_der = None
        try:
            # Try to get the underlying SSL socket from pymodbus client
            sock = None
            if hasattr(client, "socket") and client.socket:
                sock = client.socket
            elif hasattr(client, "transport") and client.transport:
                sock = getattr(client.transport, "_ssl_protocol", None)
                if sock and hasattr(sock, "_sslpipe"):
                    sock = getattr(sock._sslpipe, "_sslobj", None)
            elif hasattr(client, "params"):
                sock = getattr(client.params, "sock", None)

            if sock is not None:
                cert_der = sock.getpeercert(binary_form=True)
        except Exception as e:
            self.logger.debug(f"Could not extract cert from client socket: {e}")

        if cert_der:
            display_cert_info(
                logger=self.logger,
                cert=cert_der,
                protocol="modbus",
                target=f"{self.host}:{self.port or 802}",
                verbose=self.debug,
            )
        else:
            # Fallback: standalone TLS probe
            check_tls_certificate(
                host=self.host,
                port=self.port or 802,
                logger=self.logger,
                protocol="modbus",
                timeout=self.timeout,
                verbose=self.debug,
            )

    def disconnect(self, connection: Any) -> None:
        """Close Modbus connection"""
        if connection:
            connection.close()

    def discover(self, connection: Any) -> Dict[str, Any]:
        """Perform Modbus discovery based on scan mode"""
        self.logger.debug("Starting Modbus discovery workflow")
        self.logger.debug(
            f"Options: scan_mode={self.scan_mode}, unit_id={self.unit_id}, "
            f"discover_units={self.discover_units}, get_device_id={self.get_device_id}"
        )

        results = {
            "server_info": {},
            "units": {},
            "function_codes": {},
            "registers": {},
        }

        # Basic server information (use cached if available)
        if hasattr(self, "_cached_server_info") and self._cached_server_info:
            self.logger.debug("Using cached server information")
            results["server_info"] = self._cached_server_info
        else:
            self.logger.debug("Getting server information...")
            results["server_info"] = self._get_server_info(connection)

        if self.scan_mode in ["discovery", "all"]:
            # Discover active unit IDs
            if self.discover_units:
                self.logger.debug("Starting unit ID discovery...")
                results["units"] = self._discover_units(connection)

            # Test supported function codes
            self.logger.debug("Testing supported function codes...")
            results["function_codes"] = self._test_function_codes(connection)

        if self.scan_mode in ["registers", "all"]:
            # Scan registers
            self.logger.debug(f"Starting register scan (range: {self.scan_range})...")
            results["registers"] = self._scan_registers(connection)

        # Report findings
        self._report_findings(results)

        self.logger.debug("Modbus discovery workflow complete")
        return results

    def _scan_registers(self, client: Any) -> Dict[str, Any]:
        """Scan Modbus registers"""
        self.logger.display("Scanning registers...")
        registers = {
            "coils": {},
            "discrete_inputs": {},
            "holding_registers": {},
            "input_registers": {},
        }

        address_range = ProtocolParser.parse_address_range(self.scan_range)

        if self.register_type in ["coil", "all"]:
            registers["coils"] = self._scan_register_type(client, "coils", address_range)

        if self.register_type in ["discrete", "all"]:
            registers["discrete_inputs"] = self._scan_register_type(
                client, "discrete_inputs", address_range
            )

        if self.register_type in ["holding", "all"]:
            registers["holding_registers"] = self._scan_register_type(
                client, "holding_registers", address_range
            )

        if self.register_type in ["input", "all"]:
            registers["input_registers"] = self._scan_register_type(
                client, "input_registers", address_range
            )

        return registers

    def _scan_register_type(
        self, client: Any, register_type: str, address_range: List[int]
    ) -> Dict[str, Any]:
        """Scan specific register type using batched reads.

        Reads registers in batches of ``max_registers`` (default 125 for
        holding/input registers, 2000 for coils/discrete inputs) to reduce
        the number of Modbus requests.  Contiguous runs within *address_range*
        are grouped and read in a single request when possible.  If a batch
        read fails the affected chunk is re-scanned one address at a time so
        that individual readable addresses are still discovered.
        """
        from .register_io import build_batches, read_registers_batched

        progress = ProgressTracker(len(address_range), logger=self.logger)

        # Determine batch size from the existing --max-registers argument.
        if register_type in ("coils", "discrete_inputs"):
            max_batch = min(int(self.args.get("max-registers", 2000)), 2000)
        else:
            max_batch = min(int(self.args.get("max-registers", 125)), 125)

        # Show progress via batches.
        batches = build_batches(address_range, max_batch)
        scanned = 0
        for _start, _count, batch_addrs in batches:
            scanned += len(batch_addrs)
            progress.update(
                pos=scanned,
                msg=f"Scanning {register_type} addresses {batch_addrs[0]}-{batch_addrs[-1]}",
            )

        # Batch-read all addresses with individual fallback.
        raw_values = read_registers_batched(
            client,
            register_type,
            address_range,
            unit_id=self.unit_id,
            max_batch=max_batch,
            fallback_individual=True,
            logger=self.logger,
        )

        # Wrap raw values into the scanner result format.
        results: Dict[str, Any] = {}
        for addr, value in raw_values.items():
            results[addr] = {
                "value": value,
                "readable": True,
                "timestamp": datetime.now().isoformat(),
            }
            if not self.read_only and register_type in ("coils", "holding_registers"):
                # Use the safe same-value write test (write-back, no data
                # change) here, not the destructive 42/43-flip test: an
                # ordinary read scan with read-only=False should not mutate
                # live registers without the explicit --confirm gate that
                # _handle_test_write() requires for its destructive mode.
                results[addr]["writable"] = self._test_write_access_safe(
                    client, register_type, addr, value
                ).get("writable", False)

        errors = len(address_range) - len(results)
        if errors > 0:
            self.logger.warning(f"{register_type}: {errors}/{len(address_range)} addresses failed")

        return results

    @staticmethod
    def _build_batches(address_range: List[int], max_batch: int) -> List[tuple]:
        """Split an address range into contiguous batches.

        Thin wrapper around :func:`register_io.build_batches` kept for
        backwards compatibility with existing tests.
        """
        from .register_io import build_batches

        return build_batches(address_range, max_batch)

    def _test_write_access_safe(
        self, client: Any, register_type: str, addr: int, original_value: Any
    ) -> Dict[str, Any]:
        """
        Test write access by writing the SAME value back (truly non-destructive).

        Pattern: read → write same value → verify
        This is the safest write test that confirms write capability without
        modifying any data.

        Args:
            client: Modbus client
            register_type: 'coils' or 'holding_registers'
            addr: Register address
            original_value: Current value to write back

        Returns:
            dict: {writable: bool, error: str or None}
        """
        result = {"writable": False, "error": None}
        try:
            # pymodbus 3.8+ uses device_id= instead of unit=
            if register_type == "coils":
                write_result = client.write_coil(addr, original_value, device_id=self.unit_id)
                if not write_result.isError():
                    # Verify value unchanged
                    verify = client.read_coils(addr, count=1, device_id=self.unit_id)
                    if not verify.isError() and verify.bits[0] == original_value:
                        result["writable"] = True
                else:
                    result["error"] = str(write_result)
            elif register_type == "holding_registers":
                write_result = client.write_register(addr, original_value, device_id=self.unit_id)
                if not write_result.isError():
                    # Verify value unchanged
                    verify = client.read_holding_registers(addr, count=1, device_id=self.unit_id)
                    if not verify.isError() and verify.registers[0] == original_value:
                        result["writable"] = True
                else:
                    result["error"] = str(write_result)
            else:
                result["error"] = f"Unsupported register type: {register_type}"

        except Exception as e:
            result["error"] = str(e)
            self.logger.debug(f"Safe write test failed for {register_type} address {addr}: {e}")

        return result

    def _test_write_access_destructive(
        self, client: Any, register_type: str, addr: int, original_value: Any
    ) -> Dict[str, Any]:
        """
        Test write access by writing a DIFFERENT value and restoring (Metasploit-style).

        Pattern: read → write different value → restore original
        This is more thorough but temporarily modifies the register value.

        Args:
            client: Modbus client
            register_type: 'coils' or 'holding_registers'
            addr: Register address
            original_value: Current value to restore after test

        Returns:
            dict: {writable: bool, restored: bool, error: str or None}
        """
        result = {"writable": False, "restored": False, "error": None}
        try:
            # pymodbus 3.8+ uses device_id= instead of unit=
            if register_type == "coils":
                # Test writing opposite boolean value
                test_value = not original_value if isinstance(original_value, bool) else True
                write_result = client.write_coil(addr, test_value, device_id=self.unit_id)
                if not write_result.isError():
                    result["writable"] = True
                    # Restore original value
                    restore_result = client.write_coil(addr, original_value, device_id=self.unit_id)
                    result["restored"] = not restore_result.isError()
                else:
                    result["error"] = str(write_result)
            elif register_type == "holding_registers":
                # Test writing a different value
                test_value = 42 if original_value != 42 else 43
                write_result = client.write_register(addr, test_value, device_id=self.unit_id)
                if not write_result.isError():
                    result["writable"] = True
                    # Restore original value
                    restore_result = client.write_register(
                        addr, original_value, device_id=self.unit_id
                    )
                    result["restored"] = not restore_result.isError()
                else:
                    result["error"] = str(write_result)
            else:
                result["error"] = f"Unsupported register type: {register_type}"

        except Exception as e:
            result["error"] = str(e)
            self.logger.debug(
                f"Destructive write test failed for {register_type} address {addr}: {e}"
            )

        return result

    def _test_write_access(
        self, client: Any, register_type: str, addr: int, original_value: Any
    ) -> bool:
        """Test write access to a register (legacy wrapper, uses destructive mode)"""
        result = self._test_write_access_destructive(client, register_type, addr, original_value)
        return result.get("writable", False)


# PDU classes are only available if pymodbus is installed
# These will be defined when the module is first used (lazy check)
if _pymodbus.is_available:
    from pymodbus.pdu import ModbusPDU

    class GenericPDU(ModbusPDU):
        """Generic PDU for testing arbitrary function codes.

        For known FCs, sends minimal valid data to get a proper response.
        For unknown FCs, sends empty data which may trigger exception 3.
        """

        rtu_frame_size = 4

        def __init__(self, function_code=1, **kwargs):
            self.function_code = function_code
            super().__init__(**kwargs)

        def encode(self):
            """Encode minimal valid request data based on function code."""
            fc = self.function_code
            # Read Coils (FC 1), Read Discrete Inputs (FC 2)
            # Read Holding Registers (FC 3), Read Input Registers (FC 4)
            if fc in [1, 2, 3, 4]:
                # Request: start_addr (2 bytes), count (2 bytes)
                return struct.pack(">HH", 0, 1)  # addr=0, count=1
            # Write Single Coil (FC 5)
            elif fc == 5:
                # Request: addr (2 bytes), value (2 bytes, 0xFF00=ON, 0x0000=OFF)
                return struct.pack(">HH", 0, 0xFF00)
            # Write Single Register (FC 6)
            elif fc == 6:
                # Request: addr (2 bytes), value (2 bytes)
                return struct.pack(">HH", 0, 0)
            # Write Multiple Coils (FC 15)
            elif fc == 15:
                # Request: addr (2), count (2), byte_count (1), values (N)
                return struct.pack(">HHBB", 0, 1, 1, 0x01)
            # Write Multiple Registers (FC 16)
            elif fc == 16:
                # Request: addr (2), count (2), byte_count (1), values (2*count)
                return struct.pack(">HHBHH", 0, 1, 2, 0, 0)
            # Report Server ID (FC 17) - no data needed
            elif fc == 17:
                return b""
            # Read/Write Multiple Registers (FC 23)
            elif fc == 23:
                # Read: addr (2), count (2), Write: addr (2), count (2), byte_count (1), values
                return struct.pack(">HHHHBHH", 0, 1, 0, 1, 2, 0, 0)
            # Mask Write Register (FC 22)
            elif fc == 22:
                # Request: addr (2), AND mask (2), OR mask (2)
                return struct.pack(">HHH", 0, 0xFFFF, 0x0000)
            # MEI Device Identification (FC 43)
            elif fc == 43:
                # MEI type (1), read code (1), object id (1)
                return struct.pack(">BBB", 0x0E, 0x01, 0x00)
            # For unknown FCs, send empty (will likely get exception)
            else:
                return b""

        def decode(self, data):
            pass


# Create metadata and run function using protocol module factory
# This replaces ~70 lines of boilerplate code
metadata, run = create_protocol_module(
    ModbusScanner, dependencies_check_func=lambda: not _pymodbus.is_available
)


if __name__ == "__main__":
    # Standalone mode
    cli_run(metadata, run)

"""
IEC 60870-5-104 Protocol Scanner

Core scanner class with connection handling, discovery, and interrogation.
Uses mixins for serial, file transfer, commands, and listen mode.
"""

from typing import Dict, Any, Set, List, Optional
from datetime import datetime
import struct
import time
import threading

from ...utils import (
    register_protocol,
    create_protocol_module,
    NetworkScanner,
    SecurityAnalyzer,
)
from ...utils.protocol_helpers import ConnectionHelper
from ...utils.cli import run as cli_run
from ...utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)

from .constants import (
    IEC104_TYPE_IDS,
    CapturedASDU,
    ListenStats,
    INFO_ELEMENT_SIZES,
    protocol_options,
    ASDU_ADDRESS_MAX,
    ASDU_COT_OFFSET,
    ASDU_HEADER_SIZE,
    ASDU_TYPE_ID_OFFSET,
    COT_NEGATIVE_BIT,
    COUNTER_TYPE_ID_START,
    COUNTER_TYPE_ID_END,
    CP56TIME2A_BASE_YEAR,
    CP56TIME2A_DAY_MASK,
    CP56TIME2A_HOUR_MASK,
    CP56TIME2A_MINUTE_MASK,
    CP56TIME2A_MONTH_MASK,
    CP56TIME2A_SIZE,
    CP56TIME2A_YEAR_MASK,
    DIQ_DPI_MASK,
    FILE_TRANSFER_TYPE_ID_START,
    FILE_TRANSFER_TYPE_ID_END,
    IFRAME_MASK,
    IOA_SIZE,
    MONITORING_TYPE_ID_MAX,
    NORMALIZED_SCALE,
    SIQ_SPI_MASK,
    VTI_VALUE_MASK,
)
from . import _deps
from .serial import IEC101Mixin
from .commands import CommandMixin
from .listen import ListenMixin


@register_protocol(
    name="IEC 104 Scanner",
    description="""IEC 60870-5-104 protocol scanner for SCADA systems.

Features:
- Type ID discovery via general interrogation
- File transfer capability probing (Type IDs 120-127)
- Custom/extended type ID detection
- Security analysis""",
    default_port=2404,
    authors=["f0rw4rd"],
    references=[{"type": "url", "ref": "https://en.wikipedia.org/wiki/IEC_60870-5"}],
    protocol_options=protocol_options,
)
class IEC104Scanner(ListenMixin, CommandMixin, IEC101Mixin, NetworkScanner):
    """IEC 60870-5-104 Scanner with enhanced type ID and file transfer discovery"""

    def __init__(self, args: Dict[str, Any]):
        super().__init__(args)

        # TLS options
        self.use_tls = args.get("tls", False)
        self.tls_cert = args.get("tls-cert")
        self.tls_key = args.get("tls-key")
        self.tls_ca = args.get("tls-ca")

        # Handle None values explicitly
        asdu = args.get("asdu-address")
        self.asdu_address = int(asdu) if asdu is not None else -1
        if self.asdu_address != -1 and not (0 <= self.asdu_address <= ASDU_ADDRESS_MAX):
            self.logger.warning(f"ASDU address {self.asdu_address} out of range, using -1")
            self.asdu_address = -1

        ca = args.get("common-address")
        if ca is not None:
            self.common_address = int(ca)
            self._ca_explicit = True
        elif self.asdu_address != -1:
            self.common_address = self.asdu_address
            self._ca_explicit = True
        else:
            self.common_address = 1
            self._ca_explicit = False
        self.probe_files = args.get("probe-files", False)
        self.interrogate = args.get("interrogate", False)
        self.interrogate_groups = args.get("interrogate-groups", False)

        # Station scan (--station-scan / -S)
        station_scan_raw = args.get("station-scan")
        self.station_scan = station_scan_raw is not None
        if self.station_scan and station_scan_raw is not None:
            try:
                parts = station_scan_raw.split("-")
                if len(parts) == 2:
                    s, e = int(parts[0]), int(parts[1])
                    if s > e:
                        s, e = e, s
                    self.ca_scan_start = max(1, min(s, 65534))
                    self.ca_scan_end = max(1, min(e, 65534))
                else:
                    raise ValueError("expected START-END")
            except (ValueError, AttributeError):
                self.logger.warning(f"Invalid station-scan range '{station_scan_raw}', using 1-254")
                self.ca_scan_start = 1
                self.ca_scan_end = 254
        else:
            self.ca_scan_start = 1
            self.ca_scan_end = 254
        self.test_commands = args.get("test-commands", False)
        wt = args.get("wait-time")
        self.wait_time = int(wt) if wt is not None else 3

        # Unified dangerous-operation confirmation flag
        self.confirm_dangerous = args.get("confirm", False)

        # Custom type probing
        self.probe_custom_types = args.get("probe-custom-types", False)

        # Read IOA parsing
        read_ioa_str = args.get("read-ioa")
        self.read_ioas: List[int] = []
        if read_ioa_str:
            try:
                self.read_ioas = [int(x.strip()) for x in read_ioa_str.split(",")]
            except ValueError:
                self.logger.warning(f"Invalid --read-ioa value '{read_ioa_str}', ignoring")
                self.read_ioas = []
        self.counter_interrogation = args.get("counter-interrogation", False)
        self.clock_read = args.get("clock-read", False)

        # Fuzzing options
        self.fuzz_enabled = args.get("fuzz", False)
        self.fuzz_iterations = args.get("fuzz-iterations", 20)
        self.fuzz_ioa = args.get("fuzz-ioa", 1)

        # Protocol parameter tuning
        self.t1 = args.get("t1")
        self.t3 = args.get("t3")
        self.originator_address = args.get("originator")

        # Write options — parse IOA[:VALUE] combined format
        inline_value = None
        self.write_single_ioa, v = self._parse_write_arg(args.get("write-single"))
        inline_value = inline_value or v
        self.write_double_ioa, v = self._parse_write_arg(args.get("write-double"))
        inline_value = inline_value or v
        self.write_float_ioa, v = self._parse_write_arg(args.get("write-float"))
        inline_value = inline_value or v
        self.write_scaled_ioa, v = self._parse_write_arg(args.get("write-scaled"))
        inline_value = inline_value or v
        self.write_normalized_ioa, v = self._parse_write_arg(args.get("write-normalized"))
        inline_value = inline_value or v
        self.write_step_ioa, v = self._parse_write_arg(args.get("write-step"))
        inline_value = inline_value or v

        # Reset process
        self.reset_process = args.get("reset-process", False)

        # Parameter commands (Types 110-113)
        self.param_normalized_ioa, v = self._parse_write_arg(args.get("param-normalized"))
        inline_value = inline_value or v
        self.param_scaled_ioa, v = self._parse_write_arg(args.get("param-scaled"))
        inline_value = inline_value or v
        self.param_float_ioa, v = self._parse_write_arg(args.get("param-float"))
        inline_value = inline_value or v
        self.param_activate_ioa, v = self._parse_write_arg(args.get("param-activate"))
        inline_value = inline_value or v

        # Explicit --value wins; inline value is fallback
        self.write_value = args.get("value") or inline_value
        self.select_execute = args.get("select-execute", False)
        self.write_type_id = args.get("write-type")
        # Target IOA for --test-commands (falls back to --write-single's IOA).
        self.test_command_ioa = args.get("test-command-ioa")
        if self.test_command_ioa is None:
            self.test_command_ioa = self.write_single_ioa
        self.write_ioa = args.get("write-ioa")

        # Listen/monitor mode options
        self.listen_mode = args.get("listen", False)
        self.listen_time = args.get("listen-time", 60)
        self.listen_output = args.get("listen-output")
        self.listen_raw = args.get("listen-raw", False)
        self.listen_filter = self._parse_type_filter(args.get("listen-filter"))

        # IEC 101 Serial mode options
        self.iec101_mode = False
        self.serial_port = None
        self.baudrate = 9600
        self.parity = "E"
        self.stopbits = 1
        self.link_address = int(args.get("link-address", 1))
        self.balanced_mode = args.get("balanced", False)
        self._serial = None
        self._fcb = False  # Frame count bit toggle

        iec101_config = args.get("iec101")
        if iec101_config:
            self.iec101_mode = True
            self._parse_iec101_config(iec101_config)

        # Output/export options
        self.output_dir = args.get("output-dir") or args.get("output")
        self.full_width = args.get("full-width", False)

        # Listen mode state
        self._captured_asdus: List[CapturedASDU] = []
        self._listen_stats: Optional[ListenStats] = None
        self._stop_listen = threading.Event()
        self._listen_output_fh = None

        # Discovery state (populated during scan)
        self._discovered_points: Dict[int, Dict[str, Any]] = {}
        self._discovered_types: Set[str] = set()
        self._discovered_stations: Set[int] = set()
        self._raw_type_ids: Set[int] = set()
        self._custom_type_ids: Set[int] = set()
        self._file_transfer_supported = False
        self._unexpected_messages: List[Dict[str, Any]] = []
        self._station_scan_results: Dict[int, Dict[str, Any]] = {}
        self._command_responses: List[Dict[str, Any]] = []
        self._clock_sync_raw: Optional[bytes] = None  # C_CS_NA_1 actcon capture
        self._init_cause: Optional[str] = None
        self._connection_state: Optional[str] = None
        self._lock = threading.Lock()

    @staticmethod
    def _parse_write_arg(raw: Optional[str]):
        """Parse 'IOA[:VALUE]' string into (ioa_int, value_str_or_None).

        Returns (None, None) when raw is None (flag not given) or malformed.
        """
        if raw is None:
            return None, None
        # Guard the int() conversions so a malformed arg (e.g. --write-single
        # foo:bar) fails cleanly instead of aborting __init__ with a raw
        # ValueError traceback (mirrors the --read-ioa parser's behavior).
        try:
            if ":" in raw:
                ioa_str, value = raw.split(":", 1)
                return int(ioa_str), value
            return int(raw), None
        except (ValueError, TypeError):
            logger.warning(f"Invalid IOA in '{raw}' (expected IOA[:VALUE] with integer IOA)")
            return None, None

    def get_protocol_name(self) -> str:
        return "IEC 104"

    def get_default_port(self) -> int:
        return 2404

    def check_dependencies(self) -> bool:
        if self.iec101_mode:
            return _deps._serial.is_available
        return _deps._c104.is_available

    # =========================================================================
    # Callbacks
    # =========================================================================

    def _create_callbacks(self):
        """Create properly typed callbacks for c104 library"""
        c104 = _deps._get_c104()
        scanner = self  # Capture self for closures

        def on_new_station(
            client: c104.Client, connection: c104.Connection, common_address: int
        ) -> None:
            with scanner._lock:
                scanner._discovered_stations.add(common_address)
            self.logger.debug(f"Discovered station CA={common_address}")

        def on_new_point(
            client: c104.Client,
            station: c104.Station,
            io_address: int,
            point_type: c104.Type,
        ) -> None:
            type_str = str(point_type)
            type_name = type_str.replace("Type.", "")

            try:
                type_id = point_type.value
            except Exception as e:
                self.logger.debug(f"Failed to get type_id from point: {e}")
                type_id = None

            with scanner._lock:
                scanner._discovered_types.add(type_name)
                if type_id is not None:
                    scanner._raw_type_ids.add(type_id)
                    if type_id not in IEC104_TYPE_IDS:
                        scanner._custom_type_ids.add(type_id)
                    if FILE_TRANSFER_TYPE_ID_START <= type_id <= FILE_TRANSFER_TYPE_ID_END:
                        scanner._file_transfer_supported = True

                scanner._discovered_points[io_address] = {
                    "type": type_name,
                    "type_id": type_id,
                    "station_ca": station.common_address,
                    "timestamp": datetime.now().isoformat(),
                }

            self.logger.debug(f"Point IOA={io_address} Type={type_name}")

        def on_receive_raw(connection: c104.Connection, data: bytes) -> None:
            if len(data) >= 7:
                # Check if this is an I-frame (data transfer) - bit 0 of ctrl1 = 0
                if len(data) >= 6 and (data[2] & IFRAME_MASK) == 0:
                    if len(data) > ASDU_TYPE_ID_OFFSET:
                        type_id = data[ASDU_TYPE_ID_OFFSET]
                        with scanner._lock:
                            scanner._raw_type_ids.add(type_id)
                            if type_id not in IEC104_TYPE_IDS:
                                scanner._custom_type_ids.add(type_id)
                            if FILE_TRANSFER_TYPE_ID_START <= type_id <= FILE_TRANSFER_TYPE_ID_END:
                                scanner._file_transfer_supported = True

                        # Capture C_CS_NA_1 (Type 103) actcon for clock read
                        if type_id == 103 and len(data) >= 22:
                            with scanner._lock:
                                scanner._clock_sync_raw = data

                        # Use c104's built-in parser to extract IOAs and store points
                        # Only store monitoring-direction types (1-44) as data points;
                        # types 45-69 (commands), 70+ (system/control) are echoes
                        try:
                            parsed = c104.explain_bytes_dict(data)

                            # Track command responses (rejections, negative confirms, error COTs)
                            is_negative = parsed.get("negative", False)
                            cot_obj = parsed.get("cot")
                            cot_str = str(cot_obj).replace("Cot.", "") if cot_obj else ""
                            is_error_cot = cot_str in (
                                "UNKNOWN_TYPE_ID",
                                "UNKNOWN_COT",
                                "UNKNOWN_CA",
                                "UNKNOWN_IOA",
                            )
                            if type_id > MONITORING_TYPE_ID_MAX or is_error_cot or is_negative:
                                ca = parsed.get("commonAddress", 0)
                                with scanner._lock:
                                    scanner._command_responses.append(
                                        {
                                            "type_id": type_id,
                                            "cot": cot_str,
                                            "is_negative": is_negative,
                                            "common_address": ca,
                                            "timestamp": datetime.now().isoformat(),
                                        }
                                    )

                            first_ioa = parsed.get("firstInformationObjectAddress")
                            is_monitoring = type_id <= MONITORING_TYPE_ID_MAX
                            if first_ioa is not None and first_ioa > 0 and is_monitoring:
                                type_obj = parsed.get("type")
                                type_name = (
                                    str(type_obj).replace("Type.", "")
                                    if type_obj
                                    else f"TYPE_{type_id}"
                                )
                                common_addr = parsed.get("commonAddress", 0)
                                num_objects = parsed.get("numberOfObjects", 1)
                                is_sequence = parsed.get("sequence", False)
                                cot_obj = parsed.get("cot")
                                cot_str = str(cot_obj).replace("Cot.", "") if cot_obj else None
                                timestamp = datetime.now().isoformat()

                                # Collect (ioa, info-element offset) pairs. The
                                # info-element offset MUST be captured at parse
                                # time from the physical object index -- deriving
                                # it later from the filtered list index misaligns
                                # every value after an IOA==0 object is skipped.
                                ioas_to_add: list = []
                                _ioa_size = IOA_SIZE
                                _ie_size = INFO_ELEMENT_SIZES.get(type_id, 0)

                                if is_sequence:
                                    # Sequence mode: one IOA, then N packed values.
                                    for i in range(num_objects):
                                        ie_off = ASDU_HEADER_SIZE + _ioa_size + i * _ie_size
                                        ioas_to_add.append((first_ioa + i, ie_off))
                                elif num_objects > 1 and type_id in INFO_ELEMENT_SIZES:
                                    # Non-sequence mode: parse each IOA from the ASDU
                                    offset = ASDU_HEADER_SIZE

                                    for i in range(num_objects):
                                        if offset + _ioa_size <= len(data):
                                            ioa = (
                                                data[offset]
                                                | (data[offset + 1] << 8)
                                                | (data[offset + 2] << 16)
                                            )
                                            if ioa > 0:
                                                ioas_to_add.append((ioa, offset + _ioa_size))
                                            offset += _ioa_size + _ie_size
                                        else:
                                            break
                                else:
                                    # Single object
                                    ioas_to_add = [(first_ioa, ASDU_HEADER_SIZE + _ioa_size)]

                                # Extract measured values from raw info elements.
                                # Returns None when the type size is unknown or the
                                # requested element runs past the end of the buffer
                                # (bounds-checked so out-of-range reads never produce
                                # bogus/duplicate values).
                                def _extract_value(buf: bytes, ie_off: int, tid: int):
                                    """Return parsed value or None."""
                                    size = INFO_ELEMENT_SIZES.get(tid)
                                    if size is None:
                                        return None
                                    if ie_off < 0 or ie_off + size > len(buf):
                                        return None
                                    try:
                                        if tid in (1, 30):  # M_SP single-point
                                            return bool(buf[ie_off] & SIQ_SPI_MASK)
                                        if tid in (3, 31):  # M_DP double-point
                                            return buf[ie_off] & DIQ_DPI_MASK
                                        if tid in (5, 32):  # M_ST step position
                                            v = buf[ie_off] & VTI_VALUE_MASK
                                            return v - 128 if buf[ie_off] & 0x40 else v
                                        if tid in (9, 21, 34):  # M_ME_NA normalized
                                            return round(
                                                struct.unpack_from("<h", buf, ie_off)[0]
                                                / NORMALIZED_SCALE,
                                                6,
                                            )
                                        if tid in (11, 35):  # M_ME_NB scaled
                                            return struct.unpack_from("<h", buf, ie_off)[0]
                                        if tid in (13, 36):  # M_ME_NC short float
                                            return round(
                                                struct.unpack_from("<f", buf, ie_off)[0], 6
                                            )
                                        if tid in (15, 37):  # M_IT integrated totals
                                            return struct.unpack_from("<i", buf, ie_off)[0]
                                        if tid in (7, 33):  # M_BO bitstring
                                            return (
                                                f"0x{struct.unpack_from('<I', buf, ie_off)[0]:08X}"
                                            )
                                    except (struct.error, IndexError) as e:
                                        scanner.logger.debug(
                                            f"Info-element value extraction failed for Type {tid}: {e}"
                                        )
                                    return None

                                # Store/update discovered IOAs. ie_off was
                                # captured from the physical object position at
                                # parse time (see above), so it stays aligned even
                                # when an IOA==0 object was skipped.
                                with scanner._lock:
                                    if common_addr > 0:
                                        scanner._discovered_stations.add(common_addr)
                                    for ioa, ie_off in ioas_to_add:
                                        value = _extract_value(data, ie_off, type_id)
                                        entry = {
                                            "type": type_name,
                                            "type_id": type_id,
                                            "station_ca": common_addr,
                                            "cot": cot_str,
                                            "timestamp": timestamp,
                                        }
                                        if value is not None:
                                            entry["value"] = value
                                        if ioa not in scanner._discovered_points:
                                            scanner._discovered_types.add(type_name)
                                            self.logger.debug(
                                                f"Discovered IOA={ioa} Type={type_name} CA={common_addr}"
                                            )
                                        scanner._discovered_points[ioa] = entry
                        except Exception as e:
                            self.logger.debug(f"ASDU parsing failed: {e}")

        def on_unexpected_message(
            connection: c104.Connection, message: c104.IncomingMessage, cause: c104.Umc
        ) -> None:
            cause_str = str(cause).replace("Umc.", "")
            type_str = str(message.type).replace("Type.", "")
            entry = {
                "cause": cause_str,
                "type": type_str,
                "type_id": message.type.value,
                "common_address": message.common_address,
                "io_address": message.io_address,
                "cot": str(message.cot).replace("Cot.", ""),
                "is_negative": message.is_negative,
                "is_test": message.is_test,
                "timestamp": datetime.now().isoformat(),
            }
            with scanner._lock:
                scanner._unexpected_messages.append(entry)

            # UNKNOWN_CA: register the station with c104 so it stops dropping
            # messages, but don't trust the CA for display
            if cause == c104.Umc.UNKNOWN_CA:
                try:
                    connection.add_station(common_address=message.common_address)
                except Exception as e:
                    self.logger.debug(
                        f"connection.add_station(common_address...: {e}"
                    )  # Best-effort station registration
                self.logger.debug(
                    f"UNKNOWN_CA: Type={type_str} CA={message.common_address} IOA={message.io_address}"
                )
                return

            # UNKNOWN_IOA is the expected outcome of a discovery interrogation:
            # The server returns points we never pre-registered in c104's local
            # station model, so c104 flags each ASDU's first IOA as unexpected.
            # The scanner's own on_receive_raw parser discovers these points
            # correctly, so this is noise, not a failure. Record it (already done
            # above) but keep it at debug level instead of a misleading [-] line.
            if cause == c104.Umc.UNKNOWN_IOA:
                self.logger.debug(
                    f"UNKNOWN_IOA: Type={type_str} CA={message.common_address} IOA={message.io_address}"
                )
                return

            self.logger.fail(
                f"Unexpected message: {cause_str} Type={type_str} CA={message.common_address} IOA={message.io_address}"
            )

        def on_station_initialized(
            client: c104.Client, station: c104.Station, cause: c104.Coi
        ) -> None:
            cause_map = {0: "local_power_on", 1: "local_manual_reset", 2: "remote_reset"}
            coi_val = cause.value if hasattr(cause, "value") else int(cause)
            cause_str = cause_map.get(coi_val, str(cause))
            scanner._init_cause = cause_str
            scanner.logger.display(
                f"Station CA={station.common_address} initialized (cause: {cause_str})"
            )

        def on_state_change(connection: c104.Connection, state: c104.ConnectionState) -> None:
            state_str = str(state).replace("ConnectionState.", "")
            scanner._connection_state = state_str
            scanner.logger.debug(f"Connection state: {state_str}")

        def on_send_raw(connection: c104.Connection, data: bytes) -> None:
            if len(data) > ASDU_TYPE_ID_OFFSET and (data[2] & IFRAME_MASK) == 0:
                try:
                    parsed = c104.explain_bytes_dict(data)
                    type_obj = parsed.get("type")
                    cot_obj = parsed.get("cot")
                    scanner.logger.debug(
                        f"TX: {type_obj} COT={cot_obj} CA={parsed.get('commonAddress')} "
                        f"IOA={parsed.get('firstInformationObjectAddress')}"
                    )
                except Exception:
                    scanner.logger.debug(f"TX: {len(data)} bytes")

        return (
            on_new_station,
            on_new_point,
            on_receive_raw,
            on_unexpected_message,
            on_station_initialized,
            on_state_change,
            on_send_raw,
        )

    # =========================================================================
    # Connection
    # =========================================================================

    def connect(self) -> Any:
        """Establish IEC 104/101 connection"""
        # IEC 101 Serial mode
        if self.iec101_mode:
            return self._connect_serial()

        # IEC 104 TCP mode
        if not _deps._c104.is_available:
            self.logger.fail("c104 library not available")
            return None
        c104 = _deps._get_c104()  # Load c104 module (updates module-level export)

        try:
            # Create properly typed callbacks
            (
                on_new_station,
                on_new_point,
                on_receive_raw,
                on_unexpected_message,
                on_station_initialized,
                on_state_change,
                on_send_raw,
            ) = self._create_callbacks()

            # Build TLS transport security if enabled
            transport_security = None
            if self.use_tls:
                transport_security = self._build_tls_config()
                if transport_security is None:
                    return None
                # Probe cert before c104 connect
                self._check_tls_certificate()

            # Create client
            client_kwargs = dict(tick_rate_ms=100, command_timeout_ms=self.timeout * 1000)
            if transport_security:
                client_kwargs["transport_security"] = transport_security
            client = c104.Client(**client_kwargs)

            # Set originator address (identifies this scanner in device audit logs)
            if self.originator_address is not None:
                client.originator_address = self.originator_address

            # Set up discovery callbacks
            client.on_new_station(on_new_station)
            client.on_new_point(on_new_point)
            client.on_station_initialized(on_station_initialized)

            # c104 (lib60870) requires a dotted IP for add_connection() and
            # rejects hostnames with "IP <host> is invalid!". Resolve first.
            try:
                ip = ConnectionHelper.resolve_hostname(self.host)
            except OSError as e:
                self.logger.fail(f"Could not resolve {self.host}: {e}")
                return None
            if ip != self.host:
                self.logger.debug("Resolved %s -> %s", self.host, ip)

            # Add connection - don't auto-interrogate, we'll do it manually
            connection = client.add_connection(
                ip=ip,
                port=self.port,
                init=c104.Init.NONE,  # Manual control
            )

            # Set connection timeout to match --timeout flag
            connection.protocol_parameters.connection_timeout = self.timeout

            # Protocol parameter tuning (t1=message ack timeout, t3=keepalive)
            if self.t1 is not None:
                connection.protocol_parameters.message_timeout = self.t1
            if self.t3 is not None:
                connection.protocol_parameters.keep_alive_interval = self.t3

            # Set up raw message callback for type ID extraction
            connection.on_receive_raw(on_receive_raw)

            # Transmit audit callback (active at debug level)
            connection.on_send_raw(on_send_raw)

            # Connection state tracking
            connection.on_state_change(on_state_change)

            # Capture server error responses
            connection.on_unexpected_message(on_unexpected_message)

            # Wire c104 internal debug to -v / --debug
            if self.debug:
                c104.set_debug_mode(c104.Debug.All)

            # Start client
            client.start()

            # Wait for connection
            for _ in range(self.timeout * 10):
                if connection.is_connected:
                    break
                time.sleep(0.1)

            if not connection.is_connected:
                client.stop()
                return None

            # Confirmed IEC 104 / APCI handshake over TCP. Plaintext by design
            # unless IEC 62351-3 TLS is in use.
            if not self.use_tls:
                self.logger.security_finding(
                    "No encryption",
                    detail="IEC 104 has no transport encryption (cleartext)",
                )

            return (client, connection)

        except Exception as e:
            self.logger.fail(f"IEC 104 connection error: {e}")
            return None

    def _build_tls_config(self):
        """Build c104.TransportSecurity for IEC 62351-3 TLS connections."""
        c104 = _deps._get_c104()
        try:
            tls = c104.TransportSecurity(validate=False, only_known=False)

            # Load CA certificate for server verification if provided
            if self.tls_ca:
                try:
                    tls.set_ca_certificate(cert=self.tls_ca)
                    self.logger.display(f"Using CA certificate: {self.tls_ca}")
                except Exception as e:
                    self.logger.fail(f"Failed to load CA certificate: {e}")
                    return None

            # Load client certificate for mutual TLS if provided
            if self.tls_cert:
                try:
                    tls.set_certificate(cert=self.tls_cert, key=self.tls_key or "")
                    self.logger.display(f"Using client certificate: {self.tls_cert}")
                except Exception as e:
                    self.logger.fail(f"Failed to load client certificate: {e}")
                    return None

            return tls
        except Exception as e:
            self.logger.fail(f"Failed to configure TLS: {e}")
            return None

    def _check_tls_certificate(self) -> None:
        """Probe the TLS endpoint to retrieve and check the server certificate."""
        from ...utils.socket_helpers import check_tls_certificate

        check_tls_certificate(
            host=self.host,
            port=self.port,
            logger=self.logger,
            protocol="iec104",
            timeout=self.timeout,
            verbose=self.debug,
        )

    def disconnect(self, connection: Any) -> None:
        """Close IEC 104/101 connection"""
        # IEC 101 Serial mode
        if self.iec101_mode:
            self._disconnect_serial()
            return

        # IEC 104 TCP mode
        if connection:
            try:
                if isinstance(connection, tuple):
                    client, conn = connection
                    client.stop()
                else:
                    if hasattr(connection, "disconnect"):
                        connection.disconnect()
            except Exception as e:
                self.logger.debug(f"Error during disconnect: {e}")

    # =========================================================================
    # Discovery
    # =========================================================================

    def discover(self, connection: Any) -> Dict[str, Any]:
        """Perform IEC 104/101 discovery with real type enumeration"""
        results = {
            "server_info": {},
            "data_points": {},
            "type_ids": {},
            "file_transfer": {},
            "custom_type_probe": {},
            "commands": {},
            "interrogation": {},
            "security_analysis": {},
            "listen_mode": {},
            "station_scan": {},
        }

        if not connection:
            return results

        # IEC 101 Serial mode
        if self.iec101_mode:
            return self._discover_iec101(connection, results)

        # IEC 104 TCP mode
        client, conn = connection

        # Get server information
        results["server_info"] = self.get_server_info(connection)

        # TESTFR - verify connection is active
        results["test_command"] = self._send_test_command(client, conn)

        # Wait briefly for server to reveal its common address via spontaneous data
        if not self._ca_explicit:
            for _ in range(10):
                with self._lock:
                    if self._discovered_stations:
                        break
                time.sleep(0.1)

        # Listen/Monitor mode (--listen / -L)
        if self.listen_mode:
            results["listen_mode"] = self._run_listen_mode(client, conn)
            if not (
                self.interrogate or self.probe_files or self.test_commands or self.fuzz_enabled
            ):
                return results

        # General interrogation (--interrogate / -I or --full)
        if self.interrogate:
            results["interrogation"] = self._perform_interrogation(client, conn)

        # Group interrogation (--interrogate-groups / -G)
        if self.interrogate_groups:
            results["group_interrogation"] = self._group_interrogation(client, conn)

        # Station scan (--station-scan / -S)
        if self.station_scan:
            results["station_scan"] = self._station_scan(client, conn)

        # Targeted IOA reads (--read-ioa / -R)
        if self.read_ioas:
            results["read_ioas"] = self._read_ioas(client, conn)

        # Counter interrogation (--counter-interrogation)
        if self.counter_interrogation:
            results["counter_interrogation"] = self._counter_interrogation(client, conn)

        # Clock read (--clock-read) -- despite the name this issues a
        # C_CS_NA_1 (Type 103) which OVERWRITES the outstation clock and
        # pollutes the SOE log. Gated on --confirm per safety-default
        # policy.
        if self.clock_read:
            if not self.args.get("confirm", False):
                reason = "--clock-read issues a clock-sync write (C_CS_NA_1) — requires --confirm"
                self.logger.fail(reason)
                # Record it. This is one phase of a larger scan, so the scan's
                # overall success still reflects the other phases — but a refusal
                # that leaves no trace in results is indistinguishable downstream
                # from "we read the clock and found nothing".
                results["clock"] = {"refused": reason}
            else:
                results["clock"] = self._read_clock(client, conn)

        # File transfer capability reporting (Type IDs 120-127 seen during
        # interrogation). c104 exposes no high-level file-transfer API, so we
        # only report whether the outstation advertises file-transfer type IDs;
        # we do not attempt the (unimplemented) F_* ASDU exchange.
        if self.probe_files:
            results["file_transfer"] = self._report_file_transfer()

        # Custom type probing (Type IDs 128-255)
        if self.probe_custom_types:
            results["custom_type_probe"] = self._probe_custom_types(client, conn)

        # Command fuzzing
        if self.fuzz_enabled:
            results["commands"] = self._fuzz_commands(client, conn)

        # Command-execution test (--test-commands): probe whether the outstation
        # accepts unauthenticated control commands.
        if self.test_commands:
            results["command_test"] = self._test_commands(client, conn)

        # Write operations (explicit value writes)
        if self._has_write_operation():
            results["write_operation"] = self._write_value(client, conn)

        # Reset process command (--reset-process)
        if self.reset_process:
            results["reset_process"] = self._reset_process(client, conn)

        # Parameter operations (--param-normalized, --param-scaled, --param-float, --param-activate)
        if self._has_param_operation():
            results["param_operation"] = self._write_parameter(client, conn)

        # Attach any unexpected messages collected during the scan
        with self._lock:
            if self._unexpected_messages:
                results["unexpected_messages"] = list(self._unexpected_messages)
            if self._command_responses:
                results["command_responses"] = list(self._command_responses)

        # Compile discovered data (only when interrogation was performed)
        if self.interrogate:
            with self._lock:
                results["data_points"] = dict(self._discovered_points)
                results["type_ids"] = self._compile_type_info()

            # Security analysis
            results["security_analysis"] = self._analyze_security(results)

            # Report findings
            self._report_findings(results)

        return results

    # =========================================================================
    # Discovery Helpers
    # =========================================================================

    def get_server_info(self, connection: Any) -> Dict[str, Any]:
        """Get server information"""
        info = {
            "host": self.host,
            "port": self.port,
            "connected": True,
            "protocol": "IEC 60870-5-104",
            "timestamp": datetime.now().isoformat(),
        }

        if isinstance(connection, tuple):
            client, conn = connection
            info["connection_state"] = str(conn.state) if hasattr(conn, "state") else "connected"

        if self._init_cause is not None:
            info["init_cause"] = self._init_cause
        if self._connection_state is not None:
            info["connection_state_tracked"] = self._connection_state

        return info

    def _perform_interrogation(self, client: Any, conn: Any) -> Dict[str, Any]:
        """Perform general interrogation and collect type IDs"""
        self.logger.display("Performing general interrogation...")

        try:
            conn.interrogation(common_address=self._interrogation_ca())

            self.logger.debug(f"Waiting {self.wait_time}s for interrogation response...")
            time.sleep(self.wait_time)

            with self._lock:
                result = {
                    "command_sent": True,
                    "stations_discovered": len(self._discovered_stations),
                    "points_discovered": len(self._discovered_points),
                    "types_discovered": list(self._discovered_types),
                    "raw_type_ids": sorted(self._raw_type_ids),
                    "custom_type_ids": sorted(self._custom_type_ids),
                    "timestamp": datetime.now().isoformat(),
                }

            self.logger.display(
                f"Discovered {result['points_discovered']} points, "
                f"{len(result['types_discovered'])} type IDs"
            )

            return result

        except Exception as e:
            self.logger.fail(f"Interrogation error: {e}")
            return {"error": str(e)}

    def _best_common_address(self) -> int:
        """Return the best common address: explicit user value > discovered > default."""
        with self._lock:
            discovered = self._discovered_stations
        if self._ca_explicit:
            return self.common_address
        if discovered:
            ca = min(discovered)
            if ca != self.common_address:
                self.logger.debug(f"Using discovered CA={ca} (default was {self.common_address})")
            return ca
        return self.common_address

    def _interrogation_ca(self) -> int:
        """Return CA for interrogation: explicit > discovered > 0 (wildcard/broadcast).

        Unlike _best_common_address(), defaults to CA=0 when no explicit CA is set
        and no stations have been discovered. CA=0 addresses all stations at once,
        which is appropriate for interrogation but not for targeted operations.
        """
        with self._lock:
            discovered = self._discovered_stations
        if self._ca_explicit:
            return self.common_address
        if discovered:
            return min(discovered)
        return 0

    def _group_interrogation(self, client: Any, conn: Any) -> Dict[str, Any]:
        """Perform group interrogation (Qoi.GROUP_1..16) to map point-to-group layout."""
        c104 = _deps._get_c104()
        self.logger.display("Performing group interrogation (groups 1-16)...")

        ca = self._interrogation_ca()
        group_map: Dict[str, List[int]] = {}

        for group_num in range(1, 17):
            qoi_name = f"GROUP_{group_num}"
            qoi = getattr(c104.Qoi, qoi_name, None)
            if qoi is None:
                continue

            with self._lock:
                points_before = set(self._discovered_points.keys())

            try:
                conn.interrogation(common_address=ca, qualifier=qoi)
                time.sleep(self.wait_time)
            except Exception as e:
                self.logger.debug(f"Group {group_num} interrogation error: {e}")
                continue

            with self._lock:
                new_ioas = sorted(set(self._discovered_points.keys()) - points_before)

            if new_ioas:
                group_map[f"group_{group_num}"] = new_ioas
                self.logger.display(f"  Group {group_num}: {len(new_ioas)} point(s)")

        if not group_map:
            self.logger.display("No group-specific points discovered")

        return {"groups": group_map, "total_groups_with_points": len(group_map)}

    def _station_scan(self, client: Any, conn: Any) -> Dict[str, Any]:
        """Scan a range of Common Addresses to find active stations.

        Sends C_IC_NA_1 (interrogation) to each CA; servers respond with
        UNKNOWN_CA for non-existent stations.  Active stations are those
        that do NOT trigger UNKNOWN_CA.
        """
        from ...utils.protocol_helpers import ProgressTracker

        ca_start = self.ca_scan_start
        ca_end = self.ca_scan_end
        total = ca_end - ca_start + 1
        probe_wait = max(0.15, self.wait_time / 6)

        self.logger.display(f"Station scan: probing CA {ca_start}-{ca_end} ({total} addresses)...")

        tracker = ProgressTracker(total=total, threshold=1.0, interval=0.5, logger=self.logger)
        rejected_cas: Set[int] = set()  # UNKNOWN_CA received
        error_cas: Set[int] = set()  # interrogation exception

        for ca in range(ca_start, ca_end + 1):
            with self._lock:
                resp_idx = len(self._command_responses)
                unex_idx = len(self._unexpected_messages)

            # Ensure station is registered so c104 doesn't auto-reject
            try:
                station = conn.get_station(ca)
                if station is None:
                    conn.add_station(common_address=ca)
            except Exception as e:
                self.logger.debug(f"Failed to get station: {e}")

            try:
                conn.interrogation(common_address=ca)
            except Exception as e:
                self.logger.debug(f"Station scan CA={ca} interrogation error: {e}")
                error_cas.add(ca)
                tracker.add_failed()
                continue

            time.sleep(probe_wait)

            # Check command responses first (protocol-level rejections)
            error = self._has_error_response(common_address=ca, since_index=resp_idx)
            if error:
                rejected_cas.add(ca)
                self.logger.debug(
                    f"CA={ca} rejected: {error['cot']}"
                    + (" [negative]" if error["is_negative"] else "")
                )
            else:
                # Fallback: c104-level UNKNOWN_CA (for servers where response
                # bypasses on_receive_raw)
                with self._lock:
                    for msg in self._unexpected_messages[unex_idx:]:
                        if msg.get("cause") == "UNKNOWN_CA" and msg.get("common_address") == ca:
                            rejected_cas.add(ca)
                            break

            tracker.update()

        tracker.finish()

        # Classify: active = got data points; rejected = UNKNOWN_CA; else no_response
        active_cas: List[int] = []
        inactive_cas: List[int] = []
        no_response_cas: List[int] = []
        ca_details: Dict[int, Dict[str, Any]] = {}

        with self._lock:
            for ca in range(ca_start, ca_end + 1):
                if ca in error_cas or ca in rejected_cas:
                    inactive_cas.append(ca)
                    ca_details[ca] = {"status": "rejected", "points": 0, "type_ids": []}
                    continue

                points = [
                    ioa for ioa, pt in self._discovered_points.items() if pt.get("station_ca") == ca
                ]
                type_ids = sorted(
                    {
                        self._discovered_points[ioa].get("type_id")
                        for ioa in points
                        if self._discovered_points[ioa].get("type_id") is not None
                    }
                )

                if points:
                    active_cas.append(ca)
                    self._discovered_stations.add(ca)
                    ca_details[ca] = {
                        "status": "active",
                        "points": len(points),
                        "type_ids": type_ids,
                    }
                else:
                    no_response_cas.append(ca)
                    ca_details[ca] = {"status": "no_response", "points": 0, "type_ids": []}

            inactive_cas.extend(no_response_cas)
            self._station_scan_results = ca_details

        nr_note = f" ({len(no_response_cas)} no response)" if no_response_cas else ""
        self.logger.display(
            f"Station scan complete: {len(active_cas)} active, "
            f"{len(inactive_cas)} inactive{nr_note}"
        )

        self._report_station_scan(ca_details)

        return {
            "active": active_cas,
            "inactive_count": len(inactive_cas),
            "no_response_count": len(no_response_cas),
            "rejected_count": len(rejected_cas),
            "total_probed": total,
            "details": ca_details,
        }

    def _report_station_scan(self, ca_details: Dict[int, Dict[str, Any]]) -> None:
        """Print a table of active stations found during station scan."""
        from ...utils.export_utils import export_table, configure as configure_export

        configure_export(logger=self.logger, output_dir=self.output_dir, full_width=self.full_width)
        headers = ["CA", "Status", "Points", "Type IDs"]
        rows = []
        for ca in sorted(ca_details):
            info = ca_details[ca]
            type_strs = [str(t) for t in info.get("type_ids", [])]
            rows.append(
                [
                    ca,
                    info.get("status", "active"),
                    info.get("points", 0),
                    ", ".join(type_strs) if type_strs else "-",
                ]
            )

        export_table(
            f"iec104_stations_{self.host.replace('.', '_')}",
            headers,
            rows,
            title="[IEC 104 Station Scan]",
        )

    def _send_test_command(self, client: Any, conn: Any) -> Dict[str, Any]:
        """Verify TESTFR - connection is OPEN means STARTDT/TESTFR succeeded"""
        connected = conn.is_connected
        result: Dict[str, Any] = {"success": connected}
        if connected:
            self.logger.debug("TESTFR: OK (connection active)")
        else:
            self.logger.warning("TESTFR: connection not active")

        return result

    def _read_ioas(self, client: Any, conn: Any) -> Dict[str, Any]:
        """Read specific IOAs via C_RD_NA_1 (Type 102) using point.read()"""
        c104 = _deps._get_c104()
        results: Dict[str, Any] = {
            "ioas_requested": self.read_ioas,
            "responses": [],
            "errors": [],
        }

        # If no explicit CA, wait briefly for server to reveal its CA
        if not self._ca_explicit:
            for _ in range(10):
                with self._lock:
                    if self._discovered_stations:
                        break
                time.sleep(0.1)

        requested_ca = self._best_common_address()

        station = conn.get_station(requested_ca)
        if station is None:
            station = conn.add_station(common_address=requested_ca)
        if station is None:
            self.logger.fail(f"Cannot create station CA={requested_ca} for read")
            results["errors"].append({"error": "Station creation failed"})
            return results

        self.logger.display(f"Reading {len(self.read_ioas)} IOA(s)...")

        for ioa in self.read_ioas:
            try:
                point = station.add_point(io_address=ioa, type=c104.Type.M_SP_NA_1)
                if point is None:
                    point = station.get_point(ioa)
                if point and point.read():
                    time.sleep(0.1)
                else:
                    results["errors"].append({"ioa": ioa, "error": "read() rejected"})
            except Exception as e:
                self.logger.fail(f"  IOA {ioa}: {e}")
                results["errors"].append({"ioa": ioa, "error": str(e)})

        # Poll until all IOAs have responses from the REQUESTED CA
        # (not C_RD_NA_1 echo, and not spontaneous data from a different CA)
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            with self._lock:
                if all(
                    ioa in self._discovered_points
                    and self._discovered_points[ioa].get("type_id") != 102
                    and self._discovered_points[ioa].get("station_ca") == requested_ca
                    for ioa in self.read_ioas
                ):
                    break
            time.sleep(0.1)

        # Gather results and display (collect under lock, display outside)
        results = self._collect_read_results(results, requested_ca)

        return results

    def _has_unknown_ca_error(self) -> bool:
        """Check if an UNKNOWN_CA error was received during this session."""
        with self._lock:
            return any(msg.get("cause") == "UNKNOWN_CA" for msg in self._unexpected_messages)

    def _has_error_response(self, *, common_address=None, since_index=0):
        """Check for error COT or negative confirmation in command responses."""
        with self._lock:
            responses = self._command_responses[since_index:]
        for r in responses:
            if common_address is not None and r["common_address"] != common_address:
                continue
            if r.get("is_negative") or r["cot"] in (
                "UNKNOWN_TYPE_ID",
                "UNKNOWN_COT",
                "UNKNOWN_CA",
                "UNKNOWN_IOA",
            ):
                return r
        return None

    def _collect_read_results(self, results: Dict[str, Any], requested_ca: int) -> Dict[str, Any]:
        """Collect read results and display them, distinguishing real responses
        from spontaneous data from a different CA."""
        # Gather data under lock
        collected = []
        with self._lock:
            for ioa in self.read_ioas:
                point = self._discovered_points.get(ioa)
                collected.append((ioa, dict(point) if point else None))

        unknown_ca_error = self._has_unknown_ca_error()

        for ioa, point in collected:
            if point and point.get("station_ca") == requested_ca and point.get("type_id") != 102:
                # Actual read response from the correct CA
                results["responses"].append(point)
                type_name = point.get("type", "?")
                val = point.get("value")
                cot = point.get("cot", "")
                val_str = f" = {val}" if val is not None else ""
                cot_str = f" COT={cot}" if cot else ""
                self.logger.success(f"IOA {ioa}: {type_name}{val_str} (CA={requested_ca}{cot_str})")
            elif point and point.get("station_ca") != requested_ca:
                # Spontaneous data from a different CA — not our read response
                if unknown_ca_error:
                    self.logger.fail(
                        f"IOA {ioa}: Read to CA={requested_ca} rejected (Unknown Common Address)"
                    )
                    results["errors"].append({"ioa": ioa, "error": f"Unknown CA={requested_ca}"})
            else:
                # No data at all (or only C_RD_NA_1 echo)
                if unknown_ca_error:
                    self.logger.fail(
                        f"IOA {ioa}: Read to CA={requested_ca} rejected (Unknown Common Address)"
                    )
                    results["errors"].append({"ioa": ioa, "error": f"Unknown CA={requested_ca}"})
                else:
                    self.logger.fail(f"IOA {ioa}: No response")
                    results["errors"].append({"ioa": ioa, "error": "No response"})

        return results

    def _counter_interrogation(self, client: Any, conn: Any) -> Dict[str, Any]:
        """Perform counter interrogation (Type 101, C_CI_NA_1)"""
        self.logger.display("Performing counter interrogation...")

        with self._lock:
            points_before = set(self._discovered_points.keys())

        try:
            conn.counter_interrogation(common_address=self._best_common_address())
            time.sleep(self.wait_time)
        except Exception as e:
            self.logger.fail(f"Counter interrogation error: {e}")
            return {"error": str(e)}

        with self._lock:
            new_points = set(self._discovered_points.keys()) - points_before
            result: Dict[str, Any] = {
                "command_sent": True,
                "new_points": len(new_points),
                "counter_types": sorted(
                    tid
                    for tid in self._raw_type_ids
                    if tid in range(COUNTER_TYPE_ID_START, COUNTER_TYPE_ID_END + 1)
                ),
            }

        self.logger.display(f"Counter interrogation: {result['new_points']} counter points")
        return result

    @staticmethod
    def _parse_cp56time2a(buf: bytes) -> Optional[datetime]:
        """Parse 7-byte CP56Time2a into a datetime."""
        if len(buf) < CP56TIME2A_SIZE:
            return None
        ms = struct.unpack_from("<H", buf, 0)[0]
        minute = buf[2] & CP56TIME2A_MINUTE_MASK
        hour = buf[3] & CP56TIME2A_HOUR_MASK
        day = buf[4] & CP56TIME2A_DAY_MASK
        month = buf[5] & CP56TIME2A_MONTH_MASK
        year = CP56TIME2A_BASE_YEAR + (buf[6] & CP56TIME2A_YEAR_MASK)
        sec, ms_rem = divmod(ms, 1000)
        try:
            return datetime(year, month, day, hour, minute, sec, ms_rem * 1000)
        except ValueError:
            return None

    def _read_clock(self, client: Any, conn: Any) -> Dict[str, Any]:
        """Read device clock via clock sync (Type 103, C_CS_NA_1)"""
        self.logger.display("Reading device clock...")
        try:
            with self._lock:
                self._clock_sync_raw = None

            ok = conn.clock_sync(common_address=self._best_common_address())
            if not ok:
                state = getattr(conn, "state", "unknown")
                self.logger.fail(f"Clock sync failed (state: {state})")
                return {"success": False, "error": f"Clock sync failed (state: {state})"}

            # clock_sync(wait_for_response=True) blocks until actcon,
            # but the raw callback may fire on a different thread — brief wait
            time.sleep(0.1)

            with self._lock:
                raw = self._clock_sync_raw

            result: Dict[str, Any] = {"success": True}

            if raw and len(raw) >= 22:
                # APCI(6) + TI(1) + VSQ(1) + COT(2) + CA(2) + IOA(3) + CP56Time2a(7)
                cp56 = raw[15:22]
                device_dt = self._parse_cp56time2a(cp56)
                is_negative = bool(raw[ASDU_COT_OFFSET] & COT_NEGATIVE_BIT)

                if is_negative:
                    self.logger.warning("Device rejected clock sync (negative confirmation)")
                    result["negative"] = True
                    result["success"] = False
                elif device_dt:
                    self.logger.success(
                        f"Device clock: {device_dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}"
                    )
                    result["device_time"] = device_dt.isoformat()
                else:
                    self.logger.success("Clock sync acknowledged")
            else:
                self.logger.success("Clock sync sent (no response captured)")

            return result
        except Exception as e:
            self.logger.fail(f"Clock sync error: {e}")
            return {"success": False, "error": str(e)}

    def _probe_custom_types(self, client: Any, conn: Any) -> Dict[str, Any]:
        """Probe for custom/vendor-specific Type IDs (128-255)"""
        c104 = _deps._get_c104()
        self.logger.display("Probing for custom Type IDs (128-255)...")

        result = {
            "probed": True,
            "custom_types_found": [],
            "unexpected_messages": [],
            "responses": [],
            "errors": [],
        }

        with self._lock:
            types_before = set(self._raw_type_ids)
            unexpected_before = len(self._unexpected_messages)

        ca = self._best_common_address()
        station = conn.get_station(ca)
        if station is None:
            station = conn.add_station(common_address=ca)

        probe_ioas = [0, 1, 100, 1000, 10000, 65535]

        for ioa in probe_ioas:
            try:
                if station:
                    point = station.add_point(io_address=ioa, type=c104.Type.M_SP_NA_1)
                    if point is None:
                        point = station.get_point(ioa)
                    if point:
                        point.read()
                        time.sleep(0.1)
            except Exception as e:
                self.logger.debug(f"Probe IOA={ioa} error: {e}")
                result["errors"].append({"ioa": ioa, "error": str(e)})

        time.sleep(self.wait_time)

        with self._lock:
            types_after = set(self._raw_type_ids)
            new_types = types_after - types_before

            for tid in new_types:
                if tid not in IEC104_TYPE_IDS:
                    result["custom_types_found"].append(
                        {
                            "type_id": tid,
                            "hex": f"0x{tid:02X}",
                            "description": "Vendor-specific/custom type",
                        }
                    )
                    self.logger.success(f"Discovered custom Type ID: {tid} (0x{tid:02X})")

            for tid in sorted(self._custom_type_ids):
                if tid not in [t["type_id"] for t in result["custom_types_found"]]:
                    result["custom_types_found"].append(
                        {
                            "type_id": tid,
                            "hex": f"0x{tid:02X}",
                            "description": "Vendor-specific/custom type",
                        }
                    )

            new_unexpected = self._unexpected_messages[unexpected_before:]
            if new_unexpected:
                result["unexpected_messages"] = list(new_unexpected)

        if new_unexpected:
            for msg in new_unexpected:
                self.logger.display(
                    f"  Server rejected: {msg['cause']} "
                    f"Type={msg['type']} CA={msg['common_address']} IOA={msg['io_address']}"
                )

        if result["custom_types_found"]:
            self.logger.warning(f"Found {len(result['custom_types_found'])} custom Type ID(s)")
        else:
            self.logger.display("No custom Type IDs detected")

        return result

    # =========================================================================
    # Analysis & Reporting
    # =========================================================================

    def _report_file_transfer(self) -> Dict[str, Any]:
        """Report file-transfer capability based on type IDs (120-127) observed
        during interrogation. c104 has no high-level file-transfer API, so this
        is detection only — no F_* ASDU exchange is performed."""
        self.logger.display("Checking file-transfer capability (Type IDs 120-127)...")
        result: Dict[str, Any] = {"supported": False, "type_ids_found": [], "files": []}

        with self._lock:
            supported = self._file_transfer_supported
            file_types = sorted(
                tid
                for tid in self._raw_type_ids
                if FILE_TRANSFER_TYPE_ID_START <= tid <= FILE_TRANSFER_TYPE_ID_END
            )

        if supported or file_types:
            result["supported"] = True
            result["type_ids_found"] = file_types
            for tid in file_types:
                if tid in IEC104_TYPE_IDS:
                    result["files"].append(
                        {
                            "type_id": tid,
                            "name": IEC104_TYPE_IDS[tid][0],
                            "description": IEC104_TYPE_IDS[tid][1],
                        }
                    )
            self.logger.security_finding(
                "File transfer exposed",
                detail="Server advertises file-transfer type IDs (120-127)",
            )
        else:
            self.logger.display("No file-transfer type IDs detected")

        return result

    def _compile_type_info(self) -> Dict[str, Any]:
        """Compile discovered type ID information"""
        type_info = {
            "standard_types": {},
            "custom_types": [],
            "file_transfer_types": [],
            "summary": {},
        }

        type_counts = {}
        for point in self._discovered_points.values():
            t = point.get("type", "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1

        for tid in self._raw_type_ids:
            if tid in IEC104_TYPE_IDS:
                name, desc = IEC104_TYPE_IDS[tid]
                type_info["standard_types"][tid] = {
                    "name": name,
                    "description": desc,
                    "count": type_counts.get(name, 0),
                }
                if FILE_TRANSFER_TYPE_ID_START <= tid <= FILE_TRANSFER_TYPE_ID_END:
                    type_info["file_transfer_types"].append(
                        {"type_id": tid, "name": name, "description": desc}
                    )
            else:
                type_info["custom_types"].append(
                    {
                        "type_id": tid,
                        "name": f"CUSTOM_{tid}",
                        "description": "Non-standard/vendor-specific type",
                    }
                )

        type_info["summary"] = {
            "total_types": len(self._raw_type_ids),
            "standard_types": len([t for t in self._raw_type_ids if t in IEC104_TYPE_IDS]),
            "custom_types": len(self._custom_type_ids),
            "file_transfer": len(
                [
                    t
                    for t in self._raw_type_ids
                    if FILE_TRANSFER_TYPE_ID_START <= t <= FILE_TRANSFER_TYPE_ID_END
                ]
            ),
        }

        return type_info

    def _analyze_security(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze IEC 104 security based on discovered capabilities"""
        analysis = {
            "authentication": False,
            "encryption": False,
            "access_control": False,
            "issues": [],
            "risk_level": "medium",
        }

        if self.use_tls:
            analysis["encryption"] = True
            analysis["issues"].append("TLS enabled (IEC 62351-3)")

        file_info = results.get("file_transfer", {})
        if file_info.get("supported"):
            # The "File transfer exposed" security_finding is already emitted by
            # _report_file_transfer() for this exact condition; don't emit a
            # second "Writable access" finding for the same thing (double-count).
            # Still record it in the analysis issues/risk summary.
            analysis["issues"].append("File transfer capability exposed (Type IDs 120-127)")
            analysis["risk_level"] = "high"

        type_info = results.get("type_ids", {})
        custom_count = type_info.get("summary", {}).get("custom_types", 0)
        if custom_count > 0:
            self.logger.security_finding(
                "Insecure configuration",
                detail=f"{custom_count} custom/vendor-specific type IDs detected - potential proprietary extensions",
            )
            analysis["issues"].append(f"{custom_count} custom/vendor-specific type IDs detected")

        points_count = len(results.get("data_points", {}))
        if points_count > 100:
            self.logger.security_finding(
                "Anonymous access allowed",
                detail=f"{points_count} data points accessible without authentication",
            )
            analysis["issues"].append(f"{points_count} data points accessible without auth")

        assessment = SecurityAnalyzer.assess_protocol_security(
            {
                "authentication": False,
                "authorization": False,
                "encryption": self.use_tls,
                "integrity_check": self.use_tls,
                "access_control": False,
            }
        )
        # assess_protocol_security() returns its own generic "issues" list
        # (e.g. "Missing authentication"); merging it in with dict.update()
        # would otherwise clobber the IEC104-specific findings (file
        # transfer, custom types, unauth access) collected above. Pop it
        # off and append instead so both sets of findings survive.
        generic_issues = assessment.pop("issues", [])
        analysis.update(assessment)
        analysis["issues"].extend(generic_issues)

        return analysis

    def _report_findings(self, results: Dict[str, Any]):
        """Report detailed scan findings"""
        data_points = results.get("data_points", {})
        type_info = results.get("type_ids", {})
        file_transfer = results.get("file_transfer", {})

        self.report_host_info(self.host, server_type="IEC 104")

        service_info = {
            "name": "iec104",
            "product": "IEC 60870-5-104 Server",
            "data_points": len(data_points),
            "type_ids": type_info.get("summary", {}).get("total_types", 0),
            "custom_types": type_info.get("summary", {}).get("custom_types", 0),
            "file_transfer": file_transfer.get("supported", False),
        }
        self.report_service_info(self.host, port=self.port, **service_info)

        if data_points:
            from ...utils.export_utils import export_table, configure as configure_export

            configure_export(
                logger=self.logger, output_dir=self.output_dir, full_width=self.full_width
            )
            headers = ["IOA", "Type ID", "Type", "Description", "Station CA"]
            rows = []
            for ioa, pt in sorted(data_points.items()):
                tid = pt.get("type_id")
                type_info_entry = IEC104_TYPE_IDS.get(tid, ("", ""))
                short_name = type_info_entry[0] if type_info_entry[0] else pt.get("type", "")
                desc = type_info_entry[1] if len(type_info_entry) > 1 else ""
                rows.append(
                    [
                        ioa,
                        tid if tid is not None else "?",
                        short_name,
                        desc,
                        pt.get("station_ca", ""),
                    ]
                )
            export_table(
                f"iec104_points_{self.host.replace('.', '_')}",
                headers,
                rows,
                title="[IEC 104 Discovered Points]",
            )

        if data_points or file_transfer.get("supported"):
            type_summary = type_info.get("summary", {})
            self.logger.display(
                f"IEC 104 scan complete: {len(data_points)} points, "
                f"{type_summary.get('total_types', 0)} types "
                f"({type_summary.get('custom_types', 0)} custom), "
                f"file transfer: {'YES' if file_transfer.get('supported') else 'no'}"
            )


# Create metadata and run function using protocol module factory
metadata, run = create_protocol_module(
    IEC104Scanner, dependencies_check_func=lambda: not _deps._c104.is_available
)


if __name__ == "__main__":
    # Standalone mode
    cli_run(metadata, run)

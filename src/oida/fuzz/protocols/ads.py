"""ADS Protocol Fuzzer

ADS (Automation Device Specification) is the communication protocol used by
Beckhoff TwinCAT PLCs. It runs over TCP port 48898.

Protocol structure:
- AMS/TCP Header: Reserved (2 bytes) + Length (4 bytes, little-endian)
- AMS Header: 32 bytes containing routing and command info
- ADS Data: Command-specific payload

All multi-byte fields are little-endian.

Security Notes:
- CVE-2019-16871 (CVSS 9.3): Remote Code Execution via ADS protocol route manipulation
- CVE-2024-41176: Buffer overflow via crafted input in TwinCAT/BSD
- ADS has no built-in encryption/authentication - relies on network isolation
"""

import struct
from typing import List

from boofuzz import Block, DWord, Group, Request, Size, Static, Word

from ..primitives.dynamic import DynamicDWord, SmartString, StringContext

from ..core.base_fuzzer import BaseFuzzer, CommonState, RequestInfo
from ..core.config import FuzzerConfig
from ..core.connections import TCPSocketConnection
from ..core.session.state_context import StateContext
from ..core.session.sequence import SequenceConfig, SequenceDirection
from ..core.session.state_machine import ProtocolState, StateMachine, StateType

import logging

logger = logging.getLogger(__name__)


# ADS Command IDs
class ADSCommandIDs:
    """ADS command identifiers"""

    READ_DEVICE_INFO = 0x0001
    READ = 0x0002
    WRITE = 0x0003
    READ_STATE = 0x0004
    WRITE_CONTROL = 0x0005
    ADD_NOTIFICATION = 0x0006
    DEL_NOTIFICATION = 0x0007
    DEVICE_NOTIFICATION = 0x0008
    READ_WRITE = 0x0009

    # All command IDs for quick coverage
    ALL_COMMANDS = [
        READ_DEVICE_INFO,
        READ,
        WRITE,
        READ_STATE,
        WRITE_CONTROL,
        ADD_NOTIFICATION,
        DEL_NOTIFICATION,
        DEVICE_NOTIFICATION,
        READ_WRITE,
    ]


# Index Group constants for memory access
class ADSIndexGroups:
    """ADS Index Group constants"""

    SYM_HNDBYNAME = 0x0000F003  # Get handle by name
    SYM_VALBYNAME = 0x0000F004  # Value by name
    SYM_VALBYHND = 0x0000F005  # Value by handle
    SYM_RELEASEHND = 0x0000F006  # Release handle
    SYM_INFOBYNAMEEX = 0x0000F009  # Extended info by name
    SYM_UPLOADINFO2 = 0x0000F00F  # Upload info
    SYM_UPLOAD = 0x0000F00B  # Upload symbols
    MEMORYBYTE = 0x00004020  # Memory byte area (%MB)
    DATA = 0x00004040  # Data area
    IOIMAGE_RWIB = 0x0000F020  # Input image byte (%IB)
    IOIMAGE_RWOB = 0x0000F030  # Output image byte (%QB)
    PLCADS_IGRP_SYM_IDXO = 0x0000F014  # Symbol index offset
    AMS_ROUTER = 0x00000001  # AMS Router (CVE target)
    SUMUP_READ = 0x0000F080  # Beckhoff SumUp Read (batch)
    SUMUP_WRITE = 0x0000F081  # Beckhoff SumUp Write (batch)
    SUMUP_READWRITE = 0x0000F082  # Beckhoff SumUp ReadWrite (batch)


# ADS State values for WRITE_CONTROL
class ADSStates:
    """ADS/device state values"""

    INVALID = 0
    IDLE = 1
    RESET = 2
    INIT = 3
    START = 4
    RUN = 5
    STOP = 6
    SAVECFG = 7
    LOADCFG = 8
    POWERFAILURE = 9
    POWERGOOD = 10
    ERROR = 11
    SHUTDOWN = 12
    SUSPEND = 13
    RESUME = 14
    CONFIG = 15
    RECONFIG = 16


def _netid_to_bytes(netid_str: str) -> bytes:
    """Convert dotted AMS NetId string (e.g. '192.168.1.1.1.1') to 6 bytes."""
    parts = netid_str.split(".")
    if len(parts) != 6:
        return b"\x7f\x00\x00\x01\x01\x01"
    return bytes(int(p) for p in parts)


class ADSMonitor:
    """ADS health monitor — sends READ_STATE and promotes ADS error codes to crash events.

    Lazy-loaded subclass of ProtocolMonitor so we don't pull boofuzz/monitors at
    module import time. Sends ADS READ_STATE (cmd 0x0004) and inspects the
    AMS error_code field. Any non-zero AMS error (e.g. 0x70A = device port not
    found, 0x6 = target port not found) is treated as a failed health check and
    routed through the standard crash-tracker. Audit S6.
    """

    def __new__(
        cls,
        host: str,
        target_netid: bytes,
        source_netid: bytes,
        target_ams_port: int = 851,
        source_ams_port: int = 32768,
        port: int = 48898,
        timeout: float = 2.0,
        check_interval: int = 10,
        retry_count: int = 2,
        failure_threshold: int = 2,
    ):
        # Lazy-build the real class so boofuzz/monitor deps stay deferred.
        from ..monitors import ProtocolMonitor

        class _ADSMonitor(ProtocolMonitor):
            def __init__(
                self,
                host: str,
                port: int,
                target_netid: bytes,
                source_netid: bytes,
                target_ams_port: int,
                source_ams_port: int,
                timeout: float,
                check_interval: int,
                retry_count: int,
                failure_threshold: int,
            ):
                super().__init__(
                    host=host,
                    port=port,
                    timeout=timeout,
                    check_interval=check_interval,
                    retry_count=retry_count,
                    failure_threshold=failure_threshold,
                )
                self._target_netid = target_netid
                self._source_netid = source_netid
                self._target_ams_port = target_ams_port
                self._source_ams_port = source_ams_port

            def _build_read_state(self) -> bytes:
                ams_header = (
                    self._target_netid
                    + struct.pack("<H", self._target_ams_port)
                    + self._source_netid
                    + struct.pack("<H", self._source_ams_port)
                    + struct.pack("<H", ADSCommandIDs.READ_STATE)
                    + struct.pack("<H", 0x0004)
                    + struct.pack("<I", 0)
                    + struct.pack("<I", 0)
                    + struct.pack("<I", 1)
                )
                tcp_header = struct.pack("<HI", 0, len(ams_header))
                return tcp_header + ams_header

            def _check_alive_once(self, fuzz_data_logger=None) -> bool:
                import socket as _socket

                sock = None
                try:
                    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    sock.connect((self.host, self.port))
                    sock.send(self._build_read_state())
                    response = sock.recv(1024)
                    if len(response) < 6 + 32:
                        if fuzz_data_logger:
                            fuzz_data_logger.log_fail(
                                f"ADSMonitor: short response ({len(response)} bytes)"
                            )
                        return False
                    # AMS error_code at offset 6 (TCP header) + 24 (within AMS header)
                    error_code = struct.unpack_from("<I", response, 6 + 24)[0]
                    if error_code != 0:
                        # 0x70A = ROUTERERR_NOLOCKEDMEMORY, 0x06 = target port unknown, etc.
                        if fuzz_data_logger:
                            fuzz_data_logger.log_fail(
                                f"ADSMonitor: ADS error code 0x{error_code:X}"
                            )
                        return False
                    if not self.baseline_established:
                        self.baseline_response = response
                        self.baseline_established = True
                    return True
                except (TimeoutError, OSError) as e:
                    if fuzz_data_logger:
                        fuzz_data_logger.log_info(f"ADSMonitor: {e}")
                    return False
                finally:
                    if sock is not None:
                        try:
                            sock.close()
                        except OSError:
                            pass

        return _ADSMonitor(
            host=host,
            port=port,
            target_netid=target_netid,
            source_netid=source_netid,
            target_ams_port=target_ams_port,
            source_ams_port=source_ams_port,
            timeout=timeout,
            check_interval=check_interval,
            retry_count=retry_count,
            failure_threshold=failure_threshold,
        )


class ADSFuzzer(BaseFuzzer):
    """ADS (Beckhoff TwinCAT) Protocol Fuzzer for automation security testing

    Optimized for:
    - Maximum early coverage (all 9 command IDs in first 30 seconds)
    - High-crash tests early (overflow, boundary attacks)
    - CVE-targeted operations (WRITE_CONTROL, route manipulation)
    """

    PROTOCOL_OPTIONS = {
        "target_ams_netid": {
            "type": str,
            "default": "127.0.0.1.1.1",
            "description": "Target AMS NetId (e.g., 192.168.1.1.1.1)",
        },
        "target_ams_port": {
            "type": int,
            "default": 851,
            "description": "Target AMS Port (default 851 for TC3PLC1)",
        },
        "source_ams_netid": {
            "type": str,
            "default": "127.0.0.1.1.2",
            "description": "Source AMS NetId for client",
        },
        "source_ams_port": {
            "type": int,
            "default": 32768,
            "description": "Source AMS Port for client",
        },
        "enable_write": {
            "type": bool,
            "default": False,
            "description": "Enable write operations (risky for production devices)",
        },
        # ADS Authentication Options
        "ads_password": {
            "type": str,
            "default": "",
            "description": "ADS password for protected operations",
            "example": "password",
        },
        "route_password": {
            "type": str,
            "default": "",
            "description": "AMS route password for route manipulation",
            "example": "routepass",
        },
        "enable_auth": {
            "type": bool,
            "default": False,
            "description": "Enable ADS/AMS authentication fuzzing",
        },
    }

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests"""
        return [
            # Phase 1: Quick Coverage
            RequestInfo(
                "ADS_Quick_Coverage",
                "Quick sweep of all 9 ADS commands",
                "baseline",
                requires_state="CONNECTED",
            ),
            # Phase 2: High-Crash Tests
            RequestInfo(
                "ADS_Overflow",
                "AMS header and payload overflow attacks (CVE-2024-41176)",
                "attack",
                requires_state=CommonState.ANY,
            ),
            RequestInfo(
                "ADS_Boundary",
                "Field boundary testing (NetId, Port, Length)",
                "boundary",
                requires_state=CommonState.ANY,
            ),
            # Phase 3: CVE-Targeted Operations
            RequestInfo(
                "ADS_Write_Control",
                "State control attacks (CVE-2019-16871 pattern)",
                "write",
                requires_state="ADS_VALIDATED",
            ),
            RequestInfo(
                "ADS_Write",
                "Memory write operations",
                "write",
                requires_state="ADS_VALIDATED",
            ),
            RequestInfo(
                "ADS_Route",
                "AMS route manipulation (CVE-2019-16871)",
                "attack",
                requires_state="CONNECTED",
            ),
            # Phase 4: Symbol Operations
            RequestInfo(
                "ADS_Symbol",
                "Symbol handle and info operations",
                "read",
                requires_state="ADS_VALIDATED",
            ),
            # Phase 5: Standard Operations
            RequestInfo(
                "ADS_Read",
                "Read operations (device info, state, memory)",
                "read",
                requires_state="CONNECTED",
            ),
            RequestInfo(
                "ADS_Notification",
                "Notification add/delete operations",
                "read",
                requires_state="ADS_VALIDATED",
            ),
            # ADS Authentication
            RequestInfo(
                "ADS_Auth",
                "ADS/AMS password and route authentication fuzzing",
                "auth",
                requires_state="CONNECTED",
            ),
            # ADS Port enumeration + bulk-op coverage
            RequestInfo(
                "ADS_Port_Enumeration",
                "Cycle Beckhoff AMS logical ports (851 PLC, 350 SysSvc, ...)",
                "enumeration",
                requires_state="CONNECTED",
            ),
            RequestInfo(
                "ADS_SumReadWrite",
                "SumUp bulk-op with fuzzable sub-request count",
                "protocol",
                requires_state="CONNECTED",
            ),
        ]

    def __init__(self, config: FuzzerConfig, connection_factory=None):
        # State tracking for ADS validation
        self.device_validated = False
        self.device_name = ""
        self._invoke_id_counter = 1

        # StateContext for carrying state between transitions
        self._state_context = StateContext()

        # Sequence manager for invoke ID tracking
        seq_mgr = self._state_context.get_sequence_manager("ads")
        seq_mgr.add_sequence(
            SequenceConfig(
                name="invoke_id",
                initial=1,
                increment=1,
                max_value=0xFFFFFFFF,
                direction=SequenceDirection.SEND,
                wrap_behavior="modulo",
                fuzzable=True,
            )
        )

        if config.target_port == 0:
            config.target_port = 48898  # Default ADS port
        super().__init__(config, connection_factory)

    def _next_invoke_id(self) -> int:
        """Get current invoke ID and increment for next use."""
        seq_mgr = self._state_context.get_sequence_manager("ads")
        return seq_mgr.get_and_increment("invoke_id")

    def _create_socket(self):
        return TCPSocketConnection(
            self.config.target_ip,
            self.config.target_port,
            **self._timeout_overrides(recv_default=2.0, send_default=2.0),
        )

    def _define_state_machine(self) -> None:
        """Send READ_DEVICE_INFO to validate ADS target and build state machine.

        ADS/AMS protocol: sends command_id=0x0001 (READ_DEVICE_INFO) with
        state_flags=0x0004 (request). Parses response for major/minor version
        and device name to confirm valid ADS service.
        """
        import socket

        target_ip = self.config.target_ip
        target_port = self.config.target_port or 48898
        sock = None

        target_netid = _netid_to_bytes(self.config.get_option("target_ams_netid", "127.0.0.1.1.1"))
        source_netid = _netid_to_bytes(self.config.get_option("source_ams_netid", "127.0.0.1.1.2"))
        target_ams_port = self.config.get_option("target_ams_port", 851)
        source_ams_port = self.config.get_option("source_ams_port", 32768)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((target_ip, target_port))

            # Build AMS/TCP + AMS Header + READ_DEVICE_INFO request
            # AMS header: 32 bytes, no data payload for READ_DEVICE_INFO
            ams_header = (
                target_netid
                + struct.pack("<H", target_ams_port)
                + source_netid
                + struct.pack("<H", source_ams_port)
                + struct.pack("<H", ADSCommandIDs.READ_DEVICE_INFO)
                + struct.pack("<H", 0x0004)  # StateFlags: ADS request
                + struct.pack("<I", 0)  # Data length: 0
                + struct.pack("<I", 0)  # Error code
                + struct.pack("<I", 1)  # Invoke ID
            )
            # AMS/TCP header: reserved(2) + length(4)
            tcp_header = struct.pack("<HI", 0, len(ams_header))
            sock.send(tcp_header + ams_header)

            response = sock.recv(1024)

            # Parse AMS/TCP header (6 bytes) + AMS header (32 bytes) + data
            if len(response) >= 6 + 32 + 8:  # Minimum: headers + major/minor/name_len
                # Skip TCP header (6) + routing fields (20) + command/state (4)
                data_offset = 6 + 32  # Start of ADS data
                # Check error code in AMS header (offset 6+24 = 30)
                error_code = struct.unpack_from("<I", response, 6 + 24)[0]
                if error_code == 0 and len(response) >= data_offset + 8:
                    # ADS data for READ_DEVICE_INFO response:
                    # result(4) + major(1) + minor(1) + version_build(2) + device_name(16)
                    ads_result = struct.unpack_from("<I", response, data_offset)[0]
                    if ads_result == 0 and len(response) >= data_offset + 24:
                        major = response[data_offset + 4]
                        minor = response[data_offset + 5]
                        name_bytes = response[data_offset + 8 : data_offset + 24]
                        self.device_name = name_bytes.split(b"\x00")[0].decode(
                            "ascii", errors="replace"
                        )
                        self.device_validated = True
                        self._state_context.set("device_name", self.device_name)
                        self._state_context.set("device_version", f"{major}.{minor}")
                        self.log.display(
                            f"[ADS] Device validated: {self.device_name} v{major}.{minor}"
                        )
                    else:
                        self.log.warning(f"[ADS] READ_DEVICE_INFO result: 0x{ads_result:08X}")
                else:
                    self.log.warning(f"[ADS] AMS error: 0x{error_code:08X}")
            else:
                self.log.warning("[ADS] Response too short for READ_DEVICE_INFO")

        except socket.timeout:
            self.log.warning("[ADS] READ_DEVICE_INFO timed out, using defaults")
        except Exception as e:
            self.log.warning(f"[ADS] READ_DEVICE_INFO failed: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except Exception as e:
                    logger.debug(f"sock.close(): {e}")

        # Define state machine
        connected = ProtocolState(
            name="CONNECTED",
            state_type=StateType.CONNECTION,
            description="TCP connection established to AMS router",
        )
        ads_validated = ProtocolState(
            name="ADS_VALIDATED",
            validation=self._validate_device,
            requires=["CONNECTED"],
            description="ADS device info confirmed",
        )

        self.state_machine = StateMachine(
            initial_state=connected,
            states=[connected, ads_validated],
            context=self._state_context,
        )

        if self.device_validated:
            self.state_machine.transition_to("ADS_VALIDATED")

        self.log.display(
            f"[ADS] State machine initialized: {self.state_machine.get_current_state_name()}"
        )

    def _validate_device(self) -> bool:
        """Check if ADS device has been validated."""
        return self.device_validated

    def setup_custom_monitors(self) -> List:
        """Setup ADS-specific monitors.

        Pairs the generic SocketHealthMonitor with an ADS-aware ADSMonitor that
        sends READ_STATE and promotes AMS-level error codes (e.g. 0x70A) to
        crash events. Catches crashes that leave TCP alive but kill the ADS
        runtime. Audit S6.
        """
        from ..monitors import SocketHealthMonitor

        port = self.config.target_port or 48898
        target_netid = _netid_to_bytes(self.config.get_option("target_ams_netid", "127.0.0.1.1.1"))
        source_netid = _netid_to_bytes(self.config.get_option("source_ams_netid", "127.0.0.1.1.2"))
        target_ams_port = self.config.get_option("target_ams_port", 851)
        source_ams_port = self.config.get_option("source_ams_port", 32768)
        return [
            SocketHealthMonitor(
                host=self.config.target_ip,
                port=port,
                retry_count=3,
                timeout=2,
                failure_threshold=2,
            ),
            ADSMonitor(
                host=self.config.target_ip,
                port=port,
                target_netid=target_netid,
                source_netid=source_netid,
                target_ams_port=target_ams_port,
                source_ams_port=source_ams_port,
                timeout=2.0,
                check_interval=10,
                retry_count=2,
                failure_threshold=2,
            ),
        ]

    def _define_protocol(self) -> None:
        """Define optimized ADS protocol structure

        Optimization phases:
        - Phase 1: Quick Coverage (~30 sec) - All 9 command IDs once
        - Phase 2: High-Crash Tests (~3 min) - Overflow, boundary attacks
        - Phase 3: CVE-Targeted (~3 min) - WRITE_CONTROL, route manipulation
        - Phase 4: Symbol Operations (~2 min) - Handle/info operations
        - Phase 5: Standard Tests (~remaining) - Reads, notifications
        """

        # ============================================================
        # RESOLVE AMS NETID FROM CONFIG
        # ============================================================
        target_netid = _netid_to_bytes(self.config.get_option("target_ams_netid", "127.0.0.1.1.1"))
        source_netid = _netid_to_bytes(self.config.get_option("source_ams_netid", "127.0.0.1.1.2"))

        # ============================================================
        # HELPER FUNCTIONS
        # ============================================================

        # AMS/TCP Header: Reserved (2 bytes) + Length (4 bytes, little-endian)
        def _create_tcp_header(ams_block_name):
            return Block(
                "AMS_TCP_Header",
                children=(
                    Word("Reserved", 0x0000, endian="<", fuzzable=False),
                    Size(
                        "Length",
                        block_name=ams_block_name,
                        length=4,
                        endian="<",
                        inclusive=False,
                        fuzzable=False,
                    ),
                ),
            )

        # AMS Header: 32 bytes total
        def _create_ams_header(cmd=0, data_block_name=None):
            children = [
                # Target NetId: 6 bytes - typically server's NetId
                Static("Target_NetId", target_netid),
                Word("Target_Port", 851, endian="<"),  # TC3PLC1 port
                # Source NetId: 6 bytes - typically client's NetId
                Static("Source_NetId", source_netid),
                Word("Source_Port", 32768, endian="<"),  # Client port
                Word("Command_ID", cmd, endian="<"),
                Word("StateFlags", 0x0004, endian="<", fuzzable=False),  # ADS command request
            ]
            if data_block_name:
                children.append(
                    Size(
                        "Data_Length",
                        block_name=data_block_name,
                        length=4,
                        endian="<",
                        inclusive=False,
                        fuzzable=False,
                    )
                )
            else:
                children.append(DWord("Data_Length", 0, endian="<", fuzzable=False))
            children.extend(
                [
                    DWord("Error_Code", 0, endian="<", fuzzable=False),
                    DynamicDWord("Invoke_ID", lambda: self._next_invoke_id(), endian="<"),
                ]
            )
            return Block("AMS_Header", children=tuple(children))

        # ============================================================
        # PHASE 1: QUICK COVERAGE (~30 seconds)
        # Touch all 9 ADS command IDs once with minimal params
        # ============================================================

        # Quick Coverage - All 9 ADS commands in one request
        quick_coverage = Request(
            "ADS_Quick_Coverage",
            children=(
                _create_tcp_header("AMS_Packet_Quick"),
                Block(
                    "AMS_Packet_Quick",
                    children=(
                        # Target NetId: 6 bytes
                        Static("Target_NetId", target_netid),
                        Word("Target_Port", 851, endian="<"),
                        # Source NetId: 6 bytes
                        Static("Source_NetId", source_netid),
                        Word("Source_Port", 32768, endian="<"),
                        # Cycle through all 9 command IDs
                        Group(
                            "Command_ID",
                            values=[
                                struct.pack("<H", ADSCommandIDs.READ_DEVICE_INFO),  # 0x0001
                                struct.pack("<H", ADSCommandIDs.READ),  # 0x0002
                                struct.pack("<H", ADSCommandIDs.WRITE),  # 0x0003
                                struct.pack("<H", ADSCommandIDs.READ_STATE),  # 0x0004
                                struct.pack("<H", ADSCommandIDs.WRITE_CONTROL),  # 0x0005
                                struct.pack("<H", ADSCommandIDs.ADD_NOTIFICATION),  # 0x0006
                                struct.pack("<H", ADSCommandIDs.DEL_NOTIFICATION),  # 0x0007
                                struct.pack("<H", ADSCommandIDs.DEVICE_NOTIFICATION),  # 0x0008
                                struct.pack("<H", ADSCommandIDs.READ_WRITE),  # 0x0009
                            ],
                        ),
                        Word("StateFlags", 0x0004, endian="<", fuzzable=False),
                        DWord("Data_Length", 12, endian="<", fuzzable=False),
                        DWord("Error_Code", 0, endian="<", fuzzable=False),
                        # Dynamic invoke ID so each sent request carries a unique
                        # value (real ADS clients increment it); rendered via
                        # original_value() even though not fuzzed.
                        DynamicDWord(
                            "Invoke_ID", lambda: self._next_invoke_id(), endian="<", fuzzable=False
                        ),
                        # Minimal valid params for most commands
                        DWord("IndexGroup", ADSIndexGroups.MEMORYBYTE, endian="<", fuzzable=False),
                        DWord("IndexOffset", 0, endian="<", fuzzable=False),
                        DWord("ReadLength", 4, endian="<", fuzzable=False),
                    ),
                ),
            ),
        )

        # Baseline read - simple device info request
        ads_read_device_info = Request(
            "ADS_READ_DEVICE_INFO",
            children=(
                _create_tcp_header("AMS_Packet_DevInfo"),
                Block(
                    "AMS_Packet_DevInfo",
                    children=(_create_ams_header(ADSCommandIDs.READ_DEVICE_INFO),),
                ),
            ),
        )

        # ============================================================
        # PHASE 2: HIGH-CRASH TESTS (~3 minutes)
        # Overflow and boundary attacks for early crash detection
        # ============================================================

        # 2a. AMS/TCP Length Field Overflow - CVE-2024-41176 pattern
        length_overflow = Request(
            "ADS_Length_Overflow",
            children=(
                Block(
                    "AMS_TCP_Header_Overflow",
                    children=(
                        Word("Reserved", 0x0000, endian="<", fuzzable=False),
                        Group(
                            "Length_Overflow",
                            values=[
                                struct.pack("<I", 0xFFFFFFFF),  # Maximum length
                                struct.pack("<I", 0x7FFFFFFF),  # Max signed
                                struct.pack("<I", 0x80000000),  # Sign bit
                                struct.pack("<I", 0x10000),  # 64KB boundary
                                struct.pack("<I", 0x1000),  # 4KB boundary
                                struct.pack("<I", 64),  # Small overflow
                                struct.pack("<I", 0),  # Zero length
                            ],
                        ),
                    ),
                ),
                Block(
                    "AMS_Packet_Overflow",
                    children=(_create_ams_header(ADSCommandIDs.READ_DEVICE_INFO),),
                ),
            ),
        )

        # 2b. Oversized Payload Attack
        oversized_payload = Request(
            "ADS_Oversized_Payload",
            children=(
                _create_tcp_header("AMS_Packet_Oversized"),
                Block(
                    "AMS_Packet_Oversized",
                    children=(
                        Static("Target_NetId", target_netid),
                        Word("Target_Port", 851, endian="<"),
                        Static("Source_NetId", source_netid),
                        Word("Source_Port", 32768, endian="<"),
                        Word("Command_ID", ADSCommandIDs.WRITE, endian="<"),
                        Word("StateFlags", 0x0004, endian="<", fuzzable=False),
                        Size(
                            "Data_Length",
                            block_name="OversizedData",
                            length=4,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        DWord("Error_Code", 0, endian="<", fuzzable=False),
                        DWord("Invoke_ID", 1, endian="<"),
                        Block(
                            "OversizedData",
                            children=(
                                DWord("IndexGroup", ADSIndexGroups.MEMORYBYTE, endian="<"),
                                DWord("IndexOffset", 0, endian="<"),
                                Group(
                                    "Oversized_Payload",
                                    values=[
                                        # Progressively larger payloads to trigger buffer overflow
                                        struct.pack("<I", 256) + b"A" * 256,
                                        struct.pack("<I", 1024) + b"B" * 1024,
                                        struct.pack("<I", 4096) + b"C" * 4096,
                                        struct.pack("<I", 8192) + b"D" * 8192,
                                    ],
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # 2c. NetId Boundary Testing (6 bytes each)
        netid_boundary = Request(
            "ADS_NetId_Boundary",
            children=(
                _create_tcp_header("AMS_Packet_NetId"),
                Block(
                    "AMS_Packet_NetId",
                    children=(
                        # Fuzz Target NetId
                        Group(
                            "Target_NetId_Boundary",
                            values=[
                                b"\x00\x00\x00\x00\x00\x00",  # All zeros
                                b"\xff\xff\xff\xff\xff\xff",  # All ones
                                b"\x00\x00\x00\x00\x00\x01",  # Minimal
                                b"\xff\xff\xff\xff\x01\x01",  # Broadcast-like
                                b"\x7f\x00\x00\x01\xff\xff",  # Localhost with max AMS
                                b"\x01\x01\x01\x01\x01\x01",  # Uniform
                            ],
                        ),
                        Word("Target_Port", 851, endian="<"),
                        Static("Source_NetId", source_netid),
                        Word("Source_Port", 32768, endian="<"),
                        Word("Command_ID", ADSCommandIDs.READ_DEVICE_INFO, endian="<"),
                        Word("StateFlags", 0x0004, endian="<", fuzzable=False),
                        DWord("Data_Length", 0, endian="<", fuzzable=False),
                        DWord("Error_Code", 0, endian="<", fuzzable=False),
                        DWord("Invoke_ID", 1, endian="<"),
                    ),
                ),
            ),
        )

        # 2d. Port Boundary Testing
        port_boundary = Request(
            "ADS_Port_Boundary",
            children=(
                _create_tcp_header("AMS_Packet_Port"),
                Block(
                    "AMS_Packet_Port",
                    children=(
                        Static("Target_NetId", target_netid),
                        Group(
                            "Target_Port_Boundary",
                            values=[
                                struct.pack("<H", 0),  # Zero
                                struct.pack("<H", 1),  # Minimal
                                struct.pack("<H", 851),  # TC3PLC1 (default)
                                struct.pack("<H", 852),  # TC3PLC2
                                struct.pack("<H", 801),  # Logger
                                struct.pack("<H", 10000),  # AMS Router
                                struct.pack("<H", 32767),  # Mid-range
                                struct.pack("<H", 32768),  # Sign bit
                                struct.pack("<H", 65534),  # Max - 1
                                struct.pack("<H", 65535),  # Maximum
                            ],
                        ),
                        Static("Source_NetId", source_netid),
                        Word("Source_Port", 32768, endian="<"),
                        Word("Command_ID", ADSCommandIDs.READ_DEVICE_INFO, endian="<"),
                        Word("StateFlags", 0x0004, endian="<", fuzzable=False),
                        DWord("Data_Length", 0, endian="<", fuzzable=False),
                        DWord("Error_Code", 0, endian="<", fuzzable=False),
                        DWord("Invoke_ID", 1, endian="<"),
                    ),
                ),
            ),
        )

        # 2e. Command ID Boundary Testing
        cmd_boundary = Request(
            "ADS_Command_ID_Boundary",
            children=(
                _create_tcp_header("AMS_Packet_CmdBoundary"),
                Block(
                    "AMS_Packet_CmdBoundary",
                    children=(
                        Static("Target_NetId", target_netid),
                        Word("Target_Port", 851, endian="<"),
                        Static("Source_NetId", source_netid),
                        Word("Source_Port", 32768, endian="<"),
                        Group(
                            "Command_ID_Boundary",
                            values=[
                                struct.pack("<H", 0x0000),  # Invalid/Reserved
                                struct.pack("<H", 0x0001),  # READ_DEVICE_INFO
                                struct.pack("<H", 0x0009),  # READ_WRITE (last valid)
                                struct.pack("<H", 0x000A),  # Invalid
                                struct.pack("<H", 0x00FF),  # Invalid
                                struct.pack("<H", 0x7FFF),  # Mid-range
                                struct.pack("<H", 0x8000),  # Sign bit
                                struct.pack("<H", 0xFFFF),  # Maximum
                            ],
                        ),
                        Word("StateFlags", 0x0004, endian="<", fuzzable=False),
                        DWord("Data_Length", 0, endian="<", fuzzable=False),
                        DWord("Error_Code", 0, endian="<", fuzzable=False),
                        DWord("Invoke_ID", 1, endian="<"),
                    ),
                ),
            ),
        )

        # 2f. StateFlags Boundary Testing
        stateflags_boundary = Request(
            "ADS_StateFlags_Boundary",
            children=(
                _create_tcp_header("AMS_Packet_StateFlags"),
                Block(
                    "AMS_Packet_StateFlags",
                    children=(
                        Static("Target_NetId", target_netid),
                        Word("Target_Port", 851, endian="<"),
                        Static("Source_NetId", source_netid),
                        Word("Source_Port", 32768, endian="<"),
                        Word("Command_ID", ADSCommandIDs.READ_DEVICE_INFO, endian="<"),
                        Group(
                            "StateFlags_Boundary",
                            values=[
                                struct.pack("<H", 0x0000),  # No flags
                                struct.pack("<H", 0x0001),  # Response flag
                                struct.pack("<H", 0x0002),  # No return
                                struct.pack("<H", 0x0004),  # ADS command (valid)
                                struct.pack("<H", 0x0008),  # System command
                                struct.pack("<H", 0x0010),  # High priority
                                struct.pack("<H", 0x0020),  # Timestamp added
                                struct.pack("<H", 0x0040),  # UDP
                                struct.pack("<H", 0x00FF),  # All lower flags
                                struct.pack("<H", 0xFFFF),  # All flags
                            ],
                        ),
                        DWord("Data_Length", 0, endian="<", fuzzable=False),
                        DWord("Error_Code", 0, endian="<", fuzzable=False),
                        DWord("Invoke_ID", 1, endian="<"),
                    ),
                ),
            ),
        )

        # 2g. Data Length Mismatch Attack
        data_length_mismatch = Request(
            "ADS_Data_Length_Mismatch",
            children=(
                _create_tcp_header("AMS_Packet_Mismatch"),
                Block(
                    "AMS_Packet_Mismatch",
                    children=(
                        Static("Target_NetId", target_netid),
                        Word("Target_Port", 851, endian="<"),
                        Static("Source_NetId", source_netid),
                        Word("Source_Port", 32768, endian="<"),
                        Word("Command_ID", ADSCommandIDs.READ, endian="<"),
                        Word("StateFlags", 0x0004, endian="<", fuzzable=False),
                        # Data length doesn't match actual data
                        Group(
                            "Data_Length_Mismatch",
                            values=[
                                struct.pack("<I", 0),  # Zero but data follows
                                struct.pack("<I", 1),  # Too small
                                struct.pack("<I", 1000),  # Too large
                                struct.pack("<I", 0xFFFFFFFF),  # Maximum
                            ],
                        ),
                        DWord("Error_Code", 0, endian="<", fuzzable=False),
                        DWord("Invoke_ID", 1, endian="<"),
                        # Actual data (12 bytes for READ command)
                        DWord("IndexGroup", ADSIndexGroups.MEMORYBYTE, endian="<", fuzzable=False),
                        DWord("IndexOffset", 0, endian="<", fuzzable=False),
                        DWord("ReadLength", 4, endian="<", fuzzable=False),
                    ),
                ),
            ),
        )

        # ============================================================
        # PHASE 3: CVE-TARGETED OPERATIONS (~3 minutes)
        # WRITE_CONTROL and route manipulation for CVE-2019-16871
        # ============================================================

        # 3a. ADS WRITE CONTROL - Change PLC state (CVE target)
        ads_write_control = Request(
            "ADS_WRITE_CONTROL",
            children=(
                _create_tcp_header("AMS_Packet_WriteCtrl"),
                Block(
                    "AMS_Packet_WriteCtrl",
                    children=(
                        _create_ams_header(ADSCommandIDs.WRITE_CONTROL, "ControlData"),
                        Block(
                            "ControlData",
                            children=(
                                Group(
                                    "ADS_State",
                                    values=[
                                        struct.pack("<H", ADSStates.INVALID),  # Invalid state
                                        struct.pack("<H", ADSStates.IDLE),  # IDLE
                                        struct.pack("<H", ADSStates.RESET),  # RESET
                                        struct.pack("<H", ADSStates.INIT),  # INIT
                                        struct.pack("<H", ADSStates.START),  # START
                                        struct.pack("<H", ADSStates.RUN),  # RUN
                                        struct.pack("<H", ADSStates.STOP),  # STOP
                                        struct.pack("<H", ADSStates.SAVECFG),  # SAVECFG
                                        struct.pack("<H", ADSStates.LOADCFG),  # LOADCFG
                                        struct.pack("<H", ADSStates.POWERFAILURE),  # POWERFAILURE
                                        struct.pack("<H", ADSStates.ERROR),  # ERROR
                                        struct.pack("<H", ADSStates.SHUTDOWN),  # SHUTDOWN
                                        struct.pack("<H", ADSStates.CONFIG),  # CONFIG
                                        struct.pack("<H", ADSStates.RECONFIG),  # RECONFIG
                                        struct.pack("<H", 0xFFFF),  # Invalid max
                                    ],
                                ),
                                Word("Device_State", 0, endian="<"),
                                DWord("DataLength", 0, endian="<"),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # 3b. ADS WRITE CONTROL with oversized data
        write_control_overflow = Request(
            "ADS_WRITE_CONTROL_Overflow",
            children=(
                _create_tcp_header("AMS_Packet_WriteCtrlOvf"),
                Block(
                    "AMS_Packet_WriteCtrlOvf",
                    children=(
                        _create_ams_header(ADSCommandIDs.WRITE_CONTROL, "ControlDataOvf"),
                        Block(
                            "ControlDataOvf",
                            children=(
                                Word("ADS_State", ADSStates.CONFIG, endian="<"),
                                Word("Device_State", 0, endian="<"),
                                Group(
                                    "Oversized_Control_Data",
                                    values=[
                                        struct.pack("<I", 256) + b"A" * 256,
                                        struct.pack("<I", 1024) + b"B" * 1024,
                                        struct.pack("<I", 4096) + b"C" * 4096,
                                    ],
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # 3c. ADS WRITE - Memory write operations
        ads_write = Request(
            "ADS_WRITE",
            children=(
                _create_tcp_header("AMS_Packet_Write"),
                Block(
                    "AMS_Packet_Write",
                    children=(
                        _create_ams_header(ADSCommandIDs.WRITE, "WriteData"),
                        Block(
                            "WriteData",
                            children=(
                                Group(
                                    "IndexGroup",
                                    values=[
                                        struct.pack("<I", ADSIndexGroups.MEMORYBYTE),
                                        struct.pack("<I", ADSIndexGroups.DATA),
                                        struct.pack("<I", ADSIndexGroups.IOIMAGE_RWOB),
                                        struct.pack("<I", ADSIndexGroups.AMS_ROUTER),  # CVE target
                                    ],
                                ),
                                DWord("IndexOffset", 0, endian="<"),
                                DWord("WriteLength", 4, endian="<"),
                                DWord("Data", 0x12345678, endian="<"),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # 3d. ADS WRITE with boundary values
        ads_write_boundary = Request(
            "ADS_WRITE_Boundary",
            children=(
                _create_tcp_header("AMS_Packet_WriteBound"),
                Block(
                    "AMS_Packet_WriteBound",
                    children=(
                        _create_ams_header(ADSCommandIDs.WRITE, "WriteBoundData"),
                        Block(
                            "WriteBoundData",
                            children=(
                                DWord("IndexGroup", ADSIndexGroups.MEMORYBYTE, endian="<"),
                                Group(
                                    "IndexOffset_Boundary",
                                    values=[
                                        struct.pack("<I", 0),  # Zero
                                        struct.pack("<I", 0x7FFFFFFF),  # Max signed
                                        struct.pack("<I", 0x80000000),  # Sign bit
                                        struct.pack("<I", 0xFFFFFFFF),  # Maximum
                                    ],
                                ),
                                Group(
                                    "WriteLength_Boundary",
                                    values=[
                                        struct.pack("<I", 0),  # Zero
                                        struct.pack("<I", 1),  # Minimal
                                        struct.pack("<I", 0x10000),  # 64KB
                                        struct.pack("<I", 0xFFFFFFFF),  # Maximum
                                    ],
                                ),
                                DWord("Data", 0xDEADBEEF, endian="<"),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # 3e. AMS Route Manipulation (CVE-2019-16871 pattern)
        route_manipulation = Request(
            "ADS_Route_Manipulation",
            children=(
                _create_tcp_header("AMS_Packet_Route"),
                Block(
                    "AMS_Packet_Route",
                    children=(
                        # Manipulate routing to access other AMS devices
                        Group(
                            "Target_NetId_Route",
                            values=[
                                b"\x00\x00\x00\x00\x00\x00",  # Null route
                                b"\xff\xff\xff\xff\xff\xff",  # Broadcast
                                b"\x01\x00\x00\x00\x00\x00",  # Minimal route
                                b"\xc0\xa8\x01\x01\x01\x01",  # 192.168.1.1.1.1
                                b"\x0a\x00\x00\x01\x01\x01",  # 10.0.0.1.1.1
                            ],
                        ),
                        Group(
                            "Target_Port_Route",
                            values=[
                                struct.pack("<H", 10000),  # AMS Router port
                                struct.pack("<H", 100),  # System port
                                struct.pack("<H", 0),  # Zero
                                struct.pack("<H", 1),  # AMS Router
                            ],
                        ),
                        Static("Source_NetId", source_netid),
                        Word("Source_Port", 32768, endian="<"),
                        Word("Command_ID", ADSCommandIDs.READ_WRITE, endian="<"),
                        Word("StateFlags", 0x0004, endian="<", fuzzable=False),
                        Size(
                            "Data_Length",
                            block_name="RouteData",
                            length=4,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        DWord("Error_Code", 0, endian="<", fuzzable=False),
                        DWord("Invoke_ID", 1, endian="<"),
                        Block(
                            "RouteData",
                            children=(
                                DWord("IndexGroup", ADSIndexGroups.AMS_ROUTER, endian="<"),
                                DWord("IndexOffset", 0, endian="<"),
                                DWord("ReadLength", 4, endian="<"),
                                DWord("WriteLength", 0, endian="<"),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # ============================================================
        # PHASE 4: SYMBOL OPERATIONS (~2 minutes)
        # ============================================================

        # 4a. Get handle by name
        ads_get_handle = Request(
            "ADS_GET_HANDLE_BY_NAME",
            children=(
                _create_tcp_header("AMS_Packet_GetHandle"),
                Block(
                    "AMS_Packet_GetHandle",
                    children=(
                        _create_ams_header(ADSCommandIDs.READ_WRITE, "HandleData"),
                        Block(
                            "HandleData",
                            children=(
                                DWord("IndexGroup", ADSIndexGroups.SYM_HNDBYNAME, endian="<"),
                                DWord("IndexOffset", 0, endian="<"),
                                DWord("ReadLength", 4, endian="<"),
                                Size(
                                    "WriteLength",
                                    block_name="SymbolName",
                                    length=4,
                                    endian="<",
                                    inclusive=False,
                                ),
                                Block(
                                    "SymbolName",
                                    children=(
                                        Group(
                                            "Symbol",
                                            values=[
                                                b"MAIN.bSystemReady\x00",
                                                b"MAIN.bStart\x00",
                                                b"MAIN.nCycleCounter\x00",
                                                b"MAIN.rTemperature\x00",
                                                b"MAIN.Motor1.bEnable\x00",
                                            ],
                                        )
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # 4b. Get handle with oversized symbol name (overflow attack)
        ads_get_handle_overflow = Request(
            "ADS_GET_HANDLE_Overflow",
            children=(
                _create_tcp_header("AMS_Packet_HandleOvf"),
                Block(
                    "AMS_Packet_HandleOvf",
                    children=(
                        _create_ams_header(ADSCommandIDs.READ_WRITE, "HandleOvfData"),
                        Block(
                            "HandleOvfData",
                            children=(
                                DWord("IndexGroup", ADSIndexGroups.SYM_HNDBYNAME, endian="<"),
                                DWord("IndexOffset", 0, endian="<"),
                                DWord("ReadLength", 4, endian="<"),
                                Size(
                                    "WriteLength",
                                    block_name="SymbolNameOvf",
                                    length=4,
                                    endian="<",
                                    inclusive=False,
                                ),
                                Block(
                                    "SymbolNameOvf",
                                    children=(
                                        Group(
                                            "Symbol_Overflow",
                                            values=[
                                                b"A" * 256 + b"\x00",
                                                b"B" * 1024 + b"\x00",
                                                b"MAIN." + b"C" * 500 + b"\x00",
                                            ],
                                        )
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # 4c. Read value by name
        ads_read_by_name = Request(
            "ADS_READ_VALUE_BY_NAME",
            children=(
                _create_tcp_header("AMS_Packet_ReadByName"),
                Block(
                    "AMS_Packet_ReadByName",
                    children=(
                        _create_ams_header(ADSCommandIDs.READ_WRITE, "ReadByNameData"),
                        Block(
                            "ReadByNameData",
                            children=(
                                DWord("IndexGroup", ADSIndexGroups.SYM_VALBYNAME, endian="<"),
                                DWord("IndexOffset", 0, endian="<"),
                                DWord("ReadLength", 4, endian="<"),
                                Size(
                                    "WriteLength",
                                    block_name="SymbolName2",
                                    length=4,
                                    endian="<",
                                    inclusive=False,
                                ),
                                Block(
                                    "SymbolName2",
                                    children=(
                                        Group(
                                            "Symbol",
                                            values=[
                                                b"MAIN.bSystemReady\x00",
                                                b"MAIN.nCycleCounter\x00",
                                                b"MAIN.rTemperature\x00",
                                            ],
                                        )
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # 4d. Get symbol info by name
        ads_get_symbol_info = Request(
            "ADS_GET_SYMBOL_INFO",
            children=(
                _create_tcp_header("AMS_Packet_SymInfo"),
                Block(
                    "AMS_Packet_SymInfo",
                    children=(
                        _create_ams_header(ADSCommandIDs.READ_WRITE, "SymInfoData"),
                        Block(
                            "SymInfoData",
                            children=(
                                DWord("IndexGroup", ADSIndexGroups.SYM_INFOBYNAMEEX, endian="<"),
                                DWord("IndexOffset", 0, endian="<"),
                                DWord("ReadLength", 256, endian="<"),
                                Size(
                                    "WriteLength",
                                    block_name="SymbolName3",
                                    length=4,
                                    endian="<",
                                    inclusive=False,
                                ),
                                Block(
                                    "SymbolName3",
                                    children=(
                                        Group(
                                            "Symbol",
                                            values=[
                                                b"MAIN.bSystemReady\x00",
                                                b"MAIN.rTemperature\x00",
                                            ],
                                        )
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # 4e. Get upload info
        ads_get_upload_info = Request(
            "ADS_GET_UPLOAD_INFO",
            children=(
                _create_tcp_header("AMS_Packet_UploadInfo"),
                Block(
                    "AMS_Packet_UploadInfo",
                    children=(
                        _create_ams_header(ADSCommandIDs.READ_WRITE, "UploadInfoData"),
                        Block(
                            "UploadInfoData",
                            children=(
                                DWord("IndexGroup", ADSIndexGroups.SYM_UPLOADINFO2, endian="<"),
                                DWord("IndexOffset", 0, endian="<"),
                                DWord("ReadLength", 8, endian="<"),
                                DWord("WriteLength", 0, endian="<"),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # ============================================================
        # PHASE 5: STANDARD OPERATIONS (~remaining)
        # ============================================================

        # 5a. ADS READ STATE
        ads_read_state = Request(
            "ADS_READ_STATE",
            children=(
                _create_tcp_header("AMS_Packet_ReadState"),
                Block(
                    "AMS_Packet_ReadState", children=(_create_ams_header(ADSCommandIDs.READ_STATE),)
                ),
            ),
        )

        # 5b. ADS READ
        ads_read = Request(
            "ADS_READ",
            children=(
                _create_tcp_header("AMS_Packet_Read"),
                Block(
                    "AMS_Packet_Read",
                    children=(
                        _create_ams_header(ADSCommandIDs.READ, "ReadData"),
                        Block(
                            "ReadData",
                            children=(
                                Group(
                                    "IndexGroup",
                                    values=[
                                        struct.pack("<I", ADSIndexGroups.MEMORYBYTE),
                                        struct.pack("<I", ADSIndexGroups.DATA),
                                        struct.pack("<I", ADSIndexGroups.IOIMAGE_RWIB),
                                        struct.pack("<I", ADSIndexGroups.IOIMAGE_RWOB),
                                    ],
                                ),
                                DWord("IndexOffset", 0, endian="<"),
                                DWord("ReadLength", 4, endian="<"),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # 5c. ADS ADD NOTIFICATION
        ads_add_notification = Request(
            "ADS_ADD_NOTIFICATION",
            children=(
                _create_tcp_header("AMS_Packet_AddNotif"),
                Block(
                    "AMS_Packet_AddNotif",
                    children=(
                        _create_ams_header(ADSCommandIDs.ADD_NOTIFICATION, "NotificationData"),
                        Block(
                            "NotificationData",
                            children=(
                                Group(
                                    "IndexGroup",
                                    values=[
                                        struct.pack("<I", ADSIndexGroups.MEMORYBYTE),
                                        struct.pack("<I", ADSIndexGroups.DATA),
                                    ],
                                ),
                                DWord("IndexOffset", 0, endian="<"),
                                DWord("Length", 4, endian="<"),
                                Group(
                                    "TransMode",
                                    values=[
                                        struct.pack("<I", 1),  # CLIENTCYCLE
                                        struct.pack("<I", 2),  # CLIENTONCHANGE
                                        struct.pack("<I", 3),  # SERVERCYCLE
                                        struct.pack("<I", 4),  # SERVERONCHANGE
                                    ],
                                ),
                                DWord("MaxDelay", 0, endian="<"),
                                DWord("CycleTime", 1000000, endian="<"),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # 5d. ADS DELETE NOTIFICATION
        ads_del_notification = Request(
            "ADS_DEL_NOTIFICATION",
            children=(
                _create_tcp_header("AMS_Packet_DelNotif"),
                Block(
                    "AMS_Packet_DelNotif",
                    children=(
                        _create_ams_header(ADSCommandIDs.DEL_NOTIFICATION, "DelNotificationData"),
                        Block(
                            "DelNotificationData",
                            children=(DWord("NotificationHandle", 1, endian="<")),
                        ),
                    ),
                ),
            ),
        )

        # 5e. Memory area read operations
        ads_read_memory = Request(
            "ADS_READ_MEMORY",
            children=(
                _create_tcp_header("AMS_Packet_ReadMem"),
                Block(
                    "AMS_Packet_ReadMem",
                    children=(
                        _create_ams_header(ADSCommandIDs.READ, "ReadMemData"),
                        Block(
                            "ReadMemData",
                            children=(
                                DWord("IndexGroup", ADSIndexGroups.MEMORYBYTE, endian="<"),
                                Group(
                                    "IndexOffset",
                                    values=[
                                        struct.pack("<I", 0),
                                        struct.pack("<I", 100),
                                        struct.pack("<I", 256),
                                        struct.pack("<I", 512),
                                    ],
                                ),
                                Group(
                                    "ReadLength",
                                    values=[
                                        struct.pack("<I", 1),
                                        struct.pack("<I", 4),
                                        struct.pack("<I", 16),
                                        struct.pack("<I", 64),
                                    ],
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # 5f. I/O image operations
        ads_read_io = Request(
            "ADS_READ_IO_IMAGE",
            children=(
                _create_tcp_header("AMS_Packet_ReadIO"),
                Block(
                    "AMS_Packet_ReadIO",
                    children=(
                        _create_ams_header(ADSCommandIDs.READ, "ReadIOData"),
                        Block(
                            "ReadIOData",
                            children=(
                                Group(
                                    "IndexGroup",
                                    values=[
                                        struct.pack("<I", ADSIndexGroups.IOIMAGE_RWIB),
                                        struct.pack("<I", ADSIndexGroups.IOIMAGE_RWOB),
                                    ],
                                ),
                                DWord("IndexOffset", 0, endian="<"),
                                DWord("ReadLength", 32, endian="<"),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # ============================================================
        # PHASE 5b: PORT ENUMERATION & BULK OPS (ref/ads/cve_patterns.json)
        # ============================================================

        # ADS_Port_Enumeration — cycle Beckhoff logical AMS ports on the READ
        # command. Per-port parsers differ (851 PLC vs. 350 SystemService etc.)
        # so this catches parser_oob bugs that only fire on specific ports.
        # ref/ads/cve_patterns.json#ads-port-enumeration
        ads_port_enumeration = Request(
            "ADS_Port_Enumeration",
            children=(
                _create_tcp_header("AMS_Packet_PortEnum"),
                Block(
                    "AMS_Packet_PortEnum",
                    children=(
                        Static("Target_NetId", target_netid),
                        Group(
                            "AMS.TargetPort",
                            values=[
                                struct.pack("<H", 100),
                                struct.pack("<H", 110),
                                struct.pack("<H", 200),
                                struct.pack("<H", 350),
                                struct.pack("<H", 400),
                                struct.pack("<H", 500),
                                struct.pack("<H", 851),
                                struct.pack("<H", 852),
                                struct.pack("<H", 853),
                                struct.pack("<H", 900),
                            ],
                        ),
                        Static("Source_NetId", source_netid),
                        Word("Source_Port", 32768, endian="<"),
                        Word("Command_ID", ADSCommandIDs.READ, endian="<"),
                        Word("StateFlags", 0x0004, endian="<", fuzzable=False),
                        Size(
                            "Data_Length",
                            block_name="PortEnumReadData",
                            length=4,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        DWord("Error_Code", 0, endian="<", fuzzable=False),
                        DynamicDWord("Invoke_ID", lambda: self._next_invoke_id(), endian="<"),
                        Block(
                            "PortEnumReadData",
                            children=(
                                DWord(
                                    "IndexGroup",
                                    ADSIndexGroups.MEMORYBYTE,
                                    endian="<",
                                    fuzzable=False,
                                ),
                                DWord("IndexOffset", 0, endian="<", fuzzable=False),
                                DWord("ReadLength", 4, endian="<", fuzzable=False),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # ADS_SumReadWrite — Beckhoff bulk-op. Wraps a SumUp ReadWrite over the
        # READ_WRITE command with a fuzzable SubCommandCount field. Targets
        # parsers that trust the count and walk the sub-request array.
        # ref/ads/cve_patterns.json#ads-sumcommand
        ads_sum_readwrite = Request(
            "ADS_SumReadWrite",
            children=(
                _create_tcp_header("AMS_Packet_SumRW"),
                Block(
                    "AMS_Packet_SumRW",
                    children=(
                        _create_ams_header(ADSCommandIDs.READ_WRITE, "SumRWData"),
                        Block(
                            "SumRWData",
                            children=(
                                DWord(
                                    "IndexGroup",
                                    ADSIndexGroups.SUMUP_READWRITE,
                                    endian="<",
                                    fuzzable=False,
                                ),
                                # SubCommandCount goes in IndexOffset for SumUp ops
                                Group(
                                    "SumCommand.SubCommandCount",
                                    values=[
                                        struct.pack("<I", 0),
                                        struct.pack("<I", 1),
                                        struct.pack("<I", 100),
                                        struct.pack("<I", 1000),
                                        struct.pack("<I", 65535),
                                    ],
                                ),
                                DWord("ReadLength", 16, endian="<", fuzzable=False),
                                DWord("WriteLength", 16, endian="<", fuzzable=False),
                                # Two sub-requests: each (IndexGroup, IndexOffset, Length) = 12B
                                DWord(
                                    "Sub1_IndexGroup",
                                    ADSIndexGroups.MEMORYBYTE,
                                    endian="<",
                                    fuzzable=False,
                                ),
                                DWord("Sub1_IndexOffset", 0, endian="<", fuzzable=False),
                                DWord("Sub1_Length", 4, endian="<", fuzzable=False),
                                DWord(
                                    "Sub2_IndexGroup",
                                    ADSIndexGroups.DATA,
                                    endian="<",
                                    fuzzable=False,
                                ),
                                DWord("Sub2_IndexOffset", 0, endian="<", fuzzable=False),
                                DWord("Sub2_Length", 4, endian="<", fuzzable=False),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # ============================================================
        # ADS/AMS AUTHENTICATION REQUESTS
        # ADS doesn't have built-in authentication, but route manipulation
        # and some operations can be protected at the PLC level
        # ============================================================

        # Get credentials from options
        ads_password = self.config.get_option("ads_password", "") or "password"
        route_password = self.config.get_option("route_password", "") or "routepass"

        # Route password authentication (CVE-2019-16871 pattern with password)
        ads_route_auth = Request(
            "ADS_Route_Auth",
            children=(
                _create_tcp_header("AMS_Packet_RouteAuth"),
                Block(
                    "AMS_Packet_RouteAuth",
                    children=(
                        # Manipulate routing with password in data
                        Group(
                            "Target_NetId",
                            values=[
                                b"\x00\x00\x00\x00\x00\x00",  # Null route
                                b"\xff\xff\xff\xff\xff\xff",  # Broadcast
                                b"\xc0\xa8\x01\x01\x01\x01",  # 192.168.1.1.1.1
                            ],
                        ),
                        Word("Target_Port", 10000, endian="<"),  # AMS Router
                        Static("Source_NetId", source_netid),
                        Word("Source_Port", 32768, endian="<"),
                        Word("Command_ID", ADSCommandIDs.READ_WRITE, endian="<"),
                        Word("StateFlags", 0x0004, endian="<", fuzzable=False),
                        Size(
                            "Data_Length",
                            block_name="RouteAuthData",
                            length=4,
                            endian="<",
                            inclusive=False,
                            fuzzable=False,
                        ),
                        DWord("Error_Code", 0, endian="<", fuzzable=False),
                        DWord("Invoke_ID", 1, endian="<"),
                        Block(
                            "RouteAuthData",
                            children=(
                                DWord("IndexGroup", ADSIndexGroups.AMS_ROUTER, endian="<"),
                                DWord("IndexOffset", 0, endian="<"),
                                DWord("ReadLength", 4, endian="<"),
                                Size(
                                    "WriteLength",
                                    block_name="RoutePassword",
                                    length=4,
                                    endian="<",
                                    inclusive=False,
                                ),
                                Block(
                                    "RoutePassword",
                                    children=(
                                        SmartString(
                                            "password",
                                            route_password,
                                            max_len=32,
                                            context=StringContext.CREDENTIAL,
                                            padding=b"\x00",
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # Password-protected state change
        ads_state_auth = Request(
            "ADS_State_Auth",
            children=(
                _create_tcp_header("AMS_Packet_StateAuth"),
                Block(
                    "AMS_Packet_StateAuth",
                    children=(
                        _create_ams_header(ADSCommandIDs.WRITE_CONTROL, "StateAuthData"),
                        Block(
                            "StateAuthData",
                            children=(
                                Word("ADS_State", ADSStates.RUN, endian="<"),
                                Word("Device_State", 0, endian="<"),
                                Size(
                                    "DataLength",
                                    block_name="StatePassword",
                                    length=4,
                                    endian="<",
                                    inclusive=False,
                                ),
                                Block(
                                    "StatePassword",
                                    children=(
                                        SmartString(
                                            "password",
                                            ads_password,
                                            max_len=32,
                                            context=StringContext.CREDENTIAL,
                                            padding=b"\x00",
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # Password brute force patterns for state control
        ads_password_brute = Request(
            "ADS_Password_Brute",
            children=(
                _create_tcp_header("AMS_Packet_PassBrute"),
                Block(
                    "AMS_Packet_PassBrute",
                    children=(
                        _create_ams_header(ADSCommandIDs.WRITE_CONTROL, "PassBruteData"),
                        Block(
                            "PassBruteData",
                            children=(
                                Word("ADS_State", ADSStates.STOP, endian="<"),  # Try STOP
                                Word("Device_State", 0, endian="<"),
                                DWord("DataLength", 32, endian="<"),
                                Group(
                                    "password_attempts",
                                    values=[
                                        b"\x00" * 32,  # Null password
                                        b"password" + b"\x00" * 24,  # Common
                                        b"admin" + b"\x00" * 27,  # admin
                                        b"twincat" + b"\x00" * 25,  # Vendor
                                        b"beckhoff" + b"\x00" * 24,  # Vendor
                                        b"\xff" * 32,  # All 0xFF
                                        b"12345678" + b"\x00" * 24,  # Numeric
                                    ],
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # Symbol access with password (some PLCs protect symbols)
        ads_symbol_auth = Request(
            "ADS_Symbol_Auth",
            children=(
                _create_tcp_header("AMS_Packet_SymAuth"),
                Block(
                    "AMS_Packet_SymAuth",
                    children=(
                        _create_ams_header(ADSCommandIDs.READ_WRITE, "SymAuthData"),
                        Block(
                            "SymAuthData",
                            children=(
                                DWord("IndexGroup", ADSIndexGroups.SYM_HNDBYNAME, endian="<"),
                                DWord("IndexOffset", 0, endian="<"),
                                DWord("ReadLength", 4, endian="<"),
                                Size(
                                    "WriteLength",
                                    block_name="SymbolWithPass",
                                    length=4,
                                    endian="<",
                                    inclusive=False,
                                ),
                                Block(
                                    "SymbolWithPass",
                                    children=(
                                        SmartString(
                                            "password",
                                            ads_password,
                                            max_len=32,
                                            context=StringContext.CREDENTIAL,
                                            padding=b"\x00",
                                        ),
                                        Static("separator", b"\x00"),
                                        Group(
                                            "Symbol",
                                            values=[
                                                b"MAIN.bSystemReady\x00",
                                                b"MAIN.bProtected\x00",
                                                b"MAIN.rSecretValue\x00",
                                            ],
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # Malformed password (boundary testing)
        ads_password_malformed = Request(
            "ADS_Password_Malformed",
            children=(
                _create_tcp_header("AMS_Packet_PassMalformed"),
                Block(
                    "AMS_Packet_PassMalformed",
                    children=(
                        _create_ams_header(ADSCommandIDs.WRITE_CONTROL, "PassMalformedData"),
                        Block(
                            "PassMalformedData",
                            children=(
                                Word("ADS_State", ADSStates.CONFIG, endian="<"),
                                Word("Device_State", 0, endian="<"),
                                Group(
                                    "Oversized_Password",
                                    values=[
                                        struct.pack("<I", 256) + b"A" * 256,
                                        struct.pack("<I", 1024) + b"B" * 1024,
                                        struct.pack("<I", 0) + b"",  # Zero length
                                        struct.pack("<I", 0xFFFFFFFF)
                                        + b"C" * 100,  # Invalid length
                                    ],
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        # ============================================================
        # OPTIMIZED REQUEST ORDERING
        # ============================================================
        # Phase 1: Quick Coverage (~30 sec)
        # Phase 2: High-Crash Tests (~3 min)
        # Phase 3: CVE-Targeted Operations (~3 min)
        # Phase 4: Symbol Operations (~2 min)
        # Phase 5: Standard Operations (~remaining)

        # ==================== PHASE 1: QUICK COVERAGE ====================
        if self.is_request_enabled("ADS_Quick_Coverage"):
            self.session.connect(quick_coverage)
            self.session.connect(ads_read_device_info)

        # ==================== PHASE 2: HIGH-CRASH TESTS ====================
        if self.is_request_enabled("ADS_Overflow"):
            self.session.connect(length_overflow)
            self.session.connect(oversized_payload)
            self.session.connect(data_length_mismatch)

        if self.is_request_enabled("ADS_Boundary"):
            self.session.connect(netid_boundary)
            self.session.connect(port_boundary)
            self.session.connect(cmd_boundary)
            self.session.connect(stateflags_boundary)

        # ==================== PHASE 3: CVE-TARGETED OPERATIONS ====================
        enable_write = self.config.get_option("enable_write", False)
        if not enable_write:
            self.log.warning(
                "[ADS] Write operations disabled (enable_write=False). "
                "Skipping ADS_Write_Control, ADS_Write, ADS_Route requests."
            )

        if enable_write and self.is_request_enabled("ADS_Write_Control"):
            self.session.connect(ads_write_control)
            self.session.connect(write_control_overflow)

        if enable_write and self.is_request_enabled("ADS_Write"):
            self.session.connect(ads_write)
            self.session.connect(ads_write_boundary)

        if enable_write and self.is_request_enabled("ADS_Route"):
            self.session.connect(route_manipulation)

        # ==================== PHASE 4: SYMBOL OPERATIONS ====================
        if self.is_request_enabled("ADS_Symbol"):
            self.session.connect(ads_get_handle)
            self.session.connect(ads_get_handle_overflow)
            self.session.connect(ads_read_by_name)
            self.session.connect(ads_get_symbol_info)
            self.session.connect(ads_get_upload_info)

        # ==================== PHASE 5: STANDARD OPERATIONS ====================
        if self.is_request_enabled("ADS_Read"):
            self.session.connect(ads_read_state)
            self.session.connect(ads_read)
            self.session.connect(ads_read_memory)
            self.session.connect(ads_read_io)
            self.session.connect(ads_port_enumeration)
            self.session.connect(ads_sum_readwrite)

        if self.is_request_enabled("ADS_Notification"):
            self.session.connect(ads_add_notification)
            self.session.connect(ads_del_notification)

        # ==================== ADS AUTHENTICATION ====================
        if self.is_request_enabled("ADS_Auth") and self.config.get_option("enable_auth", False):
            self.session.connect(ads_route_auth)
            self.session.connect(ads_state_auth)
            self.session.connect(ads_password_brute)
            self.session.connect(ads_symbol_auth)
            self.session.connect(ads_password_malformed)

        # ==================== ADS PORT ENUMERATION & BULK OPS ====================
        if self.is_request_enabled("ADS_Port_Enumeration"):
            self.session.connect(ads_port_enumeration)
        if self.is_request_enabled("ADS_SumReadWrite"):
            self.session.connect(ads_sum_readwrite)

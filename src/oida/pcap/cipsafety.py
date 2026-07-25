"""
CIP Safety Passive Listener (PyShark-based).

Passively monitors CIP Safety traffic -- the safety-critical extension of
Common Industrial Protocol (CIP) used over EtherNet/IP for functional safety
applications (SIL 3 / PLe per IEC 62443 and IEC 61784-3).

CIP Safety adds integrity checks (CRCs), time coordination, and safety
validator/supervisor objects on top of standard CIP I/O connections.

Three tshark dissector layers are relevant:
- cipsafety: Base CIP Safety protocol (mode byte, CRCs, timestamps, data)
- cipssupervisor: CIP Safety Supervisor object (configuration, TUNID, passwords)
- cipsvalidator: CIP Safety Validator object (connection state, fault counts)

tshark fields used:

CIP Safety base (cipsafety.*):
- cipsafety.data: Safety data payload (FT_BYTES)
- cipsafety.mode_byte: Mode byte (FT_UINT8)
- cipsafety.mode_byte.run_idle: Run/Idle flag (FT_BOOLEAN)
- cipsafety.mode_byte.not_run_idle: Not Run/Idle flag (FT_BOOLEAN)
- cipsafety.mode_byte.tbd: TBD bit (FT_BOOLEAN)
- cipsafety.mode_byte.not_tbd: Not TBD bit (FT_BOOLEAN)
- cipsafety.mode_byte.ping_count: Ping count (FT_UINT8)
- cipsafety.crc_s1: CRC S1 (FT_UINT8)
- cipsafety.crc_s1.status: CRC S1 status (FT_UINT8)
- cipsafety.crc_s2: CRC S2 (FT_UINT8)
- cipsafety.crc_s2.status: CRC S2 status (FT_UINT8)
- cipsafety.crc_s3: CRC S3 (FT_UINT16)
- cipsafety.crc_s3.status: CRC S3 status (FT_UINT8)
- cipsafety.complement_crc_s3: Complement CRC S3 (FT_UINT16)
- cipsafety.complement_crc_s3.status: Complement CRC S3 status (FT_UINT8)
- cipsafety.timestamp: Safety timestamp (FT_UINT16)
- cipsafety.ack_byte: Acknowledge byte (FT_UINT8)
- cipsafety.ack_byte.ping_count_reply: Ping count reply (FT_UINT8)
- cipsafety.ack_byte.ping_response: Ping response (FT_BOOLEAN)
- cipsafety.consumer_time_value: Consumer time value (FT_UINT16)
- cipsafety.mcast_byte: Multicast byte (FT_UINT8)
- cipsafety.mcast_byte.consumer_num: Consumer number (FT_UINT8)
- cipsafety.mcast_byte.active_idle: Multicast Active/Idle (FT_BOOLEAN)
- cipsafety.time_correction: Time correction (FT_UINT16)
- cipsafety.complement_data: Complement data (FT_BYTES)
- cipsafety.message_encoding: Safety message encoding (FT_UINT32)

CIP Safety Supervisor (cipsafety.ssupervisor.*):
- cipsafety.ssupervisor.sc: Service code (FT_UINT8)
- cipsafety.ssupervisor.configure_request.password: Config password (FT_BYTES)
- cipsafety.ssupervisor.configure_request.tunid: Target UNID (FT_BYTES)
- cipsafety.ssupervisor.set_password.current_pass: Current password (FT_BYTES)
- cipsafety.ssupervisor.set_password.new_pass: New password (FT_BYTES)
- cipsafety.ssupervisor.configure_lock.lock: Lock value (FT_UINT8)
- cipsafety.ssupervisor.configure_lock.password: Lock password (FT_BYTES)
- cipsafety.ssupervisor.mode_change.value: Mode change value (FT_UINT8)
- cipsafety.ssupervisor.mode_change.password: Mode change password (FT_BYTES)
- cipsafety.ssupervisor.reset.type: Reset type (FT_UINT8)
- cipsafety.ssupervisor.reset.password: Reset password (FT_BYTES)
- cipsafety.ssupervisor.device_status: Device status (FT_UINT8)
- cipsafety.ssupervisor.configuration_lock: Configuration lock state (FT_UINT8)
- cipsafety.ssupervisor.manufacture_name: Manufacturer name (FT_STRING)
- cipsafety.ssupervisor.manufacture_model_number: Model number (FT_STRING)
- cipsafety.ssupervisor.manufacture_serial_number: Serial number (FT_STRING)
- cipsafety.ssupervisor.sw_rev_level: Software revision (FT_STRING)
- cipsafety.ssupervisor.hw_rev_level: Hardware revision (FT_STRING)

CIP Safety Validator (cipsafety.svalidator.*):
- cipsafety.svalidator.sc: Service code (FT_UINT8)
- cipsafety.svalidator.state: Safety Validator state (FT_UINT8)
- cipsafety.svalidator.type: Safety Validator type (FT_UINT8)
- cipsafety.svalidator.type.pc: Producer/Consumer flag (FT_UINT8)
- cipsafety.svalidator.type.conn_type: Connection type (FT_UINT8)
- cipsafety.svalidator.sconn_fault_count: Safety connection fault count (FT_UINT16)
- cipsafety.svalidator.ping_epi: Ping interval EPI multiplier (FT_UINT16)
- cipsafety.svalidator.data_conn_inst: Data connection instance (FT_UINT16)
- cipsafety.svalidator.max_consumer_num: Max consumer number (FT_UINT8)
- cipsafety.svalidator.max_data_age: Max data age (FT_UINT16)
- cipsafety.svalidator.error_code: Error code (FT_UINT16)

Security notes:
- Password fields in supervisor services are transmitted in safety frames
- Mode changes and configuration locks are security-relevant operations
- CRC failures indicate potential data corruption or tampering
- Validator state transitions (especially to fault state) are security events
- Reset operations could indicate unauthorized reconfiguration
- Safety connection fault counts indicate potential attack or hardware failure

References:
- ODVA CIP Safety (CIP Volume 5)
- IEC 62443-4-2: Security for IACS components (safety integration)
- IEC 61784-3: Functional safety fieldbuses (CPF 2 -- CIP Safety)
- Wireshark dissectors: packet-cipsafety.c, packet-cipssupervisor.c, packet-cipsvalidator.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip

# CIP Safety Supervisor service codes
# cipsafety.ssupervisor.sc service codes (matches Wireshark's value_string in
# packet-cipssupervisor.c). The high range (0x4C+) is CIP-Safety-specific and
# was previously off by one/two codes -- e.g. real Set_Password is 0x51, not
# 0x4F -- which mislabelled password/config operations.
SUPERVISOR_SERVICES = {
    0x01: "Get_Attributes_All",
    0x02: "Set_Attributes_All",
    0x03: "Get_Attribute_List",
    0x04: "Set_Attribute_List",
    0x05: "Reset",
    0x06: "Start",
    0x07: "Stop",
    0x08: "Create",
    0x09: "Delete",
    0x0A: "Multiple_Service_Packet",
    0x0D: "Apply_Attributes",
    0x0E: "Get_Attribute_Single",
    0x10: "Set_Attribute_Single",
    0x11: "Find_Next_Object_Instance",
    0x15: "Restore",
    0x16: "Save",
    0x17: "Nop",
    0x18: "Get_Member",
    0x19: "Set_Member",
    0x1A: "Insert_Member",
    0x1B: "Remove_Member",
    0x1C: "Group_Sync",
    0x4C: "Recover",
    0x4E: "Perform_Diagnostics",
    0x4F: "Configure_Request",
    0x50: "Validate_Configuration",
    0x51: "Set_Password",
    0x52: "Configuration_Lock",
    0x53: "Mode_Change",
    0x54: "Safety_Reset",
    0x55: "Reset_Password",
    0x56: "Propose_TUNID",
    0x57: "Apply_TUNID",
    0x58: "Propose_TUNID_List",
    0x59: "Apply_TUNID_List",
}

# Security-relevant supervisor services (configuration changes, password ops)
SUPERVISOR_SECURITY_SERVICES = {
    0x4F,  # Configure_Request
    0x50,  # Validate_Configuration
    0x51,  # Set_Password
    0x52,  # Configuration_Lock
    0x53,  # Mode_Change
    0x54,  # Safety_Reset
    0x55,  # Reset_Password
    0x56,  # Propose_TUNID
    0x57,  # Apply_TUNID
    0x58,  # Propose_TUNID_List
    0x59,  # Apply_TUNID_List
}

# Safety Validator states
VALIDATOR_STATES = {
    0: "Idle",
    1: "Initializing",
    2: "Established",
    3: "Connection_Failed",
    4: "Faulted",
}

# Safety Supervisor device status
SUPERVISOR_STATUS = {
    0: "Uninitialized",
    1: "Self_Testing",
    2: "Idle",
    3: "Self_Testing_Exception",
    4: "Running",
    5: "Exception",
    6: "Abort",
    7: "Waiting_for_TUNID",
}


@dataclass
class CIPSafetySession:
    """Track CIP Safety session statistics."""

    client_ip: str
    server_ip: str
    safety_frames: int = 0
    crc_errors: int = 0
    supervisor_services: Set[str] = field(default_factory=set)
    validator_states: Set[str] = field(default_factory=set)
    security_events: int = 0
    password_operations: int = 0
    mode_changes: int = 0
    resets: int = 0
    first_seen: str = ""
    last_seen: str = ""


class CIPSafetyPassiveListener(PySharkListenerBase):
    """Passive CIP Safety traffic listener for industrial safety analysis.

    Captures CIP Safety protocol traffic to extract:
    - Safety data frames with mode byte, CRCs, and timestamps
    - Safety Supervisor configuration operations (TUNID, passwords, locks)
    - Safety Validator state transitions and fault counts
    - CRC validation status (integrity monitoring)
    - Security-relevant operations (password changes, mode changes, resets)

    CIP Safety runs on top of EtherNet/IP (or DeviceNet) and adds
    safety-integrity mechanisms for SIL 3 / PLe applications.

    Usage:
        listener = CIPSafetyPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()
    """

    PROTOCOL_NAME = "cipsafety"
    DISPLAY_FILTER = "cipsafety or cipssupervisor or cipsvalidator"
    REQUIRED_LAYERS = ("cipsafety", "cipssupervisor", "cipsvalidator")
    PROTOCOL_COLUMNS = ("operation", "run_idle", "crc_status", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.sessions: Dict[Tuple[str, str], CIPSafetySession] = {}
        self._alerts: List[Dict[str, str]] = []

    def process_packet(self, packet) -> None:
        """Process CIP Safety packet and extract safety data."""
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        src_port, dst_port = self.get_port_info(packet)
        flow_id = self.get_flow_id(packet)
        stream_id = self.get_stream_id(packet)
        now = datetime.now().isoformat()

        # Process CIP Safety base layer
        if hasattr(packet, "cipsafety"):
            self._process_safety_data(
                packet.cipsafety,
                src_ip,
                dst_ip,
                now,
                flow_id,
                src_port,
                dst_port,
                stream_id,
            )

        # Process CIP Safety Supervisor layer
        if hasattr(packet, "cipssupervisor"):
            self._process_supervisor(
                packet.cipssupervisor,
                src_ip,
                dst_ip,
                now,
                flow_id,
                src_port,
                dst_port,
                stream_id,
            )

        # Process CIP Safety Validator layer
        if hasattr(packet, "cipsvalidator"):
            self._process_validator(
                packet.cipsvalidator,
                src_ip,
                dst_ip,
                now,
                flow_id,
                src_port,
                dst_port,
                stream_id,
            )

    def _process_safety_data(
        self,
        layer,
        src_ip: str,
        dst_ip: str,
        now: str,
        flow_id: str = "",
        src_port: int = 0,
        dst_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Process CIP Safety base data frame."""
        mode_byte = self.get_field(layer, "mode_byte", None)
        run_idle = self.get_field(layer, "mode_byte_run_idle", None)
        ping_count = self.get_field(layer, "mode_byte_ping_count", None)
        timestamp = self.get_field(layer, "timestamp", None)
        msg_encoding = self.get_field(layer, "message_encoding", None)

        # CRC status fields
        crc_s1_status = self.get_field(layer, "crc_s1_status", None)
        crc_s2_status = self.get_field(layer, "crc_s2_status", None)
        crc_s3_status = self.get_field(layer, "crc_s3_status", None)
        complement_crc_s3_status = self.get_field(layer, "complement_crc_s3_status", None)

        # Multicast fields
        mcast_byte = self.get_field(layer, "mcast_byte", None)
        consumer_num = self.get_field(layer, "mcast_byte_consumer_num", None)
        mcast_active_idle = self.get_field(layer, "mcast_byte_active_idle", None)
        time_correction = self.get_field(layer, "time_correction", None)

        # Ack byte fields
        ack_byte = self.get_field(layer, "ack_byte", None)
        ping_response = self.get_field(layer, "ack_byte_ping_response", None)
        consumer_time = self.get_field(layer, "consumer_time_value", None)

        # Determine run/idle state
        run_idle_str = ""
        if run_idle is not None:
            run_idle_str = "RUN" if self._parse_bool(run_idle) else "IDLE"

        # Check CRC status
        crc_ok = True
        crc_detail = ""
        for crc_name, crc_stat in [
            ("S1", crc_s1_status),
            ("S2", crc_s2_status),
            ("S3", crc_s3_status),
            ("cS3", complement_crc_s3_status),
        ]:
            if crc_stat is not None:
                stat_val = self._parse_int(crc_stat, 0)
                if stat_val != 0:
                    crc_ok = False
                    crc_detail += f" CRC_{crc_name}=FAIL"

        crc_status = "OK" if crc_ok else "FAIL"

        details: Dict[str, Any] = {
            "frame_type": "safety_data",
        }
        if mode_byte is not None:
            details["mode_byte"] = str(mode_byte)
        if run_idle_str:
            details["run_idle"] = run_idle_str
        if ping_count is not None:
            details["ping_count"] = str(ping_count)
        if timestamp is not None:
            details["safety_timestamp"] = str(timestamp)
        if msg_encoding is not None:
            details["message_encoding"] = str(msg_encoding)
        if not crc_ok:
            details["crc_status"] = crc_status
            details["crc_detail"] = crc_detail.strip()
        if mcast_byte is not None:
            details["mcast_byte"] = str(mcast_byte)
        if consumer_num is not None:
            details["consumer_num"] = str(consumer_num)
        if mcast_active_idle is not None:
            details["mcast_active_idle"] = str(mcast_active_idle)
        if time_correction is not None:
            details["time_correction"] = str(time_correction)
        if ack_byte is not None:
            details["ack_byte"] = str(ack_byte)
        if ping_response is not None:
            details["ping_response"] = str(ping_response)
        if consumer_time is not None:
            details["consumer_time_value"] = str(consumer_time)

        operation = "Safety I/O"
        summary = f"Safety I/O {run_idle_str}" if run_idle_str else "Safety I/O"
        if not crc_ok:
            summary += f" [{crc_status}]"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            operation,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Update session
        session = self._get_session(src_ip, dst_ip, now)
        session.safety_frames += 1
        if not crc_ok:
            session.crc_errors += 1
            self._alerts.append(
                {
                    "level": "fail",
                    "category": "cipsafety_crc_error",
                    "message": (
                        f"CIP SAFETY CRC FAIL: {src_ip} -> {dst_ip}"
                        f"{crc_detail} (data integrity compromised)"
                    ),
                }
            )

        self._update_devices(src_ip, dst_ip)

    def _process_supervisor(
        self,
        layer,
        src_ip: str,
        dst_ip: str,
        now: str,
        flow_id: str = "",
        src_port: int = 0,
        dst_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Process CIP Safety Supervisor service."""
        # Supervisor object fields are dissected under the cipsafety.ssupervisor.*
        # filter prefix (the layer surfaces as ``cipssupervisor`` but its fields
        # keep the cipsafety prefix), so the fully-qualified name is what a real
        # capture exposes; the bare alias is kept as a fallback for fixtures.
        svc_raw = self.get_field_any(layer, "cipsafety.ssupervisor.sc", "sc")
        if svc_raw is None:
            # Try reading attribute fields directly (Get responses)
            self._process_supervisor_attributes(
                layer, src_ip, dst_ip, now, flow_id, src_port, dst_port, stream_id
            )
            return

        svc_code = self._parse_int(svc_raw, 0) & 0x7F  # Mask response bit
        is_response = bool(self._parse_int(svc_raw, 0) & 0x80)
        svc_name = SUPERVISOR_SERVICES.get(svc_code, f"Supervisor Svc 0x{svc_code:02x}")

        direction = "response" if is_response else "request"
        is_security_event = svc_code in SUPERVISOR_SECURITY_SERVICES

        details: Dict[str, Any] = {
            "frame_type": "supervisor",
            "service_code": svc_code,
            "service_name": svc_name,
            "security_event": is_security_event,
        }

        # Extract supervisor-specific fields
        if svc_code == 0x4F:  # Configure_Request
            tunid = self.get_field_any(
                layer, "cipsafety.ssupervisor.configure_request.tunid", "configure_request_tunid"
            )
            if tunid is not None:
                details["tunid"] = str(tunid)
            password = self.get_field_any(
                layer,
                "cipsafety.ssupervisor.configure_request.password",
                "configure_request_password",
            )
            if password is not None:
                details["has_password"] = True

        elif svc_code == 0x51:  # Set_Password
            details["has_password"] = True

        elif svc_code == 0x52:  # Configuration_Lock
            lock_val = self.get_field_any(
                layer, "cipsafety.ssupervisor.configure_lock.lock", "configure_lock_lock"
            )
            if lock_val is not None:
                details["lock_value"] = str(lock_val)

        elif svc_code == 0x53:  # Mode_Change
            mode_val = self.get_field_any(
                layer, "cipsafety.ssupervisor.mode_change.value", "mode_change_value"
            )
            if mode_val is not None:
                details["mode_value"] = str(mode_val)

        elif svc_code == 0x54:  # Safety_Reset
            reset_type = self.get_field_any(layer, "cipsafety.ssupervisor.reset.type", "reset_type")
            if reset_type is not None:
                details["reset_type"] = str(reset_type)

        # Extract device info fields when present
        mfg_name = self.get_field_any(
            layer, "cipsafety.ssupervisor.manufacture_name", "manufacture_name"
        )
        if mfg_name is not None:
            details["manufacturer_name"] = str(mfg_name)
        model_num = self.get_field_any(
            layer, "cipsafety.ssupervisor.manufacture_model_number", "manufacture_model_number"
        )
        if model_num is not None:
            details["model_number"] = str(model_num)
        serial_num = self.get_field_any(
            layer, "cipsafety.ssupervisor.manufacture_serial_number", "manufacture_serial_number"
        )
        if serial_num is not None:
            details["serial_number"] = str(serial_num)
        sw_rev = self.get_field_any(layer, "cipsafety.ssupervisor.sw_rev_level", "sw_rev_level")
        if sw_rev is not None:
            details["sw_revision"] = str(sw_rev)
        hw_rev = self.get_field_any(layer, "cipsafety.ssupervisor.hw_rev_level", "hw_rev_level")
        if hw_rev is not None:
            details["hw_revision"] = str(hw_rev)
        dev_status = self.get_field_any(
            layer, "cipsafety.ssupervisor.device_status", "device_status"
        )
        if dev_status is not None:
            status_val = self._parse_int(dev_status, -1)
            status_name = SUPERVISOR_STATUS.get(status_val, str(dev_status))
            details["device_status"] = status_name
        config_lock = self.get_field_any(
            layer, "cipsafety.ssupervisor.configuration_lock", "configuration_lock"
        )
        if config_lock is not None:
            details["configuration_lock"] = str(config_lock)

        summary = f"Supervisor {svc_name}"
        if is_security_event:
            summary = f"[SECURITY] Supervisor {svc_name}"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            f"Supervisor {svc_name}",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Update session and track security events
        if is_response:
            session = self._get_session(dst_ip, src_ip, now)
        else:
            session = self._get_session(src_ip, dst_ip, now)
        session.supervisor_services.add(svc_name)

        if is_security_event and not is_response:
            session.security_events += 1
            if svc_code in (0x51, 0x55):  # Password operations (Set/Reset_Password)
                session.password_operations += 1
            if svc_code == 0x53:  # Mode change
                session.mode_changes += 1
            if svc_code == 0x54:  # Reset (Safety_Reset)
                session.resets += 1

            self._alerts.append(
                {
                    "level": "fail",
                    "category": "cipsafety_security_event",
                    "message": (
                        f"CIP SAFETY SECURITY: {src_ip} -> {dst_ip} "
                        f"{svc_name} (safety supervisor configuration change)"
                    ),
                }
            )

        self._update_devices(src_ip, dst_ip, details)

    def _process_supervisor_attributes(
        self,
        layer,
        src_ip: str,
        dst_ip: str,
        now: str,
        flow_id: str = "",
        src_port: int = 0,
        dst_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Process supervisor attribute data (Get responses without service code)."""
        details: Dict[str, Any] = {"frame_type": "supervisor_attr"}

        mfg_name = self.get_field_any(
            layer, "cipsafety.ssupervisor.manufacture_name", "manufacture_name"
        )
        if mfg_name is not None:
            details["manufacturer_name"] = str(mfg_name)
        model_num = self.get_field_any(
            layer, "cipsafety.ssupervisor.manufacture_model_number", "manufacture_model_number"
        )
        if model_num is not None:
            details["model_number"] = str(model_num)
        serial_num = self.get_field_any(
            layer, "cipsafety.ssupervisor.manufacture_serial_number", "manufacture_serial_number"
        )
        if serial_num is not None:
            details["serial_number"] = str(serial_num)
        dev_status = self.get_field_any(
            layer, "cipsafety.ssupervisor.device_status", "device_status"
        )
        if dev_status is not None:
            status_val = self._parse_int(dev_status, -1)
            details["device_status"] = SUPERVISOR_STATUS.get(status_val, str(dev_status))

        if len(details) <= 1:
            return  # No meaningful attributes found

        summary_parts = []
        if "manufacturer_name" in details:
            summary_parts.append(details["manufacturer_name"])
        if "model_number" in details:
            summary_parts.append(details["model_number"])
        if "device_status" in details:
            summary_parts.append(f"status={details['device_status']}")

        summary = "Supervisor " + " ".join(summary_parts)

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "response",
            "Supervisor Attributes",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )
        self._update_devices(src_ip, dst_ip, details)

    def _process_validator(
        self,
        layer,
        src_ip: str,
        dst_ip: str,
        now: str,
        flow_id: str = "",
        src_port: int = 0,
        dst_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Process CIP Safety Validator service."""
        # Validator object fields are dissected under cipsafety.svalidator.*;
        # the fully-qualified name is what a real capture exposes, with the bare
        # alias kept as a fixture fallback.
        svc_raw = self.get_field_any(layer, "cipsafety.svalidator.sc", "sc")
        svc_val = self._parse_int(svc_raw, 0) if svc_raw is not None else 0
        is_response = bool(svc_val & 0x80)
        direction = "response" if is_response else "request"

        state_raw = self.get_field_any(layer, "cipsafety.svalidator.state", "state")
        state_val = self._parse_int(state_raw, -1) if state_raw is not None else -1
        state_name = (
            VALIDATOR_STATES.get(state_val, f"Unknown({state_val})") if state_val >= 0 else ""
        )

        validator_type = self.get_field_any(layer, "cipsafety.svalidator.type", "type")
        pc_flag = self.get_field_any(layer, "cipsafety.svalidator.type.pc", "type_pc")
        conn_type = self.get_field_any(
            layer, "cipsafety.svalidator.type.conn_type", "type_conn_type"
        )
        fault_count = self.get_field_any(
            layer, "cipsafety.svalidator.sconn_fault_count", "sconn_fault_count"
        )
        ping_epi = self.get_field_any(layer, "cipsafety.svalidator.ping_epi", "ping_epi")
        data_conn_inst = self.get_field_any(
            layer, "cipsafety.svalidator.data_conn_inst", "data_conn_inst"
        )
        max_consumer = self.get_field_any(
            layer, "cipsafety.svalidator.max_consumer_num", "max_consumer_num"
        )
        max_data_age = self.get_field_any(
            layer, "cipsafety.svalidator.max_data_age", "max_data_age"
        )
        error_code = self.get_field_any(layer, "cipsafety.svalidator.error_code", "error_code")

        details: Dict[str, Any] = {"frame_type": "validator"}
        if state_name:
            details["validator_state"] = state_name
        if validator_type is not None:
            details["validator_type"] = str(validator_type)
        if pc_flag is not None:
            details["producer_consumer"] = "Producer" if self._parse_bool(pc_flag) else "Consumer"
        if conn_type is not None:
            details["conn_type"] = str(conn_type)
        if fault_count is not None:
            details["fault_count"] = str(fault_count)
        if ping_epi is not None:
            details["ping_epi"] = str(ping_epi)
        if data_conn_inst is not None:
            details["data_conn_inst"] = str(data_conn_inst)
        if max_consumer is not None:
            details["max_consumer_num"] = str(max_consumer)
        if max_data_age is not None:
            details["max_data_age"] = str(max_data_age)
        if error_code is not None:
            details["error_code"] = str(error_code)

        operation = f"Validator {state_name}" if state_name else "Validator"
        summary = operation
        if fault_count is not None:
            fc = self._parse_int(fault_count, 0)
            if fc > 0:
                summary += f" faults={fc}"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            operation,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Track validator states
        if is_response:
            session = self._get_session(dst_ip, src_ip, now)
        else:
            session = self._get_session(src_ip, dst_ip, now)
        if state_name:
            session.validator_states.add(state_name)

        # Alert on fault states
        if state_val in (3, 4):  # Connection_Failed or Faulted
            self._alerts.append(
                {
                    "level": "fail",
                    "category": "cipsafety_validator_fault",
                    "message": (
                        f"CIP SAFETY VALIDATOR FAULT: {src_ip} -> {dst_ip} "
                        f"state={state_name} "
                        f"(safety connection may be compromised)"
                    ),
                }
            )

        # Alert on high fault counts
        if fault_count is not None:
            fc = self._parse_int(fault_count, 0)
            if fc > 10:
                self._alerts.append(
                    {
                        "level": "fail",
                        "category": "cipsafety_high_fault_count",
                        "message": (
                            f"CIP SAFETY HIGH FAULTS: {src_ip} -> {dst_ip} "
                            f"fault_count={fc} "
                            f"(possible attack or hardware failure)"
                        ),
                    }
                )

        self._update_devices(src_ip, dst_ip, details)

    # ------------------------------------------------------------------
    # Session tracking
    # ------------------------------------------------------------------

    def _get_session(self, client_ip: str, server_ip: str, now: str) -> CIPSafetySession:
        """Get or create a session."""
        key = (client_ip, server_ip)
        if key not in self.sessions:
            self.sessions[key] = CIPSafetySession(
                client_ip=client_ip,
                server_ip=server_ip,
                first_seen=now,
                last_seen=now,
            )
        session = self.sessions[key]
        session.last_seen = now
        return session

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    def _update_devices(
        self,
        src_ip: str,
        dst_ip: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Update device entries for CIP Safety endpoints."""
        for ip in (src_ip, dst_ip):
            if not is_valid_discovered_ip(ip):
                continue
            device_key = f"cipsafety:{ip}"
            name = f"CIP Safety Device ({ip})"
            if details:
                mfg = details.get("manufacturer_name", "")
                model = details.get("model_number", "")
                if mfg or model:
                    name = f"{mfg} {model}".strip() or name

            device, is_new = self._ensure_device(
                device_key,
                ip,
                name=name,
                device_type="CIP Safety Device",
            )
            if is_new:
                device.cipsafety_passive_data = {"protocol": "CIP Safety/EtherNet/IP"}

    # ------------------------------------------------------------------
    # Formatting
    # ------------------------------------------------------------------

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        frame_type = d.get("frame_type", "")

        if frame_type == "safety_data":
            operation = "Safety I/O"
            run_idle = d.get("run_idle", "")
            crc_status = d.get("crc_status", "OK")
            detail = d.get("crc_detail", "")
        elif frame_type in ("supervisor", "supervisor_attr"):
            operation = d.get("service_name", "Supervisor")
            run_idle = ""
            crc_status = ""
            detail_parts = []
            if d.get("device_status"):
                detail_parts.append(f"status={d['device_status']}")
            if d.get("manufacturer_name"):
                detail_parts.append(d["manufacturer_name"])
            if d.get("security_event"):
                detail_parts.append("[SECURITY]")
            detail = " ".join(detail_parts)
        elif frame_type == "validator":
            operation = "Validator"
            run_idle = ""
            crc_status = ""
            detail_parts = []
            if d.get("validator_state"):
                detail_parts.append(f"state={d['validator_state']}")
            if d.get("fault_count"):
                fc = self._parse_int(d["fault_count"], 0)
                if fc > 0:
                    detail_parts.append(f"faults={fc}")
            detail = " ".join(detail_parts)
        else:
            operation = ix.operation
            run_idle = ""
            crc_status = ""
            detail = ""

        return [operation, run_idle, crc_status, detail]

    # ------------------------------------------------------------------
    # Harvest
    # ------------------------------------------------------------------

    def harvest(self) -> Dict[str, Any]:
        """Return harvest data with CIP Safety-specific alerts."""
        result = super().harvest()
        if not result and not self._alerts:
            return {}
        if not result:
            result = {"tables": [], "alerts": []}
        if self._alerts:
            result.setdefault("alerts", []).extend(self._alerts)
        return result

    def get_sessions_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all observed CIP Safety sessions."""
        return [
            {
                "client": s.client_ip,
                "server": s.server_ip,
                "safety_frames": s.safety_frames,
                "crc_errors": s.crc_errors,
                "supervisor_services": sorted(s.supervisor_services),
                "validator_states": sorted(s.validator_states),
                "security_events": s.security_events,
                "password_operations": s.password_operations,
                "mode_changes": s.mode_changes,
                "resets": s.resets,
            }
            for s in self.sessions.values()
        ]

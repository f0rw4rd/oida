"""
Beckhoff ADS/AMS Passive Listener (PyShark-based).

Passively monitors Beckhoff ADS (Automation Device Specification) traffic
over AMS (Automation Message Specification) to identify:
- ADS servers (TwinCAT PLCs) and clients (HMIs, engineering tools)
- AMS Net IDs and port numbers in use
- ADS command types (Read, Write, ReadDeviceInfo, ReadState, etc.)
- Index Group / Index Offset access patterns
- Write operations (potentially dangerous in ICS environments)
- Device information from ReadDeviceInfo responses (device name, version)

Based on Beckhoff ADS/AMS protocol specification.

Protocol format:
- AMS Header: Target NetID (6B) + Target Port (2B) + Source NetID (6B) +
  Source Port (2B) + Command ID (2B) + State Flags (2B) + Data Length (4B) +
  Error Code (4B) + Invoke ID (4B)
- ADS Data: Varies by command (Index Group, Index Offset, Length, payload)

tshark fields used:
- ams.targetnetid: Target AMS Net ID (string, e.g. "5.80.192.37.1.1")
- ams.targetport: Target AMS port (uint16)
- ams.sendernetid: Source AMS Net ID
- ams.senderport: Source AMS port (uint16)
- ams.cmdid: ADS command ID (uint16)
- ams.stateflags: State flags (uint16, bit 0 = response)
- ams.state_response: Response flag (bool)
- ams.errorcode: AMS error code (uint32)
- ams.cbdata: Data length (uint32)
- ams.invokeid: Invoke ID for request/response correlation (uint32)
- ams.ads_indexgroup: ADS Index Group (uint32)
- ams.ads_indexoffset: ADS Index Offset (uint32)
- ams.ads_cblength: Read/Write length (uint32)
- ams.ads_cbreadlength: ReadWrite read length (uint32)
- ams.ads_cbwritelength: ReadWrite write length (uint32)
- ams.adsresult: ADS result/error code (uint32)
- ams.ads_state: ADS state (uint16)
- ams.ads_devicestate: Device state (uint16)
- ams.ads_devicename: Device name from ReadDeviceInfo (string)
- ams.ads_versionversion: Major version (uint8)
- ams.ads_versionrevision: Minor version (uint8)
- ams.ads_versionbuild: Build number (uint16)
- ams.ads_notificationhandle: Notification handle (uint32)
- ams.ads_transmode: Notification transmission mode (uint32)
- ams.ads_cycletime: Notification cycle time (uint32)
- ams.ads_maxdelay: Notification max delay (uint32)

References:
- Beckhoff ADS/AMS specification
- Wireshark dissector: packet-ams.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from oida.pcap.pyshark_base import ProtocolInteraction, PySharkListenerBase
from oida.protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor
from oida.protocols.ads.constants import (
    ADS_COMMANDS,
    ADS_ERROR_CODES,
    ADS_IDX_GRP_NAMES,
    ADS_STATE_MAP,
    AMS_PORT_NAMES,
    READ_COMMAND_IDS,
    WRITE_COMMAND_IDS,
)

import logging

logger = logging.getLogger(__name__)


@dataclass
class ADSSession:
    """Track ADS/AMS session statistics."""

    client_ip: str
    server_ip: str
    client_netid: str = ""
    server_netid: str = ""
    client_ports: Set[int] = field(default_factory=set)
    server_ports: Set[int] = field(default_factory=set)
    commands_seen: Set[int] = field(default_factory=set)
    index_groups: Set[int] = field(default_factory=set)
    write_count: int = 0
    read_count: int = 0
    device_name: str = ""
    device_version: str = ""
    first_seen: str = ""
    last_seen: str = ""


class ADSPassiveListener(PySharkListenerBase):
    """Passive Beckhoff ADS/AMS traffic listener (PyShark-based).

    Monitors ADS/AMS traffic without sending packets to:
    - Identify ADS servers (TwinCAT PLCs) and clients (HMIs/engineering)
    - Track AMS Net IDs and port numbers
    - Monitor ADS commands (Read, Write, ReadState, ReadDeviceInfo, etc.)
    - Map Index Group / Index Offset access patterns
    - Extract device information from ReadDeviceInfo responses
    - Detect write and control operations

    Uses PyShark/tshark for AMS protocol dissection.

    Usage:
        listener = ADSPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for session in listener.sessions.values():
            print(f"{session.client_ip} -> {session.server_ip}")
            print(f"  Server NetID: {session.server_netid}")
            print(f"  Commands: {session.commands_seen}")
            print(f"  Writes: {session.write_count}")

    Data stored in device.ads_passive_data:
        {
            "role": "server" | "client",
            "ams_netid": "5.80.192.37.1.1",
            "ams_ports": [851],
            "commands_seen": [1, 2, 3],
            "command_names": ["ReadDeviceInfo", "Read", "Write"],
            "index_groups": ["0x4020", ...],
            "write_operations": 5,
            "read_operations": 10,
            "device_name": "CX-12345",
            "device_version": "3.1.4024",
            "protocol": "ADS/AMS",
        }
    """

    PROTOCOL_NAME = "ads"
    DISPLAY_FILTER = "ams"
    REQUIRED_LAYERS = ("ams",)
    PROTOCOL_COLUMNS = (
        "rw",
        "operation",
        "invoke_id",
        "target_netid",
        "target_port",
        "target_port_name",
        "sender_netid",
        "sender_port",
        "sender_port_name",
        "index_group",
        "index_group_name",
        "index_offset",
        "length",
        "data",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        """Initialize ADS passive listener."""
        super().__init__(interface, timeout, nxc_logger)
        self.sessions: Dict[Tuple[str, str], ADSSession] = {}

    def process_packet(self, packet) -> None:
        """Process ADS/AMS packet using PyShark dissection."""
        if not hasattr(packet, "ams"):
            return

        ams_layer = packet.ams

        # Get IP info
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)

        # Get MAC addresses
        src_mac, dst_mac = self.get_mac_info(packet)

        # Extract AMS header fields
        target_netid = str(self.get_field(ams_layer, "targetnetid", "") or "")
        target_port_raw = self.get_field(ams_layer, "targetport", None)
        sender_netid = str(self.get_field(ams_layer, "sendernetid", "") or "")
        sender_port_raw = self.get_field(ams_layer, "senderport", None)
        cmd_id_raw = self.get_field(ams_layer, "cmdid", None)
        error_code_raw = self.get_field(ams_layer, "errorcode", None)
        invoke_id_raw = self.get_field(ams_layer, "invokeid", None)

        # Parse command ID
        cmd_id = self._parse_int(cmd_id_raw, default=None)
        if cmd_id is None:
            return

        # Parse ports
        target_port = self._parse_int(target_port_raw, default=None) or 0
        sender_port = self._parse_int(sender_port_raw, default=None) or 0

        # Parse invoke ID (for request/response correlation)
        invoke_id = self._parse_int(invoke_id_raw, default=None)

        # Parse AMS-level data length (cbdata)
        cbdata_raw = self.get_field(ams_layer, "cbdata", None)
        cbdata = self._parse_int(cbdata_raw, default=None)

        # Determine direction: bit 0 of state flags = response
        is_response = False
        state_resp = self.get_field(ams_layer, "state_response", None)
        if state_resp is not None:
            is_response = str(state_resp) in ("True", "1")
        else:
            stateflags_raw = self.get_field(ams_layer, "stateflags", None)
            stateflags = self._parse_int(stateflags_raw, default=None)
            if stateflags is not None:
                is_response = bool(stateflags & 0x01)

        # Determine client/server roles:
        # Request: sender=client, target=server
        # Response: sender=server, target=client
        # DeviceNotification (cmd 0x0008) is an unsolicited server->client push
        # with the response bit NOT set, so the sender is the server (PLC)
        # regardless of the response bit -- otherwise the PLC is mislabeled as
        # the client and the conversation is split into two role-reversed halves.
        sender_is_server = is_response or cmd_id == 0x0008
        if sender_is_server:
            client_ip = dst_ip
            server_ip = src_ip
            client_mac = dst_mac
            server_mac = src_mac
            client_netid = target_netid
            server_netid = sender_netid
            client_port = target_port
            server_port = sender_port
        else:
            client_ip = src_ip
            server_ip = dst_ip
            client_mac = src_mac
            server_mac = dst_mac
            client_netid = sender_netid
            server_netid = target_netid
            client_port = sender_port
            server_port = target_port

        # Parse error code
        error_code = self._parse_int(error_code_raw, default=None) or 0

        # Extract command-specific data
        cmd_name = ADS_COMMANDS.get(cmd_id, f"Cmd 0x{cmd_id:04x}")
        index_group = None
        index_offset = None
        data_length = None
        extra_details: Dict[str, Any] = {}

        if cmd_id in (0x0002, 0x0003, 0x0009):
            # Read, Write, ReadWrite: have Index Group / Index Offset
            ig_raw = self.get_field(ams_layer, "ads_indexgroup", None)
            io_raw = self.get_field(ams_layer, "ads_indexoffset", None)
            index_group = self._parse_int(ig_raw, default=None)
            index_offset = self._parse_int(io_raw, default=None)

            # Data length
            if cmd_id == 0x0002:
                # Read: cblength in request, adsresult + data in response
                length_raw = self.get_field(ams_layer, "ads_cblength", None)
                data_length = self._parse_int(length_raw, default=None)
            elif cmd_id == 0x0003:
                # Write: cblength
                length_raw = self.get_field(ams_layer, "ads_cblength", None)
                data_length = self._parse_int(length_raw, default=None)
            elif cmd_id == 0x0009:
                # ReadWrite: separate read and write lengths
                rl = self._parse_int(
                    self.get_field(ams_layer, "ads_cbreadlength", None), default=None
                )
                wl = self._parse_int(
                    self.get_field(ams_layer, "ads_cbwritelength", None), default=None
                )
                if rl is not None:
                    extra_details["read_length"] = rl
                if wl is not None:
                    extra_details["write_length"] = wl
                data_length = rl or wl

        elif cmd_id == 0x0001:
            # ReadDeviceInfo response: extract device name and version
            if is_response:
                dev_name = str(self.get_field(ams_layer, "ads_devicename", "") or "").strip()
                major = self._parse_int(
                    self.get_field(ams_layer, "ads_versionversion", None), default=None
                )
                minor = self._parse_int(
                    self.get_field(ams_layer, "ads_versionrevision", None), default=None
                )
                build = self._parse_int(
                    self.get_field(ams_layer, "ads_versionbuild", None), default=None
                )

                if dev_name:
                    extra_details["device_name"] = dev_name
                if major is not None and minor is not None:
                    version = f"{major}.{minor}"
                    if build is not None:
                        version += f".{build}"
                    extra_details["device_version"] = version

        elif cmd_id == 0x0004:
            # ReadState response: ADS state and device state
            if is_response:
                ads_state = self._parse_int(
                    self.get_field(ams_layer, "ads_state", None), default=None
                )
                dev_state = self._parse_int(
                    self.get_field(ams_layer, "ads_devicestate", None), default=None
                )
                if ads_state is not None:
                    state_name = ADS_STATE_MAP.get(ads_state, f"0x{ads_state:04x}")
                    extra_details["ads_state"] = state_name
                if dev_state is not None:
                    extra_details["device_state"] = dev_state

        elif cmd_id == 0x0005:
            # WriteControl: ADS state + device state + data length
            ads_state = self._parse_int(self.get_field(ams_layer, "ads_state", None), default=None)
            dev_state = self._parse_int(
                self.get_field(ams_layer, "ads_devicestate", None), default=None
            )
            length_raw = self.get_field(ams_layer, "ads_cblength", None)
            data_length = self._parse_int(length_raw, default=None)
            if ads_state is not None:
                state_name = ADS_STATE_MAP.get(ads_state, f"0x{ads_state:04x}")
                extra_details["ads_state"] = state_name
            if dev_state is not None:
                extra_details["device_state"] = dev_state

        elif cmd_id == 0x0006:
            # AddDeviceNotification: index group/offset + trans mode + cycle time
            ig_raw = self.get_field(ams_layer, "ads_indexgroup", None)
            io_raw = self.get_field(ams_layer, "ads_indexoffset", None)
            index_group = self._parse_int(ig_raw, default=None)
            index_offset = self._parse_int(io_raw, default=None)
            length_raw = self.get_field(ams_layer, "ads_cblength", None)
            data_length = self._parse_int(length_raw, default=None)

            trans_mode = self._parse_int(
                self.get_field(ams_layer, "ads_transmode", None), default=None
            )
            cycle_time = self._parse_int(
                self.get_field(ams_layer, "ads_cycletime", None), default=None
            )
            max_delay = self._parse_int(
                self.get_field(ams_layer, "ads_maxdelay", None), default=None
            )
            if trans_mode is not None:
                extra_details["trans_mode"] = trans_mode
            if cycle_time is not None:
                extra_details["cycle_time_ms"] = cycle_time
            if max_delay is not None:
                extra_details["max_delay_ms"] = max_delay

        elif cmd_id == 0x0007:
            # DeleteDeviceNotification
            handle = self._parse_int(
                self.get_field(ams_layer, "ads_notificationhandle", None), default=None
            )
            if handle is not None:
                extra_details["notification_handle"] = handle

        elif cmd_id == 0x0008:
            # DeviceNotification (push from server)
            stamps = self._parse_int(
                self.get_field(ams_layer, "ads_noteblocksstamps", None), default=None
            )
            if stamps is not None:
                extra_details["stamp_count"] = stamps

        # ADS result code (in responses)
        if is_response:
            ads_result = self._parse_int(self.get_field(ams_layer, "adsresult", None), default=None)
            if ads_result is not None and ads_result != 0:
                extra_details["ads_result"] = ads_result
                extra_details["ads_result_name"] = ADS_ERROR_CODES.get(
                    ads_result, f"0x{ads_result:04x}"
                )

        # Extract data payload as hex from tcp.payload
        data_hex = self._extract_data_hex(packet, cmd_id, is_response)
        if data_hex:
            extra_details["data_hex"] = data_hex

        # Classify as read or write
        if cmd_id in WRITE_COMMAND_IDS:
            rw = "write"
        elif cmd_id in READ_COMMAND_IDS:
            rw = "read"
        elif cmd_id in (0x0006, 0x0007, 0x0008):
            rw = "notify"
        else:
            rw = ""

        # Build details dict. An unsolicited DeviceNotification push (cmd 0x0008)
        # is server-initiated even without the response bit set, so force
        # notify/response direction rather than mislabelling it a client request.
        if cmd_id == 0x0008:
            direction = "response"
        else:
            direction = "response" if is_response else "request"
        now = datetime.now().isoformat()

        details: Dict[str, Any] = {
            "command_id": cmd_id,
            "command_name": cmd_name,
            "rw": rw,
            "target_netid": target_netid,
            "target_port": target_port,
            "target_port_name": AMS_PORT_NAMES.get(target_port, ""),
            "sender_netid": sender_netid,
            "sender_port": sender_port,
            "sender_port_name": AMS_PORT_NAMES.get(sender_port, ""),
        }
        if invoke_id is not None:
            details["invoke_id"] = invoke_id

        # Decode AMS per-bit state flags. tshark exposes each bit as its own
        # boolean field (ams.state_noreturn, .state_adscmd, ...). Collect the
        # names of bits that are set so triage can grep e.g. state_broadcast.
        state_flag_names = (
            "state_noreturn",
            "state_adscmd",
            "state_syscmd",
            "state_highprio",
            "state_timestampadded",
            "state_udp",
            "state_initcmd",
            "state_broadcast",
        )
        active_flags = []
        for flag in state_flag_names:
            raw = self.get_field(ams_layer, flag, None)
            if raw is not None and str(raw) in ("True", "1", "true"):
                active_flags.append(flag)
        if active_flags:
            details["state_flags"] = active_flags

        if index_group is not None:
            details["index_group"] = f"0x{index_group:04X}"
            details["index_group_name"] = ADS_IDX_GRP_NAMES.get(index_group, "")
        if index_offset is not None:
            details["index_offset"] = f"0x{index_offset:08X}"
        if data_length is not None:
            details["length"] = data_length
        if cbdata is not None:
            details["cbdata"] = cbdata
        if error_code:
            details["ams_error"] = error_code
        details.update(extra_details)

        # Build summary
        summary = self._build_summary(
            cmd_name,
            index_group,
            index_offset,
            data_length,
            is_response,
            extra_details,
        )

        src_port, dst_port = self.get_port_info(packet)
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            cmd_name,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        # Update session
        session_key = (client_ip, server_ip)
        self._update_session(
            session_key,
            cmd_id,
            index_group,
            is_response,
            client_netid,
            server_netid,
            client_port,
            server_port,
            extra_details,
        )

        # Update devices
        self._update_devices(
            client_ip,
            client_mac,
            server_ip,
            server_mac,
            session_key,
        )

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_data_hex(packet, cmd_id: int, is_response: bool) -> str:
        """Extract ADS data payload as hex from tcp.payload.

        tshark's ams.ads_data is FT_NONE (no value in JSON/EK), so we slice
        the raw TCP payload using known AMS wire format offsets.
        """
        if not hasattr(packet, "tcp"):
            return ""
        raw = getattr(packet.tcp, "payload", None)
        if not raw:
            return ""
        try:
            if isinstance(raw, (bytes, bytearray)):
                payload = bytes(raw)
            else:
                raw_str = str(raw)
                # EK mode: repr'd bytes literal "b'\\x00\\x00...'"
                if raw_str.startswith("b'") or raw_str.startswith('b"'):
                    import ast

                    payload = ast.literal_eval(raw_str)
                else:
                    # XML/PDML mode: colon-separated hex "00:00:2c:..."
                    payload = bytes.fromhex(raw_str.replace(":", ""))
        except (ValueError, AttributeError, SyntaxError) as e:
            logger.debug(f"ADS: failed to decode raw TCP payload to bytes: {e}")
            return ""

        # AMS/TCP header: reserved(2) + length(4) + AMS_header(32) = 38 bytes
        BASE = 38

        # Wire format per command (offsets relative to BASE=38):
        #   Read Resp:         result(4) + cblength(4) + data
        #   Write Req:         ig(4) + io(4) + cblength(4) + data
        #   WriteControl Req:  state(2) + devstate(2) + cblength(4) + data
        #   ReadWrite Req:     ig(4) + io(4) + cbreadlen(4) + cbwritelen(4) + data
        #   ReadWrite Resp:    result(4) + cblength(4) + data
        #   DeviceNotif Req:   cblength(4) + nstamps(4) + stamp_data
        if cmd_id == 0x0002 and is_response:
            # Read Response: result(4) + cblength(4) + data
            if len(payload) < BASE + 8:
                return ""
            cblength = int.from_bytes(payload[BASE + 4 : BASE + 8], "little")
            data_off = BASE + 8
        elif cmd_id == 0x0003 and not is_response:
            # Write Request: ig(4) + io(4) + cblength(4) + data
            if len(payload) < BASE + 12:
                return ""
            cblength = int.from_bytes(payload[BASE + 8 : BASE + 12], "little")
            data_off = BASE + 12
        elif cmd_id == 0x0005 and not is_response:
            # WriteControl Request: state(2) + devstate(2) + cblength(4) + data
            if len(payload) < BASE + 8:
                return ""
            cblength = int.from_bytes(payload[BASE + 4 : BASE + 8], "little")
            data_off = BASE + 8
        elif cmd_id == 0x0008 and not is_response:
            # DeviceNotification: cblength(4) + nstamps(4) + stamp_data
            if len(payload) < BASE + 8:
                return ""
            cblength = int.from_bytes(payload[BASE : BASE + 4], "little")
            data_off = BASE + 4  # include nstamps + stamp blocks
        elif cmd_id == 0x0009 and not is_response:
            # ReadWrite Request: ig(4) + io(4) + cbreadlen(4) + cbwritelen(4) + data
            if len(payload) < BASE + 16:
                return ""
            cblength = int.from_bytes(payload[BASE + 12 : BASE + 16], "little")
            data_off = BASE + 16
        elif cmd_id == 0x0009 and is_response:
            # ReadWrite Response: result(4) + cblength(4) + data
            if len(payload) < BASE + 8:
                return ""
            cblength = int.from_bytes(payload[BASE + 4 : BASE + 8], "little")
            data_off = BASE + 8
        else:
            return ""

        if cblength == 0:
            return ""
        end = min(data_off + cblength, len(payload))
        data = payload[data_off:end]
        if not data:
            return ""
        return data.hex()

    # ------------------------------------------------------------------
    # Summary and formatting
    # ------------------------------------------------------------------

    def _build_summary(
        self,
        cmd_name: str,
        index_group: Optional[int],
        index_offset: Optional[int],
        data_length: Optional[int],
        is_response: bool,
        extra: Dict[str, Any],
    ) -> str:
        """Build a one-line human-readable interaction summary."""
        parts = [cmd_name]

        if is_response:
            ads_result = extra.get("ads_result")
            if ads_result:
                result_name = extra.get("ads_result_name", f"0x{ads_result:04x}")
                parts.append(f"err={result_name}")

        if index_group is not None:
            ig_name = ADS_IDX_GRP_NAMES.get(index_group, "")
            if ig_name:
                parts.append(f"IG={ig_name}")
            else:
                parts.append(f"IG=0x{index_group:04X}")

        if index_offset is not None:
            parts.append(f"IO=0x{index_offset:04X}")

        if data_length is not None:
            parts.append(f"len={data_length}")

        dev_name = extra.get("device_name")
        if dev_name:
            parts.append(f'"{dev_name}"')

        dev_version = extra.get("device_version")
        if dev_version:
            parts.append(f"v{dev_version}")

        ads_state = extra.get("ads_state")
        if ads_state:
            parts.append(f"state={ads_state}")

        return " ".join(parts)

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format a single interaction as a table row matching PROTOCOL_COLUMNS."""
        d = ix.details

        # R/W column
        rw = d.get("rw", "")

        # Operation column
        operation = d.get("command_name", ix.operation)

        # Invoke ID column (for request/response correlation)
        inv_id = d.get("invoke_id")
        inv_id_str = str(inv_id) if inv_id is not None else ""

        # Target NetID / Port columns
        t_netid = d.get("target_netid", "")
        t_port = d.get("target_port", 0)
        t_port_str = str(t_port) if t_port else ""
        t_port_name = d.get("target_port_name", "")

        # Sender NetID / Port columns
        s_netid = d.get("sender_netid", "")
        s_port = d.get("sender_port", 0)
        s_port_str = str(s_port) if s_port else ""
        s_port_name = d.get("sender_port_name", "")

        # Index Group column (already hex string in details)
        ig_str = d.get("index_group", "")
        ig_name = d.get("index_group_name", "")

        # Index Offset column (already hex string in details)
        io_str = d.get("index_offset", "")

        # Length column
        length = d.get("length", "")
        if length == "":
            # Try read_length / write_length for ReadWrite
            rl = d.get("read_length")
            wl = d.get("write_length")
            if rl is not None and wl is not None:
                length = f"r{rl}/w{wl}"
            elif rl is not None:
                length = f"r{rl}"
            elif wl is not None:
                length = f"w{wl}"

        # Data column: device info, state, errors, notification details
        data_parts: List[str] = []

        ads_result = d.get("ads_result")
        if ads_result:
            result_name = d.get("ads_result_name", f"0x{ads_result:04x}")
            data_parts.append(f"err={result_name}")

        dev_name = d.get("device_name")
        if dev_name:
            data_parts.append(dev_name)

        dev_version = d.get("device_version")
        if dev_version:
            data_parts.append(f"v{dev_version}")

        ads_state = d.get("ads_state")
        if ads_state:
            data_parts.append(f"state={ads_state}")

        device_state = d.get("device_state")
        if device_state is not None:
            data_parts.append(f"devstate={device_state}")

        handle = d.get("notification_handle")
        if handle is not None:
            data_parts.append(f"handle=0x{handle:08X}")

        stamp_count = d.get("stamp_count")
        if stamp_count is not None:
            data_parts.append(f"stamps={stamp_count}")

        trans_mode = d.get("trans_mode")
        if trans_mode is not None:
            data_parts.append(f"mode={trans_mode}")

        cycle_time = d.get("cycle_time_ms")
        if cycle_time is not None:
            data_parts.append(f"cycle={cycle_time}ms")

        ams_error = d.get("ams_error")
        if ams_error:
            data_parts.append(f"ams_err=0x{ams_error:04X}")

        data_hex = d.get("data_hex")
        if data_hex:
            data_parts.append(data_hex)

        data_str = ", ".join(data_parts)

        return [
            rw,
            operation,
            inv_id_str,
            t_netid,
            t_port_str,
            t_port_name,
            s_netid,
            s_port_str,
            s_port_name,
            ig_str,
            ig_name,
            io_str,
            length,
            data_str,
        ]

    # ------------------------------------------------------------------
    # Session tracking
    # ------------------------------------------------------------------

    def _update_session(
        self,
        session_key: Tuple[str, str],
        cmd_id: int,
        index_group: Optional[int],
        is_response: bool,
        client_netid: str,
        server_netid: str,
        client_port: int,
        server_port: int,
        extra: Dict[str, Any],
    ) -> None:
        """Update session statistics."""
        now = datetime.now().isoformat()
        client_ip, server_ip = session_key

        if session_key not in self.sessions:
            self.sessions[session_key] = ADSSession(
                client_ip=client_ip,
                server_ip=server_ip,
                first_seen=now,
                last_seen=now,
            )

        session = self.sessions[session_key]
        session.last_seen = now
        session.commands_seen.add(cmd_id)

        if client_netid:
            session.client_netid = client_netid
        if server_netid:
            session.server_netid = server_netid
        if client_port:
            session.client_ports.add(client_port)
        if server_port:
            session.server_ports.add(server_port)

        if index_group is not None:
            session.index_groups.add(index_group)

        # Count read/write operations on requests only
        if not is_response:
            if cmd_id in WRITE_COMMAND_IDS:
                session.write_count += 1
            elif cmd_id in READ_COMMAND_IDS:
                session.read_count += 1

        # Capture device info from ReadDeviceInfo responses
        dev_name = extra.get("device_name")
        if dev_name:
            session.device_name = dev_name
        dev_version = extra.get("device_version")
        if dev_version:
            session.device_version = dev_version

    # ------------------------------------------------------------------
    # Device tracking
    # ------------------------------------------------------------------

    def _update_devices(
        self,
        client_ip: str,
        client_mac: str,
        server_ip: str,
        server_mac: str,
        session_key: Tuple[str, str],
    ) -> None:
        """Update device entries for client and server."""
        session = self.sessions[session_key]

        # Server device (TwinCAT PLC)
        if is_valid_discovered_ip(server_ip):
            server_key = f"ads-server:{server_ip}"
            server_vendor = lookup_mac_vendor(server_mac) if server_mac else ""

            dev_type = "ADS Server (TwinCAT PLC)"
            if session.device_name:
                dev_type = f"ADS Server ({session.device_name})"

            device, is_new = self._ensure_device(
                server_key,
                server_ip,
                mac=server_mac,
                device_type=dev_type,
                manufacturer=server_vendor if server_vendor else "",
            )
            device.ads_passive_data = self._build_device_data("server", session)
            if is_new:
                self.logger.debug(
                    "ADS: Server %s NetID=%s ports=%s",
                    server_ip,
                    session.server_netid,
                    sorted(session.server_ports),
                )

        # Client device (HMI / Engineering tool)
        if is_valid_discovered_ip(client_ip):
            client_key = f"ads-client:{client_ip}"
            client_vendor = lookup_mac_vendor(client_mac) if client_mac else ""

            device, is_new = self._ensure_device(
                client_key,
                client_ip,
                mac=client_mac,
                device_type="ADS Client (HMI/Engineering)",
                manufacturer=client_vendor if client_vendor else "",
            )
            device.ads_passive_data = self._build_device_data("client", session)

    def _build_device_data(self, role: str, session: ADSSession) -> Dict[str, Any]:
        """Build ads_passive_data dict from session."""
        sorted_cmds = sorted(session.commands_seen)
        sorted_igs = sorted(session.index_groups)
        ports = sorted(session.server_ports if role == "server" else session.client_ports)

        data: Dict[str, Any] = {
            "role": role,
            "ams_netid": session.server_netid if role == "server" else session.client_netid,
            "ams_ports": ports,
            "ams_port_names": [AMS_PORT_NAMES.get(p, "") for p in ports],
            "commands_seen": sorted_cmds,
            "command_names": [ADS_COMMANDS.get(c, f"Cmd 0x{c:04x}") for c in sorted_cmds],
            "index_groups": [f"0x{ig:04X}" for ig in sorted_igs],
            "index_group_names": [ADS_IDX_GRP_NAMES.get(ig, "") for ig in sorted_igs],
            "write_operations": session.write_count,
            "read_operations": session.read_count,
            "protocol": "ADS/AMS",
            "first_seen": session.first_seen,
            "last_seen": session.last_seen,
        }

        if session.device_name:
            data["device_name"] = session.device_name
        if session.device_version:
            data["device_version"] = session.device_version

        return data

    # ------------------------------------------------------------------
    # Harvest API
    # ------------------------------------------------------------------

    def get_sessions_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all observed ADS sessions."""
        return [
            {
                "client": s.client_ip,
                "server": s.server_ip,
                "server_netid": s.server_netid,
                "commands": sorted(s.commands_seen),
                "write_count": s.write_count,
                "read_count": s.read_count,
                "device_name": s.device_name,
            }
            for s in self.sessions.values()
        ]

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get sessions with write operations (potentially dangerous)."""
        return [
            {
                "client": s.client_ip,
                "server": s.server_ip,
                "write_count": s.write_count,
                "write_commands": [
                    ADS_COMMANDS.get(c, f"Cmd 0x{c:04x}")
                    for c in s.commands_seen
                    if c in WRITE_COMMAND_IDS
                ],
            }
            for s in self.sessions.values()
            if s.write_count > 0
        ]

    def get_control_operations(self) -> List[Dict[str, Any]]:
        """Get sessions with WriteControl commands."""
        return [
            {
                "controlling": s.client_ip,
                "controlled": s.server_ip,
                "control_count": sum(1 for c in s.commands_seen if c == 0x0005),
            }
            for s in self.sessions.values()
            if 0x0005 in s.commands_seen
        ]

    def harvest(self) -> Dict[str, Any]:
        """Filter out WRITE alerts (writes are visible in the operations table)."""
        result = super().harvest()
        if result and result.get("alerts"):
            result["alerts"] = [a for a in result["alerts"] if a.get("category") != "write_alert"]
        return result

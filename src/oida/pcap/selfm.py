"""
SEL Fast Message (SELFM) Passive Listener (PyShark-based).

Passively monitors Schweitzer Engineering Laboratories (SEL) Fast Message
traffic to identify:
- SEL relays/IEDs and the masters polling them
- Message types (Fast Meter config/data, relay definition, Fast Operate)
- Fast Operate control commands (breaker OPEN/CLOSE, remote-bit set/clear)
  -- the safety-critical operations on a protective relay

SEL Fast Message rides over serial or TCP (often Telnet-encapsulated,
port 23, or a raw TCP data port).  tshark's ``selfm`` is a heuristic
dissector keyed on the 0xA5xx command word, so a decode-as / port binding
is required for it to fire on a non-standard port.

Message command words (16-bit, tshark field selfm.msgtype):
- 0xA5C0 Relay Definition      0xA5C1 Fast Meter Config
- 0xA5D1 Fast Meter Data       0xA5D2/0xA5D3 Demand/Peak Meter Data
- 0xA5E0/0xA5E3 Fast Operate remote-bit / breaker-bit control
- 0xA5E5/0xA5E6 (Alt) Fast Operate OPEN / CLOSE  <-- control
- 0xA5E7/0xA5E8/0xA5E9 Fast Operate SET / CLEAR / PULSE  <-- control

tshark fields used (selfm layer):
- selfm.msgtype        : 16-bit command word
- selfm.fmdata.len     : Fast Meter data frame length

Reference: packet-selfm.c (Wireshark) / SEL Application Guides on selinc.com.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from oida.pcap.pyshark_base import ProtocolInteraction, PySharkListenerBase
from oida.protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

# Command word -> human-readable name.
SELFM_CMD = {
    0xA546: "Fast Message",
    0xA5B9: "Clear Status Bits",
    0xA5C0: "Relay Definition",
    0xA5C1: "Fast Meter Config",
    0xA5C2: "Demand Meter Config",
    0xA5C3: "Peak Meter Config",
    0xA5CD: "Fast Operate Reset Def",
    0xA5CE: "Fast Operate Config",
    0xA5CF: "Alt Fast Operate Config",
    0xA5D1: "Fast Meter Data",
    0xA5D2: "Demand Meter Data",
    0xA5D3: "Peak Meter Data",
    0xA5E0: "Fast Operate Remote-Bit Ctrl",
    0xA5E3: "Fast Operate Breaker-Bit Ctrl",
    0xA5E5: "Alt Fast Operate OPEN",
    0xA5E6: "Alt Fast Operate CLOSE",
    0xA5E7: "Alt Fast Operate SET",
    0xA5E8: "Alt Fast Operate CLEAR",
    0xA5E9: "Alt Fast Operate PULSE",
    0xA5ED: "Fast Operate Reset",
}

# Fast Operate / control command words -- these actuate the relay (breaker
# operations, remote-bit changes) and are the safety-critical ones to flag.
SELFM_CONTROL_CMDS = {
    0xA5E0,
    0xA5E3,
    0xA5E5,
    0xA5E6,
    0xA5E7,
    0xA5E8,
    0xA5E9,
    0xA5ED,
}

# Data/response command words (relay -> master).
SELFM_DATA_CMDS = {0xA5D1, 0xA5D2, 0xA5D3, 0xA5C0, 0xA5C1, 0xA5C2, 0xA5C3}


class SELFMPassiveListener(PySharkListenerBase):
    """Passive SEL Fast Message traffic listener (PyShark-based).

    Monitors SEL relay traffic to:
    - Identify SEL relays/IEDs and their masters
    - Track message types (meter config/data, relay definition)
    - Flag Fast Operate control commands (breaker/remote-bit operations)

    Data stored in device.selfm_passive_data:
        {
            "role": "relay" | "master",
            "commands_seen": ["Fast Meter Data", "Alt Fast Operate OPEN"],
            "control_ops": 2,
            "protocol": "SEL Fast Message",
        }
    """

    PROTOCOL_NAME = "selfm"
    DISPLAY_FILTER = "selfm"
    REQUIRED_LAYERS = ("selfm",)
    # Common SEL Fast Message transports: Telnet-encapsulated (23) and the
    # SEL data port 1025.  Bind both so the heuristic dissector fires.
    SERVER_PORTS = (23, 1025)
    OVERRIDE_PREFS = {"selfm.tcp.port": "1025"}
    PROTOCOL_COLUMNS = ("command", "cmd_word", "role", "length")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        # ip -> {role, commands, control_ops}
        self.endpoints: Dict[str, Dict[str, Any]] = {}
        # control operations for the harvest control-alert hook
        self._control_ops: List[Dict[str, Any]] = []

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        return [
            d.get("command_name", "?"),
            d.get("command_word", "?"),
            d.get("role", "?"),
            d.get("data_len", "-"),
        ]

    def process_packet(self, packet) -> None:
        """Process a SEL Fast Message packet."""
        if not hasattr(packet, "selfm"):
            return

        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        selfm = packet.selfm
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)
        flow_id = self.get_flow_id(packet)

        cmd_raw = self.get_field(selfm, "msgtype", None)
        if cmd_raw is None:
            self.logger.debug(f"SELFM: missing msgtype from {src_ip}")
            return

        # tshark reports selfm.msgtype as a decimal integer (e.g. 42432 for
        # 0xA5C0); only hex-prefixed strings are base 16.
        cmd_str = str(cmd_raw).strip().lower()
        cmd_word = self._parse_int(cmd_raw, default=0, base=16 if cmd_str.startswith("0x") else 10)
        command_name = SELFM_CMD.get(cmd_word, f"Unknown (0x{cmd_word:04x})")
        data_len = str(self.get_field(selfm, "fmdata_len", "") or "")

        is_control = cmd_word in SELFM_CONTROL_CMDS
        is_data = cmd_word in SELFM_DATA_CMDS

        # Fast Operate/control comes from the master; data comes from the relay.
        # A config/data reply => relay is the source (server/response).
        if is_control:
            role, direction = "master", "request"
        elif is_data:
            role, direction = "relay", "response"
        else:
            d = self.resolve_direction(
                packet,
                native=None,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                flow_id=flow_id,
            )
            role = "relay" if not d.is_request else "master"
            direction = d.direction

        details: Dict[str, Any] = {
            "command_name": command_name,
            "command_word": f"0x{cmd_word:04x}",
            "role": role,
            "data_len": data_len,
            "is_control": is_control,
        }

        now = datetime.now().isoformat()
        summary = f"SELFM {command_name} {src_ip} -> {dst_ip}"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            f"SELFM {command_name}",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        if is_control:
            self.logger.warning(
                f"SEL Fast Operate control: {src_ip} -> {dst_ip} ({command_name}) "
                "-- relay actuation command"
            )
            self._control_ops.append(
                {
                    "controlling": src_ip,
                    "controlled": dst_ip,
                    "controlled_port": dst_port,
                    "control_count": 1,
                    "command": command_name,
                }
            )

        # Track endpoints: the relay is the data source; the master issues
        # config requests / Fast Operate.
        self._track_endpoint(src_ip, role, command_name, is_control)

        if is_valid_discovered_ip(src_ip):
            dev_role = role
            vendor = lookup_mac_vendor(src_mac) if src_mac else ""
            self._ensure_device(
                f"selfm-{dev_role}:{src_ip}",
                src_ip,
                mac=src_mac or "",
                device_type=f"SEL {dev_role.title()}",
                manufacturer=vendor if vendor and vendor != "Unknown" else "Schweitzer",
                data_attr="selfm_passive_data",
                protocol_data=self._endpoint_data(src_ip),
            )

    def get_control_operations(self) -> List[Dict[str, Any]]:
        """Expose Fast Operate control commands to the base harvest hook."""
        return self._control_ops

    # ------------------------------------------------------------------
    def _track_endpoint(self, ip: str, role: str, command_name: str, is_control: bool) -> None:
        info = self.endpoints.setdefault(ip, {"role": role, "commands": set(), "control_ops": 0})
        info["role"] = role
        info["commands"].add(command_name)
        if is_control:
            info["control_ops"] += 1

    def _endpoint_data(self, ip: str) -> Dict[str, Any]:
        info = self.endpoints.get(ip, {})
        return {
            "role": info.get("role", ""),
            "commands_seen": sorted(info.get("commands", set())),
            "control_ops": info.get("control_ops", 0),
            "protocol": "SEL Fast Message",
        }

"""
PTP / IEEE 1588 Passive Listener (PyShark-based).

Passively monitors Precision Time Protocol (IEEE 1588) traffic to identify:
- Grandmaster clocks and their quality parameters
- Boundary and transparent clocks
- Clock domains and sync rates
- Management and signaling messages
- Time synchronization topology

PTP provides sub-microsecond time synchronization for industrial networks,
power systems, telecom, and financial trading. It operates on UDP ports
319 (event messages) and 320 (general messages), or directly at Layer 2
using EtherType 0x88F7.

Protocol format:
- PTP header (34 bytes): transportSpecific (4b), messageType (4b),
  versionPTP (4b), messageLength (16b), domainNumber (8b), flags (16b),
  correctionField (64b), sourcePortIdentity (clockIdentity 64b + portNumber 16b),
  sequenceId (16b), controlField (8b), logMessageInterval (8b)
- Message-specific body varies by type

Message types:
- 0x0: Sync (event)
- 0x1: Delay_Req (event)
- 0x2: Pdelay_Req (event)
- 0x3: Pdelay_Resp (event)
- 0x8: Follow_Up (general)
- 0x9: Delay_Resp (general)
- 0xA: Pdelay_Resp_Follow_Up (general)
- 0xB: Announce (general)
- 0xC: Signaling (general)
- 0xD: Management (general)

tshark fields used:
- ptp.v2.messagetype: Message type (FT_UINT8, 4-bit)
- ptp.v2.domainnumber: Domain number (FT_UINT8)
- ptp.v2.clockidentity: Source clock identity (FT_UINT64)
- ptp.v2.sourceportid: Source port number (FT_UINT16)
- ptp.v2.sequenceid: Sequence ID (FT_UINT16)
- ptp.v2.correctionns: Correction field nanoseconds (FT_INT64)
- ptp.v2.correctionsubns: Correction field sub-nanoseconds (FT_INT16)
- ptp.v2.logmessageperiod: Log message interval (FT_INT8)
- ptp.v2.flags.twostep: Two-step flag (FT_BOOLEAN)
- ptp.v2.flags.unicast: Unicast flag (FT_BOOLEAN)
- ptp.v2.an.gm.clockidentity: Grandmaster clock identity (FT_UINT64)
- ptp.v2.an.gm.priority1: Grandmaster priority1 (FT_UINT8)
- ptp.v2.an.gm.priority2: Grandmaster priority2 (FT_UINT8)
- ptp.v2.an.gm.clockclass: Grandmaster clock class (FT_UINT8)
- ptp.v2.an.gm.clockaccuracy: Grandmaster clock accuracy (FT_UINT8)
- ptp.v2.an.gm.offsetscaledlogvariance: Grandmaster variance (FT_UINT16)
- ptp.v2.an.stepsremoved: Steps removed (FT_UINT16)
- ptp.v2.an.timesource: Time source (FT_UINT8)
- ptp.v2.mm.managementId: Management message ID (FT_UINT16)
- ptp.v2.mm.action: Management action (FT_UINT8)

Security notes:
- Grandmaster changes may indicate BMCA (Best Master Clock Algorithm) attacks
- Management messages can reconfigure PTP devices (enable/disable ports, etc.)
- Signaling messages can alter sync intervals (grant unicast, deny service)
- Clock quality degradation over time may indicate a gradual spoofing attack
- Excessive Announce messages from unknown sources suggest spoofing
- PTP has no built-in authentication (IEEE 1588-2019 adds Annex P / MACsec)

References:
- IEEE 1588-2008 / IEEE 1588-2019: Precision Time Protocol
- IEC 61850-9-3: PTP power utility profile (Power Profile)
- SMPTE ST 2059: PTP for media/broadcast
- Wireshark dissector: packet-ptp.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from oida.pcap.pyshark_base import ProtocolInteraction, PySharkListenerBase
from oida.protocols.discovery.core import is_valid_discovered_ip

# PTP message types
PTP_MESSAGE_TYPES = {
    0x0: "Sync",
    0x1: "Delay_Req",
    0x2: "Pdelay_Req",
    0x3: "Pdelay_Resp",
    0x8: "Follow_Up",
    0x9: "Delay_Resp",
    0xA: "Pdelay_Resp_Follow_Up",
    0xB: "Announce",
    0xC: "Signaling",
    0xD: "Management",
}

# Event messages (timing-critical, port 319)
EVENT_MESSAGES = {0x0, 0x1, 0x2, 0x3}

# PTP time sources
PTP_TIME_SOURCES = {
    0x10: "Atomic Clock",
    0x20: "GPS",
    0x30: "Terrestrial Radio",
    0x39: "Serial Time Code",
    0x40: "PTP",
    0x50: "NTP",
    0x60: "Hand Set",
    0x90: "Other",
    0xA0: "Internal Oscillator",
}

# PTP clock accuracy enumeration
PTP_CLOCK_ACCURACY = {
    0x20: "25ns",
    0x21: "100ns",
    0x22: "250ns",
    0x23: "1us",
    0x24: "2.5us",
    0x25: "10us",
    0x26: "25us",
    0x27: "100us",
    0x28: "250us",
    0x29: "1ms",
    0x2A: "2.5ms",
    0x2B: "10ms",
    0x2C: "25ms",
    0x2D: "100ms",
    0x2E: "250ms",
    0x2F: "1s",
    0x30: "10s",
    0x31: ">10s",
    0xFE: "Unknown",
}

# PTP management actions
PTP_MGMT_ACTIONS = {
    0x0: "GET",
    0x1: "SET",
    0x2: "RESPONSE",
    0x3: "COMMAND",
    0x4: "ACKNOWLEDGE",
}

# Notable management IDs
PTP_MGMT_IDS = {
    0x0000: "NULL_PTP_MANAGEMENT",
    0x0001: "CLOCK_DESCRIPTION",
    0x0002: "USER_DESCRIPTION",
    0x0003: "SAVE_IN_NON_VOLATILE_STORAGE",
    0x0004: "RESET_NON_VOLATILE_STORAGE",
    0x0005: "INITIALIZE",
    0x0006: "FAULT_LOG",
    0x0007: "FAULT_LOG_RESET",
    0x2000: "DEFAULT_DATA_SET",
    0x2001: "CURRENT_DATA_SET",
    0x2002: "PARENT_DATA_SET",
    0x2003: "TIME_PROPERTIES_DATA_SET",
    0x2004: "PORT_DATA_SET",
    0x2005: "PRIORITY1",
    0x2006: "PRIORITY2",
    0x2007: "DOMAIN",
    0x2008: "SLAVE_ONLY",
    0x2009: "LOG_ANNOUNCE_INTERVAL",
    0x200A: "ANNOUNCE_RECEIPT_TIMEOUT",
    0x200B: "LOG_SYNC_INTERVAL",
    0x200C: "VERSION_NUMBER",
    0x200D: "ENABLE_PORT",
    0x200E: "DISABLE_PORT",
    0x200F: "TIME",
    0x2010: "CLOCK_ACCURACY",
    0x2011: "UTC_PROPERTIES",
    0x2012: "TRACEABILITY_PROPERTIES",
    0x2013: "TIMESCALE_PROPERTIES",
    0x2014: "UNICAST_NEGOTIATION_ENABLE",
    0x6000: "DELAY_MECHANISM",
    0x6001: "LOG_MIN_PDELAY_REQ_INTERVAL",
}


@dataclass
class PTPClock:
    """Track a PTP clock (identified by clock identity)."""

    clock_identity: str
    domains: Set[int] = field(default_factory=set)
    port_numbers: Set[int] = field(default_factory=set)
    message_types: Set[str] = field(default_factory=set)
    gm_clock_id: str = ""
    gm_priority1: int = 255
    gm_priority2: int = 255
    gm_clock_class: int = 255
    gm_clock_accuracy: int = 0xFE
    gm_variance: int = 0xFFFF
    steps_removed: int = 0
    time_source: int = 0
    is_grandmaster: bool = False
    announce_count: int = 0
    sync_count: int = 0
    total_messages: int = 0
    first_seen: str = ""
    last_seen: str = ""


class PTPPassiveListener(PySharkListenerBase):
    """Passive PTP/IEEE 1588 traffic listener (PyShark-based).

    Monitors Precision Time Protocol traffic to:
    - Identify grandmaster clocks and their quality parameters
    - Map PTP clock topology (grandmaster, boundary, ordinary clocks)
    - Track sync rates and domain configurations
    - Detect grandmaster changes (potential BMCA attacks)
    - Alert on Management messages (device reconfiguration)
    - Alert on Signaling messages (interval changes)
    - Monitor clock quality degradation

    PTP can run on UDP (ports 319/320) or Layer 2 (EtherType 0x88F7).
    Both transports are captured via the ``ptp`` tshark display filter.

    Usage:
        listener = PTPPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

    Data stored in device.ptp_passive_data:
        {
            "role": "grandmaster" | "boundary_clock" | "ordinary_clock",
            "clock_identity": "001b21fffe123456",
            "domains": [0],
            "gm_clock_id": "001b21fffe123456",
            "gm_priority1": 128,
            "gm_clock_class": 6,
            "protocol": "PTP/UDP",
        }
    """

    PROTOCOL_NAME = "ptp"
    DISPLAY_FILTER = "ptp"
    REQUIRED_LAYERS = ("ptp",)
    PROTOCOL_COLUMNS = ("msg_type", "domain", "clock_id", "seq_id", "gm_info", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        """Initialize PTP passive listener."""
        super().__init__(interface, timeout, nxc_logger)
        self.clocks: Dict[str, PTPClock] = {}
        self._alerts: List[Dict[str, str]] = []
        # Track grandmaster history per domain for change detection
        self._gm_history: Dict[int, List[str]] = {}
        # Per-domain count of GM history entries already alerted (1 = initial GM,
        # no transition yet) so each transition fires exactly once.
        self._gm_change_alerted: Dict[int, int] = {}

    def process_packet(self, packet) -> None:
        """Process a PTP packet using PyShark dissection."""
        if not hasattr(packet, "ptp"):
            return

        ptp_layer = packet.ptp

        # Extract network info (may be IP or L2)
        src_ip, dst_ip = self.get_ip_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)
        src_port, dst_port = self.get_port_info(packet)
        flow_id = self.get_flow_id(packet)
        stream_id = self.get_stream_id(packet)
        now = datetime.now().isoformat()

        # Extract PTP header fields
        msg_type_raw = self.get_field(ptp_layer, "v2_messagetype")
        if msg_type_raw is None:
            # Try alternate field names
            msg_type_raw = self.get_field(ptp_layer, "v2_messageid")
        msg_type = self._parse_int(msg_type_raw, None)
        if msg_type is None:
            return

        domain = self._parse_int(self.get_field(ptp_layer, "v2_domainnumber"), 0)
        clock_id = str(self.get_field(ptp_layer, "v2_clockidentity") or "")
        port_num = self._parse_int(self.get_field(ptp_layer, "v2_sourceportid"), 0)
        seq_id = self._parse_int(self.get_field(ptp_layer, "v2_sequenceid"), 0)
        correction_ns = self.get_field(ptp_layer, "v2_correction_ns")
        log_interval = self.get_field(ptp_layer, "v2_logmessageperiod")

        # Flags
        two_step = self._parse_bool(self.get_field(ptp_layer, "v2_flags_twostep"))
        unicast = self._parse_bool(self.get_field(ptp_layer, "v2_flags_unicast"))

        msg_name = PTP_MESSAGE_TYPES.get(msg_type, f"Type 0x{msg_type:x}")

        # Update clock state
        clock = self._update_clock(clock_id, domain, port_num, msg_name, now)

        # Build details
        details: Dict[str, Any] = {
            "message_type": msg_type,
            "message_name": msg_name,
            "domain": domain,
            "clock_identity": clock_id,
            "port_number": port_num,
            "sequence_id": seq_id,
        }

        if correction_ns is not None:
            details["correction_ns"] = str(correction_ns)
        if log_interval is not None:
            details["log_interval"] = str(log_interval)
        if two_step:
            details["two_step"] = True
        if unicast:
            details["unicast"] = True

        # Process message-type-specific fields
        gm_info = ""
        if msg_type == 0xB:  # Announce
            gm_info = self._process_announce(ptp_layer, clock, domain, details)
        elif msg_type == 0xD:  # Management
            self._process_management(ptp_layer, details)
        elif msg_type == 0xC:  # Signaling
            details["signaling"] = True

        # Track message counts
        if msg_type == 0x0:
            clock.sync_count += 1
        elif msg_type == 0xB:
            clock.announce_count += 1

        # Determine direction label
        # PTP event messages are timing-critical; general messages are informational
        direction = "request" if msg_type in EVENT_MESSAGES else "response"

        # Use source IP if available, otherwise use MAC
        src_addr = src_ip if src_ip else src_mac
        dst_addr = dst_ip if dst_ip else dst_mac

        summary = self._build_summary(msg_name, domain, clock_id, seq_id, gm_info)

        self._record_interaction(
            now,
            src_addr,
            dst_addr,
            direction,
            msg_name,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Security checks
        self._check_security(msg_type, msg_name, src_addr, dst_addr, details)

        # Update devices
        self._update_device(src_ip, src_mac, clock)

    # ------------------------------------------------------------------
    # Announce message processing
    # ------------------------------------------------------------------

    def _process_announce(
        self,
        ptp_layer,
        clock: PTPClock,
        domain: int,
        details: Dict[str, Any],
    ) -> str:
        """Process PTP Announce message and extract grandmaster info."""
        gm_clock_id = str(self.get_field(ptp_layer, "v2_an_grandmasterclockidentity") or "")
        gm_p1 = self._parse_int(self.get_field(ptp_layer, "v2_an_priority1"), 255)
        gm_p2 = self._parse_int(self.get_field(ptp_layer, "v2_an_priority2"), 255)
        gm_class = self._parse_int(self.get_field(ptp_layer, "v2_an_grandmasterclockclass"), 255)
        gm_accuracy = self._parse_int(
            self.get_field(ptp_layer, "v2_an_grandmasterclockaccuracy"), 0xFE
        )
        gm_variance = self._parse_int(
            self.get_field(ptp_layer, "v2_an_grandmasterclockvariance"), 0xFFFF
        )
        steps_removed = self._parse_int(self.get_field(ptp_layer, "v2_an_localstepsremoved"), 0)
        # Announce has no dedicated tshark timeSource field; left as default.
        time_source = self._parse_int(self.get_field(ptp_layer, "v2_an_timesource"), 0)

        # Update clock's grandmaster info
        clock.gm_clock_id = gm_clock_id
        clock.gm_priority1 = gm_p1
        clock.gm_priority2 = gm_p2
        clock.gm_clock_class = gm_class
        clock.gm_clock_accuracy = gm_accuracy
        clock.gm_variance = gm_variance
        clock.steps_removed = steps_removed
        clock.time_source = time_source

        # Determine if this clock IS the grandmaster
        if gm_clock_id and gm_clock_id == clock.clock_identity:
            clock.is_grandmaster = True

        # Track grandmaster changes per domain
        if gm_clock_id:
            gm_list = self._gm_history.setdefault(domain, [])
            if not gm_list or gm_list[-1] != gm_clock_id:
                gm_list.append(gm_clock_id)

        # Add to details
        if gm_clock_id:
            details["gm_clock_id"] = gm_clock_id
        details["gm_priority1"] = gm_p1
        details["gm_priority2"] = gm_p2
        details["gm_clock_class"] = gm_class
        accuracy_str = PTP_CLOCK_ACCURACY.get(gm_accuracy, f"0x{gm_accuracy:02x}")
        details["gm_accuracy"] = accuracy_str
        details["gm_variance"] = gm_variance
        details["steps_removed"] = steps_removed
        time_source_str = PTP_TIME_SOURCES.get(time_source, f"0x{time_source:02x}")
        details["time_source"] = time_source_str

        # Build GM info string for column display
        gm_parts = [f"GM={gm_clock_id[-8:]}" if gm_clock_id else ""]
        gm_parts.append(f"class={gm_class}")
        gm_parts.append(f"p1={gm_p1}")
        return " ".join(p for p in gm_parts if p)

    # ------------------------------------------------------------------
    # Management message processing
    # ------------------------------------------------------------------

    def _process_management(
        self,
        ptp_layer,
        details: Dict[str, Any],
    ) -> None:
        """Process PTP Management message."""
        mgmt_id_raw = self.get_field(ptp_layer, "v2_mm_managementId")
        mgmt_id = self._parse_int(mgmt_id_raw, None)
        action_raw = self.get_field(ptp_layer, "v2_mm_action")
        action_val = self._parse_int(action_raw, None)

        if mgmt_id is not None:
            mgmt_name = PTP_MGMT_IDS.get(mgmt_id, f"MGMT_0x{mgmt_id:04x}")
            details["mgmt_id"] = mgmt_id
            details["mgmt_name"] = mgmt_name

        if action_val is not None:
            action_name = PTP_MGMT_ACTIONS.get(action_val, f"Action_{action_val}")
            details["mgmt_action"] = action_name

    # ------------------------------------------------------------------
    # Clock tracking
    # ------------------------------------------------------------------

    def _update_clock(
        self,
        clock_id: str,
        domain: int,
        port_num: int,
        msg_name: str,
        now: str,
    ) -> PTPClock:
        """Update or create a PTP clock entry."""
        if clock_id not in self.clocks:
            self.clocks[clock_id] = PTPClock(
                clock_identity=clock_id,
                first_seen=now,
                last_seen=now,
            )

        clock = self.clocks[clock_id]
        clock.last_seen = now
        clock.total_messages += 1
        clock.domains.add(domain)
        clock.port_numbers.add(port_num)
        clock.message_types.add(msg_name)

        return clock

    # ------------------------------------------------------------------
    # Security checks
    # ------------------------------------------------------------------

    def _check_security(
        self,
        msg_type: int,
        msg_name: str,
        src_addr: str,
        dst_addr: str,
        details: Dict[str, Any],
    ) -> None:
        """Generate security alerts for suspicious PTP activity."""
        # Grandmaster change detection
        for domain, gm_list in self._gm_history.items():
            if len(gm_list) > 1:
                prev_gm = gm_list[-2]
                new_gm = gm_list[-1]
                # Alert exactly once per transition. _gm_history only grows when
                # the GM actually changes (see the append guard), so its length is
                # 1 + (number of transitions). Tracking how many transitions we've
                # already alerted per domain fires once for every real change —
                # including a flap back to a previous GM (A->B->A->B) — without the
                # per-packet re-alert, and without suppressing a repeated A->B that
                # a (domain,prev,new) set would wrongly collapse.
                alerted = self._gm_change_alerted.get(domain, 1)
                if len(gm_list) > alerted:
                    self._gm_change_alerted[domain] = len(gm_list)
                    self._alerts.append(
                        {
                            "level": "fail",
                            "category": "ptp_gm_change",
                            "message": (
                                f"PTP GRANDMASTER CHANGE: domain={domain} "
                                f"{prev_gm} -> {new_gm} "
                                f"(possible BMCA attack)"
                            ),
                        }
                    )

        # Management messages (configuration changes)
        if msg_type == 0xD:
            action = details.get("mgmt_action", "")
            mgmt_name = details.get("mgmt_name", "")
            if action in ("SET", "COMMAND"):
                self._alerts.append(
                    {
                        "level": "fail",
                        "category": "ptp_management",
                        "message": (
                            f"PTP MANAGEMENT {action}: {src_addr} -> {dst_addr} "
                            f"{mgmt_name} (device reconfiguration)"
                        ),
                    }
                )

        # Signaling messages (interval/grant changes)
        if msg_type == 0xC:
            self._alerts.append(
                {
                    "level": "highlight",
                    "category": "ptp_signaling",
                    "message": (
                        f"PTP SIGNALING: {src_addr} -> {dst_addr} (interval/grant negotiation)"
                    ),
                }
            )

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    def _update_device(self, ip: str, mac: str, clock: PTPClock) -> None:
        """Update device entry for a PTP clock."""
        if ip and is_valid_discovered_ip(ip):
            device_key = f"ptp:{ip}"
            identifier = ip
        elif mac:
            device_key = f"ptp:{mac}"
            identifier = mac
        else:
            return

        # Determine clock role
        if clock.is_grandmaster:
            role = "grandmaster"
            dev_type = "PTP Grandmaster Clock"
        elif clock.steps_removed > 0 and clock.sync_count > 0:
            role = "boundary_clock"
            dev_type = "PTP Boundary Clock"
        else:
            role = "ordinary_clock"
            dev_type = "PTP Clock"

        device, is_new = self._ensure_device(
            device_key,
            ip if ip else "",
            mac=mac if mac else "",
            device_type=dev_type,
        )

        device.ptp_passive_data = self._build_device_data(role, clock)

        if is_new:
            self.logger.debug(
                f"PTP: {dev_type} {identifier} "
                f"clock_id={clock.clock_identity} "
                f"domain={sorted(clock.domains)}"
            )

    def _build_device_data(self, role: str, clock: PTPClock) -> Dict[str, Any]:
        """Build ptp_passive_data dict from clock state."""
        data: Dict[str, Any] = {
            "role": role,
            "clock_identity": clock.clock_identity,
            "domains": sorted(clock.domains),
            "port_numbers": sorted(clock.port_numbers),
            "message_types": sorted(clock.message_types),
            "total_messages": clock.total_messages,
            "sync_count": clock.sync_count,
            "announce_count": clock.announce_count,
            "protocol": "PTP/UDP",
            "first_seen": clock.first_seen,
            "last_seen": clock.last_seen,
        }
        if clock.gm_clock_id:
            data["gm_clock_id"] = clock.gm_clock_id
            data["gm_priority1"] = clock.gm_priority1
            data["gm_priority2"] = clock.gm_priority2
            data["gm_clock_class"] = clock.gm_clock_class
            data["gm_accuracy"] = PTP_CLOCK_ACCURACY.get(
                clock.gm_clock_accuracy, f"0x{clock.gm_clock_accuracy:02x}"
            )
            data["steps_removed"] = clock.steps_removed
            data["time_source"] = PTP_TIME_SOURCES.get(
                clock.time_source, f"0x{clock.time_source:02x}"
            )
        return data

    # ------------------------------------------------------------------
    # Interaction formatting
    # ------------------------------------------------------------------

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details

        msg_name = d.get("message_name", "")
        domain = d.get("domain", "")
        clock_id = d.get("clock_identity", "")
        # Show last 8 chars for readability
        if clock_id and len(clock_id) > 8:
            clock_id = "..." + clock_id[-8:]
        seq_id = d.get("sequence_id", "")

        # GM info (from Announce)
        gm_parts: List[str] = []
        if d.get("gm_clock_id"):
            gm_id = d["gm_clock_id"]
            if len(gm_id) > 8:
                gm_id = gm_id[-8:]
            gm_parts.append(f"GM={gm_id}")
            gm_parts.append(f"c={d.get('gm_clock_class', '')}")
        gm_info = " ".join(gm_parts)

        # Detail column
        detail_parts: List[str] = []
        if d.get("mgmt_name"):
            detail_parts.append(d["mgmt_name"])
        if d.get("mgmt_action"):
            detail_parts.append(f"[{d['mgmt_action']}]")
        if d.get("steps_removed") is not None and d.get("message_name") == "Announce":
            detail_parts.append(f"steps={d['steps_removed']}")
        if d.get("time_source"):
            detail_parts.append(d["time_source"])
        if d.get("two_step"):
            detail_parts.append("2-step")
        if d.get("unicast"):
            detail_parts.append("unicast")
        if d.get("signaling"):
            detail_parts.append("signaling")
        detail = " ".join(detail_parts)

        return [msg_name, domain, clock_id, seq_id, gm_info, detail]

    # ------------------------------------------------------------------
    # Summary helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_summary(
        msg_name: str,
        domain: int,
        clock_id: str,
        seq_id: int,
        gm_info: str,
    ) -> str:
        """Build a one-line human-readable interaction summary."""
        parts: List[str] = [msg_name, f"dom={domain}"]

        if clock_id:
            short_id = clock_id[-8:] if len(clock_id) > 8 else clock_id
            parts.append(f"clk={short_id}")

        parts.append(f"seq={seq_id}")

        if gm_info:
            parts.append(gm_info)

        return " ".join(parts)

    # ------------------------------------------------------------------
    # Harvest
    # ------------------------------------------------------------------

    def harvest(self) -> Dict[str, Any]:
        """Return harvest data with PTP-specific security alerts."""
        result = super().harvest()
        if not result and not self._alerts:
            return {}
        if not result:
            result = {"tables": [], "alerts": []}
        if self._alerts:
            # Deduplicate GM change alerts (can fire repeatedly)
            seen_msgs: Set[str] = set()
            unique_alerts: List[Dict[str, str]] = []
            for alert in self._alerts:
                msg = alert["message"]
                if msg not in seen_msgs:
                    seen_msgs.add(msg)
                    unique_alerts.append(alert)
            result.setdefault("alerts", []).extend(unique_alerts)
        return result

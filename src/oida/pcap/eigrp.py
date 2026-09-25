"""
EIGRP (Enhanced Interior Gateway Routing Protocol) passive listener.

EIGRP uses:
- IP protocol 88
- Multicast 224.0.0.10 (EIGRP Routers)

Useful for discovering:
- EIGRP routers and AS numbers
- Network topology and routes (IPv4 + IPv6, internal + external)
- K-values (metric weights)
- Hold times and flags (including restart/NSF detection)
- Authentication credentials (MD5/SHA-256 digests)
- Virtual Router IDs
- Software and release versions
- Checksum validation status
- Route metrics (bandwidth, delay, reliability, load, hopcount)

Uses PyShark (tshark wrapper) for EIGRP packet dissection.

PyShark EIGRP field reference -- EK-mode names (packet.eigrp.*):
- opcode: EIGRP opcode (1=Update, 3=Query, 4=Reply, 5=Hello)
- as: Autonomous System number
- flags: EIGRP flags (EkMultiField)
- flags_restart: Restart/NSF flag
- flags_init: Init flag
- flags_condrecv: Conditional Receive flag
- flags_eot: End of Table flag
- seq: Sequence number (EK mode; XML mode: sequence)
- ack: Acknowledgment number (EK mode; XML mode: acknowledge)
- vrid: Virtual Router ID
- checksum: Checksum (EkMultiField)
- checksum_status: Checksum verification status
  (tshark convention: 0=Bad, 1=Good, 2=Unverified, 3=Not present, 4=Illegal)
- release_version: EIGRP release version (packed uint16)
- tlv_version: TLV version (packed uint16)
- par_k1..par_k6: K-values (Parameter TLV)
- par_holdtime: Hold time (Parameter TLV)
- auth_type / auth.type: Authentication type (2=MD5, 3=SHA-256)
- auth_keyid / auth.keyid: Key ID
- auth_digest / auth.digest: Authentication digest
- auth_length / auth.length: Auth data length
- auth_keyseq / auth.keyseq: Key sequence number
- ipv6_destination: IPv6 route destination
- ipv6_prefixlen: IPv6 route prefix length
- ipv6_nexthop: IPv6 next-hop address
- old_metric_bw: Bandwidth metric
- old_metric_delay: Delay metric
- old_metric_rel: Reliability metric
- old_metric_load: Load metric
- old_metric_hopcount: Hop count metric
- old_metric_mtu: MTU metric
- extdata_origrid: External route originating router ID
- extdata_as: External route originating AS
- extdata_proto: External route originating protocol
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from oida.pcap.pyshark_base import ProtocolInteraction, PySharkListenerBase
from oida.protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor


# EIGRP constants
EIGRP_PROTOCOL = 88
EIGRP_MULTICAST = "224.0.0.10"

# EIGRP opcodes -- verbatim from `tshark -G values | grep eigrp.opcode`.
# 2/7/8/9 used to be missing entirely, so those packets rendered as
# "Unknown(2)" / "Opcode_7" instead of their real names.
EIGRP_OPCODES = {
    1: "Update",
    2: "Request",
    3: "Query",
    4: "Reply",
    5: "Hello",
    6: "IPX/SAP Update",
    7: "Route Probe",
    8: "Hello (Ack)",
    9: "Stub-Info",
    10: "SIA-Query",
    11: "SIA-Reply",
}

# EIGRP TLV types
EIGRP_TLV_TYPES = {
    0x0001: "Parameters",
    0x0002: "Sequence",
    0x0003: "Software Version",
    0x0004: "Next Multicast Sequence",
    0x0005: "Peer Termination",
    0x0006: "Stub",
    0x0102: "Internal Route (IPv4)",
    0x0103: "External Route (IPv4)",
    0x0402: "Internal Route (IPv6)",
    0x0403: "External Route (IPv6)",
}

# EIGRP flags
EIGRP_FLAGS = {
    0x01: "Init",
    0x02: "Conditional Receive",
    0x04: "Restart",
    0x08: "End of Table",
}

# EIGRP auth types
EIGRP_AUTH_TYPES = {
    2: "MD5",
    3: "SHA-256",
}

# Checksum status values (tshark -G values eigrp.checksum.status:
# the standard checksum-status convention 0=Bad, 1=Good, 2=Unverified, ...).
# Named status codes for the consumers below -- correcting the table alone is
# not enough; the alert site used to test `== 2` (Unverified).
CHECKSUM_STATUS_BAD = 0
CHECKSUM_STATUS_NOT_PRESENT = 3

EIGRP_CHECKSUM_STATUS = {
    0: "Bad",
    1: "Good",
    2: "Unverified",
    3: "Not present",
    4: "Illegal",
}


@dataclass
class EIGRPCredential:
    """Extracted EIGRP authentication credential."""

    auth_type: int  # 2 = MD5, 3 = SHA-256
    auth_type_name: str
    credential_type: str = "hash"
    auth_data: str = ""  # digest hex
    key_id: int = 0
    key_seq: int = 0
    auth_length: int = 0
    router_ip: str = ""
    as_number: int = 0
    timestamp: str = ""

    @property
    def username(self) -> str:
        """Canonical credential field."""
        return self.auth_data

    @property
    def server_ip(self) -> str:
        """Canonical credential field."""
        return self.router_ip

    @property
    def auth_method(self) -> str:
        """Canonical credential field."""
        return self.auth_type_name

    @property
    def hash_value(self) -> str:
        """Canonical credential field."""
        return self.auth_data


class EIGRPPassiveListener(PySharkListenerBase):
    """Passive EIGRP traffic listener using PyShark.

    Captures EIGRP packets to identify:
    - EIGRP routers and AS numbers
    - K-values (metric configuration)
    - Advertised routes (IPv4 + IPv6, internal + external)
    - Hold times
    - Authentication credentials (MD5/SHA-256 digests)
    - Virtual Router IDs
    - Release/TLV versions for software fingerprinting
    - Checksum validation (bad checksum alerts)
    - Route metrics (bandwidth, delay, reliability, load, hopcount)
    """

    PROTOCOL_NAME = "eigrp"
    DISPLAY_FILTER = "eigrp"
    REQUIRED_LAYERS = ("eigrp",)
    PROTOCOL_COLUMNS = (
        "as_num",
        "vrid",
        "opcode",
        "seq",
        "flags",
        "hold_time",
        "software",
        "routes",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 30,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.autonomous_systems: Dict[int, Dict] = {}  # AS -> info
        self.credentials: List[EIGRPCredential] = []
        self._seen_creds: Set[Tuple[str, int, str]] = set()  # (router_ip, auth_type, digest)
        # Integrity/NSF alerts accumulate here and are surfaced via harvest();
        # previously they were built into a per-packet local and discarded.
        self._alerts: List[Dict[str, str]] = []

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format EIGRP protocol-specific columns."""
        d = ix.details
        routes = d.get("routes", [])
        route_str = ", ".join(r.get("network", "?") for r in routes)
        as_num = d.get("as_number", "")
        if as_num == 0 or as_num == "":
            as_num = "?"
            self.logger.debug(f"Missing AS number in EIGRP interaction from {ix.src_ip}")
        vrid = d.get("vrid", "?")
        seq_num = d.get("seq_num", "?")
        return [
            as_num,
            vrid,
            d.get("opcode_name", ix.operation),
            seq_num,
            ", ".join(d.get("flag_names", [])) or "-",
            d.get("hold_time", "?"),
            d.get("software_version", "") or "-",
            route_str if route_str else str(len(routes)),
        ]

    def harvest(self) -> Dict[str, Any]:
        """Harvest EIGRP data, surfacing accumulated integrity/NSF alerts.

        Does NOT early-return on an empty super().harvest(): the base returns {}
        when there are no write/control ops (always, for EIGRP), which would
        otherwise drop every bad-checksum / restart alert.
        """
        result = super().harvest()
        result = result or {}
        if self._alerts:
            result.setdefault("alerts", []).extend(self._alerts)
        return result

    def process_packet(self, packet) -> None:
        """Process EIGRP packet using PyShark's EIGRP dissector."""
        if not hasattr(packet, "eigrp"):
            return

        eigrp = packet.eigrp

        # Get IP info
        src_ip, dst_ip = self.get_ip_info(packet)
        flow_id = self.get_flow_id(packet)
        if not src_ip:
            return

        # Skip invalid IPs
        if not is_valid_discovered_ip(src_ip):
            return

        # Get MAC info
        src_mac, _ = self.get_mac_info(packet)

        # Extract EIGRP header fields
        version = self._parse_int(self.get_field(eigrp, "version", "2"), 2)
        opcode = self._parse_int(self.get_field(eigrp, "opcode", "0"), 0)
        flags = self._parse_int(self.get_field(eigrp, "flags", "0"), 0)
        as_number = self._parse_int(self.get_field(eigrp, "as", "0"), 0)

        # T1: eigrp.seq -- EK mode uses "seq", XML mode uses "sequence"
        seq_num = self._parse_int(
            self.get_field_any(eigrp, "seq", "sequence", default="0"),
            0,
        )
        if seq_num == 0 and opcode != 5:  # non-Hello with seq=0 is unusual
            self.logger.debug(f"EIGRP seq=0 for non-Hello opcode={opcode} from {src_ip}")

        # T2: eigrp.ack -- EK mode uses "ack", XML mode uses "acknowledge"
        ack_num = self._parse_int(
            self.get_field_any(eigrp, "ack", "acknowledge", default="0"),
            0,
        )

        # T1: eigrp.vrid -- Virtual Router ID
        vrid = self._parse_int(self.get_field(eigrp, "vrid", "0"), 0)

        # T1: eigrp.checksum + eigrp.checksum.status
        checksum_raw = self.get_field(eigrp, "checksum", "")
        # NB: 0 means "Bad", so an ABSENT field must NOT default to 0 or every
        # capture without checksum validation would raise a forgery alert.
        checksum_status_raw = self.get_field(eigrp, "checksum_status", None)
        checksum_status = (
            self._parse_int(checksum_status_raw, CHECKSUM_STATUS_NOT_PRESENT)
            if checksum_status_raw is not None
            else CHECKSUM_STATUS_NOT_PRESENT
        )
        checksum_status_name = EIGRP_CHECKSUM_STATUS.get(
            checksum_status, f"Unknown({checksum_status})"
        )

        # T1: eigrp.release_version + eigrp.tlv_version
        release_version_raw = self._parse_int(self.get_field(eigrp, "release_version", "0"), 0)
        tlv_version_raw = self._parse_int(self.get_field(eigrp, "tlv_version", "0"), 0)
        # Decode packed versions: high byte = major, low byte = minor
        release_major = (release_version_raw >> 8) & 0xFF
        release_minor = release_version_raw & 0xFF
        tlv_major = (tlv_version_raw >> 8) & 0xFF
        tlv_minor = tlv_version_raw & 0xFF
        release_version = f"{release_major}.{release_minor}" if release_version_raw else ""
        tlv_version = f"{tlv_major}.{tlv_minor}" if tlv_version_raw else ""

        # T1: eigrp.flags.restart -- Restart/NSF flag (individual boolean)
        flags_restart = self.get_field(eigrp, "flags_restart", None)
        flags_init = self.get_field(eigrp, "flags_init", None)
        flags_condrecv = self.get_field(eigrp, "flags_condrecv", None)
        flags_eot = self.get_field(eigrp, "flags_eot", None)

        # Parse flags -- prefer individual boolean fields (EK mode), fall back to bitmask
        flag_names = []
        if flags_restart is not None:
            # EK mode: individual boolean fields available
            if _is_true(flags_init):
                flag_names.append("Init")
            if _is_true(flags_condrecv):
                flag_names.append("Conditional Receive")
            if _is_true(flags_restart):
                flag_names.append("Restart")
            if _is_true(flags_eot):
                flag_names.append("End of Table")
        else:
            # XML mode fallback: parse bitmask
            for bit, name in EIGRP_FLAGS.items():
                if flags & bit:
                    flag_names.append(name)

        # Extract authentication credentials
        self._extract_credentials(eigrp, src_ip, as_number)

        # Extract K-values and hold time from Parameter TLV fields
        k_values = {}
        hold_time = 15  # default
        software_version = ""
        routes: List[Dict] = []

        # PyShark exposes Parameter TLV fields directly on the eigrp layer
        k1 = self.get_field(eigrp, "par_k1", None)
        if k1 is not None:
            k_values = {
                "k1": self._parse_int(self.get_field(eigrp, "par_k1", "1"), 1),
                "k2": self._parse_int(self.get_field(eigrp, "par_k2", "0"), 0),
                "k3": self._parse_int(self.get_field(eigrp, "par_k3", "1"), 1),
                "k4": self._parse_int(self.get_field(eigrp, "par_k4", "0"), 0),
                "k5": self._parse_int(self.get_field(eigrp, "par_k5", "0"), 0),
                "k6": self._parse_int(self.get_field(eigrp, "par_k6", "0"), 0),
            }
            hold_time = self._parse_int(self.get_field(eigrp, "par_holdtime", "15"), 15)

        # Software version (SW Version TLV) - reuse the decoded release_version /
        # tlv_version above (there are no eigrp.sw_version.* fields).
        if release_version:
            software_version = f"IOS {release_version}, EIGRP {tlv_version}"

        # --- Route extraction (IPv4 internal) ---
        # A single Update can bundle many Route TLVs; get_field comma-joins the
        # repeated ipv4_destination / ipv4_prefixlen values, so split and pair
        # positionally (mirrors rip.py) instead of treating them as one scalar.
        ip_prefix = self.get_field(eigrp, "ipv4_destination", None)
        if ip_prefix is not None:
            nets = str(ip_prefix).split(",")
            prefix_lens = str(self.get_field(eigrp, "ipv4_prefixlen", "0")).split(",")
            for i, net in enumerate(nets):
                net = net.strip()
                if not net:
                    continue
                plen = prefix_lens[i].strip() if i < len(prefix_lens) else "0"
                routes.append(
                    {
                        "network": net,
                        "prefix_len": self._parse_int(plen, 0),
                        "type": "internal",
                        "af": "ipv4",
                    }
                )

        # --- Route extraction (IPv6 internal/external) ---
        # Split repeated TLVs positionally (see IPv4 note above).
        ipv6_dest = self.get_field(eigrp, "ipv6_destination", None)
        if ipv6_dest is not None:
            v6_nets = str(ipv6_dest).split(",")
            v6_plens = str(self.get_field(eigrp, "ipv6_prefixlen", "0")).split(",")
            v6_nhs = str(self.get_field(eigrp, "ipv6_nexthop", "")).split(",")
            v6_types = str(self.get_field(eigrp, "tlv_type", "")).split(",")
            for i, net in enumerate(v6_nets):
                net = net.strip()
                if not net:
                    continue
                plen = self._parse_int(v6_plens[i].strip() if i < len(v6_plens) else "0", 0)
                tlv_type_int = self._parse_int(v6_types[i].strip() if i < len(v6_types) else "0", 0)
                route_type = "external" if tlv_type_int == 0x0403 else "internal"
                route_entry: Dict[str, Any] = {
                    "network": net,
                    "prefix_len": plen,
                    "type": route_type,
                    "af": "ipv6",
                }
                nh = v6_nhs[i].strip() if i < len(v6_nhs) else ""
                if nh and nh != "::":
                    route_entry["nexthop"] = nh
                routes.append(route_entry)

        # --- T1: eigrp.old_metric.rel + other route metrics ---
        old_metric: Dict[str, Any] = {}
        old_metric_rel = self.get_field(eigrp, "old_metric_rel", None)
        if old_metric_rel is not None:
            old_metric["reliability"] = self._parse_int(old_metric_rel, 0)
            old_metric["bandwidth"] = self._parse_int(
                self.get_field(eigrp, "old_metric_bw", "0"), 0
            )
            old_metric["delay"] = self._parse_int(self.get_field(eigrp, "old_metric_delay", "0"), 0)
            old_metric["load"] = self._parse_int(self.get_field(eigrp, "old_metric_load", "0"), 0)
            old_metric["hopcount"] = self._parse_int(
                self.get_field(eigrp, "old_metric_hopcount", "0"), 0
            )
            old_metric["mtu"] = self._parse_int(self.get_field(eigrp, "old_metric_mtu", "0"), 0)
            # Attach metrics to routes extracted in this packet
            for route in routes:
                route["metric"] = old_metric

        # --- External route data ---
        extdata: Dict[str, Any] = {}
        extdata_origrid = self.get_field(eigrp, "extdata_origrid", None)
        if extdata_origrid is not None:
            extdata["originating_router_id"] = str(extdata_origrid)
            extdata["originating_as"] = self._parse_int(self.get_field(eigrp, "extdata_as", "0"), 0)
            extdata["originating_protocol"] = self._parse_int(
                self.get_field(eigrp, "extdata_proto", "0"), 0
            )
            extdata["external_metric"] = self._parse_int(
                self.get_field(eigrp, "extdata_metric", "0"), 0
            )
            extdata["external_tag"] = self._parse_int(self.get_field(eigrp, "extdata_tag", "0"), 0)
            for route in routes:
                route["external_data"] = extdata

        # Alert on bad checksum
        if checksum_status == CHECKSUM_STATUS_BAD:  # Bad checksum
            self._alerts.append(
                {
                    "level": "fail",
                    "category": "integrity_alert",
                    "message": (
                        f"EIGRP BAD CHECKSUM: {src_ip} -> {dst_ip} "
                        f"(checksum={checksum_raw}, status={checksum_status_name})"
                    ),
                }
            )
            self.logger.debug(
                f"EIGRP bad checksum from {src_ip}: raw={checksum_raw} status={checksum_status}"
            )

        # Alert on Restart flag (NSF event)
        if "Restart" in flag_names:
            self._alerts.append(
                {
                    "level": "info",
                    "category": "restart_alert",
                    "message": f"EIGRP RESTART: {src_ip} AS={as_number} (NSF signaling detected)",
                }
            )

        # Record interaction
        opcode_name = EIGRP_OPCODES.get(opcode, f"Opcode_{opcode}")
        now = datetime.now().isoformat()
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            f"EIGRP {opcode_name}",
            {
                "opcode": opcode,
                "opcode_name": opcode_name,
                "as_number": as_number,
                "vrid": vrid,
                "seq_num": seq_num,
                "ack_num": ack_num,
                "flag_names": flag_names,
                "hold_time": hold_time,
                "software_version": software_version,
                "routes": routes,
                "checksum_status": checksum_status_name,
                "release_version": release_version,
                "tlv_version": tlv_version,
                "old_metric": old_metric if old_metric else None,
            },
            f"EIGRP {opcode_name} AS={as_number} seq={seq_num}",
            flow_id=flow_id,
        )

        self._update_device(
            src_ip=src_ip,
            src_mac=src_mac if src_mac else "",
            dst_ip=dst_ip,
            version=version,
            opcode=opcode,
            as_number=as_number,
            flags=flags,
            flag_names=flag_names,
            seq_num=seq_num,
            ack_num=ack_num,
            vrid=vrid,
            k_values=k_values,
            hold_time=hold_time,
            software_version=software_version,
            routes=routes,
            release_version=release_version,
            tlv_version=tlv_version,
            checksum_status=checksum_status,
            checksum_status_name=checksum_status_name,
        )

    def _extract_credentials(self, eigrp, src_ip: str, as_number: int) -> None:
        """Extract EIGRP authentication data (MD5/SHA-256 digest)."""
        # Try both EK-mode and XML-mode field names
        auth_type_raw = self.get_field_any(eigrp, "auth_type", "auth.type")
        if auth_type_raw is None:
            return

        auth_type = self._parse_int(auth_type_raw, 0)
        if auth_type not in EIGRP_AUTH_TYPES:
            return

        digest = str(self.get_field_any(eigrp, "auth_digest", "auth.digest", default="")).strip()
        if not digest:
            return

        key_id = self._parse_int(
            self.get_field_any(eigrp, "auth_keyid", "auth.keyid", default="0"),
            0,
        )
        auth_type_name = EIGRP_AUTH_TYPES.get(auth_type, f"Unknown({auth_type})")

        # T1: eigrp.auth.keyseq -- key sequence for rotation tracking
        key_seq = self._parse_int(
            self.get_field_any(eigrp, "auth_keyseq", "auth.keyseq", default="0"),
            0,
        )

        # T1: eigrp.auth.length -- auth data length
        auth_length = self._parse_int(
            self.get_field_any(eigrp, "auth_length", "auth.length", default="0"),
            0,
        )

        cred_key = (src_ip, auth_type, digest)
        if cred_key in self._seen_creds:
            return
        self._seen_creds.add(cred_key)

        cred = EIGRPCredential(
            auth_type=auth_type,
            auth_type_name=auth_type_name,
            credential_type="hash",
            auth_data=digest,
            key_id=key_id,
            key_seq=key_seq,
            auth_length=auth_length,
            router_ip=src_ip,
            as_number=as_number,
            timestamp=datetime.now().isoformat(),
        )
        self.credentials.append(cred)
        self.logger.info(
            f"EIGRP: {auth_type_name} digest from {src_ip} AS={as_number} "
            f"key={key_id} keyseq={key_seq} len={auth_length}"
        )

    def _update_device(
        self,
        src_ip: str,
        src_mac: str,
        dst_ip: str,
        version: int,
        opcode: int,
        as_number: int,
        flags: int,
        flag_names: List[str],
        seq_num: int,
        ack_num: int,
        vrid: int,
        k_values: Dict,
        hold_time: int,
        software_version: str,
        routes: List[Dict],
        release_version: str,
        tlv_version: str,
        checksum_status: int,
        checksum_status_name: str,
    ) -> None:
        """Update or create device entry."""
        # Use MAC as key if available, otherwise fall back to IP-based key
        device_key = src_mac if src_mac else f"eigrp:{src_ip}:{as_number}"

        opcode_name = EIGRP_OPCODES.get(opcode, f"Unknown({opcode})")

        manufacturer = lookup_mac_vendor(src_mac) if src_mac else ""

        device, is_new = self._ensure_device(
            device_key,
            src_ip,
            mac=src_mac,
            name=f"EIGRP Router (AS {as_number})",
            device_type="Router (EIGRP)",
            manufacturer=manufacturer if manufacturer != "Unknown" else "",
        )
        if is_new:
            device.eigrp_data = {
                "version": version,
                "as_number": as_number,
                "opcode": opcode,
                "opcode_name": opcode_name,
                "flags": flags,
                "flag_names": flag_names,
                "hold_time": hold_time,
                "k_values": k_values,
                "software_version": software_version,
                "routes": routes,
                "route_count": len(routes),
                "multicast_dst": dst_ip,
                "protocol": "EIGRP",
                "vrid": vrid,
                "release_version": release_version,
                "tlv_version": tlv_version,
                "checksum_status": checksum_status_name,
            }

            # Track AS
            if as_number not in self.autonomous_systems:
                self.autonomous_systems[as_number] = {
                    "as_number": as_number,
                    "routers": [],
                }
            self.autonomous_systems[as_number]["routers"].append(
                {
                    "ip": src_ip,
                    "hold_time": hold_time,
                }
            )

            self.logger.debug(
                f"EIGRP: {src_ip} AS={as_number} VRID={vrid} "
                f"{opcode_name} seq={seq_num} hold={hold_time}s"
            )
        else:
            data = self.discovered_devices[device_key].eigrp_data
            if data is None:
                data = {}
                self.discovered_devices[device_key].eigrp_data = data
            # Update routes if new ones found
            existing_routes = data.get("routes", [])
            existing_networks = {r.get("network") for r in existing_routes}
            for route in routes:
                if route.get("network") not in existing_networks:
                    existing_routes.append(route)
            data["routes"] = existing_routes
            data["route_count"] = len(existing_routes)
            # Update software version if newly discovered
            if software_version and not data.get("software_version"):
                data["software_version"] = software_version
            # Update release/tlv version if newly discovered
            if release_version and not data.get("release_version"):
                data["release_version"] = release_version
            if tlv_version and not data.get("tlv_version"):
                data["tlv_version"] = tlv_version

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted EIGRP credentials."""
        return [
            {
                "protocol": "EIGRP",
                "credential_type": cred.credential_type,
                "username": cred.auth_data,
                "server_ip": cred.router_ip,
                "client_ip": cred.router_ip,
                "auth_method": cred.auth_type_name,
                "key_id": cred.key_id,
                "key_seq": cred.key_seq,
                "auth_length": cred.auth_length,
                "as_number": cred.as_number,
                "timestamp": cred.timestamp,
            }
            for cred in self.credentials
        ]


def _is_true(value) -> bool:
    """Check if a PyShark boolean field is truthy.

    EK mode returns native bool; XML mode returns string "True"/"False"/"1"/"0".
    """
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    return s in ("true", "1", "yes")

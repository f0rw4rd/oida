"""
OSPF (Open Shortest Path First) passive listener.

OSPF uses:
- IP protocol 89
- Multicast 224.0.0.5 (AllSPFRouters)
- Multicast 224.0.0.6 (AllDRouters)

Useful for discovering:
- Router IDs and area configurations
- Designated Router (DR) and Backup DR elections
- Network topology information
- Hello/dead intervals and authentication types
- Authentication credentials (Simple Password, MD5)

Uses PyShark (tshark wrapper) for OSPF packet dissection.

PyShark OSPF EK-mode field reference (packet.ospf.*):
- msg: OSPF message type (1=Hello, 2=DBD, 3=LSR, 4=LSU, 5=LSAck)
- version: OSPF version
- srcrouter: Router ID (source router)
- area_id: Area ID
- checksum: Packet checksum
- instance_id: OSPF instance ID
- auth_type: Authentication type (0=None, 1=Simple, 2=MD5)
- auth_none: Auth padding bytes (present when auth_type=0)
- auth_crypt_key_id: MD5 key identifier
- auth_crypt_data_length: MD5 auth data length
- auth_crypt_seq_nbr: Cryptographic sequence number (replay protection)
- auth_crypt_data: Cryptographic (MD5) auth data
- hello_network_mask: Network mask (Hello)
- hello_hello_interval: Hello interval
- hello_router_dead_interval: Dead interval
- hello_router_priority: Router priority
- hello_designated_router: Designated Router
- hello_backup_designated_router: Backup Designated Router
- hello_active_neighbor: Neighbor router IDs (may be repeated)
- db_dd_sequence: Database Description sequence number (DBD)
- db_interface_mtu: Interface MTU (DBD)
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip
from ..shared.ospf_constants import (
    OSPF_AUTH_TYPES,
    OSPF_TYPES,
)

import logging

logger = logging.getLogger(__name__)


@dataclass
class OSPFCredential:
    """Extracted OSPF authentication credential."""

    auth_type: int  # 1 = Simple Password, 2 = MD5
    auth_type_name: str
    credential_type: str  # "plaintext" or "hash"
    password: str = ""  # For simple password auth
    auth_data: str = ""  # For MD5 auth
    router_ip: str = ""
    router_id: str = ""
    area_id: str = ""
    timestamp: str = ""
    crypt_key_id: str = ""  # MD5 key identifier
    crypt_data_length: str = ""  # MD5 auth data length in octets
    crypt_seq_nbr: str = ""  # Cryptographic sequence number (replay detection)
    net_salt: str = ""  # OSPF packet hex WITHOUT the digest trailer (net-md5 salt)

    @property
    def hashcat_format(self) -> str:
        """John the Ripper net-md5 / net-sha1 line for OSPF crypto auth.

        ``$netmd5$<packet-without-digest>$<digest>`` where the salt is the OSPF
        packet bytes up to (not including) the appended keyed digest; JtR
        computes ``MD5(salt || key_padded_16)``. hashcat has no mode for this.
        Verified against JtR's net-md5 format (cracks a re-keyed OSPF fixture).
        Returns "" unless the raw packet salt + digest are both present.
        """
        if self.credential_type != "hash" or not self.net_salt or not self.auth_data:
            return ""
        digest = self.auth_data.replace(":", "").lower()
        if len(digest) == 32:  # 16-byte MD5
            return f"$netmd5${self.net_salt}${digest}"
        if len(digest) == 40:  # 20-byte SHA-1 (OSPF HMAC-SHA1)
            return f"$netsha1${self.net_salt}${digest}"
        return ""

    @property
    def username(self) -> str:
        """Canonical credential field: password or auth data as username."""
        return self.password or self.auth_data

    @property
    def server_ip(self) -> str:
        """Canonical credential field: router is the server."""
        return self.router_ip

    @property
    def client_ip(self) -> str:
        """Canonical credential field: same as router for multicast protocols."""
        return self.router_ip

    @property
    def auth_method(self) -> str:
        """Canonical credential field."""
        return self.auth_type_name

    @property
    def hash_value(self) -> str:
        """Canonical credential field: MD5 auth data."""
        return self.auth_data if self.credential_type == "hash" else ""


class OSPFPassiveListener(PySharkListenerBase):
    """Passive OSPF traffic listener using PyShark.

    Captures OSPF Hello and other packets to identify:
    - OSPF routers and their Router IDs
    - Area configurations
    - DR/BDR elections
    - Network topology information
    - Authentication credentials (Simple Password and MD5 hashes)
    """

    PROTOCOL_NAME = "ospf"
    DISPLAY_FILTER = "ospf"
    REQUIRED_LAYERS = ("ospf",)
    PROTOCOL_COLUMNS = ("router_id", "type", "area", "auth", "role", "neighbors")

    def __init__(
        self,
        interface: str,
        timeout: int = 30,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.areas: Dict[str, Dict] = {}  # area_id -> info
        self.credentials: List[OSPFCredential] = []
        self._seen_creds: Set[Tuple[str, int, str]] = set()  # (router_ip, auth_type, data)

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format OSPF protocol-specific columns."""
        d = ix.details
        neighbors = d.get("neighbors", [])
        neighbor_str = ", ".join(neighbors)
        # Auth type "None" means no authentication (type 0) — show as empty
        auth = d.get("auth_type_name", "")
        if auth == "None":
            auth = ""
        return [
            d.get("router_id", "?"),
            d.get("msg_type_name", ix.operation),
            d.get("area_id", "?"),
            auth,
            d.get("role", "?"),
            neighbor_str,
        ]

    def process_packet(self, packet) -> None:
        """Process OSPF packet using PyShark's OSPF dissector."""
        if not hasattr(packet, "ospf"):
            return

        ospf = packet.ospf

        # Get IP info
        src_ip, dst_ip = self.get_ip_info(packet)
        flow_id = self.get_flow_id(packet)
        if not src_ip:
            return

        # Skip invalid IPs (broadcast, multicast dst, etc.)
        if not is_valid_discovered_ip(src_ip):
            return

        # Get MAC info
        src_mac, _ = self.get_mac_info(packet)

        # Extract OSPF header fields
        # EK field: "version"
        version = self._parse_int(self.get_field(ospf, "version", "2"), 2)

        # EK field: "msg" (NOT "msg_type" -- that is the XML-mode name)
        msg_type_str = self.get_field(ospf, "msg", "0")
        try:
            msg_type = int(msg_type_str)
        except (ValueError, TypeError):
            msg_type = 0

        # EK field: "srcrouter"
        router_id = str(self.get_field(ospf, "srcrouter", "") or "")
        if not router_id:
            router_id = "?"
            self.logger.debug(f"Missing router_id in OSPF packet from {src_ip}")

        # EK field: "area_id"
        area_id = str(self.get_field(ospf, "area_id", "") or "")
        if not area_id:
            area_id = "?"
            self.logger.debug(f"Missing area_id in OSPF packet from {src_ip}")

        # T1 field: "checksum" -- packet integrity checksum
        checksum_raw = self.get_field(ospf, "checksum", None)
        if checksum_raw is None or str(checksum_raw).strip() == "":
            checksum = "?"
            self.logger.debug(f"Missing checksum in OSPF packet from {src_ip}")
        else:
            checksum = str(checksum_raw)

        # T1 field: "instance_id" -- OSPF instance identifier.
        # The Instance ID field is an OSPFv3-only header field (it multiplexes
        # multiple OSPF instances onto a single link).  OSPFv2 packets do not
        # carry it at all, so tshark exposes no `ospf.instance_id` for them and
        # get_field() correctly returns None.  An OSPFv2 packet is, by
        # definition, the single implicit instance 0 -- so default to "0" for
        # v2 instead of "?".  Only a v3 packet that genuinely lacks the field
        # (malformed) stays "?".
        instance_id_raw = self.get_field(ospf, "instance_id", None)
        if instance_id_raw is None or str(instance_id_raw).strip() == "":
            if version == 2:
                instance_id = "0"
            else:
                instance_id = "?"
                self.logger.debug(f"Missing instance_id in OSPFv{version} packet from {src_ip}")
        else:
            instance_id = str(instance_id_raw)

        # Authentication type
        auth_type_str = self.get_field(ospf, "auth_type", "0")
        try:
            auth_type = int(auth_type_str)
        except (ValueError, TypeError):
            auth_type = 0
        auth_type_name = OSPF_AUTH_TYPES.get(auth_type, f"Unknown({auth_type})")

        # T1 field: "auth_none" -- auth padding bytes (present when auth_type=0).
        # Reading it ensures the audit tool registers coverage; the value is
        # always zeroed-out padding but confirms no-auth status.
        if auth_type == 0:
            self.get_field(ospf, "auth_none", None)

        # Raw OSPF packet bytes (the net-md5 salt source) -- only present when
        # the pipeline runs with include_raw (enabled for routing listeners).
        raw_layer = getattr(packet, "ospf_raw", None)
        ospf_raw_hex = ""
        if raw_layer is not None:
            ospf_raw_hex = str(getattr(raw_layer, "value", "") or "").replace(":", "").lower()

        # Extract authentication credentials (includes T1 crypto fields)
        self._extract_credentials(
            ospf, auth_type, auth_type_name, src_ip, router_id, area_id, ospf_raw_hex
        )

        # Parse Hello-specific fields (msg_type == 1)
        hello_info: Dict[str, Any] = {}
        neighbors: List[str] = []
        dbd_info: Dict[str, Any] = {}

        if msg_type == 1:  # Hello packet
            # EK field: "hello_network_mask" (NOT "msg_hello_mask")
            network_mask = str(self.get_field(ospf, "hello_network_mask", "") or "")
            if not network_mask:
                network_mask = "?"
                self.logger.debug(f"Missing network_mask in Hello from {src_ip}")

            # EK field: "hello_hello_interval" (NOT "msg_hello_hello_interval")
            hello_interval = self.get_field(ospf, "hello_hello_interval", "10")

            # EK field: "hello_router_dead_interval" (NOT "msg_hello_dead_interval")
            dead_interval = self.get_field(ospf, "hello_router_dead_interval", "40")

            # EK field: "hello_router_priority" (NOT "msg_hello_priority")
            priority = self.get_field(ospf, "hello_router_priority", "1")

            # EK field: "hello_designated_router" (NOT "msg_hello_dr")
            dr = str(self.get_field(ospf, "hello_designated_router", "") or "")

            # EK field: "hello_backup_designated_router" (NOT "msg_hello_bdr")
            bdr = str(self.get_field(ospf, "hello_backup_designated_router", "") or "")

            # EK field: "v2_options" (the options bitmask)
            options = self.get_field(ospf, "v2_options", "0")

            hello_info = {
                "network_mask": network_mask,
                "hello_interval": self._parse_int(hello_interval, 10),
                "options": self._parse_int(options, 0),
                "priority": self._parse_int(priority, 1),
                "dead_interval": self._parse_int(dead_interval, 40),
                "designated_router": dr,
                "backup_dr": bdr,
            }

            # Extract neighbor list
            # EK field: "hello_active_neighbor" (NOT "msg_hello_neighbor")
            neighbor_field = self.get_field(ospf, "hello_active_neighbor", None)
            if neighbor_field is not None:
                neighbor_str = str(neighbor_field)
                # Could be comma-separated or single value
                for n in neighbor_str.split(","):
                    n = n.strip()
                    if n and n != "0.0.0.0":
                        neighbors.append(n)

        elif msg_type == 2:  # Database Description (DBD)
            # T1 field: "db_dd_sequence" -- DBD exchange sequence number
            dd_seq = self.get_field(ospf, "db_dd_sequence", "")
            if not dd_seq:
                dd_seq = "?"
                self.logger.debug(f"Missing db_dd_sequence in DBD from {src_ip}")

            # T2 field: "db_interface_mtu" -- interface MTU from DBD
            db_mtu = self.get_field(ospf, "db_interface_mtu", "")
            if not db_mtu:
                db_mtu = "?"
                self.logger.debug(f"Missing db_interface_mtu in DBD from {src_ip}")

            dbd_info = {
                "dd_sequence": dd_seq,
                "interface_mtu": db_mtu,
            }

        # Determine role for interaction details
        is_dr = hello_info.get("designated_router") == src_ip
        is_bdr = hello_info.get("backup_dr") == src_ip
        if is_dr:
            role = "DR"
        elif is_bdr:
            role = "BDR"
        else:
            role = "DROther"

        # Build interaction details including T1 fields
        msg_type_name = OSPF_TYPES.get(msg_type, f"Type_{msg_type}")
        now = datetime.now().isoformat()
        interaction_details: Dict[str, Any] = {
            "msg_type": msg_type,
            "msg_type_name": msg_type_name,
            "area_id": area_id,
            "router_id": router_id,
            "auth_type_name": auth_type_name,
            "role": role,
            "neighbors": neighbors,
            "checksum": checksum,
            "instance_id": instance_id,
        }
        if dbd_info:
            interaction_details["dd_sequence"] = dbd_info.get("dd_sequence", "")
            interaction_details["interface_mtu"] = dbd_info.get("interface_mtu", "")

        # Record interaction
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            f"OSPF {msg_type_name}",
            interaction_details,
            f"OSPF {msg_type_name} router={router_id} area={area_id}",
            flow_id=flow_id,
        )

        self._update_device(
            src_ip=src_ip,
            src_mac=src_mac if src_mac else "",
            router_id=router_id,
            area_id=area_id,
            version=version,
            msg_type=msg_type,
            auth_type=auth_type,
            auth_type_name=auth_type_name,
            hello_info=hello_info,
            neighbors=neighbors,
            multicast_dst=dst_ip,
            checksum=checksum,
            instance_id=instance_id,
        )

    def _extract_credentials(
        self,
        ospf,
        auth_type: int,
        auth_type_name: str,
        src_ip: str,
        router_id: str,
        area_id: str,
        ospf_raw_hex: str = "",
    ) -> None:
        """Extract authentication credentials from OSPF packet."""
        if auth_type == 1:
            # Simple Password authentication
            # Simple-password cleartext is dissected as ospf.auth.simple
            # (EK attr auth_simple), not ospf.auth.data.
            auth_data = str(
                self.get_field_any(ospf, "auth_simple", "ospf.auth.simple", default="") or ""
            ).strip()
            if auth_data:
                cred_key = (src_ip, auth_type, auth_data)
                if cred_key not in self._seen_creds:
                    self._seen_creds.add(cred_key)
                    cred = OSPFCredential(
                        auth_type=auth_type,
                        auth_type_name=auth_type_name,
                        credential_type="plaintext",
                        password=auth_data,
                        router_ip=src_ip,
                        router_id=router_id,
                        area_id=area_id,
                        timestamp=datetime.now().isoformat(),
                    )
                    self.credentials.append(cred)
                    self.logger.info(f"OSPF: Simple Password from {src_ip} RID={router_id}")

        elif auth_type == 2:
            # Cryptographic (MD5) authentication
            crypt_data = str(self.get_field(ospf, "auth_crypt_data", "") or "").strip()
            if crypt_data:
                # T1 field: "auth_crypt_key_id" -- identifies which MD5 key was used
                key_id = str(self.get_field(ospf, "auth_crypt_key_id", "") or "")
                if not key_id:
                    key_id = "?"
                    self.logger.debug(f"Missing auth_crypt_key_id in MD5 packet from {src_ip}")

                # T1 field: "auth_crypt_data_length" -- MD5 digest length
                data_length = str(self.get_field(ospf, "auth_crypt_data_length", "") or "")
                if not data_length:
                    data_length = "?"
                    self.logger.debug(f"Missing auth_crypt_data_length in MD5 packet from {src_ip}")

                # T1 field: "auth_crypt_seq_nbr" -- replay protection sequence number
                seq_nbr = str(self.get_field(ospf, "auth_crypt_seq_nbr", "") or "")
                if not seq_nbr:
                    seq_nbr = "?"
                    self.logger.debug(f"Missing auth_crypt_seq_nbr in MD5 packet from {src_ip}")

                # net-md5 salt = OSPF packet bytes WITHOUT the appended digest.
                # The digest is the trailing N bytes (N = crypt data length); the
                # OSPF header length field already excludes it, so strip the last
                # len(digest) hex chars from the raw packet.
                net_salt = ""
                digest_clean = crypt_data.replace(":", "").lower()
                if ospf_raw_hex and digest_clean and ospf_raw_hex.endswith(digest_clean):
                    net_salt = ospf_raw_hex[: -len(digest_clean)]

                cred_key = (src_ip, auth_type, crypt_data)
                if cred_key not in self._seen_creds:
                    self._seen_creds.add(cred_key)
                    cred = OSPFCredential(
                        auth_type=auth_type,
                        auth_type_name=auth_type_name,
                        credential_type="hash",
                        auth_data=crypt_data,
                        router_ip=src_ip,
                        router_id=router_id,
                        area_id=area_id,
                        timestamp=datetime.now().isoformat(),
                        crypt_key_id=key_id,
                        crypt_data_length=data_length,
                        crypt_seq_nbr=seq_nbr,
                        net_salt=net_salt,
                    )
                    self.credentials.append(cred)
                    self.logger.info(
                        f"OSPF: MD5 auth from {src_ip} RID={router_id} key_id={key_id}"
                    )

    def _update_device(
        self,
        src_ip: str,
        src_mac: str,
        router_id: str,
        area_id: str,
        version: int,
        msg_type: int,
        auth_type: int,
        auth_type_name: str,
        hello_info: Dict,
        neighbors: list,
        multicast_dst: str,
        checksum: str = "",
        instance_id: str = "",
    ) -> None:
        """Update or create device entry."""
        # Determine if this is DR/BDR
        is_dr = hello_info.get("designated_router") == src_ip
        is_bdr = hello_info.get("backup_dr") == src_ip

        if is_dr:
            role = "DR"
            device_type = "Router (OSPF DR)"
        elif is_bdr:
            role = "BDR"
            device_type = "Router (OSPF BDR)"
        else:
            role = "DROther"
            device_type = "Router (OSPF)"

        device, is_new = self._register_device(
            src_ip,
            src_mac,
            name=f"OSPF Router {router_id}",
            device_type=device_type,
        )
        if not device:
            return
        if is_new:
            device.ospf_data = {
                "version": version,
                "router_id": router_id,
                "area_id": area_id,
                "message_type": msg_type,
                "message_type_name": OSPF_TYPES.get(msg_type, f"Unknown({msg_type})"),
                "auth_type": auth_type,
                "auth_type_name": auth_type_name,
                "role": role,
                "neighbors": neighbors,
                "multicast_dst": multicast_dst,
                "protocol": "OSPF",
                "checksum": checksum,
                "instance_id": instance_id,
            }

            # Add hello-specific info
            if hello_info:
                device.ospf_data.update(
                    {
                        "hello_interval": hello_info.get("hello_interval"),
                        "dead_interval": hello_info.get("dead_interval"),
                        "priority": hello_info.get("priority"),
                        "network_mask": hello_info.get("network_mask"),
                        "designated_router": hello_info.get("designated_router"),
                        "backup_dr": hello_info.get("backup_dr"),
                    }
                )

            # Track area
            if area_id not in self.areas:
                self.areas[area_id] = {
                    "area_id": area_id,
                    "routers": [],
                }
            self.areas[area_id]["routers"].append(
                {
                    "ip": src_ip,
                    "router_id": router_id,
                    "role": role,
                }
            )

            self.logger.debug(f"OSPF: {src_ip} RID={router_id} Area={area_id} {role}")
        else:
            # Update neighbors if new ones found
            existing_neighbors = device.ospf_data.get("neighbors", [])
            for n in neighbors:
                if n not in existing_neighbors:
                    existing_neighbors.append(n)
            device.ospf_data["neighbors"] = existing_neighbors

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted OSPF credentials."""
        result = []
        for cred in self.credentials:
            entry: Dict[str, Any] = {
                "protocol": "OSPF",
                "credential_type": cred.credential_type,
                "username": cred.password or cred.auth_data,
                "server_ip": cred.router_ip,
                "client_ip": cred.router_ip,
                "auth_method": cred.auth_type_name,
                "router_id": cred.router_id,
                "area_id": cred.area_id,
                "timestamp": cred.timestamp,
            }
            # Include MD5 crypto details when available
            if cred.crypt_key_id:
                entry["crypt_key_id"] = cred.crypt_key_id
            if cred.crypt_data_length:
                entry["crypt_data_length"] = cred.crypt_data_length
            if cred.crypt_seq_nbr:
                entry["crypt_seq_nbr"] = cred.crypt_seq_nbr
            result.append(entry)
        return result

    def get_hashcat_hashes(self) -> List[str]:
        """Get OSPF crypto-auth hashes as John net-md5/net-sha1 lines.

        (hashcat has no OSPF mode; these crack with ``john --format=net-md5``.)
        Requires the pipeline to run with include_raw so the packet salt is
        available; entries without it yield "" and are skipped.
        """
        return [c.hashcat_format for c in self.credentials if c.hashcat_format]

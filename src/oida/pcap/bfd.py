"""
BFD Passive Listener for authentication data extraction.

Passively captures BFD (Bidirectional Forwarding Detection) traffic
to extract authentication credentials.

BFD supports several authentication modes:
- Simple Password (type 1): Plaintext password
- Keyed MD5 (type 2): MD5 hash with sequence number
- Meticulous Keyed MD5 (type 3)
- Keyed SHA1 (type 4): SHA1 hash with sequence number
- Meticulous Keyed SHA1 (type 5)

tshark fields (EK-mode names in parentheses):
- bfd.version (version): Protocol version number
- bfd.sta (sta): Session state
- bfd.diag (diag): Diagnostic code for session failure
- bfd.detect_time_multiplier (detect_time_multiplier): Failure detection multiplier
- bfd.message_length (message_length): Control packet length
- bfd.my_discriminator (my_discriminator): Local session discriminator
- bfd.your_discriminator (your_discriminator): Remote session discriminator
- bfd.desired_min_tx_interval (desired_min_tx_interval): Min TX interval
- bfd.required_min_rx_interval (required_min_rx_interval): Min RX interval
- bfd.auth.type (auth_type): Authentication type
- bfd.auth.len (auth_len): Authentication section length
- bfd.auth.key (auth_key): Key ID
- bfd.auth.password (auth_password): Simple password (type 1)
- bfd.auth.seq_num (auth_seq_num): Sequence number

References:
- RFC 5880: Bidirectional Forwarding Detection (BFD)
- RFC 5881: BFD for IPv4 and IPv6 (Single Hop)
- Wireshark dissector: packet-bfd.c
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from .pyshark_base import ProtocolInteraction, PySharkListenerBase

import logging

logger = logging.getLogger(__name__)


# BFD authentication types
BFD_AUTH_TYPES = {
    0: "Reserved",
    1: "Simple Password",
    2: "Keyed MD5",
    3: "Meticulous Keyed MD5",
    4: "Keyed SHA1",
    5: "Meticulous Keyed SHA1",
}


@dataclass
class BFDCredential:
    """Extracted BFD authentication credential."""

    auth_type: int
    auth_type_name: str
    credential_type: str  # "plaintext" or "hash"
    password: str = ""  # For simple password auth
    key_id: int = 0
    seq_num: int = 0
    server_ip: str = ""
    client_ip: str = ""
    timestamp: str = ""

    @property
    def username(self) -> str:
        """Canonical credential field: password as username for simple auth."""
        return self.password

    @property
    def auth_method(self) -> str:
        """Canonical credential field."""
        return self.auth_type_name

    @property
    def hash_value(self) -> str:
        """Canonical credential field: password/digest for hash types."""
        return self.password if self.credential_type == "hash" else ""


class BFDPassiveListener(PySharkListenerBase):
    """Passive BFD traffic listener for authentication data extraction.

    Captures BFD packets to extract authentication passwords and hashes.
    """

    PROTOCOL_NAME = "bfd"
    DISPLAY_FILTER = "bfd"
    REQUIRED_LAYERS = ("bfd",)
    PROTOCOL_COLUMNS = (
        "ver",
        "state",
        "diag",
        "my_disc",
        "your_disc",
        "auth_type",
        "auth_len",
        "min_tx",
        "min_rx",
    )
    # BFD state codes
    BFD_STATES = {0: "AdminDown", 1: "Down", 2: "Init", 3: "Up"}
    BFD_DIAG = {
        0: "No Diagnostic",
        1: "Control Detection Expired",
        2: "Echo Function Failed",
        3: "Neighbor Signaled Down",
        4: "Forwarding Plane Reset",
        5: "Path Down",
        6: "Concatenated Path Down",
        7: "Administratively Down",
        8: "Reverse Concatenated Path Down",
    }

    def __init__(
        self,
        interface: str,
        timeout: int = 30,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.credentials: List[BFDCredential] = []

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format BFD protocol-specific columns."""
        d = ix.details
        return [
            d.get("version", "?"),
            d.get("state_name", ""),
            d.get("diag_name", ""),
            d.get("my_discriminator", ""),
            d.get("your_discriminator", ""),
            d.get("auth_type_name", "None"),
            d.get("auth_len", ""),
            d.get("min_tx", ""),
            d.get("min_rx", ""),
        ]

    def process_packet(self, packet) -> None:
        """Process BFD packet and extract session state + authentication data."""
        if not hasattr(packet, "bfd"):
            return

        bfd = packet.bfd
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        src_port, dst_port = self.get_port_info(packet)
        flow_id = self.get_flow_id(packet)

        # --- T1 field: bfd.version (EK: "version") ---
        version_raw = self.get_field(bfd, "version", None)
        version = _safe_int(version_raw, -1) if version_raw is not None else -1
        if version < 0:
            self.logger.debug(f"Missing bfd.version in packet from {src_ip} -> {dst_ip}")

        # --- Session state fields ---
        # EK-mode field name is "sta" (not "flags_sta")
        state_raw = _safe_int(self.get_field(bfd, "sta", None), -1)
        if state_raw < 0:
            state_name = "?"
            self.logger.debug(f"Missing bfd.sta in packet from {src_ip} -> {dst_ip}")
        else:
            state_name = self.BFD_STATES.get(state_raw, f"Unknown({state_raw})")

        # EK-mode field name is "diag" (not "flags_diag")
        diag_raw = _safe_int(self.get_field(bfd, "diag", None), -1)
        if diag_raw < 0:
            diag_name = "?"
            self.logger.debug(f"Missing bfd.diag in packet from {src_ip} -> {dst_ip}")
        else:
            diag_name = self.BFD_DIAG.get(diag_raw, f"Unknown({diag_raw})")

        # --- T2 fields: discriminators, timing, length ---
        my_disc = str(self.get_field(bfd, "my_discriminator", "") or "").strip()
        your_disc = str(self.get_field(bfd, "your_discriminator", "") or "").strip()
        detect_mult = str(self.get_field(bfd, "detect_time_multiplier", "") or "").strip()
        msg_len = str(self.get_field(bfd, "message_length", "") or "").strip()
        min_tx = str(self.get_field(bfd, "desired_min_tx_interval", "") or "").strip()
        min_rx = str(self.get_field(bfd, "required_min_rx_interval", "") or "").strip()

        # --- Authentication section ---
        auth_type_raw = self.get_field(bfd, "auth_type", None)
        auth_type = _safe_int(auth_type_raw, 0) if auth_type_raw is not None else 0
        auth_type_name = (
            BFD_AUTH_TYPES.get(auth_type, f"Unknown({auth_type})") if auth_type else "None"
        )

        # --- T1 field: bfd.auth.len (EK: "auth_len") ---
        auth_len = ""
        if auth_type:
            auth_len_raw = self.get_field(bfd, "auth_len", None)
            if auth_len_raw is not None:
                auth_len = str(auth_len_raw).strip()
            else:
                auth_len = "?"
                self.logger.debug(
                    f"Missing bfd.auth.len in authenticated packet from {src_ip} -> {dst_ip}"
                )

        key_id = 0
        seq_num = 0
        password = ""
        credential_type = ""

        if auth_type:
            key_id = _safe_int(self.get_field(bfd, "auth_key", "0"), 0)
            seq_num = _safe_int(self.get_field(bfd, "auth_seq_num", "0"), 0)
            credential_type = "hash"

            if auth_type == 1:
                password = str(self.get_field(bfd, "auth_password", "") or "").strip()
                credential_type = "plaintext"

        # Record interaction for all BFD packets (state tracking)
        now = datetime.now().isoformat()
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            f"BFD {state_name}" if state_name and state_name != "?" else "BFD",
            {
                "version": version,
                "state": state_raw,
                "state_name": state_name,
                "diag": diag_raw,
                "diag_name": diag_name,
                "my_discriminator": my_disc,
                "your_discriminator": your_disc,
                "detect_time_multiplier": detect_mult,
                "message_length": msg_len,
                "auth_type": auth_type,
                "auth_type_name": auth_type_name,
                "auth_len": auth_len,
                "min_tx": min_tx,
                "min_rx": min_rx,
            },
            f"BFD {state_name} {src_ip} -> {dst_ip}",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
        )

        # Update devices for all packets
        self._update_devices(
            src_ip,
            dst_ip,
            state_name=state_name,
            version=version,
            my_disc=my_disc,
            detect_mult=detect_mult,
        )

        # Extract credentials only from auth-bearing packets
        if not auth_type:
            return
        if auth_type == 1 and not password:
            return

        if not self._is_duplicate(auth_type, password, key_id, src_ip, dst_ip):
            cred = BFDCredential(
                auth_type=auth_type,
                auth_type_name=auth_type_name,
                credential_type=credential_type,
                password=password,
                key_id=key_id,
                seq_num=seq_num,
                server_ip=dst_ip,
                client_ip=src_ip,
                timestamp=datetime.now().isoformat(),
            )
            self.credentials.append(cred)

            if credential_type == "plaintext":
                self.logger.info(f"BFD: Simple Password={password} from {src_ip}")
            else:
                self.logger.info(f"BFD: {auth_type_name} key_id={key_id} from {src_ip}")

    def _is_duplicate(
        self,
        auth_type: int,
        password: str,
        key_id: int,
        client_ip: str,
        server_ip: str,
    ) -> bool:
        """Check if credential is already recorded."""
        for cred in self.credentials:
            if (
                cred.auth_type == auth_type
                and cred.password == password
                and cred.key_id == key_id
                and cred.client_ip == client_ip
                and cred.server_ip == server_ip
            ):
                return True
        return False

    def _update_devices(
        self,
        src_ip: str,
        dst_ip: str,
        state_name: str = "",
        version: int = -1,
        my_disc: str = "",
        detect_mult: str = "",
    ) -> None:
        """Update device entries with BFD session state."""
        for ip, role in [(src_ip, "sender"), (dst_ip, "receiver")]:
            device_key = f"bfd:{ip}"
            device, is_new = self._ensure_device(
                device_key,
                ip,
                name=f"BFD Peer ({ip})",
                device_type="Router",
            )
            if is_new:
                device.bfd_passive_data = {
                    "role": role,
                    "protocol": "BFD/UDP",
                }
            # Enrich with data from the sender's packet
            if ip == src_ip:
                if not device.bfd_passive_data:
                    device.bfd_passive_data = {}
                if state_name and state_name != "?":
                    device.bfd_passive_data["state"] = state_name
                if version >= 0:
                    device.bfd_passive_data["version"] = version
                if my_disc:
                    device.bfd_passive_data["discriminator"] = my_disc
                if detect_mult:
                    device.bfd_passive_data["detect_time_multiplier"] = detect_mult

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted credentials."""
        return [
            {
                "protocol": "BFD",
                "auth_method": cred.auth_type_name,
                "credential_type": cred.credential_type,
                "username": cred.password,  # BFD uses password as identifier
                "password": cred.password,
                "key_id": cred.key_id,
                "seq_num": cred.seq_num,
                "client_ip": cred.client_ip,
                "server_ip": cred.server_ip,
                "timestamp": cred.timestamp,
            }
            for cred in self.credentials
        ]


def _safe_int(value, default: int = 0) -> int:
    """Safely convert a PyShark field value to int."""
    try:
        return int(value)
    except (ValueError, TypeError) as e:
        logger.debug(f"Return value computation failed: {e}")
        return default

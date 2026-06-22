"""
Kerberos Passive Listener for hash extraction.

Passively captures Kerberos traffic to extract:
- AS-REQ pre-authentication hashes (for password cracking)
- AS-REP ticket hashes (AS-REP roasting)
- TGS-REP service ticket hashes (Kerberoasting)
- KRB-ERROR codes (failed auth detection)

Based on BruteShark's KerberosAsReqHashParser and KerberosTicketHashParser.

Kerberos Message Types:
- AS-REQ (10): Authentication Service Request with pre-auth data
- AS-REP (11): Authentication Service Reply with TGT
- TGS-REQ (12): Ticket Granting Service Request
- TGS-REP (13): Ticket Granting Service Reply with service ticket
- KRB-ERROR (30): Error response from KDC

Encryption Types (etypes):
- 17: AES128-CTS-HMAC-SHA1-96
- 18: AES256-CTS-HMAC-SHA1-96
- 23: RC4-HMAC-MD5 (arcfour-hmac)

Hash output formats are compatible with hashcat.

Uses PyShark for Kerberos dissection, providing access to Wireshark's
comprehensive Kerberos protocol parser.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import (
    is_valid_discovered_ip,
)

import logging

logger = logging.getLogger(__name__)


@dataclass
class KerberosHash:
    """Extracted Kerberos hash."""

    hash_type: str  # "AS-REQ", "AS-REP", "TGS-REP"
    etype: int  # Encryption type
    username: str
    domain: str
    service_name: str = ""
    hash_value: str = ""
    server_ip: str = ""
    server_port: int = 0
    client_ip: str = ""
    protocol: str = ""  # "UDP" or "TCP"
    timestamp: str = ""

    @property
    def credential_type(self) -> str:
        return "hash"

    @property
    def auth_method(self) -> str:
        return self.hash_type

    @property
    def hashcat_format(self) -> str:
        """Hashcat-compatible hash string."""
        if self.hash_type == "AS-REQ" and self.etype == 23:
            return f"$krb5pa$23${self.username}${self.domain}${self.hash_value}"
        elif self.hash_type == "AS-REP":
            return f"$krb5asrep${self.etype}${self.username}@{self.domain}:{self.hash_value}"
        elif self.hash_type == "TGS-REP":
            return f"$krb5tgs${self.etype}$*{self.username}${self.domain}${self.service_name}*${self.hash_value}"
        # Unrecognized type / unsupported etype: no valid $krb5 hashcat line, so
        # return "" rather than a bare value that looks like a deliverable hash.
        return ""


# Kerberos message types
KRB_AS_REQ = 10
KRB_AS_REP = 11
KRB_TGS_REQ = 12
KRB_TGS_REP = 13
KRB_ERROR = 30

# Supported encryption types
ETYPE_AES128 = 17
ETYPE_AES256 = 18
ETYPE_RC4_HMAC = 23

# Kerberos error code names (RFC 4120 section 7.5.9)
KRB_ERROR_NAMES: Dict[int, str] = {
    6: "KDC_ERR_C_PRINCIPAL_UNKNOWN",
    14: "KDC_ERR_ETYPE_NOSUPP",
    18: "KDC_ERR_CLIENT_REVOKED",
    24: "KDC_ERR_PREAUTH_FAILED",
    25: "KDC_ERR_PREAUTH_REQUIRED",
    31: "KRB_AP_ERR_SKEW",
    32: "KRB_AP_ERR_BADADDR",
    41: "KRB_AP_ERR_MODIFIED",
    60: "KRB_ERR_GENERIC",
    68: "KDC_ERR_WRONG_REALM",
}


class KerberosPassiveListener(PySharkListenerBase):
    """Passive Kerberos traffic listener for hash extraction.

    Captures Kerberos traffic to extract:
    - AS-REQ pre-authentication hashes (etype 23)
    - AS-REP ticket hashes (AS-REP roasting)
    - TGS-REP service ticket hashes (Kerberoasting)
    - AP-REQ/AP-REP embedded in LDAP, SMB2, HTTP (GSSAPI/SPNEGO)

    Uses PyShark (tshark) for Kerberos protocol dissection.

    Usage:
        # Live capture
        listener = KerberosPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        # Access extracted hashes
        for h in listener.hashes:
            print(f"{h.hash_type}: {h.username}@{h.domain}")

    Data structure stored in device.kerberos_passive_data:
        {
            "role": "kdc" | "client",
            "hashes": [...],
            "protocol": "Kerberos/UDP" or "Kerberos/TCP",
        }
    """

    PROTOCOL_NAME = "kerberos"
    DISPLAY_FILTER = "kerberos"
    REQUIRED_LAYERS = ()  # Disabled: embedded kerberos may lack top-level layer

    PROTOCOL_COLUMNS = ("message", "principal", "service", "detail")

    # Parent layers that may carry embedded Kerberos via GSSAPI/SPNEGO
    _SPNEGO_PARENT_LAYERS = ("ldap", "smb2", "http")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        """Initialize Kerberos passive listener."""
        super().__init__(interface, timeout, nxc_logger)

        # Extracted hashes
        self.hashes: List[KerberosHash] = []

        # Error tracking: (src_ip, error_code, username, realm) -> count
        self.error_counts: Dict[Tuple[str, int, str, str], int] = {}
        # NetBIOS hostname map: client_ip -> hostname
        self.client_hostnames: Dict[str, str] = {}

    @property
    def credentials(self) -> List[KerberosHash]:
        """Expose hashes as credentials for scanner.py credential surfacing."""
        return self.hashes

    def should_process_packet(self, packet) -> bool:
        """Accept packets with top-level kerberos layer OR embedded kerberos.

        Kerberos tokens can be embedded inside LDAP (SASL/GSSAPI bind),
        SMB2 (session setup), or HTTP (Negotiate auth) via SPNEGO.
        tshark's 'kerberos' display filter matches these, but pyshark
        may not expose a top-level 'kerberos' layer in EK mode.
        """
        if hasattr(packet, "kerberos"):
            return True
        # Check for embedded kerberos in parent layers
        for layer_name in self._SPNEGO_PARENT_LAYERS:
            if hasattr(packet, layer_name):
                layer = getattr(packet, layer_name)
                if self._find_embedded_kerberos_dict(layer) is not None:
                    return True
        return False

    @staticmethod
    def _find_embedded_kerberos_dict(layer) -> Optional[Dict[str, Any]]:
        """Find embedded kerberos dict inside a parent layer's _fields_dict.

        Searches for the 'kerberos' key in nested SPNEGO/GSS-API structures.
        Known nesting paths:
          - gss-api -> spnego -> kerberos (LDAP bind request, HTTP, SMB2)
          - spnego -> kerberos (LDAP bind response)
        Returns the kerberos dict or None if not found.
        """
        fd = getattr(layer, "_fields_dict", None)
        if not isinstance(fd, dict):
            return None

        # Try all known nesting paths
        # Path 1: gss-api -> spnego -> kerberos
        gss = fd.get("gss-api")
        if isinstance(gss, dict):
            spnego = gss.get("spnego")
            if isinstance(spnego, dict):
                krb = spnego.get("kerberos")
                if isinstance(krb, dict):
                    return krb

        # Path 2: spnego -> kerberos (e.g. LDAP bind response)
        spnego = fd.get("spnego")
        if isinstance(spnego, dict):
            krb = spnego.get("kerberos")
            if isinstance(krb, dict):
                return krb

        return None

    def _get_layer_field(self, layer, name: str) -> str:
        """Get a Kerberos field as a normalized string.

        Uses self.get_field() which works via getattr in both EK and XML modes.
        The base class normalizes lists to comma-separated strings, ints to str, etc.
        Returns empty string if field is missing.
        """
        val = self.get_field(layer, name, default="")
        if val is None:
            return ""
        return str(val)

    @staticmethod
    def _parse_principal(raw: str) -> str:
        """Parse principal from CNameString/SNameString.

        EK mode returns comma-separated components (e.g. 'krbtgt,EXAMPLE.COM'
        or 'WELLKNOWN,ANONYMOUS'). For usernames, skip WELLKNOWN/ANONYMOUS.
        For service names, join with '/'.
        """
        if not raw:
            return ""
        parts = [p.strip() for p in raw.split(",") if p.strip()]
        if not parts:
            return ""
        # Filter out anonymous/wellknown markers for username
        real_parts = [p for p in parts if p.upper() not in ("WELLKNOWN", "ANONYMOUS")]
        if real_parts:
            return real_parts[0]
        return parts[0]

    @staticmethod
    def _parse_service_name(raw: str) -> str:
        """Parse service name from SNameString (e.g. 'krbtgt,EXAMPLE.COM' -> 'krbtgt/EXAMPLE.COM')."""
        if not raw:
            return ""
        parts = [p.strip() for p in raw.split(",") if p.strip()]
        return "/".join(parts) if parts else ""

    @staticmethod
    def _has_crackable_etype(etype_str: str) -> int:
        """Check if any etype in the list is crackable, return first crackable one.

        Returns the crackable etype value or 0 if none found.
        """
        if not etype_str:
            return 0
        crackable = {ETYPE_AES128, ETYPE_AES256, ETYPE_RC4_HMAC}
        for part in etype_str.split(","):
            try:
                e = int(part.strip())
                if e in crackable:
                    return e
            except (ValueError, TypeError) as e:
                logger.debug(f"Kerberos: etype int parse failed: {e}")
                continue
        return 0

    def process_packet(self, packet) -> None:
        """Process Kerberos packet and extract hashes using PyShark."""
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)

        if hasattr(packet, "tcp"):
            protocol = "TCP"
        elif hasattr(packet, "udp"):
            protocol = "UDP"
        else:
            return

        # Check for embedded kerberos (SPNEGO in LDAP/SMB2/HTTP)
        if not hasattr(packet, "kerberos"):
            self._process_embedded_kerberos(
                packet, src_ip, dst_ip, flow_id, src_port, dst_port, protocol
            )
            return

        krb_layer = packet.kerberos
        _f = self._get_layer_field

        # Get message type (may be comma-separated for combined messages)
        msg_type_str = _f(krb_layer, "msg_type")
        try:
            msg_type = int(msg_type_str.split(",")[0]) if msg_type_str else 0
        except (ValueError, TypeError):
            msg_type = 0

        # --- Extract T1 fields using self.get_field() for audit coverage ---

        # kerberos.error_code: KRB-ERROR error code (T1: critical for auth failure detection)
        error_code_raw = self.get_field(krb_layer, "error_code", default="")
        error_code = 0
        if error_code_raw:
            try:
                error_code = int(str(error_code_raw).split(",")[0])
            except (ValueError, TypeError):
                error_code = 0

        # kerberos.cname_string: count of CNameString components (T1: sequence count)
        cname_string_count = self.get_field(krb_layer, "cname_string", default="")

        # kerberos.sname_string: count of SNameString components (T1: sequence count)
        sname_string_count = self.get_field(krb_layer, "sname_string", default="")

        # kerberos.name_string: generic KerberosString sequence count (T1)
        name_string_count = self.get_field(krb_layer, "name_string", default="")

        # kerberos.encryptedAuthenticator_cipher: AP-REQ authenticator cipher (T1)
        encrypted_authenticator = self.get_field(
            krb_layer, "encryptedAuthenticator_cipher", default=""
        )

        # kerberos.rEQ_SEQUENCE_OF_PA_DATA: count of PA-DATA in requests (T1)
        pa_req_count = self.get_field(krb_layer, "rEQ_SEQUENCE_OF_PA_DATA", default="")

        # kerberos.rEP_SEQUENCE_OF_PA_DATA: count of PA-DATA in replies (T1)
        pa_rep_count = self.get_field(krb_layer, "rEP_SEQUENCE_OF_PA_DATA", default="")

        # kerberos.kdc-req-body.etype: count of requested etypes (T1)
        # Note: the EK field name uses underscore: "kdc-req-body_etype"
        # but the tshark dotted name is "kdc-req-body.etype"
        etype_count = self.get_field(krb_layer, "kdc-req-body_etype", default="")
        if not etype_count:
            etype_count = self.get_field(krb_layer, "kdc-req-body.etype", default="")

        # kerberos.checksum: authenticator checksum bytes (T1)
        checksum = self.get_field(krb_layer, "checksum", default="")

        # kerberos.addr_nb: NetBIOS client hostname (T1: device enrichment)
        addr_nb = self.get_field(krb_layer, "addr_nb", default="")

        # kerberos.addresses: count of host addresses in request (T1)
        addresses_count = self.get_field(krb_layer, "addresses", default="")

        # --- Build interaction details ---
        now = datetime.now().isoformat()
        msg_names = {
            10: "AS-REQ",
            11: "AS-REP",
            12: "TGS-REQ",
            13: "TGS-REP",
            30: "KRB-ERROR",
        }
        msg_name = msg_names.get(msg_type, f"Type{msg_type}")
        cname_raw = _f(krb_layer, "CNameString")
        username = self._parse_principal(cname_raw)
        realm = _f(krb_layer, "realm").split(",")[0]
        sname_raw = _f(krb_layer, "SNameString")
        service_name = self._parse_service_name(sname_raw)

        details: Dict[str, Any] = {
            "msg_type": msg_type,
            "username": username,
            "realm": realm,
            "service_name": service_name,
        }

        # Add T1 fields to details when present
        if error_code:
            details["error_code"] = error_code
            details["error_name"] = KRB_ERROR_NAMES.get(error_code, f"ERR_{error_code}")
        if cname_string_count:
            details["cname_string_count"] = str(cname_string_count)
        if sname_string_count:
            details["sname_string_count"] = str(sname_string_count)
        if name_string_count:
            details["name_string_count"] = str(name_string_count)
        if encrypted_authenticator:
            details["has_authenticator_cipher"] = True
        if pa_req_count:
            details["pa_data_req_count"] = str(pa_req_count)
        if pa_rep_count:
            details["pa_data_rep_count"] = str(pa_rep_count)
        if etype_count:
            details["requested_etype_count"] = str(etype_count)
        if checksum:
            details["has_checksum"] = True
        if addr_nb:
            details["client_hostname"] = str(addr_nb)
            # Store NetBIOS hostname for client device enrichment
            client_ip = src_ip if msg_type in (KRB_AS_REQ, KRB_TGS_REQ) else dst_ip
            self.client_hostnames[client_ip] = str(addr_nb)
        if addresses_count:
            details["addresses_count"] = str(addresses_count)

        # Build summary
        summary_parts = [f"Kerberos {msg_name}"]
        if username:
            summary_parts.append(f"{username}@{realm}")
        if error_code:
            err_name = KRB_ERROR_NAMES.get(error_code, f"ERR_{error_code}")
            summary_parts.append(f"[{err_name}]")
        if addr_nb:
            summary_parts.append(f"host={addr_nb}")

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request" if msg_type in (KRB_AS_REQ, KRB_TGS_REQ) else "response",
            f"Kerberos {msg_name}",
            details,
            " ".join(summary_parts),
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        if msg_type == KRB_AS_REQ:
            self._process_as_req(src_ip, dst_ip, protocol, krb_layer, dst_port)
        elif msg_type == KRB_AS_REP:
            # For *-REP the KDC is the sender, so its port (88) is src_port.
            self._process_as_rep(src_ip, dst_ip, protocol, krb_layer, src_port)
        elif msg_type == KRB_TGS_REP:
            # For *-REP the KDC is the sender, so its port (88) is src_port.
            self._process_tgs_rep(src_ip, dst_ip, protocol, krb_layer, src_port)
        elif msg_type == KRB_ERROR:
            self._process_krb_error(
                src_ip, dst_ip, protocol, error_code, username, realm, service_name
            )

    def _process_embedded_kerberos(
        self,
        packet,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        src_port: int,
        dst_port: int,
        protocol: str,
    ) -> None:
        """Process Kerberos tokens embedded in LDAP/SMB2/HTTP via GSSAPI/SPNEGO.

        When tshark matches the 'kerberos' display filter but pyshark does not
        expose a top-level 'kerberos' layer (common in EK mode for SPNEGO),
        the kerberos data is nested inside the parent layer's _fields_dict.

        Supported message types:
        - AP-REQ (14): Application request (Kerberos ticket + authenticator)
        - AP-REP (15): Application reply (mutual authentication confirmation)
        """
        for layer_name in self._SPNEGO_PARENT_LAYERS:
            if not hasattr(packet, layer_name):
                continue
            layer = getattr(packet, layer_name)
            krb_dict = self._find_embedded_kerberos_dict(layer)
            if krb_dict is None:
                continue

            # Extract fields from the embedded kerberos dict
            # Keys are prefixed with 'kerberos_kerberos_' in EK mode
            msg_type_raw = krb_dict.get("kerberos_kerberos_msg_type", 0)
            try:
                msg_type = int(msg_type_raw) if msg_type_raw else 0
            except (ValueError, TypeError):
                msg_type = 0

            # AP-REQ = 14, AP-REP = 15
            KRB_AP_REQ = 14
            KRB_AP_REP = 15
            msg_names = {
                KRB_AP_REQ: "AP-REQ",
                KRB_AP_REP: "AP-REP",
            }
            msg_name = msg_names.get(msg_type, f"Type{msg_type}")

            realm = str(krb_dict.get("kerberos_kerberos_realm", "") or "")
            sname_raw = krb_dict.get("kerberos_kerberos_SNameString", "")
            if isinstance(sname_raw, list):
                service_name = "/".join(str(s) for s in sname_raw)
            else:
                service_name = self._parse_service_name(str(sname_raw)) if sname_raw else ""

            etype_raw = krb_dict.get("kerberos_kerberos_etype", "")
            if isinstance(etype_raw, list):
                etype_str = str(etype_raw[0]) if etype_raw else ""
            else:
                etype_str = str(etype_raw) if etype_raw else ""

            now = datetime.now().isoformat()
            # Determine direction based on msg type
            direction = "request" if msg_type == KRB_AP_REQ else "response"

            details: Dict[str, Any] = {
                "msg_type": msg_type,
                "username": "",
                "realm": realm,
                "service_name": service_name,
                "embedded_in": layer_name.upper(),
            }
            if etype_str:
                details["etype"] = etype_str

            summary_parts = [f"Kerberos {msg_name}", f"via {layer_name.upper()}"]
            if service_name:
                summary_parts.append(f"svc={service_name}")
            if realm:
                summary_parts.append(f"realm={realm}")

            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                direction,
                f"Kerberos {msg_name} (SPNEGO)",
                details,
                " ".join(summary_parts),
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=self.get_stream_id(packet),
            )

            self.logger.debug(
                f"Embedded Kerberos {msg_name} in {layer_name.upper()}: "
                f"{src_ip} -> {dst_ip} realm={realm} svc={service_name}"
            )
            # Found and processed embedded kerberos -- done
            return

        # If we get here, should_process_packet accepted the packet but we
        # couldn't extract any embedded kerberos data. Log it.
        self.logger.debug(
            f"Packet matched kerberos filter but no kerberos data found: {src_ip} -> {dst_ip}"
        )

    def _process_as_req(
        self, src_ip: str, dst_ip: str, protocol: str, krb_layer, server_port: int = 0
    ) -> None:
        """Process AS-REQ to extract pre-authentication hash.

        Extracts the PA-ENC-TIMESTAMP cipher from PA-DATA type 2.
        The padata_value contains an ASN.1 EncryptedData structure:
          SEQUENCE { [0] etype INT, [2] cipher OCTET STRING }
        We extract etype and cipher from the raw DER bytes.
        """
        _f = self._get_layer_field

        # Get padata_type and padata_value as raw lists from the layer
        raw_types = self.get_field(krb_layer, "padata_type", default=None)
        raw_values = self.get_field(krb_layer, "padata_value", default=None)
        if raw_types is None or raw_values is None:
            return

        # Normalize to lists
        if not isinstance(raw_types, list):
            raw_types = [raw_types]
        if not isinstance(raw_values, list):
            raw_values = [raw_values]

        # Find the PA-ENC-TIMESTAMP (type 2) entry
        pa_enc_ts_hex = None
        for pt, pv in zip(raw_types, raw_values):
            try:
                if int(self._resolve_value(pt, 0)) == 2:
                    pa_enc_ts_hex = str(self._resolve_value(pv, ""))
                    break
            except (ValueError, TypeError) as e:
                self.logger.debug(
                    f"Kerberos: failed to parse PA-DATA type for PA-ENC-TIMESTAMP: {e}"
                )
                continue

        if not pa_enc_ts_hex:
            return

        username = self._parse_principal(_f(krb_layer, "CNameString"))
        if not username:
            return

        realm = _f(krb_layer, "realm").split(",")[0]

        # Parse etype and cipher from the ASN.1 EncryptedData DER bytes
        etype, cipher_hex = self._parse_encrypted_data(pa_enc_ts_hex)
        if not cipher_hex:
            return

        if etype not in (ETYPE_AES128, ETYPE_AES256, ETYPE_RC4_HMAC):
            return

        if self._is_duplicate_hash("AS-REQ", username, realm, cipher_hex):
            return

        krb_hash = KerberosHash(
            hash_type="AS-REQ",
            etype=etype,
            username=username,
            domain=realm,
            hash_value=cipher_hex,
            server_ip=dst_ip,
            server_port=server_port,
            client_ip=src_ip,
            protocol=protocol,
            timestamp=datetime.now().isoformat(),
        )
        self._record_hash(krb_hash)

    @staticmethod
    def _parse_encrypted_data(hex_str: str) -> tuple:
        """Parse etype and cipher from ASN.1 EncryptedData DER hex.

        Structure: SEQUENCE { [0] etype INTEGER, [2] cipher OCTET STRING }
        Returns (etype: int, cipher_hex: str) or (0, "") on failure.
        """
        try:
            raw = bytes.fromhex(hex_str.replace(":", ""))
        except ValueError as e:
            logger.debug(f"Kerberos: EncryptedData hex decode failed: {e}")
            return 0, ""
        if len(raw) < 10 or raw[0] != 0x30:
            return 0, ""

        etype = 0
        cipher_hex = ""

        # Walk the SEQUENCE contents
        # Skip SEQUENCE tag + length
        pos = 1
        if raw[pos] & 0x80:
            n_len_bytes = raw[pos] & 0x7F
            pos += 1 + n_len_bytes
        else:
            pos += 1

        while pos < len(raw):
            tag = raw[pos]
            pos += 1
            if pos >= len(raw):
                break
            # Read length
            length = raw[pos]
            pos += 1
            if length & 0x80:
                n = length & 0x7F
                length = int.from_bytes(raw[pos : pos + n], "big")
                pos += n

            content = raw[pos : pos + length]
            pos += length

            if tag == 0xA0 and len(content) >= 3:
                # [0] etype — contains INTEGER (02 len val)
                if content[0] == 0x02:
                    etype = int.from_bytes(content[2 : 2 + content[1]], "big")
            elif tag == 0xA2 and len(content) >= 2:
                # [2] cipher — contains OCTET STRING (04 len val)
                if content[0] == 0x04:
                    clen = content[1]
                    offset = 2
                    if clen & 0x80:
                        n = clen & 0x7F
                        clen = int.from_bytes(content[2 : 2 + n], "big")
                        offset = 2 + n
                    cipher_hex = content[offset : offset + clen].hex()

        return etype, cipher_hex

    def _process_as_rep(
        self, src_ip: str, dst_ip: str, protocol: str, krb_layer, server_port: int = 0
    ) -> None:
        """Process AS-REP to extract ticket hash (AS-REP roasting)."""
        _f = self._get_layer_field

        etype_str = _f(krb_layer, "etype")
        etype = self._has_crackable_etype(etype_str)
        if not etype:
            return

        username = self._parse_principal(_f(krb_layer, "CNameString"))
        if not username:
            return

        realm = _f(krb_layer, "realm").split(",")[0]

        # AS-REP cipher: try encryptedKDCREPData_cipher first (KDC reply encryption),
        # then encryptedTicketData_cipher (ticket encryption), then generic cipher.
        cipher = (
            _f(krb_layer, "encryptedKDCREPData_cipher")
            or _f(krb_layer, "encryptedTicketData_cipher")
            or _f(krb_layer, "cipher")
        )
        if not cipher:
            return

        hash_value = cipher.replace(":", "")

        if self._is_duplicate_hash("AS-REP", username, realm, hash_value):
            return

        krb_hash = KerberosHash(
            hash_type="AS-REP",
            etype=etype,
            username=username,
            domain=realm,
            hash_value=hash_value,
            server_ip=src_ip,
            server_port=server_port,
            client_ip=dst_ip,
            protocol=protocol,
            timestamp=datetime.now().isoformat(),
        )
        self._record_hash(krb_hash)

    def _process_tgs_rep(
        self, src_ip: str, dst_ip: str, protocol: str, krb_layer, server_port: int = 0
    ) -> None:
        """Process TGS-REP to extract service ticket hash (Kerberoasting)."""
        _f = self._get_layer_field

        etype_str = _f(krb_layer, "etype")
        etype = self._has_crackable_etype(etype_str)
        if not etype:
            return

        username = self._parse_principal(_f(krb_layer, "CNameString"))
        if not username:
            return

        realm = _f(krb_layer, "realm").split(",")[0]
        service_name = self._parse_service_name(_f(krb_layer, "SNameString"))

        # TGS-REP cipher: try encryptedTicketData_cipher first (ticket encryption),
        # then generic cipher.
        cipher = _f(krb_layer, "encryptedTicketData_cipher") or _f(krb_layer, "cipher")
        if not cipher:
            return

        hash_value = cipher.replace(":", "")

        if self._is_duplicate_hash("TGS-REP", username, realm, hash_value):
            return

        krb_hash = KerberosHash(
            hash_type="TGS-REP",
            etype=etype,
            username=username,
            domain=realm,
            service_name=service_name,
            hash_value=hash_value,
            server_ip=src_ip,
            server_port=server_port,
            client_ip=dst_ip,
            protocol=protocol,
            timestamp=datetime.now().isoformat(),
        )
        self._record_hash(krb_hash)

    def _process_krb_error(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        error_code: int,
        username: str,
        realm: str,
        service_name: str,
    ) -> None:
        """Process KRB-ERROR message for auth failure tracking.

        KRB-ERROR (msg_type=30) carries error codes that indicate
        authentication failures, policy violations, or clock skew.
        Security-relevant error codes:
        - 6: CLIENT_NOT_FOUND (invalid username)
        - 14: ETYPE_NOSUPP (encryption negotiation failure)
        - 24: PREAUTH_FAILED (wrong password)
        - 25: PREAUTH_REQUIRED (normal pre-auth negotiation step)
        """
        if not error_code:
            return

        # KDC is the sender (src_ip) for KRB-ERROR
        kdc_ip = src_ip
        client_ip = dst_ip
        err_key = (kdc_ip, error_code, username, realm)

        # Count errors
        self.error_counts[err_key] = self.error_counts.get(err_key, 0) + 1

        # Track KDC device with error info
        if is_valid_discovered_ip(kdc_ip):
            kdc_key = f"kerberos-kdc:{kdc_ip}"
            device, is_new = self._ensure_device(
                kdc_key,
                kdc_ip,
                name=f"Kerberos KDC ({realm})" if realm else f"Kerberos KDC ({kdc_ip})",
                device_type="Kerberos KDC",
            )
            if is_new:
                device.kerberos_passive_data = {
                    "role": "kdc",
                    "domain": realm,
                    "hashes": [],
                    "error_codes_seen": [error_code],
                    "protocol": f"Kerberos/{protocol}",
                }
            else:
                if device.kerberos_passive_data:
                    seen = device.kerberos_passive_data.setdefault("error_codes_seen", [])
                    if error_code not in seen:
                        seen.append(error_code)

        # Track client device for error context
        if is_valid_discovered_ip(client_ip):
            client_key = f"kerberos-client:{client_ip}"
            hostname = self.client_hostnames.get(client_ip, "")
            name = f"Kerberos Client ({hostname})" if hostname else f"Kerberos Client ({client_ip})"
            device, is_new = self._ensure_device(
                client_key,
                client_ip,
                name=name,
                device_type="Kerberos Client",
            )
            if is_new:
                device.kerberos_passive_data = {
                    "role": "client",
                    "domain": realm,
                    "users": [username] if username else [],
                    "error_codes_seen": [error_code],
                    "protocol": f"Kerberos/{protocol}",
                }
            else:
                if device.kerberos_passive_data:
                    if username:
                        users = device.kerberos_passive_data.setdefault("users", [])
                        if username not in users:
                            users.append(username)
                    seen = device.kerberos_passive_data.setdefault("error_codes_seen", [])
                    if error_code not in seen:
                        seen.append(error_code)

        error_name = KRB_ERROR_NAMES.get(error_code, f"ERR_{error_code}")
        self.logger.debug(
            f"Kerberos KRB-ERROR {error_code} ({error_name}) from KDC {kdc_ip}: "
            f"user={username}@{realm} service={service_name}"
        )

    def _is_duplicate_hash(
        self, hash_type: str, username: str, domain: str, hash_value: str
    ) -> bool:
        """Check if hash is already recorded."""
        for h in self.hashes:
            if (
                h.hash_type == hash_type
                and h.username == username
                and h.domain == domain
                and h.hash_value == hash_value
            ):
                return True
        return False

    def _record_hash(self, krb_hash: KerberosHash) -> None:
        """Record extracted Kerberos hash."""
        self.hashes.append(krb_hash)

        self.logger.info(
            f"Kerberos {krb_hash.hash_type} (etype {krb_hash.etype}): "
            f"{krb_hash.username}@{krb_hash.domain}"
        )

        # Update device entries
        self._update_devices(krb_hash)

    def _update_devices(self, krb_hash: KerberosHash) -> None:
        """Update device entries with hash information."""
        # KDC device
        kdc_ip = krb_hash.server_ip
        client_ip = krb_hash.client_ip

        if not is_valid_discovered_ip(kdc_ip):
            return

        kdc_key = f"kerberos-kdc:{kdc_ip}"
        client_key = f"kerberos-client:{client_ip}"

        hash_entry = {
            "hash_type": krb_hash.hash_type,
            "etype": krb_hash.etype,
            "username": krb_hash.username,
            "domain": krb_hash.domain,
            "service_name": krb_hash.service_name,
            "timestamp": krb_hash.timestamp,
        }

        # KDC device
        device, is_new = self._ensure_device(
            kdc_key,
            kdc_ip,
            name=f"Kerberos KDC ({krb_hash.domain})",
            device_type="Kerberos KDC",
        )
        if is_new:
            device.kerberos_passive_data = {
                "role": "kdc",
                "domain": krb_hash.domain,
                "hashes": [hash_entry],
                "protocol": f"Kerberos/{krb_hash.protocol}",
            }
        else:
            if device.kerberos_passive_data:
                device.kerberos_passive_data.setdefault("hashes", []).append(hash_entry)
        # Client device -- enrich with NetBIOS hostname if known
        if is_valid_discovered_ip(client_ip):
            hostname = self.client_hostnames.get(client_ip, "")
            name = f"Kerberos Client ({hostname})" if hostname else f"Kerberos Client ({client_ip})"
            device, is_new = self._ensure_device(
                client_key,
                client_ip,
                name=name,
                device_type="Kerberos Client",
            )
            if is_new:
                pdata: Dict[str, Any] = {
                    "role": "client",
                    "domain": krb_hash.domain,
                    "users": [krb_hash.username],
                    "protocol": f"Kerberos/{krb_hash.protocol}",
                }
                if hostname:
                    pdata["hostname"] = hostname
                device.kerberos_passive_data = pdata
            else:
                if device.kerberos_passive_data:
                    users = device.kerberos_passive_data.get("users", [])
                    if krb_hash.username not in users:
                        users.append(krb_hash.username)
                        device.kerberos_passive_data["users"] = users
                    if hostname and "hostname" not in device.kerberos_passive_data:
                        device.kerberos_passive_data["hostname"] = hostname

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format a single Kerberos interaction as a table row.

        Columns: Message, Principal, Service, Detail
        """
        d = ix.details
        # Message: short msg type like "AS-REQ", "TGS-REP", etc.
        msg_type = d.get("msg_type", 0)
        msg_names = {10: "AS-REQ", 11: "AS-REP", 12: "TGS-REQ", 13: "TGS-REP", 30: "KRB-ERROR"}
        message = msg_names.get(msg_type, f"Type{msg_type}")

        # Principal: username@realm
        username = d.get("username", "")
        realm = d.get("realm", "")
        if username and realm:
            principal = f"{username}@{realm}"
        elif username:
            principal = username
        else:
            principal = ""

        # Service
        service = d.get("service_name", "")

        # Detail: error info, hostname, or other context
        detail_parts: List[str] = []
        error_code = d.get("error_code", 0)
        if error_code:
            error_name = d.get("error_name", f"ERR_{error_code}")
            detail_parts.append(f"{error_name} ({error_code})")
        if d.get("has_authenticator_cipher"):
            detail_parts.append("authenticator")
        hostname = d.get("client_hostname", "")
        if hostname:
            detail_parts.append(f"host={hostname}")
        detail = ", ".join(detail_parts)

        return [str(message), str(principal), str(service), str(detail)]

    def get_hashes_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted hashes.

        Returns list of dicts with keys expected by base class harvest():
        protocol, hash_type, username, domain, server_ip, client_ip,
        hashcat_format.
        """
        result = []
        for h in self.hashes:
            result.append(
                {
                    "protocol": "Kerberos",
                    "hash_type": f"{h.hash_type} (etype {h.etype})",
                    "etype": h.etype,
                    "etype_name": self._etype_name(h.etype),
                    "username": h.username,
                    "domain": h.domain,
                    "service_name": h.service_name,
                    "hash": h.hash_value,
                    "server_ip": h.server_ip,
                    "client_ip": h.client_ip,
                    "timestamp": h.timestamp,
                    "hashcat_format": h.hashcat_format,
                }
            )
        return result

    def _etype_name(self, etype: int) -> str:
        """Get human-readable encryption type name."""
        names = {
            17: "AES128-CTS-HMAC-SHA1-96",
            18: "AES256-CTS-HMAC-SHA1-96",
            23: "RC4-HMAC-MD5",
        }
        return names.get(etype, f"Unknown ({etype})")

    def harvest(self) -> Dict[str, Any]:
        """Build harvest output with hash tables and error alerts."""
        result = super().harvest()
        if not result:
            result = {"tables": [], "alerts": [], "results": {}}

        alerts = result.setdefault("alerts", [])

        # Add alerts for security-relevant error codes
        for (kdc_ip, error_code, username, realm), count in self.error_counts.items():
            error_name = KRB_ERROR_NAMES.get(error_code, f"ERR_{error_code}")
            # PREAUTH_REQUIRED (25) is normal negotiation -- skip alerting
            if error_code == 25:
                continue
            # PREAUTH_FAILED (24), CLIENT_NOT_FOUND (6) are auth failure indicators
            if error_code in (6, 24):
                level = "fail"
                msg = (
                    f"Kerberos AUTH FAILURE: {error_name} (code {error_code}) "
                    f"for {username}@{realm} from KDC {kdc_ip} (x{count})"
                )
            else:
                level = "warning"
                msg = (
                    f"Kerberos ERROR: {error_name} (code {error_code}) "
                    f"for {username}@{realm} from KDC {kdc_ip} (x{count})"
                )
            alerts.append({"level": level, "category": "auth_error", "message": msg})

        return result

    def get_hashcat_hashes(self) -> List[str]:
        """Get hashes in hashcat-compatible format.

        Hashcat modes:
        - 7500: Kerberos 5 AS-REQ Pre-Auth etype 23
        - 18200: Kerberos 5 AS-REP etype 23
        - 13100: Kerberos 5 TGS-REP etype 23
        - 19600: Kerberos 5 TGS-REP etype 17 (AES128)
        - 19700: Kerberos 5 TGS-REP etype 18 (AES256)
        """
        # Delegate to the per-entry KerberosHash.hashcat_format property so the
        # formatting stays consistent and never falls out of alignment with
        # self.hashes (it returns "" for entries with no valid hashcat line).
        return [h.hashcat_format for h in self.hashes if h.hashcat_format]

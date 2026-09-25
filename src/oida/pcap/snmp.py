"""
SNMP Passive Listener for credential and device extraction.

Passively captures SNMP traffic to extract:
- SNMPv1/v2c community strings (plaintext credentials)
- SNMPv3 usernames, engine IDs, auth/priv flags
- OID names and values from GET/SET/TRAP operations
- System info (sysDescr, sysName, sysLocation, etc.)
- SET operations (config changes - security-relevant)

Based on PCredz and CredSLayer approaches, now using PyShark for dissection.

SNMP versions:
- v1 (0x00): Uses community string for authentication
- v2c (0x01): Uses community string for authentication
- v3 (0x03): Uses USM (User-based Security Model) with usernames

PyShark SNMP field reference (packet.snmp.*):
- snmp.version / snmp.msgVersion: Protocol version
- snmp.community: Community string (v1/v2c)
- snmp.msgUserName: USM username (v3)
- snmp.name: OID being queried/returned
- snmp.var-bind_str: Human-readable OID value
- snmp.value.octets / .int / .oid / .counter: Typed values
- snmp.data: PDU type (0=GET, 1=GET-NEXT, 2=RESPONSE, 3=SET, 4=TRAP, 5=GET-BULK)
- snmp.error_status / .error_index: Error info
- snmp.enterprise: Trap enterprise OID
- snmp.agent_addr: Trap agent address
- snmp.v3.flags.auth / .crypt: SNMPv3 security flags
- snmp.msgAuthoritativeEngineID: SNMPv3 engine ID
- snmp.engineid.enterprise: Engine enterprise number
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from oida.pcap.pyshark_base import ProtocolInteraction, PySharkListenerBase
from oida.protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

from oida.utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)


# Well-known OIDs for system info (MIB-II system group)
WELL_KNOWN_OIDS = {
    "1.3.6.1.2.1.1.1.0": "sysDescr",
    "1.3.6.1.2.1.1.2.0": "sysObjectID",
    "1.3.6.1.2.1.1.3.0": "sysUpTime",
    "1.3.6.1.2.1.1.4.0": "sysContact",
    "1.3.6.1.2.1.1.5.0": "sysName",
    "1.3.6.1.2.1.1.6.0": "sysLocation",
    "1.3.6.1.2.1.1.7.0": "sysServices",
    "1.3.6.1.2.1.2.1.0": "ifNumber",
}

# OID prefixes for friendly names
OID_PREFIXES = {
    "1.3.6.1.2.1.1.": "system.",
    "1.3.6.1.2.1.2.": "interfaces.",
    "1.3.6.1.2.1.4.": "ip.",
    "1.3.6.1.2.1.6.": "tcp.",
    "1.3.6.1.2.1.7.": "udp.",
    "1.3.6.1.2.1.25.": "host.",
    "1.3.6.1.2.1.31.": "ifMIB.",
    "1.3.6.1.2.1.47.": "entityMIB.",
    "1.3.6.1.4.1.": "enterprise.",
}

# PDU type mapping
PDU_TYPES = {
    "0": "GET",
    "1": "GET-NEXT",
    "2": "RESPONSE",
    "3": "SET",
    "4": "TRAPv1",
    "5": "GET-BULK",
    "6": "INFORM",
    "7": "TRAPv2",
    "8": "REPORT",
}

# SNMPv3 security model mapping
SECURITY_MODEL_MAP = {
    "1": "SNMPv1",
    "2": "SNMPv2c",
    "3": "USM",
    1: "SNMPv1",
    2: "SNMPv2c",
    3: "USM",
}

# SNMP error status mapping (RFC 3416)
ERROR_STATUS_MAP = {
    "0": "noError",
    "1": "tooBig",
    "2": "noSuchName",
    "3": "badValue",
    "4": "readOnly",
    "5": "genErr",
    "6": "noAccess",
    "7": "wrongType",
    "8": "wrongLength",
    "9": "wrongEncoding",
    "10": "wrongValue",
    "11": "noCreation",
    "12": "inconsistentValue",
    "13": "resourceUnavailable",
    "14": "commitFailed",
    "15": "undoFailed",
    "16": "authorizationError",
    "17": "notWritable",
    "18": "inconsistentName",
}


@dataclass
class SNMPCredential:
    """Extracted SNMP credential."""

    community_or_username: str
    version: str  # "v1", "v2c", or "v3"
    source_ip: str
    dest_ip: str
    dest_port: int = 0
    timestamp: str = ""
    credential_type: str = "plaintext"  # community strings are plaintext

    @property
    def username(self) -> str:
        """Alias for scanner credential loop compatibility."""
        return self.community_or_username

    @property
    def password(self) -> str:
        """Community strings have no separate password."""
        return ""

    @property
    def server_ip(self) -> str:
        """Alias: dest_ip is typically the SNMP agent (server)."""
        return self.dest_ip

    @property
    def client_ip(self) -> str:
        """Alias: source_ip is typically the SNMP manager (client)."""
        return self.source_ip

    @property
    def auth_method(self) -> str:
        """Return auth method for scanner loop."""
        return f"SNMP {self.version}"


class SNMPPassiveListener(PySharkListenerBase):
    """Passive SNMP traffic listener for credential and device extraction.

    Captures SNMP traffic to extract:
    - Community strings (SNMPv1/v2c)
    - Usernames (SNMPv3)
    - OID names and values (system info, interface data, etc.)
    - PDU types (GET, SET, TRAP - SET is security-critical)
    - SNMPv3 security flags and engine IDs

    Usage:
        listener = SNMPPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for cred in listener.credentials:
            print(f"{cred.version}: {cred.community_or_username}")
    """

    PROTOCOL_NAME = "snmp"
    DISPLAY_FILTER = "snmp"
    REQUIRED_LAYERS = ("snmp",)
    PROTOCOL_COLUMNS = (
        "version",
        "operation",
        "community_user",
        "oid",
        "value",
    )

    # SNMP version mapping (PyShark returns string values)
    VERSION_MAP = {
        "0": "v1",
        "1": "v2c",
        "3": "v3",
        0: "v1",
        1: "v2c",
        3: "v3",
    }

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.credentials: List[SNMPCredential] = []
        self._seen_creds: set = set()
        # Track system info extracted from OID responses
        self.system_info: Dict[str, Dict[str, str]] = {}  # agent_ip -> {sysDescr, sysName, ...}
        # Track SET (write) operations for structured harvest alerts. SET is a
        # config change -- security-relevant, must not be log-only.
        self._set_ops: List[Dict[str, str]] = []

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format SNMP interaction as protocol-specific table columns."""
        d = ix.details
        version = d.get("version", "?")
        operation = d.get("operation", "?")
        # Flag SET operations
        if operation == "SET":
            operation = "[!] SET"
        community = d.get("community", "") or d.get("username", "") or "-"
        oid_name = d.get("oid_friendly", "") or d.get("oid", "") or "-"
        value = d.get("value_str", "") or "-"
        return [
            version,
            operation,
            community,
            oid_name,
            value,
        ]

    def process_packet(self, packet) -> None:
        """Process SNMP packet and extract credentials, OIDs, and values."""
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)

        if not hasattr(packet, "snmp"):
            return

        snmp = packet.snmp

        # Get SNMP version (v3 uses msgVersion, v1/v2c uses version)
        version_raw = self.get_field(snmp, "version", None)
        is_v3 = False
        if version_raw is None:
            version_raw = self.get_field(snmp, "msgVersion", None)
            if str(version_raw) == "3":
                is_v3 = True
        if version_raw is None:
            return

        version = self.VERSION_MAP.get(version_raw, self.VERSION_MAP.get(str(version_raw), "v1"))

        # Extract PDU type / operation
        operation = self._get_operation(snmp)
        is_response = operation in ("RESPONSE", "REPORT")
        direction = "response" if is_response else "request"

        # Determine which endpoint is the manager (client) vs the agent
        # (server). GET/GET-NEXT/GET-BULK/SET are manager -> agent queries;
        # RESPONSE/REPORT are agent -> manager replies; TRAPv1/TRAPv2/INFORM
        # are agent-initiated notifications (also agent -> manager) even
        # though `direction` above labels them "request" for display. Using
        # `is_response` alone (agent iff response) swaps roles for every
        # trap/inform. Fall back to the canonical agent port (161) / trap
        # port (162) when the operation can't be classified (PDU_TYPES
        # "UNKNOWN").
        is_agent_sender = operation in ("RESPONSE", "REPORT", "TRAPv1", "TRAPv2", "INFORM")
        if operation == "UNKNOWN":
            if dst_port == 161:
                is_agent_sender = False
            elif src_port in (161, 162) or dst_port == 162:
                is_agent_sender = True
        if is_agent_sender:
            manager_ip, agent_ip = dst_ip, src_ip
            manager_mac, agent_mac = dst_mac, src_mac
            agent_port = src_port
        else:
            manager_ip, agent_ip = src_ip, dst_ip
            manager_mac, agent_mac = src_mac, dst_mac
            agent_port = dst_port

        # Extract credential (community or v3 username)
        community = ""
        username = ""
        if is_v3 or version == "v3":
            username = self._extract_v3_username(snmp) or ""
        else:
            raw_community = self.get_field(snmp, "community", None)
            if raw_community:
                community = self._clean_community_string(raw_community) or ""

        # Extract OID and value
        oid = str(self.get_field(snmp, "name", "") or "")
        oid_friendly = _resolve_oid(oid) if oid else ""
        value_str = str(self.get_field(snmp, "var_bind_str", "") or "")
        if not value_str:
            # Try typed value fields
            for vtype in ("octets", "int", "oid", "counter", "timeticks", "gauge32", "ipaddress"):
                val = self.get_field(snmp, f"value_{vtype}", None)
                if val is not None:
                    value_str = str(val)
                    break

        # Decode hex octets to readable string if possible
        if value_str and ":" in value_str and len(value_str) > 5:
            decoded = _try_decode_hex(value_str)
            if decoded:
                value_str = decoded

        # Extract request/response correlation and error info
        request_id = self.get_field(snmp, "request_id", None)
        if request_id is not None:
            request_id = str(request_id)
        else:
            request_id = ""

        error_status = str(self.get_field(snmp, "error_status", "0") or "0")
        error_index = self.get_field(snmp, "error_index", None)
        if error_index is not None:
            error_index = str(error_index)
        else:
            error_index = ""

        # VarBind count (number of OID-value pairs in the PDU)
        variable_bindings = self.get_field(snmp, "variable_bindings", None)
        if variable_bindings is not None:
            variable_bindings = str(variable_bindings)
        else:
            variable_bindings = ""

        # SNMPv3 security details
        v3_auth = ""
        v3_crypt = ""
        engine_id = ""
        msg_id = ""
        security_model = ""
        engine_boots = ""
        engine_time = ""
        auth_params = ""
        context_engine_id = ""
        context_name = ""
        if is_v3 or version == "v3":
            v3_auth = str(self.get_field(snmp, "v3_flags_auth", "") or "")
            v3_crypt = str(self.get_field(snmp, "v3_flags_crypt", "") or "")
            engine_id = str(self.get_field(snmp, "msgAuthoritativeEngineID", "") or "")
            engine_enterprise = str(self.get_field(snmp, "engineid_enterprise", "") or "")
            if engine_enterprise:
                engine_id = f"enterprise:{engine_enterprise}"

            # T1 gap fields: v3 message correlation and security parameters
            raw_msg_id = self.get_field(snmp, "msgID", None)
            msg_id = str(raw_msg_id) if raw_msg_id is not None else ""

            raw_sec_model = self.get_field(snmp, "msgSecurityModel", None)
            if raw_sec_model is not None:
                security_model = SECURITY_MODEL_MAP.get(
                    raw_sec_model, SECURITY_MODEL_MAP.get(str(raw_sec_model), str(raw_sec_model))
                )
            else:
                security_model = ""

            raw_boots = self.get_field(snmp, "msgAuthoritativeEngineBoots", None)
            engine_boots = str(raw_boots) if raw_boots is not None else ""

            raw_time = self.get_field(snmp, "msgAuthoritativeEngineTime", None)
            engine_time = str(raw_time) if raw_time is not None else ""

            raw_auth = self.get_field(snmp, "msgAuthenticationParameters", None)
            auth_params = str(raw_auth) if raw_auth is not None else ""

            raw_ctx_engine = self.get_field(snmp, "contextEngineID", None)
            context_engine_id = str(raw_ctx_engine) if raw_ctx_engine is not None else ""

            raw_ctx_name = self.get_field(snmp, "contextName", None)
            context_name = str(raw_ctx_name) if raw_ctx_name is not None else ""

        # Trap-specific fields
        trap_enterprise = ""
        trap_agent = ""
        trap_type = ""
        if operation in ("TRAPv1", "TRAPv2"):
            trap_enterprise = str(self.get_field(snmp, "enterprise", "") or "")
            trap_agent = str(self.get_field(snmp, "agent_addr", "") or "")
            generic_trap = str(self.get_field(snmp, "generic_trap", "") or "")
            specific_trap = str(self.get_field(snmp, "specific_trap", "") or "")
            if generic_trap:
                trap_type = f"generic={generic_trap}"
                if specific_trap and specific_trap != "0":
                    trap_type += f" specific={specific_trap}"

        # Build interaction details
        details: Dict[str, Any] = {
            "version": version,
            "operation": operation,
            "community": community,
            "username": username,
            "oid": oid,
            "oid_friendly": oid_friendly,
            "value_str": value_str,
            "error_status": error_status,
            "request_id": request_id,
            "error_index": error_index,
            "variable_bindings": variable_bindings,
        }
        # Annotate human-readable error status when non-zero
        if error_status and error_status != "0":
            details["error_name"] = ERROR_STATUS_MAP.get(error_status, f"unknown({error_status})")
        if is_v3 or version == "v3":
            sec_str = []
            if str(v3_auth).lower() in ("1", "true"):
                sec_str.append("auth")
            if str(v3_crypt).lower() in ("1", "true"):
                sec_str.append("priv")
            details["v3_security"] = "+".join(sec_str) if sec_str else "noAuth"
            details["engine_id"] = engine_id
            details["msg_id"] = msg_id
            details["security_model"] = security_model
            details["engine_boots"] = engine_boots
            details["engine_time"] = engine_time
            details["auth_params"] = auth_params
            details["context_engine_id"] = context_engine_id
            details["context_name"] = context_name
        if trap_enterprise:
            details["trap_enterprise"] = trap_enterprise
            details["trap_agent"] = trap_agent
            details["trap_type"] = trap_type

        # Record interaction
        now = datetime.now().isoformat()
        summary = f"SNMP {version} {operation} {src_ip}"
        if oid_friendly:
            summary += f" {oid_friendly}"
        if value_str:
            summary += f"={value_str}"
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            f"SNMP {version} {operation}",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        # Track system info from well-known OID responses
        if is_response and oid in WELL_KNOWN_OIDS and value_str:
            field_name = WELL_KNOWN_OIDS[oid]
            if src_ip not in self.system_info:
                self.system_info[src_ip] = {}
            self.system_info[src_ip][field_name] = value_str
            self.logger.debug(f"SNMP {src_ip} {field_name}={value_str}")

        # Flag SET operations as warnings + record for structured harvest alert
        if operation == "SET":
            self._set_ops.append(
                {
                    "client": src_ip,
                    "server": dst_ip,
                    "oid": oid_friendly or oid or "?",
                    "value": value_str or "?",
                }
            )
            self.logger.warning(
                f"SNMP SET detected: {src_ip} -> {dst_ip} "
                f"OID={oid_friendly or oid} value={value_str}"
            )

        # Record credentials.  Pass manager_ip/agent_ip (not raw src_ip/dst_ip)
        # so the credential's client/server attribution matches who actually
        # sent the query vs. who answered/notified (see is_agent_sender
        # above) -- a response or trap has src_ip == the agent, not the
        # manager.
        if community:
            self._record_credential(
                community_or_username=community,
                version=version,
                credential_type="community",
                src_ip=manager_ip,
                dst_ip=agent_ip,
                dest_port=agent_port,
                src_mac=manager_mac or "",
                dst_mac=agent_mac or "",
            )
        if username:
            self._record_credential(
                community_or_username=username,
                version="v3",
                credential_type="username",
                src_ip=manager_ip,
                dst_ip=agent_ip,
                dest_port=agent_port,
                src_mac=manager_mac or "",
                dst_mac=agent_mac or "",
            )

    def _get_operation(self, snmp) -> str:
        """Determine SNMP PDU operation type."""
        # Check for PDU element fields (most reliable)
        pdu_elements = {
            "get_request_element": "GET",
            "get_response_element": "RESPONSE",
            "get_next_request_element": "GET-NEXT",
            "set_request_element": "SET",
            "trap_element": "TRAPv1",
            "getBulkRequest_element": "GET-BULK",
            "report_element": "REPORT",
        }
        for field, op in pdu_elements.items():
            if self.get_field(snmp, field, None) is not None:
                return op

        # Fallback to data field (PDU type number)
        data_val = str(self.get_field(snmp, "data", "") or "")
        return PDU_TYPES.get(data_val, "UNKNOWN")

    def _extract_v3_username(self, snmp_layer) -> Optional[str]:
        """Extract username from SNMPv3 USM structure via PyShark."""
        username = self.get_field(snmp_layer, "msgUserName", None)
        if username:
            cleaned = self._clean_string(username)
            if cleaned:
                return cleaned

        all_fields = self.get_all_fields(snmp_layer)
        for field in ("snmp.msgUserName", "msgUserName"):
            if field in all_fields:
                value = all_fields[field]
                if value:
                    cleaned = self._clean_string(value)
                    if cleaned:
                        return cleaned

        return None

    def _clean_community_string(self, raw_value: str) -> Optional[str]:
        """Clean up community string from PyShark."""
        if not raw_value:
            return None

        value = str(raw_value)

        # Remove surrounding quotes
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        if value.startswith("'") and value.endswith("'"):
            value = value[1:-1]

        # Check if hex-encoded (colon-separated)
        if ":" in value and all(len(p) == 2 for p in value.split(":")):
            try:
                value = bytes.fromhex(value.replace(":", "")).decode("utf-8", errors="ignore")
            except (ValueError, UnicodeDecodeError) as e:
                self.logger.debug(f"Failed to get value: {e}")

        # Skip <MISSING> placeholder
        if "<MISSING>" in value:
            return None

        if value and value.isprintable() and not value.isspace():
            return value

        return None

    def _clean_string(self, raw_value: str) -> Optional[str]:
        """Clean and validate a string value from PyShark."""
        if not raw_value:
            return None
        value = str(raw_value)
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        if value.startswith("'") and value.endswith("'"):
            value = value[1:-1]
        # Skip <MISSING> placeholder
        if "<MISSING>" in value:
            return None
        if value and value.isprintable() and not value.isspace():
            return value
        return None

    def _record_credential(
        self,
        community_or_username: str,
        version: str,
        credential_type: str,
        src_ip: str,
        dst_ip: str,
        dest_port: int = 0,
        src_mac: str = "",
        dst_mac: str = "",
    ) -> None:
        """Record extracted SNMP credential.

        ``src_ip``/``dst_ip`` here are the manager (client) / agent (server)
        IPs respectively -- callers must resolve manager vs. agent role
        first (a response/trap/inform has the agent as the packet's src_ip,
        not the manager) and pass those in, not the raw packet src/dst.
        """
        manager_ip, agent_ip = src_ip, dst_ip
        manager_mac, agent_mac = src_mac, dst_mac
        cred_key = (community_or_username, version, manager_ip, agent_ip)
        if cred_key in self._seen_creds:
            return
        self._seen_creds.add(cred_key)

        cred = SNMPCredential(
            community_or_username=community_or_username,
            version=version,
            source_ip=manager_ip,
            dest_ip=agent_ip,
            dest_port=dest_port,
            timestamp=datetime.now().isoformat(),
            credential_type=credential_type,
        )
        self.credentials.append(cred)

        type_str = "community string" if credential_type == "community" else "username"
        self.logger.info(
            f"SNMP {version} {type_str}: {community_or_username} "
            f"({manager_ip} -> {agent_ip}:{dest_port})"
        )

        self._update_devices(
            manager_ip,
            agent_ip,
            version,
            credential_type,
            community_or_username,
            src_mac=manager_mac,
            dst_mac=agent_mac,
        )

    def _update_devices(
        self,
        manager_ip: str,
        agent_ip: str,
        version: str,
        credential_type: str,
        value: str,
        src_mac: str = "",
        dst_mac: str = "",
    ) -> None:
        """Update or create device entries for SNMP participants."""
        if is_valid_discovered_ip(manager_ip):
            self._update_device(manager_ip, "manager", version, credential_type, value, mac=src_mac)
        if is_valid_discovered_ip(agent_ip):
            self._update_device(agent_ip, "agent", version, credential_type, value, mac=dst_mac)

    def _update_device(
        self,
        ip: str,
        role: str,
        version: str,
        credential_type: str,
        value: str,
        mac: str = "",
    ) -> None:
        """Update or create single device entry."""
        device_key = f"snmp-{role}:{ip}"

        vendor = lookup_mac_vendor(mac) if mac else ""
        # Use sysName if available
        sys_info = self.system_info.get(ip, {})
        name = sys_info.get("sysName", "")

        device, is_new = self._ensure_device(
            device_key,
            ip,
            mac=mac,
            name=name,
            device_type=f"SNMP {role.title()}",
            manufacturer=vendor if vendor != "Unknown" else "",
        )
        if is_new:
            device.snmp_passive_data = {
                "role": role,
                "version": version,
                "credentials": [],
                "protocol": "SNMP/UDP",
            }
        if device.snmp_passive_data:
            creds = device.snmp_passive_data.get("credentials", [])
            cred_entry = {"type": credential_type, "value": value}
            if cred_entry not in creds:
                creds.append(cred_entry)
                device.snmp_passive_data["credentials"] = creds
            current_version = device.snmp_passive_data.get("version", "v1")
            if version == "v3" or (version == "v2c" and current_version == "v1"):
                device.snmp_passive_data["version"] = version
            # Attach system info if available
            if sys_info:
                device.snmp_passive_data["system_info"] = sys_info

    def harvest(self) -> Dict[str, Any]:
        """Surface SNMP SET (write) alerts and a system-info fingerprint table."""
        result = super().harvest()
        if not result:
            result = {"tables": [], "alerts": []}
        tables = result.setdefault("tables", [])
        alerts = result.setdefault("alerts", [])

        # SET operations are config writes -- emit a fail-level alert each.
        for op in self._set_ops:
            alerts.append(
                {
                    "level": "fail",
                    "category": "write_alert",
                    "message": (
                        f"SNMP SET: {op['client']} -> {op['server']} "
                        f"OID={op['oid']} value={op['value']}"
                    ),
                }
            )

        # System-info fingerprint table (sysDescr / sysName / sysLocation ...).
        if self.system_info:
            rows = []
            for ip, info in sorted(self.system_info.items()):
                rows.append(
                    [
                        ip,
                        info.get("sysName", ""),
                        info.get("sysDescr", ""),
                        info.get("sysLocation", ""),
                        info.get("sysContact", ""),
                    ]
                )
            if rows:
                tables.append(
                    {
                        "headers": ["Agent", "sysName", "sysDescr", "sysLocation", "sysContact"],
                        "rows": rows,
                        "title": f"SNMP System Info ({len(rows)})",
                    }
                )

        if not tables and not alerts:
            return {}
        return result

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted credentials."""
        return [
            {
                "protocol": "SNMP",
                "version": cred.version,
                "credential_type": cred.credential_type,
                "auth_method": f"SNMP {cred.version}",
                "value": cred.community_or_username,
                "username": cred.community_or_username,
                "source_ip": cred.source_ip,
                "dest_ip": cred.dest_ip,
                "server_ip": cred.dest_ip,
                "client_ip": cred.source_ip,
                "timestamp": cred.timestamp,
            }
            for cred in self.credentials
        ]


def _resolve_oid(oid: str) -> str:
    """Resolve an OID to a friendly name."""
    if not oid:
        return ""
    # Exact match
    if oid in WELL_KNOWN_OIDS:
        return WELL_KNOWN_OIDS[oid]
    # Prefix match
    for prefix, name in OID_PREFIXES.items():
        if oid.startswith(prefix):
            suffix = oid[len(prefix) :]
            return f"{name}{suffix}"
    return oid


def _try_decode_hex(hex_str: str) -> Optional[str]:
    """Try to decode a colon-separated hex string to UTF-8."""
    parts = hex_str.split(":")
    if not all(len(p) == 2 for p in parts):
        return None
    try:
        decoded = bytes.fromhex(hex_str.replace(":", "")).decode("utf-8", errors="strict")
        if decoded.isprintable():
            return decoded
    except (ValueError, UnicodeDecodeError) as e:
        logger.debug(f"Failed to get decoded: {e}")
    return None

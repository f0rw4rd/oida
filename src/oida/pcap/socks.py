"""
SOCKS Proxy Passive Listener for credential extraction.

Passively captures SOCKS proxy traffic to extract:
- Usernames from SOCKS5 username/password authentication
- Passwords from SOCKS5 authentication
- SOCKS protocol version (4 or 5)
- Authentication methods offered and accepted
- Authentication status (success/failure)
- Subnegotiation version

SOCKS5 (RFC 1928) supports username/password authentication (RFC 1929)
which transmits credentials in cleartext.

SOCKS5 authentication flow:
    1. Client -> Server: Greeting (version, auth_method_count, auth_methods)
    2. Server -> Client: Method selection (version, auth_accepted_method)
    3. Client -> Server: Auth request (subneg_version, username, password)
    4. Server -> Client: Auth response (subneg_version, auth_status)

tshark fields extracted:
- socks.version: SOCKS protocol version (4 or 5)
- socks.auth_method_count: Number of auth methods offered by client
- socks.auth_method: Auth methods offered (0=none, 1=GSSAPI, 2=user/pass)
- socks.auth_accepted_method: Auth method selected by server
- socks.auth_status: Authentication result (0=success, non-zero=failure)
- socks.subnegotiation_version: Auth subnegotiation version
- socks.username: SOCKS username
- socks.password: SOCKS password

References:
- RFC 1928: SOCKS Protocol Version 5
- RFC 1929: Username/Password Authentication for SOCKS V5
- Wireshark dissector: packet-socks.c
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .pyshark_base import ProtocolInteraction, PySharkListenerBase

# SOCKS authentication method names (RFC 1928 Section 3)
AUTH_METHOD_NAMES: Dict[str, str] = {
    "0": "No Authentication",
    "1": "GSSAPI",
    "2": "Username/Password",
    "255": "No Acceptable Methods",
}

# SOCKS auth status codes (RFC 1929 Section 2)
AUTH_STATUS_NAMES: Dict[str, str] = {
    "0": "Success",
}

# SOCKS command codes (RFC 1928 Section 4)
COMMAND_NAMES: Dict[str, str] = {
    "1": "CONNECT",
    "2": "BIND",
    "3": "UDP ASSOCIATE",
}

# SOCKS reply/result codes (RFC 1928 Section 6)
RESULT_NAMES: Dict[str, str] = {
    "0": "Succeeded",
    "1": "General SOCKS server failure",
    "2": "Connection not allowed by ruleset",
    "3": "Network unreachable",
    "4": "Host unreachable",
    "5": "Connection refused",
    "6": "TTL expired",
    "7": "Command not supported",
    "8": "Address type not supported",
}


def _command_name(code: str) -> str:
    """Return human-readable SOCKS command name."""
    return COMMAND_NAMES.get(code, f"Command({code})")


def _result_name(code: str) -> str:
    """Return human-readable SOCKS reply/result name."""
    return RESULT_NAMES.get(code, f"Result({code})")


def _auth_method_name(code: str) -> str:
    """Return human-readable auth method name for a SOCKS method code."""
    return AUTH_METHOD_NAMES.get(code, f"Private({code})")


def _auth_status_name(code: str) -> str:
    """Return human-readable auth status name."""
    return AUTH_STATUS_NAMES.get(code, f"Failure({code})")


@dataclass
class SOCKSCredential:
    """Extracted SOCKS credential."""

    username: str
    password: str = ""
    credential_type: str = "plaintext"
    server_ip: str = ""
    server_port: int = 0
    client_ip: str = ""
    timestamp: str = ""
    success: Optional[bool] = None  # True if auth_status=0, False otherwise, None if unknown

    @property
    def auth_method(self) -> str:
        """Scanner credential loop compatibility."""
        return "SOCKS5"


class SOCKSPassiveListener(PySharkListenerBase):
    """Passive SOCKS proxy traffic listener for credential extraction.

    Captures SOCKS5 authentication traffic to extract usernames, passwords,
    protocol version, offered/accepted auth methods, and auth status.
    """

    PROTOCOL_NAME = "socks"
    DISPLAY_FILTER = "socks"
    REQUIRED_LAYERS = ("socks",)

    PROTOCOL_COLUMNS = ("version", "operation", "detail", "status")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.credentials: List[SOCKSCredential] = []
        # Track auth status per flow to correlate with credentials
        self._flow_auth_status: Dict[str, Optional[bool]] = {}

    def process_packet(self, packet) -> None:
        """Process SOCKS packet and extract all protocol fields."""
        if not hasattr(packet, "socks"):
            return

        socks = packet.socks
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        now = self._get_timestamp()

        # --- T1 fields: extract from every SOCKS packet ---
        version = self.get_field(socks, "version", "")
        if not version:
            version = "?"
            self.logger.debug(f"Missing socks.version in packet from {src_ip} -> {dst_ip}")
        version_str = str(version)

        auth_method_count = self.get_field(socks, "auth_method_count", "")
        auth_method = self.get_field(socks, "auth_method", "")
        auth_accepted_method = self.get_field(socks, "auth_accepted_method", "")
        auth_status = self.get_field(socks, "auth_status", "")
        subneg_version = self.get_field(socks, "subnegotiation_version", "")
        username = str(self.get_field(socks, "username", "") or "").strip()
        password = str(self.get_field(socks, "password", "") or "").strip()
        command = self.get_field(socks, "command", "")
        # socks.dst is FT_IPv4 only; SOCKS5 clients overwhelmingly send
        # ATYP=domainname (socks.remote_name / socks.v4a_dns_name) and IPv6
        # targets appear as socks.dstV6. Reading only the IPv4 field dropped the
        # single most security-relevant datum -- which host the proxy was asked
        # to reach -- for most real traffic. ("remote_ip" was a dead fallback.)
        dst = self.get_field_any(socks, "dst", "dstV6", "remote_name", "v4a_dns_name", default="")
        dstport = self.get_field(socks, "dstport", "")
        results = self.get_field(socks, "results", "")

        # --- Determine packet type and record interaction ---

        # Type 1: Client greeting (has auth_method_count and/or auth_method)
        if auth_method_count:
            method_name = _auth_method_name(str(auth_method)) if auth_method else "?"
            detail = f"methods={auth_method_count} [{method_name}]"
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request",
                "SOCKS Greeting",
                {
                    "version": version_str,
                    "auth_method_count": str(auth_method_count),
                    "auth_method": str(auth_method) if auth_method else "?",
                    "auth_method_name": method_name,
                },
                f"SOCKSv{version_str} greeting: {detail}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=self.get_stream_id(packet),
            )
            self._update_devices(
                client_ip=src_ip,
                server_ip=dst_ip,
                dst_port=dst_port,
                version=version_str,
                auth_methods_offered=str(auth_method) if auth_method else "",
            )
            return

        # Type 2: Server method selection (has auth_accepted_method)
        if auth_accepted_method:
            accepted_name = _auth_method_name(str(auth_accepted_method))
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                "SOCKS Method Select",
                {
                    "version": version_str,
                    "auth_accepted_method": str(auth_accepted_method),
                    "auth_accepted_method_name": accepted_name,
                },
                f"SOCKSv{version_str} server selected: {accepted_name}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=self.get_stream_id(packet),
            )
            return

        # Type 3: Client auth request (has username).
        # tshark maps the SOCKS4/4a USERID onto the same socks.username field
        # used by SOCKS5 auth. A SOCKS4 request also carries a `command`, while
        # the SOCKS5 auth subnegotiation does not — so only treat `username` as
        # an auth credential when no command is present. Otherwise a SOCKS4
        # CONNECT with a userid would be recorded as a bogus credential and
        # return here, dropping the actual CONNECT target (handled at Type 5).
        _has_command = command != "" and command is not None
        if username and not _has_command:
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request",
                "SOCKS Auth Request",
                {
                    "version": version_str,
                    "subnegotiation_version": str(subneg_version) if subneg_version else "?",
                    "username": username,
                },
                f"SOCKSv{version_str} auth user={username}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=self.get_stream_id(packet),
            )

            if not self._is_duplicate(username, password, src_ip, dst_ip):
                cred = SOCKSCredential(
                    username=username,
                    password=password,
                    credential_type="plaintext" if password else "username_only",
                    server_ip=dst_ip,
                    server_port=dst_port,
                    client_ip=src_ip,
                    timestamp=now,
                    success=None,  # will be updated when auth_status response arrives
                )
                self.credentials.append(cred)
                self._update_devices(
                    client_ip=src_ip,
                    server_ip=dst_ip,
                    dst_port=dst_port,
                    version=version_str,
                )

                if password:
                    self.logger.info(f"SOCKS: {username}:{password} @ {dst_ip}:{dst_port}")
                else:
                    self.logger.info(f"SOCKS: username={username} @ {dst_ip}:{dst_port}")
            return

        # Type 4: Server auth response (has auth_status)
        if auth_status is not None and auth_status != "":
            status_str = str(auth_status)
            status_name = _auth_status_name(status_str)
            success = status_str == "0"

            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                "SOCKS Auth Response",
                {
                    "version": version_str,
                    "subnegotiation_version": str(subneg_version) if subneg_version else "?",
                    "auth_status": status_str,
                    "auth_status_name": status_name,
                    "success": success,
                },
                f"SOCKSv{version_str} auth {status_name}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=self.get_stream_id(packet),
            )

            # Update the most recent credential for this flow with success status
            if flow_id:
                self._flow_auth_status[flow_id] = success
            self._update_credential_status(src_ip, dst_ip, success)

            if not success:
                self.logger.info(f"SOCKS auth failure: {src_ip} -> {dst_ip} status={status_str}")
            return

        # Type 5: Client command request (CONNECT/BIND/UDP ASSOCIATE) -- the
        # most security-relevant part of a SOCKS session: which host/port the
        # proxy was asked to reach.
        if command != "" and command is not None:
            command_str = str(command)
            command_name = _command_name(command_str)
            dst_str = str(dst) if dst else ""
            dstport_str = str(dstport) if dstport else ""
            target = f"{dst_str}:{dstport_str}" if dst_str else dstport_str
            detail = f"{command_name} {target}".strip()
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request",
                "SOCKS Connect",
                {
                    "version": version_str,
                    "command": command_str,
                    "command_name": command_name,
                    "dst": dst_str,
                    "dstport": dstport_str,
                },
                f"SOCKSv{version_str} {detail}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=self.get_stream_id(packet),
            )
            self._update_devices(
                client_ip=src_ip,
                server_ip=dst_ip,
                dst_port=dst_port,
                version=version_str,
            )
            return

        # Type 6: Server command reply (carries the connection result code).
        if results != "" and results is not None:
            results_str = str(results)
            result_name = _result_name(results_str)
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                "SOCKS Reply",
                {
                    "version": version_str,
                    "results": results_str,
                    "results_name": result_name,
                },
                f"SOCKSv{version_str} reply: {result_name}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=self.get_stream_id(packet),
            )
            return

        # Catch-all: a SOCKS packet that matched the display filter but carries
        # none of the recognized fields. Record a generic interaction so no
        # filtered packet is silently dropped without trace.
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            "SOCKS Data",
            {"version": version_str},
            f"SOCKSv{version_str} data",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )
        self.logger.debug(
            f"SOCKS: unclassified packet {src_ip} -> {dst_ip} recorded as generic data"
        )

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format a SOCKS interaction as a table row."""
        d = ix.details
        version = d.get("version", "?")

        # Build detail string based on operation type
        op = ix.operation
        if op == "SOCKS Greeting":
            detail = f"methods={d.get('auth_method_count', '?')} [{d.get('auth_method_name', '?')}]"
        elif op == "SOCKS Method Select":
            detail = d.get("auth_accepted_method_name", "?")
        elif op == "SOCKS Auth Request":
            detail = f"user={d.get('username', '?')}"
        elif op == "SOCKS Auth Response":
            detail = d.get("auth_status_name", "?")
        elif op == "SOCKS Connect":
            dst = d.get("dst", "")
            dstport = d.get("dstport", "")
            target = f"{dst}:{dstport}" if dst else dstport
            detail = f"{d.get('command_name', '?')} {target}".strip()
        elif op == "SOCKS Reply":
            detail = d.get("results_name", "?")
        else:
            detail = ix.summary

        # Status column: success/failure for auth response, empty for others
        status = ""
        if "success" in d:
            status = "OK" if d["success"] else "FAIL"

        return [version, op, detail, status]

    def _is_duplicate(self, username: str, password: str, client_ip: str, server_ip: str) -> bool:
        """Check if credential is already recorded."""
        for cred in self.credentials:
            if (
                cred.username == username
                and cred.password == password
                and cred.client_ip == client_ip
                and cred.server_ip == server_ip
            ):
                return True
        return False

    def _update_credential_status(self, server_ip: str, client_ip: str, success: bool) -> None:
        """Update the most recent credential for this server/client pair with auth status."""
        # The auth response comes from the server (src_ip) to the client (dst_ip)
        # so server_ip=src_ip, client_ip=dst_ip
        for cred in reversed(self.credentials):
            if cred.server_ip == server_ip and cred.client_ip == client_ip:
                if cred.success is None:
                    cred.success = success
                break

    def _update_devices(
        self,
        client_ip: str,
        server_ip: str,
        dst_port: int = 0,
        version: str = "",
        auth_methods_offered: str = "",
    ) -> None:
        """Update device entries with protocol-specific data."""
        server_data: Dict[str, Any] = {
            "role": "server",
            "protocol": "SOCKS/TCP",
        }
        if version:
            server_data["socks_version"] = version
        if auth_methods_offered:
            server_data["auth_methods_offered"] = auth_methods_offered

        self._ensure_device(
            f"socks-server:{server_ip}",
            server_ip,
            name=f"SOCKS Proxy ({server_ip})",
            device_type="Proxy Server",
            data_attr="socks_passive_data",
            protocol_data=server_data,
        )

        client_data: Dict[str, Any] = {
            "role": "client",
            "protocol": "SOCKS/TCP",
        }
        if version:
            client_data["socks_version"] = version

        self._ensure_device(
            f"socks-client:{client_ip}",
            client_ip,
            name=f"SOCKS Client ({client_ip})",
            device_type="SOCKS Client",
            data_attr="socks_passive_data",
            protocol_data=client_data,
        )

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted credentials using canonical key names."""
        return [
            {
                "protocol": "SOCKS",
                "credential_type": cred.credential_type,
                "auth_method": "SOCKS5",
                "username": cred.username,
                "password": cred.password,
                "server_ip": cred.server_ip,
                "server_port": cred.server_port,
                "client_ip": cred.client_ip,
                "success": cred.success,
                "timestamp": cred.timestamp,
            }
            for cred in self.credentials
        ]

"""
IRC Passive Listener for credential extraction.

Passively captures IRC traffic to extract:
- NICK commands (nickname)
- USER commands (username, realname)
- PASS commands (server password)

IRC authentication is plaintext, making this a high-value extraction target.

tshark fields:
- irc.request.command: IRC command (NICK, USER, PASS, etc.)
- irc.request.command_parameter: Command parameters

References:
- RFC 2812: Internet Relay Chat: Client Protocol
- Wireshark dissector: packet-irc.c
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from oida.pcap.pyshark_base import ProtocolInteraction, PySharkListenerBase
from oida.protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor


@dataclass
class IRCCredential:
    """Extracted IRC credential."""

    credential_type: str  # "plaintext" (PASS), "nick", "user"
    value: str
    nick: str = ""
    username: str = ""
    realname: str = ""
    server_ip: str = ""
    client_ip: str = ""
    timestamp: str = ""

    @property
    def password(self) -> str:
        """Alias for scanner credential loop compatibility."""
        return self.value if self.credential_type == "plaintext" else ""

    @property
    def auth_method(self) -> str:
        """Return auth method for scanner credential loop."""
        return f"IRC/{self.credential_type}"


class IRCPassiveListener(PySharkListenerBase):
    """Passive IRC traffic listener for credential extraction.

    Captures IRC traffic to extract:
    - PASS commands (server/NickServ passwords)
    - NICK commands (nicknames)
    - USER commands (usernames)

    Uses PyShark (tshark) for IRC protocol dissection.
    """

    PROTOCOL_NAME = "irc"
    DISPLAY_FILTER = "irc"
    REQUIRED_LAYERS = ("irc",)

    PROTOCOL_COLUMNS = ("command", "parameter", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.credentials: List[IRCCredential] = []
        # Track session state per client IP for correlating NICK/USER/PASS
        self._sessions: Dict[str, Dict[str, str]] = {}

    def process_packet(self, packet) -> None:
        """Process IRC packet and extract credentials."""
        if not hasattr(packet, "irc"):
            return

        irc = packet.irc
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)

        command = self.get_field(irc, "request_command", "") or ""
        parameter = self.get_field(irc, "request_command_parameter", "") or ""

        # tshark tags server->client frames with irc.response.command (numeric
        # replies 001/375/433, NOTICE, PING, relayed PRIVMSG). Reading only
        # request_command dropped every server frame silently. Resolve direction
        # from whichever side carried the command.
        if command:
            direction = "request"
        else:
            command = self.get_field(irc, "response_command", "") or ""
            parameter = self.get_field(irc, "response_command_parameter", "") or ""
            direction = "response"

        if not command:
            self.logger.debug(f"IRC frame with no request/response command {src_ip} -> {dst_ip}")
            return

        command_upper = str(command).upper().strip()
        param_str = str(parameter).strip()

        # Don't leak the raw server password into the always-on operations
        # table; the credential table surfaces it instead.
        display_param = "<redacted>" if command_upper == "PASS" and param_str else param_str

        # Record interaction
        now = datetime.now().isoformat()
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            f"IRC {command_upper}",
            {"command": command_upper, "parameter": display_param},
            f"IRC {command_upper} {display_param}".strip(),
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
        )

        # Session tracking and credential extraction below assume the CLIENT is
        # the source (PASS/NICK/USER are client->server commands). Skip them for
        # server->client responses, whose src_ip is the server.
        if direction != "request":
            return

        # Get or create session tracker
        if src_ip not in self._sessions:
            self._sessions[src_ip] = {"nick": "", "user": "", "server": dst_ip}

        session = self._sessions[src_ip]
        session["server"] = dst_ip

        if command_upper == "PASS" and parameter:
            password = str(parameter).strip()
            if password and not self._is_duplicate("plaintext", password, src_ip, dst_ip):
                nick = session.get("nick", "")
                cred = IRCCredential(
                    credential_type="plaintext",
                    value=password,
                    nick=nick,
                    username=nick or session.get("user", ""),
                    server_ip=dst_ip,
                    client_ip=src_ip,
                    timestamp=datetime.now().isoformat(),
                )
                self.credentials.append(cred)
                self._update_devices(src_ip, dst_ip, src_mac, dst_mac)
                self.logger.debug(f"IRC PASS captured from {src_ip} to {dst_ip}")

        elif command_upper == "NICK" and parameter:
            nick = str(parameter).strip()
            session["nick"] = nick
            if nick and not self._is_duplicate("nick", nick, src_ip, dst_ip):
                cred = IRCCredential(
                    credential_type="nick",
                    value=nick,
                    nick=nick,
                    server_ip=dst_ip,
                    client_ip=src_ip,
                    timestamp=datetime.now().isoformat(),
                )
                self.credentials.append(cred)
                self._update_devices(src_ip, dst_ip, src_mac, dst_mac)

        elif command_upper == "USER" and parameter:
            # USER params: <username> <mode> <unused> :<realname>
            parts = str(parameter).strip().split(" ", 3)
            username = parts[0] if parts else ""
            realname = parts[3].lstrip(":") if len(parts) > 3 else ""
            session["user"] = username

            if username and not self._is_duplicate("user", username, src_ip, dst_ip):
                cred = IRCCredential(
                    credential_type="user",
                    value=username,
                    username=username,
                    realname=realname,
                    nick=session.get("nick", ""),
                    server_ip=dst_ip,
                    client_ip=src_ip,
                    timestamp=datetime.now().isoformat(),
                )
                self.credentials.append(cred)
                self._update_devices(src_ip, dst_ip, src_mac, dst_mac)

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format a single interaction as a table row matching PROTOCOL_COLUMNS."""
        command = str(ix.details.get("command", ""))
        parameter = str(ix.details.get("parameter", ""))
        detail = str(ix.summary)
        return [command, parameter, detail]

    def _is_duplicate(self, cred_type: str, value: str, client_ip: str, server_ip: str) -> bool:
        """Check if credential is already recorded."""
        for cred in self.credentials:
            if (
                cred.credential_type == cred_type
                and cred.value == value
                and cred.client_ip == client_ip
                and cred.server_ip == server_ip
            ):
                return True
        return False

    def _update_devices(
        self,
        client_ip: str,
        server_ip: str,
        client_mac: str = "",
        server_mac: str = "",
    ) -> None:
        """Update device entries for both IRC server and client."""
        if is_valid_discovered_ip(server_ip):
            server_key = f"irc-server:{server_ip}"
            server_vendor = lookup_mac_vendor(server_mac) if server_mac else ""
            device, is_new = self._ensure_device(
                server_key,
                server_ip,
                mac=server_mac,
                name=f"IRC Server ({server_ip})",
                device_type="IRC Server",
                manufacturer=server_vendor if server_vendor and server_vendor != "Unknown" else "",
            )
            if is_new:
                device.irc_passive_data = {"role": "server", "protocol": "IRC/TCP"}

        if is_valid_discovered_ip(client_ip):
            client_key = f"irc-client:{client_ip}"
            client_vendor = lookup_mac_vendor(client_mac) if client_mac else ""
            device, is_new = self._ensure_device(
                client_key,
                client_ip,
                mac=client_mac,
                name=f"IRC Client ({client_ip})",
                device_type="IRC Client",
                manufacturer=client_vendor if client_vendor and client_vendor != "Unknown" else "",
            )
            if is_new:
                device.irc_passive_data = {"role": "client", "protocol": "IRC/TCP"}

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted credentials.

        Uses canonical key names for the base class harvest()
        credential table builder.
        """
        result = []
        for cred in self.credentials:
            # For PASS credentials, username is the nick or user; value is the
            # PASSWORD -- so it must never be used as the username fallback.
            # RFC 2812 sec. 3.1 registers as PASS -> NICK -> USER, so a PASS
            # seen first has neither nick nor user yet; leave the identity
            # blank rather than printing the password in the username column.
            if cred.credential_type == "plaintext":
                username = cred.nick or cred.username or ""
            else:
                username = cred.nick or cred.username or cred.value
            entry: Dict[str, Any] = {
                "protocol": "IRC",
                "credential_type": cred.credential_type,
                "auth_method": f"IRC/{cred.credential_type}",
                "username": username,
                "password": cred.value if cred.credential_type == "plaintext" else "",
                "server_ip": cred.server_ip,
                "client_ip": cred.client_ip,
                "timestamp": cred.timestamp,
            }
            if cred.nick:
                entry["nick"] = cred.nick
            if cred.realname:
                entry["realname"] = cred.realname
            result.append(entry)
        return result

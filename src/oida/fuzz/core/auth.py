"""Protocol authenticator interface for stateful protocol fuzzing.

This module provides abstract base classes and common implementations
for protocol-specific authentication strategies.
"""

from abc import ABC, abstractmethod
from typing import Dict, Optional

from ...utils.ics_logger import get_logger


class ProtocolAuthenticator(ABC):
    """Interface for protocol-specific authentication.

    Subclasses implement protocol-specific login sequences (USER/PASS for FTP,
    CONNECT/CONNACK for MQTT, etc.).
    """

    def __init__(self, protocol_name: str = "AUTH"):
        """Initialize authenticator.

        Args:
            protocol_name: Protocol name for logging
        """
        self._log = get_logger(f"AUTH-{protocol_name}", "auth", 0)

    @abstractmethod
    def authenticate(self, connection) -> bool:
        """Perform authentication on the connection.

        Args:
            connection: StatefulConnection instance to authenticate

        Returns:
            True if authentication successful, False otherwise
        """
        pass

    @abstractmethod
    def validate(self, connection) -> bool:
        """Validate that connection is still authenticated.

        Args:
            connection: StatefulConnection instance to validate

        Returns:
            True if still authenticated, False otherwise
        """
        pass

    def get_credentials(self) -> Dict[str, str]:
        """Return credentials for logging (may mask sensitive values).

        Returns:
            Dictionary with credential information
        """
        return {}


class UsernamePasswordAuth(ProtocolAuthenticator):
    """Common username/password authentication.

    Works for protocols that use USER/PASS style authentication
    (FTP, POP3, SMTP AUTH, etc.).
    """

    def __init__(
        self,
        username: str,
        password: str,
        user_cmd_fmt: str = "USER {}\r\n",
        pass_cmd_fmt: str = "PASS {}\r\n",
        user_ok_codes: Optional[list] = None,
        pass_ok_codes: Optional[list] = None,
        protocol_name: str = "AUTH",
    ):
        """Initialize username/password authenticator.

        Args:
            username: Username for authentication
            password: Password for authentication
            user_cmd_fmt: Format string for USER command (with {} placeholder)
            pass_cmd_fmt: Format string for PASS command (with {} placeholder)
            user_ok_codes: Acceptable response codes for USER (default: [331])
            pass_ok_codes: Acceptable response codes for PASS (default: [230])
            protocol_name: Protocol name for logging
        """
        super().__init__(protocol_name)
        self.username = username
        self.password = password
        self.user_cmd_fmt = user_cmd_fmt
        self.pass_cmd_fmt = pass_cmd_fmt
        self.user_ok_codes = user_ok_codes or [331]
        self.pass_ok_codes = pass_ok_codes or [230]

    def authenticate(self, conn) -> bool:
        """Perform USER/PASS authentication.

        Args:
            conn: Connection with _send_command method

        Returns:
            True if authentication successful
        """
        self._log.debug(f"Authenticating as '{self.username}'")
        try:
            # Send USER command
            user_cmd = self.user_cmd_fmt.format(self.username).encode()
            conn._send_command(user_cmd, self.user_ok_codes)

            # Send PASS command
            pass_cmd = self.pass_cmd_fmt.format(self.password).encode()
            conn._send_command(pass_cmd, self.pass_ok_codes)

            self._log.debug("Authentication successful")
            return True
        except ConnectionError as e:
            self._log.fail(f"Authentication failed: {e}")
            return False
        except Exception as e:
            self._log.fail(f"Authentication error: {e}")
            return False

    def validate(self, conn) -> bool:
        """Validate authentication is still valid.

        Default implementation returns True. Override for protocols
        that can actively check authentication state.

        Args:
            conn: Connection to validate

        Returns:
            True if still authenticated
        """
        return True

    def get_credentials(self) -> Dict[str, str]:
        """Return credentials for logging."""
        return {"username": self.username, "password": self.password}


class MQTTAuthenticator(ProtocolAuthenticator):
    """MQTT CONNECT/CONNACK authentication.

    Handles MQTT connection establishment with optional username/password.
    """

    # MQTT Return Codes
    RC_ACCEPTED = 0x00
    RC_UNACCEPTABLE_PROTOCOL = 0x01
    RC_IDENTIFIER_REJECTED = 0x02
    RC_SERVER_UNAVAILABLE = 0x03
    RC_BAD_CREDENTIALS = 0x04
    RC_NOT_AUTHORIZED = 0x05

    RC_MESSAGES = {
        RC_ACCEPTED: "Connection accepted",
        RC_UNACCEPTABLE_PROTOCOL: "Unacceptable protocol version",
        RC_IDENTIFIER_REJECTED: "Identifier rejected",
        RC_SERVER_UNAVAILABLE: "Server unavailable",
        RC_BAD_CREDENTIALS: "Bad username or password",
        RC_NOT_AUTHORIZED: "Not authorized",
    }

    def __init__(
        self,
        client_id: str = "oida-fuzz",
        username: Optional[str] = None,
        password: Optional[str] = None,
        protocol_version: int = 4,
        keep_alive: int = 60,
        clean_session: bool = True,
        protocol_name: str = "MQTT",
    ):
        """Initialize MQTT authenticator.

        Args:
            client_id: MQTT client identifier
            username: Optional username for authentication
            password: Optional password for authentication
            protocol_version: MQTT protocol version (3=3.1, 4=3.1.1, 5=5.0)
            keep_alive: Keep alive interval in seconds
            clean_session: Clean session flag
            protocol_name: Protocol name for logging
        """
        super().__init__(protocol_name)
        self.client_id = client_id
        self.username = username
        self.password = password
        self.protocol_version = protocol_version
        self.keep_alive = keep_alive
        self.clean_session = clean_session

    def authenticate(self, conn) -> bool:
        """Send MQTT CONNECT and validate CONNACK.

        Args:
            conn: Connection with send() and recv() methods

        Returns:
            True if connection accepted
        """
        self._log.debug(f"Sending CONNECT (client_id={self.client_id})")
        try:
            # Build and send CONNECT packet
            connect_packet = self._build_connect_packet()
            conn.send(connect_packet)

            # Receive CONNACK
            connack = conn.recv(4)
            if len(connack) < 4:
                self._log.fail(f"Incomplete CONNACK: {len(connack)} bytes")
                return False

            packet_type = connack[0]
            return_code = connack[3]

            self._log.debug(f"CONNACK received: type=0x{packet_type:02x}, rc={return_code}")

            if packet_type != 0x20:
                self._log.fail(f"Expected CONNACK (0x20), got 0x{packet_type:02x}")
                return False

            if return_code == self.RC_ACCEPTED:
                self._log.debug("MQTT connection accepted")
                return True
            else:
                msg = self.RC_MESSAGES.get(return_code, f"Unknown error: {return_code}")
                self._log.fail(f"MQTT connection refused: {msg}")
                return False

        except Exception as e:
            self._log.fail(f"MQTT CONNECT failed: {e}")
            return False

    def validate(self, conn) -> bool:
        """Validate MQTT connection with PINGREQ/PINGRESP.

        Args:
            conn: Connection to validate

        Returns:
            True if connection is alive
        """
        self._log.debug("Sending PINGREQ")
        try:
            conn.send(b"\xc0\x00")  # PINGREQ
            response = conn.recv(2)
            if response == b"\xd0\x00":  # PINGRESP
                self._log.debug("PINGRESP received, connection valid")
                return True
            self._log.warning(f"Invalid PINGRESP: {response.hex()}")
            return False
        except Exception as e:
            self._log.fail(f"PING validation failed: {e}")
            return False

    def get_credentials(self) -> Dict[str, str]:
        """Return credentials for logging."""
        return {
            "client_id": self.client_id,
            "username": self.username or "(none)",
            "password": "***" if self.password else "(none)",
        }

    def _build_connect_packet(self) -> bytes:
        """Build MQTT CONNECT packet.

        Returns:
            Complete CONNECT packet bytes
        """
        # Protocol name
        if self.protocol_version >= 4:
            protocol_name = b"MQTT"
        else:
            protocol_name = b"MQIsdp"

        # Connect flags
        flags = 0x00
        if self.clean_session:
            flags |= 0x02
        if self.username:
            flags |= 0x80
        if self.password:
            flags |= 0x40

        # Build variable header
        variable_header = (
            len(protocol_name).to_bytes(2, "big")
            + protocol_name
            + self.protocol_version.to_bytes(1, "big")
            + flags.to_bytes(1, "big")
            + self.keep_alive.to_bytes(2, "big")
        )

        # Build payload
        client_id_bytes = self.client_id.encode("utf-8")
        payload = len(client_id_bytes).to_bytes(2, "big") + client_id_bytes

        if self.username:
            username_bytes = self.username.encode("utf-8")
            payload += len(username_bytes).to_bytes(2, "big") + username_bytes

        if self.password:
            password_bytes = self.password.encode("utf-8")
            payload += len(password_bytes).to_bytes(2, "big") + password_bytes

        # Calculate remaining length
        remaining_length = len(variable_header) + len(payload)
        remaining_length_encoded = self._encode_remaining_length(remaining_length)

        # Build complete packet
        return b"\x10" + remaining_length_encoded + variable_header + payload

    def _encode_remaining_length(self, value: int) -> bytes:
        """Encode MQTT variable length integer.

        Args:
            value: Integer to encode

        Returns:
            Encoded bytes
        """
        result = b""
        while value > 0:
            byte = value & 0x7F
            value >>= 7
            if value > 0:
                byte |= 0x80
            result += bytes([byte])
        return result if result else b"\x00"

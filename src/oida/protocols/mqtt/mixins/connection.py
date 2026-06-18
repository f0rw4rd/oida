"""
MQTT Connection Mixin

Handles MQTT client creation, TLS certificate checking, MQTT 5.0 properties,
connection attempts, and protocol version enumeration.
"""

import time
from typing import Any, Dict, Tuple

from .. import scanner as _scanner_mod
from ....utils.socket_helpers import build_tls_context, check_tls_certificate

import logging

logger = logging.getLogger(__name__)


class ConnectionMixin:
    """Mixin providing MQTT connection and protocol version operations."""

    def _check_tls_certificate(self, client: Any) -> None:
        """Check TLS certificate for security issues after handshake completes."""
        from ....utils.security_findings import display_cert_info

        cert_der = None
        try:
            sock = client.socket()
            if sock and hasattr(sock, "getpeercert"):
                cert_der = sock.getpeercert(binary_form=True)
        except Exception as e:
            self.logger.debug(f"Could not extract cert from client socket: {e}")

        if cert_der:
            display_cert_info(
                logger=self.logger,
                cert=cert_der,
                protocol="mqtt",
                target=f"{self.host}:{self.port}",
                verbose=self.debug,
            )
        else:
            # Fallback: standalone TLS probe
            check_tls_certificate(
                host=self.host,
                port=self.port,
                logger=self.logger,
                protocol="mqtt",
                timeout=self.timeout,
                verbose=self.debug,
            )

    def _create_mqtt_client(
        self, username: str = "", password: str = "", client_id_suffix: str = ""
    ) -> Any:
        """Create and configure an MQTT client (shared helper)"""
        mqtt = _scanner_mod.paho_client()
        CallbackAPIVersion = _scanner_mod.paho_enums.CallbackAPIVersion

        # Map protocol version to paho constants
        # 3 = MQTTv31, 4 = MQTTv311, 5 = MQTTv5
        protocol_map = {
            3: mqtt.MQTTv31,
            4: mqtt.MQTTv311,
            5: mqtt.MQTTv5,
        }
        protocol = protocol_map.get(self.protocol_version, mqtt.MQTTv311)

        client_id = self.client_id or f"oida-{client_id_suffix}-{int(time.time())}"
        client = mqtt.Client(
            callback_api_version=CallbackAPIVersion.VERSION2,
            client_id=client_id,
            protocol=protocol,
        )

        # Workaround for paho-mqtt 2.x: source_address=('', 0) causes
        # "Address already in use" on systems with many TIME_WAIT sockets.
        # Patch the client's socket creation to skip empty source_address.
        if hasattr(client, "_create_socket_connection"):

            def patched_create_socket_connection():
                import socket as _socket

                proxy = client._get_proxy()
                addr = (client._host, client._port)
                # Skip source_address binding
                if proxy:
                    import socks

                    return socks.create_connection(addr, timeout=client._connect_timeout, **proxy)
                else:
                    return _socket.create_connection(addr, timeout=client._connect_timeout)

            client._create_socket_connection = patched_create_socket_connection

        # Set up authentication
        if username:
            client.username_pw_set(username, password)

        # Set up TLS (accepts any certificate for security testing)
        if self.use_tls:
            context = build_tls_context(self.args, logger=self.logger)
            client.tls_set_context(context)

        return client

    def _has_v5_properties(self, args: Dict[str, Any]) -> bool:
        """Check if any MQTT 5.0 properties are specified."""
        return any(
            [
                args.get("response_topic") or args.get("response-topic"),
                args.get("correlation_id") or args.get("correlation-id"),
                args.get("content_type") or args.get("content-type"),
                args.get("message_expiry") or args.get("message-expiry"),
                args.get("user_prop") or args.get("user-prop"),
            ]
        )

    def _build_publish_properties(self, args: Dict[str, Any]) -> Any:
        """Build MQTT 5.0 properties from args.

        Returns:
            Properties object if MQTT 5.0 properties are specified, None otherwise.
        """
        if not self._has_v5_properties(args):
            return None

        Properties = _scanner_mod.paho_properties.Properties
        PacketTypes = _scanner_mod.paho_packettypes.PacketTypes

        props = Properties(PacketTypes.PUBLISH)

        response_topic = args.get("response_topic") or args.get("response-topic")
        if response_topic:
            props.ResponseTopic = response_topic

        correlation_id = args.get("correlation_id") or args.get("correlation-id")
        if correlation_id:
            props.CorrelationData = correlation_id.encode()

        content_type = args.get("content_type") or args.get("content-type")
        if content_type:
            props.ContentType = content_type
            props.PayloadFormatIndicator = 1  # UTF-8

        message_expiry = args.get("message_expiry") or args.get("message-expiry")
        if message_expiry:
            props.MessageExpiryInterval = int(message_expiry)

        user_prop = args.get("user_prop") or args.get("user-prop")
        if user_prop:
            props.UserProperty = []
            for kv in user_prop:
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    props.UserProperty.append((k, v))

        return props

    def _extract_message_properties(self, msg: Any) -> Dict[str, Any]:
        """Extract MQTT 5.0 properties from a received message.

        Returns:
            Dict with property values (empty values omitted).
        """
        props_dict = {}

        if not hasattr(msg, "properties") or not msg.properties:
            return props_dict

        props = msg.properties

        if hasattr(props, "ResponseTopic") and props.ResponseTopic:
            props_dict["response_topic"] = props.ResponseTopic

        if hasattr(props, "CorrelationData") and props.CorrelationData:
            try:
                props_dict["correlation_id"] = props.CorrelationData.decode()
            except (UnicodeDecodeError, AttributeError):
                props_dict["correlation_id"] = props.CorrelationData.hex()

        if hasattr(props, "ContentType") and props.ContentType:
            props_dict["content_type"] = props.ContentType

        if hasattr(props, "MessageExpiryInterval") and props.MessageExpiryInterval:
            props_dict["message_expiry"] = props.MessageExpiryInterval

        if hasattr(props, "UserProperty") and props.UserProperty:
            props_dict["user_properties"] = list(props.UserProperty)

        return props_dict

    def _format_properties_debug(self, props_dict: Dict[str, Any]) -> str:
        """Format MQTT 5.0 properties for debug output."""
        parts = []
        if props_dict.get("response_topic"):
            parts.append(f"ResponseTopic={props_dict['response_topic']}")
        if props_dict.get("correlation_id"):
            parts.append(f"CorrelationID={props_dict['correlation_id']}")
        if props_dict.get("content_type"):
            parts.append(f"ContentType={props_dict['content_type']}")
        if props_dict.get("message_expiry"):
            parts.append(f"Expiry={props_dict['message_expiry']}s")
        if props_dict.get("user_properties"):
            for k, v in props_dict["user_properties"]:
                parts.append(f"{k}={v}")
        return ", ".join(parts)

    def _attempt_connect(self, client: Any, timeout: float = 1.0) -> Tuple[bool, str]:
        """Attempt connection and return (success, reason) using sync loop"""
        connect_result = {"connected": False, "reason": None}

        def on_connect(cli, userdata, flags, reason_code, properties):
            connect_result["connected"] = reason_code == 0
            connect_result["reason"] = str(reason_code)

        client.on_connect = on_connect

        try:
            t_start = time.time()
            # TCP connect (blocking)
            client.connect(self.host, self.port, keepalive=10)

            # Poll for CONNACK using sync loop() - avoids thread spawn overhead
            start = time.time()
            while time.time() - start < timeout:
                try:
                    client.loop(timeout=0.05)  # 50ms socket timeout per iteration
                except (IndexError, KeyError):
                    # MQTT 5.0 client receiving 3.x CONNACK
                    if self.protocol_version == 5:
                        return False, "Server does not support MQTT 5.0"
                    raise
                if connect_result["connected"] or connect_result["reason"]:
                    break

            elapsed = time.time() - t_start
            self.logger.debug(
                f"attempt_connect total={elapsed:.3f}s result={connect_result['reason']}"
            )

            return connect_result["connected"], connect_result["reason"] or "Unknown"

        except Exception as e:
            return False, str(e)
        finally:
            try:
                client.disconnect()
            except Exception as e:
                logger.debug(f"client.disconnect(): {e}")

    def _attempt_connect_with_properties(
        self, version: int, timeout: float = 2.0
    ) -> Tuple[bool, str, Dict[str, Any], bool]:
        """Attempt connection with specific MQTT version and capture CONNACK properties.

        Args:
            version: MQTT version (3, 4, or 5)
            timeout: Connection timeout in seconds

        Returns:
            Tuple of (success, reason, properties_dict, version_supported)
            - success: True if connection succeeded (authenticated)
            - reason: CONNACK reason string
            - properties_dict: MQTT 5.0 properties if available
            - version_supported: True if version is supported (even if auth failed)
        """
        mqtt = _scanner_mod.paho_client()
        CallbackAPIVersion = _scanner_mod.paho_enums.CallbackAPIVersion

        protocol_map = {
            3: mqtt.MQTTv31,
            4: mqtt.MQTTv311,
            5: mqtt.MQTTv5,
        }
        protocol = protocol_map.get(version, mqtt.MQTTv311)

        client_id = f"oida-version-probe-{version}-{int(time.time())}"
        client = mqtt.Client(
            callback_api_version=CallbackAPIVersion.VERSION2,
            client_id=client_id,
            protocol=protocol,
        )

        connect_result = {
            "connected": False,
            "reason": None,
            "reason_code": None,
            "properties": {},
        }

        def on_connect(cli, userdata, flags, reason_code, properties):
            connect_result["connected"] = reason_code == 0
            connect_result["reason"] = str(reason_code)
            connect_result["reason_code"] = (
                int(reason_code) if hasattr(reason_code, "__int__") else reason_code
            )

            # Capture MQTT 5.0 CONNACK properties (even on auth failure)
            if version == 5 and properties:
                props = connect_result["properties"]
                # Server capabilities
                if hasattr(properties, "MaximumQoS"):
                    props["max_qos"] = properties.MaximumQoS
                if hasattr(properties, "RetainAvailable"):
                    props["retain_available"] = bool(properties.RetainAvailable)
                if hasattr(properties, "WildcardSubscriptionAvailable"):
                    props["wildcard_subscription"] = bool(properties.WildcardSubscriptionAvailable)
                if hasattr(properties, "SubscriptionIdentifierAvailable"):
                    props["subscription_identifier"] = bool(
                        properties.SubscriptionIdentifierAvailable
                    )
                if hasattr(properties, "SharedSubscriptionAvailable"):
                    props["shared_subscription"] = bool(properties.SharedSubscriptionAvailable)
                # Server limits
                if hasattr(properties, "MaximumPacketSize"):
                    props["max_packet_size"] = properties.MaximumPacketSize
                if hasattr(properties, "TopicAliasMaximum"):
                    props["topic_alias_max"] = properties.TopicAliasMaximum
                if hasattr(properties, "ReceiveMaximum"):
                    props["receive_max"] = properties.ReceiveMaximum
                if hasattr(properties, "ServerKeepAlive"):
                    props["server_keepalive"] = properties.ServerKeepAlive
                # Server info
                if hasattr(properties, "AssignedClientIdentifier"):
                    props["assigned_client_id"] = properties.AssignedClientIdentifier
                if hasattr(properties, "ServerReference"):
                    props["server_reference"] = properties.ServerReference
                if hasattr(properties, "ReasonString"):
                    props["reason_string"] = properties.ReasonString
                if hasattr(properties, "ResponseInformation"):
                    props["response_info"] = properties.ResponseInformation
                # Session
                if hasattr(properties, "SessionExpiryInterval"):
                    props["session_expiry"] = properties.SessionExpiryInterval

        client.on_connect = on_connect

        # Don't send auth for version probing - we want to see if version is supported
        # Auth failures still indicate version support

        # Set up TLS if configured
        if self.use_tls:
            context = build_tls_context(self.args, logger=self.logger)
            client.tls_set_context(context)

        try:
            client.connect(self.host, self.port, keepalive=10)

            start = time.time()
            while time.time() - start < timeout:
                try:
                    client.loop(timeout=0.05)
                except KeyError:
                    # MQTT 5.0 client receiving MQTT 3.x response causes KeyError
                    # in paho's ReasonCode parsing. This means the server doesn't
                    # support MQTT 5.0 but does support older versions.
                    if version == 5:
                        return False, "Server sent MQTT 3.x response", {}, False
                    raise
                if connect_result["connected"] or connect_result["reason"]:
                    break

            # Determine if version is supported based on response
            # Auth failures (4, 5, 0x86, 0x87) mean version IS supported
            reason_code = connect_result["reason_code"]
            version_supported = False

            if connect_result["connected"]:
                # Success - version supported
                version_supported = True
            elif reason_code is not None:
                # Got a CONNACK response - check reason code
                # paho-mqtt 2.x uses ReasonCode objects with .value attribute
                # It translates MQTT 3.x codes to 5.0 equivalents (e.g., 5 -> 0x87)
                try:
                    if hasattr(reason_code, "value"):
                        rc = reason_code.value
                    else:
                        rc = int(reason_code)
                except (TypeError, ValueError, AttributeError):
                    rc = -1

                # Protocol NOT supported codes (in MQTT 5.0 terms, as paho translates):
                # 0x81=malformed, 0x82=protocol error, 0x84=unsupported protocol version
                unsupported_codes = {0x81, 0x82, 0x84}
                # If we got a response and it's NOT a protocol rejection, version is supported
                if rc >= 0 and rc not in unsupported_codes:
                    version_supported = True

            return (
                connect_result["connected"],
                connect_result["reason"] or "Unknown",
                connect_result["properties"],
                version_supported,
            )

        except Exception as e:
            # Connection error - can't determine version support
            return False, str(e), {}, False
        finally:
            try:
                client.disconnect()
            except Exception as e:
                logger.debug(f"client.disconnect(): {e}")

    def enumerate_mqtt_versions(self) -> Dict[str, Any]:
        """Enumerate supported MQTT protocol versions and server capabilities.

        Probes the broker with MQTT 3.1, 3.1.1, and 5.0 to determine support.
        This is a PRE-AUTH check - it detects version support even when auth is required.
        For MQTT 5.0, captures CONNACK properties to discover server capabilities.

        Returns:
            Dict with version support info and capabilities
        """
        self.logger.display("Enumerating MQTT protocol versions (pre-auth)...")

        results = {
            "versions_tested": [],
            "versions_supported": [],
            "requires_auth": False,
            "anonymous_allowed": False,
            "mqtt5_capabilities": {},
            "recommended_version": None,
        }

        version_names = {3: "3.1", 4: "3.1.1", 5: "5.0"}
        any_auth_required = False
        any_anonymous = False

        for version in [3, 4, 5]:
            ver_name = version_names[version]
            self.logger.debug(f"Testing MQTT {ver_name}...")

            success, reason, properties, version_supported = self._attempt_connect_with_properties(
                version
            )

            # Determine auth status from reason
            auth_required = False
            if not success and version_supported:
                # Version supported but connection failed = auth required
                auth_required = True
                any_auth_required = True
            elif success:
                any_anonymous = True

            results["versions_tested"].append(
                {
                    "version": version,
                    "name": ver_name,
                    "supported": version_supported,
                    "anonymous": success,
                    "auth_required": auth_required,
                    "reason": reason if not version_supported else None,
                }
            )

            if version_supported:
                results["versions_supported"].append(ver_name)
                status = "anonymous" if success else "auth required"
                self.logger.debug(f"  MQTT {ver_name}: supported ({status})")

                if version == 5 and properties:
                    results["mqtt5_capabilities"] = properties
                    self.logger.debug(f"  MQTT 5.0 capabilities: {properties}")
            else:
                self.logger.debug(f"  MQTT {ver_name}: not supported ({reason})")

        results["requires_auth"] = any_auth_required and not any_anonymous
        results["anonymous_allowed"] = any_anonymous

        # Determine recommended version (prefer 5.0 > 3.1.1 > 3.1)
        if "5.0" in results["versions_supported"]:
            results["recommended_version"] = "5.0"
        elif "3.1.1" in results["versions_supported"]:
            results["recommended_version"] = "3.1.1"
        elif "3.1" in results["versions_supported"]:
            results["recommended_version"] = "3.1"

        # Log results
        if results["versions_supported"]:
            versions_str = ", ".join(results["versions_supported"])
            auth_status = ""
            if any_anonymous:
                auth_status = " (anonymous allowed)"
            elif any_auth_required:
                auth_status = " (auth required)"
            self.logger.display(f"Supported MQTT versions: {versions_str}{auth_status}")

            # Log MQTT 5.0 capabilities
            if results["mqtt5_capabilities"]:
                caps = results["mqtt5_capabilities"]
                cap_strs = []
                if caps.get("max_qos") is not None:
                    cap_strs.append(f"MaxQoS={caps['max_qos']}")
                if caps.get("retain_available") is not None:
                    cap_strs.append(f"Retain={'Yes' if caps['retain_available'] else 'No'}")
                if caps.get("wildcard_subscription") is not None:
                    cap_strs.append(f"Wildcard={'Yes' if caps['wildcard_subscription'] else 'No'}")
                if caps.get("shared_subscription") is not None:
                    cap_strs.append(f"SharedSub={'Yes' if caps['shared_subscription'] else 'No'}")
                if caps.get("max_packet_size"):
                    cap_strs.append(f"MaxPacket={caps['max_packet_size']}")

                if cap_strs:
                    self.logger.display(f"MQTT 5.0 capabilities: {', '.join(cap_strs)}")

                # Security notes
                if caps.get("wildcard_subscription") is False:
                    self.logger.display("  Note: Wildcard subscriptions disabled (good security)")
                if caps.get("retain_available") is False:
                    self.logger.display("  Note: Retain disabled")
        else:
            self.logger.warning("No MQTT versions detected (connection failed)")

        return results

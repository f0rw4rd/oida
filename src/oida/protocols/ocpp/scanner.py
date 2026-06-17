#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OCPP Protocol Scanner for OIDA

Supports:
- OCPP version detection (1.6, 2.0.1, 2.1) via WebSocket subprotocol
- BootNotification / Heartbeat probing
- Action enumeration (supported vs. not implemented)
- Configuration key enumeration (OCPP 1.6)
- Security profile detection and assessment
- TLS certificate validation
- WebSocket Basic Auth testing
"""

import asyncio
import base64
import json
import ssl
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from ...utils import (
    register_protocol,
    create_protocol_module,
    NetworkScanner,
    parse_bool,
)
from ...utils.lazy_import import lazy_import

from .constants import (
    OCPP_SUBPROTOCOLS,
    SUBPROTOCOL_TO_VERSION,
    DEFAULT_WS_PORT,
    DEFAULT_WSS_PORT,
    DEFAULT_CP_ID,
    PROTOCOL_OPTIONS,
    MessageType,
    MAX_INCOMING_CALLS_PER_EXCHANGE,
    DEFAULT_HEARTBEAT_INTERVAL,
)

# Lazy import for websockets dependency
_websockets = lazy_import("websockets", "OCPP", install_hint="pip install websockets>=12.0")

# Backward compatibility flag
dependencies_missing = not _websockets.is_available


@register_protocol(
    name="OCPP Scanner",
    description="Open Charge Point Protocol (OCPP) scanner for EV charging infrastructure",
    default_port=DEFAULT_WS_PORT,
    authors=["f0rw4rd"],
    references=[
        {
            "type": "url",
            "ref": "https://openchargealliance.org/protocols/open-charge-point-protocol/",
        },
        {"type": "url", "ref": "https://en.wikipedia.org/wiki/Open_Charge_Point_Protocol"},
    ],
    protocol_options=PROTOCOL_OPTIONS,
)
class OCPPScanner(NetworkScanner):
    """
    OCPP Protocol Scanner

    Scans OCPP WebSocket endpoints for:
    - Version detection (OCPP 1.6, 2.0.1, 2.1)
    - BootNotification acceptance policy
    - Supported action enumeration
    - Configuration key disclosure
    - Security profile assessment
    - TLS certificate validation

    OCPP uses WebSocket transport (ws:// or wss://) with JSON payloads.
    The scanner acts as a simulated Charge Point connecting to a CSMS.
    """

    def __init__(self, args: Dict[str, Any]):
        # Parse OCPP-specific args before super().__init__
        self.target_url = args.get("target-url", "") or args.get("target", "")
        self.ocpp_version = args.get("version", "auto")
        self.charge_point_id = args.get("charge-point-id", DEFAULT_CP_ID)
        self.username = args.get("username", "") or ""
        self.password = args.get("password", "") or ""
        # TLS inferred from wss:// scheme (no --tls flag)
        self.tls = self.target_url.startswith("wss://")
        self.tls_insecure = parse_bool(args.get("tls-insecure", False))
        self.tls_cert = args.get("tls-cert", "")
        self.tls_key = args.get("tls-key", "")
        self.tls_ca = args.get("tls-ca", "")

        # Parse URL to extract host/port if target_url is a WebSocket URL
        self._parse_target_url(args)

        super().__init__(args)

    def _parse_target_url(self, args: Dict[str, Any]):
        """Parse WebSocket URL and set host/port in args."""
        url = self.target_url
        _log = getattr(self, "logger", None)

        if url and (url.startswith("ws://") or url.startswith("wss://")):
            parsed = urlparse(url)
            scheme = parsed.scheme
            if _log:
                _log.debug(
                    f"Parsed WebSocket URL: host={parsed.hostname}, port={parsed.port}, scheme={scheme}"
                )

            if not args.get("rhost"):
                args["rhost"] = parsed.hostname or "localhost"

            if not args.get("rport"):
                if parsed.port:
                    args["rport"] = parsed.port
                elif scheme == "wss":
                    args["rport"] = DEFAULT_WSS_PORT
                else:
                    args["rport"] = DEFAULT_WS_PORT

            if scheme == "wss":
                self.tls = True
        elif url:
            # Plain hostname/IP - construct a ws:// URL
            if not args.get("rhost"):
                args["rhost"] = url
            port = args.get("rport", DEFAULT_WS_PORT)
            scheme = "wss" if self.tls else "ws"
            self.target_url = f"{scheme}://{url}:{port}/{self.charge_point_id}"
            if _log:
                _log.debug(f"Constructed WebSocket URL from host: {self.target_url}")

    def get_protocol_name(self) -> str:
        return "OCPP"

    def get_default_port(self) -> int:
        return DEFAULT_WSS_PORT if self.tls else DEFAULT_WS_PORT

    def check_dependencies(self) -> bool:
        if not _websockets.is_available:
            self.logger.fail(
                "websockets library required. Install with: pip install websockets>=12.0"
            )
            return False
        return True

    def _build_ws_url(self) -> str:
        """Build the WebSocket URL for connection."""
        if self.target_url and (
            self.target_url.startswith("ws://") or self.target_url.startswith("wss://")
        ):
            return self.target_url

        scheme = "wss" if self.tls else "ws"
        host, port = self.get_target_info()
        return f"{scheme}://{host}:{port}/{self.charge_point_id}"

    def _get_subprotocols(self) -> List[str]:
        """Get WebSocket subprotocols to negotiate based on version preference."""
        if self.ocpp_version == "auto":
            # Try all versions, prefer newest
            protos = ["ocpp2.0.1", "ocpp1.6"]
        elif self.ocpp_version in OCPP_SUBPROTOCOLS:
            protos = [OCPP_SUBPROTOCOLS[self.ocpp_version]]
        else:
            protos = ["ocpp1.6"]
        _log = getattr(self, "logger", None)
        if _log:
            _log.debug(f"Subprotocol negotiation list: {protos} (version={self.ocpp_version})")
        return protos

    def _build_ssl_context(self) -> Optional[ssl.SSLContext]:
        """Build SSL context for wss:// connections."""
        if not self.tls:
            return None

        _log = getattr(self, "logger", None)
        if _log:
            _log.debug(
                f"Building SSL context: insecure={self.tls_insecure}, "
                f"ca={'set' if self.tls_ca else 'default'}, "
                f"client_cert={'set' if self.tls_cert else 'none'}"
            )

        ctx = ssl.create_default_context()

        if self.tls_insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        if self.tls_ca:
            ctx.load_verify_locations(self.tls_ca)

        if self.tls_cert and self.tls_key:
            ctx.load_cert_chain(certfile=self.tls_cert, keyfile=self.tls_key)

        return ctx

    def connect(self) -> Any:
        """
        Establish WebSocket connection to the OCPP endpoint.

        Returns:
            WebSocket connection object or None on failure
        """
        self.check_dependencies()
        _ = _websockets()  # Ensure module is loaded

        ws_url = self._build_ws_url()
        subprotocols = self._get_subprotocols()
        ssl_context = self._build_ssl_context()

        self.logger.debug(f"Connecting to {ws_url} with subprotocols {subprotocols}")

        # Build connection kwargs
        connect_kwargs = {
            "subprotocols": subprotocols,
            "open_timeout": self.timeout,
            "close_timeout": self.timeout,
        }

        if ssl_context:
            connect_kwargs["ssl"] = ssl_context

        # Add HTTP Basic Auth headers if credentials provided
        if self.username:
            credentials = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            connect_kwargs["additional_headers"] = {
                "Authorization": f"Basic {credentials}",
            }

        try:
            # Use the new asyncio API (websockets >= 13.0) which works
            # correctly with asyncio.new_event_loop() in Python 3.13+.
            # The legacy websockets.connect has event loop attachment issues.
            from websockets.asyncio.client import connect as ws_connect

            loop = asyncio.new_event_loop()
            # Suppress noisy "Fatal error: protocol.eof_received() call failed"
            # from websockets 13.x on Python 3.13+ when server rejects upgrade
            _default_handler = loop.get_exception_handler()

            def _quiet_handler(loop, context):
                msg = context.get("message", "")
                if "eof_received" in msg:
                    return  # suppress websockets internal assertion noise
                if _default_handler:
                    _default_handler(loop, context)
                else:
                    loop.default_exception_handler(context)

            loop.set_exception_handler(_quiet_handler)
            try:
                ws = loop.run_until_complete(ws_connect(ws_url, **connect_kwargs))
                self.logger.debug(f"Connected, subprotocol: {getattr(ws, 'subprotocol', 'none')}")
                return ws
            finally:
                # Don't close the loop yet - we need it for send/recv
                self._event_loop = loop

        except Exception as e:
            self.logger.debug(f"WebSocket connection failed: {e}")
            # Store structured error for caller to provide specific messages
            resp = getattr(e, "response", None)
            status_code = getattr(resp, "status_code", None) or getattr(e, "status_code", None)
            err_str = str(e)
            if status_code:
                self._last_connect_error = ("HTTP", status_code)
            elif "Errno 111" in err_str or "Connect call failed" in err_str:
                self._last_connect_error = ("REFUSED",)
            elif "timed out" in err_str.lower() or "timeout" in err_str.lower():
                self._last_connect_error = ("TIMEOUT",)
            elif "Name or service not known" in err_str or "getaddrinfo" in err_str:
                self._last_connect_error = ("DNS",)
            else:
                self._last_connect_error = ("OTHER", err_str)
            return None

    def _connect_with_auth(self, target_url: str, auth_header_value: str) -> Any:
        """
        Attempt a WebSocket connection with a specific Authorization header.

        Used by brute force to test credentials without modifying scanner state.

        Args:
            target_url: WebSocket URL to connect to
            auth_header_value: Base64-encoded credentials for Authorization header

        Returns:
            WebSocket connection object or None on auth failure
        """
        self.logger.debug(f"Auth probe connection to {target_url}")
        self.check_dependencies()
        _ = _websockets()  # Ensure module is loaded

        from websockets.asyncio.client import connect as ws_connect

        subprotocols = self._get_subprotocols()
        ssl_context = self._build_ssl_context()

        connect_kwargs = {
            "subprotocols": subprotocols,
            "open_timeout": min(self.timeout, 5),
            "close_timeout": 2,
            "additional_headers": {
                "Authorization": f"Basic {auth_header_value}",
            },
        }

        if ssl_context:
            connect_kwargs["ssl"] = ssl_context

        loop = asyncio.new_event_loop()
        # Suppress websockets eof_received assertion noise
        loop.set_exception_handler(
            lambda lp, ctx: (
                None
                if "eof_received" in ctx.get("message", "")
                else lp.default_exception_handler(ctx)
            )
        )
        try:

            async def _try_connect():
                try:
                    ws = await ws_connect(target_url, **connect_kwargs)
                    return ws
                except Exception as e:
                    error_str = str(e).lower()
                    if "401" in error_str or "403" in error_str:
                        return None
                    self.logger.debug(f"Auth probe connection error: {e}")
                    return None

            result = loop.run_until_complete(_try_connect())
            if result is not None:
                # Store this loop under the name disconnect() actually reads
                # (_event_loop). The old _brute_loop name had no reader, so the
                # per-probe loop was never closed (resource leak).
                self._event_loop = loop
                return result
            loop.close()
            return None
        except Exception:
            loop.close()
            return None

    def disconnect(self, connection: Any) -> None:
        """Close WebSocket connection."""
        if connection:
            self.logger.debug("Closing WebSocket connection")
            try:
                loop = getattr(self, "_event_loop", None)
                if loop and not loop.is_closed():
                    loop.run_until_complete(connection.close())
                    loop.close()
                    self.logger.debug("WebSocket connection closed cleanly")
            except Exception as e:
                self.logger.debug(f"Error closing WebSocket: {e}")
            finally:
                if hasattr(self, "_event_loop"):
                    try:
                        if not self._event_loop.is_closed():
                            self._event_loop.close()
                    except Exception as e:
                        self.logger.debug(f"Event loop close error: {e}")

    def _send_and_receive(
        self, connection: Any, message: str, timeout: Optional[int] = None
    ) -> Optional[str]:
        """
        Send a message and wait for a response.

        If the server sends unsolicited CALL messages (e.g., Reset,
        GetDiagnostics) before responding with a CALLRESULT/CALLERROR,
        those are handled via _handle_incoming_call and the method
        continues waiting for the actual response.

        Args:
            connection: WebSocket connection
            message: JSON message string to send
            timeout: Response timeout in seconds

        Returns:
            Response message string or None on timeout/error
        """
        if not connection:
            return None

        if timeout is None:
            timeout = self.timeout

        loop = getattr(self, "_event_loop", None)
        if not loop or loop.is_closed():
            self.logger.debug("Send/receive aborted: event loop unavailable")
            return None

        # Extract action name for debug logging
        try:
            _parsed = json.loads(message)
            _action = (
                _parsed[2]
                if isinstance(_parsed, list)
                and len(_parsed) >= 3
                and _parsed[0] == MessageType.CALL
                else "response"
            )
        except Exception:
            _action = "unknown"
        self.logger.debug(f"Sending {_action} ({len(message)} bytes, timeout={timeout}s)")

        async def _exchange():
            await connection.send(message)

            for _ in range(MAX_INCOMING_CALLS_PER_EXCHANGE + 1):
                try:
                    raw = await asyncio.wait_for(connection.recv(), timeout=timeout)
                except asyncio.TimeoutError as e:
                    self.logger.debug(f"OCPP exchange: recv timeout: {e}")
                    return None

                if raw is None:
                    return None

                # Check if this is a server-initiated CALL instead of our response
                try:
                    data = json.loads(raw)
                except (json.JSONDecodeError, TypeError) as e:
                    self.logger.debug(f"OCPP exchange: JSON parse of incoming frame failed: {e}")
                    return raw

                if isinstance(data, list) and len(data) >= 4 and data[0] == MessageType.CALL:
                    # Server sent us a CALL -- handle it and keep waiting
                    action = data[2]
                    payload = data[3]
                    call_msg_id = str(data[1])
                    self.logger.debug(
                        f"Received server-initiated CALL: {action} (while waiting for response)"
                    )
                    response_msg = self._handle_incoming_call(
                        action, payload, call_msg_id, connection
                    )
                    if response_msg:
                        try:
                            await connection.send(response_msg)
                        except Exception as e:
                            self.logger.debug(f"Error sending CALL response: {e}")
                    continue

                # This is a CALLRESULT or CALLERROR -- return it
                _resp_type = (
                    "CALLRESULT"
                    if (isinstance(data, list) and data[0] == MessageType.CALLRESULT)
                    else "CALLERROR"
                )
                self.logger.debug(f"Received {_resp_type} ({len(raw)} bytes)")
                return raw

            # Exhausted retries
            self.logger.debug("Max incoming CALLs exceeded while waiting for response")
            return None

        try:
            return loop.run_until_complete(_exchange())
        except Exception as e:
            self.logger.debug(f"Send/receive error: {e}")
            return None

    def _handle_incoming_call(
        self,
        action: str,
        payload: Dict[str, Any],
        message_id: str,
        connection: Any,
    ) -> Optional[str]:
        """
        Handle an unsolicited CALL message from the server.

        Logs what the server tried to do and builds an appropriate CALLRESULT
        response with safe defaults.

        Args:
            action: OCPP action name from the server
            payload: CALL payload dictionary
            message_id: CALL message ID (for building response)
            connection: WebSocket connection (not used directly but available)

        Returns:
            JSON-encoded CALLRESULT string to send back, or None
        """
        self.logger.debug(f"Server-initiated CALL: {action} (id={message_id})")

        # Build safe CALLRESULT responses for known server-initiated actions
        response_payload = self._get_default_call_response(action)

        result = [MessageType.CALLRESULT, message_id, response_payload]
        return json.dumps(result)

    def _get_default_call_response(self, action: str) -> Dict[str, Any]:
        """
        Get a safe default CALLRESULT payload for a server-initiated action.

        Args:
            action: OCPP action name

        Returns:
            Payload dictionary for the CALLRESULT
        """
        # Map known actions to safe default responses
        defaults = {
            "Reset": {"status": "Accepted"},
            "RemoteStartTransaction": {"status": "Rejected"},
            "RemoteStopTransaction": {"status": "Rejected"},
            "UnlockConnector": {"status": "UnlockFailed"},
            "ChangeAvailability": {"status": "Accepted"},
            "ChangeConfiguration": {"status": "Accepted"},
            "ClearCache": {"status": "Accepted"},
            "GetConfiguration": {
                "configurationKey": [],
                "unknownKey": [],
            },
            "GetDiagnostics": {"fileName": ""},
            "UpdateFirmware": {},
            "SetChargingProfile": {"status": "Accepted"},
            "ClearChargingProfile": {"status": "Accepted"},
            "TriggerMessage": {"status": "Accepted"},
            "GetCompositeSchedule": {"status": "Rejected"},
            "ReserveNow": {"status": "Rejected"},
            "CancelReservation": {"status": "Rejected"},
            "DataTransfer": {"status": "UnknownVendorId"},
            "SendLocalList": {"status": "Accepted"},
            "GetLocalListVersion": {"listVersion": 0},
            # OCPP 2.0.1 additions
            "GetBaseReport": {"status": "Accepted"},
            "SetVariables": {"setVariableResult": []},
            "GetVariables": {"getVariableResult": []},
            "RequestStartTransaction": {"status": "Rejected"},
            "RequestStopTransaction": {"status": "Rejected"},
            "SetNetworkProfile": {"status": "Accepted"},
            "InstallCertificate": {"status": "Accepted"},
            "DeleteCertificate": {"status": "Accepted"},
            "CertificateSigned": {"status": "Accepted"},
            "CustomerInformation": {"status": "Accepted"},
            "SetDisplayMessage": {"status": "Accepted"},
            "ClearDisplayMessage": {"status": "Accepted"},
        }

        return defaults.get(action, {})

    def listen_mode(
        self,
        connection: Any,
        heartbeat_interval: Optional[int] = None,
        timeout: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Persistent listen mode with heartbeat keep-alive.

        Keeps the WebSocket open, sends periodic Heartbeat messages to prevent
        the connection from timing out, and records all server-initiated CALL
        messages. Runs until ``timeout`` seconds elapse (None = indefinite) or
        the connection drops / KeyboardInterrupt.

        Args:
            connection: WebSocket connection
            heartbeat_interval: Seconds between Heartbeats (default: from
                BootNotification response or DEFAULT_HEARTBEAT_INTERVAL)
            timeout: Total listen duration in seconds (None = run forever)

        Returns:
            List of server commands received
        """
        if not connection:
            return []

        loop = getattr(self, "_event_loop", None)
        if not loop or loop.is_closed():
            return []

        if heartbeat_interval is None:
            heartbeat_interval = DEFAULT_HEARTBEAT_INTERVAL

        self.logger.debug(
            f"Persistent listen mode: heartbeat_interval={heartbeat_interval}s, "
            f"timeout={'indefinite' if timeout is None else f'{timeout}s'}"
        )
        commands: List[Dict[str, Any]] = []

        async def _persistent_listen():
            import time as _time
            import uuid

            start = _time.monotonic()
            next_heartbeat = start + heartbeat_interval

            while True:
                # Check total timeout
                if timeout is not None:
                    elapsed = _time.monotonic() - start
                    if elapsed >= timeout:
                        break

                now = _time.monotonic()

                # Send heartbeat to keep alive
                if now >= next_heartbeat:
                    msg_id = str(uuid.uuid4())[:8]
                    hb = json.dumps([2, msg_id, "Heartbeat", {}])
                    try:
                        await connection.send(hb)
                        self.logger.debug("Heartbeat sent (keep-alive)")
                    except Exception as e:
                        self.logger.debug(f"Heartbeat send failed: {e}")
                        break
                    next_heartbeat = _time.monotonic() + heartbeat_interval

                # Wait for incoming message (short poll so we can heartbeat)
                wait = min(2.0, next_heartbeat - _time.monotonic())
                if timeout is not None:
                    remaining = timeout - (_time.monotonic() - start)
                    wait = min(wait, max(remaining, 0))

                try:
                    raw = await asyncio.wait_for(connection.recv(), timeout=max(wait, 0.1))
                except asyncio.TimeoutError as e:
                    self.logger.debug(
                        f"OCPP listen-with-heartbeat: recv timed out (poll continues): {e}"
                    )
                    continue
                except Exception as e:
                    self.logger.debug(f"Listen recv error: {e}")
                    break

                if raw is None:
                    continue

                try:
                    data = json.loads(raw)
                except (json.JSONDecodeError, TypeError) as e:
                    self.logger.debug(
                        f"OCPP listen-with-heartbeat: JSON parse of incoming frame failed: {e}"
                    )
                    continue

                if isinstance(data, list) and len(data) >= 4 and data[0] == MessageType.CALL:
                    action = data[2]
                    payload = data[3]
                    call_msg_id = str(data[1])

                    self.logger.display(f"    [LISTEN] Received: {action}")

                    response_msg = self._handle_incoming_call(
                        action, payload, call_msg_id, connection
                    )
                    if response_msg:
                        try:
                            await connection.send(response_msg)
                        except Exception as e:
                            self.logger.debug(f"Failed to send response: {e}")

                    commands.append(
                        {
                            "action": action,
                            "message_id": call_msg_id,
                            "payload": payload,
                        }
                    )
                elif (
                    isinstance(data, list) and len(data) >= 2 and data[0] == MessageType.CALLRESULT
                ):
                    # Heartbeat response or other CALLRESULT — ignore
                    continue

        try:
            loop.run_until_complete(_persistent_listen())
        except KeyboardInterrupt:
            self.logger.display("    Listen mode interrupted (Ctrl+C)")
        except Exception as e:
            self.logger.debug(f"Listen mode error: {e}")

        return commands

    def _probe_version(self, target_url: str, subprotocol: str) -> Dict[str, Any]:
        """
        Probe whether a specific OCPP version is supported.

        Args:
            target_url: WebSocket URL to connect to
            subprotocol: OCPP subprotocol to test

        Returns:
            Dict with 'supported' (bool) and 'reason' (str)
        """
        self.logger.debug(f"Probing version: {subprotocol} at {target_url}")
        self.check_dependencies()
        _ = _websockets()  # Ensure module is loaded

        from websockets.asyncio.client import connect as ws_connect

        ssl_context = self._build_ssl_context()

        connect_kwargs = {
            "subprotocols": [subprotocol],
            "open_timeout": min(self.timeout, 5),
            "close_timeout": 2,
        }

        if ssl_context:
            connect_kwargs["ssl"] = ssl_context

        if self.username:
            credentials = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            connect_kwargs["additional_headers"] = {
                "Authorization": f"Basic {credentials}",
            }

        loop = asyncio.new_event_loop()
        try:

            async def _probe():
                try:
                    ws = await ws_connect(target_url, **connect_kwargs)
                    negotiated = getattr(ws, "subprotocol", None)
                    await ws.close()
                    if negotiated == subprotocol:
                        return {"supported": True, "reason": "accepted"}
                    else:
                        return {"supported": False, "reason": f"negotiated {negotiated}"}
                except Exception as e:
                    error_str = str(e).lower()
                    if "subprotocol" in error_str:
                        return {"supported": False, "reason": "subprotocol rejected"}
                    elif "401" in error_str or "403" in error_str:
                        # Auth required but version may still be supported
                        return {"supported": True, "reason": "auth required"}
                    else:
                        return {"supported": False, "reason": str(e)}

            return loop.run_until_complete(_probe())
        finally:
            loop.close()

    def _probe_path(self, base_url: str, path: str, charge_point_id: str) -> Dict[str, Any]:
        """
        Probe whether a specific WebSocket path is a valid OCPP endpoint.

        Constructs a URL from the base + path + charge_point_id and attempts
        a WebSocket connection with OCPP subprotocol negotiation.

        Args:
            base_url: Base URL without path (e.g., "ws://host:9000")
            path: Path prefix to test (e.g., "/ocpp")
            charge_point_id: Charge point ID to append

        Returns:
            Dict with 'reachable' (bool), 'subprotocol' (str or None),
            'version' (str or None), 'status_code' (int or None),
            'url' (str), and 'reason' (str)
        """
        self.check_dependencies()
        _ = _websockets()  # Ensure module is loaded

        from websockets.asyncio.client import connect as ws_connect

        # Build the probe URL
        # Normalize: ensure path starts with /, strip trailing /
        if path and not path.startswith("/"):
            path = "/" + path
        path = path.rstrip("/") if path else ""

        # Append charge point ID
        probe_url = f"{base_url}{path}/{charge_point_id}"
        self.logger.debug(f"Probing path: {probe_url}")

        subprotocols = self._get_subprotocols()
        ssl_context = self._build_ssl_context()

        connect_kwargs = {
            "subprotocols": subprotocols,
            "open_timeout": min(self.timeout, 5),
            "close_timeout": 2,
        }

        if ssl_context:
            connect_kwargs["ssl"] = ssl_context

        # Add HTTP Basic Auth if configured
        if self.username:
            credentials = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            connect_kwargs["additional_headers"] = {
                "Authorization": f"Basic {credentials}",
            }

        loop = asyncio.new_event_loop()
        try:

            async def _probe():
                try:
                    ws = await ws_connect(probe_url, **connect_kwargs)
                    negotiated = getattr(ws, "subprotocol", None)
                    version = (
                        SUBPROTOCOL_TO_VERSION.get(negotiated, negotiated) if negotiated else None
                    )
                    await ws.close()
                    return {
                        "reachable": True,
                        "subprotocol": negotiated,
                        "version": version,
                        "status_code": None,
                        "url": probe_url,
                        "reason": "connected",
                    }
                except Exception as e:
                    error_str = str(e).lower()
                    status_code = None
                    # Extract HTTP status code from error message
                    for code in ("401", "403", "404", "400", "500", "502", "503"):
                        if code in error_str:
                            status_code = int(code)
                            break

                    if status_code == 401 or status_code == 403:
                        # Endpoint exists but requires auth
                        return {
                            "reachable": True,
                            "subprotocol": None,
                            "version": None,
                            "status_code": status_code,
                            "url": probe_url,
                            "reason": f"auth required ({status_code})",
                        }
                    elif status_code == 404:
                        return {
                            "reachable": False,
                            "subprotocol": None,
                            "version": None,
                            "status_code": 404,
                            "url": probe_url,
                            "reason": "not found",
                        }
                    elif "subprotocol" in error_str:
                        # Server exists but rejected our subprotocol
                        return {
                            "reachable": True,
                            "subprotocol": None,
                            "version": None,
                            "status_code": status_code,
                            "url": probe_url,
                            "reason": "subprotocol rejected (WebSocket endpoint exists)",
                        }
                    else:
                        return {
                            "reachable": False,
                            "subprotocol": None,
                            "version": None,
                            "status_code": status_code,
                            "url": probe_url,
                            "reason": str(e),
                        }

            return loop.run_until_complete(_probe())
        finally:
            loop.close()

    def discover(self, connection: Any) -> Dict[str, Any]:
        """
        Perform OCPP endpoint discovery.

        Args:
            connection: WebSocket connection object

        Returns:
            Discovery results dictionary
        """
        results = {}

        # Detect version from negotiated subprotocol
        subprotocol = getattr(connection, "subprotocol", None)
        if subprotocol:
            version = SUBPROTOCOL_TO_VERSION.get(subprotocol, subprotocol)
            results["version"] = version
            results["subprotocol"] = subprotocol
            self.logger.debug(f"Discovered OCPP version: {version} (subprotocol={subprotocol})")
        else:
            self.logger.debug("No subprotocol negotiated during handshake")

        return results

    def _get_server_info(self, connection: Any) -> Dict[str, Any]:
        """
        Get basic server information from the OCPP endpoint.

        Args:
            connection: WebSocket connection

        Returns:
            Server info dictionary
        """
        info = {
            "connection_type": "WebSocket",
            "url": self._build_ws_url(),
            "tls": self.tls,
        }

        subprotocol = getattr(connection, "subprotocol", None)
        if subprotocol:
            info["subprotocol"] = subprotocol
            info["version"] = SUBPROTOCOL_TO_VERSION.get(subprotocol, subprotocol)

        # Extract HTTP Server header from handshake response
        resp = getattr(connection, "response", None)
        if resp:
            headers = getattr(resp, "headers", None)
            if headers:
                server = headers.get("Server", "")
                if server:
                    info["http_server"] = server

        return info

    def test_ws_hijacking(
        self,
        target_url: str,
        subprotocols: Optional[List[str]] = None,
        auth_header: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Test WebSocket connection hijacking (SaiFlow-style attack).

        Opens a second WebSocket connection to the same OCPP endpoint while
        the first connection is still active, then checks whether parallel
        connections are accepted or the first connection was displaced.

        Args:
            target_url: WebSocket URL to connect to
            subprotocols: OCPP subprotocol list (default: auto-detect)
            auth_header: Optional Base64-encoded Basic Auth credentials

        Returns:
            Dict with "accepted" (bool), "first_displaced" (bool),
            "parallel" (bool), and "error" (str or None)
        """
        self.logger.debug(f"WS hijacking test: opening second connection to {target_url}")
        self.check_dependencies()
        _ = _websockets()  # Ensure module is loaded

        from websockets.asyncio.client import connect as ws_connect

        if subprotocols is None:
            subprotocols = self._get_subprotocols()

        ssl_context = self._build_ssl_context()

        connect_kwargs = {
            "subprotocols": subprotocols,
            "open_timeout": min(self.timeout, 5),
            "close_timeout": 2,
        }

        if ssl_context:
            connect_kwargs["ssl"] = ssl_context

        if auth_header:
            connect_kwargs["additional_headers"] = {
                "Authorization": f"Basic {auth_header}",
            }
        elif self.username:
            credentials = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            connect_kwargs["additional_headers"] = {
                "Authorization": f"Basic {credentials}",
            }

        result = {
            "accepted": False,
            "first_displaced": False,
            "parallel": False,
            "error": None,
        }

        loop2 = asyncio.new_event_loop()
        # Suppress websockets eof_received assertion noise
        loop2.set_exception_handler(
            lambda lp, ctx: (
                None
                if "eof_received" in ctx.get("message", "")
                else lp.default_exception_handler(ctx)
            )
        )

        try:

            async def _hijack_test():
                # Step 1: Open second WebSocket connection
                try:
                    ws2 = await ws_connect(target_url, **connect_kwargs)
                except Exception as e:
                    error_str = str(e).lower()
                    if "401" in error_str or "403" in error_str:
                        result["error"] = "auth_rejected"
                    else:
                        result["error"] = str(e)
                    return

                result["accepted"] = True
                self.logger.debug("Second WS connection accepted")

                # Step 2: Try sending Heartbeat on second connection to
                # confirm it's fully functional
                try:
                    import uuid as _uuid

                    hb_id = str(_uuid.uuid4())[:8]
                    hb_msg = json.dumps([2, hb_id, "Heartbeat", {}])
                    await ws2.send(hb_msg)
                    resp = await asyncio.wait_for(ws2.recv(), timeout=3)
                    if resp:
                        self.logger.debug("Second connection is fully functional (Heartbeat OK)")
                        result["parallel"] = True
                except asyncio.TimeoutError:
                    self.logger.debug("Second connection: Heartbeat timed out")
                except Exception as e:
                    self.logger.debug(f"Second connection Heartbeat error: {e}")

                # Close the second connection
                try:
                    await ws2.close()
                except Exception as e:
                    self.logger.debug(f"await ws2.close(): {e}")

            loop2.run_until_complete(_hijack_test())

        except Exception as e:
            self.logger.debug(f"WS hijacking test error: {e}")
            result["error"] = str(e)
        finally:
            loop2.close()

        return result


# Create protocol module exports
metadata, run = create_protocol_module(OCPPScanner)

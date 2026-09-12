"""
OCPP Protocol Module

This module provides OCPP (Open Charge Point Protocol) scanning capabilities for
EV charging infrastructure. OCPP is a WebSocket-based protocol used for communication
between Charging Stations (CS/CP) and a Central System / Charging Station Management
System (CSMS).

Supports:
- OCPP version detection (1.6, 2.0.1, 2.1) via WebSocket subprotocol negotiation
- BootNotification probing and acceptance policy detection
- Supported action enumeration
- Configuration key disclosure (OCPP 1.6 GetConfiguration)
- Security profile detection (Profiles 0-3)
- TLS certificate validation
- HTTP Basic Auth testing
- Active security probes (reset, unlock, firmware, charging profile, config write)

Easy CLI examples:
    oida ocpp ws://192.168.1.100:9000/CP_001           # Connect and detect version
    oida ocpp 192.168.1.100                             # Auto-construct ws:// URL
    oida ocpp ws://host:9000/CP_001 -e                  # Enumerate supported actions
    oida ocpp ws://host:9000/CP_001 --security          # Run all security tests
    oida ocpp ws://host:9000/CP_001 -E                  # Probe OCPP versions
"""

from .scanner import (
    OCPPScanner,
    metadata,
    run,
    dependencies_missing,
)

from .constants import (
    MessageType,
    OCPPVersion,
    SecurityProfile,
    SECURITY_PROFILE_NAMES,
    ChargePointStatus,
    RegistrationStatus,
    ErrorCode,
    ERROR_CODE_DESCRIPTIONS,
    OCPP_SUBPROTOCOLS,
    PROTOCOL_OPTIONS as protocol_options,
    ALL_ACTIONS_V16,
    ALL_ACTIONS_V201,
    CONFIGURATION_KEYS_V16,
    DEFAULT_WS_PORT,
    DEFAULT_WSS_PORT,
)

from ...connection import NetworkConnection
from .mixins import DiscoveryMixin, SecurityMixin, MessagesMixin, ChargingMixin


def _payload_status(payload, container_key: str | None = None) -> str:
    """Read a status out of a CALLRESULT payload the peer fully controls.

    ``_parse_message`` returns element 2 of the OCPP-J frame verbatim, so it
    can be any JSON type -- a string, number, list or null, not just the
    object the spec calls for. Reading ``.get()`` off that directly raises
    AttributeError, which escapes the callers' ``except ValueError`` and
    aborts the rest of the host scan. Anything that isn't the expected
    nesting degrades to "Unknown" instead.
    """
    if not isinstance(payload, dict):
        return "Unknown"
    if container_key is not None:
        payload = payload.get(container_key, {})
        if not isinstance(payload, dict):
            return "Unknown"
    status = payload.get("status")
    return "Unknown" if status is None else str(status)


class ocpp(DiscoveryMixin, SecurityMixin, ChargingMixin, MessagesMixin, NetworkConnection):
    """
    NXC-style OCPP scanner (callable)

    Automatically executes scanning workflow on instantiation.

    Usage:
        result = ocpp(args, db, "192.168.1.100")
    """

    # Flags that trigger specific discovery operations
    _DISCOVERY_FLAGS = [
        "enumerate",
        "enum_versions",
        "get_config",
        "data_transfer",
        "firmware_info",
        "meter_values",
        "enum_connectors",
        "local_list_version",
        "composite_schedule",
        "installed_certs",
    ]

    # Flags that trigger security checks (passive analysis)
    _SECURITY_CHECK_FLAGS = [
        "check_auth",
        "check_boot",
        "check_config_keys",
    ]

    # Flags that trigger active security probes (send commands)
    # Ordered: least invasive → most invasive
    _SECURITY_PROBE_FLAGS = [
        "test_config_write",
        "test_charging_profile",
        "test_remote_start",
        "test_remote_stop",
        "test_reset",
        "test_unlock",
        "test_firmware",
        "test_availability",
        "test_clear_cache",
        "test_diagnostics",
        "test_reserve",
        "test_local_list",
        # Extended probes (more invasive / 2.0.1-specific)
        "test_network_profile",
        "test_install_cert",
        "test_display_msg",
        "test_customer_info",
        "test_ssrf_extended",
        "test_ws_hijack",
    ]

    # Flags that trigger charging flow tests
    _CHARGING_FLAGS = [
        "test_authorize",
        "test_charging",
        "test_meter_inject",
    ]

    # Combined list of every flag that triggers an operation; consumed by
    # proto_flow() to decide whether the connection phase can be skipped.
    _OPERATION_FLAGS = (
        _DISCOVERY_FLAGS
        + _SECURITY_CHECK_FLAGS
        + _SECURITY_PROBE_FLAGS
        + _CHARGING_FLAGS
        + [
            "raw_message",
            "auth_id",
            "status",
            "trigger",
            "security",
            "charging",
            "brute",
            "default_creds",
            "ws_brute",
            "listen",
        ]
    )

    @staticmethod
    def _bracket_ipv6(host: str) -> str:
        """Bracket a bare IPv6 literal so "ws://host:port/path" is parseable.

        f"ws://{host}:{port}" with a bare IPv6 host yields
        "ws://2001:db8::1:9000/CP1", which websockets' URI parser rejects
        ("Port could not be cast to integer value"), failing every scan
        against an IPv6 target.
        """
        if ":" in host and not host.startswith("["):
            try:
                import ipaddress

                ipaddress.ip_address(host)
                return f"[{host}]"
            except ValueError:
                return host
        return host

    def __init__(self, args, db, host):
        self.protocol_name = "OCPP"
        self.default_port = DEFAULT_WS_PORT
        self.conn = None
        self.scanner = None

        # Determine the target URL from args
        target = getattr(args, "target", host)
        if target and (target.startswith("ws://") or target.startswith("wss://")):
            self._target_url = target
            if target.startswith("wss://"):
                # Honor an explicit port in the URL (e.g. wss://host:8443/...) so
                # downstream checks like _check_tls_certificate probe the right
                # port; only fall back to 443 when the URL omits the port.
                from urllib.parse import urlparse

                url_port = urlparse(target).port
                if url_port:
                    args.port = url_port
                elif not getattr(args, "port", None) or getattr(args, "port", 9000) == 9000:
                    args.port = DEFAULT_WSS_PORT
        else:
            # Build URL from host/port
            tls = getattr(args, "port", None) == DEFAULT_WSS_PORT
            port = getattr(args, "port", None) or (DEFAULT_WSS_PORT if tls else DEFAULT_WS_PORT)
            args.port = port
            scheme = "wss" if tls else "ws"
            ws_path = getattr(args, "ws_path", None)
            if ws_path:
                path = ws_path if ws_path.startswith("/") else f"/{ws_path}"
            else:
                cp_id = getattr(args, "charge_point_id", "CP_SCANNER_001")
                path = f"/{cp_id}"
            self._target_url = f"{scheme}://{self._bracket_ipv6(host)}:{port}{path}"

        super().__init__(args, db, host)
        self.logger.debug(f"OCPP target URL resolved: {self._target_url}")

    def proto_flow(self):
        """Execute OCPP scanning workflow (modeled after OPC UA _async_proto_flow)."""
        args_dict = self._convert_args_to_dict()
        self.scanner = OCPPScanner(args_dict)

        # Store target URL in results for mixins to access
        self.results["data"]["target_url"] = self._target_url
        self.logger.debug(f"Starting OCPP proto_flow for {self._target_url}")

        # --- Pre-connection phase (no WebSocket needed) ---
        if getattr(self.args, "enum_versions", False):
            self.logger.debug("Pre-connection: version enumeration requested")
            self._handle_version_enumeration()

        if getattr(self.args, "ws_brute", None):
            self.logger.debug("Pre-connection: WebSocket path brute-force requested")
            self.ws_brute_force()
            # ws_brute is a standalone operation; skip connection phase
            # unless other flags also require it
            remaining_flags = [f for f in self._OPERATION_FLAGS if f != "ws_brute"]
            if not any(getattr(self.args, f, None) for f in remaining_flags):
                self.logger.debug("No remaining flags after ws_brute, skipping connection phase")
                return

        # --- Connection phase ---
        self.logger.debug("Entering connection phase")
        self.create_conn_obj()
        if not self.conn:
            self.logger.debug("Connection failed, aborting proto_flow")
            return

        # --- Post-connection: always run basic info ---
        self.logger.debug("Running post-connection discovery (enum_host_info, boot, heartbeat)")
        self.enum_host_info()
        self.print_host_info()
        self._handle_boot_notification()
        self._handle_heartbeat()

        # --- Brute force (early dispatch, like OPC UA pattern) ---
        if self._should_brute_force():
            self.logger.debug("Brute force mode detected, dispatching")
            self._dispatch_brute_force()
            return

        # --- Dispatch flag-based operations ---
        self._dispatch_discovery()
        self._dispatch_security_checks()
        self._dispatch_security_probes()
        self._dispatch_charging_tests()
        self._dispatch_misc_operations()

        # --- Listen mode (runs last, blocks until timeout/Ctrl+C) ---
        if getattr(self.args, "listen", False):
            self.logger.debug("Listen mode requested")
            self._enter_listen_mode()

        # No specific operation flags → the basic info (version, boot,
        # heartbeat) already displayed during connect is the default scan.

    def _dispatch_discovery(self):
        """Dispatch discovery operations based on CLI flags."""
        flag_to_handler = {
            "get_config": self._handle_get_configuration,
            "data_transfer": self._handle_data_transfer_probe,
            "firmware_info": self._handle_firmware_info,
            "enumerate": self._handle_enumerate_actions,
            "meter_values": self.probe_meter_values,
            "enum_connectors": self.enumerate_connectors,
            "local_list_version": self.get_local_list_version,
            "composite_schedule": self.get_composite_schedule,
            "installed_certs": self.get_installed_certs,
        }
        active = [f for f in flag_to_handler if getattr(self.args, f, False)]
        if active:
            self.logger.debug(f"Dispatching {len(active)} discovery operations: {active}")
        for flag, handler in flag_to_handler.items():
            if getattr(self.args, flag, False):
                handler()

    def _dispatch_security_checks(self):
        """Dispatch passive security checks based on CLI flags."""
        run_all = getattr(self.args, "security", False)

        flag_to_handler = {
            "check_auth": self._handle_check_auth,
            "check_boot": self._handle_check_boot,
            "check_config_keys": self._handle_check_config_keys,
        }
        active = [f for f in flag_to_handler if run_all or getattr(self.args, f, False)]
        if active:
            self.logger.debug(
                f"Dispatching {len(active)} security checks (--security={run_all}): {active}"
            )
        for flag, handler in flag_to_handler.items():
            if run_all or getattr(self.args, flag, False):
                handler()

    def _dispatch_security_probes(self):
        """Dispatch active security probes based on CLI flags.

        Requires --confirm since these send real commands to the target.

        Ordered from least invasive to most invasive:
        config write → charging profile → remote start → reset → unlock → firmware
        """
        run_all = getattr(self.args, "security", False)

        flag_to_handler = {
            "test_config_write": self.test_config_write,
            "test_charging_profile": self.test_charging_profile_write,
            "test_remote_start": self.test_remote_transaction_control,
            "test_remote_stop": self.test_remote_stop,
            "test_reset": self.test_reset_command,
            "test_unlock": self.test_unlock_connector,
            "test_firmware": self.test_firmware_update,
            "test_availability": self.test_availability,
            "test_clear_cache": self.test_clear_cache,
            "test_diagnostics": self.test_diagnostics,
            "test_reserve": self.test_reserve,
            "test_local_list": self.test_local_list,
            # Extended probes (more invasive / 2.0.1-specific)
            "test_network_profile": self.test_network_profile,
            "test_install_cert": self.test_install_certificate,
            "test_display_msg": self.test_display_message,
            "test_customer_info": self.test_customer_info,
            "test_ssrf_extended": self.test_ssrf_extended,
            "test_ws_hijack": self.test_ws_hijacking,
        }
        active = [f for f in flag_to_handler if run_all or getattr(self.args, f, False)]
        if not active:
            return

        if not getattr(self.args, "confirm", False):
            self.logger.fail(
                "Security probes require --confirm flag. "
                "These send real commands (Reset, Unlock, etc.) to the target!"
            )
            return

        self.logger.debug(
            f"Dispatching {len(active)} active security probes (--security={run_all}): {active}"
        )
        for flag, handler in flag_to_handler.items():
            if run_all or getattr(self.args, flag, False):
                handler()

    def _dispatch_charging_tests(self):
        """Dispatch charging flow security tests based on CLI flags.

        Requires --confirm since these send real transactions to the target.
        """
        run_all = getattr(self.args, "charging", False)

        flag_to_handler = {
            "test_authorize": self._test_authorize_flow,
            "test_charging": self._test_charging_session,
            "test_meter_inject": self._test_meter_injection,
        }
        active = [f for f in flag_to_handler if run_all or getattr(self.args, f, False)]
        if not active:
            return

        if not getattr(self.args, "confirm", False):
            self.logger.fail(
                "Charging flow tests require --confirm flag. "
                "These send real transactions to the target!"
            )
            return

        self.logger.debug(
            f"Dispatching {len(active)} charging tests (--charging={run_all}): {active}"
        )
        for flag, handler in flag_to_handler.items():
            if run_all or getattr(self.args, flag, False):
                handler()

        # OCPP 2.0.1 TransactionEvent test (auto-run when --charging on 2.0.1)
        version = self.results["data"].get("ocpp_version", "1.6") or "1.6"
        if run_all and version.startswith("2."):
            self.logger.debug(f"Auto-running TransactionEvent test for OCPP {version}")
            self._test_transaction_event()

    def _dispatch_misc_operations(self):
        """Dispatch miscellaneous operations (raw message, auth test, etc.)."""
        if getattr(self.args, "raw_message", None):
            self.logger.debug("Dispatching raw message send")
            self._handle_raw_message()

        if getattr(self.args, "auth_id", None):
            self.logger.debug(
                f"Dispatching authorize test for idTag={getattr(self.args, 'auth_id', '')}"
            )
            self._handle_authorize_test()

        if getattr(self.args, "status", False):
            self.logger.debug("Dispatching StatusNotification")
            self._handle_status_notification()

        if getattr(self.args, "trigger", None):
            self.logger.debug(f"Dispatching TriggerMessage: {getattr(self.args, 'trigger', '')}")
            self._handle_trigger_message()

    def _enter_listen_mode(self):
        """Enter persistent listen mode with heartbeat keep-alive."""
        if not self.conn or not self.scanner:
            self.logger.debug("Listen mode skipped: no connection or scanner")
            return

        timeout = getattr(self.args, "listen_timeout", None)

        # Use heartbeat interval from BootNotification if available
        boot = self.results.get("data", {}).get("boot_notification", {})
        hb_interval = boot.get("interval") or None

        self.logger.debug(
            f"Entering listen mode: timeout={timeout}, heartbeat_interval={hb_interval}"
        )
        duration_str = f"{timeout}s" if timeout else "indefinite (Ctrl+C to stop)"
        self.logger.display(f"    Entering listen mode ({duration_str})")

        commands = self.scanner.listen_mode(
            self.conn,
            heartbeat_interval=hb_interval,
            timeout=timeout,
        )

        if commands:
            self.logger.debug(f"Listen mode ended: {len(commands)} command(s) received")
            self.logger.display(f"    Received {len(commands)} server command(s)")
            self.results["data"]["listen_commands"] = commands
        else:
            self.logger.debug("Listen mode ended: no commands received")
            self.logger.display("    No server commands received")

    def _should_brute_force(self) -> bool:
        """Check if brute force mode is requested."""
        if getattr(self.args, "brute", False):
            self.logger.debug("Brute force triggered by --brute flag")
            return True
        if getattr(self.args, "default_creds", False):
            self.logger.debug("Brute force triggered by --default-creds flag")
            return True
        # Auto-detect file input on -u or -P (like OPC UA pattern)
        from ...utils.default_credentials import parse_credential_input

        username = getattr(self.args, "username", None)
        password = getattr(self.args, "password", None)
        if username:
            _, u_is_file = parse_credential_input(username)
            if u_is_file:
                self.logger.debug("Brute force triggered by username file input")
                return True
        if password:
            _, p_is_file = parse_credential_input(password)
            if p_is_file:
                self.logger.debug("Brute force triggered by password file input")
                return True
        return False

    def _dispatch_brute_force(self):
        """Dispatch brute force credential testing."""
        from ...utils.default_credentials import (
            parse_credential_input,
            get_protocol_defaults,
        )

        username = getattr(self.args, "username", None)
        password = getattr(self.args, "password", None)
        wordlist = getattr(self.args, "wordlist", None)
        self.logger.debug(
            f"Brute force dispatch: username={'set' if username else 'none'}, "
            f"password={'set' if password else 'none'}, wordlist={'set' if wordlist else 'none'}"
        )

        # Parse credential inputs (auto-detect files)
        usernames, _ = parse_credential_input(username) if username else ([], False)
        passwords, _ = parse_credential_input(password) if password else ([], False)

        # Load default credentials if requested
        if getattr(self.args, "default_creds", False):
            defaults = get_protocol_defaults("ocpp")
            if defaults and not usernames and not passwords:
                usernames = list(set(u for u, _ in defaults))
                passwords = list(set(p for _, p in defaults))
            elif defaults:
                # Merge defaults into existing lists
                for u, p in defaults:
                    if u and u not in usernames:
                        usernames.append(u)
                    if p and p not in passwords:
                        passwords.append(p)

        # HTTP Basic Auth brute force (if we have username/password pairs)
        if usernames or passwords:
            if not usernames:
                usernames = [""]
            if not passwords:
                passwords = [""]
            self._brute_force_http_auth(usernames, passwords)

        # IdTag brute force (if wordlist provided or default-creds)
        if wordlist:
            tags, _ = parse_credential_input(wordlist)
            if tags:
                self._brute_force_id_tags(tags)
        elif getattr(self.args, "default_creds", False):
            default_tags = get_protocol_defaults("ocpp_tags")
            if default_tags:
                self._brute_force_id_tags(default_tags)

    def _handle_raw_message(self):
        """Send a raw OCPP-J message from --raw-message flag."""
        raw = getattr(self.args, "raw_message", None)
        if not raw or not self.conn:
            return

        self.logger.debug(f"Parsing raw message ({len(raw)} bytes)")

        # Validate JSON structure
        import json as _json

        try:
            data = _json.loads(raw)
        except _json.JSONDecodeError as e:
            self.logger.debug(f"Raw message JSON parse failed: {e}")
            self.logger.fail(f"[Raw Message] Invalid JSON: {e}")
            return

        if not isinstance(data, list) or len(data) < 3:
            self.logger.fail(
                "[Raw Message] Invalid OCPP-J format: expected JSON array "
                "with at least 3 elements [type, id, action/payload, ...]"
            )
            return

        msg_type = data[0]
        if msg_type not in (2, 3, 4):
            self.logger.fail(
                f"[Raw Message] Invalid message type {msg_type}: "
                "must be 2 (CALL), 3 (CALLRESULT), or 4 (CALLERROR)"
            )
            return

        if msg_type == 2 and len(data) < 4:
            self.logger.fail(
                "[Raw Message] CALL message requires 4 elements: [2, messageId, action, payload]"
            )
            return

        # Re-serialize to ensure clean JSON
        message = _json.dumps(data)

        self.logger.debug(
            f"Sending raw message: type={msg_type}, action={data[2] if msg_type == 2 else 'N/A'}"
        )
        self.logger.display(f"[Raw Message] Sending: {message[:120]}...")
        response = self.scanner._send_and_receive(self.conn, message)
        if response:
            self.logger.display(f"[Raw Message] Response: {response}")
            try:
                parsed = _json.loads(response)
                self.results["data"]["raw_message"] = {
                    "sent": data,
                    "received": parsed,
                }
            except _json.JSONDecodeError:
                self.results["data"]["raw_message"] = {
                    "sent": data,
                    "received_raw": response,
                }
        else:
            self.logger.display("[Raw Message] No response")
            self.results["data"]["raw_message"] = {
                "sent": data,
                "received": None,
            }

    def _handle_authorize_test(self):
        """Test authorization with an ID tag from --auth-id flag."""
        auth_id = getattr(self.args, "auth_id", None)
        if not auth_id or not self.conn:
            return

        version = self.results["data"].get("ocpp_version", "1.6") or "1.6"
        if version.startswith("2."):
            payload = {"idToken": {"idToken": auth_id, "type": "ISO14443"}}
        else:
            payload = {"idTag": auth_id}

        msg = self._build_call("Authorize", payload)
        self.logger.display(f"[Authorize] Testing idTag: {auth_id}")
        response = self.scanner._send_and_receive(self.conn, msg)
        if response:
            try:
                msg_type, _, resp_payload = self._parse_message(response)
            except ValueError as e:
                # Lenient real-world OCPP stacks can emit invalid JSON or a short
                # CALLERROR; degrade here instead of letting ValueError abort the
                # whole scan (skipping later ops such as listen mode).
                self.logger.display(f"[Authorize] Unparseable response: {e}")
                return
            if msg_type == MessageType.CALLRESULT:
                if version.startswith("2."):
                    status = _payload_status(resp_payload, "idTokenInfo")
                else:
                    status = _payload_status(resp_payload, "idTagInfo")
                self.logger.display(f"[Authorize] {auth_id}: {status}")
                self.results["data"]["authorize"] = {"id_tag": auth_id, "status": status}
            elif msg_type == MessageType.CALLERROR:
                # error_code lives on the parsed response, not the request payload.
                self.logger.display(
                    f"[Authorize] Error: {resp_payload.get('error_code', 'Unknown')}"
                )
        else:
            self.logger.display("[Authorize] No response")

    def _handle_status_notification(self):
        """Send StatusNotification from --status flag."""
        if not self.conn:
            return
        connector_id = getattr(self.args, "connector_id", 0)
        msg = self._build_status_notification(connector_id=connector_id)
        self.logger.display(f"[StatusNotification] Connector {connector_id}")
        response = self.scanner._send_and_receive(self.conn, msg)
        if response:
            try:
                msg_type, _, payload = self._parse_message(response)
            except ValueError as e:
                self.logger.display(f"[StatusNotification] Unparseable response: {e}")
                return
            if msg_type == MessageType.CALLRESULT:
                self.logger.display("[StatusNotification] Accepted")
            elif msg_type == MessageType.CALLERROR:
                self.logger.display(
                    f"[StatusNotification] Error: {payload.get('error_code', 'Unknown')}"
                )

    def _handle_trigger_message(self):
        """Send TriggerMessage from --trigger flag."""
        if not self.conn:
            return
        requested = getattr(self.args, "trigger", None)
        if not requested:
            return
        connector_id = getattr(self.args, "connector_id", 0)
        msg = self._build_trigger_message(requested, connector_id=connector_id)
        self.logger.display(f"[TriggerMessage] Requesting: {requested}")
        response = self.scanner._send_and_receive(self.conn, msg)
        if response:
            try:
                msg_type, _, payload = self._parse_message(response)
            except ValueError as e:
                self.logger.display(f"[TriggerMessage] Unparseable response: {e}")
                return
            if msg_type == MessageType.CALLRESULT:
                status = _payload_status(payload)
                self.logger.display(f"[TriggerMessage] {requested}: {status}")
            elif msg_type == MessageType.CALLERROR:
                self.logger.display(
                    f"[TriggerMessage] Error: {payload.get('error_code', 'Unknown')}"
                )

    def create_conn_obj(self):
        """Create WebSocket connection to OCPP endpoint."""
        self.logger.info(f"Connecting to {self._target_url}")
        self.conn = self.scanner.connect()

        # A TLS client certificate (OCPP Security Profile 2/3) IS an identity,
        # even without an HTTP Basic-Auth username -- so don't flag such a
        # cert-authenticated session as "Anonymous access".
        has_client_cert = bool(getattr(self.args, "tls_cert", None))
        if self.conn and not getattr(self.args, "username", None) and not has_client_cert:
            self.logger.success(f"Connected to OCPP endpoint at {self._target_url}")
            self.logger.security_finding(
                "Anonymous access",
                detail="Anonymous connection accepted (no credentials provided)",
            )
        elif self.conn:
            self.logger.success(f"Connected to OCPP endpoint at {self._target_url}")

        # Plaintext transport finding: only on a confirmed connection over plain
        # ws:// (no TLS). wss:// endpoints are encrypted, so skip the finding.
        if self.conn and self._target_url.startswith("ws://"):
            self.logger.security_finding(
                "No encryption",
                detail="OCPP over ws:// -- charge point traffic in cleartext (no TLS)",
            )

        if not self.conn:
            err = getattr(self.scanner, "_last_connect_error", None)
            if isinstance(err, tuple) and err[0] == "HTTP":
                code = err[1]
                if code == 401:
                    self.logger.fail(
                        f"{self._target_url} — HTTP 401 Unauthorized "
                        "(credentials required, use -u / -P)"
                    )
                elif code == 403:
                    self.logger.fail(
                        f"{self._target_url} — HTTP 403 Forbidden (invalid credentials)"
                    )
                else:
                    self.logger.fail(f"{self._target_url} — HTTP {code}")
            elif isinstance(err, tuple) and err[0] == "REFUSED":
                self.logger.fail(f"{self._target_url} — Connection refused")
            elif isinstance(err, tuple) and err[0] == "TIMEOUT":
                self.logger.fail(f"{self._target_url} — Connection timed out")
            elif isinstance(err, tuple) and err[0] == "DNS":
                self.logger.fail(f"{self._target_url} — DNS resolution failed")
            elif isinstance(err, tuple) and err[0] == "OTHER":
                self.logger.fail(f"{self._target_url} — {err[1]}")
            else:
                self.logger.fail(f"Failed to connect to {self._target_url}")

    def enum_host_info(self):
        """Enumerate OCPP endpoint information."""
        if not self.conn:
            return
        self.logger.debug("Enumerating host info from connection")
        server_info = self.scanner._get_server_info(self.conn)
        self.logger.debug(
            f"Server info: version={server_info.get('version', 'unknown')}, tls={server_info.get('tls', False)}"
        )
        self.results["data"]["server_info"] = server_info
        self._handle_version_detection()

    def print_host_info(self):
        """Display discovered OCPP endpoint information."""
        server_info = self.results["data"].get("server_info", {})
        self.logger.success(f"OCPP Endpoint: {self._target_url}")
        self.logger.display("    Connection: WebSocket")
        http_server = server_info.get("http_server")
        if http_server:
            self.logger.display(f"    Server: {http_server}")
        if server_info.get("tls"):
            self.logger.display("    Transport: Encrypted (wss://)")
            self._check_tls_certificate()
        else:
            self.logger.display("    Transport: Plaintext (ws://)")

    def cleanup(self):
        """Cleanup WebSocket connection."""
        if self.conn:
            try:
                self.scanner.disconnect(self.conn)
                self.logger.debug("WebSocket connection closed")
            except Exception as e:
                self.logger.debug(f"Error closing connection: {e}")
            finally:
                self.conn = None

    @staticmethod
    def check_dependencies() -> bool:
        return not dependencies_missing


__all__ = [
    # Scanner exports
    "OCPPScanner",
    "metadata",
    "run",
    "dependencies_missing",
    # NXC-style class
    "ocpp",
    # Constants
    "MessageType",
    "OCPPVersion",
    "SecurityProfile",
    "SECURITY_PROFILE_NAMES",
    "ChargePointStatus",
    "RegistrationStatus",
    "ErrorCode",
    "ERROR_CODE_DESCRIPTIONS",
    "OCPP_SUBPROTOCOLS",
    "protocol_options",
    "ALL_ACTIONS_V16",
    "ALL_ACTIONS_V201",
    "CONFIGURATION_KEYS_V16",
    "DEFAULT_WS_PORT",
    "DEFAULT_WSS_PORT",
]

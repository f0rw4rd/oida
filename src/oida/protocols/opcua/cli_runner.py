#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OPC UA NXC-Style Connection Class

This module provides the NXC-style callable opcua class that auto-executes
on instantiation, following the NetExec pattern.

The class uses mixins to organize functionality into logical groups:
- DiscoveryMixin: Server discovery, endpoints, namespaces
- BrowseMixin: Address space browsing, permissions
- SecurityMixin: Security analysis, certificates, auditing
- MethodsMixin: Method discovery and invocation
- SubscriptionsMixin: Data change and event subscriptions
- WritesMixin: Write operations
- HistoryMixin: Historical data access
- FilesMixin: File transfer operations
- CredentialsMixin: Credential testing, RBAC
- FuzzMixin: Fuzzing capabilities

ARCHITECTURE TODO: This class does NOT delegate to ``OPCUAScanner`` (the L1
class in ``scanner.py``). Both classes implement the protocol independently.
Refactor target: extract the mixin work into protocol-impl methods on
``OPCUAScanner`` (taking an asyncua client param) and reduce this class to
a CLI dispatcher that owns one. Modbus is the reference for the facade
pattern.
"""

import asyncio
import os
from typing import Any, Dict, Optional

from oida.connection import NetworkConnection
from oida.utils.lazy_import import lazy_import
from oida.utils.protocol_helpers import is_auth_rejection

from oida.protocols.opcua.helpers import (
    _asyncua,
    _get_client_class,
    _normalize_opcua_url,
    _parse_opcua_url,
    ua,
)

_asyncua_sec_policies = lazy_import(
    "asyncua.crypto.security_policies", "OPC UA", install_hint="pip install oida-ics[opcua]"
)
_asyncua_validator = lazy_import(
    "asyncua.crypto.validator", "OPC UA", install_hint="pip install oida-ics[opcua]"
)
# Import mixins for modular functionality
from oida.protocols.opcua.mixins import (
    DiscoveryMixin,
    BrowseMixin,
    SecurityMixin,
    MethodsMixin,
    SubscriptionsMixin,
    WritesMixin,
    HistoryMixin,
    FilesMixin,
    CredentialsMixin,
    FuzzMixin,
)


class opcua(
    DiscoveryMixin,
    BrowseMixin,
    SecurityMixin,
    MethodsMixin,
    SubscriptionsMixin,
    WritesMixin,
    HistoryMixin,
    FilesMixin,
    CredentialsMixin,
    FuzzMixin,
    NetworkConnection,
):
    """NXC-style OPC UA scanner (callable)

    Inherits from mixins providing modular functionality groups.
    Methods defined directly in this class override mixin methods.
    """

    def __init__(self, args, db, host):
        self.protocol_name = "OPC UA"
        self.default_port = 4840
        self._client: Any = None
        self._original_url = None

        # Parse OPC UA URL - supports opc.tcp://host:port/path or just host:port.
        # A port in the target URL wins; otherwise honour -p/--port (args.port),
        # falling back to the OPC UA default. Previously this hardcoded 4840, so
        # `-p <port>` on a bare host (e.g. `oida opcua host -p 4841`) was ignored
        # AND then clobbered by `args.port = port` below.
        port_default = getattr(args, "port", None) or self.default_port
        self._original_url = _normalize_opcua_url(host, port_default)
        parsed_host, port, path = _parse_opcua_url(self._original_url)

        # Update args with parsed port. self.logger does not exist yet at this
        # point — it's only created inside super().__init__ via proto_logger() —
        # so we cannot log a debug message here. Catch & ignore silently; if
        # args is a frozen-style Namespace the parent constructor will raise
        # a clearer error.
        try:
            args.port = port
        except AttributeError:
            pass

        super().__init__(args, db, parsed_host)

    # Note: proto_logger() inherited from NetworkConnection base class

    def proto_flow(self):
        """Main OPC UA scanning workflow"""

        # Run async workflow
        asyncio.run(self._async_proto_flow())

    # Asyncua loggers to suppress during discovery/auth
    _ASYNCUA_LOGGERS = [
        "asyncua",
        "asyncua.client",
        "asyncua.client.client",
        "asyncua.client.ua_client",
        "asyncua.common",
        "asyncua.uaprotocol",
        "asyncua.ua",
        "asyncua.crypto",
    ]

    def _suppress_asyncua_logging(self) -> dict:
        """Suppress asyncua logging and return original levels"""
        import logging

        orig_levels = {name: logging.getLogger(name).level for name in self._ASYNCUA_LOGGERS}
        for name in self._ASYNCUA_LOGGERS:
            logging.getLogger(name).setLevel(logging.CRITICAL + 1)
        return orig_levels

    def _restore_asyncua_logging(self, orig_levels: dict):
        """Restore asyncua logging to original levels"""
        import logging

        # Restore the exact captured level. For child loggers this is NOTSET (0),
        # which makes them inherit the parent "asyncua" logger again (set to
        # CRITICAL in cli.py). Coercing 0 -> WARNING here would give each child an
        # explicit WARNING level that overrides the parent, leaking teardown noise
        # such as "close_secure_channel was called but connection is closed".
        for name, level in orig_levels.items():
            logging.getLogger(name).setLevel(level)

    async def _pre_auth_discovery(self, url: str) -> bool:
        """Perform pre-auth endpoint discovery. Returns True if successful."""
        self.logger.debug("Starting pre-auth endpoint discovery...")
        try:
            endpoints = await self._client.connect_and_get_server_endpoints()
            self.logger.debug(f"Discovered {len(endpoints)} endpoints")
            self.logger.success(f"OPC UA Server: {url}")
            await self._show_endpoints_summary(endpoints)
            self.results["data"]["endpoints"] = len(endpoints)
            return True
        except Exception as e:
            self.logger.debug(f"Pre-auth endpoint discovery failed: {e}")
            return False

    async def _configure_secure_channel(
        self, cert_path: str, key_path: str, requested_mode: str, requested_policy: str
    ):
        """Configure secure channel with auto-generated or provided certificates"""
        try:
            sec_policies = _asyncua_sec_policies()
            validator_mod = _asyncua_validator()

            # Map ALL policies the CLI advertises (`--policy` choices in
            # proto_args.py) to their asyncua classes. Previously the map only
            # covered Basic256Sha256 + the two Aes variants, so a user passing
            # `--policy Basic128Rsa15` or `--policy Basic256` silently got
            # Basic256Sha256 instead — masking a deliberate test of the weaker
            # legacy policies. A defensive-security tool must NOT swap the
            # requested policy under the user's feet.
            policy_map = {
                "Basic128Rsa15": sec_policies.SecurityPolicyBasic128Rsa15,
                "Basic256": sec_policies.SecurityPolicyBasic256,
                "Basic256Sha256": sec_policies.SecurityPolicyBasic256Sha256,
                "Aes128_Sha256_RsaOaep": sec_policies.SecurityPolicyAes128Sha256RsaOaep,
                "Aes256_Sha256_RsaPss": sec_policies.SecurityPolicyAes256Sha256RsaPss,
            }
            if requested_policy not in policy_map:
                self.logger.warning(
                    f"Unknown OPC UA security policy {requested_policy!r}; "
                    f"falling back to Basic256Sha256. Pass one of: "
                    f"{', '.join(policy_map.keys())}"
                )
            policy_class = policy_map.get(
                requested_policy, sec_policies.SecurityPolicyBasic256Sha256
            )

            if hasattr(self, "_client_app_uri"):
                self._client.application_uri = self._client_app_uri

            validator = validator_mod.CertificateValidator(
                validator_mod.CertificateValidatorOptions.EXT_VALIDATION
            )
            self._client.certificate_validator = validator

            ua_mod = ua
            if not hasattr(ua_mod.MessageSecurityMode, requested_mode):
                valid_modes = [m for m in dir(ua_mod.MessageSecurityMode) if not m.startswith("_")]
                raise ValueError(
                    f"Unknown OPC UA security mode {requested_mode!r}; "
                    f"expected one of: {', '.join(valid_modes)}"
                )
            await self._client.set_security(
                policy_class,
                certificate=cert_path,
                private_key=key_path,
                mode=getattr(ua_mod.MessageSecurityMode, requested_mode),
            )
        except Exception as e:
            self.logger.debug(f"Failed to configure security: {e}")
            await self._client.set_security_string(
                f"{requested_policy},{requested_mode},{cert_path},{key_path}"
            )

    async def _setup_authentication(
        self,
        usernames: list,
        passwords: list,
        cert_path: Optional[str],
        key_path: Optional[str],
        use_anonymous: bool,
        needs_secure_channel: bool,
        auto_cert_path: Optional[str],
        requested_mode: str,
    ):
        """Setup authentication based on provided credentials.

        Returns the security mode ACTUALLY applied to the channel, which may
        differ from the requested mode (cert auth silently upgrades an unset
        'None' mode to SignAndEncrypt). Callers must record this, not the
        requested mode, so results['security_mode'] doesn't report unencrypted.
        """
        if use_anonymous:
            if needs_secure_channel and auto_cert_path:
                self.logger.display(f"Authenticating: Anonymous ({requested_mode})")
                return requested_mode
            self.logger.display("Authenticating: Anonymous (auto)")
            return "None"
        elif usernames and passwords:
            self._client.set_user(usernames[0])
            self._client.set_password(passwords[0])
            if needs_secure_channel and auto_cert_path:
                self.logger.display(
                    f"Authenticating: {usernames[0]}:{passwords[0]} ({requested_mode})"
                )
                return requested_mode
            self.logger.display(f"Authenticating: {usernames[0]}:{passwords[0]}")
            return "None"
        elif cert_path and key_path:
            # args.mode/args.policy always exist (argparse defaults both to
            # "None" -- see proto_args.py), so the getattr(...) fallbacks
            # here were dead code that could never fire; the *real* default
            # was silently "None,None". A user passing --certificate/
            # --privatekey without an explicit --mode/--policy got a
            # set_security_string("None,None,cert,key") secure channel,
            # which asyncua treats as unsecured and the certificate is
            # never actually presented to the server -- "Authenticating:
            # Certificate" printed even though no cert-based auth occurred.
            # A cert only makes sense over a Sign/SignAndEncrypt channel, so
            # upgrade unset values to a real secure default and say so.
            security_mode = getattr(self.args, "mode", "None") or "None"
            security_policy = getattr(self.args, "policy", "None") or "None"
            if security_mode == "None" or security_policy == "None":
                self.logger.warning(
                    "Certificate auth requires a secure channel; --mode/--policy "
                    "were 'None' -- upgrading to SignAndEncrypt/Basic256Sha256. "
                    "Pass --mode/--policy explicitly to select different values."
                )
                if security_mode == "None":
                    security_mode = "SignAndEncrypt"
                if security_policy == "None":
                    security_policy = "Basic256Sha256"
            await self._client.set_security_string(
                f"{security_policy},{security_mode},{cert_path},{key_path}"
            )
            self.logger.display(
                f"Authenticating: Certificate ({cert_path}, {security_mode}/{security_policy})"
            )
            return security_mode

        return "None"

    def _store_security_info(
        self,
        usernames: list,
        passwords: list,
        cert_path: Optional[str],
        key_path: Optional[str],
        security_mode: str = "None",
    ):
        """Store authentication and security info in results.

        ``security_mode`` is the mode that was actually negotiated for this
        session (passed in by the caller). asyncua's SecurityPolicy objects
        expose ``URI`` but no ``Mode`` attribute, so the mode can only come
        from the requested/applied value, not from introspecting the policy.
        """
        auth_type = "Anonymous"
        if usernames and passwords:
            auth_type = f"Username ({usernames[0]})"
        elif cert_path and key_path:
            auth_type = "Certificate"

        security_policy = "None"
        try:
            policy = getattr(self._client, "security_policy", None)
            if policy is not None and getattr(policy, "URI", None):
                security_policy = policy.URI.split("#")[-1]
        except Exception as e:
            self.logger.debug(f"Failed to get security info: {e}")

        self.results["data"]["auth_type"] = auth_type
        self.results["data"]["security_policy"] = security_policy
        self.results["data"]["security_mode"] = security_mode
        self.logger.display(f"  Policy: {security_policy} | Mode: {security_mode}")

    async def _dispatch_operations(self):
        """Execute operations based on CLI flags"""
        # Direct operation dispatch
        if getattr(self.args, "call_method", None):
            await self._invoke_method(self.args.call_method)

        if getattr(self.args, "subscribe", False):
            await self._subscribe_data_changes()

        if getattr(self.args, "subscribe_events", False):
            await self._subscribe_events()

        if getattr(self.args, "find_servers", False):
            await self._find_servers()

        if getattr(self.args, "find_servers_on_network", False):
            await self._find_servers_on_network()

        if getattr(self.args, "test_subscription_limits", False):
            await self._test_subscription_limits()

        if getattr(self.args, "scan_writable", False):
            await self._test_write_access_scan()

        # Fuzzing operations
        if any([getattr(self.args, f, None) for f in ("fuzz", "fuzz_node", "fuzz_method")]):
            await self._handle_fuzz()

        # --write-value and --history-read both key off --node-id and do
        # their own read of the target node's current value internally, so
        # running the plain _read_node() display first was pure redundant
        # noise (two "Value: X" / "Current: X" lines for the same node).
        # Only run the standalone read when neither other node operation
        # was requested.
        if getattr(self.args, "node_id", None) and not (
            getattr(self.args, "write_value", None) or getattr(self.args, "history_read", False)
        ):
            await self._read_node()

        # Address space dump operations
        await self._handle_dump_operations()

        if getattr(self.args, "get_endpoints", False):
            await self._get_endpoints()

        if getattr(self.args, "write_value", None):
            await self._write_value()

        if getattr(self.args, "history_read", False):
            await self._read_history()

        if getattr(self.args, "read_file", None):
            await self._read_file()

        if getattr(self.args, "write_file", None):
            await self._write_file()

    async def _handle_dump_operations(self):
        """Handle address space dump operations"""
        dump_flags = [
            "dump",
            "dump_all",
            "dump_methods",
            "dump_write",
            "dump_namespaces",
            "dump_history",
            "dump_files",
        ]
        any_dump = any(getattr(self.args, f, False) for f in dump_flags)

        if any_dump:
            await self._dump_namespaces()

        # --dump-namespaces is exclusive: when set it prints only the namespace
        # table (handled above) and does not co-run an address-space dump. This
        # matches its "Only show namespace table" help and keeps the dump modes
        # below genuinely mutually exclusive.
        if getattr(self.args, "dump_namespaces", False):
            return

        # Dump mode dispatch (mutually exclusive)
        dump_mode_map = {
            "dump": ("fast", self._dump_address_space),
            "dump_all": ("full", self._dump_address_space),
            "dump_methods": ("methods", self._dump_address_space),
            "dump_write": ("write", self._dump_address_space),
            "dump_history": (None, self._dump_historizing_nodes),
            "dump_files": (None, self._dump_files),
        }

        for flag, (mode, method) in dump_mode_map.items():
            if getattr(self.args, flag, False):
                if mode is not None:
                    await method(mode=mode)
                else:
                    await method()
                break  # Mutually exclusive

    async def _async_proto_flow(self):
        """Async OPC UA scanning workflow"""
        _orig_levels = {}
        auto_cert_path = None
        auto_key_path = None
        try:
            from oida.utils.default_credentials import parse_credential_input

            self.logger.debug("Starting OPC UA async workflow")
            url = self._original_url
            if url is None:
                self.logger.fail("No target URL configured")
                return
            self.logger.debug(f"Target URL: {url}")

            # Parse credentials
            username_input = getattr(self.args, "username", None)
            password_input = getattr(self.args, "password", None)
            usernames, u_is_file = parse_credential_input(username_input)
            passwords, p_is_file = parse_credential_input(password_input)

            # An explicit empty password (-P '') is a valid credential for a
            # passwordless account. parse_credential_input() collapses '' to
            # [], so restore it as a single empty password here rather than
            # letting it trip the "no password" guard below.
            if password_input is not None and not p_is_file and not passwords:
                passwords = [""]

            # Handle RBAC test mode (early return)
            if getattr(self.args, "test_rbac", False):
                self.logger.debug("Starting RBAC comparison test...")
                await self._test_rbac(url, usernames, passwords)
                self.results["success"] = True
                return

            # Handle brute force mode (early return)
            if u_is_file or p_is_file:
                self.logger.debug(
                    f"Starting credential brute force (users: {len(usernames)}, passwords: {len(passwords)})..."
                )
                await self._brute_force_credentials(usernames, passwords)
                self.results["success"] = True
                return

            # Setup client and suppress logging. asyncua reads `timeout` only
            # from the constructor (no settable descriptor), so it must be
            # passed here — assigning self._client.timeout afterwards was a
            # silent no-op that left the library 4s default in place.
            Client = _get_client_class()
            timeout = getattr(self.args, "timeout", 5)
            self._client = Client(url=url, timeout=timeout)
            _orig_levels = self._suppress_asyncua_logging()

            # Pre-auth endpoint discovery
            pre_auth_ok = await self._pre_auth_discovery(url)

            # Validate credentials
            cert_path = getattr(self.args, "certificate", None)
            key_path = getattr(self.args, "privatekey", None)

            if usernames and not passwords:
                self.logger.fail(
                    f"Username '{usernames[0]}' provided but no password. "
                    "Use -P '' for a passwordless account, or -P <password>."
                )
                self._restore_asyncua_logging(_orig_levels)
                self._client = None
                self.results["success"] = False
                return

            if passwords and not usernames:
                self.logger.fail("Password provided but no username (-u)")
                self._restore_asyncua_logging(_orig_levels)
                self._client = None
                self.results["success"] = False
                return

            has_credentials = (usernames and passwords) or (cert_path and key_path)
            has_anonymous = self.results.get("data", {}).get("has_anonymous", False)
            use_anonymous = not has_credentials and has_anonymous

            # Early return if no credentials and no anonymous
            if not has_credentials and not has_anonymous:
                self._restore_asyncua_logging(_orig_levels)
                self._client = None
                self.results["success"] = pre_auth_ok
                if not pre_auth_ok:
                    self.logger.fail("Could not connect to OPC UA server")
                return

            # Recreate client for auth
            self._client = Client(url=url, timeout=timeout)

            # Setup secure channel if needed
            requested_mode = getattr(self.args, "mode", "None")
            requested_policy = getattr(self.args, "policy", "None")
            needs_secure_channel = requested_mode in ("Sign", "SignAndEncrypt")

            # Honest reporting of mode/policy mismatch: previously the code
            # accepted requested_policy='None' alongside mode=Sign|SignAndEncrypt
            # and the downstream policy_map silently substituted Basic256Sha256.
            # Operators who deliberately asked for 'None' (e.g. probing
            # legacy-config endpoints) got a different policy than they
            # requested. Make the upgrade explicit.
            if needs_secure_channel and requested_policy == "None":
                self.logger.warning(
                    f"--mode {requested_mode} requires a non-None security policy. "
                    "Upgrading to Basic256Sha256 — pass --policy explicitly to "
                    "select a different policy."
                )
                requested_policy = "Basic256Sha256"

            auto_cert_path = None
            auto_key_path = None
            if needs_secure_channel and not (cert_path and key_path):
                auto_cert_path, auto_key_path = await self._generate_client_cert()

            if needs_secure_channel and auto_cert_path and auto_key_path:
                await self._configure_secure_channel(
                    auto_cert_path, auto_key_path, requested_mode, requested_policy
                )

            # Setup authentication. Use the mode ACTUALLY applied (cert auth
            # upgrades an unset 'None' mode to SignAndEncrypt) rather than the
            # requested mode, so the reported security_mode isn't a false 'None'.
            applied_mode = await self._setup_authentication(
                usernames,
                passwords,
                cert_path,
                key_path,
                use_anonymous,
                needs_secure_channel,
                auto_cert_path,
                requested_mode,
            )

            # Connect
            self.logger.debug("Connecting with authentication...")
            await self._client.connect()
            self.conn = self._client
            self.logger.debug("Authentication successful")
            self._restore_asyncua_logging(_orig_levels)
            self.logger.success("Connected")

            # An activated anonymous session is the only proof that anonymous
            # access is real; the endpoint list merely advertises the policy.
            if use_anonymous:
                self.results["data"]["anonymous_verified"] = True
                self.logger.security_finding(
                    "Anonymous access",
                    detail="Anonymous session activated - server grants access without credentials",
                )

            # Store the security mode actually negotiated (applied_mode), which
            # already accounts for the cert-auth 'None' -> SignAndEncrypt upgrade.
            self._store_security_info(
                usernames, passwords, cert_path, key_path, security_mode=applied_mode
            )

            # Post-auth operations
            await self._get_server_info()
            await self._check_server_security()
            await self._check_certificate()

            endpoints = await self._client.get_endpoints()
            self.results["data"]["endpoints"] = len(endpoints)

            # Dispatch flag-based operations
            await self._dispatch_operations()

            # A refused dangerous operation (--call-method, --write-value,
            # --test-subscription-limits ...) already set success=False inside
            # the dispatched handler; setting True here would clobber that
            # refusal into a reported success. Only assert success for the
            # connect+enumerate flow when nothing refused.
            if self.results.get("success") is None:
                self.results["success"] = True

        except TimeoutError as e:
            self.logger.debug(f"async proto flow failed: {e}")
            self.logger.fail("Connection timed out")
            self.results["success"] = False
            self.results["error"] = "Connection timed out"
        except ConnectionRefusedError as e:
            self.logger.debug(f"async proto flow failed: {e}")
            self.logger.fail("Connection refused (port closed or filtered)")
            self.results["success"] = False
            self.results["error"] = "Connection refused"
        except OSError as e:
            self.logger.debug(f"async proto flow failed: {e}")
            error_msg = str(e) if str(e) else f"Network error: {type(e).__name__}"
            self.logger.fail(error_msg)
            self.results["success"] = False
            self.results["error"] = error_msg
        except Exception as e:
            self.logger.debug(f"async proto flow failed: {e}")
            error_msg = str(e) if str(e) else f"{type(e).__name__}"
            # A credential rejection is not a generic failure: say so, and name
            # the identity that was rejected. Otherwise "Error: ...
            # BadUserAccessDenied" reads like a scanner fault rather than
            # "this username/password is wrong".
            if is_auth_rejection(e):
                if usernames and passwords:
                    identity = f"{usernames[0]}:{passwords[0]}"
                elif cert_path:
                    identity = f"certificate {cert_path}"
                else:
                    identity = "anonymous"
                self.logger.fail(f"Authentication failed ({identity}) - {error_msg}")
            else:
                self.logger.fail(f"Error: {error_msg}")
            self.results["success"] = False
            self.results["error"] = error_msg
        finally:
            if self._client:
                try:
                    await self._client.disconnect()
                except Exception as e:
                    self.logger.debug(f"OPC UA disconnect failed: {e}")

            if _orig_levels:
                try:
                    self._restore_asyncua_logging(_orig_levels)
                except Exception as e:
                    self.logger.debug(f"Failed to restore asyncua logging: {e}")

            # Auto-generated client cert/key are only needed to establish
            # the secure channel; remove them from shared temp regardless
            # of how the flow exited so a private key never outlives the
            # scan (see _generate_client_cert).
            for _path in (auto_cert_path, auto_key_path):
                if _path:
                    try:
                        os.unlink(_path)
                    except OSError as e:
                        self.logger.debug(f"Failed to remove temp cert/key {_path}: {e}")

    # All mixin methods (_show_endpoints_summary, _invoke_method, etc.)
    # are inherited from DiscoveryMixin, MethodsMixin, SubscriptionsMixin,
    # WritesMixin, HistoryMixin, FilesMixin, CredentialsMixin, FuzzMixin

    def create_conn_obj(self):
        """Not used -- connection is managed by _async_proto_flow."""

    def enum_host_info(self):
        """Not used -- enumeration is managed by _async_proto_flow."""

    def print_host_info(self):
        """Not used -- display is managed by _async_proto_flow."""

    def cleanup(self):
        """Cleanup OPC UA connection"""
        # Note: Async cleanup is handled in _async_proto_flow's finally block
        # This method handles any remaining sync cleanup if needed
        if self._client:
            try:
                # Run async disconnect in sync context if needed
                import asyncio

                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError as e:
                    self.logger.debug("cleanup failed: %s", e)
                    loop = None

                if loop and loop.is_running():
                    # Already in async context, can't run sync
                    pass
                else:
                    asyncio.run(self._client.disconnect())
                self.logger.debug("OPC UA connection closed")
            except Exception as e:
                self.logger.debug(f"Error closing connection: {e}")
            finally:
                self._client = None  # Prevent duplicate cleanup

    def _convert_args_to_dict(self) -> Dict[str, Any]:
        """Override to handle OPC UA arg name mappings"""
        result = super()._convert_args_to_dict()
        # Map alternate arg names used by scanner
        if hasattr(self.args, "mode"):
            result["security-mode"] = self.args.mode
        if hasattr(self.args, "policy"):
            result["security-policy"] = self.args.policy
        if hasattr(self.args, "certificate"):
            result["certificate-path"] = self.args.certificate
        if hasattr(self.args, "privatekey"):
            result["private-key-path"] = self.args.privatekey
        return result

    @staticmethod
    def check_dependencies() -> bool:
        return _asyncua.is_available

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
See ``docs/ARCHITECTURE.md`` § Refactor targets P0: extract the mixin work
into protocol-impl methods on ``OPCUAScanner`` (taking an asyncua client
param) and reduce this class to a CLI dispatcher that owns one. Modbus is
the reference for the facade pattern.
"""

import asyncio
from typing import Any, Dict

from ...connection import NetworkConnection
from ...utils.lazy_import import lazy_import

from .helpers import (
    _asyncua,
    _get_client_class,
    _normalize_opcua_url,
    _parse_opcua_url,
)

_asyncua_sec_policies = lazy_import(
    "asyncua.crypto.security_policies", "OPC UA", install_hint="pip install asyncua"
)
_asyncua_validator = lazy_import(
    "asyncua.crypto.validator", "OPC UA", install_hint="pip install asyncua"
)
# Import mixins for modular functionality
from .mixins import (
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
        self.protocol_name = "opcua"
        self.default_port = 4840
        self._scan_results = None
        self._client = None
        self._original_url = None

        # Parse OPC UA URL - supports opc.tcp://host:port/path or just host:port
        self._original_url = _normalize_opcua_url(host, self.default_port)
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

    # Flags that trigger specific operations (used for dispatch)
    _OPERATION_FLAGS = [
        "call_method",
        "subscribe",
        "subscribe_events",
        "find_servers",
        "find_servers_on_network",
        "test_subscription_limits",
        "fuzz",
        "fuzz_node",
        "fuzz_method",
        "node_id",
        "dump",
        "dump_all",
        "dump_methods",
        "dump_write",
        "dump_namespaces",
        "dump_history",
        "dump_files",
        "get_endpoints",
        "write_value",
        "history_read",
        "read_file",
        "write_file",
    ]

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

        for name, level in orig_levels.items():
            logging.getLogger(name).setLevel(level if level else logging.WARNING)

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

            policy_map = {
                "Basic256Sha256": sec_policies.SecurityPolicyBasic256Sha256,
                "Aes128_Sha256_RsaOaep": sec_policies.SecurityPolicyAes128Sha256RsaOaep,
                "Aes256_Sha256_RsaPss": sec_policies.SecurityPolicyAes256Sha256RsaPss,
            }
            policy_class = policy_map.get(
                requested_policy, sec_policies.SecurityPolicyBasic256Sha256
            )

            if hasattr(self, "_client_app_uri"):
                self._client.application_uri = self._client_app_uri

            validator = validator_mod.CertificateValidator(
                validator_mod.CertificateValidatorOptions.EXT_VALIDATION
            )
            self._client.certificate_validator = validator

            await self._client.set_security(
                policy_class,
                certificate=cert_path,
                private_key=key_path,
                mode=getattr(
                    __import__("asyncua.ua", fromlist=["MessageSecurityMode"]).MessageSecurityMode,
                    requested_mode,
                ),
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
        cert_path: str,
        key_path: str,
        use_anonymous: bool,
        needs_secure_channel: bool,
        auto_cert_path: str,
        requested_mode: str,
    ):
        """Setup authentication based on provided credentials"""
        if use_anonymous:
            if needs_secure_channel and auto_cert_path:
                self.logger.display(f"Authenticating: Anonymous ({requested_mode})")
            else:
                self.logger.display("Authenticating: Anonymous (auto)")
        elif usernames and passwords:
            self._client.set_user(usernames[0])
            self._client.set_password(passwords[0])
            if needs_secure_channel and auto_cert_path:
                self.logger.display(f"Authenticating: {usernames[0]}:*** ({requested_mode})")
            else:
                self.logger.display(f"Authenticating: {usernames[0]}:***")
        elif cert_path and key_path:
            security_mode = getattr(self.args, "mode", "SignAndEncrypt")
            security_policy = getattr(self.args, "policy", "Basic256Sha256")
            await self._client.set_security_string(
                f"{security_policy},{security_mode},{cert_path},{key_path}"
            )
            self.logger.display(f"Authenticating: Certificate ({cert_path})")

    def _store_security_info(self, usernames: list, passwords: list, cert_path: str, key_path: str):
        """Store authentication and security info in results"""
        auth_type = "Anonymous"
        if usernames and passwords:
            auth_type = f"Username ({usernames[0]})"
        elif cert_path and key_path:
            auth_type = "Certificate"

        security_policy = "None"
        security_mode = "None"
        try:
            if hasattr(self._client, "security_policy") and self._client.security_policy:
                policy = self._client.security_policy
                if hasattr(policy, "URI"):
                    security_policy = policy.URI.split("#")[-1] if policy.URI else "None"
                if hasattr(policy, "Mode"):
                    mode_map = {1: "None", 2: "Sign", 3: "SignAndEncrypt"}
                    security_mode = mode_map.get(policy.Mode, str(policy.Mode))
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

        # Fuzzing operations
        if any([getattr(self.args, f, None) for f in ("fuzz", "fuzz_node", "fuzz_method")]):
            await self._handle_fuzz()

        if getattr(self.args, "node_id", None):
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

        # Dump mode dispatch
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

    def _has_any_operation_flag(self) -> bool:
        """Check if any operation flag is set"""
        return any(getattr(self.args, flag, None) for flag in self._OPERATION_FLAGS)

    async def _async_proto_flow(self):
        """Async OPC UA scanning workflow"""
        _orig_levels = {}
        try:
            from ...utils.default_credentials import parse_credential_input

            self.logger.debug("Starting OPC UA async workflow")
            url = self._original_url
            self.logger.debug(f"Target URL: {url}")

            # Parse credentials
            username_input = getattr(self.args, "username", None)
            password_input = getattr(self.args, "password", None)
            usernames, u_is_file = parse_credential_input(username_input)
            passwords, p_is_file = parse_credential_input(password_input)

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

            # Setup client and suppress logging
            Client = _get_client_class()
            self._client = Client(url=url)
            self._client.timeout = getattr(self.args, "timeout", 5)
            _orig_levels = self._suppress_asyncua_logging()

            # Pre-auth endpoint discovery
            pre_auth_ok = await self._pre_auth_discovery(url)

            # Validate credentials
            cert_path = getattr(self.args, "certificate", None)
            key_path = getattr(self.args, "privatekey", None)

            if usernames and not passwords:
                self.logger.fail(f"Username '{usernames[0]}' provided but no password (-p)")
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
            self._client = Client(url=url)
            self._client.timeout = getattr(self.args, "timeout", 5)

            # Setup secure channel if needed
            requested_mode = getattr(self.args, "mode", "None")
            requested_policy = getattr(self.args, "policy", "None")
            needs_secure_channel = requested_mode in ("Sign", "SignAndEncrypt")

            auto_cert_path = None
            auto_key_path = None
            if needs_secure_channel and not (cert_path and key_path):
                auto_cert_path, auto_key_path = await self._generate_client_cert()

            if needs_secure_channel and auto_cert_path:
                await self._configure_secure_channel(
                    auto_cert_path, auto_key_path, requested_mode, requested_policy
                )

            # Setup authentication
            await self._setup_authentication(
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

            # Store security info
            self._store_security_info(usernames, passwords, cert_path, key_path)

            # Post-auth operations
            await self._get_server_info()
            await self._check_server_security()

            endpoints = await self._client.get_endpoints()
            self.results["data"]["endpoints"] = len(endpoints)

            # Dispatch flag-based operations
            await self._dispatch_operations()

            # Default scan if no specific operations requested
            if not self._has_any_operation_flag():
                await self._default_scan()

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
            self.logger.fail(f"Error: {error_msg}")
            self.results["success"] = False
            self.results["error"] = error_msg
        finally:
            if self._client:
                try:
                    await self._client.disconnect()
                except Exception as e:
                    self.logger.debug(f"async proto flow failed: {e}")

            if _orig_levels:
                try:
                    self._restore_asyncua_logging(_orig_levels)
                except Exception as e:
                    self.logger.debug(f"async proto flow failed: {e}")

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

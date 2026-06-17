#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OPC UA Scanner Class

This module provides the OPCUAScanner class that implements
the BaseScanner interface for OPC UA protocol scanning.
"""

import asyncio
import ipaddress
from typing import Dict, List, Tuple, Any, TYPE_CHECKING

from ...utils import (
    register_protocol,
    create_protocol_module,
    NetworkScanner,
    SecurityAnalyzer,
    ProgressTracker,
    parse_bool,
    safe_int_conversion,
)
from ...utils.protocol_helpers import ConnectionHelper
from ...utils.default_credentials import load_credentials

from .helpers import (
    _asyncua,
    _get_client_class,
    _get_bad_user_access_denied,
    ua,
)

# Type hints only - no runtime import
if TYPE_CHECKING:
    from asyncua.client.client import Client


protocol_options = {
    "username": {
        "type": "string",
        "description": "Username for authentication testing",
        "required": False,
        "default": "",
    },
    "password": {
        "type": "string",
        "description": "Password for authentication testing",
        "required": False,
        "default": "",
    },
    "security-policy": {
        "type": "string",
        "description": "Security policy (none, basic128rsa15, basic256, basic256sha256, etc.)",
        "required": False,
        "default": "none",
    },
    "security-mode": {
        "type": "string",
        "description": "Security mode (none, sign, signandencrypt)",
        "required": False,
        "default": "none",
    },
    "certificate-path": {
        "type": "string",
        "description": "Path to client certificate file",
        "required": False,
        "default": "",
    },
    "private-key-path": {
        "type": "string",
        "description": "Path to private key file",
        "required": False,
        "default": "",
    },
    "max-nodes": {
        "type": "int",
        "description": "Maximum number of nodes to browse",
        "required": False,
        "default": 1000,
    },
    "max-depth": {
        "type": "int",
        "description": "Maximum depth for browsing address space",
        "required": False,
        "default": 10,
    },
    "read-values": {
        "type": "bool",
        "description": "Read values from variable nodes",
        "required": False,
        "default": False,
    },
    "test-write": {
        "type": "bool",
        "description": "Test write access to variables",
        "required": False,
        "default": False,
    },
}


@register_protocol(
    name="OPC UA Scanner",
    description="""OPC UA server scanner for nodes, endpoints, and security configs""",
    default_port=4840,
    authors=["f0rw4rd"],
    references=[
        {"type": "url", "ref": "https://opcfoundation.org"},
        {"type": "url", "ref": "https://github.com/FreeOpcUa/python-opcua"},
    ],
    protocol_options=protocol_options,
)
class OPCUAScanner(NetworkScanner):
    """OPC UA Scanner implementing the base scanner interface"""

    def __init__(self, args: Dict[str, Any]):
        super().__init__(args)
        self.username = args.get("username", "")
        self.password = args.get("password", "")
        self.security_policy = args.get("security-policy", "none")
        self.security_mode = args.get("security-mode", "none")
        self.certificate_path = args.get("certificate-path", "")
        self.private_key_path = args.get("private-key-path", "")
        self.max_nodes = safe_int_conversion(args.get("max-nodes"), 1000)
        self.max_depth = safe_int_conversion(args.get("max-depth"), 10)
        self.read_values = parse_bool(args.get("read-values", False))
        self.test_write = parse_bool(args.get("test-write", False))

        # Internal state
        self.nodes = []
        self.node_values = {}
        self.address_space = {}

    def get_protocol_name(self) -> str:
        return "OPC UA"

    def get_default_port(self) -> int:
        return 4840

    def check_dependencies(self) -> bool:
        return _asyncua.is_available

    def get_target_info(self) -> Tuple[str, int]:
        """Extract target host and port from args, handling OPC UA URLs"""
        host = self.args.get("rhost")

        if not host:
            raise ValueError("Target host (rhost) is required")

        # Handle OPC UA URLs
        if host.startswith("opc.tcp://"):
            # The old quick-and-dirty parser did
            # host.replace("opc.tcp://","").split(":") then int(parts[1]).
            # That crashed with ValueError on:
            #   - opc.tcp://host:4840/path  (parts[1] = '4840/path')
            #   - opc.tcp://[::1]:4840      (extra colons inside IPv6)
            # Delegate to helpers._parse_opcua_url which handles both.
            from .helpers import _parse_opcua_url

            _, port, _ = _parse_opcua_url(host)
            return host, port
        else:
            # Regular host:port handling
            port = int(self.args.get("rport", self.get_default_port()))
            return host, port

    def validate_target(self, host: str, port: int) -> bool:
        """Validate OPC UA target, allowing opc.tcp:// URLs"""
        if host.startswith("opc.tcp://"):
            # Extract actual host from URL for validation
            actual_host = host.replace("opc.tcp://", "").split(":")[0]
            try:
                ipaddress.ip_address(actual_host)
                return True
            except ValueError:
                try:
                    ConnectionHelper.resolve_hostname(actual_host)
                    return True
                except OSError:
                    self.logger.fail(f"Invalid host in URL: {actual_host}")
                    return False
        else:
            # Use parent validation for regular hosts
            return super().validate_target(host, port)

    def connect(self) -> Any:
        """Establish OPC UA connection"""
        # Build URL
        host, port = self.get_target_info()
        if host.startswith("opc.tcp://"):
            url = host
        else:
            url = f"opc.tcp://{host}:{port}"

        self.logger.debug(f"Connecting to OPC UA server: {url}")

        # Get Client class (lazy import)
        Client = _get_client_class()

        # Create client
        client = Client(url=url, timeout=self.timeout)

        # Set security settings if specified
        if self.security_policy != "none":
            self._configure_security(client)

        return client

    def disconnect(self, connection: Any) -> None:
        """Close OPC UA connection"""
        if connection:
            try:
                asyncio.run(connection.disconnect())
            except Exception as e:
                self.logger.debug(f"Error disconnecting: {e}")

    def discover(self, connection: Any) -> Dict[str, Any]:
        """Perform OPC UA discovery and scanning"""
        self.logger.debug("Starting OPC UA discovery workflow")
        self.logger.debug(
            f"Options: scan_mode={self.scan_mode}, security_policy={self.security_policy}, "
            f"max_depth={self.max_depth}"
        )

        results = {
            "server_info": {},
            "endpoints": [],
            "security_analysis": {},
            "address_space": {},
            "authentication_test": {},
        }

        try:
            # Run async discovery
            self.logger.debug("Starting async discovery...")
            async_results = asyncio.run(self._async_discover(connection))
            results.update(async_results)

            # Security analysis
            self.logger.debug("Performing security analysis...")
            results["security_analysis"] = self._analyze_security(results)

            # Report findings
            self._report_findings(results)

        except Exception as e:
            self.logger.fail(f"Error during OPC UA discovery: {e}")
            results["error"] = str(e)

        self.logger.debug("OPC UA discovery workflow complete")
        return results

    async def _async_discover(self, client: "Client") -> Dict[str, Any]:
        """Async discovery implementation"""
        results = {}

        try:
            # Connect
            self.logger.debug("Connecting to OPC UA server...")
            await client.connect()
            self.logger.debug("Connected successfully")

            # Get server info
            self.logger.debug("Getting server information...")
            results["server_info"] = await self._get_server_info(client)

            # Discover endpoints
            self.logger.debug("Discovering endpoints...")
            results["endpoints"] = await self._discover_endpoints(client)

            if self.scan_mode in ["discovery", "all"]:
                # Test authentication methods
                self.logger.debug("Testing authentication methods...")
                results["authentication_test"] = await self._test_authentication(client)

            if self.scan_mode in ["browse", "all"]:
                # Browse address space
                self.logger.debug(f"Browsing address space (max_depth={self.max_depth})...")
                results["address_space"] = await self._browse_address_space(client)

        except Exception as e:
            self.logger.fail(f"Error in async discovery: {e}")
            results["error"] = str(e)
        finally:
            try:
                self.logger.debug("Disconnecting from server...")
                await client.disconnect()
            except Exception as exc:
                self.logger.debug(f"Error during disconnect: {exc}")

        return results

    async def _get_server_info(self, client: "Client") -> Dict[str, Any]:
        """Get basic server information"""
        try:
            # Get server node
            server_node = client.get_server_node()

            # Basic server info
            info = {
                "server_uri": await server_node.get_child("ServerUri").read_value(),
                "product_uri": await server_node.get_child("ProductUri").read_value(),
                "manufacturer_name": await server_node.get_child("ManufacturerName").read_value(),
                "product_name": await server_node.get_child("ProductName").read_value(),
                "software_version": await server_node.get_child("SoftwareVersion").read_value(),
                "build_number": await server_node.get_child("BuildNumber").read_value(),
            }

            self.logger.display(f"OPC UA Server: {info.get('product_name', 'Unknown')}")
            self.logger.display(f"Manufacturer: {info.get('manufacturer_name', 'Unknown')}")
            self.logger.display(f"Version: {info.get('software_version', 'Unknown')}")

            return info

        except Exception as e:
            self.logger.debug(f"Error getting server info: {e}")
            return {}

    async def _discover_endpoints(self, client: "Client") -> List[Dict[str, Any]]:
        """Discover available endpoints"""
        try:
            endpoints = await client.connect_and_get_server_endpoints()
            endpoint_list = []

            self.logger.display(f"Discovered {len(endpoints)} endpoints")

            for endpoint in endpoints:
                endpoint_info = {
                    "endpoint_url": endpoint.EndpointUrl,
                    "security_policy": endpoint.SecurityPolicyUri,
                    "security_mode": endpoint.SecurityMode.name,
                    "transport_profile": endpoint.TransportProfileUri,
                    "security_level": endpoint.SecurityLevel,
                }

                endpoint_list.append(endpoint_info)
                self.logger.debug(
                    f"Endpoint: {endpoint_info['endpoint_url']} "
                    f"(Policy: {endpoint_info['security_policy']}, "
                    f"Mode: {endpoint_info['security_mode']})"
                )

            return endpoint_list

        except Exception as e:
            self.logger.fail(f"Error discovering endpoints: {e}")
            return []

    async def _test_authentication(self, client: "Client") -> Dict[str, Any]:
        """Test authentication methods"""
        _get_bad_user_access_denied()

        results = {
            "anonymous_access": False,
            "username_password": {},
            "tested_credentials": [],
        }

        try:
            # Test anonymous access by actually establishing a credential-less
            # session and exercising the Read service. asyncua's set_user()
            # only configures the NEXT request and takes a single str arg, so
            # the old `set_user(None)` raised TypeError and was swallowed — the
            # anonymous check never ran. A fresh Client with no user/password
            # and a real connect()+Read is the only honest probe.
            client_class = _get_client_class()
            host, port = self.get_target_info()
            url = host if host.startswith("opc.tcp://") else f"opc.tcp://{host}:{port}"
            anon_client = client_class(url=url, timeout=self.timeout)
            try:
                await anon_client.connect()
                try:
                    # Read service requires an (anonymous) session to succeed.
                    await anon_client.get_root_node().read_browse_name()
                    results["anonymous_access"] = True
                    self.logger.display("Anonymous access: ALLOWED")
                finally:
                    try:
                        await anon_client.disconnect()
                    except Exception as e:
                        self.logger.debug(f"anon probe disconnect: {e}")
            except Exception as e:
                self.logger.display("Anonymous access: DENIED")
                self.logger.debug(f"anonymous probe -> {type(e).__name__}: {e}")

            # Load credentials from args (auto-detects files)
            credentials = load_credentials(
                username=self.username,
                password=self.password,
                defaults=None,  # OPC UA has no built-in defaults
            )

            if credentials:
                await self._test_credentials_list(client, credentials, results)

        except Exception as e:
            self.logger.fail(f"Error testing authentication: {e}")

        return results

    async def _test_credentials_list(
        self, client: "Client", credentials: list, results: Dict[str, Any]
    ) -> None:
        """Test list of credential pairs"""
        BadUserAccessDenied = _get_bad_user_access_denied()
        progress = ProgressTracker(len(credentials), logger=self.logger)

        self.logger.display(f"Testing {len(credentials)} credential combinations")

        valid_count = 0
        # asyncua.Client.set_user() is a sync setter that only configures
        # the credentials for the NEXT outgoing request — it does NOT
        # validate them. Marking the credential "VALID" just because
        # set_user didn't raise produces false positives on every
        # invocation. To actually verify a credential we have to either
        # call client.connect() (heavy: full session re-establishment)
        # or send a probe request (lightweight). We use the probe via
        # client.get_root_node().read_browse_name() which exercises
        # authentication via Read service.
        client_class = _get_client_class()
        host, port = self.get_target_info()
        url = host if host.startswith("opc.tcp://") else f"opc.tcp://{host}:{port}"
        timeout = self.timeout

        for username, password in credentials:
            probe_client = client_class(url=url, timeout=timeout)
            try:
                # asyncua's set_user() takes only the username; the password
                # is configured via the separate set_password() setter.
                probe_client.set_user(username)
                probe_client.set_password(password)
                await probe_client.connect()
                try:
                    # Read service requires an authenticated session.
                    await probe_client.get_root_node().read_browse_name()
                    results["username_password"][username] = "valid"
                    results["tested_credentials"].append(f"{username}:{password}")
                    self.logger.display(f"VALID: {username}:{password}")
                    valid_count += 1
                finally:
                    try:
                        await probe_client.disconnect()
                    except Exception as e:
                        self.logger.debug(f"probe disconnect: {e}")
            except BadUserAccessDenied:
                results["username_password"][username] = "invalid"
                self.logger.debug(f"Tested {username}:{password} -> BadUserAccessDenied")
            except Exception as e:
                # Connection failures, certificate errors etc. - record
                # as inconclusive (NOT valid) so we don't falsely report.
                results["username_password"][username] = "error"
                self.logger.debug(f"Tested {username}:{password} -> {type(e).__name__}: {e}")

            progress.update()

        if valid_count == 0:
            self.logger.display("Credentials: No valid credentials found")

    async def _browse_address_space(self, client: "Client") -> Dict[str, Any]:
        """Browse the OPC UA address space"""
        try:
            self.logger.display("Browsing address space...")

            # Start from root
            root = client.get_root_node()

            # Initialize tracking
            self.nodes = []
            self.node_values = {}
            self.address_space = {"nodes": [], "values": {}}

            # Create progress tracker
            progress = ProgressTracker(self.max_nodes, logger=self.logger)

            # Recursively explore
            await self._explore_node(
                root,
                self.max_nodes,
                self.max_depth,
                0,
                progress,
                self.read_values,
                self.test_write,
            )

            # Compile results
            self.address_space["nodes"] = self.nodes
            self.address_space["values"] = self.node_values

            self.logger.display(f"Discovered {len(self.nodes)} nodes in address space")

            if self.read_values:
                variables_count = sum(
                    1 for node in self.nodes if node.get("node_class") == "Variable"
                )
                self.logger.display(
                    f"Read values for {len(self.node_values)} of {variables_count} variables"
                )

            # Report writable nodes if write testing was enabled
            if self.test_write:
                writable_nodes = [n for n in self.nodes if n.get("writable")]
                self.address_space["writable_nodes"] = writable_nodes
                if writable_nodes:
                    self.logger.display(f"Found {len(writable_nodes)} writable variable nodes")
                    for wn in writable_nodes[:5]:  # Show first 5
                        self.logger.display(f"  [W] {wn['node_id']} - {wn['display_name']}")
                    if len(writable_nodes) > 5:
                        self.logger.display(f"  ... and {len(writable_nodes) - 5} more")

            return self.address_space

        except Exception as e:
            self.logger.fail(f"Error exploring address space: {e}")
            return {}

    async def _test_write_access(self, node) -> Dict[str, Any]:
        """
        Test write access to a variable node.

        Prefers the UserAccessLevel attribute bitmask (no write performed). If
        the node does not expose AccessLevel (BadAttributeIdInvalid), falls back
        to a read/write-back round trip to probe writability.

        Args:
            node: OPC UA node to test

        Returns:
            Dict with writable (bool) and error (str or None)
        """
        result = {"writable": False, "error": None}
        try:
            # Check UserAccessLevel attribute (respects current user permissions)
            access = await node.read_attribute(ua.AttributeIds.UserAccessLevel)
            level = access.Value.Value

            # Check write bit (bit 1 = 0x02). _explore_node consumes only
            # "writable"/"error", so we don't compute the other AccessLevel
            # bits here (the full bitmask breakdown lives in the
            # --scan-writable path).
            result["writable"] = (level & 0x02) != 0

        except Exception as e:
            error_str = str(e).lower()
            if "badattributeidinvalid" in error_str:
                # Node doesn't support AccessLevel, fall back to write test
                try:
                    original = await node.read_value()
                    await node.write_value(original)
                    result["writable"] = True
                except Exception as write_e:
                    result["writable"] = False
                    if "notwritable" in str(write_e).lower():
                        pass
                    else:
                        result["error"] = str(write_e)
            else:
                result["error"] = str(e)

        return result

    async def _explore_node(
        self,
        node,
        max_nodes: int,
        max_depth: int,
        current_depth: int,
        tracker: ProgressTracker,
        read_values: bool,
        test_write: bool = False,
        visited: set = None,
    ) -> None:
        """Recursively explore a node and its children"""
        if visited is None:
            visited = set()

        # Check limits
        if max_depth > 0 and current_depth >= max_depth:
            return

        if max_nodes > 0 and len(self.nodes) >= max_nodes:
            return

        try:
            # Get node information
            node_id = node.nodeid.to_string()

            if node_id in visited:
                return
            visited.add(node_id)
            browse_name = await node.read_browse_name()
            display_name = await node.read_display_name()
            node_class = await node.read_node_class()

            # Create node info
            node_info = {
                "node_id": node_id,
                "browse_name": f"{browse_name.NamespaceIndex}:{browse_name.Name}",
                "display_name": display_name.Text,
                "node_class": node_class.name,
                "depth": current_depth,
            }

            # Read value if it's a variable and requested
            if read_values and node_class.name == "Variable":
                try:
                    value = await node.read_value()
                    data_type = await node.read_data_type_as_variant_type()
                    node_info["data_type"] = data_type.name
                    self.node_values[node_id] = str(value)
                except Exception as e:
                    self.logger.debug(f"Could not read value for {node_id}: {e}")

            # Test write access if requested (for Variable nodes only)
            if test_write and node_class.name == "Variable":
                write_result = await self._test_write_access(node)
                node_info["writable"] = write_result["writable"]
                if write_result.get("error"):
                    self.logger.debug(f"Write test error for {node_id}: {write_result['error']}")

            self.nodes.append(node_info)
            tracker.update()

            # Get children
            try:
                children = await node.get_children()
                for child in children:
                    if len(self.nodes) < max_nodes:
                        await self._explore_node(
                            child,
                            max_nodes,
                            max_depth,
                            current_depth + 1,
                            tracker,
                            read_values,
                            test_write,
                            visited,
                        )
            except Exception as e:
                self.logger.debug(f"Could not get children for {node_id}: {e}")

        except Exception as e:
            self.logger.debug(f"Error exploring node: {e}")

    def _configure_security(self, client: "Client") -> None:
        """Configure security settings for the client"""
        try:
            if self.certificate_path and self.private_key_path:
                security_string = (
                    f"{self.security_policy},{self.security_mode},"
                    f"{self.certificate_path},{self.private_key_path}"
                )
                client.set_security_string(security_string)
                self.logger.debug(
                    f"Configured security: {self.security_policy}, {self.security_mode}"
                )
        except Exception as e:
            self.logger.debug(f"Error configuring security: {e}")

    def _analyze_security(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze security configuration"""
        analysis = SecurityAnalyzer.assess_protocol_security(
            {
                "authentication": not results.get("authentication_test", {}).get(
                    "anonymous_access", True
                ),
                "authorization": len(results.get("endpoints", [])) > 1,
                "encryption": any(
                    ep.get("security_mode") != "None" for ep in results.get("endpoints", [])
                ),
                "integrity_check": any(
                    "Sign" in ep.get("security_mode", "") for ep in results.get("endpoints", [])
                ),
                "access_control": not results.get("authentication_test", {}).get(
                    "anonymous_access", True
                ),
            }
        )

        return analysis

    def _report_findings(self, results: Dict[str, Any]) -> None:
        """Report scanner findings"""
        host, port = self.get_target_info()

        # Report host and service
        self.report_host_info(host)
        self.report_service_info(host, port=port, name="opcua", proto="tcp")

        # Report security findings
        auth_test = results.get("authentication_test", {})
        if auth_test.get("anonymous_access"):
            self.report_vulnerability(
                host,
                "opcua_anonymous_access",
                description="OPC UA server allows anonymous access",
                severity="high",
            )
            # Centralized security finding
            self.logger.security_finding("Anonymous access allowed")

        # Check encryption support
        endpoints = results.get("endpoints", [])
        has_encryption = any(ep.get("security_mode") not in ["None", None] for ep in endpoints)
        if not has_encryption:
            self.logger.security_finding("No encryption", detail="No secure endpoints available")

        # Report valid credentials
        for username, status in auth_test.get("username_password", {}).items():
            if status == "valid":
                self.report_credential(username, self.password, host=host, port=port)

        # Report writable nodes as security finding
        address_space = results.get("address_space", {})
        writable_nodes = address_space.get("writable_nodes", [])
        if writable_nodes:
            self.report_vulnerability(
                host,
                "opcua_writable_nodes",
                description=f"Found {len(writable_nodes)} writable variable nodes - "
                "unauthorized writes could impact process control",
                severity="medium",
            )
            # Centralized security finding
            self.logger.security_finding(
                "Writable access", detail=f"{len(writable_nodes)} writable nodes"
            )


# Create metadata and run function using protocol module factory
metadata, run = create_protocol_module(
    OPCUAScanner, dependencies_check_func=lambda: not _asyncua.is_available
)


if __name__ == "__main__":
    # CLI entry point
    import sys
    from ...utils.cli import main

    main(sys.argv, run, metadata)

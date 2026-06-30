"""
OPC UA Discovery Mixin

Provides server discovery, endpoint enumeration, and namespace browsing functionality.
"""


class DiscoveryMixin:
    """Mixin providing OPC UA discovery functionality."""

    async def _find_servers(self):
        """Discover OPC UA servers via FindServers"""
        self.logger.display("Finding servers...")

        try:
            servers = await self._client.find_servers()

            for server in servers:
                name = server.ApplicationName.Text if server.ApplicationName else "Unknown"
                uri = server.ApplicationUri or ""
                self.logger.display(f"Server: {name}")
                self.logger.display(f"  URI: {uri}")
                for url in server.DiscoveryUrls or []:
                    self.logger.display(f"  Endpoint: {url}")

            self.results["data"]["discovered_servers"] = len(servers)

        except Exception as e:
            self.logger.debug(f"[OPCUA] find servers failed: {e}")
            self.logger.fail(f"FindServers failed: {e}")

    async def _find_servers_on_network(self):
        """Discover OPC UA servers via GDS/LDS FindServersOnNetwork"""
        from ..helpers import _get_client_class

        gds_url = getattr(self.args, "gds_url", None)

        self.logger.display("Finding servers on network (GDS/LDS)...")

        try:
            Client = _get_client_class()
            if gds_url:
                # Connect to specific GDS endpoint. asyncua reads `timeout` only
                # from the constructor (no settable descriptor), so assigning
                # gds_client.timeout afterwards was a silent no-op.
                gds_client = Client(gds_url, timeout=getattr(self.args, "timeout", 5))
                await gds_client.connect()
                servers = await gds_client.find_servers_on_network()
                await gds_client.disconnect()
            else:
                # Use current client's discovery service
                servers = await self._client.find_servers_on_network()

            for server in servers:
                name = server.ServerName if hasattr(server, "ServerName") else "Unknown"
                discovery_url = server.DiscoveryUrl if hasattr(server, "DiscoveryUrl") else ""
                capabilities = (
                    server.ServerCapabilities if hasattr(server, "ServerCapabilities") else []
                )

                self.logger.display(f"Network Server: {name}")
                self.logger.display(f"  Discovery URL: {discovery_url}")
                if capabilities:
                    self.logger.display(f"  Capabilities: {', '.join(capabilities)}")

            self.results["data"]["servers_on_network"] = len(servers)

        except Exception as e:
            self.logger.debug("find servers on network failed: %s", e)
            self.logger.fail(f"FindServersOnNetwork failed: {e}")
            self.logger.display("Note: GDS/LDS discovery requires a discovery server")

    async def _get_server_info(self):
        """Read and display server build/version info for fingerprinting."""
        try:
            # Read BuildInfo node (ns=0;i=2260)
            build_info_node = self._client.get_node("ns=0;i=2260")
            build_info = await build_info_node.read_value()

            if build_info:
                product = getattr(build_info, "ProductName", "") or ""
                manufacturer = getattr(build_info, "ManufacturerName", "") or ""
                version = getattr(build_info, "SoftwareVersion", "") or ""
                build_num = getattr(build_info, "BuildNumber", "") or ""
                product_uri = getattr(build_info, "ProductUri", "") or ""
                build_date = getattr(build_info, "BuildDate", None)

                # Format build date if available
                build_date_str = ""
                if build_date and hasattr(build_date, "year") and build_date.year > 1601:
                    build_date_str = build_date.strftime("%Y-%m-%d")

                # Display header and fields
                self.logger.display("Server:")
                if product:
                    self.logger.display(f"  Product: {product}")
                if manufacturer:
                    self.logger.display(f"  Vendor: {manufacturer}")
                if version or build_num:
                    ver_str = version or ""
                    if build_num and build_num != version:
                        ver_str += f" (build: {build_num})" if ver_str else build_num
                    self.logger.display(f"  Version: {ver_str}")
                if build_date_str:
                    self.logger.display(f"  Build Date: {build_date_str}")
                if product_uri:
                    self.logger.display(f"  URI: {product_uri}")

                # Store in results
                self.results["data"]["server_info"] = {
                    "product": product,
                    "manufacturer": manufacturer,
                    "version": version,
                    "build": build_num,
                    "build_date": build_date_str,
                    "uri": product_uri,
                }
        except Exception as e:
            self.logger.debug(f"Could not read server info: {e}")

    async def _get_endpoints(self):
        """Get and display all server endpoints with security info"""
        self.logger.display("Getting server endpoints...")

        try:
            endpoints = await self._client.get_endpoints()

            if not endpoints:
                self.logger.display("Endpoints: None available")
                self.results["data"]["endpoints_detail"] = []
                return

            self.logger.display(f"Found {len(endpoints)} endpoints:")

            endpoint_list = []
            for ep in endpoints:
                url = ep.EndpointUrl
                policy = ep.SecurityPolicyUri.split("#")[-1] if ep.SecurityPolicyUri else "None"
                mode = (
                    ep.SecurityMode.name
                    if hasattr(ep.SecurityMode, "name")
                    else str(ep.SecurityMode)
                )
                level = ep.SecurityLevel

                self.logger.display(f"  {url}")
                self.logger.display(f"    Policy: {policy}, Mode: {mode}, Level: {level}")

                endpoint_list.append(
                    {
                        "url": url,
                        "policy": policy,
                        "mode": mode,
                        "level": level,
                    }
                )

            self.results["data"]["endpoints_detail"] = endpoint_list

        except Exception as e:
            self.logger.debug("get endpoints failed: %s", e)
            self.logger.fail(f"Failed to get endpoints: {e}")

    async def _dump_namespaces(self):
        """Dump server namespace table."""
        from oida.utils.export_utils import export_data

        try:
            # Read NamespaceArray (i=2255)
            ns_node = self._client.get_node("i=2255")
            ns_array = await ns_node.read_value()

            if not ns_array:
                self.logger.display("No namespaces found")
                return

            self.results["data"]["namespaces"] = list(ns_array)

            # Build table
            headers = ["NS", "URI"]
            data = [[i, uri] for i, uri in enumerate(ns_array)]

            output_format = getattr(self.args, "format", "console") or "console"
            output_dir = getattr(self.args, "output", None)
            export_data(
                data,
                headers,
                output_format=output_format,
                output_dir=output_dir,
                filename_prefix=f"opcua_namespaces_{self.host}",
                title=f"Namespaces ({len(ns_array)})",
                logger=self.logger,
            )

        except Exception as e:
            self.logger.debug(f"Failed to read namespaces: {e}")

    async def _show_endpoints_summary(self, endpoints):
        """Display endpoint summary (pre-auth, no connection required)"""
        # Group endpoints by mode and collect auth types
        modes = {}  # mode -> set of policies
        all_auth_types = set()
        has_anon_endpoint = False
        has_mode_none = False  # No signing/encryption on messages
        has_mode_invalid = False  # MessageSecurityMode.Invalid advertised (spec violation)
        has_policy_none = False  # No security policy defined
        has_sign_only = False  # Sign but no encrypt
        deprecated_policies = set()
        server_cert = None

        for ep in endpoints:
            mode = (
                ep.SecurityMode.name if hasattr(ep.SecurityMode, "name") else str(ep.SecurityMode)
            )
            policy_uri = ep.SecurityPolicyUri or ""
            policy = policy_uri.split("#")[-1] if policy_uri else "None"

            if mode not in modes:
                modes[mode] = set()
            modes[mode].add(policy)

            # Collect auth types
            if hasattr(ep, "UserIdentityTokens") and ep.UserIdentityTokens:
                for token in ep.UserIdentityTokens:
                    if hasattr(token, "TokenType"):
                        ttype = (
                            token.TokenType.name
                            if hasattr(token.TokenType, "name")
                            else str(token.TokenType)
                        )
                        all_auth_types.add(ttype)
                        if ttype == "Anonymous":
                            has_anon_endpoint = True

            # Track specific security issues
            if mode == "Invalid":
                has_mode_invalid = True
            if mode in ("None", "None_"):
                has_mode_none = True
            if policy == "None":
                has_policy_none = True
            if mode == "Sign" and policy != "None":
                has_sign_only = True

            # Check for deprecated policies
            if "Basic128Rsa15" in policy_uri:
                deprecated_policies.add("Basic128Rsa15")
            if "Basic256" in policy_uri and "Sha256" not in policy_uri:
                deprecated_policies.add("Basic256")

            # Get server certificate
            if not server_cert and hasattr(ep, "ServerCertificate") and ep.ServerCertificate:
                server_cert = ep.ServerCertificate

        # Display endpoint info
        auth_str = ",".join(sorted(all_auth_types)) if all_auth_types else "?"
        self.logger.display(f"Endpoints: {len(endpoints)} [{auth_str}]")
        for mode in ["Invalid", "None_", "Sign", "SignAndEncrypt"]:
            if mode in modes:
                policies = ", ".join(sorted(modes[mode]))
                self.logger.display(f"  {mode}: {policies}")

        # Show certificate info using central function
        if server_cert:
            try:
                from oida.utils.security_findings import display_cert_info

                display_cert_info(
                    self.logger,
                    server_cert,
                    protocol="opcua",
                    results=self.results.get("data"),
                )
            except Exception as e:
                self.logger.debug("show endpoints summary failed: %s", e)

        # Collect security issues
        issues = []
        if has_anon_endpoint:
            issues.append("Anonymous authentication allowed")
        if has_mode_invalid:
            issues.append(
                "SecurityMode Invalid: endpoint advertises an invalid/unspecified "
                "message security mode (OPC UA spec violation)"
            )
        if has_mode_none:
            issues.append("SecurityMode None: traffic is unencrypted and unsigned")
        if has_policy_none:
            issues.append("SecurityPolicy None: no cryptographic protection")
        if has_sign_only:
            issues.append(
                "Sign-only mode: traffic signed but not encrypted (passive MitM possible)"
            )
        if deprecated_policies:
            for policy in sorted(deprecated_policies):
                if policy == "Basic128Rsa15":
                    issues.append(f"Weak cipher {policy}: 128-bit key, vulnerable to decryption")
                elif policy == "Basic256":
                    issues.append(
                        f"Weak cipher {policy}: SHA-1 signatures, collision attacks possible"
                    )

        if issues:
            for issue in issues:
                self.logger.warning(issue)

        # Store in results
        self.results["data"]["auth_types"] = list(all_auth_types)
        self.results["data"]["has_mode_invalid"] = has_mode_invalid
        self.results["data"]["has_mode_none"] = has_mode_none
        self.results["data"]["has_policy_none"] = has_policy_none
        self.results["data"]["has_sign_only"] = has_sign_only
        self.results["data"]["has_anonymous"] = has_anon_endpoint
        self.results["data"]["has_nosecurity"] = has_mode_none or has_policy_none
        self.results["data"]["deprecated_policies"] = list(deprecated_policies)

        # Test if server accepts untrusted client certificates (only with --test-cert-trust)
        # This is a security vulnerability - servers should validate client certs
        if getattr(self.args, "test_cert_trust", False):
            has_secure_endpoints = any(
                ep_mode in ("Sign", "SignAndEncrypt")
                for ep_mode in [
                    ep.SecurityMode.name
                    if hasattr(ep.SecurityMode, "name")
                    else str(ep.SecurityMode)
                    for ep in endpoints
                    if hasattr(ep, "SecurityMode")
                ]
            )
            if has_secure_endpoints:
                url = (
                    self._original_url
                    or f"opc.tcp://{self.host}:{getattr(self.args, 'port', 4840)}"
                )
                cert_result = await self._test_self_signed_cert_acceptance(url)
                self.results["data"]["untrusted_cert_test"] = cert_result
            else:
                self.logger.display("No secure endpoints (Sign/SignAndEncrypt) to test cert trust")

            # Self-signed USER certificate acceptance (distinct from the app/
            # secure-channel cert above): does the server accept an untrusted
            # self-signed X509 user identity token? Only meaningful when an
            # endpoint advertises a Certificate user token.
            user_cert_result = await self._test_self_signed_user_cert_acceptance(endpoints)
            self.results["data"]["untrusted_user_cert_test"] = user_cert_result

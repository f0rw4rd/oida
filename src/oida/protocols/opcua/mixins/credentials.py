"""
OPC UA Credentials Mixin

Provides credential testing, RBAC analysis, and brute force functionality.
"""

import asyncio

from oida.utils.common_types import Category

from ..helpers import _get_client_class, ua


class CredentialsMixin:
    """Mixin providing OPC UA credential testing operations."""

    async def _brute_force_credentials(self, usernames: list, passwords: list):
        """Test credentials against the server (auto-triggered when -u or -p is a file)"""

        # Build URL
        if self._original_url:
            url = self._original_url
        else:
            port = getattr(self.args, "port", self.default_port)
            url = f"opc.tcp://{self.host}:{port}"

        delay = getattr(self.args, "brute_rate", 0.5)

        # Check for user:pass format in usernames (when -p not provided)
        combo_pairs = []
        clean_usernames = []

        if not passwords:
            # Check if usernames contain user:pass format
            for val in usernames:
                if ":" in val:
                    u, p = val.split(":", 1)
                    combo_pairs.append((u, p))
                else:
                    clean_usernames.append(val)
            usernames = clean_usernames

        # Build credential pairs
        if combo_pairs:
            credentials = combo_pairs
            self.logger.display(f"Testing {len(credentials)} credential pairs...")
        elif usernames and passwords:
            credentials = [(u, p) for u in usernames for p in passwords]
            self.logger.display(
                f"Testing {len(credentials)} pairs ({len(usernames)} users x {len(passwords)} passwords)..."
            )
        else:
            self.logger.fail("No credentials to test")
            return

        valid_creds = []
        tested = 0

        Client = _get_client_class()
        for username, password in credentials:
            tested += 1
            try:
                timeout = getattr(self.args, "timeout", 5)
                test_client = Client(url=url, timeout=timeout)
                test_client.set_user(username)
                test_client.set_password(password)

                await test_client.connect()
                await test_client.disconnect()

                # Success
                self.logger.security_finding(
                    "Default credentials",
                    category=Category.AUTHENTICATION,
                    detail=f"Valid OPC UA credentials: {username}:{password}",
                )
                valid_creds.append({"username": username, "password": password})

                # Stop on first valid credential (default behavior)
                if not getattr(self.args, "continue_on_success", False):
                    break

            except Exception as e:
                err_str = str(e).lower()
                if "badidentitytoken" in err_str or "badusername" in err_str or "denied" in err_str:
                    self.logger.debug(f"Tested {username}:{password} -> BadIdentityToken")
                else:
                    self.logger.debug(f"Tested {username}:{password} -> {e}")

            if delay > 0:
                await asyncio.sleep(delay)

        self.logger.display(f"Tested {tested} credentials, found {len(valid_creds)} valid")
        self.results["data"]["brute_force"] = {
            "tested": tested,
            "valid": valid_creds,
        }

    async def _test_rbac(self, url: str, usernames: list, passwords: list):
        """
        Test RBAC by comparing access across different auth methods.

        Tests: Anonymous, each user credential, certificate (if provided)
        Compares: read access, write access, method calls
        """
        self.logger.display("Testing RBAC (Role-Based Access Control)...")

        # Get certificate paths if provided
        cert_path = getattr(self.args, "certificate", None)
        key_path = getattr(self.args, "privatekey", None)

        # Build list of auth methods to test
        auth_methods = []

        # 1. Anonymous
        auth_methods.append(
            {
                "name": "Anonymous",
                "type": "anonymous",
                "user": None,
                "password": None,
            }
        )

        # 2. Username/password credentials
        if usernames and passwords:
            # Single user:pass pair
            auth_methods.append(
                {
                    "name": f"User:{usernames[0]}",
                    "type": "username",
                    "user": usernames[0],
                    "password": passwords[0],
                }
            )
        elif usernames:
            # Users might be in user:pass format
            for u in usernames:
                if ":" in u:
                    user, pwd = u.split(":", 1)
                    auth_methods.append(
                        {
                            "name": f"User:{user}",
                            "type": "username",
                            "user": user,
                            "password": pwd,
                        }
                    )

        # 3. Certificate auth
        if cert_path and key_path:
            auth_methods.append(
                {
                    "name": f"Cert:{cert_path}",
                    "type": "certificate",
                    "cert": cert_path,
                    "key": key_path,
                }
            )

        if len(auth_methods) < 2:
            self.logger.warning(
                "RBAC test needs multiple auth methods. Provide -u file or --certificate"
            )
            return

        self.logger.display(f"Testing {len(auth_methods)} auth methods...")

        # Define test operations
        test_results = {}

        for auth in auth_methods:
            auth_name = auth["name"]
            self.logger.display(f"\n--- Testing: {auth_name} ---")

            access = {
                "connected": False,
                "readable_nodes": [],
                "writable_nodes": [],
                "callable_methods": [],
                "errors": [],
            }

            try:
                # Create client with appropriate auth
                Client = _get_client_class()
                timeout = getattr(self.args, "timeout", 5)
                client = Client(url=url, timeout=timeout)

                if auth["type"] == "username":
                    client.set_user(auth["user"])
                    client.set_password(auth["password"])
                elif auth["type"] == "certificate":
                    await client.set_security_string(
                        f"Basic256Sha256,SignAndEncrypt,{auth['cert']},{auth['key']}"
                    )

                # Try to connect
                await client.connect()
                access["connected"] = True
                self.logger.success(f"{auth_name}: Connected")

                # Get some test nodes
                objects = client.get_objects_node()
                children = await objects.get_children()

                # Test read access on first 10 nodes
                test_nodes = children[:10]
                for node in test_nodes:
                    try:
                        await node.read_value()
                        node_id = str(node.nodeid)
                        access["readable_nodes"].append(node_id)
                    except Exception as e:
                        self.logger.debug("test rbac failed: %s", e)
                        pass

                self.logger.display(f"  Readable nodes: {len(access['readable_nodes'])}")

                # Test write access - find variable nodes and try safe write.
                # The write-back issues a real Write service call against a
                # live variable — gate it on --confirm like every other write
                # path. Without --confirm, skip the write column gracefully.
                if not getattr(self.args, "confirm", False):
                    self.logger.display(
                        "  Writable nodes: skipped (write-back probe writes to "
                        "live variables) — requires --confirm"
                    )
                else:
                    for node in test_nodes:
                        try:
                            node_class = await node.read_node_class()
                            if node_class == ua.NodeClass.Variable:
                                # Try to read current value
                                current = await node.read_value()
                                # Try to write same value back (safe)
                                await node.write_value(current)
                                access["writable_nodes"].append(str(node.nodeid))
                        except Exception as e:
                            self.logger.debug("test rbac failed: %s", e)
                            pass

                    self.logger.display(f"  Writable nodes: {len(access['writable_nodes'])}")

                # Test method access - find and try to call methods
                try:
                    server_node = client.get_node(ua.ObjectIds.Server)
                    methods = await server_node.get_methods()
                    for method in methods[:5]:
                        try:
                            # Just check if we can get method info (not actually call)
                            browse_name = await method.read_browse_name()
                            access["callable_methods"].append(str(browse_name))
                        except Exception as e:
                            self.logger.debug("test rbac failed: %s", e)
                            pass
                except Exception as e:
                    self.logger.debug("test rbac failed: %s", e)
                    pass

                self.logger.display(f"  Accessible methods: {len(access['callable_methods'])}")

                # Collect detailed per-node permissions if --rbac-detailed
                if getattr(self.args, "rbac_detailed", False):
                    access["perms"] = await self._collect_role_permissions(client)
                    self.logger.display(f"  Collected permissions for {len(access['perms'])} nodes")

                await client.disconnect()

            except Exception as e:
                self.logger.debug("test rbac failed: %s", e)
                access["errors"].append(str(e))
                err_short = str(e)[:50]
                self.logger.fail(f"{auth_name}: {err_short}")

            test_results[auth_name] = access

        # Compare results
        self.logger.display("\n=== RBAC Analysis ===")

        connected_methods = [k for k, v in test_results.items() if v["connected"]]
        self.logger.display(f"Connected auth methods: {len(connected_methods)}/{len(auth_methods)}")

        if len(connected_methods) >= 2:
            # Compare access levels
            read_counts = {
                k: len(v["readable_nodes"]) for k, v in test_results.items() if v["connected"]
            }
            write_counts = {
                k: len(v["writable_nodes"]) for k, v in test_results.items() if v["connected"]
            }

            # Check if all have same access
            read_values = list(read_counts.values())
            write_values = list(write_counts.values())

            all_same_read = len(set(read_values)) == 1
            all_same_write = len(set(write_values)) == 1

            if all_same_read and all_same_write:
                self.logger.security_finding(
                    "No authentication",
                    category=Category.AUTHENTICATION,
                    detail="NO RBAC DETECTED - All auth methods have same access (may indicate missing access control)",
                )
            else:
                self.logger.success("[+] RBAC appears to be configured:")
                for name, count in read_counts.items():
                    w_count = write_counts.get(name, 0)
                    self.logger.display(f"    {name}: read={count}, write={w_count}")

        # Check if anonymous has same access as authenticated
        if "Anonymous" in test_results and test_results["Anonymous"]["connected"]:
            anon_read = len(test_results["Anonymous"]["readable_nodes"])
            for name, access in test_results.items():
                if name != "Anonymous" and access["connected"]:
                    user_read = len(access["readable_nodes"])
                    if anon_read >= user_read:
                        self.logger.security_finding(
                            "Anonymous access",
                            category=Category.AUTHENTICATION,
                            detail=f"Anonymous has same/more access than {name}",
                        )

        # Export RBAC results
        from ....utils.export_utils import export_data

        output_dir = getattr(self.args, "output", None)
        fmt = getattr(self.args, "format", "console") if output_dir else "console"

        # Summary table
        summary_data = []
        for name, access in test_results.items():
            summary_data.append(
                [
                    name,
                    "Y" if access["connected"] else "-",
                    str(len(access["readable_nodes"])),
                    str(len(access["writable_nodes"])),
                    str(len(access["callable_methods"])),
                ]
            )
        export_data(
            summary_data,
            ["Role", "Connected", "Read", "Write", "Methods"],
            fmt,
            output_dir,
            "opcua_rbac_summary",
            "RBAC Summary",
            logger=self.logger,
        )

        # Detailed matrix if --rbac-detailed
        if getattr(self.args, "rbac_detailed", False):
            all_nodes = set()
            for access in test_results.values():
                all_nodes.update(access.get("perms", {}).keys())

            roles = [k for k, v in test_results.items() if v["connected"]]
            matrix_headers = ["NodeId", "Name", "Type"]
            for r in roles:
                matrix_headers.extend([f"{r[:6]}_R", f"{r[:6]}_W"])

            matrix_data = []
            for nid in sorted(all_nodes):
                name = type_ = "-"
                for access in test_results.values():
                    if nid in access.get("perms", {}):
                        name = access["perms"][nid].get("name", "-")
                        type_ = access["perms"][nid].get("type", "-")
                        break
                row = [nid, name, type_]
                for role in roles:
                    p = test_results[role].get("perms", {}).get(nid, {})
                    row.append("Y" if p.get("r") else "-")
                    row.append("Y" if p.get("w") or p.get("x") else "-")
                matrix_data.append(row)

            export_data(
                matrix_data,
                matrix_headers,
                fmt,
                output_dir,
                "opcua_rbac_matrix",
                "RBAC Permission Matrix",
                logger=self.logger,
            )

        self.results["data"]["rbac_test"] = test_results

    async def _collect_role_permissions(self, client, max_depth: int = 5) -> dict:
        """Collect per-node permissions for authenticated client.

        Args:
            client: Connected OPC UA client
            max_depth: Maximum browse depth

        Returns:
            Dict mapping node_id -> permission dict
        """
        perms = {}

        async def scan(node, depth=0):
            if depth > max_depth:
                return
            try:
                nc = await node.read_node_class()
                nid = str(node.nodeid)
                name = (await node.read_browse_name()).Name
                p = {"name": name, "type": str(nc).split(".")[-1]}

                if nc == ua.NodeClass.Variable:
                    try:
                        lvl = (
                            await node.read_attribute(ua.AttributeIds.UserAccessLevel)
                        ).Value.Value
                        p["r"] = bool(lvl & 0x01)
                        p["w"] = bool(lvl & 0x02)
                    except Exception as e:
                        self.logger.debug("scan failed: %s", e)
                        p["r"], p["w"] = False, False
                elif nc == ua.NodeClass.Method:
                    try:
                        exec_attr = await node.read_attribute(ua.AttributeIds.UserExecutable)
                        p["x"] = exec_attr.Value.Value
                    except Exception as e:
                        self.logger.debug("scan failed: %s", e)
                        p["x"] = False

                perms[nid] = p

                for child in await node.get_children():
                    await scan(child, depth + 1)
            except Exception as e:
                self.logger.debug("scan failed: %s", e)
                pass

        await scan(client.get_objects_node())
        return perms

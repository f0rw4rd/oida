"""
OPC UA Browse Mixin

Provides address space browsing, node reading, and permission dumping functionality.
"""

import asyncio

import logging

logger = logging.getLogger(__name__)


class BrowseMixin:
    """Mixin providing OPC UA address space browsing functionality."""

    async def _dump_address_space(self, mode: str = "fast"):
        """
        Dump address space with different detail levels.

        Modes:
            fast: Names/types only (no extra attribute reads)
            full: Include DataType, Access levels for Variables
            methods: Only show Method nodes
            write: Only show writable Variable nodes
        """
        from oida.utils.export_utils import export_data
        from ..helpers import _get_asyncua

        max_depth = getattr(self.args, "max_depth", 3)
        max_nodes = getattr(self.args, "max_nodes", 1000)
        include_values = getattr(self.args, "dump_values", False)

        # Parse namespace filter (e.g., "2" or "2,3")
        ns_filter = None
        ns_filter_str = getattr(self.args, "ns", None)
        if ns_filter_str:
            try:
                ns_filter = set(int(x.strip()) for x in ns_filter_str.split(","))
            except ValueError:
                self.logger.fail(f"Invalid namespace filter: {ns_filter_str}")
                return

        # Determine start node
        start_node_id = getattr(self.args, "start_node", None)
        if start_node_id:
            try:
                start_node = self._client.get_node(start_node_id)
                start_name = await start_node.read_browse_name()
                self.logger.display(f"Starting from: {start_name.Name} ({start_node_id})")
            except Exception as e:
                self.logger.fail(f"Invalid start node '{start_node_id}': {e}")
                return
        else:
            start_node = self._client.get_root_node()

        # Build description
        mode_desc = {
            "fast": "fast",
            "full": "detailed",
            "methods": "methods only",
            "write": "writable only",
        }
        filter_info = []
        if ns_filter:
            filter_info.append(f"ns={','.join(map(str, sorted(ns_filter)))}")
        filter_str = f", filter: {', '.join(filter_info)}" if filter_info else ""
        self.logger.display(
            f"Dumping address space ({mode_desc.get(mode, mode)}, depth: {max_depth}, max: {max_nodes}{filter_str})..."
        )

        nodes = []
        visited = set()

        # BFS queue: (node, depth)
        queue = [(start_node, 0)]
        batch_size = 20  # Process nodes in batches

        def format_node_id(nodeid) -> str:
            """Format node ID with explicit namespace prefix."""
            ns = nodeid.NamespaceIndex
            raw = nodeid.to_string()
            # Always include ns= prefix for consistency
            if (
                raw.startswith("i=")
                or raw.startswith("s=")
                or raw.startswith("g=")
                or raw.startswith("b=")
            ):
                return f"ns={ns};{raw}"
            return raw

        async def process_node(node, depth):
            """Process a single node and return its info + children."""
            node_id_raw = node.nodeid.to_string()
            if node_id_raw in visited or depth >= max_depth:
                return None, []
            visited.add(node_id_raw)

            try:
                name = await node.read_browse_name()
                nc = await node.read_node_class()
                ns = node.nodeid.NamespaceIndex
                node_id = format_node_id(node.nodeid)
                class_name = nc.name if nc else "?"

                data_type = ""
                access = ""
                writable = False
                value = ""

                # Get extra details in full/write mode
                if mode in ["full", "write"]:
                    ua = _get_asyncua().ua
                    # DataType only for Variables
                    if class_name == "Variable":
                        try:
                            dt = await node.read_data_type()
                            dt_node = self._client.get_node(dt)
                            dt_name = await dt_node.read_browse_name()
                            data_type = dt_name.Name
                        except Exception as e:
                            logger.debug(f"OPC UA: read_data_type/browse_name failed: {e}")
                        try:
                            level_set = await node.get_access_level()
                            parts = []
                            if ua.AccessLevel.CurrentRead in level_set:
                                parts.append("R")
                            if ua.AccessLevel.CurrentWrite in level_set:
                                parts.append("W")
                                writable = True
                            if ua.AccessLevel.HistoryRead in level_set:
                                parts.append("H")
                            access = "".join(parts) if parts else "-"
                        except Exception:
                            access = "-"
                        # Read value if requested
                        if include_values:
                            try:
                                val = await node.read_value()
                                # Format value for display (truncate if too long)
                                val_str = str(val)
                                if len(val_str) > 30:
                                    val_str = val_str[:27] + "..."
                                value = val_str
                            except Exception:
                                value = "<error>"
                    elif class_name == "Method":
                        # Methods have Executable attribute
                        try:
                            exe = await node.read_attribute(ua.AttributeIds.Executable)
                            user_exe = await node.read_attribute(ua.AttributeIds.UserExecutable)
                            if user_exe.Value.Value:
                                access = "Call"
                            elif exe.Value.Value:
                                access = "Exec"
                            else:
                                access = "-"
                        except Exception:
                            access = "-"
                    else:
                        # Objects/Views - no specific access
                        access = "-"

                # Filter
                include = True
                # Namespace filter
                if ns_filter is not None and ns not in ns_filter:
                    include = False
                # Mode-specific filters
                elif mode == "methods" and class_name != "Method":
                    include = False
                elif mode == "write" and not writable:
                    include = False

                node_info = None
                if include:
                    node_info = {
                        "node_id": node_id,
                        "name": name.Name,
                        "class": class_name,
                        "namespace": ns,
                        "data_type": data_type,
                        "access": access,
                        "writable": writable,
                        "value": value,
                        "depth": depth,
                    }
                    # Store node reference for methods mode to get details later
                    if mode == "methods":
                        node_info["_node"] = node

                # Get children for next level
                children = []
                if depth + 1 < max_depth:
                    try:
                        children = await node.get_children()
                    except Exception as e:
                        logger.debug(f"Failed to get children: {e}")

                return node_info, [(c, depth + 1) for c in children]

            except Exception as e:
                self.logger.debug(f"Dump error {node_id}: {e}")
                return None, []

        # BFS with batched processing
        while queue and len(nodes) < max_nodes:
            # Take a batch
            batch = queue[:batch_size]
            queue = queue[batch_size:]

            # Process batch in parallel
            tasks = [process_node(n, d) for n, d in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    continue
                node_info, children = result
                if node_info and len(nodes) < max_nodes:
                    nodes.append(node_info)
                    if len(nodes) % 100 == 0:
                        self.logger.display(f"  ...{len(nodes)} nodes")
                queue.extend(children)

        self.results["data"]["nodes"] = nodes

        # Build table based on mode
        if mode == "methods":
            # Fetch method details for all methods
            self.logger.display(f"Fetching details for {len(nodes)} method(s)...")
            for n in nodes:
                if "_node" in n:
                    details = await self._get_method_details(n["_node"])
                    n["description"] = details.get("description", "")
                    n["input_args"] = details.get("input_args", [])
                    n["output_args"] = details.get("output_args", [])
                    n["executable"] = details.get("executable", False)
                    n["user_executable"] = details.get("user_executable", False)
                    del n["_node"]  # Remove node reference

            headers = ["NS", "Name", "Desc", "Permissions", "Node ID"]
            data = []
            for n in nodes:
                in_args = self._format_method_args(n.get("input_args", []))
                out_args = self._format_method_args(n.get("output_args", []))
                desc = f"{in_args} -> {out_args}"
                method_desc = n.get("description", "")
                if method_desc:
                    desc = (
                        f"{desc} | {method_desc[:25]}..."
                        if len(method_desc) > 25
                        else f"{desc} | {method_desc}"
                    )
                perm = "Call" if n.get("user_executable") else "-"
                data.append([n["namespace"], n["name"], desc, perm, n["node_id"]])
        elif mode in ["full", "write"]:
            if include_values:
                headers = ["NS", "Name", "Class", "DataType", "Access", "Value", "Node ID"]
                data = [
                    [
                        n["namespace"],
                        n["name"],
                        n["class"],
                        n["data_type"],
                        n["access"],
                        n["value"],
                        n["node_id"],
                    ]
                    for n in nodes
                ]
            else:
                headers = ["NS", "Name", "Class", "DataType", "Access", "Node ID"]
                data = [
                    [
                        n["namespace"],
                        n["name"],
                        n["class"],
                        n["data_type"],
                        n["access"],
                        n["node_id"],
                    ]
                    for n in nodes
                ]
            # Show legend
            self.logger.display("Access: R=Read, W=Write, H=History, Call=Method callable")
        else:
            headers = ["NS", "Name", "Node ID"]
            data = [[n["namespace"], n["name"], n["node_id"]] for n in nodes]

        # Report writable nodes
        writable_nodes = [n for n in nodes if n.get("writable")]
        if writable_nodes and mode != "write":
            self.logger.security_finding(
                "Writable access", detail=f"Found {len(writable_nodes)} writable variable(s)"
            )
            for wn in writable_nodes[:5]:
                self.logger.display(f"  [W] {wn['name']} ({wn['node_id']})")
            if len(writable_nodes) > 5:
                self.logger.display(f"  ... and {len(writable_nodes) - 5} more")

        # Export
        output_format = getattr(self.args, "format", "console") or "console"
        output_dir = getattr(self.args, "output", None)
        export_data(
            data,
            headers,
            output_format=output_format,
            output_dir=output_dir,
            filename_prefix=f"opcua_dump_{self.host}",
            title=f"OPC UA Address Space ({len(nodes)} nodes)",
            logger=self.logger,
        )

        # Show example CLI usage for methods
        if mode == "methods" and getattr(self.args, "dump_examples", False):
            callable_methods = [n for n in nodes if n.get("user_executable")]
            if callable_methods:
                self.logger.display("")
                self.logger.display("Example CLI usage:")
                for method in callable_methods:
                    example = self._generate_method_example(method)
                    self.logger.display(f"  # {method['name']}")
                    self.logger.display(f"  {example}")
                    self.logger.display("")

    async def _dump_permissions(self):
        """Full permission dump with filtering.

        Scans address space and collects all permission-related attributes:
        - Variables: UserAccessLevel, AccessRestrictions
        - Methods: Executable, UserExecutable
        - Objects: EventNotifier
        """
        from oida.utils.export_utils import export_data
        from ..helpers import ua, DANGEROUS_KEYWORDS

        perm_filter = getattr(self.args, "perm_filter", "all")
        max_depth = getattr(self.args, "max_depth", 5)

        self.logger.display(f"Dumping permissions (filter: {perm_filter}, depth: {max_depth})...")

        results = {
            "variables": [],
            "methods": [],
            "objects": [],
        }

        async def scan_node(node, depth=0):
            if depth > max_depth:
                return

            try:
                node_class = await node.read_node_class()
                name = await node.read_browse_name()

                entry = {
                    "node_id": str(node.nodeid),
                    "name": name.Name,
                }

                if node_class == ua.NodeClass.Variable:
                    # Get UserAccessLevel
                    try:
                        access = await node.read_attribute(ua.AttributeIds.UserAccessLevel)
                        level = access.Value.Value
                        entry["access_level"] = level
                        entry["can_read"] = bool(level & 0x01)
                        entry["can_write"] = bool(level & 0x02)
                        entry["can_history_read"] = bool(level & 0x04)
                        entry["can_history_write"] = bool(level & 0x08)
                    except Exception:
                        entry["can_read"] = False
                        entry["can_write"] = False
                        entry["can_history_read"] = False
                        entry["can_history_write"] = False

                    # Get AccessRestrictions
                    entry["restriction_flags"] = []
                    try:
                        restr = await node.read_attribute(ua.AttributeIds.AccessRestrictions)
                        restriction_val = restr.Value.Value
                        if restriction_val:
                            entry["restrictions"] = restriction_val
                            if restriction_val & 0x01:
                                entry["restriction_flags"].append("SignReq")
                            if restriction_val & 0x02:
                                entry["restriction_flags"].append("EncryptReq")
                            if restriction_val & 0x04:
                                entry["restriction_flags"].append("SessionReq")
                    except Exception as e:
                        logger.debug(f"Failed to get restr: {e}")

                    # Apply filter
                    include = False
                    if perm_filter == "all":
                        include = True
                    elif perm_filter == "write" and entry.get("can_write"):
                        include = True
                    elif perm_filter == "restricted" and entry.get("restriction_flags"):
                        include = True
                    elif perm_filter == "history" and (
                        entry.get("can_history_read") or entry.get("can_history_write")
                    ):
                        include = True
                    elif perm_filter == "dangerous" and entry.get("can_write"):
                        include = True

                    if include:
                        results["variables"].append(entry)

                elif node_class == ua.NodeClass.Method:
                    # Get Executable/UserExecutable
                    try:
                        exec_attr = await node.read_attribute(ua.AttributeIds.UserExecutable)
                        entry["user_executable"] = exec_attr.Value.Value
                    except Exception:
                        entry["user_executable"] = False

                    # Check dangerous
                    entry["dangerous"] = any(kw in name.Name.lower() for kw in DANGEROUS_KEYWORDS)

                    # Apply filter
                    include = False
                    if perm_filter in ["all", "methods"]:
                        include = True
                    elif (
                        perm_filter == "dangerous"
                        and entry.get("dangerous")
                        and entry.get("user_executable")
                    ):
                        include = True

                    if include:
                        results["methods"].append(entry)

                elif node_class == ua.NodeClass.Object:
                    # Get EventNotifier
                    try:
                        notifier = await node.read_attribute(ua.AttributeIds.EventNotifier)
                        entry["event_notifier"] = notifier.Value.Value
                        if perm_filter == "all":
                            results["objects"].append(entry)
                    except Exception as e:
                        logger.debug(f"Failed to get notifier: {e}")

                # Recurse into children
                try:
                    children = await node.get_children()
                    for child in children:
                        await scan_node(child, depth + 1)
                except Exception as e:
                    logger.debug(f"Failed to get children: {e}")

            except Exception as e:
                self.logger.debug(f"Error scanning node: {e}")

        # Start scan from objects node
        root = self._client.get_objects_node()
        await scan_node(root)

        # Build unified table (all node types combined)
        unified_data = []

        for v in results["variables"]:
            restr = ",".join(v.get("restriction_flags", [])) or "-"
            unified_data.append(
                [
                    v["node_id"],
                    v["name"],
                    "Variable",
                    "Y" if v.get("can_read") else "-",
                    "Y" if v.get("can_write") else "-",
                    "Y" if v.get("can_history_read") else "-",
                    "Y" if v.get("can_history_write") else "-",
                    "-",
                    restr,
                ]
            )

        for m in results["methods"]:
            unified_data.append(
                [
                    m["node_id"],
                    m["name"],
                    "Method",
                    "-",
                    "-",
                    "-",
                    "-",
                    "Y" if m.get("user_executable") else "-",
                    "!" if m.get("dangerous") else "-",
                ]
            )

        for o in results["objects"]:
            en = o.get("event_notifier", 0)
            unified_data.append(
                [
                    o["node_id"],
                    o["name"],
                    "Object",
                    "-",
                    "-",
                    "Y" if (en & 0x04) else "-",
                    "-",
                    "-",
                    "-",
                ]
            )

        headers = ["NodeId", "Name", "Type", "R", "W", "HR", "HW", "Exec", "Notes"]

        # Export using export_data() - honors -o and --format
        output_dir = getattr(self.args, "output", None)
        fmt = getattr(self.args, "format", "console") if output_dir else "console"
        export_data(
            unified_data,
            headers,
            fmt,
            output_dir,
            "opcua_permissions",
            "OPC UA Permissions",
            logger=self.logger,
        )

        # Summary
        self.logger.display(
            f"\nTotal: {len(results['variables'])} variables, {len(results['methods'])} methods, {len(results['objects'])} objects"
        )

        self.results["data"]["permissions"] = results

    async def _read_node(self):
        """Read specific node by ID"""
        node_id = getattr(self.args, "node_id", None)
        if not node_id:
            self.logger.fail("No node ID specified")
            return

        self.logger.display(f"Reading node: {node_id}")

        try:
            node = self._client.get_node(node_id)

            # Read value
            value = await node.read_value()
            self.logger.display(f"Value: {value}")

            # Read attributes if requested
            if getattr(self.args, "read_attributes", False):
                browse_name = await node.read_browse_name()
                display_name = await node.read_display_name()
                node_class = await node.read_node_class()

                self.logger.display(f"Browse Name: {browse_name.Name}")
                self.logger.display(f"Display Name: {display_name.Text}")
                self.logger.display(f"Node Class: {node_class.name}")

                try:
                    data_type = await node.read_data_type_as_variant_type()
                    self.logger.display(f"Data Type: {data_type.name}")
                except Exception as e:
                    logger.debug(f"Failed to get data_type: {e}")

                try:
                    access_level = await node.get_access_level()
                    self.logger.display(f"Access Level: {access_level}")
                except Exception as e:
                    logger.debug(f"Failed to get access_level: {e}")

            self.results["data"]["node_read"] = {
                "node_id": node_id,
                "value": str(value),
            }

        except Exception as e:
            self.logger.fail(f"Failed to read node: {e}")

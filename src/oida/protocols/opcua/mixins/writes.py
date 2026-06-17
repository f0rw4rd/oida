"""
OPC UA Writes Mixin

Provides write operations and write access testing functionality.
"""

from ..helpers import ua


class WritesMixin:
    """Mixin providing OPC UA write operations."""

    async def _write_value(self):
        """Write a value to a specific node."""
        node_id = getattr(self.args, "node_id", None)
        value_str = getattr(self.args, "write_value", None)
        confirm = getattr(self.args, "confirm", False)

        if not node_id:
            self.logger.fail("--write-value requires --node-id to specify target node")
            return

        if not confirm:
            self.logger.fail("--write-value requires --confirm (dangerous operation)")
            return

        try:
            node = self._client.get_node(node_id)
            name = await node.read_browse_name()

            # Read current value and data type
            current_value = await node.read_value()
            data_type = await node.read_data_type()
            dt_node = self._client.get_node(data_type)
            dt_name = await dt_node.read_browse_name()

            self.logger.display(f"Node: {name.Name} ({node_id})")
            self.logger.display(f"  DataType: {dt_name.Name}")
            self.logger.display(f"  Current: {current_value}")

            # Convert value based on data type
            new_value = self._convert_value(value_str, dt_name.Name, current_value)

            if new_value is None:
                self.logger.fail(f"Could not convert '{value_str}' to {dt_name.Name}")
                return

            # Write the value
            await node.write_value(new_value)

            # Verify
            verify_value = await node.read_value()
            self.logger.success(f"  Written: {new_value}")
            self.logger.display(f"  Verified: {verify_value}")

            self.results["data"]["write"] = {
                "node_id": node_id,
                "name": name.Name,
                "old_value": str(current_value),
                "new_value": str(new_value),
                "verified": str(verify_value),
            }

        except Exception as e:
            self.logger.debug("write value failed: %s", e)
            self.logger.fail(f"Write failed: {e}")

    def _convert_value(self, value_str: str, data_type: str, current_value):
        """Convert string value to appropriate OPC UA type."""
        try:
            dt_lower = data_type.lower()

            # Boolean
            if dt_lower == "boolean":
                return value_str.lower() in ("true", "1", "yes", "on")

            # Integer types (signed and unsigned both parse via int())
            if dt_lower in (
                "int16",
                "int32",
                "int64",
                "sbyte",
                "uint16",
                "uint32",
                "uint64",
                "byte",
            ):
                return int(value_str)

            # Float types
            if dt_lower in ("float", "double"):
                return float(value_str)

            # String
            if dt_lower == "string":
                return value_str

            # DateTime - try ISO format
            if dt_lower in ("datetime", "utctime"):
                from datetime import datetime

                return datetime.fromisoformat(value_str)

            # Fallback: try to match current value type
            if current_value is not None:
                val_type = type(current_value)
                return val_type(value_str)

            # Last resort: return as string
            return value_str

        except Exception as e:
            self.logger.debug("convert value failed: %s", e)
            return None

    async def _test_write_access_scan(self):
        """Scan address space for writable nodes using AccessLevel attribute.

        Uses UserAccessLevel attribute bitmask to detect write permissions
        without performing actual write operations. This is faster and safer.

        AccessLevel bitmask:
          Bit 0 (0x01): CurrentRead
          Bit 1 (0x02): CurrentWrite
          Bit 2 (0x04): HistoryRead
          Bit 3 (0x08): HistoryWrite
        """
        self.logger.display("Scanning for writable nodes (AccessLevel check)...")

        writable_nodes = []
        read_only_nodes = []
        objects = self._client.get_objects_node()

        async def check_node(node, depth=0):
            if depth > 3 or len(writable_nodes) >= 50:
                return

            try:
                children = await node.get_children()
                for child in children:
                    try:
                        node_class = await child.read_node_class()
                        if node_class == ua.NodeClass.Variable:
                            # Check UserAccessLevel attribute (respects current user permissions)
                            try:
                                access = await child.read_attribute(ua.AttributeIds.UserAccessLevel)
                                level = access.Value.Value

                                can_read = (level & 0x01) != 0
                                can_write = (level & 0x02) != 0
                                can_history_read = (level & 0x04) != 0
                                can_history_write = (level & 0x08) != 0

                                name = await child.read_browse_name()
                                node_info = {
                                    "node_id": str(child.nodeid),
                                    "name": name.Name,
                                    "access_level": level,
                                    "can_read": can_read,
                                    "can_write": can_write,
                                    "can_history_read": can_history_read,
                                    "can_history_write": can_history_write,
                                }

                                # Check AccessRestrictions (IP/network/encryption requirements)
                                try:
                                    restrictions = await child.read_attribute(
                                        ua.AttributeIds.AccessRestrictions
                                    )
                                    restriction_val = restrictions.Value.Value
                                    if restriction_val:
                                        restriction_flags = []
                                        if restriction_val & 0x01:
                                            restriction_flags.append("SignReq")
                                        if restriction_val & 0x02:
                                            restriction_flags.append("EncryptReq")
                                        if restriction_val & 0x04:
                                            restriction_flags.append("SessionReq")
                                        node_info["restrictions"] = restriction_val
                                        node_info["restriction_flags"] = restriction_flags
                                except Exception as e:
                                    self.logger.debug("check node failed: %s", e)
                                    pass  # AccessRestrictions not supported by all servers

                                if can_write:
                                    writable_nodes.append(node_info)
                                    flags = []
                                    if can_history_write:
                                        flags.append("HistWrite")
                                    if node_info.get("restriction_flags"):
                                        flags.extend(node_info["restriction_flags"])
                                    flag_str = f" [{','.join(flags)}]" if flags else ""
                                    self.logger.success(
                                        f"[WRITABLE] {name.Name} ({child.nodeid}){flag_str}"
                                    )
                                elif can_read:
                                    read_only_nodes.append(node_info)

                            except Exception as e:
                                self.logger.debug(
                                    f"Could not read AccessLevel for {child.nodeid}: {e}"
                                )

                        await check_node(child, depth + 1)
                    except Exception as e:
                        self.logger.debug("check node failed: %s", e)
                        pass
            except Exception as e:
                self.logger.debug("check node failed: %s", e)
                pass

        await check_node(objects)

        if writable_nodes:
            self.logger.security_finding(
                "Writable access", detail=f"Found {len(writable_nodes)} writable nodes"
            )
        else:
            self.logger.display("No writable nodes found")

        self.logger.display(f"Read-only nodes: {len(read_only_nodes)}")

        self.results["data"]["writable_nodes"] = writable_nodes
        self.results["data"]["read_only_nodes"] = len(read_only_nodes)

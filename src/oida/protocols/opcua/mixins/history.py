"""
OPC UA History Mixin

Provides historical data reading and historizing node discovery functionality.
"""

from ..helpers import ua


class HistoryMixin:
    """Mixin providing OPC UA historical data operations."""

    async def _read_history(self):
        """Read historical data from a node."""
        from datetime import datetime, timedelta, timezone

        node_id = getattr(self.args, "node_id", None)
        if not node_id:
            self.logger.fail("--history-read requires --node-id")
            return

        try:
            node = self._client.get_node(node_id)
            node_name = await node.read_browse_name()

            # Check if node supports historizing
            try:
                historizing = await node.read_attribute(ua.AttributeIds.Historizing)
                if not historizing.Value.Value:
                    self.logger.warning(f"Node {node_id} does not have historizing enabled")
            except Exception as e:
                self.logger.debug("read history failed: %s", e)
                pass

            # Parse time range
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=1)  # Default: last 24 hours

            if getattr(self.args, "history_start", None):
                try:
                    start_time = datetime.fromisoformat(self.args.history_start)
                except ValueError as e:
                    self.logger.debug("read history failed: %s", e)
                    self.logger.fail(f"Invalid start time format: {self.args.history_start}")
                    return

            if getattr(self.args, "history_end", None):
                try:
                    end_time = datetime.fromisoformat(self.args.history_end)
                except ValueError as e:
                    self.logger.debug("read history failed: %s", e)
                    self.logger.fail(f"Invalid end time format: {self.args.history_end}")
                    return

            max_values = getattr(self.args, "history_max", 100)

            self.logger.display(f"Reading historical data from {node_name.Name} ({node_id})")
            self.logger.display(f"  Time range: {start_time.isoformat()} to {end_time.isoformat()}")

            # Read history
            try:
                history_result = await node.read_raw_history(
                    starttime=start_time,
                    endtime=end_time,
                    numvalues=max_values,
                )

                if history_result:
                    self.logger.success(f"Retrieved {len(history_result)} historical values")

                    # Store in results
                    history_data = []

                    # Display values in a table
                    self.logger.display(
                        "+---------------------------+----------------------+--------+"
                    )
                    self.logger.display(
                        "|         Timestamp         |        Value         | Status |"
                    )
                    self.logger.display(
                        "+---------------------------+----------------------+--------+"
                    )

                    for dv in history_result[:50]:  # Limit display to 50
                        timestamp = dv.SourceTimestamp.isoformat() if dv.SourceTimestamp else "N/A"
                        value = str(dv.Value.Value)[:20] if dv.Value else "N/A"
                        status = "Good" if dv.StatusCode.is_good() else str(dv.StatusCode)

                        self.logger.display(f"| {timestamp:25} | {value:20} | {status:6} |")

                        history_data.append(
                            {
                                "timestamp": timestamp,
                                "value": str(dv.Value.Value) if dv.Value else None,
                                "status": str(dv.StatusCode),
                            }
                        )

                    self.logger.display(
                        "+---------------------------+----------------------+--------+"
                    )

                    if len(history_result) > 50:
                        self.logger.display(f"  ... and {len(history_result) - 50} more values")

                    self.results["data"]["history"] = {
                        "node_id": node_id,
                        "node_name": node_name.Name,
                        "start_time": start_time.isoformat(),
                        "end_time": end_time.isoformat(),
                        "count": len(history_result),
                        "values": history_data,
                    }
                else:
                    self.logger.warning("No historical data found in the specified time range")

            except ua.UaStatusCodeError as e:
                self.logger.debug("read history failed: %s", e)
                if "BadHistoryOperationUnsupported" in str(e):
                    self.logger.fail("Server does not support historical data access")
                elif "BadHistoryOperationInvalid" in str(e):
                    self.logger.fail("Invalid history operation for this node")
                elif "BadNotReadable" in str(e):
                    self.logger.fail("Historical data not readable (access denied)")
                else:
                    self.logger.fail(f"History read failed: {e}")

        except Exception as e:
            self.logger.debug("read history failed: %s", e)
            self.logger.fail(f"Error reading history: {e}")

    async def _dump_historizing_nodes(self):
        """Dump all nodes with historizing enabled."""
        self.logger.display("Searching for nodes with historizing enabled...")

        historizing_nodes = []
        objects = self._client.get_objects_node()
        max_depth = getattr(self.args, "max_depth", 3)
        max_nodes = getattr(self.args, "max_nodes", 1000)

        async def search(node, depth=0):
            if depth > max_depth or len(historizing_nodes) >= max_nodes:
                return

            try:
                children = await node.get_children()
                for child in children:
                    try:
                        node_class = await child.read_node_class()
                        if node_class == ua.NodeClass.Variable:
                            # Check historizing attribute
                            try:
                                historizing = await child.read_attribute(
                                    ua.AttributeIds.Historizing
                                )
                                if historizing.Value.Value:
                                    name = await child.read_browse_name()
                                    historizing_nodes.append(
                                        {
                                            "node_id": child.nodeid.to_string(),
                                            "name": name.Name,
                                        }
                                    )
                            except Exception as e:
                                self.logger.debug("search failed: %s", e)
                                pass
                        await search(child, depth + 1)
                    except Exception as e:
                        self.logger.debug("search failed: %s", e)
                        pass
            except Exception as e:
                self.logger.debug("search failed: %s", e)
                pass

        await search(objects)

        if historizing_nodes:
            self.logger.success(f"Found {len(historizing_nodes)} nodes with historizing enabled")

            self.logger.display("+------+--------------------+-------------------------+")
            self.logger.display("|  NS  |        Name        |         Node ID         |")
            self.logger.display("+------+--------------------+-------------------------+")

            for node_info in historizing_nodes:
                ns = (
                    node_info["node_id"].split(";")[0].replace("ns=", "")
                    if "ns=" in node_info["node_id"]
                    else "0"
                )
                name = node_info["name"][:18]
                node_id = node_info["node_id"][:23]
                self.logger.display(f"| {ns:4} | {name:18} | {node_id:23} |")

            self.logger.display("+------+--------------------+-------------------------+")

            self.results["data"]["historizing_nodes"] = historizing_nodes
        else:
            self.logger.warning("No nodes with historizing enabled found")

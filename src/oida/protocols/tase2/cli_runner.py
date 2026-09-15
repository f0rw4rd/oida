#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TASE.2/ICCP NXC-style callable class."""

from typing import Any, Optional

from ...connection import NetworkConnection
from ...utils.lazy_import import lazy_import

from .scanner import TASE2Scanner

_pyiec61850_tase2 = lazy_import(
    "pyiec61850.tase2", "TASE.2", install_hint="pip install oida-ics[tase2]"
)


class tase2(NetworkConnection):
    """NXC-style TASE.2/ICCP scanner (callable)"""

    def __init__(self, args: Any, db: Optional[Any], host: str):
        self.protocol_name = "TASE.2"
        self.default_port = 102
        super().__init__(args, db, host)

    def proto_flow(self) -> None:
        """Main TASE.2 workflow with action support."""
        args_dict = self._convert_args_to_dict()
        self.scanner = TASE2Scanner(args_dict)
        self.create_conn_obj()
        if not self.conn:
            self.logger.fail(f"Failed to connect to {self.host}")
            self.results["success"] = False
            self.results["error"] = "Connection failed"
            return

        self.enum_host_info()
        self.print_host_info()

        # Check for action commands vs regular scan
        if self._has_action():
            self._execute_action()
        else:
            self._execute_scan()

    def create_conn_obj(self) -> None:
        """Create TASE.2 connection."""
        self.logger.info(f"Connecting to {self.ip}:{self.args.port}")
        self.conn = self.scanner.connect()
        if self.conn:
            self.logger.success(f"Connected to TASE.2 server at {self.ip}:{self.args.port}")
            # TASE.2/ICCP over MMS is TLS-OPTIONAL (IEC 62351). This scanner has
            # no TLS concept (no --tls arg, TASE2Client opened without a secure
            # context), so TLS is never in use -- gate on use_tls just in case a
            # secure path is ever added, and report cleartext on the confirmed
            # connection.
            if not getattr(self.scanner, "use_tls", False):
                self.logger.security_finding(
                    "No encryption",
                    detail="TASE.2 / ICCP without TLS (IEC 62351) -- cleartext",
                )
        else:
            self.logger.fail(f"Connection failed to {self.ip}:{self.args.port}")

    def enum_host_info(self) -> None:
        """Enumerate TASE.2 server information."""
        if not self.conn:
            return

        self.logger.debug("Enumerating server information...")

        try:
            # Get bilateral table info
            blt_id = self.conn.get_bilateral_table_id()
            blt_count = self.conn.get_server_bilateral_table_count()

            self.results["data"]["bilateral_table"] = {
                "id": blt_id,
                "count": blt_count,
            }

            # Get domains
            domains = self.conn.get_domains()
            self.results["data"]["domain_count"] = len(domains)
            self.results["data"]["domains"] = [
                {
                    "name": d.name,
                    "type": "VCC" if d.is_vcc else "ICC",
                    "variables": len(d.variables),
                    "data_sets": len(d.data_sets),
                }
                for d in domains
            ]

        except Exception as e:
            self.logger.debug(f"Enumeration error: {e}")

    def print_host_info(self) -> None:
        """Display TASE.2 server information."""
        if hasattr(self.args, "quiet") and self.args.quiet:
            return

        self.logger.display(f"TASE.2 Server: {self.host}")

        blt = self.results["data"].get("bilateral_table", {})
        if blt.get("id"):
            self.logger.display(f"  Bilateral Table: {blt['id']}")

        domains = self.results["data"].get("domains", [])
        if domains:
            self.logger.display(f"  Domains: {len(domains)}")
            for d in domains[:5]:
                self.logger.display(f"    {d['type']}: {d['name']} ({d['variables']} vars)")
            if len(domains) > 5:
                self.logger.display(f"    ... and {len(domains) - 5} more")

    def _execute_scan(self) -> None:
        """Execute TASE.2 scanning."""
        if not self.conn:
            return

        self.logger.display("Executing scan...")
        scan_results = self.scanner.discover(self.conn)
        self.results["data"]["scan_results"] = scan_results

    def _has_action(self) -> bool:
        """Check if an action command was requested."""
        action_attrs = [
            # Discovery
            "list_domains",
            "list_variables",
            "list_data_sets",
            "list_transfer_sets",
            # Data access
            "read_point",
            "write_point",
            # Control
            "send_command",
            "select_device",
            "operate_device",
            # Transfer sets
            "enable_rbe",
            "disable_rbe",
            # Info
            "get_blt",
            "get_server_info",
            "get_features",
            "get_version",
            # Data type operations (Block 1)
            "get_data_type",
            "read_points",
            # Data set operations (Block 1)
            "get_ds_members",
            "read_data_set",
            "create_data_set",
            "delete_data_set",
            # Device tag operations (Block 5)
            "get_tag",
            "set_tag",
            # Information Messages (Block 4)
            "list_im_stores",
            "list_messages",
            "read_message",
            "write_message",
            "delete_message",
            "test_im",
        ]
        for attr in action_attrs:
            val = getattr(self.args, attr, None)
            if val not in (None, False):
                return True
        return False

    # Actions that modify state and require --confirm
    _WRITE_ACTIONS = frozenset(
        {
            "write_point",
            "send_command",
            "select_device",
            "operate_device",
            "enable_rbe",
            "disable_rbe",
            "set_tag",
            "create_data_set",
            "delete_data_set",
            "write_message",
            "delete_message",
        }
    )

    def _needs_confirm(self) -> bool:
        """Check if the requested action is a write/control operation needing --confirm."""
        for attr in self._WRITE_ACTIONS:
            val = getattr(self.args, attr, None)
            if val not in (None, False):
                return True
        return False

    def _execute_action(self) -> None:
        """Execute requested action command."""
        # Gate write/control operations behind --confirm
        if self._needs_confirm() and not getattr(self.args, "confirm", False):
            self.logger.fail(
                "Write/control operations require --confirm "
                "(write-point, send-command, operate-device, set-tag, etc.)"
            )
            return

        result = None

        # List domains
        if getattr(self.args, "list_domains", False):
            self.logger.display("Listing domains...")
            domains = self.conn.get_domains()
            for d in domains:
                dtype = "VCC" if d.is_vcc else "ICC"
                self.logger.display(f"  {dtype}: {d.name} ({len(d.variables)} vars)")
            result = {"domains": [d.name for d in domains]}

        # List variables
        elif getattr(self.args, "list_variables", None):
            domain = self.args.list_variables
            self.logger.display(f"Listing variables for {domain}...")
            variables = self.conn.get_domain_variables(domain)
            for v in variables:
                self.logger.display(f"  {v}")
            result = {"variables": list(variables)}

        # List data sets
        elif getattr(self.args, "list_data_sets", None):
            domain = self.args.list_data_sets if self.args.list_data_sets is not True else None
            self.logger.display("Listing data sets...")
            data_sets = self.conn.get_data_sets(domain)
            for ds in data_sets:
                self.logger.display(f"  {ds.domain}/{ds.name} ({ds.member_count} members)")
            result = {"data_sets": [f"{ds.domain}/{ds.name}" for ds in data_sets]}

        # List transfer sets
        elif getattr(self.args, "list_transfer_sets", None):
            domain = self.args.list_transfer_sets
            self.logger.display(f"Listing transfer sets for {domain}...")
            ts_list = self.conn.get_transfer_sets(domain)
            for ts in ts_list:
                self.logger.display(f"  {ts.name} (RBE: {ts.rbe_enabled})")
            result = {"transfer_sets": [ts.name for ts in ts_list]}

        # Read point
        elif getattr(self.args, "read_point", None):
            point_spec = self.args.read_point
            parts = point_spec.split("/")
            if len(parts) != 2:
                self.logger.fail("Invalid format. Use DOMAIN/POINTNAME")
                return
            domain, name = parts
            self.logger.display(f"Reading {domain}/{name}...")
            try:
                pv = self.conn.read_point(domain, name)
                self.logger.display(f"  Value: {pv.value}")
                self.logger.display(f"  Quality: {pv.quality}")
                self.logger.display(f"  Type: {pv.point_type}")
                result = {
                    "point": f"{domain}/{name}",
                    "value": pv.value,
                    "quality": str(pv.quality),
                }
            except Exception as e:
                self.logger.fail(f"Read failed: {e}")
                result = {"error": str(e)}

        # Write point
        elif getattr(self.args, "write_point", None):
            point_spec = self.args.write_point
            parts = point_spec.split(":")
            if len(parts) != 2:
                self.logger.fail("Invalid format. Use DOMAIN/POINTNAME:VALUE")
                return
            point_path, value_str = parts
            path_parts = point_path.split("/")
            if len(path_parts) != 2:
                self.logger.fail("Invalid format. Use DOMAIN/POINTNAME:VALUE")
                return
            domain, name = path_parts
            try:
                value = float(value_str)
            except ValueError:
                try:
                    value = int(value_str)
                except ValueError:
                    self.logger.fail(f"Invalid value '{value_str}': must be a number")
                    return

            self.logger.display(f"Writing {value} to {domain}/{name}...")
            try:
                self.conn.write_point(domain, name, value)
                self.logger.display("Write successful")
                result = {"success": True}
            except Exception as e:
                self.logger.fail(f"Write failed: {e}")
                result = {"error": str(e)}

        # Send command
        elif getattr(self.args, "send_command", None):
            cmd_spec = self.args.send_command
            parts = cmd_spec.split(":")
            if len(parts) != 2:
                self.logger.fail("Invalid format. Use DOMAIN/DEVICE:COMMAND")
                return
            device_path, cmd_str = parts
            path_parts = device_path.split("/")
            if len(path_parts) != 2:
                self.logger.fail("Invalid format. Use DOMAIN/DEVICE:COMMAND")
                return
            domain, device = path_parts
            try:
                command = int(cmd_str)
            except ValueError:
                self.logger.fail(f"Invalid command '{cmd_str}': must be an integer")
                return

            self.logger.display(f"Sending command {command} to {domain}/{device}...")
            try:
                self.conn.send_command(domain, device, command)
                self.logger.display("Command sent")
                result = {"success": True}
            except Exception as e:
                self.logger.fail(f"Command failed: {e}")
                result = {"error": str(e)}

        # Select device
        elif getattr(self.args, "select_device", None):
            device_spec = self.args.select_device
            parts = device_spec.split("/")
            if len(parts) != 2:
                self.logger.fail("Invalid format. Use DOMAIN/DEVICE")
                return
            domain, device = parts

            self.logger.display(f"Selecting {domain}/{device}...")
            try:
                self.conn.select_device(domain, device)
                self.logger.display("Device selected")
                result = {"success": True}
            except Exception as e:
                self.logger.fail(f"Select failed: {e}")
                result = {"error": str(e)}

        # Operate device
        elif getattr(self.args, "operate_device", None):
            op_spec = self.args.operate_device
            parts = op_spec.split(":")
            if len(parts) != 2:
                self.logger.fail("Invalid format. Use DOMAIN/DEVICE:VALUE")
                return
            device_path, value_str = parts
            path_parts = device_path.split("/")
            if len(path_parts) != 2:
                self.logger.fail("Invalid format. Use DOMAIN/DEVICE:VALUE")
                return
            domain, device = path_parts
            try:
                value = int(value_str)
            except ValueError:
                self.logger.fail(f"Invalid value '{value_str}': must be an integer")
                return

            self.logger.display(f"Operating {domain}/{device} with value {value}...")
            try:
                self.conn.operate_device(domain, device, value)
                self.logger.display("Operation successful")
                result = {"success": True}
            except Exception as e:
                self.logger.fail(f"Operate failed: {e}")
                result = {"error": str(e)}

        # Enable RBE
        elif getattr(self.args, "enable_rbe", None):
            ts_spec = self.args.enable_rbe
            parts = ts_spec.split("/")
            if len(parts) != 2:
                self.logger.fail("Invalid format. Use DOMAIN/TRANSFERSET")
                return
            domain, ts_name = parts

            self.logger.display(f"Enabling transfer set {domain}/{ts_name}...")
            try:
                self.conn.enable_transfer_set(domain, ts_name)
                self.logger.display("Transfer set enabled")
                result = {"success": True}
            except Exception as e:
                self.logger.fail(f"Enable failed: {e}")
                result = {"error": str(e)}

        # Disable RBE
        elif getattr(self.args, "disable_rbe", None):
            ts_spec = self.args.disable_rbe
            parts = ts_spec.split("/")
            if len(parts) != 2:
                self.logger.fail("Invalid format. Use DOMAIN/TRANSFERSET")
                return
            domain, ts_name = parts

            self.logger.display(f"Disabling transfer set {domain}/{ts_name}...")
            try:
                self.conn.disable_transfer_set(domain, ts_name)
                self.logger.display("Transfer set disabled")
                result = {"success": True}
            except Exception as e:
                self.logger.fail(f"Disable failed: {e}")
                result = {"error": str(e)}

        # Get bilateral table
        elif getattr(self.args, "get_blt", False):
            self.logger.display("Getting bilateral table info...")
            blt_id = self.conn.get_bilateral_table_id()
            blt_count = self.conn.get_server_bilateral_table_count()
            self.logger.display(f"  Table ID: {blt_id}")
            self.logger.display(f"  Table Count: {blt_count}")
            result = {"table_id": blt_id, "count": blt_count}

        # Get server info
        elif getattr(self.args, "get_server_info", False):
            self.logger.display("Getting server info...")
            info = self.conn.get_server_info()
            domain_count = len(self.conn.get_domains())
            self.logger.display(f"  Vendor: {info.vendor}")
            self.logger.display(f"  Model: {info.model}")
            self.logger.display(f"  Revision: {info.revision}")
            self.logger.display(f"  Domains: {domain_count}")
            self.logger.display(f"  Bilateral Table ID: {info.bilateral_table_id}")
            self.logger.display(f"  Bilateral Table Count: {info.bilateral_table_count}")
            self.logger.display(f"  Conformance Blocks: {info.conformance_blocks}")
            result = {
                "server_info": {
                    "vendor": info.vendor,
                    "model": info.model,
                    "revision": info.revision,
                    "domain_count": domain_count,
                    "bilateral_table_id": info.bilateral_table_id,
                    "bilateral_table_count": info.bilateral_table_count,
                    "conformance_blocks": info.conformance_blocks,
                }
            }

        # Get supported features
        elif getattr(self.args, "get_features", False):
            self.logger.display("Getting supported features...")
            features = self.scanner.get_supported_features(self.conn)
            self.logger.display("Supported Conformance Blocks:")
            for block, supported in features.items():
                status = "YES" if supported else "NO"
                self.logger.display(f"  {block.upper()}: {status}")
            result = {"supported_features": features}

        # Get TASE.2 version
        elif getattr(self.args, "get_version", False):
            self.logger.display("Getting TASE.2 version...")
            version = self.scanner.get_tase2_version(self.conn)
            if version["major"] > 0:
                self.logger.display(f"  Version: {version['major']}.{version['minor']:02d}")
            else:
                self.logger.display("  Version: Unknown")
            result = {"tase2_version": version}

        # Get data value type
        elif getattr(self.args, "get_data_type", None):
            type_spec = self.args.get_data_type
            parts = type_spec.split("/")
            if len(parts) != 2:
                self.logger.fail("Invalid format. Use DOMAIN/NAME")
                return
            domain, name = parts
            self.logger.display(f"Getting type for {domain}/{name}...")
            type_info = self.scanner.get_data_value_type(self.conn, domain, name)
            self.logger.display(f"  Type: {type_info['type_name']}")
            result = {"type_info": type_info}

        # Read multiple points
        elif getattr(self.args, "read_points", None):
            points_spec = self.args.read_points
            # Parse DOMAIN/NAME1,NAME2,...
            parts = points_spec.split("/", 1)
            if len(parts) != 2:
                self.logger.fail("Invalid format. Use DOMAIN/NAME1,NAME2,...")
                return
            domain, names_str = parts
            names = [n.strip() for n in names_str.split(",")]
            self.logger.display(f"Reading {len(names)} points from {domain}...")
            values = self.scanner.get_data_values(self.conn, domain, names)
            for v in values:
                if v.get("error"):
                    self.logger.display(f"  {v['name']}: ERROR - {v['error']}")
                else:
                    self.logger.display(f"  {v['name']}: {v['value']} [{v['quality']}]")
            result = {"values": values}

        # Get data set members
        elif getattr(self.args, "get_ds_members", None):
            ds_spec = self.args.get_ds_members
            parts = ds_spec.split("/")
            if len(parts) != 2:
                self.logger.fail("Invalid format. Use DOMAIN/DATASET")
                return
            domain, ds_name = parts
            self.logger.display(f"Getting members of {domain}/{ds_name}...")
            members = self.scanner.get_data_set_members(self.conn, domain, ds_name)
            self.logger.display(f"Data set has {len(members)} members:")
            for m in members:
                self.logger.display(f"  {m['domain']}/{m['name']}")
            result = {"members": members}

        # Read data set values
        elif getattr(self.args, "read_data_set", None):
            ds_spec = self.args.read_data_set
            parts = ds_spec.split("/")
            if len(parts) != 2:
                self.logger.fail("Invalid format. Use DOMAIN/DATASET")
                return
            domain, ds_name = parts
            self.logger.display(f"Reading values from {domain}/{ds_name}...")
            values = self.scanner.read_data_set_values(self.conn, domain, ds_name)
            for v in values:
                if v.get("error"):
                    self.logger.display(f"  {v['name']}: ERROR")
                else:
                    self.logger.display(f"  {v['name']}: {v['value']} [{v['quality']}]")
            result = {"values": values}

        # Create data set
        elif getattr(self.args, "create_data_set", None):
            ds_spec = self.args.create_data_set
            # Parse DOMAIN/NAME:VAR1,VAR2,...
            parts = ds_spec.split(":")
            if len(parts) != 2:
                self.logger.fail("Invalid format. Use DOMAIN/NAME:VAR1,VAR2,...")
                return
            ds_path, vars_str = parts
            path_parts = ds_path.split("/")
            if len(path_parts) != 2:
                self.logger.fail("Invalid format. Use DOMAIN/NAME:VAR1,VAR2,...")
                return
            domain, ds_name = path_parts
            var_names = [v.strip() for v in vars_str.split(",")]
            members = [{"domain": domain, "name": v} for v in var_names]

            self.logger.display(
                f"Creating data set {domain}/{ds_name} with {len(members)} members..."
            )
            success = self.scanner.create_data_set(self.conn, domain, ds_name, members)
            if success:
                self.logger.display("Data set created successfully")
            else:
                self.logger.fail("Failed to create data set")
            result = {"success": success}

        # Delete data set
        elif getattr(self.args, "delete_data_set", None):
            ds_spec = self.args.delete_data_set
            parts = ds_spec.split("/")
            if len(parts) != 2:
                self.logger.fail("Invalid format. Use DOMAIN/DATASET")
                return
            domain, ds_name = parts

            self.logger.display(f"Deleting data set {domain}/{ds_name}...")
            success = self.scanner.delete_data_set(self.conn, domain, ds_name)
            if success:
                self.logger.display("Data set deleted successfully")
            else:
                self.logger.fail("Failed to delete data set")
            result = {"success": success}

        # Get device tag
        elif getattr(self.args, "get_tag", None):
            tag_spec = self.args.get_tag
            parts = tag_spec.split("/")
            if len(parts) != 2:
                self.logger.fail("Invalid format. Use DOMAIN/DEVICE")
                return
            domain, device = parts

            self.logger.display(f"Getting tag for {domain}/{device}...")
            tag_info = self.scanner.get_tag(self.conn, domain, device)
            self.logger.display(f"  Tag Value: {tag_info['tag_value']}")
            if tag_info.get("reason"):
                self.logger.display(f"  Reason: {tag_info['reason']}")
            result = {"tag_info": tag_info}

        # Set device tag
        elif getattr(self.args, "set_tag", None):
            tag_spec = self.args.set_tag
            # Parse DOMAIN/DEVICE:TAG[:REASON]
            parts = tag_spec.split(":")
            if len(parts) < 2:
                self.logger.fail("Invalid format. Use DOMAIN/DEVICE:TAG[:REASON]")
                return
            device_path = parts[0]
            tag_value = parts[1]
            reason = parts[2] if len(parts) > 2 else ""

            path_parts = device_path.split("/")
            if len(path_parts) != 2:
                self.logger.fail("Invalid format. Use DOMAIN/DEVICE:TAG[:REASON]")
                return
            domain, device = path_parts

            self.logger.display(f"Setting tag for {domain}/{device} to {tag_value}...")
            success = self.scanner.set_tag(self.conn, domain, device, tag_value, reason)
            if success:
                self.logger.display("Tag set successfully")
            else:
                self.logger.fail("Failed to set tag")
            result = {"success": success}

        # List IM stores (Block 4)
        elif getattr(self.args, "list_im_stores", None):
            domain = self.args.list_im_stores if self.args.list_im_stores is not True else None
            if domain:
                self.logger.display(f"Listing IM stores in domain {domain}...")
                stores = self.scanner.get_information_message_stores(self.conn, domain)
            else:
                self.logger.display("Listing all IM stores...")
                stores = []
                domains = self.results.get("data", {}).get("domains", [])
                for d in domains:
                    d_name = d.get("name", d) if isinstance(d, dict) else d
                    stores.extend(self.scanner.get_information_message_stores(self.conn, d_name))

            if stores:
                self.logger.display(f"Found {len(stores)} IM store(s):")
                for store in stores:
                    self.logger.display(
                        f"  {store['domain']}/{store['name']} - "
                        f"{store.get('current_count', 0)}/{store.get('max_messages', '?')} msgs "
                        f"[{store.get('storage_status', 'UNKNOWN')}]"
                    )
            else:
                self.logger.display("No IM stores found")
            result = {"im_stores": stores}

        # List messages in IM store
        elif getattr(self.args, "list_messages", None):
            msg_spec = self.args.list_messages
            parts = msg_spec.split("/")
            if len(parts) != 2:
                self.logger.fail("Invalid format. Use DOMAIN/STORE")
                return
            domain, store = parts

            self.logger.display(f"Listing messages in {domain}/{store}...")
            messages = self.scanner.get_information_messages(self.conn, domain, store)
            if messages:
                self.logger.display(f"Found {len(messages)} message(s):")
                for msg in messages:
                    line = f"  {msg['message_id']} - {msg.get('size', 0)} bytes"
                    if msg.get("time_created"):
                        line += f" @ {msg['time_created']}"
                    self.logger.display(line)
            else:
                self.logger.display("No messages found")
            result = {"messages": messages}

        # Read message content
        elif getattr(self.args, "read_message", None):
            msg_spec = self.args.read_message
            parts = msg_spec.split("/")
            if len(parts) != 3:
                self.logger.fail("Invalid format. Use DOMAIN/STORE/MSGID")
                return
            domain, store, msg_id = parts

            self.logger.display(f"Reading message {domain}/{store}/{msg_id}...")
            msg = self.scanner.read_information_message(self.conn, domain, store, msg_id)
            if msg.get("content"):
                self.logger.display("Message content:")
                self.logger.display(f"  {msg['content']}")
                if msg.get("time_created"):
                    self.logger.display(f"  Time: {msg['time_created']}")
            elif msg.get("error"):
                self.logger.fail(f"Error: {msg['error']}")
            else:
                self.logger.display("Message is empty or not found")
            result = {"message": msg}

        # Write message
        elif getattr(self.args, "write_message", None):
            msg_spec = self.args.write_message
            parts = msg_spec.split(":", 1)
            if len(parts) != 2:
                self.logger.fail("Invalid format. Use DOMAIN/STORE:CONTENT")
                return
            store_path, content = parts

            path_parts = store_path.split("/")
            if len(path_parts) != 2:
                self.logger.fail("Invalid format. Use DOMAIN/STORE:CONTENT")
                return
            domain, store = path_parts

            self.logger.display(f"Writing message to {domain}/{store}...")
            write_result = self.scanner.write_information_message(self.conn, domain, store, content)
            if write_result.get("success"):
                msg_id = write_result.get("message_id", "")
                self.logger.display(f"Message written successfully: {msg_id}")
            else:
                self.logger.fail(f"Failed: {write_result.get('error', 'Unknown error')}")
            result = write_result

        # Delete message
        elif getattr(self.args, "delete_message", None):
            msg_spec = self.args.delete_message
            parts = msg_spec.split("/")
            if len(parts) != 3:
                self.logger.fail("Invalid format. Use DOMAIN/STORE/MSGID")
                return
            domain, store, msg_id = parts

            self.logger.display(f"Deleting message {domain}/{store}/{msg_id}...")
            del_result = self.scanner.delete_information_message(self.conn, domain, store, msg_id)
            if del_result.get("success"):
                self.logger.display("Message deleted successfully")
            else:
                self.logger.fail(f"Failed: {del_result.get('error', 'Unknown error')}")
            result = del_result

        # Test IM access (Block 4)
        elif getattr(self.args, "test_im", False):
            self.logger.display("Testing Information Message access (Block 4)...")
            im_stores = []
            domains = self.results.get("data", {}).get("domains", [])
            for d in domains:
                d_name = d.get("name", d) if isinstance(d, dict) else d
                stores = self.scanner.get_information_message_stores(self.conn, d_name)
                im_stores.extend(stores)

            if im_stores:
                self.logger.display(f"Block 4 accessible - found {len(im_stores)} IM store(s)")
                # Try to read first message from first store
                store = im_stores[0]
                messages = self.scanner.get_information_messages(
                    self.conn, store["domain"], store["name"]
                )
                if messages:
                    self.logger.display(f"  Can list messages: {len(messages)} found")
            else:
                self.logger.display("No IM stores found - Block 4 may not be enabled")
            result = {"im_stores": im_stores, "block4_accessible": len(im_stores) > 0}

        if result:
            self.results["data"]["action_result"] = result

    def cleanup(self) -> None:
        """Cleanup TASE.2 connection."""
        if self.conn:
            try:
                self.scanner.disconnect(self.conn)
                self.logger.debug("Connection closed")
            except Exception as e:
                self.logger.debug(f"Error closing connection: {e}")

    @staticmethod
    def check_dependencies() -> bool:
        """Check if pyiec61850.tase2 is available."""
        return _pyiec61850_tase2.is_available

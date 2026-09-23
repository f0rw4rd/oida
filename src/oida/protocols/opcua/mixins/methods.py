"""
OPC UA Methods Mixin

Provides method discovery, invocation, and argument parsing functionality.
"""

from typing import Dict, List

from oida.protocols.opcua.helpers import _get_asyncua

# OPC UA namespace-0 built-in DataType NodeId identifiers -> type names.
BUILTIN_TYPE_NAMES = {
    1: "Boolean",
    2: "SByte",
    3: "Byte",
    4: "Int16",
    5: "UInt16",
    6: "Int32",
    7: "UInt32",
    8: "Int64",
    9: "UInt64",
    10: "Float",
    11: "Double",
    12: "String",
    13: "DateTime",
    14: "Guid",
    15: "ByteString",
    16: "XmlElement",
    17: "NodeId",
    18: "ExpandedNodeId",
    19: "StatusCode",
    20: "QualifiedName",
    21: "LocalizedText",
    22: "ExtensionObject",
    23: "DataValue",
    24: "Variant",
    25: "DiagnosticInfo",
}


class MethodsMixin:
    """Mixin providing OPC UA method operations."""

    async def _invoke_method(self, method_node_id: str):
        """Invoke an OPC UA method"""
        # --call-method invokes arbitrary server-defined methods (Restart,
        # ResetCounters, custom site methods etc.) — gate on --confirm.
        if not self.require_confirm(
            "--call-method",
            detail=f"--call-method invokes arbitrary OPC UA method '{method_node_id}' "
            "(server-side side effects unknown) — requires --confirm",
        ):
            self.results["success"] = False
            self.results["data"]["refused"] = "--call-method requires --confirm"
            return
        import json

        ua_mod = _get_asyncua().ua

        self.logger.display(f"Calling method: {method_node_id}")

        try:
            # Parse method arguments from JSON
            raw_args = []
            if getattr(self.args, "method_args", None):
                raw_args = json.loads(self.args.method_args)

            # Find the method's parent node
            method_node = self._client.get_node(method_node_id)
            parent = await method_node.get_parent()

            if not parent:
                self.logger.fail("Could not find method parent node")
                return

            # Get InputArguments to determine types
            typed_args = []
            try:
                children = await method_node.get_children()
                for child in children:
                    name = await child.read_browse_name()
                    if name.Name == "InputArguments":
                        input_args = await child.read_value()
                        if input_args and len(raw_args) == len(input_args):
                            for i, arg_def in enumerate(input_args):
                                val = raw_args[i]
                                # Map DataType NodeId to VariantType
                                dt_id = (
                                    arg_def.DataType.Identifier
                                    if hasattr(arg_def.DataType, "Identifier")
                                    else 0
                                )
                                vtype = self._get_variant_type(dt_id)
                                if vtype:
                                    typed_args.append(ua_mod.Variant(val, vtype))
                                else:
                                    typed_args.append(val)
                        break
            except Exception as e:
                self.logger.debug(f"Could not read InputArguments: {e}")
                typed_args = raw_args  # Fall back to raw args

            # Use typed args if available, otherwise raw
            call_args = typed_args if typed_args else raw_args
            result = await parent.call_method(method_node, *call_args)
            self.logger.success(f"Method returned: {result}")
            self.results["data"]["method_result"] = str(result)

        except Exception as e:
            self.logger.debug("invoke method failed: %s", e)
            self.logger.fail(f"Method call failed: {e}")

    def _get_variant_type(self, datatype_id: int):
        """Map OPC UA DataType NodeId to VariantType."""
        ua_mod = _get_asyncua().ua
        type_map = {
            1: ua_mod.VariantType.Boolean,
            2: ua_mod.VariantType.SByte,
            3: ua_mod.VariantType.Byte,
            4: ua_mod.VariantType.Int16,
            5: ua_mod.VariantType.UInt16,
            6: ua_mod.VariantType.Int32,
            7: ua_mod.VariantType.UInt32,
            8: ua_mod.VariantType.Int64,
            9: ua_mod.VariantType.UInt64,
            10: ua_mod.VariantType.Float,
            11: ua_mod.VariantType.Double,
            12: ua_mod.VariantType.String,
            13: ua_mod.VariantType.DateTime,
            14: ua_mod.VariantType.Guid,
            15: ua_mod.VariantType.ByteString,
            17: ua_mod.VariantType.NodeId,
            20: ua_mod.VariantType.QualifiedName,
            21: ua_mod.VariantType.LocalizedText,
        }
        return type_map.get(datatype_id)

    async def _get_method_details(self, method_node) -> dict:
        """
        Get method details including description, arguments, and permissions.

        Returns:
            Dict with description, input_args, output_args, executable, user_executable
        """
        ua_mod = _get_asyncua().ua
        details = {
            "description": "",
            "input_args": [],
            "output_args": [],
            "executable": False,
            "user_executable": False,
        }

        # Read Executable and UserExecutable attributes
        try:
            exec_attr = await method_node.read_attribute(ua_mod.AttributeIds.Executable)
            details["executable"] = bool(exec_attr.Value.Value)
        except Exception as e:
            self.logger.debug("get method details failed: %s", e)
        try:
            user_exec_attr = await method_node.read_attribute(ua_mod.AttributeIds.UserExecutable)
            details["user_executable"] = bool(user_exec_attr.Value.Value)
        except Exception as e:
            self.logger.debug("get method details failed: %s", e)

        # Read method description
        try:
            desc_attr = await method_node.read_attribute(ua_mod.AttributeIds.Description)
            if desc_attr.Value.Value:
                desc_text = desc_attr.Value.Value
                # LocalizedText has Text attribute
                if hasattr(desc_text, "Text"):
                    details["description"] = desc_text.Text or ""
                else:
                    details["description"] = str(desc_text)
        except Exception as e:
            self.logger.debug("get method details failed: %s", e)

        # Get InputArguments and OutputArguments from properties
        try:
            children = await method_node.get_children()
            for child in children:
                try:
                    name = await child.read_browse_name()
                    if name.Name == "InputArguments":
                        args = await child.read_value()
                        if args:
                            for arg in args:
                                arg_info = self._parse_argument(arg)
                                details["input_args"].append(arg_info)
                    elif name.Name == "OutputArguments":
                        args = await child.read_value()
                        if args:
                            for arg in args:
                                arg_info = self._parse_argument(arg)
                                details["output_args"].append(arg_info)
                except Exception as e:
                    self.logger.debug("get method details failed: %s", e)
        except Exception as e:
            self.logger.debug("get method details failed: %s", e)

        return details

    def _parse_argument(self, arg) -> dict:
        """Parse an OPC UA Argument structure into a dict."""
        arg_info = {"name": "", "data_type": "", "description": ""}

        try:
            # Argument structure has: Name, DataType, ValueRank, ArrayDimensions, Description
            if hasattr(arg, "Name"):
                arg_info["name"] = arg.Name or ""
            if hasattr(arg, "DataType"):
                # DataType is a NodeId, resolve to name
                dt_id = arg.DataType
                if hasattr(dt_id, "Identifier") and dt_id.NamespaceIndex == 0:
                    arg_info["data_type"] = BUILTIN_TYPE_NAMES.get(dt_id.Identifier, str(dt_id))
                else:
                    arg_info["data_type"] = str(dt_id)
            if hasattr(arg, "Description") and arg.Description:
                desc = arg.Description
                if hasattr(desc, "Text"):
                    arg_info["description"] = desc.Text or ""
                else:
                    arg_info["description"] = str(desc)
        except Exception as e:
            self.logger.debug("parse argument failed: %s", e)
            pass

        return arg_info

    def _format_method_args(self, args: list) -> str:
        """Format method arguments for display."""
        if not args:
            return "()"

        parts = []
        for arg in args:
            name = arg.get("name", "?")
            dtype = arg.get("data_type", "?")
            parts.append(f"{name}:{dtype}")

        return f"({', '.join(parts)})"

    def _get_example_value(self, data_type: str):
        """Generate example value for a given OPC UA data type."""
        type_examples = {
            "Boolean": True,
            "SByte": -1,
            "Byte": 1,
            "Int16": -100,
            "UInt16": 100,
            "Int32": 42,
            "UInt32": 42,
            "Int64": 1000,
            "UInt64": 1000,
            "Float": 3.14,
            "Double": 3.14159,
            "String": "example",
            "DateTime": "2025-01-01T00:00:00Z",
            "Guid": "00000000-0000-0000-0000-000000000000",
            "ByteString": "AQID",
            "NodeId": "ns=0;i=84",
            "QualifiedName": "0:Name",
            "LocalizedText": "Example text",
        }
        return type_examples.get(data_type, 0)

    def _generate_method_example(self, method: dict) -> str:
        """Generate example CLI usage for a method."""
        import json

        node_id = method.get("node_id", "")
        input_args = method.get("input_args", [])

        if not input_args:
            return f'oida opcua <target> --call-method "{node_id}"'

        # Generate example values for each argument
        example_values = []
        for arg in input_args:
            dtype = arg.get("data_type", "Int32")
            example_values.append(self._get_example_value(dtype))

        args_json = json.dumps(example_values)
        return f"oida opcua <target> --call-method \"{node_id}\" --method-args '{args_json}'"

    async def _get_method_arguments(self, method_node) -> List[Dict]:
        """Get input argument definitions for a method."""
        args = []
        try:
            # InputArguments is typically a property of the method
            children = await method_node.get_children()
            for child in children:
                name = await child.read_browse_name()
                if name.Name == "InputArguments":
                    value = await child.read_value()
                    if value:
                        for arg in value:
                            arg_info = {
                                "name": arg.Name if hasattr(arg, "Name") else "unknown",
                            }
                            # Map common data types
                            dt_id = (
                                arg.DataType.Identifier
                                if hasattr(arg.DataType, "Identifier")
                                else None
                            )
                            arg_info["type_id"] = dt_id
                            arg_info["type_name"] = self._get_type_name(dt_id)
                            args.append(arg_info)
        except Exception as e:
            self.logger.debug("get method arguments failed: %s", e)
            pass
        return args

    def _get_type_name(self, type_id: int) -> str:
        """Map OPC UA type ID to type name."""
        return BUILTIN_TYPE_NAMES.get(type_id, f"Unknown({type_id})")

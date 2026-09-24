"""
OPC UA Fuzz Mixin

Provides fuzzing functionality for nodes and methods.
"""

import asyncio
import os
import struct
from typing import Dict, List, Optional

from oida.protocols.opcua.helpers import _get_asyncua, ua


class FuzzMixin:
    """Mixin providing OPC UA fuzzing operations."""

    async def _handle_fuzz(self) -> None:
        """Handle fuzzing operations for OPC UA nodes and methods"""
        # Check confirmation
        if not self.require_confirm(
            "--confirm", detail="Fuzzing requires --confirm flag (writes to device)"
        ):
            self.logger.display("Use: oida opcua <target> --fuzz [nodes|methods|all] --confirm")
            return

        # --fuzz is declared as action='store_true' so args.fuzz is a bool,
        # not a string. The old code did fuzz_mode = getattr(args, 'fuzz',
        # 'nodes') and then tested `fuzz_mode in ('nodes', 'all')` — True
        # is never in that tuple so the whole module did nothing. Fall
        # back to an explicit --fuzz-mode if present, else 'nodes'.
        raw = getattr(self.args, "fuzz", False)
        if isinstance(raw, str) and raw:
            fuzz_mode = raw
        else:
            fuzz_mode = getattr(self.args, "fuzz_mode", "nodes") or "nodes"
        iterations = getattr(self.args, "fuzz_iterations", 10)
        specific_node = getattr(self.args, "fuzz_node", None)
        specific_method = getattr(self.args, "fuzz_method", None)
        max_targets = getattr(self.args, "fuzz_max_targets", 10)

        self.logger.display(
            f"Starting OPC UA fuzzing (mode: {fuzz_mode}, iterations: {iterations})"
        )

        total_stats = {"tests": 0, "calls": 0, "writes": 0, "anomalies": 0, "crashes": 0}

        # Fuzz variable nodes
        if fuzz_mode in ("nodes", "all") and not specific_method:
            if specific_node:
                result = await self._fuzz_node(specific_node, iterations)
                if result:
                    for k in ["tests", "writes", "anomalies", "crashes"]:
                        total_stats[k] += result.get(k, 0)
            else:
                writable_nodes = await self._find_writable_nodes()
                if writable_nodes:
                    self.logger.display(f"Found {len(writable_nodes)} writable nodes")
                    for node_info in writable_nodes[:max_targets]:
                        node_id = node_info["node_id"]
                        self.logger.display(
                            f"\nFuzzing: {node_id} ({node_info.get('name', 'unknown')})"
                        )
                        result = await self._fuzz_node(node_id, iterations)
                        if result:
                            for k in ["tests", "writes", "anomalies", "crashes"]:
                                total_stats[k] += result.get(k, 0)
                elif fuzz_mode == "nodes":
                    self.logger.display("No writable variable nodes found")

        # Fuzz methods
        if fuzz_mode in ("methods", "all") or specific_method:
            if specific_method:
                result = await self._fuzz_method(specific_method, iterations)
                if result:
                    for k in ["tests", "calls", "anomalies", "crashes"]:
                        total_stats[k] += result.get(k, 0)
            else:
                methods = await self._find_callable_methods()
                if methods:
                    self.logger.display(f"\nFound {len(methods)} callable methods")
                    for method_info in methods[:max_targets]:
                        method_id = method_info["node_id"]
                        self.logger.display(
                            f"\nFuzzing method: {method_id} ({method_info.get('name', 'unknown')})"
                        )
                        result = await self._fuzz_method(method_id, iterations, method_info)
                        if result:
                            for k in ["tests", "calls", "anomalies", "crashes"]:
                                total_stats[k] += result.get(k, 0)
                elif fuzz_mode == "methods":
                    self.logger.display("No callable methods found")

        # Summary
        self.logger.display("\n=== Fuzzing Summary ===")
        self.logger.display(
            f"Tests: {total_stats['tests']}, Calls: {total_stats['calls']}, "
            f"Writes: {total_stats['writes']}, Anomalies: {total_stats['anomalies']}, "
            f"Crashes: {total_stats['crashes']}"
        )

    async def _fuzz_node(self, node_id: str, iterations: int) -> Optional[Dict]:
        """Fuzz a single OPC UA variable node"""
        from oida.utils.fuzzer import fuzz

        try:
            node = self._client.get_node(node_id)

            node_class = await node.read_node_class()
            if node_class != ua.NodeClass.Variable:
                self.logger.warning(f"Node {node_id} is not a Variable, skipping")
                return None

            # Determine Float (32-bit) vs Double (64-bit) so a Double node's
            # captured value is not silently round-tripped through float32,
            # which would write a precision-truncated value back on restore.
            try:
                _variant_type = await node.read_data_type_as_variant_type()
            except Exception:
                _variant_type = None
            is_double = _variant_type == ua.VariantType.Double
            _float_fmt = "<d" if is_double else "<f"
            _float_width = 8 if is_double else 4

            # Integers need the same treatment as floats above: a hardcoded
            # 4-byte signed encoding raises OverflowError for any UInt32 >= 2**31
            # (counters, IDs, timestamps) and for every Int64/UInt64, which the
            # caller's except-block turns into "node silently not fuzzed"; it
            # also narrows an Int64 on restore (5000000000 -> 705032704).
            _INT_WIDTHS = {
                ua.VariantType.SByte: (1, True),
                ua.VariantType.Byte: (1, False),
                ua.VariantType.Int16: (2, True),
                ua.VariantType.UInt16: (2, False),
                ua.VariantType.Int32: (4, True),
                ua.VariantType.UInt32: (4, False),
                ua.VariantType.Int64: (8, True),
                ua.VariantType.UInt64: (8, False),
            }
            _int_width, _int_signed = _INT_WIDTHS.get(_variant_type, (4, True))

            def encode_value(value) -> bytes:
                """Encode a typed OPC UA value to its canonical byte form."""
                if isinstance(value, bytes):
                    return value
                elif isinstance(value, str):
                    return value.encode("utf-8")
                elif isinstance(value, bool):
                    return bytes([1 if value else 0])
                elif isinstance(value, int):
                    try:
                        return value.to_bytes(_int_width, byteorder="little", signed=_int_signed)
                    except OverflowError:
                        # Value does not fit the node's declared width (server
                        # reported a narrower type than it serves). Wrap rather
                        # than abort the whole node.
                        mask = (1 << (8 * _int_width)) - 1
                        return (value & mask).to_bytes(_int_width, byteorder="little")
                elif isinstance(value, float):
                    return struct.pack(_float_fmt, value)
                elif value is None:
                    return b""
                else:
                    return bytes(str(value), "utf-8")

            def decode_value(data: bytes, template):
                """Decode raw fuzz bytes into a typed value matching `template`."""
                if isinstance(template, bool):
                    return bool(data[0]) if data else False
                elif isinstance(template, int):
                    return int.from_bytes(
                        data[:_int_width].ljust(_int_width, b"\x00"),
                        byteorder="little",
                        signed=_int_signed,
                    )
                elif isinstance(template, float):
                    return (
                        struct.unpack(_float_fmt, data[:_float_width].ljust(_float_width, b"\x00"))[
                            0
                        ]
                        if len(data) >= _float_width
                        else 0.0
                    )
                elif isinstance(template, str):
                    return data.decode("utf-8", errors="replace")
                else:
                    return data

            async def read_value():
                return encode_value(await node.read_value())

            async def write_value(data: bytes):
                """Write fuzz bytes; return the typed value written, or None on failure.

                Returning the typed value lets the caller re-encode it the same way
                read_value() does and compare like-with-like, instead of comparing a
                re-encoded readback against the raw pre-encoding payload bytes.
                """
                try:
                    template = await node.read_value()
                    value = decode_value(data, template)
                    await node.write_value(value)
                    return value
                except Exception as e:
                    self.logger.debug("write value failed: %s", e)
                    return None

            original = await read_value()
            successful, failed, anomalies, crashes = 0, 0, 0, 0

            for payload, _desc in fuzz(
                original, count=iterations
            ):  # fuzz() yields (bytes, desc) tuples
                try:
                    written = await write_value(payload)
                    if written is not None:
                        successful += 1
                        # Compare like-with-like: re-encode the value we actually
                        # wrote (after write_value decoded the raw payload) and
                        # compare it against the re-encoded readback. Comparing the
                        # raw payload bytes here would flag almost every faithful
                        # int/float/str write as a false anomaly, since the typed
                        # round-trip rarely reproduces the original byte string.
                        expected = encode_value(written)
                        readback = await read_value()
                        if readback != expected and readback != original:
                            anomalies += 1
                    else:
                        failed += 1
                except Exception as e:
                    self.logger.debug("write value failed: %s", e)
                    crashes += 1
                await asyncio.sleep(0.1)

            # Restore original. read_value() always returns bytes (b"" for an
            # empty/None-valued node), so guard on `is not None`, not truthiness,
            # to avoid leaving an empty-but-valid node holding the last payload.
            restore_failures = 0
            if original is not None:
                restored = await write_value(original)
                if restored is None:
                    restore_failures = 1
                    self.logger.fail(
                        f"Failed to restore original value on {node_id} after fuzzing "
                        f"(device left in modified state, original value: {original!r})"
                    )

            status = "+" if crashes == 0 and anomalies == 0 else "!"
            self.logger.display(
                f"  [{status}] {node_id}: {successful + failed} tests, "
                f"{successful} writes, {anomalies} anomalies, {crashes} crashes"
            )

            return {
                "tests": successful + failed,
                "writes": successful,
                "anomalies": anomalies,
                "crashes": crashes,
                "restore_failures": restore_failures,
            }

        except Exception as e:
            self.logger.debug("write value failed: %s", e)
            self.logger.fail(f"Error fuzzing node {node_id}: {e}")
            return None

    async def _find_writable_nodes(self) -> List[Dict[str, str]]:
        """Find writable variable nodes in the address space.

        Uses AccessLevel attribute as a pre-filter, then verifies actual write
        capability for fuzzing purposes.
        """
        writable_nodes = []
        objects = self._client.get_objects_node()

        async def search(node, depth=0):
            if depth > 3 or len(writable_nodes) >= 50:
                return

            try:
                children = await node.get_children()
                for child in children:
                    try:
                        node_class = await child.read_node_class()
                        if node_class == ua.NodeClass.Variable:
                            # First check AccessLevel (fast pre-filter)
                            try:
                                access = await child.read_attribute(ua.AttributeIds.UserAccessLevel)
                                level = access.Value.Value
                                can_write = (level & 0x02) != 0

                                if can_write:
                                    # Verify actual write works (for fuzzing)
                                    try:
                                        current = await child.read_value()
                                        await child.write_value(current)
                                        name = await child.read_browse_name()
                                        writable_nodes.append(
                                            {
                                                "node_id": str(child.nodeid),
                                                "name": name.Name,
                                            }
                                        )
                                    except Exception as e:
                                        self.logger.debug("search failed: %s", e)
                                        pass  # AccessLevel says writable but write failed
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
        return writable_nodes

    async def _find_callable_methods(self) -> List[Dict]:
        """Find callable methods in the address space."""
        methods = []
        objects = self._client.get_objects_node()

        async def search(node, parent=None, depth=0):
            if depth > 4 or len(methods) >= 50:
                return

            try:
                children = await node.get_children()
                for child in children:
                    try:
                        node_class = await child.read_node_class()
                        if node_class == ua.NodeClass.Method:
                            # Check if executable
                            try:
                                executable = await child.read_attribute(ua.AttributeIds.Executable)
                                user_exec = await child.read_attribute(
                                    ua.AttributeIds.UserExecutable
                                )
                                if executable.Value.Value and user_exec.Value.Value:
                                    name = await child.read_browse_name()
                                    # Get input arguments
                                    input_args = await self._get_method_arguments(child)
                                    methods.append(
                                        {
                                            "node_id": child.nodeid.to_string(),
                                            "name": name.Name,
                                            "parent": parent.nodeid.to_string() if parent else None,
                                            "input_args": input_args,
                                        }
                                    )
                            except Exception as e:
                                self.logger.debug("search failed: %s", e)
                                pass
                        else:
                            await search(child, child, depth + 1)
                    except Exception as e:
                        self.logger.debug("search failed: %s", e)
                        pass
            except Exception as e:
                self.logger.debug("search failed: %s", e)
                pass

        await search(objects)
        return methods

    def _generate_fuzz_value(self, type_id: int, iteration: int):
        """Generate a fuzz value for a given OPC UA type."""
        # NOTE: random module is acceptable here - fuzzing values don't require
        # cryptographic randomness, just variety in test inputs
        import random

        # Boolean (1)
        if type_id == 1:
            return [True, False, True, False][iteration % 4]

        # Integer types
        elif type_id == 2:  # SByte
            cases = [0, -1, 127, -128, random.randint(-128, 127)]
            return cases[iteration % len(cases)]
        elif type_id == 3:  # Byte
            cases = [0, 255, 1, 128, random.randint(0, 255)]
            return cases[iteration % len(cases)]
        elif type_id == 4:  # Int16
            cases = [0, -1, 32767, -32768, random.randint(-32768, 32767)]
            return cases[iteration % len(cases)]
        elif type_id == 5:  # UInt16
            cases = [0, 65535, 1, 32768, random.randint(0, 65535)]
            return cases[iteration % len(cases)]
        elif type_id == 6:  # Int32
            cases = [0, -1, 2147483647, -2147483648, random.randint(-(2**31), 2**31 - 1)]
            return cases[iteration % len(cases)]
        elif type_id == 7:  # UInt32
            cases = [0, 4294967295, 1, 2147483648, random.randint(0, 2**32 - 1)]
            return cases[iteration % len(cases)]
        elif type_id == 8:  # Int64
            cases = [0, -1, 2**63 - 1, -(2**63), random.randint(-(2**63), 2**63 - 1)]
            return cases[iteration % len(cases)]
        elif type_id == 9:  # UInt64
            cases = [0, 2**64 - 1, 1, 2**63, random.randint(0, 2**64 - 1)]
            return cases[iteration % len(cases)]

        # Float types
        elif type_id == 10:  # Float
            cases = [
                0.0,
                -1.0,
                1.0,
                float("inf"),
                float("-inf"),
                float("nan"),
                3.4028235e38,
                -3.4028235e38,
                1.17549435e-38,
                random.uniform(-1e6, 1e6),
            ]
            return cases[iteration % len(cases)]
        elif type_id == 11:  # Double
            cases = [
                0.0,
                -1.0,
                1.0,
                float("inf"),
                float("-inf"),
                float("nan"),
                1.7976931348623157e308,
                -1.7976931348623157e308,
                random.uniform(-1e100, 1e100),
            ]
            return cases[iteration % len(cases)]

        # String (12)
        elif type_id == 12:
            cases = [
                "",  # Empty
                "A" * 1000,  # Long string
                "A" * 65536,  # Very long
                "\x00\x00\x00",  # Null bytes
                "%s%s%s%n%n%n",  # Format string
                "{{{{{{{{",  # Template injection
                "<script>alert(1)</script>",  # XSS
                "'; DROP TABLE users; --",  # SQL injection
                "../../../etc/passwd",  # Path traversal
                "\xff\xfe",  # Invalid UTF-8
                "A" * iteration,  # Variable length
                "\n" * 100,  # Newlines
                "\t" * 100,  # Tabs
            ]
            return cases[iteration % len(cases)]

        # DateTime (13)
        elif type_id == 13:
            from datetime import datetime

            cases = [
                datetime.now(),
                datetime(1970, 1, 1),  # Unix epoch
                datetime(1601, 1, 1),  # Windows epoch
                datetime(9999, 12, 31, 23, 59, 59),  # Max date
                datetime(1, 1, 1),  # Min date
            ]
            return cases[iteration % len(cases)]

        # ByteString (15)
        elif type_id == 15:
            cases = [
                b"",  # Empty
                b"\x00" * 100,  # Null bytes
                b"\xff" * 100,  # All 0xFF
                bytes(range(256)),  # All bytes
                b"A" * 65536,  # Large
                os.urandom(100),  # Random
            ]
            return cases[iteration % len(cases)]

        # NodeId (17)
        elif type_id == 17:
            ua_mod = _get_asyncua().ua
            cases = [
                ua_mod.NodeId(0, 0),  # Null
                ua_mod.NodeId(85, 0),  # Objects
                ua_mod.NodeId(2147483647, 0),  # Max int
                ua_mod.NodeId(0, 65535),  # Max namespace
            ]
            return cases[iteration % len(cases)]

        # Default: try various types
        else:
            cases = [0, "", None, [], {}, True, False, -1, 2**31]
            return cases[iteration % len(cases)]

    async def _fuzz_method(
        self, method_id: str, iterations: int, method_info: Dict = None
    ) -> Optional[Dict]:
        """Fuzz a single OPC UA method with various argument payloads."""
        result = {"tests": 0, "calls": 0, "anomalies": 0, "crashes": 0}

        try:
            method_node = self._client.get_node(method_id)

            # Get parent node (methods need to be called on their parent object)
            parent_id = method_info.get("parent") if method_info else None
            if not parent_id:
                # Try to find parent via inverse HasComponent reference
                refs = await method_node.get_references(direction=ua.BrowseDirection.Inverse)
                for ref in refs:
                    # ReferenceTypeId is a NodeId, compare the Identifier
                    if (
                        hasattr(ref.ReferenceTypeId, "Identifier")
                        and ref.ReferenceTypeId.Identifier == ua.ObjectIds.HasComponent
                    ):
                        parent_id = ref.NodeId.to_string()
                        break

            if not parent_id:
                self.logger.warning(f"  Cannot find parent object for method {method_id}")
                return result

            parent_node = self._client.get_node(parent_id)

            # Get input arguments
            input_args = method_info.get("input_args", []) if method_info else []
            if not input_args:
                input_args = await self._get_method_arguments(method_node)

            arg_count = len(input_args)
            self.logger.display(f"  Method has {arg_count} input argument(s)")

            if arg_count > 0:
                for arg in input_args:
                    self.logger.display(
                        f"    - {arg.get('name', '?')}: {arg.get('type_name', '?')}"
                    )

            # Fuzz the method
            for i in range(iterations):
                result["tests"] += 1

                # Generate fuzz arguments
                fuzz_args = []
                for arg in input_args:
                    type_id = arg.get("type_id", 12)  # Default to String
                    fuzz_val = self._generate_fuzz_value(type_id, i)
                    fuzz_args.append(fuzz_val)

                # Also test with wrong number of arguments
                if i == iterations - 1 and arg_count > 0:
                    # Too few args
                    fuzz_args = fuzz_args[:-1] if fuzz_args else []
                elif i == iterations - 2:
                    # Too many args
                    fuzz_args.append(self._generate_fuzz_value(12, i))

                try:
                    # Call the method
                    await parent_node.call_method(method_node, *fuzz_args)
                    result["calls"] += 1
                except ua.UaStatusCodeError as e:
                    # Expected errors from invalid inputs
                    status = str(e.code) if hasattr(e, "code") else str(e)
                    if "BadInvalidArgument" in status or "BadTypeMismatch" in status:
                        pass  # Expected
                    elif "BadOutOfRange" in status or "BadUnexpectedError" in status:
                        result["anomalies"] += 1
                        self.logger.warning(f"    [!] Anomaly on iteration {i}: {status}")
                except Exception as e:
                    self.logger.debug("fuzz method failed: %s", e)
                    err = str(e)[:50]
                    if "timeout" in err.lower() or "disconnect" in err.lower():
                        result["crashes"] += 1
                        self.logger.fail(f"    [!!] Potential crash on iteration {i}: {err}")
                    else:
                        result["anomalies"] += 1

                await asyncio.sleep(0.05)  # Rate limit

            status = "+" if result["crashes"] == 0 else "!"
            self.logger.display(
                f"  [{status}] {method_id}: {result['tests']} tests, "
                f"{result['calls']} successful, {result['anomalies']} anomalies, "
                f"{result['crashes']} crashes"
            )

        except Exception as e:
            self.logger.debug("fuzz method failed: %s", e)
            self.logger.fail(f"Error fuzzing method {method_id}: {e}")

        return result

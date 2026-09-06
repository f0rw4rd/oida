"""
OPC UA Files Mixin

Provides file transfer operations (read/write/dump) for OPC UA FileType nodes.
"""

from ..helpers import ua

# Default ceiling on the total bytes pulled from a server-advertised FileType
# node, to bound memory growth when the server reports/streams an arbitrarily
# large file. Override per-invocation via args.max_read_bytes.
DEFAULT_MAX_READ_BYTES = 64 * 1024 * 1024  # 64 MiB


class FilesMixin:
    """Mixin providing OPC UA file transfer operations."""

    async def _dump_files(self):
        """Dump all FileType nodes in the address space."""
        self.logger.display("Dumping file nodes (FileType and file-like objects)...")

        file_nodes = []
        objects = self._client.get_objects_node()
        max_depth = getattr(self.args, "max_depth", 4)
        max_nodes = getattr(self.args, "max_nodes", 500)

        async def is_file_like(node):
            """Check if a node looks like a file (has Size and/or Writable children)."""
            try:
                children = await node.get_children()
                child_names = []
                for child in children:
                    name = await child.read_browse_name()
                    child_names.append(name.Name)
                # File-like if it has Size or Writable
                return "Size" in child_names or "Writable" in child_names
            except Exception as e:
                self.logger.debug("is file like failed: %s", e)
                return False

        async def search(node, depth=0):
            if depth > max_depth or len(file_nodes) >= max_nodes:
                return

            try:
                children = await node.get_children()
                for child in children:
                    try:
                        node_class = await child.read_node_class()
                        is_file = False
                        name = await child.read_browse_name()

                        # Check for standard FileType
                        if node_class == ua.NodeClass.Object:
                            try:
                                type_def = await child.read_type_definition()
                                if type_def and type_def.Identifier == ua.ObjectIds.FileType:
                                    is_file = True
                            except Exception as e:
                                self.logger.debug("search failed: %s", e)
                                pass

                            # Also check for file-like objects (have Size/Writable properties)
                            if not is_file:
                                # Check if name looks like a file (has extension)
                                if "." in name.Name:
                                    is_file = await is_file_like(child)

                        if is_file:
                            # Try to get file size
                            size = None
                            try:
                                size_node = await child.get_child("0:Size")
                                size = await size_node.read_value()
                            except Exception as e:
                                self.logger.debug("search failed: %s", e)
                                try:
                                    # Try namespace 2
                                    for sub in await child.get_children():
                                        sub_name = await sub.read_browse_name()
                                        if sub_name.Name == "Size":
                                            size = await sub.read_value()
                                            break
                                except Exception as e:
                                    self.logger.debug("search failed: %s", e)
                                    pass

                            # Try to get writable status
                            writable = None
                            try:
                                writable_node = await child.get_child("0:Writable")
                                writable = await writable_node.read_value()
                            except Exception as e:
                                self.logger.debug("search failed: %s", e)
                                try:
                                    # Try namespace 2
                                    for sub in await child.get_children():
                                        sub_name = await sub.read_browse_name()
                                        if sub_name.Name == "Writable":
                                            writable = await sub.read_value()
                                            break
                                except Exception as e:
                                    self.logger.debug("search failed: %s", e)
                                    pass

                            file_nodes.append(
                                {
                                    "node_id": child.nodeid.to_string(),
                                    "name": name.Name,
                                    "size": size,
                                    "writable": writable,
                                }
                            )

                        await search(child, depth + 1)
                    except Exception as e:
                        self.logger.debug("search failed: %s", e)
                        pass
            except Exception as e:
                self.logger.debug("search failed: %s", e)
                pass

        await search(objects)

        if file_nodes:
            self.logger.success(f"Found {len(file_nodes)} FileType nodes")

            self.logger.display("+--------------------+----------------+-----------+----------+")
            self.logger.display("|        Name        |     Node ID    |    Size   | Writable |")
            self.logger.display("+--------------------+----------------+-----------+----------+")

            for file_info in file_nodes:
                name = file_info["name"][:18]
                node_id = file_info["node_id"][:14]
                size = str(file_info["size"])[:9] if file_info["size"] is not None else "?"
                writable = (
                    "Yes"
                    if file_info["writable"]
                    else ("No" if file_info["writable"] is False else "?")
                )

                self.logger.display(f"| {name:18} | {node_id:14} | {size:9} | {writable:8} |")

            self.logger.display("+--------------------+----------------+-----------+----------+")

            # Show security warning
            writable_count = sum(1 for f in file_nodes if f["writable"])
            if writable_count > 0:
                self.logger.highlight(
                    f"  [!] {writable_count} writable file(s) found - potential attack vector"
                )

            self.results["data"]["file_nodes"] = file_nodes
        else:
            self.logger.warning("No FileType nodes found in address space")

    async def _read_file(self):
        """Read/download a file from a FileType node."""
        file_node_id = getattr(self.args, "read_file", None)
        if not file_node_id:
            return

        try:
            file_node = self._client.get_node(file_node_id)
            file_name = await file_node.read_browse_name()

            self.logger.display(f"Reading file from {file_name.Name} ({file_node_id})")

            # Get file size first
            try:
                size_node = await file_node.get_child("0:Size")
                file_size = await size_node.read_value()
                self.logger.display(f"  File size: {file_size} bytes")
            except Exception:
                file_size = None
                self.logger.debug("Could not read file size")

            # Get Open method
            try:
                open_method = await file_node.get_child("0:Open")
                read_method = await file_node.get_child("0:Read")
                close_method = await file_node.get_child("0:Close")
            except Exception as e:
                self.logger.debug("read file failed: %s", e)
                self.logger.fail(f"Could not find file methods: {e}")
                return

            # Open file for reading (mode = 1 = Read)
            try:
                file_handle = await file_node.call_method(open_method, ua.Byte(1))
                self.logger.debug(f"File opened with handle: {file_handle}")
            except ua.UaStatusCodeError as e:
                self.logger.debug("read file failed: %s", e)
                if "BadNotReadable" in str(e):
                    self.logger.fail("File not readable (access denied)")
                elif "BadUserAccessDenied" in str(e):
                    self.logger.fail("Access denied - authentication required")
                else:
                    self.logger.fail(f"Failed to open file: {e}")
                return

            # Read file content
            try:
                # Read in chunks (max 4KB per read typically)
                file_content = b""
                chunk_size = 4096

                # Cap the total read to bound memory growth: the server-advertised
                # Size is untrusted, so we never let an unbounded/oversized stream
                # accumulate in RAM.
                max_read_bytes = getattr(self.args, "max_read_bytes", None)
                if not max_read_bytes or max_read_bytes <= 0:
                    max_read_bytes = DEFAULT_MAX_READ_BYTES
                truncated = False

                # The OPC UA Read method may return fewer bytes than requested
                # without signalling EOF (e.g. on server buffer boundaries), so
                # we only stop on an empty/None chunk, never on a short read.
                while True:
                    chunk = await file_node.call_method(read_method, file_handle, chunk_size)
                    if not chunk:
                        break
                    file_content += bytes(chunk)
                    if len(file_content) >= max_read_bytes:
                        truncated = True
                        self.logger.fail(
                            f"File exceeds max read size ({max_read_bytes} bytes) - "
                            "aborting read to bound memory use"
                        )
                        break

                if truncated:
                    # Close handle and abort without storing the partial blob.
                    try:
                        await file_node.call_method(close_method, file_handle)
                    except Exception as e:
                        self.logger.debug("read file failed: %s", e)
                    return

                self.logger.success(f"Read {len(file_content)} bytes")

                # Close file
                await file_node.call_method(close_method, file_handle)

                # Output file
                output_path = getattr(self.args, "file_output", None)
                if output_path:
                    from oida.utils.common_types import safe_file_path

                    try:
                        safe_path = safe_file_path(output_path)
                    except ValueError as e:
                        self.logger.fail(str(e))
                        return
                    with open(safe_path, "wb") as f:
                        f.write(file_content)
                    self.logger.success(f"File saved to: {safe_path}")
                else:
                    # Display content (if text-like)
                    try:
                        text_content = file_content.decode("utf-8")
                        self.logger.display("--- File Content ---")
                        for line in text_content.split("\n")[:50]:
                            self.logger.display(line)
                        if text_content.count("\n") > 50:
                            self.logger.display(
                                f"... ({text_content.count(chr(10)) - 50} more lines)"
                            )
                        self.logger.display("--- End Content ---")
                    except UnicodeDecodeError as e:
                        self.logger.debug("read file failed: %s", e)
                        self.logger.display(f"Binary content ({len(file_content)} bytes)")
                        self.logger.display(f"  First 64 bytes (hex): {file_content[:64].hex()}")

                self.results["data"]["file_read"] = {
                    "node_id": file_node_id,
                    "name": file_name.Name,
                    "size": len(file_content),
                    "content_preview": file_content[:256].hex() if len(file_content) > 0 else None,
                }

            except Exception as e:
                self.logger.debug("read file failed: %s", e)
                self.logger.fail(f"Error reading file: {e}")
                # Try to close the file handle
                try:
                    await file_node.call_method(close_method, file_handle)
                except Exception as e:
                    self.logger.debug("read file failed: %s", e)
                    pass

        except Exception as e:
            self.logger.debug("read file failed: %s", e)
            self.logger.fail(f"Error accessing file node: {e}")

    async def _write_file(self):
        """Write/upload a file to a FileType node."""
        import os

        file_node_id = getattr(self.args, "write_file", None)
        if not file_node_id:
            return

        # Safety check
        if not getattr(self.args, "confirm", False):
            self.logger.fail("--write-file requires --confirm flag (dangerous operation)")
            return

        file_data = getattr(self.args, "file_data", None)
        if not file_data:
            self.logger.fail("--write-file requires --file-data (path or content)")
            return

        try:
            file_node = self._client.get_node(file_node_id)
            file_name = await file_node.read_browse_name()

            # Check if writable
            try:
                writable_node = await file_node.get_child("0:Writable")
                writable = await writable_node.read_value()
                if not writable:
                    self.logger.fail(f"File {file_name.Name} is not writable")
                    return
            except Exception:
                self.logger.warning("Could not verify writable status, attempting write anyway")

            # Get content to write
            if os.path.isfile(file_data):
                with open(file_data, "rb") as f:
                    content = f.read()
                self.logger.display(f"Uploading file: {file_data} ({len(content)} bytes)")
            else:
                content = file_data.encode("utf-8")
                self.logger.display(f"Writing data: {len(content)} bytes")

            self.logger.highlight(f"[!] WRITING to {file_name.Name} ({file_node_id})")

            # Get file methods
            try:
                open_method = await file_node.get_child("0:Open")
                write_method = await file_node.get_child("0:Write")
                close_method = await file_node.get_child("0:Close")
            except Exception as e:
                self.logger.debug("write file failed: %s", e)
                self.logger.fail(f"Could not find file methods: {e}")
                return

            # Open file for writing (mode = 2 = Write, mode = 6 = Write+EraseExisting)
            try:
                file_handle = await file_node.call_method(open_method, ua.Byte(6))
                self.logger.debug(f"File opened for writing with handle: {file_handle}")
            except ua.UaStatusCodeError as e:
                self.logger.debug("write file failed: %s", e)
                if "BadNotWritable" in str(e):
                    self.logger.fail("File not writable (access denied)")
                elif "BadUserAccessDenied" in str(e):
                    self.logger.fail("Access denied - authentication required")
                else:
                    self.logger.fail(f"Failed to open file for writing: {e}")
                return

            # Write content in chunks
            try:
                chunk_size = 4096
                bytes_written = 0

                for i in range(0, len(content), chunk_size):
                    chunk = content[i : i + chunk_size]
                    await file_node.call_method(write_method, file_handle, chunk)
                    bytes_written += len(chunk)

                # Close file
                await file_node.call_method(close_method, file_handle)

                self.logger.success(f"Wrote {bytes_written} bytes to {file_name.Name}")

                self.results["data"]["file_write"] = {
                    "node_id": file_node_id,
                    "name": file_name.Name,
                    "bytes_written": bytes_written,
                    "success": True,
                }

            except Exception as e:
                self.logger.debug("write file failed: %s", e)
                self.logger.fail(f"Error writing file: {e}")
                # Try to close the file handle
                try:
                    await file_node.call_method(close_method, file_handle)
                except Exception as e:
                    self.logger.debug("write file failed: %s", e)
                    pass

        except Exception as e:
            self.logger.debug("write file failed: %s", e)
            self.logger.fail(f"Error accessing file node: {e}")

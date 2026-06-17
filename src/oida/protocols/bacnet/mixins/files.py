"""
BACnet Files Mixin

Handles file enumeration and AtomicReadFile operations.
"""

import asyncio

from ..constants import _load_bacpypes3


class FilesMixin:
    """Mixin providing BACnet file operations."""

    async def _bacpypes3_enumerate_files(self, app, target_addr, device_id: int, timeout: float):
        """Enumerate file objects using bacpypes3"""
        types = _load_bacpypes3()
        ReadPropertyRequest = types["ReadPropertyRequest"]
        ObjectIdentifier = types["ObjectIdentifier"]
        PropertyIdentifier = types["PropertyIdentifier"]
        CharacterString = types["CharacterString"]
        Unsigned = types["Unsigned"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]

        self.logger.display("\n[File Objects]")

        # Get file instances from enumerated objects
        file_instances = []
        if device_id in self.objects and "file" in self.objects[device_id]:
            file_instances = self.objects[device_id]["file"]
        else:
            file_instances = [1]  # Common default

        for instance in file_instances:
            self.logger.display(f"\n  File:{instance}")
            obj_id = ObjectIdentifier(("file", instance))

            file_props = [
                ("objectName", "Name"),
                ("description", "Description"),
                ("fileType", "Type"),
                ("fileSize", "Size"),
                ("fileAccessMethod", "Access Method"),
                ("readOnly", "Read Only"),
                ("archive", "Archive"),
            ]

            for prop_name, display_name in file_props:
                try:
                    request = ReadPropertyRequest(
                        objectIdentifier=obj_id,
                        propertyIdentifier=PropertyIdentifier(prop_name),
                    )
                    request.pduDestination = target_addr

                    try:
                        response = await asyncio.wait_for(
                            app.request(request), timeout=min(timeout, 3.0)
                        )
                    except BaseException as e:
                        self.logger.debug(f"bacpypes3 enumerate files failed: {e}")
                        continue

                    if response and not isinstance(
                        response, (AbortPDU, ErrorPDU, RejectPDU, Error)
                    ):
                        pv = getattr(response, "propertyValue", None)
                        value = None
                        if pv is not None and hasattr(pv, "cast_out"):
                            for cast_type in (CharacterString, Unsigned):
                                try:
                                    decoded = pv.cast_out(cast_type)
                                except BaseException as e:
                                    self.logger.debug(
                                        f"bacpypes3 enumerate files failed: {e}"
                                    )
                                    continue
                                if decoded is not None and decoded != "":
                                    value = (
                                        str(decoded).strip()
                                        if cast_type is CharacterString
                                        else decoded
                                    )
                                    break

                        if value:
                                if prop_name == "fileSize":
                                    self.logger.display(f"    {display_name}: {value} bytes")
                                elif prop_name == "readOnly":
                                    self.logger.display(
                                        f"    {display_name}: {'Yes' if value else 'No'}"
                                    )
                                else:
                                    self.logger.display(f"    {display_name}: {value}")

                except BaseException as e:
                    self.logger.debug(f"bacpypes3 enumerate files failed: {e}")
                    continue

    async def _bacpypes3_read_file(self, app, target_addr, file_instance: int, timeout: float):
        """Read file content using AtomicReadFile"""
        types = _load_bacpypes3()
        ReadPropertyRequest = types["ReadPropertyRequest"]
        ObjectIdentifier = types["ObjectIdentifier"]
        PropertyIdentifier = types["PropertyIdentifier"]
        Unsigned = types["Unsigned"]

        self.logger.display(f"\n[Reading File:{file_instance}]")

        try:
            obj_id = ObjectIdentifier(("file", file_instance))

            # Get file size first
            request = ReadPropertyRequest(
                objectIdentifier=obj_id,
                propertyIdentifier=PropertyIdentifier("fileSize"),
            )
            request.pduDestination = target_addr

            try:
                response = await asyncio.wait_for(app.request(request), timeout=timeout)
                file_size = 0
                pv = getattr(response, "propertyValue", None)
                if pv is not None and hasattr(pv, "cast_out"):
                    try:
                        file_size = int(pv.cast_out(Unsigned))
                    except BaseException as e:
                        self.logger.debug(f"bacpypes3 read file size decode failed: {e}")
                self.logger.display(f"  File size: {file_size} bytes")
            except BaseException as e:
                self.logger.warning(f"  Could not read file size: {e}")
                file_size = 1024  # Try default

            # Try to read file content using AtomicReadFile
            AtomicReadFileRequest = types["AtomicReadFileRequest"]
            AbortPDU = types["AbortPDU"]
            ErrorPDU = types["ErrorPDU"]
            RejectPDU = types["RejectPDU"]
            Error = types["Error"]

            self.logger.display("  Attempting to read file content via AtomicReadFile...")

            # Determine access method
            access_method = getattr(self.args, "file_access_method", "stream")
            chunk_size = getattr(self.args, "file_chunk_size", 1024)
            output_path = getattr(self.args, "output", None)

            all_data = bytearray()
            offset = 0
            max_reads = (file_size // chunk_size) + 2 if file_size > 0 else 10

            for read_num in range(max_reads):
                try:
                    if access_method == "stream":
                        request = AtomicReadFileRequest(
                            fileIdentifier=obj_id,
                            accessMethod={
                                "streamAccess": {
                                    "fileStartPosition": offset,
                                    "requestedOctetCount": chunk_size,
                                }
                            },
                        )
                    else:
                        request = AtomicReadFileRequest(
                            fileIdentifier=obj_id,
                            accessMethod={
                                "recordAccess": {
                                    "fileStartRecord": offset,
                                    "requestedRecordCount": min(chunk_size, 100),
                                }
                            },
                        )
                    request.pduDestination = target_addr

                    try:
                        response = await asyncio.wait_for(
                            app.request(request), timeout=min(timeout, 5.0)
                        )
                    except (asyncio.TimeoutError, TimeoutError):
                        self.logger.warning(f"  Timeout at offset {offset}")
                        break
                    except BaseException as e:
                        self.logger.debug(f"AtomicReadFile error: {e}")
                        break

                    if response and not isinstance(
                        response, (AbortPDU, ErrorPDU, RejectPDU, Error)
                    ):
                        # Extract data from response
                        chunk = None
                        end_of_file = False

                        if hasattr(response, "endOfFile"):
                            end_of_file = bool(response.endOfFile)

                        if hasattr(response, "accessMethod"):
                            am = response.accessMethod
                            if hasattr(am, "streamAccess"):
                                sa = am.streamAccess
                                if hasattr(sa, "fileData"):
                                    chunk = bytes(sa.fileData)
                            elif hasattr(am, "recordAccess"):
                                ra = am.recordAccess
                                if hasattr(ra, "fileRecordData"):
                                    for record in ra.fileRecordData:
                                        chunk = (
                                            bytes(record)
                                            if chunk is None
                                            else chunk + bytes(record)
                                        )

                        if chunk:
                            all_data.extend(chunk)
                            offset += len(chunk)
                            self.logger.debug(
                                f"  Read {len(chunk)} bytes at offset {offset - len(chunk)}"
                            )
                        else:
                            self.logger.debug("  Empty chunk received")
                            break

                        if end_of_file or (file_size > 0 and offset >= file_size):
                            break
                    else:
                        error_str = str(response) if response else "no response"
                        self.logger.warning(f"  AtomicReadFile error: {error_str}")
                        break

                except BaseException as e:
                    self.logger.debug(f"AtomicReadFile chunk error: {e}")
                    break

            if all_data:
                self.logger.success(f"  Read {len(all_data)} bytes total")

                if output_path:
                    from pathlib import Path

                    out_file = Path(output_path) / f"bacnet_file_{file_instance}.bin"
                    out_file.parent.mkdir(parents=True, exist_ok=True)
                    out_file.write_bytes(all_data)
                    self.logger.success(f"  Saved to {out_file}")
                else:
                    # Try to display as text
                    try:
                        text = all_data.decode("utf-8", errors="replace")
                        preview = text[:500]
                        self.logger.display(f"  Content preview:\n{preview}")
                        if len(text) > 500:
                            self.logger.display(f"  ... ({len(text) - 500} more characters)")
                    except BaseException as e:
                        self.logger.debug(f"bacpypes3 read file failed: {e}")
                        self.logger.display(f"  Binary content: {all_data[:64].hex()}...")
            else:
                self.logger.warning("  No data retrieved via AtomicReadFile")
                self.logger.display("  Device may not support AtomicReadFile for this object")

        except BaseException as e:
            self.logger.debug(f"bacpypes3 read file failed: {e}")
            self.logger.fail(f"File read error: {e}")

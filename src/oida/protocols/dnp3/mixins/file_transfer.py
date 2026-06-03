"""
DNP3 File Transfer Mixin (opendnp3 / yadnp3)

Handles file transfer and octet string operations:
- Directory listing via IMaster.ReadDirectory
- File read via IMaster.ReadFile / ReadFileWithAuth
- File write via IMaster.WriteFile / WriteFileWithAuth
- File info via IMaster.GetFileInfo
- File delete via IMaster.DeleteFile
- File authentication via IMaster.AuthenticateFile
- Abort via IMaster.AbortFile
- Octet string reads (Groups 110-111) via ScanAllObjects
"""

from __future__ import annotations

import time
from typing import Any, Dict, TYPE_CHECKING

from ....utils.payload import resolve_file_payload

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class FileTransferMixin(_ScannerBase):
    """Mixin providing DNP3 file transfer and octet string operations.

    Uses opendnp3's built-in file transfer methods which handle the
    multi-block Group 70 protocol (open -> read/write blocks -> close)
    internally, rather than raw PerformFunction calls.
    """

    @staticmethod
    def _format_permissions(perms) -> str:
        """Format DNP3 FilePermissions as a unix-style string (e.g. rwxr-xr--)."""
        parts = []
        for role_attr in ("owner", "group", "world"):
            ps = getattr(perms, role_attr, None)
            if ps is None:
                parts.append("---")
            else:
                parts.append("r" if getattr(ps, "read", False) else "-")
                parts.append("w" if getattr(ps, "write", False) else "-")
                parts.append("x" if getattr(ps, "execute", False) else "-")
        return "".join(parts)

    @staticmethod
    def _file_info_to_dict(info) -> dict:
        """Convert a FileInfo object to a serializable dict."""
        result = {
            "name": str(info.fileName) if info.fileName else "",
            "size": int(info.size) if info.size is not None else 0,
            "type": info.type.name if info.type else "UNKNOWN",
        }
        if info.timeOfCreation is not None:
            result["created"] = int(info.timeOfCreation)
        if info.permissions is not None:
            result["permissions"] = FileTransferMixin._format_permissions(info.permissions)
            result["permissions_raw"] = info.permissions.ToRaw()
        return result

    def _list_directory(self, results: Dict[str, Any]) -> None:
        """List directory contents on the outstation.

        Uses IMaster.ReadDirectory which handles the full Group 70
        multi-block protocol internally.
        """
        dnp3 = self._dnp3
        path = self.list_dir

        try:
            result = self._sync_callback(
                lambda master, cb, config: master.ReadDirectory(path, cb, config),
                timeout=float(self.op_timeout) + 5.0,
            )

            if result is None:
                self.logger.warning(f"Directory listing timed out for '{path}'")
                results["operations"]["list_dir"] = {
                    "success": False,
                    "path": path,
                    "error": "Timeout waiting for response",
                }
                return

            status = result.statusCode
            if status == dnp3.FileStatus.SUCCESS:
                entries = []
                for entry in result.entries:
                    info = self._file_info_to_dict(entry)
                    ftype = "DIR" if entry.type == dnp3.FileType.DIRECTORY else "FILE"
                    size_str = f"{info['size']:>8}" if ftype == "FILE" else "     <DIR>"
                    perms = info.get("permissions", "---------")
                    self.logger.display(f"  {perms}  {size_str}  {info['name']}")
                    entries.append(info)

                self.logger.display(f"Directory '{path}': {len(entries)} entries")
                results["operations"]["list_dir"] = {
                    "success": True,
                    "path": path,
                    "count": len(entries),
                    "entries": entries,
                }
            else:
                reason = f"{status.name}" + (f" ({result.summary})" if result.summary else "")
                self.logger.warning(f"Directory listing failed for '{path}': {reason}")
                results["operations"]["list_dir"] = {
                    "success": False,
                    "path": path,
                    "error": reason,
                }

        except Exception as e:
            self.logger.fail(f"Directory listing error for '{path}': {type(e).__name__}: {e}")
            results["operations"]["list_dir"] = {
                "success": False,
                "path": path,
                "error": str(e),
            }

    def _read_file(self, results: Dict[str, Any]) -> None:
        """Read a file from the outstation.

        Uses IMaster.ReadFile (or ReadFileWithAuth if an auth key is stored)
        which handles the full multi-block transfer protocol internally.
        """
        dnp3 = self._dnp3
        filename = self.read_file
        auth_key = getattr(self, "_file_auth_key", None)

        try:
            if auth_key is not None:
                result = self._sync_callback(
                    lambda master, cb, config: master.ReadFileWithAuth(
                        filename, auth_key, cb, config
                    ),
                    timeout=float(self.op_timeout) + 10.0,
                )
            else:
                result = self._sync_callback(
                    lambda master, cb, config: master.ReadFile(filename, cb, config),
                    timeout=float(self.op_timeout) + 10.0,
                )

            if result is None:
                self.logger.warning(f"File read timed out for '{filename}'")
                results["operations"]["read_file"] = {
                    "success": False,
                    "filename": filename,
                    "error": "Timeout waiting for response",
                }
                return

            status = result.statusCode
            if status == dnp3.FileStatus.SUCCESS:
                data = result.data
                size = len(data) if data else 0
                self.logger.display(f"File read '{filename}': {size} bytes received")

                # Show preview for text-like content
                if data and size <= 4096:
                    try:
                        text = data.decode("utf-8", errors="replace")
                        for line in text.splitlines()[:20]:
                            self.logger.display(f"  | {line}")
                        if len(text.splitlines()) > 20:
                            self.logger.display(
                                f"  | ... ({len(text.splitlines()) - 20} more lines)"
                            )
                    except Exception:
                        self.logger.display(f"  (binary data: {data[:64].hex()}...)")
                elif data and size > 4096:
                    self.logger.display(
                        f"  (binary data: {size} bytes, first 64: {data[:64].hex()})"
                    )

                results["operations"]["read_file"] = {
                    "success": True,
                    "filename": filename,
                    "size": size,
                    "data_hex": data.hex() if data and size <= 65536 else None,
                }
            else:
                reason = f"{status.name}" + (f" ({result.summary})" if result.summary else "")
                self.logger.warning(f"File read failed for '{filename}': {reason}")
                results["operations"]["read_file"] = {
                    "success": False,
                    "filename": filename,
                    "error": reason,
                }

        except Exception as e:
            self.logger.fail(f"File read error for '{filename}': {type(e).__name__}: {e}")
            results["operations"]["read_file"] = {
                "success": False,
                "filename": filename,
                "error": str(e),
            }

    def _write_file(self, results: Dict[str, Any]) -> None:
        """Write a file to the outstation.

        Uses IMaster.WriteFile (or WriteFileWithAuth if an auth key is stored)
        which handles the full multi-block transfer protocol internally.
        """
        dnp3 = self._dnp3

        filename = self.write_file
        raw_data = self.write_data

        if not raw_data:
            self.logger.fail("--write-data is required for file write")
            results["operations"]["write_file"] = {
                "success": False,
                "filename": filename,
                "error": "--write-data not provided",
            }
            return

        # If data starts with @, read from local file
        try:
            data, local_path = resolve_file_payload(raw_data)
        except OSError as e:
            self.logger.fail(f"Cannot read local file '{raw_data[1:]}': {e}")
            results["operations"]["write_file"] = {
                "success": False,
                "filename": filename,
                "error": f"Cannot read local file: {e}",
            }
            return

        if data is not None:
            file_bytes = data
            self.logger.debug(f"Read {len(file_bytes)} bytes from {local_path}")
        else:
            file_bytes = raw_data.encode("utf-8")

        self.logger.display(f"Writing {len(file_bytes)} bytes to '{filename}' on outstation")

        # Default permissions: owner rw, group r, world r (0644)
        permissions = dnp3.FilePermissions.FromRaw(0o644)

        auth_key = getattr(self, "_file_auth_key", None)

        try:
            if auth_key is not None:
                result = self._sync_callback(
                    lambda master, cb, config: master.WriteFileWithAuth(
                        filename,
                        file_bytes,
                        permissions,
                        dnp3.FileMode.WRITE,
                        auth_key,
                        cb,
                        config,
                    ),
                    timeout=float(self.op_timeout) + 10.0,
                )
            else:
                result = self._sync_callback(
                    lambda master, cb, config: master.WriteFile(
                        filename, file_bytes, permissions, cb, config
                    ),
                    timeout=float(self.op_timeout) + 10.0,
                )

            if result is None:
                self.logger.warning(f"File write timed out for '{filename}'")
                results["operations"]["write_file"] = {
                    "success": False,
                    "filename": filename,
                    "size": len(file_bytes),
                    "error": "Timeout waiting for response",
                }
                return

            status = result.statusCode
            if status == dnp3.FileStatus.SUCCESS:
                self.logger.display(f"File write '{filename}': SUCCESS ({len(file_bytes)} bytes)")
                results["operations"]["write_file"] = {
                    "success": True,
                    "filename": filename,
                    "size": len(file_bytes),
                }
            else:
                reason = f"{status.name}" + (f" ({result.summary})" if result.summary else "")
                self.logger.display(f"File write '{filename}': FAILED ({reason})")
                results["operations"]["write_file"] = {
                    "success": False,
                    "filename": filename,
                    "size": len(file_bytes),
                    "error": reason,
                }

        except Exception as e:
            self.logger.fail(f"File write error for '{filename}': {type(e).__name__}: {e}")
            results["operations"]["write_file"] = {
                "success": False,
                "filename": filename,
                "error": str(e),
            }

    def _authenticate_file(self, results: Dict[str, Any]) -> None:
        """Authenticate for file transfer operations.

        Uses IMaster.AuthenticateFile(username, password) which returns
        an auth key for subsequent ReadFileWithAuth / WriteFileWithAuth calls.
        """
        dnp3 = self._dnp3

        file_auth = self.file_auth
        if not file_auth:
            return

        # Parse USER:PASS format
        if ":" in file_auth:
            username, password = file_auth.split(":", 1)
        else:
            username = file_auth
            password = ""

        self.logger.display(f"Authenticating for file transfer as '{username}'")

        try:
            result = self._sync_callback(
                lambda master, cb, config: master.AuthenticateFile(username, password, cb, config),
            )

            if result is None:
                self.logger.warning("File authentication timed out")
                results["operations"]["file_auth"] = {
                    "success": False,
                    "username": username,
                    "error": "Timeout waiting for response",
                }
                return

            status = result.statusCode
            if status == dnp3.FileStatus.SUCCESS:
                auth_key = result.authKey
                self._file_auth_key = auth_key
                self.logger.display(f"File authentication SUCCESS (auth key: {auth_key})")
                results["operations"]["file_auth"] = {
                    "success": True,
                    "username": username,
                    "auth_key": auth_key,
                }
            else:
                reason = f"{status.name}" + (f" ({result.summary})" if result.summary else "")
                self.logger.warning(f"File authentication FAILED: {reason}")
                results["operations"]["file_auth"] = {
                    "success": False,
                    "username": username,
                    "error": reason,
                }

        except Exception as e:
            self.logger.fail(f"File authentication error: {type(e).__name__}: {e}")
            results["operations"]["file_auth"] = {
                "success": False,
                "username": username,
                "error": str(e),
            }

    def _get_file_info(self, results: Dict[str, Any]) -> None:
        """Get file metadata from the outstation.

        Uses IMaster.GetFileInfo which returns FileInfoResult containing
        file name, size, type (DIRECTORY/SIMPLE_FILE), permissions, and
        creation time.
        """
        dnp3 = self._dnp3
        filename = self.file_info

        try:
            result = self._sync_callback(
                lambda master, cb, config: master.GetFileInfo(filename, cb, config),
            )

            if result is None:
                self.logger.warning(f"File info request timed out for '{filename}'")
                results["operations"]["file_info"] = {
                    "success": False,
                    "filename": filename,
                    "error": "Timeout waiting for response",
                }
                return

            status = result.statusCode
            if status == dnp3.FileStatus.SUCCESS:
                info = result.info
                info_dict = self._file_info_to_dict(info)

                self.logger.display(f"File info for '{filename}':")
                self.logger.display(f"  Type:        {info_dict['type']}")
                self.logger.display(f"  Size:        {info_dict['size']} bytes")
                if "permissions" in info_dict:
                    self.logger.display(f"  Permissions: {info_dict['permissions']}")
                if "created" in info_dict:
                    self.logger.display(f"  Created:     {info_dict['created']}")

                results["operations"]["file_info"] = {
                    "success": True,
                    "filename": filename,
                    **info_dict,
                }
            else:
                reason = f"{status.name}" + (f" ({result.summary})" if result.summary else "")
                self.logger.warning(f"File info failed for '{filename}': {reason}")
                results["operations"]["file_info"] = {
                    "success": False,
                    "filename": filename,
                    "error": reason,
                }

        except Exception as e:
            self.logger.fail(f"File info error for '{filename}': {type(e).__name__}: {e}")
            results["operations"]["file_info"] = {
                "success": False,
                "filename": filename,
                "error": str(e),
            }

    def _delete_remote_file(self, results: Dict[str, Any]) -> None:
        """Delete a file on the outstation.

        Uses IMaster.DeleteFile which sends the appropriate Group 70
        delete request.
        """
        dnp3 = self._dnp3
        filename = self.delete_file

        try:
            result = self._sync_callback(
                lambda master, cb, config: master.DeleteFile(filename, cb, config),
            )

            if result is None:
                self.logger.warning(f"Delete file request timed out for '{filename}'")
                results["operations"]["delete_file"] = {
                    "success": False,
                    "filename": filename,
                    "error": "Timeout waiting for response",
                }
                return

            status = result.statusCode
            if status == dnp3.FileStatus.SUCCESS:
                self.logger.display(f"Delete file '{filename}': SUCCESS")
                results["operations"]["delete_file"] = {
                    "success": True,
                    "filename": filename,
                }
            else:
                reason = f"{status.name}" + (f" ({result.summary})" if result.summary else "")
                self.logger.display(f"Delete file '{filename}': FAILED ({reason})")
                results["operations"]["delete_file"] = {
                    "success": False,
                    "filename": filename,
                    "error": reason,
                }

        except Exception as e:
            self.logger.fail(f"Delete file error: {type(e).__name__}: {e}")
            results["operations"]["delete_file"] = {
                "success": False,
                "filename": filename,
                "error": str(e),
            }

    def _abort_file_transfer(self, file_handle: int, results: Dict[str, Any]) -> None:
        """Abort an in-progress file transfer.

        Uses IMaster.AbortFile with the file handle from a previous
        open operation.
        """
        dnp3 = self._dnp3

        try:
            result = self._sync_callback(
                lambda master, cb, config: master.AbortFile(file_handle, cb, config),
            )

            if result is None:
                self.logger.warning("Abort file transfer timed out")
                results["operations"]["abort_file"] = {
                    "success": False,
                    "file_handle": file_handle,
                    "error": "Timeout waiting for response",
                }
                return

            status = result.statusCode
            success = status == dnp3.FileStatus.SUCCESS
            result_str = "SUCCESS" if success else status.name
            self.logger.display(f"Abort file transfer (handle={file_handle}): {result_str}")
            results["operations"]["abort_file"] = {
                "success": success,
                "file_handle": file_handle,
            }

        except Exception as e:
            self.logger.fail(f"Abort file error: {type(e).__name__}: {e}")
            results["operations"]["abort_file"] = {
                "success": False,
                "file_handle": file_handle,
                "error": str(e),
            }

    def _read_octet_string(self, results: Dict[str, Any]) -> None:
        """Read octet string data points (Groups 110-111).

        Octet strings are arbitrary binary data stored in the outstation.
        Group 110 = static octet strings, Group 111 = octet string events.

        Format: "GROUP:START-END" or "GROUP:INDEX"
        Examples: "110:0-9" reads octet strings 0-9, "111:5" reads event at index 5
        """
        dnp3 = self._dnp3

        entry = self.read_octet
        if not entry:
            return

        try:
            parts = entry.split(":")
            if len(parts) < 2:
                self.logger.warning(f"Invalid read-octet format: {entry}")
                results["operations"]["read_octet"] = {
                    "success": False,
                    "error": "Format must be GROUP:START-END or GROUP:INDEX",
                }
                return

            group = int(parts[0])
            range_parts = parts[1].split("-")
            start_idx = int(range_parts[0])
            end_idx = int(range_parts[1]) if len(range_parts) > 1 else start_idx

            if group not in (110, 111):
                self.logger.warning(f"Invalid octet string group: {group} (must be 110 or 111)")
                results["operations"]["read_octet"] = {
                    "success": False,
                    "error": "Group must be 110 (static) or 111 (events)",
                }
                return

            self._handler.clear()

            gv_id = dnp3.GroupVariationID(group, 0)
            scan_result = self._sync_scan(
                lambda master, handler, config, _gv=gv_id: master.ScanAllObjects(
                    _gv, handler, config
                )
            )

            time.sleep(0.5)

            if scan_result:
                octet_data = []
                if hasattr(self._handler, "octet_strings"):
                    for os_item in self._handler.octet_strings:
                        # ScanAllObjects() returns everything in the group;
                        # filter to the user-requested range here.
                        # Previously the user's start/end were parsed,
                        # echoed in the log, and silently ignored.
                        if not (start_idx <= os_item.index <= end_idx):
                            continue
                        val_obj = os_item.value
                        raw_value = getattr(val_obj, "value", b"")
                        if isinstance(raw_value, (bytes, bytearray)):
                            hex_value = raw_value.hex()
                            length = len(raw_value)
                        else:
                            hex_value = str(raw_value)
                            length = len(str(raw_value))
                        octet_data.append(
                            {"index": os_item.index, "value": hex_value, "length": length}
                        )
                        self.logger.display(f"  Octet[{os_item.index}]: {hex_value}")

                self.logger.display(
                    f"Octet string read: Group {group}[{start_idx}-{end_idx}] - "
                    f"{len(octet_data)} items"
                )
                results["operations"]["read_octet"] = {
                    "success": True,
                    "group": group,
                    "start": start_idx,
                    "end": end_idx,
                    "count": len(octet_data),
                    "data": octet_data,
                }
            else:
                reason = self._error_detail()
                self.logger.warning(f"Octet string read failed for Group {group} ({reason})")
                results["operations"]["read_octet"] = {
                    "success": False,
                    "group": group,
                    "start": start_idx,
                    "end": end_idx,
                    "error": reason,
                }

        except (ValueError, IndexError) as e:
            self.logger.fail(f"Invalid read-octet entry: {e}")
            results["operations"]["read_octet"] = {"success": False, "error": str(e)}
        except Exception as e:
            self.logger.fail(f"Octet string read error: {type(e).__name__}: {e}")
            results["operations"]["read_octet"] = {"success": False, "error": str(e)}

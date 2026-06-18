"""
IEC 104 File Transfer Mixin

Provides file transfer operations: probe, download, upload, delete, query_log.
"""

from typing import Dict, Any
from datetime import datetime

from .constants import (
    IEC104_TYPE_IDS,
    FILE_TRANSFER_TYPE_ID_START,
    FILE_TRANSFER_TYPE_ID_END,
    MS_PER_HOUR,
    MS_PER_MINUTE,
)


class FileTransferMixin:
    """Mixin providing IEC 104 file transfer operations.

    Expects the host class to provide:
        - self.logger
        - self.host, self.port, self.timeout
        - self._lock, self._file_transfer_supported, self._raw_type_ids
        - self.list_files, self.probe_files
        - self.download_file_ioa, self.file_output
        - self.delete_file_ioa, self.upload_file_path, self.upload_ioa, self.upload_nof
        - self.query_log_ioa, self.log_start, self.log_end, self.log_type
        - self.confirm_dangerous
        - self._best_common_address()
    """

    def _probe_file_transfer(self, client: Any, conn: Any) -> Dict[str, Any]:
        """Probe for file transfer capability using c104's native methods"""
        self.logger.display("Probing file transfer capability...")

        result = {
            "supported": False,
            "type_ids_found": [],
            "files": [],
            "directory": [],
            "downloaded": None,
        }

        # Check if we already detected file transfer types from interrogation
        with self._lock:
            if self._file_transfer_supported:
                result["supported"] = True
                file_types = [
                    tid
                    for tid in self._raw_type_ids
                    if FILE_TRANSFER_TYPE_ID_START <= tid <= FILE_TRANSFER_TYPE_ID_END
                ]
                result["type_ids_found"] = file_types
                for tid in file_types:
                    if tid in IEC104_TYPE_IDS:
                        result["files"].append(
                            {
                                "type_id": tid,
                                "name": IEC104_TYPE_IDS[tid][0],
                                "description": IEC104_TYPE_IDS[tid][1],
                            }
                        )

        # Use c104's browse_directory if --list-files or --probe-files
        if self.list_files or self.probe_files:
            try:
                self.logger.display("Requesting directory listing via c104...")
                # c104's browse_directory returns list of dicts
                entries = conn.browse_directory(
                    common_address=self._best_common_address(),
                    ioa=0,  # Root directory
                    timeout_ms=self.timeout * 1000,
                )

                if entries:
                    result["supported"] = True
                    result["directory"] = entries
                    self.logger.success(f"Directory listing: {len(entries)} entries found")

                    for entry in entries:
                        ioa = entry.get("ioa", 0)
                        length = entry.get("length", 0)
                        nof = entry.get("nof", 0)
                        is_dir = entry.get("is_directory", False)
                        entry.get("creation_time", 0)

                        type_str = "DIR" if is_dir else "FILE"
                        nof_str = {1: "transparent", 2: "disturbance"}.get(nof, f"type_{nof}")
                        self.logger.display(
                            f"  IOA={ioa:5d} {type_str:4s} {length:8d} bytes ({nof_str})"
                        )
                else:
                    self.logger.display("No files in directory (or not supported)")

            except Exception as e:
                self.logger.debug(f"Directory listing failed: {e}")
                # May not be supported - that's okay

        # Download file if requested
        if self.download_file_ioa is not None:
            result["downloaded"] = self._download_file(conn, self.download_file_ioa)

        # Delete file if requested (requires confirmation)
        if self.delete_file_ioa is not None:
            result["deleted"] = self._delete_file(conn, self.delete_file_ioa)

        # Upload file if requested (requires confirmation)
        if self.upload_file_path is not None and self.upload_ioa is not None:
            result["uploaded"] = self._upload_file(
                conn, self.upload_ioa, self.upload_file_path, self.upload_nof
            )

        # Query log if requested
        if self.query_log_ioa is not None:
            result["log_query"] = self._query_log(
                conn, self.query_log_ioa, self.log_type, self.log_start, self.log_end
            )

        if result["supported"]:
            self.logger.security_finding(
                "File transfer exposed",
                detail="Server exposes file transfer capability (Type IDs 120-127)",
            )
        else:
            self.logger.display("No file transfer support detected")

        return result

    def _download_file(self, conn: Any, ioa: int) -> Dict[str, Any]:
        """Download a file using c104's high-level download_file API"""
        self.logger.display(f"Downloading file IOA={ioa} via c104...")

        result = {
            "ioa": ioa,
            "success": False,
            "size": 0,
            "data": None,
            "output_path": None,
            "error": None,
        }

        try:
            # Use c104's high-level download_file API
            data = conn.download_file(
                common_address=self._best_common_address(),
                ioa=ioa,
                timeout_ms=self.timeout * 1000,
            )

            if data:
                result["success"] = True
                result["size"] = len(data)
                result["data"] = bytes(data)

                # Save to file
                if self.file_output:
                    output_path = self.file_output
                else:
                    output_path = f"iec104_file_{self.host}_{ioa}.bin"

                from ...utils.common_types import safe_file_path

                try:
                    output_path = safe_file_path(output_path)
                except ValueError as e:
                    result["error"] = str(e)
                    self.logger.fail(str(e))
                    return result

                with open(output_path, "wb") as f:
                    f.write(data)
                result["output_path"] = output_path

                self.logger.success(f"Downloaded {len(data)} bytes -> {output_path}")
            else:
                result["error"] = "No data received or download failed"
                self.logger.fail(f"File download failed for IOA={ioa}")

        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"File download error: {e}")

        return result

    def _upload_file(self, conn: Any, ioa: int, path: str, nof: int) -> Dict[str, Any]:
        """Upload a file using c104's high-level upload_file API

        WARNING: This is a WRITE operation that modifies the remote device!
        """
        result = {
            "ioa": ioa,
            "success": False,
            "path": path,
            "size": 0,
            "error": None,
        }

        # Safety check - require explicit confirmation
        if not self.confirm_dangerous:
            result["error"] = "Upload requires --confirm flag"
            self.logger.fail("Upload BLOCKED - use --confirm to enable upload operations")
            return result

        try:
            # Read the file
            with open(path, "rb") as f:
                data = f.read()

            result["size"] = len(data)

            self.logger.warning(f"UPLOADING {len(data)} bytes to IOA={ioa} on {self.host}...")

            # Use c104's high-level upload_file API
            success = conn.upload_file(
                common_address=self._best_common_address(),
                ioa=ioa,
                nof=nof,
                data=data,
                timeout_ms=self.timeout * 1000,
            )

            if success:
                result["success"] = True
                self.logger.success(f"Uploaded {len(data)} bytes to IOA={ioa}")
            else:
                result["error"] = "Upload failed (server rejected or timeout)"
                self.logger.fail(f"Upload failed for IOA={ioa}")

        except FileNotFoundError:
            result["error"] = f"File not found: {path}"
            self.logger.fail(f"File not found: {path}")
        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"Upload error: {e}")

        return result

    def _query_log(
        self, conn: Any, ioa: int, nof: int, start_time: str, end_time: str
    ) -> Dict[str, Any]:
        """Query archive log using c104's query_log API (Type 127)"""
        result = {
            "ioa": ioa,
            "success": False,
            "nof": nof,
            "start_time": start_time,
            "end_time": end_time,
            "error": None,
        }

        try:
            # Parse time strings
            now = datetime.now()
            now_ms = int(now.timestamp() * 1000)

            if start_time is None:
                # Default to 1 hour ago
                start_ms = now_ms - MS_PER_HOUR
            elif start_time == "now":
                start_ms = now_ms
            elif start_time.startswith("now-"):
                # Parse relative time like "now-1h", "now-30m"
                offset = start_time[4:]
                if offset.endswith("h"):
                    start_ms = now_ms - int(offset[:-1]) * MS_PER_HOUR
                elif offset.endswith("m"):
                    start_ms = now_ms - int(offset[:-1]) * MS_PER_MINUTE
                else:
                    start_ms = now_ms - int(offset) * 1000
            else:
                # Parse ISO format
                dt = datetime.fromisoformat(start_time)
                start_ms = int(dt.timestamp() * 1000)

            if end_time is None or end_time == "now":
                end_ms = now_ms
            elif end_time.startswith("now-"):
                offset = end_time[4:]
                if offset.endswith("h"):
                    end_ms = now_ms - int(offset[:-1]) * MS_PER_HOUR
                elif offset.endswith("m"):
                    end_ms = now_ms - int(offset[:-1]) * MS_PER_MINUTE
                else:
                    end_ms = now_ms - int(offset) * 1000
            else:
                dt = datetime.fromisoformat(end_time)
                end_ms = int(dt.timestamp() * 1000)

            self.logger.display(
                f"Querying log IOA={ioa} type={nof} from "
                f"{datetime.fromtimestamp(start_ms / 1000).isoformat()} to "
                f"{datetime.fromtimestamp(end_ms / 1000).isoformat()}"
            )

            # Use c104's query_log API
            success = conn.query_log(
                common_address=self._best_common_address(),
                ioa=ioa,
                nof=nof,
                start_time_ms=start_ms,
                stop_time_ms=end_ms,
            )

            if success:
                result["success"] = True
                self.logger.success(
                    f"Log query sent for IOA={ioa} - server should respond with F_FR_NA_1"
                )
            else:
                result["error"] = "Failed to send log query"
                self.logger.fail(f"Log query failed for IOA={ioa}")

        except ValueError as e:
            result["error"] = f"Invalid time format: {e}"
            self.logger.fail(f"Invalid time format: {e}")
        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"Log query error: {e}")

        return result

    def _delete_file(self, conn: Any, ioa: int) -> Dict[str, Any]:
        """Delete a file on the remote server using c104's delete_file

        WARNING: This is a DESTRUCTIVE operation!
        """
        result = {
            "ioa": ioa,
            "success": False,
            "error": None,
        }

        # Safety check - require explicit confirmation
        if not self.confirm_dangerous:
            result["error"] = "File deletion requires --confirm flag"
            self.logger.fail(
                f"Delete IOA={ioa} BLOCKED - use --confirm to enable destructive operations"
            )
            return result

        self.logger.warning(f"DELETING file IOA={ioa} on {self.host}...")

        try:
            # Use c104's delete_file method
            sent = conn.delete_file(common_address=self._best_common_address(), ioa=ioa)

            if sent:
                result["success"] = True
                self.logger.success(f"Delete command sent for IOA={ioa}")
            else:
                result["error"] = "Failed to send delete command"
                self.logger.fail(f"Delete command failed for IOA={ioa}")

        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"File delete error: {e}")

        return result

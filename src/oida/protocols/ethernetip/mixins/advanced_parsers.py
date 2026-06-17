"""
EtherNet/IP Advanced Parsers Mixin

Handles advanced CIP object parsing:
- Message Router (0x02) - supported class discovery
- Connection Manager (0x06) - connection statistics
- Parameter Object (0x0F) - device parameters
- File Object (0x37) - firmware/config files with download
- Port Object (0x47) - communication ports
- Vendor-specific classes (0x64+)
- Get_Attributes_All service
"""

from __future__ import annotations

import base64
import os
import re
import struct
from typing import Any, Dict, Optional, TYPE_CHECKING

from ....utils.vendor_maps import ethernetip_wellknown_class_types as wellknown_class_types

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class AdvancedParsersMixin(_ScannerBase):
    """Mixin providing advanced CIP object parsers."""

    def _parse_message_router(self, conn: Any) -> Dict[str, Any]:
        """
        Parse Message Router object (0x02) to discover supported classes.

        The Message Router's Object List attribute reveals all CIP classes
        the device supports - useful for fingerprinting and enumeration.
        """
        mr_info = {
            "object_id": 0x02,
            "object_name": "Message Router",
            "accessible": False,
            "supported_classes": [],
            "class_names": {},
        }

        self.logger.display("Parsing Message Router (0x02)...")

        # Attribute 1 = Object list (array of UINT class IDs)
        data = self._read_cip_attribute(conn, 0x02, 1, 1)

        if data is not None and len(data) >= 2:
            mr_info["accessible"] = True

            # First 2 bytes = count of classes
            count = struct.unpack("<H", data[:2])[0]
            self.logger.debug(f"  Supported classes: {count}")

            for i in range(min(count, (len(data) - 2) // 2)):
                class_id = struct.unpack("<H", data[2 + i * 2 : 4 + i * 2])[0]
                class_name = wellknown_class_types.get(class_id, f"Unknown_0x{class_id:02X}")
                mr_info["supported_classes"].append(class_id)
                mr_info["class_names"][class_id] = class_name

            if mr_info["supported_classes"]:
                self.logger.display(
                    f"  Device supports {len(mr_info['supported_classes'])} CIP classes"
                )
                # Log interesting classes
                interesting = [0x04, 0x0F, 0x37, 0x64, 0x65, 0x66, 0x67, 0x68]
                for cls in interesting:
                    if cls in mr_info["supported_classes"]:
                        self.logger.display(f"    - 0x{cls:02X}: {mr_info['class_names'][cls]}")
        else:
            self.logger.debug("  Message Router: Not accessible")

        return mr_info

    def _parse_connection_manager(self, conn: Any) -> Dict[str, Any]:
        """
        Parse Connection Manager object (0x06).

        Reveals active connections, connection timeouts, and protocol info.
        Important for understanding device communication state.
        """
        cm_info = {
            "object_id": 0x06,
            "object_name": "Connection Manager",
            "accessible": False,
            "open_requests": None,
            "open_format_rejects": None,
            "open_resource_rejects": None,
            "open_other_rejects": None,
            "close_requests": None,
            "close_format_requests": None,
            "close_other_requests": None,
            "connection_timeouts": None,
        }

        self.logger.display("Parsing Connection Manager (0x06)...")

        # Key attributes for Connection Manager
        attrs = [
            (1, "open_requests"),
            (2, "open_format_rejects"),
            (3, "open_resource_rejects"),
            (4, "open_other_rejects"),
            (5, "close_requests"),
            (6, "close_format_requests"),
            (7, "close_other_requests"),
            (8, "connection_timeouts"),
        ]

        for attr_id, attr_name in attrs:
            data = self._read_cip_attribute(conn, 0x06, 1, attr_id)
            if data is not None:
                cm_info["accessible"] = True
                if len(data) >= 2:
                    value = struct.unpack("<H", data[:2])[0]
                    cm_info[attr_name] = value
                    if value > 0:
                        self.logger.debug(f"  {attr_name}: {value}")

        if cm_info["accessible"]:
            # Summarize connection activity
            total_opens = cm_info.get("open_requests", 0) or 0
            total_timeouts = cm_info.get("connection_timeouts", 0) or 0
            if total_opens or total_timeouts:
                self.logger.display(
                    f"  Connection stats: {total_opens} opens, {total_timeouts} timeouts"
                )
        else:
            self.logger.debug("  Connection Manager: Not accessible")

        return cm_info

    def _parse_parameter_object(self, conn: Any) -> Dict[str, Any]:
        """
        Parse Parameter Object (0x0F) instances.

        Parameters are configurable device settings. Reading them reveals
        operational configuration and potential security settings.
        """
        param_info = {
            "object_id": 0x0F,
            "object_name": "Parameter",
            "accessible": False,
            "parameters": {},
            "count": 0,
        }

        self.logger.display("Scanning Parameter Object (0x0F)...")

        # Scan first 50 parameter instances
        for instance in range(1, 51):
            # Attr 1 = Value, Attr 2 = Link path to data, Attr 4 = Name
            value_data = self._read_cip_attribute(conn, 0x0F, instance, 1)

            if value_data is not None:
                param_info["accessible"] = True
                param_info["count"] += 1

                param_data = {"instance": instance, "value": value_data.hex()}

                # Try to read parameter name (attr 7)
                name_data = self._read_cip_attribute(conn, 0x0F, instance, 7)
                if name_data and len(name_data) >= 2:
                    name_len = struct.unpack("<H", name_data[:2])[0]
                    if len(name_data) >= 2 + name_len:
                        param_data["name"] = name_data[2 : 2 + name_len].decode(
                            "ascii", errors="replace"
                        )

                param_info["parameters"][instance] = param_data

        if param_info["count"] > 0:
            self.logger.display(f"  Found {param_info['count']} parameters")
            # Show first few named parameters
            for inst, data in list(param_info["parameters"].items())[:5]:
                if "name" in data:
                    self.logger.display(
                        f"    Param {inst}: {data['name']} = {data['value'][:16]}..."
                    )
        else:
            self.logger.debug("  Parameter Object: No instances found")

        return param_info

    def _parse_file_object(self, conn: Any) -> Dict[str, Any]:
        """
        Parse File Object (0x37) instances.

        File objects can contain firmware, configuration, or log data.
        Important for security assessment.
        """
        file_info = {
            "object_id": 0x37,
            "object_name": "File",
            "accessible": False,
            "files": {},
        }

        self.logger.display("Scanning File Object (0x37)...")

        # Scan file instances 1-10
        for instance in range(1, 11):
            # Attr 4 = File name, Attr 5 = File revision, Attr 6 = File size
            name_data = self._read_cip_attribute(conn, 0x37, instance, 4)

            if name_data is not None:
                file_info["accessible"] = True

                file_data = {"instance": instance}

                # Parse file name (short string)
                if len(name_data) >= 2:
                    name_len = struct.unpack("<H", name_data[:2])[0]
                    if len(name_data) >= 2 + name_len:
                        file_data["name"] = name_data[2 : 2 + name_len].decode(
                            "ascii", errors="replace"
                        )

                # Get file size
                size_data = self._read_cip_attribute(conn, 0x37, instance, 6)
                if size_data and len(size_data) >= 4:
                    file_data["size"] = struct.unpack("<I", size_data[:4])[0]

                # Get file revision
                rev_data = self._read_cip_attribute(conn, 0x37, instance, 5)
                if rev_data and len(rev_data) >= 2:
                    file_data["revision"] = struct.unpack("<H", rev_data[:2])[0]

                file_info["files"][instance] = file_data
                self.logger.display(
                    f"  File {instance}: {file_data.get('name', 'Unknown')} "
                    f"({file_data.get('size', '?')} bytes, rev {file_data.get('revision', '?')})"
                )

        if not file_info["files"]:
            self.logger.debug("  File Object: No instances found")

        return file_info

    def _download_file(self, conn: Any, instance: int, max_size: int = 65536) -> Optional[bytes]:
        """
        Download file contents from File Object using CIP File Upload services.

        Uses:
        - Service 0x4B: Initiate Upload
        - Service 0x4F: Upload Transfer

        Args:
            conn: Connection object
            instance: File instance number
            max_size: Maximum file size to download (safety limit)

        Returns:
            File contents as bytes, or None if download failed
        """
        file_data = bytearray()

        # First get file size to check against max_size
        size_data = self._read_cip_attribute(conn, 0x37, instance, 6)
        if size_data and len(size_data) >= 4:
            file_size = struct.unpack("<I", size_data[:4])[0]
            if file_size > max_size:
                self.logger.warning(f"File size {file_size} exceeds max {max_size}, skipping")
                return None

        # Initiate Upload (Service 0x4B)
        # Request: Maximum size (UINT)
        initiate_request = struct.pack("<H", 512)  # 512 byte chunks

        init_response = self._direct_cip_service(conn, 0x37, instance, 0x4B, initiate_request)

        if init_response is None:
            self.logger.debug(f"Failed to initiate upload for file instance {instance}")
            return None

        # Parse initiate response: File size (UDINT), Transfer size (UINT)
        if len(init_response) < 6:
            return None

        total_size = struct.unpack("<I", init_response[:4])[0]
        transfer_size = struct.unpack("<H", init_response[4:6])[0]

        # Bound the device-reported total_size against max_size: a malicious or
        # buggy PLC can advertise a huge total_size and OOM the scanner (data is
        # held fully in memory before base64 encoding). This also covers the case
        # where the attr-6 pre-check above was skipped (size_data unreadable).
        effective_max = min(total_size, max_size)
        if total_size > max_size:
            self.logger.warning(
                f"Reported file size {total_size} exceeds max {max_size}, "
                f"capping download at {effective_max} bytes"
            )

        self.logger.display(
            f"  Downloading file: {total_size} bytes in {transfer_size}-byte chunks"
        )

        # Upload Transfer (Service 0x4F) - repeat until done
        transfer_number = 0
        while len(file_data) < effective_max:
            # Request: Transfer Number (USINT)
            transfer_request = struct.pack("<B", transfer_number)

            chunk_response = self._direct_cip_service(conn, 0x37, instance, 0x4F, transfer_request)

            if chunk_response is None:
                self.logger.warning(f"  Upload transfer {transfer_number} failed")
                break

            # Response: Transfer Number (USINT), Transfer Packet Type (USINT), Data
            if len(chunk_response) < 2:
                break

            # Skip resp_transfer_num at index 0
            packet_type = chunk_response[1]
            chunk_data = chunk_response[2:]

            file_data.extend(chunk_data)
            transfer_number = (transfer_number + 1) % 256

            # Packet type: 0=first, 1=middle, 2=last, 3=first&last (abort)
            if packet_type in (2, 3):
                break

            if len(file_data) >= effective_max:
                self.logger.warning(f"  Download reached cap of {effective_max} bytes, stopping")
                break

        # Truncate any overrun from the final chunk to honor the cap.
        if len(file_data) > effective_max:
            del file_data[effective_max:]

        self.logger.success(f"  Downloaded {len(file_data)} bytes")
        return bytes(file_data)

    def _direct_cip_service(
        self,
        conn: Any,
        class_id: int,
        instance: int,
        service: int,
        data: bytes = b"",
    ) -> Optional[bytes]:
        """
        Send a CIP service request using pycomm3 generic_message.

        Args:
            conn: pycomm3 connection (LogixDriver or CIPDriver)
            class_id: CIP class ID
            instance: Instance number
            service: Service code
            data: Request data

        Returns:
            Response data or None on failure
        """
        if not hasattr(conn, "generic_message"):
            self.logger.debug("Connection does not support generic_message")
            return None

        try:
            result = conn.generic_message(
                service=service,
                class_code=class_id,
                instance=instance,
                request_data=data,
                connected=True,
                unconnected_send=False,
            )
            if result and result.value is not None:
                if isinstance(result.value, (bytes, bytearray)):
                    return bytes(result.value)
                elif isinstance(result.value, (list, tuple)):
                    return bytes(result.value)
            return None
        except Exception as e:
            self.logger.debug(f"CIP service 0x{service:02X} failed: {e}")
            return None

    def _download_all_files(self, conn: Any) -> Dict[str, Any]:
        """
        Download all accessible files from File Object (0x37).

        Scans file instances 1-10 and Logix-specific ranges, downloads contents.
        """
        downloaded = {"files": {}, "total_bytes": 0, "saved_to": None}

        self.logger.display("Downloading files from File Object (0x37)...")

        if not conn or not hasattr(conn, "generic_message"):
            self.logger.display("  Connection does not support file operations")
            return downloaded

        # Check if File Object class is accessible (read class attribute 1 = revision)
        class_rev = self._read_cip_attribute(conn, 0x37, 0, 1)
        if class_rev:
            self.logger.display(f"  File Object accessible (revision: {class_rev.hex()})")
        else:
            self.logger.display("  File Object class not accessible")
            return downloaded

        # Scan for file instances - prioritize common Logix instances
        # Logix EDS file is typically instance 200
        instances_to_check = [200, 201, 202] + list(range(1, 11))

        consecutive_misses = 0
        max_misses = 3  # Stop after 3 consecutive empty instances

        for instance in instances_to_check:
            # Try to read file state (attr 1) first
            state_data = self._read_cip_attribute(conn, 0x37, instance, 1)
            if state_data is None:
                consecutive_misses += 1
                if consecutive_misses >= max_misses and len(downloaded["files"]) > 0:
                    self.logger.debug(f"  Stopping after {max_misses} empty instances")
                    break
                continue

            consecutive_misses = 0  # Reset on hit
            self.logger.debug(
                f"  File instance {instance} state: {state_data.hex() if state_data else 'None'}"
            )

            # Read file name (attr 4) - Logix uses STRINGI format
            name_data = self._read_cip_attribute(conn, 0x37, instance, 4)
            if name_data is None:
                # Try attr 2 (Instance Name)
                name_data = self._read_cip_attribute(conn, 0x37, instance, 2)

            # Parse file name (handle Logix STRINGI format: header(7) + len(1) + string)
            file_name = f"file_{instance}.bin"
            if name_data and len(name_data) >= 9:
                # STRINGI format: count(1) + lang(3) + marker(2) + reserved(1) + len(1) + string
                str_len = name_data[7]
                if str_len > 0 and len(name_data) >= 8 + str_len:
                    file_name = name_data[8 : 8 + str_len].decode("ascii", errors="replace")
            elif name_data and len(name_data) >= 2:
                # Try SHORT_STRING format
                name_len = struct.unpack("<H", name_data[:2])[0]
                if name_len > 0 and len(name_data) >= 2 + name_len:
                    file_name = name_data[2 : 2 + name_len].decode("ascii", errors="replace")

            # Get file size
            size_data = self._read_cip_attribute(conn, 0x37, instance, 6)
            file_size = 0
            if size_data and len(size_data) >= 4:
                file_size = struct.unpack("<I", size_data[:4])[0]

            # Get file state
            file_state = "unknown"
            if state_data and len(state_data) >= 1:
                states = {
                    0: "nonexistent",
                    1: "empty",
                    2: "loaded",
                    3: "upload_init",
                    4: "download_init",
                }
                file_state = states.get(state_data[0], f"state_{state_data[0]}")

            self.logger.display(f"  Found: {file_name} ({file_size} bytes, {file_state})")

            # Store file metadata
            file_info = {
                "instance": instance,
                "name": file_name,
                "size": file_size,
                "state": file_state,
                "downloaded": False,
                "content": None,
            }

            # Try to download file contents
            content = self._download_file(conn, instance, self.max_file_size)

            if content:
                file_info["downloaded"] = True
                file_info["content"] = base64.b64encode(content).decode("ascii")
                downloaded["total_bytes"] += len(content)
                self.logger.success(f"    Downloaded {len(content)} bytes")

                # Save to disk if output directory specified
                if self.file_output:
                    output_dir = self.file_output
                    os.makedirs(output_dir, exist_ok=True)

                    # Sanitize filename and validate path
                    from oida.utils.common_types import safe_output_path

                    safe_name = re.sub(r'[<>:"/\\|?*]', "_", file_name)
                    try:
                        output_path = safe_output_path(safe_name, output_dir)
                    except ValueError:
                        self.logger.fail(f"    Unsafe filename blocked: {file_name}")
                        continue

                    with open(output_path, "wb") as f:
                        f.write(content)
                    self.logger.success(f"    Saved to: {output_path}")
                    downloaded["saved_to"] = output_dir
            else:
                self.logger.display("    Download blocked (access restricted)")

            downloaded["files"][instance] = file_info

        if downloaded["files"]:
            downloadable = sum(1 for f in downloaded["files"].values() if f["downloaded"])
            self.logger.display(
                f"  Found {len(downloaded['files'])} files, {downloadable} downloadable "
                f"({downloaded['total_bytes']} bytes)"
            )
        else:
            self.logger.display("  No files available for download")

        return downloaded

    def _parse_port_object(self, conn: Any) -> Dict[str, Any]:
        """
        Parse Port Object (0x47) instances.

        Port objects describe physical and logical communication ports.
        """
        port_info = {
            "object_id": 0x47,
            "object_name": "Port",
            "accessible": False,
            "ports": {},
        }

        self.logger.display("Scanning Port Object (0x47)...")

        # Scan port instances 1-8
        for instance in range(1, 9):
            # Attr 1 = Port type, Attr 2 = Port number, Attr 4 = Port name
            type_data = self._read_cip_attribute(conn, 0x47, instance, 1)

            if type_data is not None:
                port_info["accessible"] = True

                port_data = {"instance": instance}

                if len(type_data) >= 2:
                    port_type = struct.unpack("<H", type_data[:2])[0]
                    # CIP Port Type values (Vol 1, Section 7-3.4.2)
                    port_types = {
                        0: "Any/Undefined",
                        1: "Backplane",
                        2: "ControlNet",
                        3: "ControlNet Redundant",
                        4: "EtherNet/IP",
                        5: "DeviceNet",
                        6: "DH+",
                        7: "DH-485",
                    }
                    port_data["type"] = port_types.get(port_type, f"Unknown ({port_type})")
                    port_data["type_raw"] = port_type

                # Get port name
                name_data = self._read_cip_attribute(conn, 0x47, instance, 4)
                if name_data and len(name_data) >= 2:
                    name_len = struct.unpack("<H", name_data[:2])[0]
                    if len(name_data) >= 2 + name_len:
                        port_data["name"] = name_data[2 : 2 + name_len].decode(
                            "ascii", errors="replace"
                        )

                port_info["ports"][instance] = port_data
                self.logger.display(
                    f"  Port {instance}: {port_data.get('type', '?')} - {port_data.get('name', 'Unnamed')}"
                )

        if not port_info["ports"]:
            self.logger.debug("  Port Object: No instances found")

        return port_info

    def _parse_vendor_specific_class(
        self, conn: Any, class_id: int, max_attrs: int = 20
    ) -> Dict[str, Any]:
        """
        Generic parser for vendor-specific CIP classes (0x64+).

        Attempts to read common attributes and identify the class type.
        """
        class_name = wellknown_class_types.get(class_id, f"Vendor_0x{class_id:02X}")

        class_info = {
            "class_id": class_id,
            "class_name": class_name,
            "accessible": False,
            "attributes": {},
            "instances_found": [],
        }

        self.logger.display(f"Parsing vendor class 0x{class_id:02X} ({class_name})...")

        # Check which instances exist (1-10)
        for instance in range(1, 11):
            attr1_data = self._read_cip_attribute(conn, class_id, instance, 1)
            if attr1_data is not None:
                class_info["accessible"] = True
                class_info["instances_found"].append(instance)

                # Read first N attributes for this instance
                instance_attrs = {}
                for attr_id in range(1, max_attrs + 1):
                    data = self._read_cip_attribute(conn, class_id, instance, attr_id)
                    if data is not None:
                        # Try to interpret the data
                        if len(data) == 1:
                            instance_attrs[attr_id] = {"type": "USINT", "value": data[0]}
                        elif len(data) == 2:
                            instance_attrs[attr_id] = {
                                "type": "UINT",
                                "value": struct.unpack("<H", data)[0],
                            }
                        elif len(data) == 4:
                            instance_attrs[attr_id] = {
                                "type": "UDINT",
                                "value": struct.unpack("<I", data)[0],
                            }
                        else:
                            instance_attrs[attr_id] = {"type": "bytes", "value": data.hex()}

                class_info["attributes"][instance] = instance_attrs

        if class_info["instances_found"]:
            self.logger.display(f"  Instances: {class_info['instances_found']}")
            # Show attribute summary for first instance
            first_inst = class_info["instances_found"][0]
            attr_count = len(class_info["attributes"].get(first_inst, {}))
            self.logger.display(f"  Instance {first_inst} has {attr_count} readable attributes")
        else:
            self.logger.debug(f"  Class 0x{class_id:02X}: No instances found")

        return class_info

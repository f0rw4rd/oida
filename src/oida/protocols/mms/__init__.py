#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MMS (Manufacturing Message Specification) Protocol Scanner

Uses pyiec61850-ng with safe wrappers for memory management.
Requires pyiec61850-ng >= 1.6.0.9 (with pyiec61850.mms submodule).

Requires: pip install pyiec61850-ng
"""

import sys
import time
from typing import Dict, List, Any, Optional

from ...utils import (
    register_protocol,
    create_protocol_module,
    NetworkScanner,
    SecurityAnalyzer,
    ProgressTracker,
    parse_bool,
    safe_int_conversion,
)
from ...utils.exceptions import DependencyError
from ...utils.lazy_import import lazy_import
from .fingerprint import FingerprintMatcher, FingerprintMatch

# Lazy imports for pyiec61850-ng (only loaded when actually used)
_pyiec61850 = lazy_import("pyiec61850", "MMS", install_hint="pip install pyiec61850-ng")
_pyiec61850_mms_utils = lazy_import(
    "pyiec61850.mms.utils", "MMS", install_hint="pip install pyiec61850-ng"
)


class _Lib:
    """Lazy-loaded pyiec61850 bindings (class-based namespace, thread-safe)."""

    iec61850 = None
    safe_to_char_p = None
    safe_linked_list_iter = None
    safe_linked_list_destroy = None
    safe_mms_value_delete = None
    safe_identity_destroy = None
    unpack_result = None

    @classmethod
    def require(cls):
        """Load pyiec61850-ng bindings (raises DependencyError if missing)."""
        if cls.iec61850 is not None:
            return

        cls.iec61850 = _pyiec61850.pyiec61850
        utils = _pyiec61850_mms_utils()
        cls.safe_to_char_p = utils.safe_to_char_p
        cls.safe_linked_list_iter = utils.safe_linked_list_iter
        cls.safe_linked_list_destroy = utils.safe_linked_list_destroy
        cls.safe_mms_value_delete = utils.safe_mms_value_delete
        cls.safe_identity_destroy = utils.safe_identity_destroy
        cls.unpack_result = utils.unpack_result


protocol_options = {
    "discover-logical-devices": {
        "type": "bool",
        "description": "Discover logical devices on the server",
        "required": False,
        "default": True,
    },
    "read-values": {
        "type": "bool",
        "description": "Read values from discovered data objects",
        "required": False,
        "default": False,
    },
    "test-write": {
        "type": "bool",
        "description": "Test write access to data objects",
        "required": False,
        "default": False,
    },
    "max-objects": {
        "type": "int",
        "description": "Maximum number of data objects to discover",
        "required": False,
        "default": 1000,
    },
    "wordlist-path": {
        "type": "string",
        "description": "Path to wordlist for object name fuzzing",
        "required": False,
        "default": "",
    },
}


@register_protocol(
    name="MMS Scanner",
    description="""Manufacturing Message Specification (MMS) protocol scanner""",
    default_port=102,
    authors=["f0rw4rd"],
    references=[
        {"type": "url", "ref": "https://en.wikipedia.org/wiki/Manufacturing_Message_Specification"}
    ],
    protocol_options=protocol_options,
)
class MMSScanner(NetworkScanner):
    """IEC 61850 MMS Scanner implementing the base scanner interface.

    Uses pyiec61850-ng safe wrappers for memory management.
    """

    def __init__(self, args: Dict[str, Any]):
        super().__init__(args)
        self.discover_logical_devices = parse_bool(args.get("discover-logical-devices", True))
        self.read_values = parse_bool(args.get("read-values", False))
        self.test_write = parse_bool(args.get("test-write", False))
        self.max_objects = safe_int_conversion(args.get("max-objects"), 1000)
        self.wordlist_path = args.get("wordlist-path", "")

        # Internal state
        self.discovered_objects = []
        self.object_values = {}

    def get_protocol_name(self) -> str:
        return "IEC 61850 MMS"

    def get_default_port(self) -> int:
        return 102

    def check_dependencies(self) -> bool:
        """Check if pyiec61850-ng is available."""
        return _pyiec61850.is_available

    def connect(self) -> Any:
        """Establish IEC 61850 MMS connection."""
        host, port = self.get_target_info()

        _Lib.require()

        try:
            connection = _Lib.iec61850.IedConnection_create()
            if connection is None:
                self.logger.fail("Failed to create IedConnection object")
                return None

            result = _Lib.iec61850.IedConnection_connect(connection, host, port)
            error_code = self._extract_error_code(result)

            if error_code != 0:
                error_name = self._get_error_name(error_code)
                self.logger.fail(f"Connection failed to {host}:{port}: {error_name}")
                _Lib.iec61850.IedConnection_destroy(connection)
                return None

            self.logger.debug(f"Connected to IEC 61850 server at {host}:{port}")
            return connection

        except DependencyError:
            raise
        except Exception as e:
            self.logger.fail(f"Failed to create IEC 61850 connection: {e}")
            return None

    @staticmethod
    def _extract_error_code(result) -> int:
        """Extract integer error code from pyiec61850-ng SWIG result.

        The SWIG binding returns a tuple (None, error_code) instead of a plain int.
        """
        if isinstance(result, tuple):
            for item in reversed(result):
                if isinstance(item, int):
                    return item
            return -1
        if isinstance(result, int):
            return result
        return -1

    def _get_error_name(self, error_code: int) -> str:
        """Convert error code to human-readable name."""
        error_names = {
            _Lib.iec61850.IED_ERROR_OK: "OK",
            _Lib.iec61850.IED_ERROR_NOT_CONNECTED: "Not connected",
            _Lib.iec61850.IED_ERROR_ALREADY_CONNECTED: "Already connected",
            _Lib.iec61850.IED_ERROR_CONNECTION_LOST: "Connection lost",
            _Lib.iec61850.IED_ERROR_SERVICE_NOT_SUPPORTED: "Service not supported",
            _Lib.iec61850.IED_ERROR_CONNECTION_REJECTED: "Connection rejected",
            _Lib.iec61850.IED_ERROR_TIMEOUT: "Timeout",
        }
        return error_names.get(error_code, f"Error code {error_code}")

    def disconnect(self, connection: Any) -> None:
        """Close IEC 61850 MMS connection with proper thread cleanup."""
        if connection is None:
            return

        try:
            try:
                _Lib.iec61850.IedConnection_close(connection)
            except Exception as e:
                self.logger.debug(f"Error during IedConnection_close: {e}")

            time.sleep(0.05)

            try:
                _Lib.iec61850.IedConnection_destroy(connection)
            except Exception as e:
                self.logger.debug(f"Error during IedConnection_destroy: {e}")

        except Exception as e:
            self.logger.debug(f"Error disconnecting: {e}")

    def discover(
        self, connection: Any, server_info: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Perform IEC 61850 MMS discovery and scanning."""
        results = {
            "server_info": {},
            "logical_devices": [],
            "logical_nodes": [],
            "data_objects": [],
            "fingerprint": {},
            "security_analysis": {},
            "read_test_results": {},
            "write_test_results": {},
        }

        try:
            results["server_info"] = (
                server_info if server_info is not None else self._get_server_info(connection)
            )

            if self.scan_mode in ["discovery", "all"]:
                if self.discover_logical_devices:
                    results["logical_devices"] = self._discover_logical_devices(connection)

                results.update(self._discover_data_model(connection, results["logical_devices"]))

                fingerprint = self._fingerprint_device(connection, results["logical_devices"])
                if fingerprint:
                    results["fingerprint"] = fingerprint.to_dict()
                    self._report_fingerprint(fingerprint)

            if self.read_values and self.scan_mode in ["detailed", "all"]:
                results["read_test_results"] = self._read_data_objects(
                    connection, results["data_objects"]
                )

            if self.test_write and not self.read_only:
                results["write_test_results"] = self._test_write_access(
                    connection, results["data_objects"]
                )

            results["security_analysis"] = self._analyze_security(results)
            self._report_findings(results)

        except Exception as e:
            self.logger.fail(f"Error during IEC 61850 discovery: {e}")
            results["error"] = str(e)

        return results

    def _get_server_info(self, connection: Any) -> Dict[str, Any]:
        """Get basic server information with safe memory handling."""
        info = {}
        identity = None
        device_list = None

        try:
            mms_conn = _Lib.iec61850.IedConnection_getMmsConnection(connection)

            if mms_conn:
                mms_error = _Lib.iec61850.MmsError_create()
                identity = _Lib.iec61850.MmsConnection_identify(mms_conn, mms_error)

                if identity is not None:
                    vendor = _Lib.safe_to_char_p(identity.vendorName)
                    model = _Lib.safe_to_char_p(identity.modelName)
                    revision = _Lib.safe_to_char_p(identity.revision)

                    if vendor:
                        info["vendor"] = vendor
                        self.logger.success(f"Vendor: {vendor}")
                    if model:
                        info["model"] = model
                        self.logger.success(f"Model: {model}")
                    if revision:
                        info["revision"] = revision
                        self.logger.display(f"Revision: {revision}")
                else:
                    self.logger.display("MMS Identity: Not available")

        except Exception as e:
            self.logger.debug(f"Error getting MMS identity: {e}")
        finally:
            _Lib.safe_identity_destroy(identity)

        try:
            result = _Lib.iec61850.IedConnection_getLogicalDeviceList(connection)
            device_list, error_code, ok = _Lib.unpack_result(result)

            if ok and device_list is not None:
                device_count = sum(1 for _ in _Lib.safe_linked_list_iter(device_list))
                info["logical_device_count"] = device_count
                self.logger.display(f"IEC 61850 Server has {device_count} logical devices")

        except Exception as e:
            self.logger.debug(f"Failed to get logical device list: {e}")
        finally:
            _Lib.safe_linked_list_destroy(device_list)

        info["supports_get_server_directory"] = True
        return info

    def _fingerprint_device(
        self, connection: Any, logical_devices: List[Dict[str, Any]]
    ) -> Optional[FingerprintMatch]:
        """Enhanced device fingerprinting using IEC 61850 data attributes."""
        if not logical_devices:
            return None

        try:
            matcher = FingerprintMatcher()
            if not matcher.load_fingerprints("mms_fingerprints.json"):
                self.logger.debug("No fingerprint rules loaded")
                return None

            def read_attribute(domain: str, attr_path: str) -> Optional[str]:
                return self._read_iec61850_attribute(connection, domain, attr_path)

            domain_names = [d["name"] for d in logical_devices]
            match = matcher.fingerprint_device(domain_names, read_attribute)
            return match

        except Exception as e:
            self.logger.debug(f"Fingerprinting failed: {e}")
            return None

    def _read_iec61850_attribute(
        self, connection: Any, domain: str, attr_path: str
    ) -> Optional[str]:
        """Read an IEC 61850 data attribute by path."""
        mms_value = None

        try:
            ref = f"{domain}/{attr_path.replace('$', '.')}"
            result = _Lib.iec61850.IedConnection_readObject(
                connection, ref, _Lib.iec61850.IEC61850_FC_DC
            )
            mms_value, error_code, ok = _Lib.unpack_result(result)

            if ok and mms_value is not None:
                return self._extract_mms_value(mms_value)

            return None

        except Exception as e:
            self.logger.debug(f"Failed to read {domain}/{attr_path}: {e}")
            return None
        finally:
            _Lib.safe_mms_value_delete(mms_value)

    def _report_fingerprint(self, fingerprint: FingerprintMatch) -> None:
        """Report fingerprint results."""
        self.logger.success(f"Fingerprint: {fingerprint.fingerprint_name}")

        if fingerprint.vendor:
            self.logger.display(f"  Vendor: {fingerprint.vendor}")
        if fingerprint.model:
            self.logger.display(f"  Model: {fingerprint.model}")
        if fingerprint.serial:
            self.logger.success(f"  Serial: {fingerprint.serial}")
        if fingerprint.firmware:
            self.logger.display(f"  Firmware: {fingerprint.firmware}")
        if fingerprint.hardware_rev:
            self.logger.display(f"  Hardware Rev: {fingerprint.hardware_rev}")

        for name, value in fingerprint.custom.items():
            self.logger.display(f"  {name}: {value}")

    def _discover_logical_devices(self, connection: Any) -> List[Dict[str, Any]]:
        """Discover logical devices on the server."""
        logical_devices = []
        device_list = None

        try:
            result = _Lib.iec61850.IedConnection_getLogicalDeviceList(connection)
            device_list, error_code, ok = _Lib.unpack_result(result)

            if not ok or device_list is None:
                self.logger.display("Logical Devices: None accessible")
                return logical_devices

            device_names = list(_Lib.safe_linked_list_iter(device_list))
            self.logger.display(f"Discovering {len(device_names)} logical devices")

            for device_name in device_names:
                device_info = {"name": device_name, "logical_nodes": [], "accessible": True}
                logical_devices.append(device_info)
                self.logger.debug(f"Found logical device: {device_name}")

            self.logger.display(f"Discovered {len(logical_devices)} logical devices")

        except Exception as e:
            self.logger.fail(f"Error discovering logical devices: {e}")
        finally:
            _Lib.safe_linked_list_destroy(device_list)

        return logical_devices

    def _discover_data_model(
        self, connection: Any, logical_devices: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Discover the complete data model."""
        results = {"logical_nodes": [], "data_objects": []}

        try:
            total_objects = 0

            for device in logical_devices:
                device_name = device["name"]

                logical_nodes = self._get_logical_nodes(connection, device_name)
                device["logical_nodes"] = logical_nodes
                results["logical_nodes"].extend(logical_nodes)

                for ln in logical_nodes:
                    if total_objects >= self.max_objects:
                        self.logger.display(f"Reached maximum object limit ({self.max_objects})")
                        break

                    data_objects = self._get_data_objects(connection, device_name, ln["name"])
                    ln["data_objects"] = data_objects
                    results["data_objects"].extend(data_objects)
                    total_objects += len(data_objects)

                if total_objects >= self.max_objects:
                    break

            ln_count = len(results["logical_nodes"])
            do_count = len(results["data_objects"])
            self.logger.display(f"Discovered {ln_count} logical nodes and {do_count} data objects")

        except Exception as e:
            self.logger.fail(f"Error discovering data model: {e}")

        return results

    def _get_logical_nodes(self, connection: Any, device_name: str) -> List[Dict[str, Any]]:
        """Get logical nodes for a device."""
        logical_nodes = []
        node_list = None

        try:
            result = _Lib.iec61850.IedConnection_getLogicalDeviceDirectory(connection, device_name)
            node_list, error_code, ok = _Lib.unpack_result(result)

            if not ok or node_list is None:
                self.logger.debug(f"No logical nodes found for {device_name}")
                return logical_nodes

            for ln_name in _Lib.safe_linked_list_iter(node_list):
                ln_info = {
                    "name": ln_name,
                    "device": device_name,
                    "full_reference": f"{device_name}/{ln_name}",
                    "data_objects": [],
                }
                logical_nodes.append(ln_info)
                self.logger.debug(f"Found logical node: {ln_info['full_reference']}")

        except Exception as e:
            self.logger.debug(f"Error getting logical nodes for {device_name}: {e}")
        finally:
            _Lib.safe_linked_list_destroy(node_list)

        return logical_nodes

    def _get_data_objects(
        self, connection: Any, device_name: str, ln_name: str
    ) -> List[Dict[str, Any]]:
        """Get data objects for a logical node."""
        data_objects = []
        object_list = None

        try:
            ln_ref = f"{device_name}/{ln_name}"
            result = _Lib.iec61850.IedConnection_getLogicalNodeDirectory(
                connection, ln_ref, _Lib.iec61850.ACSI_CLASS_DATA_OBJECT
            )
            object_list, error_code, ok = _Lib.unpack_result(result)

            if not ok or object_list is None:
                self.logger.debug(f"No data objects found for {ln_ref}")
                return data_objects

            for do_name in _Lib.safe_linked_list_iter(object_list):
                do_info = {
                    "name": do_name,
                    "logical_node": ln_name,
                    "device": device_name,
                    "full_reference": f"{ln_ref}.{do_name}",
                    "readable": False,
                    "writable": False,
                    "value": None,
                    "data_type": None,
                }
                data_objects.append(do_info)
                self.logger.debug(f"Found data object: {do_info['full_reference']}")

        except Exception as e:
            self.logger.debug(f"Error getting data objects for {device_name}/{ln_name}: {e}")
        finally:
            _Lib.safe_linked_list_destroy(object_list)

        return data_objects

    def _read_data_objects(
        self, connection: Any, data_objects: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Read values from data objects."""
        read_results = {"successful_reads": [], "failed_reads": [], "total_tested": 0}

        self.logger.display(f"Testing read access to {len(data_objects)} data objects")
        progress = ProgressTracker(len(data_objects), logger=self.logger)

        for do in data_objects:
            read_results["total_tested"] += 1
            mms_value = None

            try:
                for fc in [_Lib.iec61850.IEC61850_FC_MX, _Lib.iec61850.IEC61850_FC_ST]:
                    result = _Lib.iec61850.IedConnection_readObject(
                        connection, do["full_reference"], fc
                    )
                    mms_value, error_code, ok = _Lib.unpack_result(result)

                    if ok and mms_value is not None:
                        break

                if mms_value is not None:
                    python_value = self._extract_mms_value(mms_value)

                    do["readable"] = True
                    do["value"] = python_value
                    do["data_type"] = self._get_mms_type_name(mms_value)

                    read_results["successful_reads"].append(
                        {
                            "reference": do["full_reference"],
                            "value": do["value"],
                            "data_type": do["data_type"],
                        }
                    )
                    self.logger.debug(f"Read {do['full_reference']}: {do['value']}")
                else:
                    read_results["failed_reads"].append(
                        {
                            "reference": do["full_reference"],
                            "error": "Read returned None",
                        }
                    )

            except Exception as e:
                read_results["failed_reads"].append(
                    {"reference": do["full_reference"], "error": str(e)}
                )
            finally:
                _Lib.safe_mms_value_delete(mms_value)

            progress.update()

        ok = len(read_results["successful_reads"])
        fail = len(read_results["failed_reads"])
        self.logger.display(f"Read test complete: {ok} successful, {fail} failed")
        return read_results

    def _extract_mms_value(self, mms_value: Any) -> Any:
        """Extract Python value from MmsValue."""
        if mms_value is None:
            return None

        try:
            mms_type = _Lib.iec61850.MmsValue_getType(mms_value)

            if mms_type == _Lib.iec61850.MMS_DATA_ACCESS_ERROR:
                return None
            elif mms_type == _Lib.iec61850.MMS_BOOLEAN:
                return _Lib.iec61850.MmsValue_getBoolean(mms_value)
            elif mms_type in [_Lib.iec61850.MMS_INTEGER, _Lib.iec61850.MMS_UNSIGNED]:
                return _Lib.iec61850.MmsValue_toInt32(mms_value)
            elif mms_type == _Lib.iec61850.MMS_FLOAT:
                return _Lib.iec61850.MmsValue_toFloat(mms_value)
            elif mms_type in [_Lib.iec61850.MMS_VISIBLE_STRING, _Lib.iec61850.MMS_STRING]:
                ptr = _Lib.iec61850.MmsValue_toString(mms_value)
                return _Lib.safe_to_char_p(ptr)
            elif mms_type == _Lib.iec61850.MMS_BIT_STRING:
                return _Lib.iec61850.MmsValue_getBitStringAsInteger(mms_value)
            elif mms_type == _Lib.iec61850.MMS_STRUCTURE:
                return "<structure>"
            elif mms_type == _Lib.iec61850.MMS_ARRAY:
                return "<array>"
            else:
                return None

        except Exception as e:
            self.logger.debug(f"Failed to get mms_type: {e}")
            return None

    def _get_mms_type_name(self, mms_value: Any) -> str:
        """Get MMS type name."""
        if mms_value is None:
            return "unknown"

        try:
            mms_type = _Lib.iec61850.MmsValue_getType(mms_value)
            type_names = {
                _Lib.iec61850.MMS_BOOLEAN: "boolean",
                _Lib.iec61850.MMS_INTEGER: "integer",
                _Lib.iec61850.MMS_UNSIGNED: "unsigned",
                _Lib.iec61850.MMS_FLOAT: "float",
                _Lib.iec61850.MMS_VISIBLE_STRING: "visible_string",
                _Lib.iec61850.MMS_STRING: "string",
                _Lib.iec61850.MMS_BIT_STRING: "bit_string",
                _Lib.iec61850.MMS_STRUCTURE: "structure",
                _Lib.iec61850.MMS_ARRAY: "array",
            }
            return type_names.get(mms_type, f"type_{mms_type}")
        except Exception as e:
            self.logger.debug(f"Failed to get mms_type: {e}")
            return "unknown"

    def _test_write_access(
        self, connection: Any, data_objects: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Test write access to data objects."""
        write_results = {"successful_writes": [], "failed_writes": [], "total_tested": 0}

        if self.read_only:
            self.logger.display("Skipping write tests (read-only mode)")
            return write_results

        writable_objects = [
            do for do in data_objects if do.get("readable") and do.get("value") is not None
        ]

        self.logger.display(
            f"Testing write access to {len(writable_objects)} readable data objects"
        )

        for do in writable_objects[:10]:
            write_results["total_tested"] += 1

            try:
                success = self._write_data_object(
                    connection, do["full_reference"], do["value"], do.get("data_type")
                )

                if success:
                    do["writable"] = True
                    write_results["successful_writes"].append(
                        {"reference": do["full_reference"], "original_value": do["value"]}
                    )
                    self.logger.display(f"WRITABLE: {do['full_reference']}")
                else:
                    write_results["failed_writes"].append(
                        {"reference": do["full_reference"], "error": "Write failed"}
                    )

            except Exception as e:
                write_results["failed_writes"].append(
                    {"reference": do["full_reference"], "error": str(e)}
                )

        ok = len(write_results["successful_writes"])
        fail = len(write_results["failed_writes"])
        self.logger.display(f"Write test complete: {ok} writable, {fail} not writable")
        return write_results

    def _write_data_object(
        self, connection: Any, reference: str, value: Any, data_type: str = None
    ) -> bool:
        """Write a value to a data object."""
        mms_value = None

        try:
            mms_value = self._create_mms_value(value, data_type)

            if mms_value is None:
                return False

            for fc in [
                _Lib.iec61850.IEC61850_FC_CO,
                _Lib.iec61850.IEC61850_FC_SP,
                _Lib.iec61850.IEC61850_FC_MX,
            ]:
                result = _Lib.iec61850.IedConnection_writeObject(
                    connection, reference, fc, mms_value
                )
                _, _, ok = _Lib.unpack_result(result)

                if ok:
                    return True

            return False

        except Exception as e:
            self.logger.debug(f"Error writing to {reference}: {e}")
            return False
        finally:
            _Lib.safe_mms_value_delete(mms_value)

    def _create_mms_value(self, value: Any, data_type: str = None) -> Any:
        """Create MmsValue from Python value."""
        try:
            if isinstance(value, bool):
                return _Lib.iec61850.MmsValue_newBoolean(value)
            elif isinstance(value, int):
                return _Lib.iec61850.MmsValue_newInteger(value)
            elif isinstance(value, float):
                return _Lib.iec61850.MmsValue_newFloat(value)
            elif isinstance(value, str):
                return _Lib.iec61850.MmsValue_newVisibleString(value)
            else:
                return _Lib.iec61850.MmsValue_newInteger(int(value))
        except Exception as e:
            self.logger.debug(f"if isinstance(value, bool):: {e}")
            return None

    def _analyze_security(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze security configuration."""
        analysis = SecurityAnalyzer.assess_protocol_security(
            {
                "authentication": False,
                "authorization": False,
                "encryption": False,
                "integrity_check": False,
                "access_control": len(
                    results.get("write_test_results", {}).get("successful_writes", [])
                )
                == 0,
            }
        )

        analysis["concerns"] = []

        device_count = len(results.get("logical_devices", []))
        if device_count > 0:
            analysis["concerns"].append(f"{device_count} logical devices accessible")

        object_count = len(results.get("data_objects", []))
        if object_count > 0:
            analysis["concerns"].append(f"{object_count} data objects discovered")

        read_count = len(results.get("read_test_results", {}).get("successful_reads", []))
        if read_count > 0:
            analysis["concerns"].append(f"{read_count} data objects readable")

        write_count = len(results.get("write_test_results", {}).get("successful_writes", []))
        if write_count > 0:
            analysis["concerns"].append(f"{write_count} data objects writable")

        return analysis

    def _report_findings(self, results: Dict[str, Any]) -> None:
        """Report scanner findings."""
        host, port = self.get_target_info()

        self.report_host_info(host)
        self.report_service_info(host, port=port, name="iec61850-mms", proto="tcp")

        for device in results.get("logical_devices", []):
            self.logger.display(f"IEC 61850 Logical Device: {device['name']}")

        security_analysis = results.get("security_analysis", {})
        for concern in security_analysis.get("concerns", []):
            self.report_vulnerability(host, "iec61850_security", description=concern)


# Create metadata and run function using protocol module factory
metadata, run = create_protocol_module(
    MMSScanner, dependencies_check_func=lambda: not _pyiec61850.is_available
)


if __name__ == "__main__":
    from utils.cli import main  # type: ignore[import-not-found]

    main(sys.argv, run, metadata)


# Re-export NXC-style callable class
from .nxc_connection import mms as mms  # noqa: E402

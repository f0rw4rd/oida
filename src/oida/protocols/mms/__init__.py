#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MMS (Manufacturing Message Specification) Protocol Scanner

Built on pyiec61850-ng's high-level ``pyiec61850.mms.MMSClient`` for connection,
identity, discovery, reads and FC-aware writes.
Requires pyiec61850-ng >= 1.6.1.4 (FC-aware ``write_value`` and a working
``get_server_identity``; with the ``pyiec61850.mms`` submodule).

Requires: pip install oida-ics[mms]
"""

import time
from typing import Dict, List, Any, Optional

from oida.utils import (
    NetworkScanner,
    SecurityAnalyzer,
    ProgressTracker,
    parse_bool,
    safe_int_conversion,
)
from oida.utils.exceptions import DependencyError
from oida.utils.lazy_import import lazy_import
from oida.protocols.mms.fingerprint import FingerprintMatcher, FingerprintMatch

# Lazy imports for pyiec61850-ng (only loaded when actually used)
_pyiec61850 = lazy_import("pyiec61850", "MMS", install_hint="pip install oida-ics[mms]")
_pyiec61850_mms = lazy_import("pyiec61850.mms", "MMS", install_hint="pip install oida-ics[mms]")
_pyiec61850_tls = lazy_import("pyiec61850.mms.tls", "MMS", install_hint="pip install oida-ics[mms]")


class _Lib:
    """Lazy-loaded pyiec61850-ng high-level client (thread-safe namespace).

    The scanner runs entirely on the package's high-level ``MMSClient`` wrapper,
    which handles connection lifecycle, identity decoding, name-list iteration
    and MmsValue<->Python marshalling internally. Requires pyiec61850-ng
    >= 1.6.1.4, which fixed ``write_value`` (now FC-aware) and
    ``get_server_identity`` (earlier builds called a binding function that did
    not exist). The one residual rough edge — ``read_value``'s lossy converter
    returning a ``"<MmsValue type=N>"`` placeholder for complex/error types — is
    smoothed over by ``MMSScanner._normalize_read``.
    """

    # Runtime-populated by require(); typed Any so attribute access on the
    # lazily-loaded binding (e.g. FC.DC, MmsType.STRUCTURE) is not flagged as
    # access on the None placeholder.
    MMSClient: Any = None
    FC: Any = None
    MmsType: Any = None
    ServerIdentity: Any = None
    MMSError: Any = None
    ConnectionFailedError: Any = None
    ReadError: Any = None
    WriteError: Any = None

    @classmethod
    def require(cls):
        """Load pyiec61850-ng (raises DependencyError if missing)."""
        if cls.MMSClient is not None:
            return

        mms = _pyiec61850_mms()
        cls.MMSClient = mms.MMSClient
        cls.FC = mms.FC
        cls.MmsType = mms.MmsType
        cls.ServerIdentity = mms.ServerIdentity
        cls.MMSError = mms.MMSError
        cls.ConnectionFailedError = mms.ConnectionFailedError
        cls.ReadError = mms.ReadError
        cls.WriteError = mms.WriteError


def build_mms_tls_config(
    *,
    tls: bool,
    logger: Any,
    tls_ca: Optional[str] = None,
    tls_pin: Optional[str] = None,
    client_cert: Optional[str] = None,
    client_key: Optional[str] = None,
) -> Optional[Any]:
    """Return a ``TLSConfig`` for an MMS connection, or ``None`` for plaintext.

    Shared by the MMS scanner and the GOOSE GoCB-enumeration MMS sub-connection
    so both apply the same policy:
      * neither ``tls_ca`` nor ``tls_pin``  -> ``insecure=True`` (no validation)
      * ``tls_pin``                         -> pin that exact server certificate
      * ``tls_ca``                          -> validate the chain against the CA
    ``client_cert``/``client_key`` add a client certificate (mutual TLS) in any
    mode. Raises ``DependencyError`` if pyiec61850-ng is not installed.
    """
    if not tls:
        return None
    TLSConfig = _pyiec61850_tls().TLSConfig

    own_cert = client_cert or ""
    own_key = client_key or ""

    if tls_pin:
        logger.debug("TLS: pinning server certificate %s", tls_pin)
        return TLSConfig.pinning(tls_pin, own_cert=own_cert, own_key=own_key)
    if tls_ca:
        logger.debug("TLS: validating chain against CA %s", tls_ca)
        return TLSConfig(ca_certs=[tls_ca], own_cert=own_cert, own_key=own_key)

    logger.debug("TLS: certificate validation disabled (no --tls-ca/--tls-pin)")
    return TLSConfig(insecure=True, own_cert=own_cert, own_key=own_key)


def _write_under_fc(client: Any, reference: str, value: Any, fc: Any) -> bool:
    """Write ``value`` to ``reference`` under an explicit functional constraint.

    A thin bool-returning adapter over ``MMSClient.write_value(ref, val, fc=fc)``
    (FC-aware as of pyiec61850-ng 1.6.1.4). The write/fuzz probe loops try each
    FC in turn and move on when one is rejected, so they want a boolean rather
    than the ``WriteError`` the high-level method raises on failure.
    """
    try:
        return bool(client.write_value(reference, value, fc=fc))
    except _Lib.WriteError:
        return False
    except Exception:
        return False


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
}


class MMSScanner(NetworkScanner):
    """IEC 61850 MMS Scanner implementing the base scanner interface.

    Runs on pyiec61850-ng's high-level MMSClient (see module docstring).
    """

    def __init__(self, args: Dict[str, Any]):
        super().__init__(args)
        self.discover_logical_devices = parse_bool(args.get("discover-logical-devices", True))
        self.read_values = parse_bool(args.get("read-values", False))
        self.test_write = parse_bool(args.get("test-write", False))
        self.confirm = parse_bool(args.get("confirm", False))
        self.max_objects = safe_int_conversion(args.get("max-objects"), 1000)
        # Single-action selectors. --identify queries server identity (always
        # done as part of server-info); --get-name-list forces logical-device
        # enumeration; --variable reads one data object by reference substring.
        self.identify = parse_bool(args.get("identify", False))
        self.get_name_list = parse_bool(args.get("get-name-list", False))
        self.variable = args.get("variable") or None

        # TLS (pyiec61850-ng >= 1.6.1.9). Validation is DISABLED by default:
        # oida connects to arbitrary IEC 61850 endpoints whose certs are usually
        # self-signed / hostname-mismatched, so --tls yields an encrypted-but-
        # unvalidated session unless the operator supplies trust material
        # (--tls-ca / --tls-pin). See _build_tls_config().
        self.tls = parse_bool(args.get("tls", False))
        self.tls_port = safe_int_conversion(args.get("tls-port"), 3782)
        self.tls_ca = args.get("tls-ca") or None
        self.tls_pin = args.get("tls-pin") or None
        self.tls_client_cert = args.get("tls-client-cert") or None
        self.tls_client_key = args.get("tls-client-key") or None

        # --test-write is a destructive op: requires --confirm and clears the
        # read-only guard so the write path actually runs.
        if self.test_write:
            if self.confirm:
                self.read_only = False
            else:
                self.logger.fail(
                    "--test-write requires --confirm flag (DANGEROUS: issues live writes)"
                )
                self.test_write = False

        # Internal state

    def get_protocol_name(self) -> str:
        return "IEC 61850 MMS"

    def get_default_port(self) -> int:
        return 102

    def check_dependencies(self) -> bool:
        """Check if pyiec61850-ng is available."""
        return _pyiec61850.is_available

    def _build_tls_config(self):
        """Return a ``pyiec61850.mms.tls.TLSConfig`` for the connection, or None.

        Returns None when ``--tls`` was not requested (plaintext MMS). When TLS
        is requested, certificate validation is DISABLED by default (an
        encrypted-but-unvalidated session): oida is an authorized testing tool
        that connects to arbitrary endpoints whose certs are typically
        self-signed or hostname-mismatched, and libiec61850 does not match
        CN/SAN against the host anyway. Validation is only enabled when the
        operator explicitly supplies trust material:
          * ``--tls-pin <server.crt>``   -> strict pin to that certificate
          * ``--tls-ca  <ca.crt>``       -> validate the chain against the CA
        ``--tls-client-cert``/``--tls-client-key`` add a client certificate
        (mutual TLS) in any mode.
        """
        return build_mms_tls_config(
            tls=self.tls,
            tls_ca=self.tls_ca,
            tls_pin=self.tls_pin,
            client_cert=self.tls_client_cert,
            client_key=self.tls_client_key,
            logger=self.logger,
        )

    def connect(self) -> Any:
        """Establish IEC 61850 MMS connection.

        Returns the high-level ``MMSClient`` (the "connection" object threaded
        through ``discover``/``disconnect`` and the NXC fuzz path), or ``None``
        on failure.
        """
        host, port = self.get_target_info()

        _Lib.require()

        tls_config = self._build_tls_config()
        # MMS-over-TLS listens on 3782 by default; switch to it when --tls is on
        # and the operator did not override the port off the plaintext default.
        if tls_config is not None and port == self.get_default_port():
            port = self.tls_port

        try:
            if tls_config is not None:
                client = _Lib.MMSClient(timeout=self.timeout * 1000, tls=tls_config)
            else:
                client = _Lib.MMSClient(timeout=self.timeout * 1000)
            client.connect(host, int(port))

            self.logger.debug(f"Connected to IEC 61850 server at {host}:{port}")
            if tls_config is None:
                # Confirmed MMS / IEC 61850 association over TCP — cleartext.
                self.logger.security_finding(
                    "No encryption",
                    detail="MMS / IEC 61850 transmitted in cleartext (no TLS)",
                )
            elif not (self.tls_ca or self.tls_pin):
                # TLS with validation disabled: the session is encrypted but the
                # server certificate was not authenticated.
                self.logger.security_finding(
                    "TLS certificate not validated",
                    detail=(
                        "MMS/TLS session established without certificate validation "
                        "(--tls-ca/--tls-pin not supplied); transport is encrypted but "
                        "the endpoint identity is unverified"
                    ),
                )
            return client

        except DependencyError:
            raise
        except _Lib.ConnectionFailedError as e:
            self.logger.fail(f"Connection failed to {host}:{port}: {e}")
            return None
        except Exception as e:
            self.logger.fail(f"Failed to create IEC 61850 connection: {e}")
            return None

    def disconnect(self, connection: Any) -> None:
        """Close the IEC 61850 MMS connection."""
        if connection is None:
            return

        try:
            connection.disconnect()
            time.sleep(0.05)
            self.logger.debug("Connection closed")
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
            # --identify forces a fresh server-identity query even if a cached
            # server_info was passed in; otherwise reuse what the caller fetched.
            if self.identify or server_info is None:
                results["server_info"] = self._get_server_info(connection)
            else:
                results["server_info"] = server_info

            # --get-name-list and --variable both need the data model, so force
            # the discovery path even if scan_mode would otherwise skip it.
            do_discovery = (
                self.scan_mode in ["discovery", "all"] or self.get_name_list or self.variable
            )
            if do_discovery:
                if self.discover_logical_devices:
                    results["logical_devices"] = self._discover_logical_devices(connection)

                results.update(self._discover_data_model(connection, results["logical_devices"]))

                fingerprint = self._fingerprint_device(connection, results["logical_devices"])
                if fingerprint:
                    results["fingerprint"] = fingerprint.to_dict()
                    self._report_fingerprint(fingerprint)

            # --variable: read just the object(s) whose reference matches.
            if self.variable:
                targets = [
                    do
                    for do in results["data_objects"]
                    if self.variable.lower() in do.get("full_reference", "").lower()
                ]
                if targets:
                    results["read_test_results"] = self._read_data_objects(connection, targets)
                else:
                    self.logger.warning(f"No data object matched variable '{self.variable}'")
            elif self.read_values and self.scan_mode in ["detailed", "all"]:
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
        """Get basic server information (identity + logical-device count)."""
        info = {}

        try:
            identity = connection.get_server_identity()
            if identity.vendor:
                info["vendor"] = identity.vendor
                self.logger.success(f"Vendor: {identity.vendor}")
            if identity.model:
                info["model"] = identity.model
                self.logger.success(f"Model: {identity.model}")
            if identity.revision:
                info["revision"] = identity.revision
                self.logger.display(f"Revision: {identity.revision}")
            if not (identity.vendor or identity.model or identity.revision):
                self.logger.display("MMS Identity: Not available")
        except Exception as e:
            self.logger.debug(f"Error getting MMS identity: {e}")

        try:
            device_count = len(connection.get_logical_devices())
            info["logical_device_count"] = device_count
            # get_logical_devices() IS a GetServerDirectory request, so its
            # success is the actual evidence of support -- rather than hardcoding
            # the key True (an unverified always-true claim in the export).
            info["supports_get_server_directory"] = True
            self.logger.display(f"IEC 61850 Server has {device_count} logical devices")
        except Exception as e:
            info["supports_get_server_directory"] = False
            self.logger.debug(f"Failed to get logical device list: {e}")

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
        """Read an IEC 61850 data attribute by path (under FC_DC)."""
        try:
            ref = f"{domain}/{attr_path.replace('$', '.')}"
            value = self._normalize_read(connection.read_value(ref, fc=_Lib.FC.DC))
            return str(value) if value is not None else None
        except _Lib.ReadError:
            return None
        except Exception as e:
            self.logger.debug(f"Failed to read {domain}/{attr_path}: {e}")
            return None

    @staticmethod
    def _normalize_read(value: Any) -> Any:
        """Normalize MMSClient.read_value()'s lossy converter output.

        The high-level read_value() returns a "<MmsValue type=N>" placeholder
        string for any type its scalar converter doesn't handle, including
        DATA_ACCESS_ERROR. Map that error placeholder to None (so the FC
        fallback and "failed read" accounting behave as before), and render
        structure/array placeholders as the friendly "<structure>"/"<array>"
        labels the old extractor produced. Scalars pass through untouched.
        """
        if not (
            isinstance(value, str) and value.startswith("<MmsValue type=") and value.endswith(">")
        ):
            return value
        try:
            tag = int(value[len("<MmsValue type=") : -1])
        except ValueError:
            return value
        if tag == int(_Lib.MmsType.DATA_ACCESS_ERROR):
            return None
        if tag == int(_Lib.MmsType.STRUCTURE):
            return "<structure>"
        if tag == int(_Lib.MmsType.ARRAY):
            return "<array>"
        return value

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

        try:
            device_names = connection.get_logical_devices()

            if not device_names:
                self.logger.display("Logical Devices: None accessible")
                return logical_devices

            self.logger.display(f"Discovering {len(device_names)} logical devices")

            for device_name in device_names:
                # Bound materialization: a hostile/misbehaving endpoint can return
                # a huge GetNameList that would exhaust memory before the
                # data-object cap ever applies.
                if len(logical_devices) >= self.max_objects:
                    self.logger.display(
                        f"Reached maximum object limit ({self.max_objects}) for logical devices"
                    )
                    break
                device_info = {"name": device_name, "logical_nodes": [], "accessible": True}
                logical_devices.append(device_info)
                self.logger.debug(f"Found logical device: {device_name}")

            self.logger.display(f"Discovered {len(logical_devices)} logical devices")

        except Exception as e:
            self.logger.fail(f"Error discovering logical devices: {e}")

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

        try:
            for ln_name in connection.get_logical_nodes(device_name):
                # Bound materialization against an oversized GetNameList.
                if len(logical_nodes) >= self.max_objects:
                    self.logger.debug(
                        f"Reached maximum object limit ({self.max_objects}) for logical nodes"
                    )
                    break
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

        return logical_nodes

    def _get_data_objects(
        self, connection: Any, device_name: str, ln_name: str
    ) -> List[Dict[str, Any]]:
        """Get data objects for a logical node."""
        data_objects = []

        try:
            ln_ref = f"{device_name}/{ln_name}"
            for do_name in connection.get_data_objects(device_name, ln_name):
                # Bound materialization against an oversized GetNameList.
                if len(data_objects) >= self.max_objects:
                    self.logger.debug(
                        f"Reached maximum object limit ({self.max_objects}) for data objects"
                    )
                    break
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

            try:
                # Measurements live under MX, status points under ST, and
                # name-plate / description objects (NamPlt, PhyNam) under DC.
                # Try them in that order so description objects — which return
                # DATA_ACCESS_ERROR under MX/ST — are read from their real FC
                # instead of being dropped.
                value = None
                for fc in (_Lib.FC.MX, _Lib.FC.ST, _Lib.FC.DC):
                    try:
                        value = self._normalize_read(
                            connection.read_value(do["full_reference"], fc=fc)
                        )
                        if value is not None:
                            break
                    except _Lib.ReadError:
                        continue

                if value is not None:
                    do["readable"] = True
                    do["value"] = value
                    do["data_type"] = self._python_type_name(value)

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

            progress.update()

        ok = len(read_results["successful_reads"])
        fail = len(read_results["failed_reads"])
        self.logger.display(f"Read test complete: {ok} successful, {fail} failed")
        return read_results

    @staticmethod
    def _python_type_name(value: Any) -> str:
        """Label a value read via MMSClient by its Python type.

        MMSClient.read_value() already converts the MmsValue to a native Python
        type, so the MMS type is no longer directly available; the python type
        is a faithful enough label for display/export. Complex MMS types are
        normalized by _normalize_read() to "<structure>"/"<array>" placeholders.
        """
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, int):
            return "integer"
        if isinstance(value, float):
            return "float"
        if isinstance(value, str):
            if value == "<structure>":
                return "structure"
            if value == "<array>":
                return "array"
            return "string"
        if isinstance(value, (list, tuple)):
            return "array"
        if isinstance(value, dict):
            return "structure"
        return type(value).__name__

    def _test_write_access(
        self, connection: Any, data_objects: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Test write access to data objects."""
        write_results = {"successful_writes": [], "failed_writes": [], "total_tested": 0}

        if self.read_only:
            self.logger.display("Skipping write tests (read-only mode)")
            return write_results

        if not self.confirm:
            self.logger.fail("--test-write requires --confirm flag (DANGEROUS: issues live writes)")
            return write_results

        # Objects only carry a value if a prior read pass ran (--read-values /
        # --variable). --test-write must work standalone, so read any missing
        # values on demand here (same FC cascade as _read_data_objects) before
        # selecting writable candidates — otherwise it silently tests nothing.
        for do in data_objects:
            if do.get("value") is not None:
                continue
            for fc in (_Lib.FC.MX, _Lib.FC.ST, _Lib.FC.DC):
                try:
                    value = self._normalize_read(connection.read_value(do["full_reference"], fc=fc))
                except _Lib.ReadError:
                    continue
                if value is not None:
                    do["readable"] = True
                    do["value"] = value
                    do["data_type"] = self._python_type_name(value)
                    break

        writable_objects = [
            do for do in data_objects if do.get("readable") and do.get("value") is not None
        ]

        self.logger.display(
            f"Testing write access to {len(writable_objects)} readable data objects"
        )

        for do in writable_objects[:10]:
            write_results["total_tested"] += 1

            try:
                success = self._write_data_object(connection, do["full_reference"], do["value"])

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

    def _write_data_object(self, connection: Any, reference: str, value: Any) -> bool:
        """Write a value to a data object, probing CO -> SP -> MX.

        A data object is writable under whichever functional constraint the
        server accepts (control objects under CO, setpoints under SP, some
        measurements under MX); try them in impact order and return on the
        first success. Uses the FC-aware write shim because the high-level
        write_value() is FC_ST-only (see /tmp/issue).
        """
        for fc in (_Lib.FC.CO, _Lib.FC.SP, _Lib.FC.MX):
            if _write_under_fc(connection, reference, value, fc):
                return True
        return False

    def _analyze_security(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze security configuration."""
        write_count = len(results.get("write_test_results", {}).get("successful_writes", []))

        # access_control is only KNOWN when --test-write actually ran. On a
        # discovery-only scan write_count is trivially 0, so `write_count == 0`
        # falsely asserted "has access control" (crediting 2 points and
        # suppressing the missing-access-control issue) -- conflating "never
        # tested" with "prevented". Require the write test to have run.
        write_tested = "write_test_results" in results
        analysis = SecurityAnalyzer.assess_protocol_security(
            {
                "authentication": False,
                "authorization": False,
                "encryption": False,
                "integrity_check": False,
                "access_control": write_tested and write_count == 0,
            }
        )

        # Only write/auth/encryption/integrity concerns are vulnerabilities.
        # Benign discovery counts (logical devices, data objects, readable
        # objects) are informational, not findings -- they were previously
        # appended here and reported via report_vulnerability(), inflating
        # the vuln count with non-issues.
        analysis["concerns"] = list(analysis.get("issues", []))

        # When writes were never tested, relabel the auto-generated "Missing
        # access control" so it reads as "not tested" rather than a confirmed
        # finding (run --test-write to actually assess it).
        if not write_tested and "Missing access control" in analysis["concerns"]:
            i = analysis["concerns"].index("Missing access control")
            analysis["concerns"][i] = "Access control not tested (run --test-write to assess)"

        if write_count > 0:
            analysis["concerns"].append(
                f"{write_count} data objects writable without authentication"
            )

        return analysis

    def _report_findings(self, results: Dict[str, Any]) -> None:
        """Report scanner findings."""
        host, port = self.get_target_info()

        self.report_host_info(host)
        self.report_service_info(host, port=port, name="iec61850-mms", proto="tcp")

        self._report_data_model(results.get("logical_devices", []))

        security_analysis = results.get("security_analysis", {})
        for concern in security_analysis.get("concerns", []):
            self.report_vulnerability(host, "iec61850_security", description=concern)

    def _report_data_model(self, logical_devices: List[Dict[str, Any]]) -> None:
        """Print the discovered IEC 61850 data model as an indented tree.

        Counts alone ("3 logical nodes and 23 data objects") don't tell an
        operator what is actually present on the device. Walk the nested
        logical-device -> logical-node -> data-object hierarchy and print the
        names, with read values / writable flags when those scans ran.
        """
        for device in logical_devices:
            self.logger.success(f"Logical Device: {device['name']}")

            logical_nodes = device.get("logical_nodes", [])
            for ln in logical_nodes:
                data_objects = ln.get("data_objects", [])
                self.logger.display(f"  LN {ln['name']} ({len(data_objects)} objects)")

                for do in data_objects:
                    # Print the qualified LN.DO name (e.g. GGIO1.Mod): it
                    # disambiguates objects that repeat across nodes (Mod, Beh,
                    # Health, NamPlt all appear under several LNs) and is a valid
                    # substring for -r/--variable, so it can be copied straight
                    # from this tree into a follow-up read.
                    ref = f"{ln['name']}.{do['name']}"
                    self.logger.display(f"    {ref}{self._format_do_detail(do)}")

    @staticmethod
    def _format_do_detail(do: Dict[str, Any]) -> str:
        """Build the trailing ' = value (type) [W]' annotation for a data object.

        Only the parts that were actually populated by a read/write scan are
        shown; in plain discovery mode this returns an empty string so the tree
        stays compact.
        """
        parts = []
        if do.get("readable") and do.get("value") is not None:
            value = do["value"]
            data_type = do.get("data_type")
            parts.append(f" = {value}" + (f" ({data_type})" if data_type else ""))
        if do.get("writable"):
            parts.append(" [WRITABLE]")
        return "".join(parts)


# Create metadata and run function using protocol module factory


# Re-export NXC-style callable class
from oida.protocols.mms.cli_runner import mms as mms  # noqa: E402

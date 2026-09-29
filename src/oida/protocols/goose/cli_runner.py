#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GOOSE NXC-style callable class."""

from oida.connection import SerialConnection
from oida.utils.permissions import check_raw_socket_capability

from oida.protocols.goose import GOOSEScanner


class goose(SerialConnection):
    """NXC-style GOOSE scanner (callable)"""

    def __init__(self, args, db, host):
        self.protocol_name = "IEC 61850 GOOSE"
        self.default_port = 0
        super().__init__(args, db, host)

    def proto_flow(self):
        """Main GOOSE scanning workflow"""
        args_dict = self._convert_args_to_dict()
        self.scanner = GOOSEScanner(args_dict)
        # Determine mode
        mms_enum = getattr(self.args, "mms_enum", None)
        rgoose = getattr(self.args, "rgoose", False)

        if mms_enum:
            # GoCB enumeration via MMS - no raw socket needed
            self.logger.display(f"Enumerating GoCBs on {mms_enum} via MMS...")
            # Stamp the effective port before connecting: default_port is 0
            # (passive GOOSE is layer-2, portless), so without this the MMS
            # probe and the target display both fall back to port 0 (GH #59).
            # With --tls on and the MMS port left at the plaintext default,
            # the scanner switches to tls_port - show the port actually
            # dialed (GH #59 port-consistency).
            effective_port = int(getattr(self.args, "mms_port", 102) or 102)
            if getattr(self.args, "tls", False) and effective_port == 102:
                from oida.utils.protocol_helpers import safe_int_conversion

                effective_port = safe_int_conversion(getattr(self.args, "tls_port", None), 3782)
            self.results["port"] = effective_port
            # Keep the per-line logger prefix in sync too - the banner and
            # failure line must show the MMS port, not the portless default
            # (GH #59 port-consistency).
            extra = getattr(getattr(self, "logger", None), "extra", None)
            if extra is not None:
                extra["port"] = self.results["port"]
            self.create_conn_obj()
            if self.conn:
                self._execute_scan()
            else:
                # No MMS connection established -> nothing was enumerated.
                # Without this, connection.py's run() would default
                # results["success"] to True and fabricate a false positive.
                # create_conn_obj() already recorded the canonical
                # connect-failure line + cause (GH issue #59).
                self.results["success"] = False
        elif rgoose:
            # R-GOOSE UDP mode - not yet supported
            self.logger.fail(
                "R-GOOSE mode not yet supported in the high-level API. "
                "R-GOOSE support will be added when pyiec61850-ng provides a wrapper."
            )
            # Nothing was scanned -> do not report a false-positive success.
            self.results["success"] = False
            self.results.setdefault("error", "R-GOOSE mode not supported (no scan performed)")
        else:
            # Passive GOOSE sniffing - needs raw socket
            has_cap, msg = check_raw_socket_capability()
            if not has_cap:
                self.logger.fail(
                    "Raw socket access required for GOOSE sniffing. "
                    "Run as root or with CAP_NET_RAW capability."
                )
                if msg:
                    self.logger.fail(f"  Detail: {msg}")
                self.results["success"] = False
                self.results.setdefault(
                    "error",
                    "Raw socket access required for GOOSE sniffing (capability missing)",
                )
                return

            self.create_conn_obj()
            if self.conn:
                self.enum_host_info()
                self.print_host_info()
                self._execute_scan()
            else:
                # Interface could not be opened (e.g. nonexistent interface) ->
                # no capture happened. Explicitly fail rather than inheriting
                # the connection.py default-success false positive.
                self.results["success"] = False
                self.results.setdefault(
                    "error",
                    "No GOOSE response (interface could not be opened / connection failed)",
                )

    def create_conn_obj(self):
        """Create GOOSE connection object."""
        if getattr(self.args, "mms_enum", None):
            # MMS mode is a real TCP connect to the --mms-enum host on
            # --mms-port; show that target, matching the failure line below
            # (GH #59 port-consistency). results["port"] already holds the
            # effective port (proto_flow stamped it, including the TLS switch).
            mms_host = self.args.mms_enum
            self.logger.info(f"Connecting via MMS to {mms_host}:{self.results['port']}")
        else:
            self.logger.info(f"Connecting to {self.host}")
        self.conn = self.scanner.connect()
        if self.conn:
            conn_type = self.conn.get("type", "unknown")
            self.logger.success(f"GOOSE {conn_type} ready on {self.host}")
        elif getattr(self.args, "mms_enum", None):
            # MMS GoCB-enumeration mode is a real TCP path: recover the cause
            # with a one-shot raw TCP probe for the shared vocabulary (GH #59).
            # The probe targets --mms-enum (self.ip may be an interface name in
            # this mode); passive GOOSE mode opens a layer-2 capture, not a
            # socket, so it keeps the interface-specific error from
            # proto_flow().
            # A TLS config error (bad --tls-ca path etc.) never reached the
            # socket: skip the probe and let the stored exception carry the
            # reason, message included.
            scanner_exc = getattr(self.scanner, "_last_connect_error", None)
            # isinstance against BaseException: a MagicMock scanner
            # auto-creates every attribute, so a bare "is not None" would
            # misroute plain connect failures into the TLS branch.
            if isinstance(scanner_exc, BaseException):
                # probed=True: the config error never reached the socket, so
                # the rescue probe would hit a healthy port and rewrite the
                # cause, hiding the real reason (mms runner has the details).
                self.record_connect_failure("tls", exc=scanner_exc, probed=True)
                # Actionable operator detail (the offending cert path); the
                # canonical line prints only the cause (mms runner details).
                self.logger.fail(f"  TLS: {scanner_exc}")
                return
            from oida.utils.protocol_helpers import probe_connect_failure_cause

            cause = (
                probe_connect_failure_cause(
                    getattr(self.args, "mms_enum", ""),
                    int(self.results["port"] or 102),
                    timeout=float(getattr(self.args, "timeout", 2) or 2),
                )
                or "unknown"
            )
            self.record_connect_failure(cause, probed=True)

    def enum_host_info(self):
        """Enumerate GOOSE information."""
        if not self.conn:
            return
        # Info enumeration happens during discover()
        self.results["data"]["interface"] = self.interface

    def print_host_info(self):
        """Display GOOSE capture information."""
        if getattr(self.args, "quiet", False):
            return

        timeout = getattr(self.args, "timeout", 10)
        self.logger.display(f"GOOSE: Interface {self.interface}, timeout {timeout}s")

    def _execute_scan(self):
        """Execute GOOSE scanning."""
        if not self.conn:
            return
        self.logger.display("Executing GOOSE scan...")
        scan_results = self.scanner.discover(self.conn)
        self.results["data"]["scan_results"] = scan_results

        # Positive result: GOOSE frames were actually captured on the wire.
        # GOOSE (IEC 61850) is plaintext-by-design with no native encryption
        # or authentication, so confirmed captured frames are the finding.
        if scan_results and scan_results.get("goose_messages"):
            self.logger.security_finding(
                "No encryption",
                detail="GOOSE (IEC 61850) has no encryption or authentication",
            )

    def cleanup(self):
        """Cleanup GOOSE connection."""
        if self.conn:
            conn = self.conn
            self.conn = None

            try:
                self.scanner.disconnect(conn)
                self.logger.debug("GOOSE connection closed")
            except Exception as e:
                self.logger.debug(f"Error closing GOOSE connection: {e}")

    @staticmethod
    def check_dependencies() -> bool:
        """Check if pyiec61850-ng is available."""
        from oida.utils.lazy_import import lazy_import

        _pyiec61850_goose = lazy_import(
            "pyiec61850.goose", "GOOSE", install_hint="pip install oida-ics[goose]"
        )
        return _pyiec61850_goose.is_available

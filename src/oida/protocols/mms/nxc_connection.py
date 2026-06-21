#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MMS NXC-style callable class."""

import time
from typing import Dict

from ...connection import NetworkConnection

from . import MMSScanner, _Lib, _pyiec61850


class mms(NetworkConnection):
    """NXC-style MMS scanner (callable)"""

    def __init__(self, args, db, host):
        self.protocol_name = "IEC 61850 MMS"
        self.default_port = 102
        super().__init__(args, db, host)

    def proto_flow(self):
        """Main MMS scanning workflow"""
        args_dict = self._convert_args_to_dict()
        self.scanner = MMSScanner(args_dict)
        self.create_conn_obj()
        if not self.conn:
            self.logger.fail(f"Failed to connect to {self.host}")
            self.results["success"] = False
            self.results["error"] = "Connection failed"
            return

        self.enum_host_info()
        self.print_host_info()
        self._execute_scan()

    def create_conn_obj(self):
        """Create MMS connection"""
        self.logger.info(f"Connecting to {self.ip}:{self.args.port}")
        self.conn = self.scanner.connect()
        if self.conn:
            self.logger.success(f"Connected to MMS device at {self.ip}:{self.args.port}")
        else:
            self.logger.fail(f"Connection failed to {self.ip}:{self.args.port}")

    def enum_host_info(self):
        """Enumerate MMS/IEC 61850 device information"""
        if not self.conn:
            return

        self.logger.debug("Enumerating device information...")
        try:
            server_info = self.scanner._get_server_info(self.conn)
            self.results["data"]["device_info"] = server_info
        except Exception as e:
            self.logger.warning(f"Device enumeration failed: {e}")
            self.results["data"]["device_info"] = {"connected": True, "enum_error": str(e)}

    def print_host_info(self):
        """Display MMS/IEC 61850 device information"""
        if getattr(self.args, "quiet", False):
            return

        info = self.results["data"].get("device_info", {})

        # create_conn_obj() already emitted "Connected to MMS device at host:port";
        # skip the redundant "MMS/IEC 61850: host:port" repeat and just print the
        # additional vendor/model/revision details.
        if info.get("vendor"):
            self.logger.display(f"    Vendor: {info['vendor']}")
        if info.get("model"):
            self.logger.display(f"    Model: {info['model']}")
        if info.get("revision"):
            self.logger.display(f"    Revision: {info['revision']}")
        if info.get("logical_device_count"):
            self.logger.display(f"    Logical Devices: {info['logical_device_count']}")

    def _execute_scan(self):
        """Execute MMS scanning"""
        if not self.conn:
            return
        self.logger.display("Executing scan...")
        server_info = self.results["data"].get("device_info")
        scan_results = self.scanner.discover(self.conn, server_info=server_info)
        self.results["data"]["scan_results"] = scan_results

        if getattr(self.args, "fuzz", None):
            self._handle_fuzz(scan_results)

    def _handle_fuzz(self, scan_results: Dict) -> None:
        """Handle fuzzing mode (--fuzz)"""
        if not getattr(self.args, "confirm", False):
            self.logger.fail("--fuzz requires --confirm flag (DANGEROUS operation)")
            return

        iterations = getattr(self.args, "fuzz_iterations", 10)

        self.logger.display(f"Starting fuzz mode: objects ({iterations} iterations)")

        fuzz_ref = getattr(self.args, "fuzz_reference", None)

        if fuzz_ref:
            self._fuzz_data_object(fuzz_ref, iterations)
        else:
            write_results = scan_results.get("write_test_results", {})
            writable = write_results.get("successful_writes", [])

            if not writable:
                self.logger.warning(
                    "No writable data objects found for fuzzing. Run with --test-write first."
                )
                return

            self.logger.display(f"Fuzzing {len(writable)} writable object(s)")

            max_targets = getattr(self.args, "fuzz_max_targets", 10)
            for obj_info in writable[:max_targets]:
                ref = obj_info.get("reference", "")
                if ref:
                    self._fuzz_data_object(ref, iterations)

    def _discover_writable_fc(self, reference: str):
        """Find the functional constraint the object is writable under.

        successful_writes (from MMSScanner._test_write_access) records only the
        reference, not the FC it was accepted under. _write_data_object probes
        [FC_CO, FC_SP, FC_MX] and returns on the first success, so an object may
        be writable only under FC_SP/FC_MX (the common case for setpoints and
        measurements). Hardcoding FC_CO here would silently target the wrong FC
        and make every fuzz write fail. Re-probe the same order using a
        same-value write (read current value, write it straight back) so the
        probe is non-destructive, and return the first FC that the server
        accepts. Returns None if none accept a write.
        """
        mms_value = None
        try:
            for fc in (
                _Lib.iec61850.IEC61850_FC_CO,
                _Lib.iec61850.IEC61850_FC_SP,
                _Lib.iec61850.IEC61850_FC_MX,
            ):
                read_result = _Lib.iec61850.IedConnection_readObject(self.conn, reference, fc)
                current, _, _ = _Lib.unpack_result(read_result)
                if current is None:
                    continue
                value = self.scanner._extract_mms_value(current)
                _Lib.safe_mms_value_delete(current)
                mms_value = self.scanner._create_mms_value(value)
                if mms_value is None:
                    continue
                write_result = _Lib.iec61850.IedConnection_writeObject(
                    self.conn, reference, fc, mms_value
                )
                _, _, ok = _Lib.unpack_result(write_result)
                _Lib.safe_mms_value_delete(mms_value)
                mms_value = None
                if ok:
                    self.logger.debug(f"  {reference} writable under FC {fc}")
                    return fc
            self.logger.debug(f"  No writable FC discovered for {reference}; defaulting to FC_MX")
            return None
        except Exception as e:
            self.logger.debug(f"Failed to discover writable FC for {reference}: {e}")
            return None
        finally:
            _Lib.safe_mms_value_delete(mms_value)

    def _fuzz_data_object(self, reference: str, iterations: int) -> None:
        """Fuzz a single MMS data object."""
        import struct
        from ...utils.fuzzer import fuzz

        _Lib.require()

        target_id = f"mms:{reference}"

        # The object may have been discovered writable under any of CO/SP/MX
        # (_write_data_object probes all three and accepts the first that
        # succeeds), but successful_writes does not record which one. Probe the
        # same order here and reuse the discovered FC for every read and write
        # below, so writes target the FC the object is actually writable under
        # (not a hardcoded FC_CO) and the read-back anomaly check compares like
        # for like. Falls back to FC_MX (measurement read) if none accepts a
        # write, which keeps the read path working for a dry/permission-denied
        # target.
        write_fc = self._discover_writable_fc(reference)
        read_fc = write_fc if write_fc is not None else _Lib.iec61850.IEC61850_FC_MX

        # Original typed Python value captured by read_value(); used for an
        # end-of-run restore that reconstructs the correct MmsValue type rather
        # than reinterpreting type-encoded bytes as a signed integer.
        original_typed = None
        original_typed_set = False

        def read_value():
            """Read value and convert to bytes for fuzzing."""
            nonlocal original_typed, original_typed_set
            mms_value = None
            try:
                result = _Lib.iec61850.IedConnection_readObject(
                    self.conn, reference, read_fc
                )
                mms_value, _, _ = _Lib.unpack_result(result)

                if mms_value is None:
                    return b"\x00\x00\x00\x00"

                value = self.scanner._extract_mms_value(mms_value)
                if not original_typed_set:
                    original_typed = value
                    original_typed_set = True
                if isinstance(value, bool):
                    return bytes([1 if value else 0])
                elif isinstance(value, int):
                    return value.to_bytes(4, "little", signed=True)
                elif isinstance(value, float):
                    try:
                        return struct.pack("<f", value)
                    except (struct.error, OverflowError) as e:
                        self.logger.debug(f"Failed to pack float for fuzz read: {e}")
                        return b"\x00\x00\x00\x00"
                else:
                    return str(value).encode()[:16]
            except Exception as e:
                self.logger.debug(f"Failed to read fuzz target value: {e}")
                return b"\x00\x00\x00\x00"
            finally:
                _Lib.safe_mms_value_delete(mms_value)

        def write_value(data):
            """Write fuzzed bytes as integer value."""
            mms_value = None
            try:
                value = int.from_bytes(data[:4].ljust(4, b"\x00"), "little", signed=True)
                mms_value = _Lib.iec61850.MmsValue_newInteger(value)
                result = _Lib.iec61850.IedConnection_writeObject(
                    self.conn, reference, read_fc, mms_value
                )
                _, _, ok = _Lib.unpack_result(result)
                return ok
            except Exception as e:
                self.logger.debug(f"Failed to write fuzz payload: {e}")
                return False
            finally:
                _Lib.safe_mms_value_delete(mms_value)

        def restore_value(value):
            """Restore the pre-fuzz value using its original MMS type.

            Reconstructs the MmsValue from the typed Python value via
            _create_mms_value so a float/bool/string is written back with the
            correct type instead of being reinterpreted as a signed integer.
            """
            mms_value = None
            try:
                mms_value = self.scanner._create_mms_value(value)
                if mms_value is None:
                    self.logger.debug(f"Could not build MmsValue to restore {value!r}")
                    return False
                result = _Lib.iec61850.IedConnection_writeObject(
                    self.conn, reference, read_fc, mms_value
                )
                _, _, ok = _Lib.unpack_result(result)
                return ok
            except Exception as e:
                self.logger.debug(f"Failed to restore original value: {e}")
                return False
            finally:
                _Lib.safe_mms_value_delete(mms_value)

        original = read_value()
        successful, failed, anomalies, crashes = 0, 0, 0, 0

        for payload, _desc in fuzz(
            original, count=iterations
        ):  # fuzz() yields (bytes, desc) tuples
            try:
                if write_value(payload):
                    successful += 1
                    readback = read_value()
                    if readback != payload and readback != original:
                        anomalies += 1
                        self.logger.warning(
                            f"  Anomaly: wrote {payload.hex()}, read {readback.hex()}"
                        )
                else:
                    failed += 1
            except Exception as e:
                crashes += 1
                self.logger.fail(f"  Crash: {e}")
            time.sleep(0.1)

        if original_typed_set and original_typed is not None:
            if restore_value(original_typed):
                self.logger.debug(f"  Restored original value: {original_typed!r}")
            else:
                self.logger.warning(
                    f"    Failed to restore original value {original_typed!r} on {target_id}"
                )

        status = "+" if crashes == 0 and anomalies == 0 else "!"
        self.logger.display(
            f"  [{status}] {target_id}: {successful + failed} tests, "
            f"{successful} writes, {anomalies} anomalies, {crashes} crashes"
        )

        if crashes > 0:
            self.logger.warning(f"    CRASHES DETECTED on {target_id}!")

    def cleanup(self):
        """Cleanup MMS connection."""
        if self.conn:
            conn = self.conn
            self.conn = None

            try:
                self.scanner.disconnect(conn)
                time.sleep(0.1)
                self.logger.debug("Connection closed")
            except Exception as e:
                self.logger.debug(f"Error closing connection: {e}")

    @staticmethod
    def check_dependencies() -> bool:
        """Check if pyiec61850-ng is available."""
        return _pyiec61850.is_available

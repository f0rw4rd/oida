#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MMS NXC-style callable class."""

import time
from typing import Dict

from oida.connection import NetworkConnection

from oida.protocols.mms import MMSScanner, _Lib, _pyiec61850, _write_under_fc


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
        if not self.require_confirm(
            "--fuzz", detail="--fuzz requires --confirm flag (DANGEROUS operation)"
        ):
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
        try:
            for fc in (_Lib.FC.CO, _Lib.FC.SP, _Lib.FC.MX):
                try:
                    value = self.scanner._normalize_read(self.conn.read_value(reference, fc=fc))
                except _Lib.ReadError:
                    continue
                if value is None:
                    continue
                if _write_under_fc(self.conn, reference, value, fc):
                    self.logger.debug(f"  {reference} writable under {fc.name}")
                    return fc
            self.logger.debug(f"  No writable FC discovered for {reference}; defaulting to FC_MX")
            return None
        except Exception as e:
            self.logger.debug(f"Failed to discover writable FC for {reference}: {e}")
            return None

    def _fuzz_data_object(self, reference: str, iterations: int) -> None:
        """Fuzz a single MMS data object."""
        import struct
        from oida.utils.fuzzer import fuzz

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
        read_fc = write_fc if write_fc is not None else _Lib.FC.MX

        # Original typed Python value captured by read_value(); used for an
        # end-of-run restore that reconstructs the correct MmsValue type rather
        # than reinterpreting type-encoded bytes as a signed integer.
        original_typed = None
        original_typed_set = False

        def read_value():
            """Read value and convert to bytes for fuzzing."""
            nonlocal original_typed, original_typed_set
            try:
                value = self.scanner._normalize_read(self.conn.read_value(reference, fc=read_fc))

                if value is None:
                    return b"\x00\x00\x00\x00"

                if not original_typed_set:
                    original_typed = value
                    original_typed_set = True
                if isinstance(value, bool):
                    return bytes([1 if value else 0])
                elif isinstance(value, int):
                    try:
                        return value.to_bytes(4, "little", signed=True)
                    except OverflowError:
                        # Value doesn't fit in a signed 32-bit window (e.g. a
                        # 64-bit counter). Widen instead of letting the
                        # generic except-Exception below silently collapse
                        # the fuzz baseline to zero.
                        return value.to_bytes(8, "little", signed=True)
                elif isinstance(value, float):
                    try:
                        return struct.pack("<f", value)
                    except (struct.error, OverflowError) as e:
                        self.logger.debug(f"Failed to pack float for fuzz read: {e}")
                        return b"\x00\x00\x00\x00"
                else:
                    return str(value).encode()[:16]
            except _Lib.ReadError:
                return b"\x00\x00\x00\x00"
            except Exception as e:
                self.logger.debug(f"Failed to read fuzz target value: {e}")
                return b"\x00\x00\x00\x00"

        def write_value(data):
            """Write fuzzed bytes as integer value (under the discovered FC).

            Returns the canonical 4-byte little-endian encoding of the value
            actually written (not `data`, which may be a different length --
            fuzz() yields payloads such as b"", b"\\x00", or original-length
            mutations that rarely land on exactly 4 bytes) so the caller can
            compare read-back against what was truly written instead of the
            raw mutated payload.
            """
            try:
                value = int.from_bytes(data[:4].ljust(4, b"\x00"), "little", signed=True)
                if _write_under_fc(self.conn, reference, value, read_fc):
                    return value.to_bytes(4, "little", signed=True)
                return None
            except Exception as e:
                self.logger.debug(f"Failed to write fuzz payload: {e}")
                return None

        def restore_value(value):
            """Restore the pre-fuzz value using its original Python type.

            write_value marshals the typed Python value itself, so a
            float/bool/string is written back with the correct type instead of
            being reinterpreted as a signed integer.
            """
            try:
                return _write_under_fc(self.conn, reference, value, read_fc)
            except Exception as e:
                self.logger.debug(f"Failed to restore original value: {e}")
                return False

        original = read_value()
        successful, failed, anomalies, crashes = 0, 0, 0, 0

        # write_value always encodes the payload as a signed int32, but
        # read_value returns type-specific widths (bool=1B, float=4B float,
        # int64=8B). A raw byte compare across those encodings falsely flags
        # every non-int32 iteration as an anomaly, so only compare for int-typed
        # objects, on the decoded integer value (width-agnostic).
        is_int_object = isinstance(original_typed, int) and not isinstance(original_typed, bool)

        def _canon_int(b: bytes) -> int:
            return int.from_bytes(b[:8].ljust(8, b"\x00"), "little", signed=False)

        for payload, _desc in fuzz(
            original, count=iterations
        ):  # fuzz() yields (bytes, desc) tuples
            try:
                written_bytes = write_value(payload)
                if written_bytes is not None:
                    successful += 1
                    readback = read_value()
                    if (
                        is_int_object
                        and _canon_int(readback) != _canon_int(written_bytes)
                        and _canon_int(readback) != _canon_int(original)
                    ):
                        anomalies += 1
                        self.logger.warning(
                            f"  Anomaly: wrote {written_bytes.hex()}, read {readback.hex()}"
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

"""
Modbus Fuzz Mixin

Handles fuzzing operations for security testing:
- Register fuzzing (raw and typed)
- Function code fuzzing
- Register map-based fuzzing
"""

from __future__ import annotations

import struct
from typing import Any, Dict, Generator, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class FuzzMixin(_ScannerBase):
    """Mixin providing Modbus fuzzing operations."""

    def _handle_fuzz(self):
        """Handle --fuzz flag for security testing."""
        if not self.require_confirm(
            "--confirm", detail="Fuzzing requires --confirm flag (writes to device)"
        ):
            return
        fuzz_mode = getattr(self.args, "fuzz_mode", "basic")
        iterations = getattr(self.args, "fuzz_iterations", 100)
        register_map = getattr(self.args, "register_map", None)

        self.logger.display(
            f"Starting Modbus fuzzing (mode: {fuzz_mode}, iterations: {iterations})"
        )

        if register_map:
            # Map-based fuzzing
            results = self._fuzz_registers_from_map(register_map, iterations)
        elif fuzz_mode in ("basic", "data", "boundary"):
            # Register fuzzing
            results = self._fuzz_registers(iterations, fuzz_mode)
        elif fuzz_mode == "function":
            # Function code fuzzing only
            results = self._fuzz_function_codes()
        elif fuzz_mode == "full":
            # Combined fuzzing
            reg_results = self._fuzz_registers(iterations // 2, "boundary")
            fc_results = self._fuzz_function_codes()
            results = {**reg_results, **fc_results}
        else:
            self.logger.fail(f"Unknown fuzz mode: {fuzz_mode}")
            return

        results = results or {}
        if results:
            self.results["data"]["fuzz"] = results

        self.logger.display("=== Fuzzing Summary ===")
        self.logger.display(
            f"Tests: {results.get('tests', 0)}, Writes: {results.get('writes', 0)}, "
            f"Errors: {results.get('errors', 0)}, Crashes: {results.get('crashes', 0)}"
        )

    def _fuzz_registers(self, iterations: int, mode: str) -> Dict:
        """Fuzz registers with various payloads."""
        # Default to "0-10" when -r/--scan-range isn't given: argparse always
        # sets the attribute (None when absent), so getattr's default never
        # applies — same pattern as writes.py's test-write handler.
        scan_range = getattr(self.args, "scan_range", None) or "0-10"
        decode_type = getattr(self.args, "decode", None)

        addresses = self._parse_fuzz_range(scan_range)
        if not addresses:
            self.logger.fail("No addresses to fuzz. Use -r/--scan-range")
            return {}

        stats = {
            "tests": 0,
            "writes": 0,
            "errors": 0,
            "crashes": 0,
            "details": [],
            "restore_warnings": [],
        }

        max_addresses = getattr(self.args, "fuzz_max_addresses", 10)
        fuzz_addrs = addresses[:max_addresses]
        self.logger.display(f"Fuzzing {len(fuzz_addrs)} of {len(addresses)} register(s)...")

        # Batch-read original values for restoration after fuzzing.
        from ..register_io import read_registers_batched

        originals = read_registers_batched(
            self.conn,
            "holding_registers",
            fuzz_addrs,
            unit_id=self.scanner.unit_id,
            fallback_individual=True,
        )

        for addr in fuzz_addrs:
            self.logger.display(f"  Fuzzing register {addr}...")
            original_value = originals.get(addr)

            # Generate payloads
            payloads = list(self._generate_fuzz_payloads(decode_type, mode, iterations))

            # 32-bit typed payloads (f32/i32/u32) are written as two
            # consecutive registers via write_registers(addr, [hi, lo]).
            # Capture addr+1's original value too so restoration below can
            # rewrite the full window instead of leaving addr+1 stuck at
            # its last fuzzed value.
            register_width = 2 if any(isinstance(p, list) for p in payloads) else 1
            original_value_hi = originals.get(addr + 1) if register_width == 2 else None
            if register_width == 2 and original_value_hi is None:
                try:
                    rr = self.conn.read_holding_registers(
                        addr + 1, count=1, device_id=self.scanner.unit_id
                    )
                    if not rr.isError():
                        original_value_hi = rr.registers[0]
                except Exception as e:
                    self.logger.debug(f"Failed to read original value at {addr + 1}: {e}")

            for i, payload in enumerate(payloads):
                stats["tests"] += 1
                try:
                    if isinstance(payload, list):
                        result = self.conn.write_registers(
                            addr, payload, device_id=self.scanner.unit_id
                        )
                    else:
                        result = self.conn.write_register(
                            addr, payload, device_id=self.scanner.unit_id
                        )

                    if not result.isError():
                        stats["writes"] += 1
                    else:
                        stats["errors"] += 1

                except Exception as e:
                    stats["errors"] += 1
                    err_str = str(e).lower()
                    if "timeout" in err_str or "connection" in err_str:
                        stats["crashes"] += 1
                        stats["details"].append(
                            {"address": addr, "payload": str(payload), "error": str(e)[:100]}
                        )

                # Progress indicator
                if (i + 1) % 20 == 0:
                    self.logger.display(f"    Progress: {i + 1}/{len(payloads)}")

            # Restore original value(s) -- rewrite the full register window
            # for 2-register typed payloads so addr+1 doesn't stay fuzzed.
            if original_value is not None:
                if register_width == 2 and original_value_hi is None:
                    # We never learned addr+1's pre-fuzz value (the read at
                    # the top of this loop failed), so only addr can be
                    # restored below -- addr+1 is left holding whatever the
                    # last fuzz payload wrote. This must not be silent.
                    msg = (
                        f"Could not restore register {addr + 1}: original value "
                        f"was never read; device left holding fuzzed data"
                    )
                    self.logger.warning(msg)
                    stats["restore_warnings"].append({"address": addr + 1, "reason": msg})
                try:
                    if register_width == 2 and original_value_hi is not None:
                        self.conn.write_registers(
                            addr,
                            [original_value, original_value_hi],
                            device_id=self.scanner.unit_id,
                        )
                    else:
                        self.conn.write_register(
                            addr, original_value, device_id=self.scanner.unit_id
                        )
                except Exception as e:
                    msg = f"Failed to restore register {addr}: {e}"
                    self.logger.warning(msg)
                    stats["restore_warnings"].append({"address": addr, "reason": msg})

        return stats

    def _fuzz_function_codes(self) -> Dict:
        """Fuzz vendor-specific function codes (65-127)."""
        stats = {"tests": 0, "responses": 0, "errors": 0, "crashes": 0, "supported": []}

        self.logger.display("Fuzzing function codes 65-127...")

        for fc in range(65, 128):
            stats["tests"] += 1

            # Generate test payload
            payload = bytes([self.scanner.unit_id, fc, 0x00, 0x00, 0x00, 0x01])

            try:
                response = self.scanner.send_custom_fc(self.conn, fc, payload, self.scanner.unit_id)

                # success=True means a response (normal or exception) was received;
                # a failed/timed-out send is success=False. The previous
                # `if response:` was always truthy, so the errors branch was
                # unreachable and errored sends were counted as "supported".
                if response and response.get("success"):
                    if not response.get("is_exception"):
                        stats["responses"] += 1
                        stats["supported"].append(
                            {"fc": fc, "response": response.get("response_payload", b"")[:20]}
                        )
                        self.logger.display(f"  FC {fc}: Supported!")
                    else:
                        # Exception is expected for unsupported FCs
                        pass
                else:
                    stats["errors"] += 1

            except Exception as e:
                stats["errors"] += 1
                err_str = str(e).lower()
                if "timeout" in err_str or "connection" in err_str:
                    stats["crashes"] += 1

        if stats["supported"]:
            self.logger.success(f"Found {len(stats['supported'])} supported vendor FC(s)")

        return stats

    def _fuzz_registers_from_map(self, map_name: str, iterations: int) -> Dict:
        """Fuzz registers based on a vendor register map."""
        from ..decoder import load_register_map

        reg_map = load_register_map(map_name)
        if not reg_map:
            self.logger.fail(f"Register map '{map_name}' not found")
            return {}

        # Filter to writable registers only (unless --fuzz-all-access)
        fuzz_all = getattr(self.args, "fuzz_all_access", False)
        writable = []

        # Register maps store "registers" as a dict keyed by name (see
        # register_maps/generic.json), not a list -- iterate .items() and
        # fold the name key into each entry so downstream code (which reads
        # entry["name"]) keeps working.
        for name, entry in reg_map.get("registers", {}).items():
            access = entry.get("access", "r").lower()
            if fuzz_all or "w" in access:
                writable.append({**entry, "name": entry.get("name", name)})

        if not writable:
            self.logger.warning("No writable registers found in map")
            return {}

        max_addresses = getattr(self.args, "fuzz_max_addresses", 10)
        self.logger.display(
            f"Fuzzing {min(len(writable), max_addresses)} of {len(writable)} registers from map '{map_name}'..."
        )

        stats = {"tests": 0, "writes": 0, "errors": 0, "crashes": 0}

        for entry in writable[:max_addresses]:
            addr = entry.get("address", entry.get("addr"))
            dtype = entry.get("type", "u16")
            name = entry.get("name", f"reg_{addr}")

            self.logger.display(f"  Fuzzing {name} @ {addr} ({dtype})...")

            payloads = list(self._generate_typed_fuzz_payloads(dtype, iterations // len(writable)))

            for payload in payloads:
                stats["tests"] += 1
                try:
                    if isinstance(payload, list):
                        result = self.conn.write_registers(
                            addr, payload, device_id=self.scanner.unit_id
                        )
                    else:
                        result = self.conn.write_register(
                            addr, int(payload) & 0xFFFF, device_id=self.scanner.unit_id
                        )

                    if not result.isError():
                        stats["writes"] += 1
                except Exception:
                    stats["errors"] += 1

        return stats

    def _parse_fuzz_range(self, range_str: str) -> List[int]:
        """Parse register range for fuzzing (central range parser)."""
        from ....utils import ProtocolParser

        return ProtocolParser.parse_address_range(range_str)

    def _generate_fuzz_payloads(
        self, decode_type: Optional[str], mode: str, count: int
    ) -> Generator[Any, None, None]:
        """Generate fuzz payloads based on mode and type."""
        if decode_type:
            yield from self._generate_typed_fuzz_payloads(decode_type, count)
        else:
            yield from self._generate_raw_fuzz_payloads(mode, count)

    def _generate_raw_fuzz_payloads(self, mode: str, count: int) -> Generator[int, None, None]:
        """Generate raw register fuzz values."""
        import random

        # Boundary values
        boundaries = [0, 1, 0x7F, 0x80, 0xFF, 0x7FFF, 0x8000, 0xFFFF]
        yield from boundaries

        remaining = count - len(boundaries)
        for _ in range(max(0, remaining)):
            yield random.randint(0, 0xFFFF)

    @staticmethod
    def _pack_as_registers(fmt: str, val) -> List[int]:
        """Pack a value with *fmt* and split into two 16-bit Modbus registers."""
        packed = struct.pack(fmt, val)
        return [struct.unpack(">H", packed[0:2])[0], struct.unpack(">H", packed[2:4])[0]]

    def _generate_typed_fuzz_payloads(self, dtype: str, count: int) -> Generator[Any, None, None]:
        """Generate type-aware fuzz payloads."""
        import random

        dtype = dtype.lower()

        if dtype in ("f32", "float", "float32"):
            # Float edge cases
            special = [0.0, -0.0, 1.0, -1.0, float("inf"), float("-inf"), float("nan")]
            special.extend([1e-38, 1e38, -1e-38, -1e38])
            for val in special:
                yield self._pack_as_registers(">f", val)

            for _ in range(count - len(special)):
                val = random.uniform(-1e38, 1e38)
                yield self._pack_as_registers(">f", val)

        elif dtype in ("i32", "int32", "s32"):
            # Signed 32-bit boundaries
            boundaries = [0, 1, -1, 0x7FFFFFFF, -0x80000000, 0x7F, 0x80, 0xFF]
            for val in boundaries:
                yield self._pack_as_registers(">i", val)

            for _ in range(count - len(boundaries)):
                val = random.randint(-0x80000000, 0x7FFFFFFF)
                yield self._pack_as_registers(">i", val)

        elif dtype in ("u32", "uint32"):
            # Unsigned 32-bit boundaries
            boundaries = [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]
            for val in boundaries:
                yield self._pack_as_registers(">I", val)

            for _ in range(count - len(boundaries)):
                val = random.randint(0, 0xFFFFFFFF)
                yield self._pack_as_registers(">I", val)

        else:
            # Default to u16
            yield from self._generate_raw_fuzz_payloads("boundary", count)

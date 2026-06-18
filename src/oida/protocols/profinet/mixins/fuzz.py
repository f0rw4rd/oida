"""
PROFINET Fuzz Mixin

Handles fuzzing operations for security testing:
- Writable index discovery
- Type-aware fuzz payload generation
- Write + readback verification
- Crash/anomaly detection
"""

from __future__ import annotations

from typing import List, Optional, Tuple, TYPE_CHECKING

from ..models import ProfinetDevice

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class FuzzMixin(_ScannerBase):
    """Mixin providing PROFINET fuzzing operations."""

    def _handle_fuzz(
        self,
        device: ProfinetDevice,
        con,
        discovered_slots: Optional[list] = None,
    ) -> None:
        """Handle fuzzing mode (--fuzz)."""
        mode = self._arg("fuzz", "basic")
        if not mode:
            return

        if not self._arg("confirm", False):
            self.logger.fail("--fuzz requires --confirm flag (DANGEROUS operation)")
            return

        iterations = self._arg("fuzz_iterations", 10)
        fuzz_indices_arg = self._arg("fuzz_indices", None)

        self.logger.display(f"Starting PROFINET fuzz mode: {mode} ({iterations} iterations)")

        if fuzz_indices_arg:
            indices_to_fuzz = self._parse_fuzz_indices(fuzz_indices_arg)
            if not indices_to_fuzz:
                return
        else:
            indices_to_fuzz = self._discover_writable_indices(con, discovered_slots)
            if not indices_to_fuzz:
                self.logger.warning("No writable indices found. Use --fuzz-indices to specify.")
                return

        self.logger.display(f"Fuzzing {len(indices_to_fuzz)} index(es)")

        self._fuzz_writable_indices(con, indices_to_fuzz, iterations, mode)

    def _discover_writable_indices(
        self,
        con,
        discovered_slots: Optional[list] = None,
    ) -> List[Tuple[int, int, int]]:
        """Discover writable indices by testing I&M indices."""
        im_indices = [
            0xAFF1,  # I&M1 - Tag function/location
            0xAFF2,  # I&M2 - Installation date
            0xAFF3,  # I&M3 - Descriptor
        ]

        writable: list = []

        if not discovered_slots:
            discovered_slots = [(0, 1, 0, 0)]

        for slot, subslot, _, _ in discovered_slots:
            for idx in im_indices:
                try:
                    result = con.read(api=0, slot=slot, subslot=subslot, idx=idx)
                    if result and len(result.payload) > 0:
                        data = result.payload
                        access = self._test_write_access(con, slot, subslot, idx, data)
                        if access == "RW":
                            writable.append((slot, subslot, idx))
                            self.logger.display(f"  Found RW: [{slot}/{subslot}] 0x{idx:04X}")
                except (OSError, ConnectionError) as e:
                    self.logger.warning(f"  Connection lost during writable index discovery: {e}")
                    return writable
                except Exception as e:
                    self.logger.debug(f"Failed to get result: {e}")

        return writable

    def _fuzz_writable_indices(
        self,
        con,
        indices: List[Tuple[int, int, int]],
        iterations: int,
        mode: str,
    ) -> None:
        """Fuzz writable indices with type-aware payloads."""
        import time

        from ....utils.fuzzer import _get_type_boundaries, fuzz
        from ..helpers import get_indices_module

        idx_module = get_indices_module()

        for slot, subslot, idx in indices:
            name = idx_module.get_index_name(idx)
            target_id = f"[{slot}/{subslot}] 0x{idx:04X} {name}"

            try:
                result = con.read(api=0, slot=slot, subslot=subslot, idx=idx)
                if not result or len(result.payload) == 0:
                    self.logger.warning(f"  {target_id}: Cannot read, skipping")
                    continue
                original = result.payload
            except Exception as e:
                self.logger.warning(f"  {target_id}: Read error: {e}")
                continue

            self.logger.display(
                f"  Fuzzing {target_id} ({len(original)} bytes, {iterations} iterations)"
            )

            successful, failed, anomalies, crashes = 0, 0, 0, 0

            data_type = self._get_index_data_type(idx)
            # PROFINET I&M string fields are fixed-width ASCII padded with
            # spaces, not length-prefixed. The "string" type generates LE
            # length-prefix boundaries which are inappropriate. Use "bytes"
            # (raw byte mutations) for these fields instead.
            if data_type == "string":
                data_type = "bytes"
            max_len = len(original) + 8 if mode == "full" else len(original)

            # "boundary" mode: only boundary/edge-case values, no random
            # mutations. Use _get_type_boundaries directly instead of fuzz().
            if mode == "boundary":
                payloads = _get_type_boundaries(data_type, original)
            else:
                payloads = fuzz(
                    original,
                    count=iterations,
                    max_len=max_len,
                    data_type=data_type,
                )
            for payload, desc in payloads:
                try:
                    con.write(
                        api=0,
                        slot=slot,
                        subslot=subslot,
                        idx=idx,
                        data=payload,
                    )
                    successful += 1

                    try:
                        readback = con.read(
                            api=0,
                            slot=slot,
                            subslot=subslot,
                            idx=idx,
                        )
                        if readback and readback.payload:
                            if readback.payload != payload and readback.payload != original:
                                anomalies += 1
                                self.logger.debug(
                                    f"    Anomaly: wrote"
                                    f" {payload.hex()}, got"
                                    f" {readback.payload.hex()}"
                                )
                    except Exception:
                        crashes += 1
                        self.logger.warning(f"    [!] Crash/hang detected after writing: {desc}")

                except (OSError, ConnectionError) as e:
                    failed += 1
                    self.logger.error(f"    Connection lost during fuzz write ({desc}): {e}")
                    # Attempt single reconnect
                    try:
                        con.connect(src_mac=con._src_mac)
                        self.logger.display("    Reconnected after connection loss")
                    except Exception:
                        self.logger.error("    Reconnect failed. Aborting fuzz run.")
                        return
                except Exception as e:
                    failed += 1
                    self.logger.debug(f"    Write failed ({desc}): {e}")

                time.sleep(self._arg("fuzz_delay", 0.05))

            # Restore original value with retry logic
            restore_ok = False
            for attempt in range(3):
                try:
                    con.write(
                        api=0,
                        slot=slot,
                        subslot=subslot,
                        idx=idx,
                        data=original,
                    )
                    self.logger.debug("    Restored original value")
                    restore_ok = True
                    break
                except Exception as e:
                    self.logger.warning(f"    Restore attempt {attempt + 1}/3 failed: {e}")
                    if attempt < 2:
                        time.sleep(0.5)

            if not restore_ok:
                self.logger.error(
                    f"    [!!!] RESTORE FAILED for {target_id}"
                    f" - index may contain corrupted data!"
                    f" Original value: {original.hex()}"
                )
                self.logger.error(
                    "    Aborting fuzz run to prevent further damage on broken connection"
                )
                break

            status = "+" if crashes == 0 and anomalies == 0 else "!"
            self.logger.display(
                f"    [{status}] {successful + failed} tests: "
                f"{successful} writes OK, {failed} rejected, "
                f"{anomalies} anomalies, {crashes} crashes"
            )

            if crashes > 0:
                self.logger.warning("    [!] CRASHES DETECTED - device may be unstable!")

    def _parse_fuzz_indices(self, indices_arg: str) -> List[Tuple[int, int, int]]:
        """Parse user-specified indices for fuzzing.

        Formats:
            - Single: 0xAFF1
            - Multiple: 0xAFF1,0xAFF2,0xAFF3
            - Range: 0xAFF1-0xAFF3
        """
        indices: list = []
        try:
            if "-" in indices_arg and "," not in indices_arg:
                parts = indices_arg.split("-")
                start = int(parts[0], 0)
                end = int(parts[1], 0)
                for idx in range(start, end + 1):
                    indices.append((0, 1, idx))
            elif "," in indices_arg:
                for part in indices_arg.split(","):
                    idx = int(part.strip(), 0)
                    indices.append((0, 1, idx))
            else:
                idx = int(indices_arg, 0)
                indices.append((0, 1, idx))
        except ValueError as e:
            self.logger.fail(f"Invalid --fuzz-indices format: {e}")
            return []

        return indices

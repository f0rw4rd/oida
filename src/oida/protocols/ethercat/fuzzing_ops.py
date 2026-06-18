"""Fuzzing operations mixin for EtherCATScanner."""

from __future__ import annotations

import struct
import time
from typing import Any, Dict, TYPE_CHECKING

from ...utils.fuzzer import fuzz

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class FuzzingOpsMixin(_ScannerBase):
    """Mixin providing SDO and PDO fuzzing operations."""

    def _perform_fuzzing(self, master: Any) -> Dict[str, Any]:
        """Perform fuzzing operations"""
        self.logger.warning("Starting EtherCAT fuzzing - this may cause device malfunction!")
        fuzzing_results = {
            "sdo_fuzzing": {},
            "pdo_fuzzing": {},
            "crashes_detected": 0,
            "anomalies": [],
        }

        if self.fuzz_sdo:
            fuzzing_results["sdo_fuzzing"] = self._fuzz_sdo(master)

        if self.fuzz_pdo:
            fuzzing_results["pdo_fuzzing"] = self._fuzz_pdo(master)

        return fuzzing_results

    def _fuzz_sdo(self, master: Any) -> Dict[str, Any]:
        """Fuzz SDO communications using central fuzz() function"""
        self.logger.display("Fuzzing SDO communications...")
        results = {"tests_performed": 0, "responses": [], "errors": []}

        # Common writable objects to fuzz
        writable_objects = [
            (0x1600, 0),  # RxPDO mapping count
            (0x1A00, 0),  # TxPDO mapping count
            (0x6040, 0),  # Control word (if DS402)
            (0x7000, 1),  # Output object
        ]

        targets = self._slave_filter()

        for slave_idx, slave in enumerate(master.slaves):
            position = slave_idx + 1
            if position not in targets:
                continue
            self.logger.display(f"  Fuzzing slave {position}...")

            for index, subindex in writable_objects:
                # First try to read the object to get valid base data
                try:
                    base_data = slave.sdo_read(index, subindex)
                    if not base_data:
                        base_data = struct.pack("<I", 0x00000000)
                except Exception:
                    base_data = struct.pack("<I", 0x00000000)

                fuzz_count = 0
                for fuzzed_data, fuzz_desc in fuzz(
                    base_data, count=self.fuzz_iterations, max_len=8
                ):
                    try:
                        slave.sdo_write(index, subindex, fuzzed_data)
                        results["tests_performed"] += 1
                        fuzz_count += 1
                        results["responses"].append(
                            {
                                "slave": position,
                                "index": f"0x{index:04X}",
                                "subindex": subindex,
                                "mutation": fuzz_desc,
                                "data": fuzzed_data.hex(),
                                "result": "accepted",
                            }
                        )
                    except Exception as e:
                        err_str = str(e)
                        results["tests_performed"] += 1
                        fuzz_count += 1
                        # SDO abort codes are expected - only log unexpected errors
                        if "abort" not in err_str.lower():
                            results["errors"].append(
                                {
                                    "slave": position,
                                    "index": f"0x{index:04X}",
                                    "subindex": subindex,
                                    "mutation": fuzz_desc,
                                    "error": err_str,
                                }
                            )
                    time.sleep(0.01)

                if fuzz_count > 0:
                    self.logger.display(
                        f"    0x{index:04X}:{subindex} - {fuzz_count} mutations tested"
                    )

        self.logger.display(f"  SDO fuzzing complete: {results['tests_performed']} tests")
        if results["responses"]:
            self.logger.warning(
                f"  {len(results['responses'])} writes accepted (potential vulnerability)"
            )
        if results["errors"]:
            self.logger.display(f"  {len(results['errors'])} unexpected errors")

        return results

    def _fuzz_pdo(self, master: Any) -> Dict[str, Any]:
        """Fuzz PDO (Process Data Object) communications using central fuzz() function"""
        self.logger.display("Fuzzing PDO communications...")
        results = {"tests_performed": 0, "anomalies": [], "errors": []}

        if not master.slaves:
            return results

        targets = self._slave_filter()

        # Get output sizes for targeted slaves
        slave_outputs = []
        for i, slave in enumerate(master.slaves):
            if (i + 1) in targets and slave.output:
                slave_outputs.append((slave, len(slave.output)))

        if not slave_outputs:
            self.logger.display("  No PDO outputs available for fuzzing")
            return results

        self.logger.display(f"  Fuzzing {len(slave_outputs)} slave(s) with PDO outputs")

        for slave, output_size in slave_outputs:
            base_data = bytes(output_size)  # Start with zeros
            fuzz_count = 0

            for fuzzed_data, fuzz_desc in fuzz(
                base_data, count=self.fuzz_iterations, max_len=output_size
            ):
                try:
                    # Pad or truncate to match output size
                    if len(fuzzed_data) < output_size:
                        fuzzed_data = fuzzed_data + bytes(output_size - len(fuzzed_data))
                    elif len(fuzzed_data) > output_size:
                        fuzzed_data = fuzzed_data[:output_size]

                    # Write fuzzed data to slave output
                    slave.output = fuzzed_data

                    # Send and receive process data
                    master.send_processdata()
                    wkc = master.receive_processdata(2000)
                    results["tests_performed"] += 1
                    fuzz_count += 1

                    if wkc != master.expected_wkc:
                        results["anomalies"].append(
                            {
                                "slave": slave.name,
                                "expected_wkc": master.expected_wkc,
                                "actual_wkc": wkc,
                                "mutation": fuzz_desc,
                                "data": fuzzed_data[:16].hex()
                                + ("..." if len(fuzzed_data) > 16 else ""),
                            }
                        )

                    time.sleep(0.005)

                except Exception as e:
                    results["errors"].append(
                        {
                            "slave": slave.name,
                            "mutation": fuzz_desc,
                            "error": str(e),
                        }
                    )

            self.logger.display(f"    {slave.name}: {fuzz_count} PDO mutations tested")

        # Reset outputs to zeros
        for slave, _ in slave_outputs:
            if slave.output:
                slave.output = bytes(len(slave.output))

        self.logger.display(f"  PDO fuzzing complete: {results['tests_performed']} tests")
        if results["anomalies"]:
            self.logger.warning(f"  {len(results['anomalies'])} WKC anomalies detected")
        if results["errors"]:
            self.logger.display(f"  {len(results['errors'])} errors")

        return results

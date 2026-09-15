"""
DICOM Fuzzing Mixin

Handles C-FIND fuzzing operations for security testing.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from ..cli_runner import _new_dataset, _sop

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class FuzzMixin(_ScannerBase):
    """Mixin providing fuzzing operations for the DICOM scanner."""

    def _handle_fuzz(self):
        """Handle C-FIND query fuzzing"""
        if not self.require_confirm(
            "--fuzz", detail="--fuzz requires --confirm flag (potentially dangerous)"
        ):
            return
        if not self.assoc or not self.assoc.is_established:
            self.logger.fail("Cannot fuzz without established association")
            return

        iterations = getattr(self.args, "fuzz_iterations", 10)
        self.logger.display(f"Starting C-FIND fuzzing with {iterations} iterations per field...")

        self._fuzz_cfind_queries(iterations)

    def _fuzz_cfind_queries(self, iterations: int):
        """Fuzz C-FIND query parameters"""
        from ....utils.fuzzer import fuzz

        fuzz_results = {
            "tested": 0,
            "errors": [],
            "crashes": [],
        }

        # Fields to fuzz at each query level
        fuzz_targets = [
            ("PATIENT", "PatientName"),
            ("PATIENT", "PatientID"),
            ("STUDY", "PatientName"),
            ("STUDY", "StudyDate"),
            ("STUDY", "AccessionNumber"),
        ]

        for query_level, field_name in fuzz_targets:
            self.logger.display(f"Fuzzing {query_level}.{field_name}...")

            # Generate fuzz payloads - use string-like data
            base_value = b"TESTPATIENT"
            # fuzz() yields (payload_bytes, description) tuples.
            for i, (payload, _desc) in enumerate(fuzz(base_value, count=iterations, max_len=64)):
                try:
                    # Decode payload to string (DICOM uses strings for these
                    # fields); errors="replace" guarantees no exception.
                    fuzz_value = payload.decode("utf-8", errors="replace")

                    # Create query dataset
                    ds = _new_dataset()
                    ds.QueryRetrieveLevel = query_level

                    # Set the fuzzed field
                    setattr(ds, field_name, fuzz_value)

                    # Add return keys
                    if query_level == "PATIENT":
                        ds.PatientID = ""
                        ds.PatientBirthDate = ""
                    elif query_level == "STUDY":
                        ds.StudyInstanceUID = ""
                        ds.StudyDate = ""

                    # Send fuzzed query
                    responses = self.assoc.send_c_find(
                        ds,
                        _sop("PatientRootQueryRetrieveInformationModelFind"),
                    )

                    # Consume responses
                    response_count = 0
                    for status, identifier in responses:
                        response_count += 1
                        if response_count > 5:
                            break  # Don't consume too many responses

                    fuzz_results["tested"] += 1
                    self.logger.debug(
                        f"  [{i + 1}/{iterations}] {field_name}={fuzz_value[:20]}... -> OK"
                    )

                except Exception as e:
                    error_str = str(e)
                    fuzz_results["errors"].append(
                        {
                            "field": field_name,
                            "payload": payload.hex()[:32],
                            "error": error_str,
                        }
                    )
                    self.logger.warning(f"  [{i + 1}/{iterations}] Error: {error_str[:50]}")

                    # Check for crash indicators
                    if "connection" in error_str.lower() or "reset" in error_str.lower():
                        fuzz_results["crashes"].append(
                            {
                                "field": field_name,
                                "payload": payload.hex(),
                                "error": error_str,
                            }
                        )
                        self.logger.fail("  Possible crash detected!")

                # Small delay between tests
                time.sleep(0.05)

        # Summary
        self.logger.display("Fuzzing complete:")
        self.logger.display(f"  Tests run: {fuzz_results['tested']}")
        self.logger.display(f"  Errors: {len(fuzz_results['errors'])}")
        if fuzz_results["crashes"]:
            self.logger.fail(f"  Potential crashes: {len(fuzz_results['crashes'])}")

        self.results["data"]["fuzz_results"] = fuzz_results

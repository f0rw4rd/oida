"""Reporting and security analysis mixin for EtherCATScanner."""

from __future__ import annotations

from typing import Any, Dict, TYPE_CHECKING
from datetime import datetime

from ...utils import SecurityAnalyzer
from ...utils.export_utils import print_table, export_json

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class ReportingMixin(_ScannerBase):
    """Mixin providing security analysis, data export, and scan reporting."""

    def _analyze_security(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze EtherCAT security"""
        analysis = {
            "authentication": False,
            "encryption": False,
            "access_control": False,
            "bus_monitoring": True,
            "issues": [],
        }

        # EtherCAT has no built-in security
        analysis["issues"].extend(
            [
                "No authentication mechanism",
                "No encryption support",
                "No access control",
                "Bus traffic can be monitored",
                "Devices can be controlled without authorization",
            ]
        )

        # Check for writable SDO objects
        sdo_data = results.get("sdo_data", {})
        writable_objects = 0
        for slave_data in sdo_data.values():
            if isinstance(slave_data, dict):
                for obj_data in slave_data.values():
                    if isinstance(obj_data, dict) and obj_data.get("readable"):
                        writable_objects += 1

        if writable_objects > 0:
            analysis["issues"].append(f"{writable_objects} readable SDO objects found")

        # Overall security assessment (EtherCAT is inherently insecure).
        # assess_protocol_security() returns its own "issues" key; updating
        # blindly used to clobber all the EtherCAT-specific findings above, so
        # merge the generic issues onto our list instead of replacing it.
        assessment = SecurityAnalyzer.assess_protocol_security(
            {
                "authentication": False,
                "authorization": False,
                "encryption": False,
                "integrity_check": False,
                "access_control": False,
            }
        )
        generic_issues = assessment.pop("issues", [])
        analysis.update(assessment)
        analysis["issues"].extend(generic_issues)

        return analysis

    def _export_dump_data(self, results: Dict[str, Any]):
        """Export detailed scan data to files using central export_json()"""
        if not self.dump_path:
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Export EEPROM data using central export function
        if results.get("eeprom_data"):
            export_json(
                results["eeprom_data"],
                self.dump_path,
                f"ethercat_eeprom_{timestamp}",
                logger=self.logger,
            )

        # Export raw EEPROM dump if available
        if results.get("eeprom_raw"):
            export_json(
                results["eeprom_raw"],
                self.dump_path,
                f"ethercat_eeprom_raw_{timestamp}",
                logger=self.logger,
            )

        # Export SDO data using central export function
        if results.get("sdo_data"):
            export_json(
                results["sdo_data"],
                self.dump_path,
                f"ethercat_sdo_{timestamp}",
                logger=self.logger,
            )

        # Export DC analysis if available
        if results.get("dc_analysis"):
            export_json(
                results["dc_analysis"],
                self.dump_path,
                f"ethercat_dc_analysis_{timestamp}",
                logger=self.logger,
            )

        # Export fuzzing results if performed
        fuzzing = results.get("fuzzing_results", {})
        if fuzzing.get("sdo_fuzzing") or fuzzing.get("pdo_fuzzing"):
            export_json(
                fuzzing,
                self.dump_path,
                f"ethercat_fuzzing_{timestamp}",
                logger=self.logger,
            )

        # Export FoE results if available
        if results.get("foe_results"):
            export_json(
                results["foe_results"],
                self.dump_path,
                f"ethercat_foe_{timestamp}",
                logger=self.logger,
            )

        # Export CoE dictionary if scanned
        if results.get("coe_dictionary"):
            export_json(
                results["coe_dictionary"],
                self.dump_path,
                f"ethercat_coe_{timestamp}",
                logger=self.logger,
            )

        # Export FSoE data if scanned
        if results.get("fsoe_data"):
            export_json(
                results["fsoe_data"],
                self.dump_path,
                f"ethercat_fsoe_{timestamp}",
                logger=self.logger,
            )

        # Export parsed EEPROM/ESI if available
        if results.get("eeprom_parsed"):
            export_json(
                results["eeprom_parsed"],
                self.dump_path,
                f"ethercat_esi_{timestamp}",
                logger=self.logger,
            )

    def _report_findings(self, results: Dict[str, Any]):
        """Report scan findings using central print_table()"""
        network_info = results.get("network_info", {})
        slaves = results.get("slaves", {})
        fuzzing = results.get("fuzzing_results", {})

        # Report network as host
        self.report_host_info(
            self.interface,
            network_type="EtherCAT",
            slave_count=network_info.get("slave_count", 0),
            cycle_time=network_info.get("cycle_time", 0),
        )

        # Display detailed table with -i (SDO-enriched data)
        if slaves and getattr(self, "device_info", False):
            table_data = []
            for slave_pos, slave_info in slaves.items():
                table_data.append(
                    [
                        str(slave_pos),
                        slave_info.get("name", "Unknown"),
                        slave_info.get("manufacturer", "Unknown"),
                        f"0x{slave_info.get('product_code', 0):08X}",
                        slave_info.get("fw_version", "") or f"Rev {slave_info.get('revision', 0)}",
                        slave_info.get("serial_number", ""),
                        slave_info.get("state", "Unknown"),
                        str(slave_info.get("io_map", {}).get("input_bytes", 0)),
                        str(slave_info.get("io_map", {}).get("output_bytes", 0)),
                    ]
                )
            print_table(
                table_data,
                [
                    "Pos",
                    "Name",
                    "Manufacturer",
                    "Product Code",
                    "FW Version",
                    "Serial",
                    "State",
                    "In",
                    "Out",
                ],
                title="EtherCAT Slaves",
                logger=self.logger,
            )

        # Report each slave as a service/device
        for slave_pos, slave_info in slaves.items():
            fw = slave_info.get("fw_version", "")
            service_info = {
                "name": "ethercat_slave",
                "product": slave_info["name"],
                "version": fw if fw else f"Rev {slave_info['revision']}",
                "manufacturer": slave_info["manufacturer"],
                "state": slave_info["state"],
            }
            # Use slave position as "port" for reporting
            self.report_service_info(self.interface, port=slave_pos, **service_info)

        # Display fuzzing results table if available
        sdo_fuzz = fuzzing.get("sdo_fuzzing", {})
        pdo_fuzz = fuzzing.get("pdo_fuzzing", {})
        if sdo_fuzz.get("tests_performed", 0) > 0 or pdo_fuzz.get("tests_performed", 0) > 0:
            fuzz_data = []
            if sdo_fuzz.get("tests_performed", 0) > 0:
                fuzz_data.append(
                    [
                        "SDO",
                        str(sdo_fuzz.get("tests_performed", 0)),
                        str(len(sdo_fuzz.get("responses", []))),
                        str(len(sdo_fuzz.get("errors", []))),
                    ]
                )
            if pdo_fuzz.get("tests_performed", 0) > 0:
                fuzz_data.append(
                    [
                        "PDO",
                        str(pdo_fuzz.get("tests_performed", 0)),
                        str(len(pdo_fuzz.get("anomalies", []))),
                        str(len(pdo_fuzz.get("errors", []))),
                    ]
                )
            if fuzz_data:
                print_table(
                    fuzz_data,
                    ["Type", "Tests", "Anomalies/Responses", "Errors"],
                    title="Fuzzing Results",
                    logger=self.logger,
                )

        # Log summary
        self.logger.display(f"EtherCAT scan complete: {len(slaves)} slaves found")

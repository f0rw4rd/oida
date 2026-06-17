"""
EtherNet/IP Fuzz Testing Mixin

Handles CIP attribute fuzz testing:
- Fuzz blacklist for dangerous attributes (network config, security, I/O)
- Fuzz writable attributes with type-aware payloads
- Monitor device responsiveness during fuzzing
- Restore original values after testing
"""

from __future__ import annotations

from typing import Any, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class FuzzMixin(_ScannerBase):
    """Mixin providing CIP attribute fuzz testing capabilities."""

    # Blacklist of dangerous attributes that can cause network disconnection or device issues
    # Format: {class_id: {attr_id: "reason"}}
    FUZZ_BLACKLIST = {
        # === Network Configuration - HIGH RISK ===
        0xF5: {  # TCP/IP Interface (245)
            3: "Configuration Control - changes IP mode (DHCP/static), can disconnect device",
            5: "Interface Configuration - contains IP/netmask/gateway, can disconnect device",
            6: "Host Name - can affect DNS resolution",
            9: "Multicast Config - can break multicast communication",
            13: "Encapsulation Inactivity Timeout - low values cause disconnects",
        },
        0xF6: {  # Ethernet Link (246)
            1: "Interface Speed - changing can disconnect device",
            2: "Interface Flags - can disable interface",
            6: "Interface Control - can disable interface or force settings",
            10: "Interface Type - network interface configuration",
        },
        0xF3: {  # Connection Configuration (243)
            1: "Connection Configuration - can break active connections",
        },
        0xF4: {  # Port (244)
            7: "Port Type - changing port config can affect routing",
        },
        # === Device Identity - MEDIUM RISK ===
        0x01: {  # Identity (1)
            5: "Status - device status word, can trigger faults",
            6: "Serial Number - device identification, may be protected",
            7: "Product Name - corrupting can affect identification",
        },
        # === Security Objects - HIGH RISK ===
        0x5D: {  # CIP Security (93)
            1: "State - can lock out access or reset security",
            3: "Security Profiles - can change authentication requirements",
        },
        0x5E: {  # EtherNet/IP Security (94)
            1: "State - can enable/disable TLS, affect connectivity",
        },
        0x5F: {  # Certificate Management (95)
            1: "Capability Flags - certificate operations",
        },
        # === I/O and Process Data - HIGH RISK ===
        0x04: {  # Assembly (4) - I/O data assemblies
            3: "Data - writing to I/O assemblies can affect physical process",
        },
        0x06: {  # Connection Manager (6)
            1: "Open Requests - can affect active I/O connections",
        },
        # === Time and Synchronization ===
        0x43: {  # Time Sync (67)
            6: "System Time - changing time can affect synchronization",
            10: "Clock Type - can affect PTP/time sync behavior",
        },
        # === Quality of Service ===
        0x48: {  # QoS (72)
            4: "DSCP Urgent - QoS markings, can affect traffic priority",
            5: "DSCP Scheduled - QoS markings",
            6: "DSCP High - QoS markings",
            7: "DSCP Low - QoS markings",
            8: "DSCP Explicit - QoS markings",
        },
    }

    def _fuzz_attributes(
        self,
        conn: Any,
        attributes: Dict[str, Any],
        write_test_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Fuzz test writable attributes.

        Args:
            conn: pycomm3 connection
            attributes: Full attribute data with values
            write_test_results: Results from write testing with 'writable' flags
        """
        fuzz_results = {}

        if self.read_only:
            self.logger.display("Skipping fuzz tests (read-only mode)")
            return fuzz_results

        # Count writable attributes and check blacklist
        writable_count = 0
        blacklisted_count = 0
        blacklisted_attrs = []
        for class_id, write_info in write_test_results.items():
            class_id_int = int(class_id)
            class_blacklist = self.FUZZ_BLACKLIST.get(class_id_int, {})
            for attr_id, attr_write in write_info.get("class_attributes", {}).items():
                if attr_write.get("writable"):
                    attr_id_int = int(attr_id)
                    if attr_id_int in class_blacklist:
                        blacklisted_count += 1
                        blacklisted_attrs.append(
                            (class_id_int, 0, attr_id_int, class_blacklist[attr_id_int])
                        )
                    else:
                        writable_count += 1
            for inst_id, inst_attrs in write_info.get("instances", {}).items():
                for attr_id, attr_write in inst_attrs.items():
                    if attr_write.get("writable"):
                        attr_id_int = int(attr_id)
                        if attr_id_int in class_blacklist:
                            blacklisted_count += 1
                            blacklisted_attrs.append(
                                (
                                    class_id_int,
                                    int(inst_id),
                                    attr_id_int,
                                    class_blacklist[attr_id_int],
                                )
                            )
                        else:
                            writable_count += 1

        if writable_count == 0 and blacklisted_count == 0:
            self.logger.display("No writable attributes found for fuzzing")
            return fuzz_results

        # Report blacklisted attributes
        if blacklisted_attrs:
            self.logger.warning(
                f"Skipping {blacklisted_count} blacklisted network-config attributes:"
            )
            for cls, inst, attr, reason in blacklisted_attrs:
                inst_str = f"inst {inst}" if inst > 0 else "class"
                self.logger.display(f"    0x{cls:02X} {inst_str} attr {attr}: {reason}")

        if writable_count == 0:
            self.logger.display("No safe attributes to fuzz (all blacklisted)")
            return fuzz_results

        self.logger.warning(
            f"FUZZING {writable_count} writable attributes - monitor device closely!"
        )
        self.logger.display("Press Ctrl+C to abort if device becomes unresponsive")

        # Fuzz each writable attribute
        for class_id, write_info in write_test_results.items():
            class_id_int = int(class_id)
            class_fuzz_results = {"class_attributes": {}, "instances": {}}
            class_blacklist = self.FUZZ_BLACKLIST.get(class_id_int, {})

            # Get original attribute data
            attr_data = attributes.get(class_id, attributes.get(class_id_int, {}))

            # Fuzz class attributes
            for attr_id, attr_write in write_info.get("class_attributes", {}).items():
                if attr_write.get("writable"):
                    attr_id_int = int(attr_id)
                    # Skip blacklisted attributes
                    if attr_id_int in class_blacklist:
                        continue
                    # Get original value and type from attributes
                    class_attrs = attr_data.get("class_attributes", {})
                    orig_info = class_attrs.get(attr_id_int, class_attrs.get(attr_id, {}))
                    orig_raw = orig_info.get("raw", "")
                    orig_value = bytes.fromhex(orig_raw) if orig_raw else b"\x00"
                    orig_type = orig_info.get("type", "")

                    fuzz_result = self._fuzz_single_attribute(
                        conn,
                        class_id_int,
                        0,
                        attr_id_int,
                        orig_value,
                        attr_write.get("name", ""),
                        orig_type,
                    )
                    class_fuzz_results["class_attributes"][attr_id_int] = fuzz_result

            # Fuzz instance attributes
            for inst_id, inst_attrs in write_info.get("instances", {}).items():
                inst_id_int = int(inst_id)
                inst_fuzz_results = {}

                for attr_id, attr_write in inst_attrs.items():
                    if attr_write.get("writable"):
                        attr_id_int = int(attr_id)
                        # Skip blacklisted attributes
                        if attr_id_int in class_blacklist:
                            continue
                        # Get original value and type
                        instances = attr_data.get("instances", {})
                        inst_data = instances.get(inst_id_int, instances.get(inst_id, {}))
                        orig_info = inst_data.get(attr_id_int, inst_data.get(attr_id, {}))
                        orig_raw = orig_info.get("raw", "")
                        orig_value = bytes.fromhex(orig_raw) if orig_raw else b"\x00"
                        orig_type = orig_info.get("type", "")

                        fuzz_result = self._fuzz_single_attribute(
                            conn,
                            class_id_int,
                            inst_id_int,
                            attr_id_int,
                            orig_value,
                            attr_write.get("name", ""),
                            orig_type,
                        )
                        inst_fuzz_results[attr_id_int] = fuzz_result

                if inst_fuzz_results:
                    class_fuzz_results["instances"][inst_id_int] = inst_fuzz_results

            if class_fuzz_results["class_attributes"] or class_fuzz_results["instances"]:
                fuzz_results[class_id_int] = class_fuzz_results

        return fuzz_results

    def _fuzz_single_attribute(
        self,
        conn: Any,
        class_id: int,
        instance: int,
        attr_id: int,
        original_value: bytes,
        attr_name: str = "",
        cip_type: str = "",
        iterations: int = 100,
    ) -> Dict[str, Any]:
        """Fuzz a single attribute with type-aware payloads.

        Args:
            conn: pycomm3 connection
            class_id: CIP class ID
            instance: Instance number (0 for class attributes)
            attr_id: Attribute ID
            original_value: Original attribute value as bytes
            attr_name: Attribute name for logging
            cip_type: CIP data type (USINT, UINT, DWORD, STRING, etc.)
            iterations: Number of fuzz iterations (default: 100)
        """
        from ..cip_definitions import get_object_name

        results = {
            "test_count": 0,
            "crashes": 0,
            "errors": [],
            "interesting": [],
            "restored": False,
        }

        class_name = get_object_name(class_id)
        inst_str = f"inst {instance}" if instance > 0 else "class"
        label = f"{class_name} {inst_str} attr {attr_id}"
        if attr_name:
            label += f" ({attr_name})"

        orig_hex = original_value.hex() if original_value else "(empty)"
        self.logger.display(f"  Fuzzing {label} [{cip_type}]...")
        self.logger.display(f"    Original: {orig_hex}")

        # Generate type-aware fuzz payloads using central fuzzer
        from ....utils.fuzzer import fuzz

        fuzz_payloads = list(fuzz(original_value, count=iterations, data_type=cip_type))

        # Generate and send fuzz payloads
        for i, (fuzz_data, fuzz_desc) in enumerate(fuzz_payloads):
            fuzz_hex = fuzz_data.hex() if fuzz_data else "(empty)"
            try:
                # Attempt to write fuzz data
                write_result = conn.generic_message(
                    service=0x10,  # Set_Attribute_Single
                    class_code=class_id,
                    instance=instance,
                    attribute=attr_id,
                    request_data=fuzz_data,
                    connected=True,
                    unconnected_send=False,
                )
                results["test_count"] += 1

                if write_result.error:
                    # Write rejected
                    self.logger.display(
                        f"    [{i + 1:2d}] {fuzz_hex:<20} ({fuzz_desc:<25}) -> REJECTED"
                    )
                else:
                    # Write succeeded - interesting!
                    self.logger.warning(
                        f"    [{i + 1:2d}] {fuzz_hex:<20} ({fuzz_desc:<25}) -> ACCEPTED!"
                    )
                    results["interesting"].append(
                        {
                            "iteration": i,
                            "payload": fuzz_hex,
                            "description": fuzz_desc,
                            "response": "accepted",
                        }
                    )

                # Check if device is still responding
                read_result = conn.generic_message(
                    service=0x0E,  # Get_Attribute_Single
                    class_code=class_id,
                    instance=instance,
                    attribute=attr_id,
                    connected=True,
                    unconnected_send=False,
                )

                if read_result.error and "timeout" in str(read_result.error).lower():
                    results["crashes"] += 1
                    results["errors"].append(f"Device unresponsive after payload {fuzz_data.hex()}")
                    self.logger.fail(f"  CRASH? Device unresponsive after fuzz iteration {i}")
                    break

            except Exception as e:
                self.logger.debug(f"fuzz single attribute failed: {e}")
                err_str = str(e).lower()
                if "timeout" in err_str or "connection" in err_str:
                    results["crashes"] += 1
                    results["errors"].append(f"Connection lost: {e}")
                    self.logger.fail(f"  CRASH? Connection lost: {e}")
                    break
                else:
                    results["errors"].append(str(e))

        # Attempt to restore original value only if something was accepted
        if original_value and results["interesting"]:
            try:
                restore_result = conn.generic_message(
                    service=0x10,
                    class_code=class_id,
                    instance=instance,
                    attribute=attr_id,
                    request_data=original_value,
                    connected=True,
                    unconnected_send=True,
                )
                results["restored"] = not restore_result.error
                if results["restored"]:
                    self.logger.success("    Restored original value")
                else:
                    self.logger.warning("    Failed to restore original value!")
            except Exception as exc:
                self.logger.warning(f"    Failed to restore: {exc}")

        # Report results
        if results["crashes"] > 0:
            self.logger.fail(f"  {label}: {results['crashes']} potential crashes!")
        elif results["interesting"]:
            self.logger.warning(f"  {label}: {len(results['interesting'])} interesting responses")
        else:
            self.logger.display(f"  {label}: {results['test_count']} tests, no issues")

        return results

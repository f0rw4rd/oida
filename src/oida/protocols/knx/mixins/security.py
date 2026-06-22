"""
KNX Security Mixin

Handles BCU authentication, access testing, and security analysis.
"""

import asyncio
from typing import Any, Dict, List, TYPE_CHECKING

if TYPE_CHECKING:
    from xknx import XKNX

from ..constants import _xknx_cls  # noqa: E402
from ....utils import SecurityAnalyzer


class SecurityMixin:
    """Mixin providing security operations."""

    async def _brute_bcu_auth(
        self,
        knx: "XKNX",
        address: str,
        keys: List[str],
        delay_ms: int = 100,
        continue_on_success: bool = False,
    ) -> Dict[str, Any]:
        """
        Test multiple BCU keys against a device.

        Args:
            knx: XKNX instance
            address: KNX individual address (e.g., "1.1.2")
            keys: List of hex keys to test
            delay_ms: Delay between attempts in milliseconds
            continue_on_success: Keep testing after the first valid key (default: stop)

        Returns:
            Dict with keys_tested, valid_keys, and errors
        """
        self.logger.debug(
            f"BCU brute force: device={address}, keys={len(keys)}, delay={delay_ms}ms"
        )
        results = {
            "address": address,
            "keys_tested": 0,
            "valid_keys": [],
            "errors": [],
        }

        total = len(keys)
        self.logger.display(f"Testing {total} BCU keys on {address}")

        addr = _xknx_cls.IndividualAddress(address)
        mgmt = knx.management

        try:
            async with mgmt.connection(addr) as p2p:
                for i, key_hex in enumerate(keys, 1):
                    try:
                        key = int(key_hex, 16)
                        resp = await p2p.request(
                            _xknx_cls.AuthorizeRequest(key), _xknx_cls.AuthorizeResponse
                        )
                        results["keys_tested"] += 1

                        if resp and resp.payload:
                            level = resp.payload.level
                            # Level 15 is the unauthenticated / no-access
                            # sentinel; levels 0-3 are all granted roles
                            # (0 = highest privilege, 3 = lowest), so any
                            # level other than 15 means the key authenticated.
                            if level != 15:
                                self.logger.success(
                                    f"[{i}/{total}] KEY FOUND: 0x{key_hex} -> level {level}"
                                )
                                results["valid_keys"].append({"key": key_hex, "level": level})
                                if not continue_on_success:
                                    self.logger.display("Stopping (first success)")
                                    break
                            else:
                                self.logger.debug(
                                    f"[{i}/{total}] 0x{key_hex} -> level {level} (no access)"
                                )
                        else:
                            self.logger.debug(f"[{i}/{total}] 0x{key_hex} -> no response")

                        # Progress update every 10 keys
                        if i % 10 == 0:
                            self.logger.display(
                                f"Progress: {i}/{total} keys tested ({i * 100 // total}%)"
                            )

                        # Delay between attempts
                        if delay_ms > 0:
                            await asyncio.sleep(delay_ms / 1000.0)

                    except Exception as e:
                        results["errors"].append(f"Key {key_hex}: {e}")
                        self.logger.debug(f"[{i}/{total}] 0x{key_hex} -> error: {e}")

        except Exception as e:
            results["errors"].append(str(e))
            self.logger.fail(f"Connection error: {e}")

        # Summary
        if results["valid_keys"]:
            self.logger.success(f"Found {len(results['valid_keys'])} valid key(s):")
            for vk in results["valid_keys"]:
                self.logger.success(f"  Key: 0x{vk['key']} -> Level {vk['level']}")
        else:
            self.logger.display(f"No valid keys found ({results['keys_tested']}/{total} tested)")

        if results["errors"]:
            self.logger.debug(f"Encountered {len(results['errors'])} errors during brute-force")

        return results

    async def _write_bcu_key(self, knx: "XKNX", address: str, key_arg: str) -> Dict[str, Any]:
        """Write BCU key (DANGEROUS operation) - NOT IMPLEMENTED.

        The actual KeyWriteRequest APCI is not exposed by xknx, so the write
        cannot be performed yet. We still validate the KEY:LEVEL argument so
        the operator gets a precise error on malformed input rather than a
        generic "not implemented".
        """
        result: Dict[str, Any] = {
            "address": address,
            "key_arg": key_arg,
            "success": False,
            "new_level": None,
            "error": None,
        }

        # Notify user immediately that this feature is not available.
        self.logger.fail("BCU key writing is NOT IMPLEMENTED in current xknx version")
        self.logger.display("This feature requires custom APCI implementation (KeyWriteRequest)")

        try:
            # Parse KEY:LEVEL format for validation only.
            parts = key_arg.split(":")
            if len(parts) != 2:
                result["error"] = "Expected format: KEY:LEVEL (e.g., 'FFFFFFFF:0')"
                return result

            key = int(parts[0], 16)
            level = int(parts[1])

            self.logger.debug(f"Requested key: 0x{key:08X} level: {level} for {address}")

            # Feature not available.
            result["error"] = "KeyWriteRequest not implemented - requires custom APCI"
        except ValueError as e:
            result["error"] = f"Invalid key/level format: {e}"
        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"Error writing BCU key: {e}")

        return result

    async def _test_read_access(self, knx: "XKNX", devices: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Test read access to devices"""
        read_results = {}
        self.logger.debug(f"Testing read access on {len(devices)} devices")

        self.logger.display(f"Testing read access to {len(devices)} devices")

        for device in devices:
            if not device.get("accessible"):
                continue

            device_addr = device["address"]
            device_results = {"readable_addresses": [], "errors": []}

            try:
                addr = _xknx_cls.IndividualAddress(device_addr)
                mgmt = knx.management

                async with mgmt.connection(addr) as p2p:
                    # Test common memory addresses
                    test_addresses = [0x0100, 0x0104, 0x0106, 0x010B, 0x0116, 0x011A]

                    for mem_addr in test_addresses:
                        try:
                            # xknx has no p2p.read_memory(); send a MemoryRead
                            # APCI and read MemoryResponse.data (mirrors the
                            # AuthorizeRequest/Response pattern above).
                            resp = await p2p.request(
                                _xknx_cls.MemoryRead(address=mem_addr, count=2),
                                _xknx_cls.MemoryResponse,
                            )
                            data = resp.payload.data if resp and resp.payload else None
                            if data:
                                device_results["readable_addresses"].append(
                                    {
                                        "address": hex(mem_addr),
                                        "data": data.hex(),
                                        "length": len(data),
                                    }
                                )
                        except Exception as e:
                            device_results["errors"].append(f"Memory {hex(mem_addr)}: {str(e)}")

                read_results[device_addr] = device_results

            except Exception as e:
                self.logger.debug(f"Read test failed for device {device_addr}: {e}")

        return read_results

    async def _test_write_access(
        self, knx: "XKNX", devices: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Test write access to devices"""
        write_results = {}
        self.logger.debug(
            f"Testing write access on {len(devices)} devices, read_only={self.read_only}"
        )

        if self.read_only:
            self.logger.display("Skipping write tests (read-only mode)")
            return write_results

        # Write-access testing actuates the bus (a real MemoryWrite transaction,
        # even though it writes the original value back), so it is a DANGEROUS
        # operation and must be gated behind --confirm like every other write
        # path in this module.
        if not self.args.get("confirm"):
            self.logger.fail("--test-write requires --confirm flag (DANGEROUS operation)")
            return write_results

        self.logger.display(f"Testing write access to {len(devices)} devices")

        # Mirror _write_memory's guard: never write into system memory.
        system_memory_end = getattr(self, "SYSTEM_MEMORY_END", 0x00FF)

        for device in devices:
            if not device.get("accessible"):
                continue

            device_addr = device["address"]
            device_results = {"writable_addresses": [], "errors": []}

            try:
                addr = _xknx_cls.IndividualAddress(device_addr)
                mgmt = knx.management

                async with mgmt.connection(addr) as p2p:
                    # Test writing to safe memory locations (read original, write back)
                    test_addresses = [0x0116]  # Safe test location

                    for mem_addr in test_addresses:
                        if mem_addr <= system_memory_end:
                            device_results["errors"].append(
                                f"Memory {hex(mem_addr)}: in system memory range "
                                f"(0x0000-{hex(system_memory_end)}), write skipped"
                            )
                            continue
                        try:
                            # Read original value (non-destructive write-back test).
                            resp = await p2p.request(
                                _xknx_cls.MemoryRead(address=mem_addr, count=1),
                                _xknx_cls.MemoryResponse,
                            )
                            original_data = resp.payload.data if resp and resp.payload else None
                            if original_data:
                                # Write the same value back via MemoryWrite APCI.
                                await p2p.request(
                                    _xknx_cls.MemoryWrite(address=mem_addr, data=original_data),
                                    _xknx_cls.MemoryResponse,
                                )
                                device_results["writable_addresses"].append(
                                    {
                                        "address": hex(mem_addr),
                                        "writable": True,
                                        "original_data": original_data.hex(),
                                    }
                                )
                        except Exception as e:
                            device_results["errors"].append(f"Memory {hex(mem_addr)}: {str(e)}")

                write_results[device_addr] = device_results

            except Exception as e:
                self.logger.debug(f"Write test failed for device {device_addr}: {e}")

        return write_results

    def _analyze_security(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze security configuration"""
        self.logger.debug("Running security analysis")
        analysis = SecurityAnalyzer.assess_protocol_security(
            {
                "authentication": False,  # KNX typically has no authentication
                "authorization": False,  # No built-in authorization
                "encryption": False,  # Clear text protocol
                "integrity_check": False,  # No integrity checking
                "access_control": len(results.get("write_test_results", {})) == 0,
            }
        )

        # Add KNX specific security concerns
        analysis["concerns"] = []

        # Report no encryption
        self.logger.security_finding("No encryption", detail="KNX protocol does not use encryption")

        # Report no authentication
        self.logger.security_finding(
            "No authentication", detail="KNX protocol does not require authentication"
        )

        device_count = len(results.get("devices", []))
        if device_count > 0:
            analysis["concerns"].append(f"{device_count} accessible devices found")

        writable_devices = len(
            [
                d
                for d in results.get("write_test_results", {}).values()
                if d.get("writable_addresses")
            ]
        )
        if writable_devices > 0:
            analysis["concerns"].append(f"{writable_devices} devices with write access")
            # Report writable access
            self.logger.security_finding(
                "Writable access",
                detail=f"{writable_devices} devices with unauthenticated write access",
            )

        if results.get("routing_test", {}).get("routing_supported"):
            analysis["concerns"].append("KNX routing is accessible")
            # Report insecure configuration
            self.logger.security_finding(
                "Insecure configuration", detail="KNX routing is accessible without authentication"
            )

        return analysis

    def _report_findings(self, results: Dict[str, Any]) -> None:
        """Report scanner findings"""
        host, port = self.get_target_info()

        # Report host and service
        self.report_host_info(host)
        self.report_service_info(host, port=port, name="knx", proto="udp")

        # Note: Device information already displayed in _display_device_info()

        # Report security concerns
        security_analysis = results.get("security_analysis", {})
        for concern in security_analysis.get("concerns", []):
            self.report_vulnerability(host, "knx_security", description=concern)

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

    # KNX BCU access levels (EMI/BCU authorization). Level 0 is the most
    # privileged role; higher numbers are progressively more restricted; 15 is
    # the unauthenticated / no-access sentinel returned when a key is rejected.
    _BCU_LEVEL_MEANING = {
        0: "system / full privilege (highest)",
        1: "privileged",
        2: "restricted",
        3: "lowest privilege",
        15: "no access (unauthenticated)",
    }

    @classmethod
    def _describe_bcu_level(cls, level: int) -> str:
        """Human-readable meaning of a BCU authorization level."""
        return cls._BCU_LEVEL_MEANING.get(level, f"level {level}")

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
                                meaning = self._describe_bcu_level(level)
                                self.logger.success(
                                    f"[{i}/{total}] KEY FOUND: 0x{key_hex} "
                                    f"-> level {level} ({meaning})"
                                )
                                results["valid_keys"].append(
                                    {"key": key_hex, "level": level, "level_meaning": meaning}
                                )
                                # Authenticating at level 0 grants full/system
                                # privilege on the device and is a distinct,
                                # high-severity outcome worth flagging on its own.
                                if level == 0:
                                    self.logger.security_finding(
                                        "Privileged BCU access",
                                        detail=(
                                            f"Key 0x{key_hex} authenticated at level 0 "
                                            f"(system / full privilege) on {address}"
                                        ),
                                    )
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
            self.logger.display(
                "  BCU levels: 0=system/full privilege (highest) .. 3=lowest, 15=no access"
            )
            for vk in results["valid_keys"]:
                meaning = vk.get("level_meaning") or self._describe_bcu_level(vk["level"])
                self.logger.success(f"  Key: 0x{vk['key']} -> Level {vk['level']} ({meaning})")
        else:
            self.logger.display(f"No valid keys found ({results['keys_tested']}/{total} tested)")

        if results["errors"]:
            self.logger.debug(f"Encountered {len(results['errors'])} errors during brute-force")

        return results

    async def _write_bcu_key(self, knx: "XKNX", address: str, key_arg: str) -> Dict[str, Any]:
        """Write a BCU access key via the KNX ``A_Key_Write`` service (DANGEROUS).

        Sends xknx's ``KeyWrite`` APCI (available since xknx 3.17) over a
        management connection and reads back the ``A_Key_Response``. The response
        carries the access level the key was set for, or ``0xFF`` (255) when the
        device rejects the write — typically because the connection is not first
        authorized at level 0 (``A_Authorize_Request``).

        ``key_arg`` is ``NEWKEY:LEVEL`` (hex key, decimal level); e.g.
        ``AABBCCDD:0`` sets key 0xAABBCCDD for level 0. Gated behind --confirm at
        the call site.
        """
        result: Dict[str, Any] = {
            "address": address,
            "key_arg": key_arg,
            "success": False,
            "new_level": None,
            "error": None,
        }

        # Parse and validate NEWKEY:LEVEL.
        try:
            parts = key_arg.split(":")
            if len(parts) != 2:
                raise ValueError("expected KEY:LEVEL (e.g., 'FFFFFFFF:0')")
            key = int(parts[0], 16)
            level = int(parts[1])
        except ValueError as e:
            result["error"] = f"Invalid key/level format: {e}"
            self.logger.fail(result["error"])
            return result

        if not 0 <= key <= 0xFFFFFFFF:
            result["error"] = f"Key out of range (0..0xFFFFFFFF): 0x{key:X}"
            self.logger.fail(result["error"])
            return result
        if not 0 <= level <= 15:
            result["error"] = f"Level out of range (0-15): {level}"
            self.logger.fail(result["error"])
            return result

        self.logger.warning(
            f"Writing BCU key 0x{key:08X} for level {level} "
            f"({self._describe_bcu_level(level)}) on {address}"
        )

        addr = _xknx_cls.IndividualAddress(address)
        mgmt = knx.management
        try:
            async with mgmt.connection(addr) as p2p:
                resp = await p2p.request(
                    _xknx_cls.KeyWrite(level=level, key=key),
                    _xknx_cls.KeyResponse,
                )
                if resp and resp.payload is not None:
                    returned = resp.payload.level
                    result["new_level"] = returned
                    # 0xFF (255) is the A_Key_Response "unsuccessful" sentinel.
                    if returned == 0xFF:
                        result["error"] = (
                            "Device rejected key write (level 0xFF) - authorization "
                            "at level 0 is required first"
                        )
                        self.logger.fail(
                            f"Key write rejected on {address} "
                            "(needs prior authorization at level 0)"
                        )
                    elif returned == level:
                        result["success"] = True
                        self.logger.success(
                            f"Key 0x{key:08X} written for level {level} on {address}"
                        )
                        self.logger.security_finding(
                            "BCU key overwritten",
                            detail=(
                                f"A_Key_Write set key 0x{key:08X} for level {level} on {address}"
                            ),
                        )
                    else:
                        result["error"] = (
                            f"Unexpected response level {returned} (requested {level})"
                        )
                        self.logger.warning(result["error"])
                else:
                    result["error"] = "No A_Key_Response received"
                    self.logger.fail(result["error"])
        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"Error writing BCU key: {e}")

        return result

    async def _test_read_access(self, knx: "XKNX", devices: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Test read access to devices"""
        read_results = {}
        self.logger.debug(f"Testing read access on {len(devices)} devices")

        # Nothing to test when no devices were discovered (e.g. a targeted
        # operation like --memory-dump or --key-write on a single address that
        # didn't run a bus scan). Emitting "Testing read access to 0 devices"
        # in that case is pure noise, so keep it to the debug channel.
        if not devices:
            return read_results

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
        system_memory_end = self.SYSTEM_MEMORY_END

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
                                # A_Memory_Write elicits NO response, so request it
                                # with a None response class (count=len(data)) --
                                # awaiting MemoryResponse always timed out, so every
                                # location was falsely reported non-writable even
                                # against a writable device (see _write_memory()).
                                await p2p.request(
                                    _xknx_cls.MemoryWrite(
                                        address=mem_addr,
                                        count=len(original_data),
                                        data=original_data,
                                    ),
                                    None,
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
                # KNX has no built-in access control. The old `write_test == 0`
                # heuristic credited it with access control whenever the (default-off,
                # --confirm-gated) write test simply hadn't run.
                "access_control": False,
            }
        )

        # Add KNX specific security concerns
        analysis["concerns"] = []

        # Report no encryption
        self.logger.security_finding(
            "No encryption",
            detail="KNX protocol does not use encryption",
        )

        # Report no authentication
        self.logger.security_finding(
            "No authentication",
            detail="KNX protocol does not require authentication",
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
                "Insecure configuration",
                detail="KNX routing is accessible without authentication",
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

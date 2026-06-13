"""
HART Enumeration Mixin

Handles device and network enumeration:
- WirelessHART detection and capabilities
- Sub-device listing for WirelessHART gateways
- Poll address scanning (multi-drop networks)
- HART command enumeration (universal, common practice, device-specific)
"""

from __future__ import annotations

import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class EnumerationMixin(_ScannerBase):
    """Mixin providing WirelessHART, sub-device, address scan, and command enumeration."""

    def detect_wirelesshart(self, device_info=None, client=None) -> Dict[str, Any]:
        """Detect WirelessHART capabilities and network information."""
        from ..scanner import PhysicalSignaling
        from ..hartip import HARTCommand, unpack_ascii

        client = client or self.client
        if not client:
            return {"error": "Not connected", "is_wireless": False}

        result = {
            "is_wireless": False,
            "is_gateway": False,
            "detection_method": [],
            "network_id": None,
            "long_tag": None,
            "sub_device_count": 0,
            "signaling_code": None,
            "security_findings": [],
        }

        # Method 1: Check signaling code from Command 0
        if device_info and device_info.physical_signaling_code == PhysicalSignaling.WIRELESS_HART:
            result["is_wireless"] = True
            result["detection_method"].append("signaling_code")
            result["signaling_code"] = "WirelessHART (2.4 GHz)"

        # Method 2: Try Command 20 (Read Long Tag) using resp.parsed
        try:
            response = client.read_long_tag(self.poll_address)
            if response.response_code == 0:
                long_tag = response.parsed
                if long_tag and isinstance(long_tag, str):
                    result["long_tag"] = long_tag.strip()
                    result["detection_method"].append("long_tag_supported")
                elif response.payload and len(response.payload) >= 24:
                    # Fallback: unpack directly
                    long_tag = unpack_ascii(response.payload[:24])
                    if long_tag:
                        result["long_tag"] = long_tag.strip()
                        result["detection_method"].append("long_tag_supported")
        except Exception as e:
            self.logger.debug(f"Failed to get response: {e}")

        # Method 3: Try Command 768 (Read Network ID)
        try:
            response = client.send_command(HARTCommand.READ_NETWORK_ID, self.poll_address)
            if response.response_code == 0 and len(response.payload) >= 2:
                network_id = struct.unpack(">H", response.payload[:2])[0]
                result["is_wireless"] = True
                result["network_id"] = network_id
                result["detection_method"].append("network_id_768")
        except Exception as e:
            self.logger.debug(f"Failed to get response: {e}")

        # Method 4: Try Command 85 (Read Sub-Device Count) - Gateway detection
        try:
            response = client.send_command(85, self.poll_address)
            if response.response_code == 0 and len(response.payload) >= 2:
                sub_device_count = struct.unpack(">H", response.payload[:2])[0]
                result["sub_device_count"] = sub_device_count
                if sub_device_count > 0:
                    result["is_gateway"] = True
                    result["is_wireless"] = True
                    result["detection_method"].append("gateway_sub_devices")
        except Exception as e:
            self.logger.debug(f"Failed to get response: {e}")

        # Add security findings for WirelessHART
        if result["is_wireless"]:
            result["security_findings"].append(
                {
                    "id": "HART-WIRELESS-001",
                    "severity": "info",
                    "finding": "WirelessHART device detected",
                    "details": f"Detection: {', '.join(result['detection_method'])}",
                }
            )

            if result["is_gateway"]:
                result["security_findings"].append(
                    {
                        "id": "HART-WIRELESS-002",
                        "severity": "medium",
                        "finding": (
                            f"WirelessHART Gateway with "
                            f"{result['sub_device_count']} connected devices"
                        ),
                        "details": "Gateway provides network access to wireless field devices",
                        "recommendation": "Ensure gateway is properly segmented and access controlled",
                    }
                )

            result["security_findings"].append(
                {
                    "id": "HART-WIRELESS-003",
                    "severity": "medium",
                    "finding": "WirelessHART network security",
                    "details": "WirelessHART uses AES-128-CCM* encryption with join/session keys",
                    "recommendation": "Ensure join keys are unique and rotated regularly",
                }
            )

        return result

    def list_sub_devices(self, client=None) -> List[Dict[str, Any]]:
        """List all sub-devices connected to a WirelessHART gateway."""
        from ..hartip import (
            HARTCommand,
            HARTIPTimeoutError,
            get_vendor_name,
            get_device_type_name,
            unpack_ascii,
        )

        client = client or self.client
        if not client:
            return []

        sub_devices = []

        # First get count (Command 85)
        try:
            count_response = client.send_command(85, self.poll_address)
            if count_response.response_code != 0 or len(count_response.payload) < 2:
                return []

            count = struct.unpack(">H", count_response.payload[:2])[0]
            if count == 0:
                return []

            self.logger.debug(f"Found {count} sub-devices")

        except Exception as e:
            self.logger.debug(f"Error reading sub-device count: {e}")
            return []

        # Enumerate each sub-device (Command 84)
        for idx in range(count):
            try:
                data = struct.pack(">H", idx)
                response = client.send_command(
                    HARTCommand.READ_SUB_DEVICE_IDENTITY, self.poll_address, data
                )

                if response.response_code == 0 and len(response.payload) >= 6:
                    payload = response.payload
                    manufacturer_id = payload[0]
                    device_type = payload[1]
                    device_id = payload[2:5].hex()

                    long_tag = ""
                    if len(payload) >= 30:
                        try:
                            long_tag = unpack_ascii(payload[6:30]).strip()
                        except Exception as e:
                            self.logger.debug(f"Failed to get long_tag: {e}")

                    sub_device = {
                        "index": idx,
                        "manufacturer_id": manufacturer_id,
                        "manufacturer": get_vendor_name(manufacturer_id),
                        "device_type": device_type,
                        "device_type_name": get_device_type_name(device_type),
                        "device_id": device_id,
                        "long_tag": long_tag,
                    }
                    sub_devices.append(sub_device)

                    self.logger.debug(
                        f"Sub-device {idx}: "
                        f"{sub_device['manufacturer']} {sub_device['device_type_name']}"
                    )

            except (HARTIPTimeoutError, TimeoutError):
                self.logger.debug(f"Timeout reading sub-device {idx}")
            except Exception as e:
                self.logger.debug(f"Error reading sub-device {idx}: {e}")

            time.sleep(0.1)

        return sub_devices

    def scan_poll_addresses(
        self, start: int = 0, end: int = 15, threads: int = 5, timeout: float = 2.0
    ) -> List[Dict[str, Any]]:
        """Scan for devices on multi-drop network."""
        from ..hartip import HARTIPClient, get_vendor_name, get_device_type_name
        from ....utils.protocol_helpers import ProgressTracker

        results = []
        addresses = list(range(max(0, start), min(16, end + 1)))

        def probe_address(addr: int) -> Optional[Dict[str, Any]]:
            try:
                probe_client = HARTIPClient(
                    host=self.host,
                    port=self.port,
                    protocol=self.transport,
                    timeout=timeout,
                )
                probe_client.connect()

                try:
                    response = probe_client.read_unique_id(addr)
                    if response.response_code == 0:
                        lib_info = response.parsed
                        return {
                            "address": addr,
                            "found": True,
                            "manufacturer_id": lib_info.manufacturer_id,
                            "manufacturer": lib_info.manufacturer_name
                            or get_vendor_name(lib_info.manufacturer_id),
                            "device_type": lib_info.device_type,
                            "device_type_name": get_device_type_name(lib_info.device_type),
                        }
                finally:
                    probe_client.close()

            except Exception as e:
                self.logger.debug(f"Probe address {addr} failed: {e}")
            return None

        progress = ProgressTracker(len(addresses), threshold=1.0, interval=0.5)

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(probe_address, addr): addr for addr in addresses}
            for future in as_completed(futures):
                result = future.result()
                if result and result.get("found"):
                    results.append(result)
                    progress.add_success()
                else:
                    progress.add_failed()

        progress.finish()
        return sorted(results, key=lambda x: x["address"])

    def enumerate_commands(
        self, command_range: str = "0-48", timeout: float = 2.0
    ) -> Dict[str, Any]:
        """Enumerate supported HART commands."""
        from ..hartip import HARTResponseCode, HARTIPTimeoutError
        from ....utils.protocol_helpers import ProgressTracker

        client = self.client
        if not client:
            return {"error": ["Not connected"]}

        commands = []
        for part in command_range.split(","):
            if "-" in part:
                start, end = map(int, part.split("-"))
                commands.extend(range(start, end + 1))
            else:
                commands.append(int(part))

        results: Dict[str, Any] = {"supported": [], "unsupported": [], "error": [], "details": {}}

        progress = ProgressTracker(len(commands), threshold=1.0, interval=0.5)

        for cmd in commands:
            try:
                response = client.send_command(cmd, self.poll_address, b"")

                if response.response_code == HARTResponseCode.SUCCESS:
                    results["supported"].append(cmd)
                    results["details"][cmd] = "OK"
                    progress.add_success()
                elif response.response_code == HARTResponseCode.UNDEFINED_COMMAND:
                    results["unsupported"].append(cmd)
                    progress.add_failed()
                elif response.response_code == HARTResponseCode.CMD_NOT_IMPLEMENTED:
                    results["unsupported"].append(cmd)
                    progress.add_failed()
                else:
                    results["supported"].append(cmd)
                    try:
                        results["details"][cmd] = HARTResponseCode(response.response_code).name
                    except ValueError:
                        results["details"][cmd] = f"code_{response.response_code}"
                    progress.add_success()

            except (HARTIPTimeoutError, TimeoutError):
                results["error"].append(cmd)
                progress.add_failed()
            except Exception as e:
                results["error"].append(cmd)
                results["details"][cmd] = str(e)
                progress.add_failed()

            time.sleep(0.1)

        progress.finish()
        return results

    def enumerate_device_specific_commands(self, start: int = 128, end: int = 253) -> List[int]:
        """Enumerate device-specific commands (128-253)."""
        result = self.enumerate_commands(f"{start}-{end}")
        return result.get("supported", [])

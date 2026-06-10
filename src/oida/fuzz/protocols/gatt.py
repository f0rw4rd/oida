"""GATT Application-Layer Fuzzer"""

from typing import Any, Dict, List, Optional, Union

import logging

logger = logging.getLogger(__name__)


try:
    import bleak

    _BLEAK_AVAILABLE = True
except ImportError:
    _BLEAK_AVAILABLE = False

from boofuzz import Block, Bytes, Group, Request

from ..core.base_fuzzer import BaseFuzzer, RequestInfo
from ..core.config import FuzzerConfig, ProtocolType
from ..monitors import BaseMonitor
from ..primitives.dynamic import SmartBytes


class GATTApplicationFuzzer(BaseFuzzer):
    """GATT Application-Layer Fuzzer for BLE device security testing

    Fuzzes application logic behind GATT services including characteristic
    values, state machines, service-specific data formats, and descriptors.
    """

    # Standard GATT Service UUIDs
    GATT_SERVICES = {
        "generic_access": "00001800-0000-1000-8000-00805f9b34fb",
        "generic_attribute": "00001801-0000-1000-8000-00805f9b34fb",
        "device_information": "0000180a-0000-1000-8000-00805f9b34fb",
        "battery_service": "0000180f-0000-1000-8000-00805f9b34fb",
        "heart_rate": "0000180d-0000-1000-8000-00805f9b34fb",
        "environmental_sensing": "0000181a-0000-1000-8000-00805f9b34fb",
        "automation_io": "00001815-0000-1000-8000-00805f9b34fb",
        "user_data": "0000181c-0000-1000-8000-00805f9b34fb",
    }

    # Standard GATT Characteristic UUIDs
    GATT_CHARACTERISTICS = {
        "device_name": "00002a00-0000-1000-8000-00805f9b34fb",
        "appearance": "00002a01-0000-1000-8000-00805f9b34fb",
        "manufacturer_name": "00002a29-0000-1000-8000-00805f9b34fb",
        "model_number": "00002a24-0000-1000-8000-00805f9b34fb",
        "serial_number": "00002a25-0000-1000-8000-00805f9b34fb",
        "firmware_revision": "00002a26-0000-1000-8000-00805f9b34fb",
        "battery_level": "00002a19-0000-1000-8000-00805f9b34fb",
        "temperature": "00002a6e-0000-1000-8000-00805f9b34fb",
        "humidity": "00002a6f-0000-1000-8000-00805f9b34fb",
    }

    # Common IoT Device Profiles
    IOT_DEVICE_PROFILES = {
        "smart_lock": {
            "services": ["automation_io", "battery_service"],
            "attack_vectors": ["unlock_commands", "pin_bypass", "state_confusion"],
        },
        "fitness_tracker": {
            "services": ["heart_rate", "battery_service", "device_information"],
            "attack_vectors": ["health_data_injection", "firmware_manipulation"],
        },
        "environmental_sensor": {
            "services": ["environmental_sensing", "battery_service"],
            "attack_vectors": ["sensor_spoofing", "calibration_bypass"],
        },
        "smart_home_device": {
            "services": ["automation_io", "user_data"],
            "attack_vectors": ["command_injection", "privilege_escalation"],
        },
    }

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests"""
        return [
            RequestInfo("Quick_Coverage", "All services quick sweep", "quick_coverage"),
            RequestInfo("gatt_baseline", "Baseline GATT operations", "baseline"),
            RequestInfo("gatt_deep_paths", "Deep path exploration", "standard"),
            RequestInfo("gatt_buffer_overflow", "Buffer overflow attacks", "high_crash"),
            RequestInfo("gatt_json_crash", "JSON parsing crash tests", "high_crash"),
            RequestInfo("gatt_state_confusion", "State machine confusion", "high_crash"),
            RequestInfo(
                "gatt_cross_characteristic_attacks",
                "Cross-characteristic attacks",
                "attack",
            ),
            RequestInfo("gatt_descriptor_attacks", "Descriptor manipulation", "attack"),
            RequestInfo("gatt_json_boundary", "JSON boundary tests", "boundary"),
            RequestInfo("gatt_iot_profile_attacks", "IoT profile-specific attacks", "attack"),
            RequestInfo("gatt_binary_payload_fuzzing", "Binary payload fuzzing", "standard"),
            RequestInfo("gatt_descriptor_deep_fuzzing", "Deep descriptor fuzzing", "standard"),
            RequestInfo("gatt_notification_fuzzing", "Notification fuzzing", "standard"),
        ]

    def __init__(self, config: FuzzerConfig = None, connection_factory=None):
        if not _BLEAK_AVAILABLE:
            raise ImportError(
                "bleak is required for GATT fuzzing. Install it with: pip install bleak"
            )
        if config:
            config.protocol_type = ProtocolType.BLE
        super().__init__(config, connection_factory)
        self.protocol_name = "GATT-Application"

        # Get configuration options
        self.device_address = config.get_option("device_address") if config else None
        if not self.device_address:
            raise ValueError("device_address option is required for GATT fuzzing")

        self.service_uuid = config.get_option("service_uuid") if config else None
        self.service_id = config.get_option("service_id") if config else None
        self.characteristic_uuid = config.get_option("characteristic_uuid") if config else None
        self.characteristic_id = config.get_option("characteristic_id") if config else None
        self.connection_timeout = config.get_option("connection_timeout", 10) if config else 10
        self.fuzz_mode = config.get_option("fuzz_mode", "discover") if config else "discover"
        self.enable_notifications = (
            config.get_option("enable_notifications", True) if config else True
        )
        self.state_fuzzing = config.get_option("state_fuzzing", True) if config else True
        self.max_write_size = config.get_option("max_write_size", 512) if config else 512

        # Runtime state
        self.client = None
        self.discovered_services = {}
        self.device_profile = None
        self.target_services = []  # List of resolved service UUIDs to target
        self.target_characteristics = []  # List of resolved characteristic UUIDs to target

        # Resolve service and characteristic identifiers
        self._resolve_service_identifiers()
        self._resolve_characteristic_identifiers()

    def _resolve_service_identifiers(self):
        """Resolve service identifiers to UUIDs"""
        if self.service_uuid:
            self.target_services.append(self.service_uuid)

        if self.service_id:
            # Check if it's a known service name
            if self.service_id.lower() in self.GATT_SERVICES:
                uuid = self.GATT_SERVICES[self.service_id.lower()]
                self.target_services.append(uuid)
                self.log.debug(f"Resolved service '{self.service_id}' to UUID: {uuid}")

            # Check if it's a hex string (handle different formats)
            elif self._is_valid_uuid_format(self.service_id):
                uuid = self._normalize_uuid(self.service_id)
                self.target_services.append(uuid)
                self.log.debug(f"Using service UUID: {uuid}")

            # Check if it's a short UUID (16-bit)
            elif self._is_hex_string(self.service_id):
                try:
                    # Convert 16-bit UUID to full 128-bit UUID
                    short_uuid = int(self.service_id, 16)
                    full_uuid = f"0000{short_uuid:04x}-0000-1000-8000-00805f9b34fb"
                    self.target_services.append(full_uuid)
                    self.log.debug(
                        f"Resolved 16-bit service ID '{self.service_id}' to UUID: {full_uuid}"
                    )
                except ValueError:
                    self.log.warning(
                        f"Warning: Could not parse service_id '{self.service_id}' as hex"
                    )
            else:
                self.log.warning(f"Warning: Unknown service identifier '{self.service_id}'")

    def _resolve_characteristic_identifiers(self):
        """Resolve characteristic identifiers to UUIDs"""
        if self.characteristic_uuid:
            self.target_characteristics.append(self.characteristic_uuid)

        if self.characteristic_id:
            # Check if it's a known characteristic name
            if self.characteristic_id.lower() in self.GATT_CHARACTERISTICS:
                uuid = self.GATT_CHARACTERISTICS[self.characteristic_id.lower()]
                self.target_characteristics.append(uuid)
                self.log.debug(
                    f"Resolved characteristic '{self.characteristic_id}' to UUID: {uuid}"
                )

            # Check if it's a hex string (handle different formats)
            elif self._is_valid_uuid_format(self.characteristic_id):
                uuid = self._normalize_uuid(self.characteristic_id)
                self.target_characteristics.append(uuid)
                self.log.debug(f"Using characteristic UUID: {uuid}")

            # Check if it's a short UUID (16-bit)
            elif self._is_hex_string(self.characteristic_id):
                try:
                    # Convert 16-bit UUID to full 128-bit UUID
                    short_uuid = int(self.characteristic_id, 16)
                    full_uuid = f"0000{short_uuid:04x}-0000-1000-8000-00805f9b34fb"
                    self.target_characteristics.append(full_uuid)
                    self.log.debug(
                        f"Resolved 16-bit characteristic ID '{self.characteristic_id}' to UUID: {full_uuid}"
                    )
                except ValueError:
                    self.log.warning(
                        f"Warning: Could not parse characteristic_id '{self.characteristic_id}' as hex"
                    )
            else:
                self.log.warning(
                    f"Warning: Unknown characteristic identifier '{self.characteristic_id}'"
                )

    def _is_valid_uuid_format(self, uuid_string: str) -> bool:
        """Check if string is a valid UUID format"""
        try:
            # Remove hyphens and check length
            clean_uuid = uuid_string.replace("-", "").replace("{", "").replace("}", "")
            return len(clean_uuid) == 32 and all(c in "0123456789abcdefABCDEF" for c in clean_uuid)
        except (AttributeError, TypeError) as e:
            self.log.debug(f"Invalid UUID format: {e}")
            return False

    def _is_hex_string(self, hex_string: str) -> bool:
        """Check if string is a valid hex string"""
        try:
            # Remove common prefixes
            clean_hex = hex_string.replace("0x", "").replace("0X", "")
            int(clean_hex, 16)
            return len(clean_hex) <= 8  # Max 32-bit hex
        except ValueError as e:
            logger.debug(f"Failed to get clean_hex: {e}")
            return False

    def _normalize_uuid(self, uuid_string: str) -> str:
        """Normalize UUID string to standard format"""
        # Remove hyphens, braces, and convert to lowercase
        clean = uuid_string.replace("-", "").replace("{", "").replace("}", "").lower()

        # Add hyphens in standard positions
        if len(clean) == 32:
            return f"{clean[0:8]}-{clean[8:12]}-{clean[12:16]}-{clean[16:20]}-{clean[20:32]}"

        return uuid_string  # Return original if can't normalize

    def _define_protocol(self):
        """Define GATT application-layer fuzzing patterns

        Test ordering is optimized for maximum early coverage and crash detection:

        Phase 1 (Quick Coverage): Touch all GATT operations once (~30 sec)
        Phase 2 (High-Crash): Buffer overflows, oversized payloads, deep paths
        Phase 3 (CVE-Targeted): State confusion, cross-char attacks, descriptors
        Phase 4 (Boundary): JSON boundary values, profile-specific edge cases
        Phase 5 (Deep Fuzzing): SmartBytes binary mutations, notification attacks
        """

        # ==================== PHASE 1: QUICK COVERAGE ====================
        # Touch all major GATT operations once for maximum early breadth
        quick_coverage = Request(
            "Quick_Coverage",
            children=(
                Block(
                    "all_operations_sweep",
                    children=(
                        Group(
                            "gatt_operations",
                            values=[
                                # Basic read/write operations
                                b"\x00",  # Read characteristic
                                b"\x01",  # Write characteristic (no response)
                                b"\x02",  # Write characteristic (with response)
                                b"\x03",  # Write long characteristic
                                b"\x04",  # Reliable write
                                b"\x05",  # Read descriptor
                                b"\x06",  # Write descriptor
                                b"\x07",  # Enable notifications (CCCD 0x0001)
                                b"\x08",  # Enable indications (CCCD 0x0002)
                                b"\x09",  # Disable notifications/indications
                                # Service discovery
                                b"\x10",  # Discover all services
                                b"\x11",  # Discover primary services
                                b"\x12",  # Discover included services
                                b"\x13",  # Discover characteristics
                                b"\x14",  # Discover descriptors
                                # MTU and connection
                                b"\x20",  # Exchange MTU
                                b"\x21",  # Read by type
                                b"\x22",  # Read by group type
                                b"\x23",  # Find information
                                b"\x24",  # Find by type value
                            ],
                        ),
                        # Minimal valid handle for quick sweep
                        Bytes("handle", b"\x00\x01", size=2, fuzzable=False),
                    ),
                )
            ),
        )
        self.session.connect(quick_coverage)

        # Baseline valid operations for comparison
        baseline = Request(
            "gatt_baseline",
            children=(
                Block(
                    "baseline_ops",
                    children=(
                        Group(
                            "valid_payloads",
                            values=[
                                '{"status": "ok"}',
                                b"\x01\x00",  # Valid CCCD enable
                                b"\x00\x00",  # Valid CCCD disable
                                "test",
                            ],
                        )
                    ),
                )
            ),
        )
        self.session.connect(baseline)

        # ==================== PHASE 2: HIGH-CRASH TESTS ====================
        # Buffer overflows, oversized payloads - highest crash likelihood

        # Deep path traversal - parser crashes (moved from end)
        deep_paths = Request(
            "gatt_deep_paths",
            children=(
                Block(
                    "deep_path_payloads",
                    children=(
                        Group(
                            "deep_paths",
                            values=[
                                "../" * 200,
                                "..\\" * 200,
                                "/.." * 200,
                                "%2e%2e/" * 100,
                                "....//....//....//....//....//....//....//....//....//....",
                            ],
                        )
                    ),
                )
            ),
        )
        self.session.connect(deep_paths)

        # Buffer overflow attacks - most likely to crash
        buffer_overflow = Request(
            "gatt_buffer_overflow",
            children=(
                Block(
                    "overflow_attacks",
                    children=(
                        Group(
                            "overflow_payloads",
                            values=[
                                # Large buffers at key sizes
                                "A" * 255,  # uint8 max
                                "A" * 256,  # uint8 overflow
                                "A" * 512,  # Common buffer size
                                "A" * 1024,  # 1KB
                                "A" * 4096,  # Page size
                                "A" * 10000,  # Large overflow
                                "A" * 65535,  # uint16 max
                                # Binary overflow patterns
                                b"\xff" * 255,
                                b"\xff" * 512,
                                b"\x00" * 1024,
                                b"\x41" * 2048,
                                # Format string triggers
                                "%s" * 100,
                                "%n" * 50,
                                "%x" * 200,
                                # Null byte injection
                                "A" * 100 + "\x00" + "B" * 100,
                                b"\x00" * 256,
                            ],
                        )
                    ),
                )
            ),
        )
        self.session.connect(buffer_overflow)

        # JSON crash patterns - extracted from original, high-crash only
        json_crash = Request(
            "gatt_json_crash",
            children=(
                Block(
                    "json_crash_patterns",
                    children=(
                        Group(
                            "crash_json",
                            values=[
                                # Oversized JSON payloads
                                '{"command": "' + "A" * 10000 + '"}',
                                '{"config": {"nested": {"deep": {"value": "' + "X" * 2000 + '"}}}}',
                                "{" + '"key":' * 1000 + '"value"}',
                                # Deep nesting
                                '{"a":' * 100 + "1" + "}" * 100,
                                "[" * 100 + "1" + "]" * 100,
                                # Number overflow
                                '{"number": 1.23e999999}',
                                '{"int": 99999999999999999999999999999999999999}',
                                '{"float": ' + "9" * 1000 + ".0}",
                                # Malformed structures
                                '{"incomplete": ',
                                '{"invalid": true false}',
                                '{"unmatched": [}',
                                '{"trailing": "comma",}',
                            ],
                        )
                    ),
                )
            ),
        )
        self.session.connect(json_crash)

        # ==================== PHASE 3: CVE-TARGETED OPERATIONS ====================
        # State confusion and cross-characteristic attacks (CVE-relevant)

        # State machine confusion attacks - moved up from Phase 5
        if self.state_fuzzing:
            state_confusion = Request(
                "gatt_state_confusion",
                children=(
                    Block(
                        "state_attacks",
                        children=(
                            Group(
                                "state_sequences",
                                values=[
                                    # Out-of-order operations (auth bypass vectors)
                                    "WRITE_WITHOUT_AUTH",
                                    "AUTHENTICATE->DISCONNECT->WRITE",
                                    "CONFIG_BEFORE_AUTH",
                                    # Rapid state changes (race conditions)
                                    "CONNECT->WRITE->DISCONNECT->CONNECT",
                                    "WRITE->WRITE->WRITE",
                                    "READ->WRITE->READ",
                                    # Notification abuse
                                    "ENABLE_NOTIFICATIONS->IMMEDIATE_DISCONNECT",
                                    # Double operations
                                    "AUTH->AUTH",
                                    "CONNECT->CONNECT",
                                ],
                            )
                        ),
                    )
                ),
            )
            self.session.connect(state_confusion)

        # Cross-characteristic dependency attacks - authentication bypass vectors
        cross_char = Request(
            "gatt_cross_characteristic_attacks",
            children=(
                Block(
                    "cross_char_attacks",
                    children=(
                        Group(
                            "dependency_violations",
                            values=[
                                # Write to dependent characteristics in wrong order
                                "CONFIG_BEFORE_AUTH",
                                "DATA_BEFORE_SETUP",
                                "EXECUTE_BEFORE_VALIDATE",
                                "WRITE_BEFORE_READ_ONLY_CHECK",
                                # Inconsistent characteristic states
                                "ENABLE_SENSOR_DISABLE_POWER",
                                "SET_LIMITS_BEYOND_CAPABILITY",
                                "CONCURRENT_EXCLUSIVE_MODES",
                                # Handle manipulation
                                "INVALID_HANDLE_WRITE",
                                "HANDLE_REUSE_AFTER_DISCONNECT",
                            ],
                        )
                    ),
                )
            ),
        )
        self.session.connect(cross_char)

        # Descriptor manipulation - privilege escalation vectors
        descriptor_attacks = Request(
            "gatt_descriptor_attacks",
            children=(
                Block(
                    "descriptor_fuzzing",
                    children=(
                        Group(
                            "descriptor_payloads",
                            values=[
                                # CCCD manipulation (notification control)
                                b"\x01\x00",  # Enable notifications
                                b"\x02\x00",  # Enable indications
                                b"\x03\x00",  # Both (invalid on some devices)
                                b"\xff\xff",  # All bits set
                                b"\x00\x00\x00\x00",  # Oversized CCCD
                                # Extended properties manipulation
                                b"\x01",  # Reliable write
                                b"\x02",  # Writable auxiliaries
                                b"\xff",  # All flags
                                # User description overflow
                                b"A" * 512,  # Long description
                                b"\x00" * 256,  # Null bytes
                            ],
                        )
                    ),
                )
            ),
        )
        self.session.connect(descriptor_attacks)

        # ==================== PHASE 4: BOUNDARY ATTACKS ====================
        # JSON boundary values and profile-specific edge cases

        # JSON boundary testing (separated from crash patterns)
        json_boundary = Request(
            "gatt_json_boundary",
            children=(
                Block(
                    "json_boundary_testing",
                    children=(
                        Group(
                            "boundary_json",
                            values=[
                                # Integer boundaries
                                '{"value": 0}',
                                '{"value": -1}',
                                '{"value": 127}',
                                '{"value": 128}',
                                '{"value": 255}',
                                '{"value": 256}',
                                '{"value": 32767}',
                                '{"value": 32768}',
                                '{"value": 65535}',
                                '{"value": 65536}',
                                '{"value": 2147483647}',
                                '{"value": 2147483648}',
                                '{"value": 4294967295}',
                                '{"value": 4294967296}',
                                # Float boundaries
                                '{"value": 0.0}',
                                '{"value": -0.0}',
                                '{"value": 1.7976931348623157e+308}',
                                '{"value": 2.2250738585072014e-308}',
                                # String boundaries
                                '{"str": ""}',
                                '{"str": null}',
                                # Unicode edge cases
                                '{"unicode": "\\u0000\\uFFFF\\uD800\\uDFFF"}',
                                '{"name": "test\\u0000\\u0001\\u0002"}',
                                '{"rtl": "\\u202E\\u202D\\u202C"}',
                            ],
                        )
                    ),
                )
            ),
        )
        self.session.connect(json_boundary)

        # Consolidated IoT profile attacks (merged to reduce redundancy)
        profile_attacks = Request(
            "gatt_iot_profile_attacks",
            children=(
                Block(
                    "profile_attack_vectors",
                    children=(
                        Group(
                            "profile_payloads",
                            values=[
                                # Smart lock attacks (pin_bypass, unlock_commands)
                                '{"pin": ""}',
                                '{"pin": null}',
                                '{"pin": -1}',
                                '{"pin": "' + "0" * 1000 + '"}',
                                '{"command": "unlock", "pin": "0000"}',
                                # Fitness tracker attacks (health_data_injection)
                                '{"heart_rate": -1}',
                                '{"heart_rate": 999999}',
                                '{"steps": 4294967295}',
                                '{"calories": -999999}',
                                # Environmental sensor attacks (sensor_spoofing)
                                '{"temperature": 999.999}',
                                '{"humidity": 200}',
                                '{"pressure": -1000}',
                                '{"co2": 999999}',
                                # Smart home attacks (command_injection, privilege_escalation)
                                '{"role": "admin"}',
                                '{"permissions": ["all"]}',
                                '{"execute": "rm -rf /"}',
                            ],
                        )
                    ),
                )
            ),
        )
        self.session.connect(profile_attacks)

        # ==================== PHASE 5: DEEP FUZZING ====================
        # SmartBytes mutations and thorough notification testing

        # Binary characteristic fuzzing - SmartBytes explores deeply
        binary_fuzzing = Request(
            "gatt_binary_payload_fuzzing",
            children=(
                Block(
                    "binary_fuzzing",
                    children=(
                        SmartBytes(
                            "characteristic_value",
                            b"test_data",
                            max_len=1024,
                            fuzzable=True,
                        ),
                    ),
                )
            ),
        )
        self.session.connect(binary_fuzzing)

        # Descriptor SmartBytes fuzzing
        descriptor_deep = Request(
            "gatt_descriptor_deep_fuzzing",
            children=(
                Block(
                    "descriptor_deep",
                    children=(
                        SmartBytes("descriptor_value", b"\x01\x00", max_len=512, fuzzable=True),
                    ),
                )
            ),
        )
        self.session.connect(descriptor_deep)

        # Notification/Indication deep fuzzing
        if self.enable_notifications:
            notification_fuzzing = Request(
                "gatt_notification_fuzzing",
                children=(
                    Block(
                        "notification_attacks",
                        children=(
                            Group(
                                "notification_exploits",
                                values=[
                                    # Notification flooding
                                    "ENABLE_ALL_NOTIFICATIONS",
                                    "RAPID_SUBSCRIPTION_CHANGES",
                                    "NOTIFICATION_WITHOUT_SUBSCRIPTION",
                                    # Malformed notification responses
                                    "OVERSIZED_NOTIFICATION_DATA",
                                    "INVALID_HANDLE_NOTIFICATIONS",
                                    "NOTIFICATION_TIMING_ATTACKS",
                                    # Extended attacks
                                    "INDICATION_WITHOUT_CONFIRM",
                                    "NOTIFICATION_HANDLE_EXHAUSTION",
                                    "CONCURRENT_NOTIFICATION_ENABLE",
                                ],
                            )
                        ),
                    )
                ),
            )
            self.session.connect(notification_fuzzing)

    async def _connect_to_device(self) -> bool:
        """Connect to the BLE device"""
        try:
            self.client = bleak.BleakClient(self.device_address)
            await self.client.connect(timeout=self.connection_timeout)
            return self.client.is_connected
        except Exception as e:
            self.log.debug(f"Failed to connect to device {self.device_address}: {e}")
            return False

    async def _discover_services(self) -> Dict[str, Any]:
        """Discover GATT services and characteristics"""
        if not self.client or not self.client.is_connected:
            return {}

        services = {}
        try:
            gatt_services = await self.client.get_services()

            for service in gatt_services:
                service_info = {"uuid": service.uuid, "characteristics": {}}

                for char in service.characteristics:
                    char_info = {
                        "uuid": char.uuid,
                        "properties": char.properties,
                        "descriptors": [desc.uuid for desc in char.descriptors],
                    }
                    service_info["characteristics"][char.uuid] = char_info

                services[service.uuid] = service_info

        except Exception as e:
            self.log.debug(f"Service discovery failed: {e}")

        return services

    async def _detect_device_profile(self) -> Optional[str]:
        """Detect IoT device profile based on discovered services"""
        if not self.discovered_services:
            return None

        service_uuids = set(self.discovered_services.keys())

        for profile_name, profile_data in self.IOT_DEVICE_PROFILES.items():
            profile_services = set(
                self.GATT_SERVICES[s] for s in profile_data["services"] if s in self.GATT_SERVICES
            )

            # Check if device has services matching this profile
            if profile_services.issubset(service_uuids):
                return profile_name

        return None

    async def _fuzz_characteristic(self, char_uuid: str, payload: Union[str, bytes]) -> bool:
        """Fuzz a specific characteristic with given payload"""
        try:
            if isinstance(payload, str):
                payload = payload.encode("utf-8")

            # Truncate payload if it exceeds max write size
            if len(payload) > self.max_write_size:
                payload = payload[: self.max_write_size]

            await self.client.write_gatt_char(char_uuid, payload)
            return True

        except Exception as e:
            self.log.debug(f"Failed to write to characteristic {char_uuid}: {e}")
            return False

    def _get_monitors(self) -> List[BaseMonitor]:
        """Return list of monitors for GATT application fuzzing"""
        monitors = []

        # Could implement BLE-specific monitors here
        # For now, return empty list as BLE monitoring is complex

        return monitors

    def setup_custom_monitors(self) -> Optional[List[BaseMonitor]]:
        """Setup GATT-specific monitors"""
        return self._get_monitors()

    async def run_discovery_mode(self) -> Dict[str, Any]:
        """Run discovery mode to understand the device"""
        self.log.debug(f"Starting GATT discovery on device: {self.device_address}")

        if not await self._connect_to_device():
            return {"error": "Failed to connect to device"}

        # Discover services and characteristics
        self.discovered_services = await self._discover_services()
        self.log.debug(f"Discovered {len(self.discovered_services)} services")

        # Detect device profile
        self.device_profile = await self._detect_device_profile()
        if self.device_profile:
            self.log.debug(f"Detected device profile: {self.device_profile}")

        # Disconnect
        if self.client and self.client.is_connected:
            await self.client.disconnect()

        return {
            "services": self.discovered_services,
            "device_profile": self.device_profile,
            "total_characteristics": sum(
                len(s["characteristics"]) for s in self.discovered_services.values()
            ),
        }

    def get_fuzzing_summary(self) -> Dict[str, Any]:
        """Get summary of GATT fuzzing capabilities"""
        return {
            "target_device": self.device_address,
            "target_services": self.target_services,
            "target_characteristics": self.target_characteristics,
            "fuzzing_mode": self.fuzz_mode,
            "payload_formats": ["json", "binary", "string", "profile-specific"],
            "attack_vectors": [
                "JSON injection",
                "Buffer overflow",
                "State confusion",
                "Command injection",
                "Cross-characteristic attacks",
                "Notification flooding",
                "Descriptor manipulation",
            ],
            "supported_profiles": list(self.IOT_DEVICE_PROFILES.keys()),
            "known_services": list(self.GATT_SERVICES.keys()),
            "known_characteristics": list(self.GATT_CHARACTERISTICS.keys()),
            "max_write_size": self.max_write_size,
            "notifications_enabled": self.enable_notifications,
            "state_fuzzing_enabled": self.state_fuzzing,
            "service_resolution": {
                "service_uuid": self.service_uuid,
                "service_id": self.service_id,
                "characteristic_uuid": self.characteristic_uuid,
                "characteristic_id": self.characteristic_id,
            },
        }

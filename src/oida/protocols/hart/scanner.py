#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HART Protocol Scanner

Implements security testing functions for HART (Highway Addressable Remote Transducer)
protocol devices over HART-IP networks.

Backed by the hartip-py library for all protocol-level operations.

Features:
- Device identification and enumeration
- Process variable reading
- Configuration extraction
- Poll address scanning
- Command enumeration
- Security analysis
- WirelessHART gateway enumeration
- Device lock testing
- Fuzzing support
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

from oida.utils import NetworkScanner
from oida.utils.lazy_import import lazy_import
from oida.protocols.hart.mixins import DeviceInfoMixin, SecurityMixin, EnumerationMixin, FuzzMixin

_hartip = lazy_import("hartip", "HART")

from oida.protocols.hart.hartip import (
    HARTIPClient,
    HARTIP_UDP_PORT,
    get_device_type_name,
    probe_server_version,
)


def analyze_protocol_security(
    revision: int, write_protected: bool = False, device_locked: bool = False
) -> List[Dict[str, Any]]:
    """Analyze security based on protocol version and device state"""
    findings = []

    if revision <= 5:
        findings.append(
            {
                "id": "HART-SEC-001",
                "finding": f"Legacy HART revision {revision} - no encryption or authentication",
                "recommendation": "Upgrade to HART 7 or implement network-level security",
            }
        )
    elif revision == 6:
        findings.append(
            {
                "id": "HART-SEC-001",
                "finding": f"HART revision {revision} - no encryption, optional device lock",
                "recommendation": "Enable device lock, consider upgrade to HART 7",
            }
        )

    if not write_protected:
        findings.append(
            {
                "id": "HART-SEC-002",
                "finding": "Write protection disabled - device configuration can be modified",
                "recommendation": "Enable write protection mode",
            }
        )

    if revision >= 6 and not device_locked:
        findings.append(
            {
                "id": "HART-SEC-003",
                "finding": "Device lock not enabled (HART 6+ feature)",
                "recommendation": "Enable device lock via Command 77",
            }
        )

    findings.append(
        {
            "id": "HART-SEC-004",
            "finding": "HART-IP traffic is unencrypted",
            "recommendation": "Use VPN or network segmentation for HART-IP",
        }
    )

    return findings


class LockState:
    """Device lock state values"""

    UNLOCKED = 0
    LOCKED = 1
    PERMANENTLY_LOCKED = 2
    UNKNOWN = -1
    NOT_SUPPORTED = -2


class PhysicalSignaling:
    """HART physical signaling codes (from Command 0 response)"""

    WIRELESS_HART = 4

    NAMES = {
        0: "Bell 202 FSK",
        2: "FSK",
        4: "WirelessHART",
    }

    @classmethod
    def get_name(cls, code: int) -> str:
        return cls.NAMES.get(code, f"Unknown ({code})")


@dataclass
class HARTDeviceInfo:
    """HART device identification information"""

    manufacturer_id: int = 0
    manufacturer_name: str = ""
    device_type: int = 0
    device_revision: int = 0
    protocol_revision: int = 0
    software_revision: int = 0
    hardware_revision: int = 0
    physical_signaling_code: int = 0
    unique_id: bytes = b""
    tag: str = ""
    long_tag: str = ""
    descriptor: str = ""
    message: str = ""
    date: str = ""
    poll_address: int = 0
    write_protected: bool = False
    config_changed: bool = False
    lock_state: int = LockState.UNKNOWN
    is_wireless: bool = False
    wireless_network_id: int = 0
    sub_device_count: int = 0
    is_gateway: bool = False

    def get_protocol_version_name(self) -> str:
        if self.is_wireless:
            return f"WirelessHART (HART {self.protocol_revision})"
        if self.protocol_revision <= 5:
            return "HART 5"
        elif self.protocol_revision == 6:
            return "HART 6"
        elif self.protocol_revision >= 7:
            return "HART 7"
        return f"HART Rev {self.protocol_revision}"

    def get_signaling_name(self) -> str:
        return PhysicalSignaling.get_name(self.physical_signaling_code)

    def get_security_rating(self) -> str:
        if self.protocol_revision <= 5:
            return "critical"
        elif self.protocol_revision == 6:
            return "high"
        else:
            return "medium"


@dataclass
class HARTVariable:
    """HART process variable"""

    name: str = ""
    value: float = 0.0
    units_code: int = 0
    units_name: str = ""
    status: int = 0


@dataclass
class HARTScanResult:
    """Scan result for a single HART device"""

    host: str = ""
    port: int = 0
    poll_address: int = 0
    connected: bool = False
    device_info: Optional[HARTDeviceInfo] = None
    variables: List[HARTVariable] = field(default_factory=list)
    output_info: Dict[str, Any] = field(default_factory=dict)
    supported_commands: List[int] = field(default_factory=list)
    security_findings: List[Dict[str, Any]] = field(default_factory=list)
    encryption_status: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


class HARTScanner(DeviceInfoMixin, SecurityMixin, EnumerationMixin, FuzzMixin, NetworkScanner):
    """HART protocol scanner for security testing.

    Uses the hartip-py library for all protocol operations including
    connection management, command execution, and response parsing.
    """

    def __init__(self, args: Dict[str, Any]):
        super().__init__(args)
        self.protocol_name = "HART"
        self.default_port = HARTIP_UDP_PORT

        self.host = args.get("rhost", "127.0.0.1")
        self.port = int(args.get("rport", self.default_port))
        self.timeout = float(args.get("timeout", 5))
        # `protocol` is the argparse subparser dest (always literal "hart"),
        # so transport must be derived from the --tcp flag instead.
        self.transport = "tcp" if args.get("tcp", False) else "udp"
        self.poll_address = int(args.get("poll-addr", 0))
        self.debug = args.get("debug", False)
        self.confirm = bool(args.get("confirm", False))

        # HART-IP v2 TLS/PSK settings
        self.psk_identity = args.get("psk-identity")
        self.psk_key = args.get("psk-key")
        self.cipher_suite = args.get("cipher-suite")
        self.server_version: Optional[int] = None

        self.client: Optional[HARTIPClient] = None

    def get_protocol_name(self) -> str:
        return "HART"

    def get_default_port(self) -> int:
        return HARTIP_UDP_PORT

    def check_dependencies(self) -> bool:
        """Check if required dependencies are available"""
        return _hartip.is_available

    def probe_version(self) -> Optional[int]:
        """Probe HART-IP server version (v1 plaintext or v2 TLS).

        Uses probe_server_version() from hartip-py to detect whether
        the server supports HART-IP v2 (TLS/PSK).

        Returns:
            1 or 2, or None if probe failed
        """
        try:
            version = probe_server_version(self.host, self.port, timeout=self.timeout)
            self.server_version = version
            return version
        except Exception as e:
            self.logger.debug(f"Version probe failed: {e}")
            return None

    def connect(self) -> Optional[HARTIPClient]:
        """Establish connection to HART-IP device.

        Supports TLS/PSK for HART-IP v2 when credentials are provided.
        If TLS is requested but transport is UDP, auto-switches to TCP.

        Returns:
            HARTIPClient instance if successful, None otherwise
        """
        try:
            kwargs = {
                "host": self.host,
                "port": self.port,
                "protocol": self.transport,
                "timeout": self.timeout,
            }

            # TLS/PSK support: if PSK credentials provided, pass to client
            if self.psk_identity and self.psk_key:
                # The library's TLS-PSK callback returns the key bytes verbatim,
                # so the documented hex string must be decoded to raw bytes here
                # (e.g. AES-128 expects 16 bytes). Passing the ASCII hex through
                # un-decoded silently breaks the handshake.
                try:
                    psk_key_bytes = bytes.fromhex(self.psk_key.replace(" ", "").replace("0x", ""))
                except ValueError:
                    self.logger.error(f"Invalid --psk-key: '{self.psk_key}' is not valid hex")
                    return None
                # TLS only works over TCP
                if self.transport == "udp":
                    self.logger.debug("TLS requires TCP; switching from UDP to TCP")
                    kwargs["protocol"] = "tcp"
                    self.transport = "tcp"
                kwargs["psk_identity"] = self.psk_identity
                kwargs["psk_key"] = psk_key_bytes
                if self.cipher_suite:
                    kwargs["ciphers"] = self.cipher_suite

            self.client = HARTIPClient(**kwargs)
            self.client.connect()
            return self.client
        except Exception as e:
            self.logger.debug(f"Connection failed: {e}")
            return None

    def disconnect(self, connection: Any = None):
        """Close connection"""
        client = connection or self.client
        if client:
            try:
                client.close()
            except Exception as e:
                self.logger.debug(f"client.close(): {e}")
        self.client = None

    def discover(self, connection: Any = None) -> Dict[str, Any]:
        """Perform device discovery (BaseScanner abstract contract).

        Returns device identification and basic information. The NXC path
        (cli_runner.hart) drives scanning directly via the mixin reads;
        this concrete implementation satisfies the BaseScanner.discover()
        abstractmethod and backs the traditional Layer-1 scanner usage.
        """
        client = connection or self.client
        if not client:
            return {"error": "Not connected"}

        result = HARTScanResult(
            host=self.host, port=self.port, poll_address=self.poll_address, connected=True
        )

        try:
            device_info = self.read_device_info(client)
            if device_info:
                result.device_info = device_info

            result.variables = self.read_all_variables(client)
            result.output_info = self.read_output_info(client)

            wireless_info = self.detect_wirelesshart(device_info, client)
            if wireless_info.get("is_wireless") and device_info:
                device_info.is_wireless = True
                device_info.is_gateway = wireless_info.get("is_gateway", False)
                device_info.wireless_network_id = wireless_info.get("network_id") or 0
                device_info.sub_device_count = wireless_info.get("sub_device_count", 0)
                if wireless_info.get("long_tag"):
                    device_info.long_tag = wireless_info["long_tag"]
                result.security_findings.extend(wireless_info.get("security_findings", []))

            if device_info:
                # read_device_info() never populates lock_state, so read it
                # explicitly (Command 76) before the security analysis - otherwise
                # it stays at the LockState.UNKNOWN default and HART-SEC-003 is
                # silently suppressed on every HART 6+ device.
                device_info.lock_state = self.read_lock_state()
                # Only treat the device as "locked" when we definitively read a
                # locked state. UNKNOWN / NOT_SUPPORTED / UNLOCKED all mean the
                # lock is not confirmed enabled, so HART-SEC-003 should fire.
                device_locked = device_info.lock_state in (
                    LockState.LOCKED,
                    LockState.PERMANENTLY_LOCKED,
                )
                result.security_findings.extend(
                    analyze_protocol_security(
                        device_info.protocol_revision,
                        device_info.write_protected,
                        device_locked=device_locked,
                    )
                )

        except Exception as e:
            result.errors.append(str(e))

        return self._result_to_dict(result)

    def _result_to_dict(self, result: HARTScanResult) -> Dict[str, Any]:
        """Convert HARTScanResult to dictionary."""
        device_info_dict = None
        if result.device_info:
            device_info_dict = {
                "manufacturer_id": result.device_info.manufacturer_id,
                "manufacturer": result.device_info.manufacturer_name,
                "device_type": result.device_info.device_type,
                "device_type_name": get_device_type_name(result.device_info.device_type),
                "device_revision": result.device_info.device_revision,
                "protocol_revision": result.device_info.protocol_revision,
                "protocol_version": result.device_info.get_protocol_version_name(),
                "security_rating": result.device_info.get_security_rating(),
                "software_revision": result.device_info.software_revision,
                "hardware_revision": result.device_info.hardware_revision,
                "physical_signaling": result.device_info.get_signaling_name(),
                "unique_id": result.device_info.unique_id.hex()
                if result.device_info.unique_id
                else None,
                "tag": result.device_info.tag,
                "descriptor": result.device_info.descriptor,
                "date": result.device_info.date,
                "poll_address": result.device_info.poll_address,
                "write_protected": result.device_info.write_protected,
                "config_changed": result.device_info.config_changed,
            }
            if result.device_info.is_wireless:
                device_info_dict["is_wireless"] = True
                device_info_dict["long_tag"] = result.device_info.long_tag
                device_info_dict["wireless_network_id"] = result.device_info.wireless_network_id
                device_info_dict["is_gateway"] = result.device_info.is_gateway
                device_info_dict["sub_device_count"] = result.device_info.sub_device_count

        return {
            "host": result.host,
            "port": result.port,
            "poll_address": result.poll_address,
            "connected": result.connected,
            "device_info": device_info_dict,
            "variables": [
                {
                    "name": v.name,
                    "value": v.value,
                    "units": v.units_name,
                    "units_code": v.units_code,
                }
                for v in result.variables
            ],
            "output_info": result.output_info,
            "supported_commands": result.supported_commands,
            "encryption_status": result.encryption_status,
            "security_findings": result.security_findings,
            "errors": result.errors,
        }

    # --- Methods provided by mixins: DeviceInfoMixin, SecurityMixin,
    #     EnumerationMixin, FuzzMixin ---

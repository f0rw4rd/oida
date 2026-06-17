#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from time import sleep
from datetime import datetime
import struct
import threading

from ...utils import (
    register_protocol,
    SerialScanner,
    SecurityAnalyzer,
    ProgressTracker,
    parse_bool,
)
from ...utils import ics_logger as module
from ...utils.permissions import check_raw_socket_capability
from ...utils.lazy_import import lazy_import
from ...utils.ics_logger import get_module_logger
from .core import lookup_mac_vendor


# Lazy import for scapy - only loads when actually used
_scapy = lazy_import("scapy", "LLDP")

# Module-level cache for scapy classes (populated by _load_scapy_classes)
_scapy_classes: Dict[str, Any] = {}
dependencies_missing = not _scapy.is_available

logger = get_module_logger(__name__)


def _load_scapy_classes() -> Dict[str, Any]:
    """Load scapy classes lazily into _scapy_classes dict."""
    if _scapy_classes:
        return _scapy_classes

    _scapy()  # Ensure scapy is available (raises DependencyError if not)
    from scapy.all import (
        AsyncSniffer,
        load_contrib,
        Ether,
        get_if_list,
    )

    # Load LLDP contrib module first
    load_contrib("lldp")
    # Then import the LLDP classes
    from scapy.contrib.lldp import (
        LLDPDU,
        LLDPDUChassisID,
        LLDPDUPortID,
        LLDPDUTimeToLive,
        LLDPDUPortDescription,
        LLDPDUSystemName,
        LLDPDUSystemDescription,
        LLDPDUManagementAddress,
        LLDPDUGenericOrganisationSpecific,
        LLDPDUSystemCapabilities,
    )

    _scapy_classes.update(
        {
            "AsyncSniffer": AsyncSniffer,
            "Ether": Ether,
            "get_if_list": get_if_list,
            "LLDPDU": LLDPDU,
            "LLDPDUChassisID": LLDPDUChassisID,
            "LLDPDUPortID": LLDPDUPortID,
            "LLDPDUTimeToLive": LLDPDUTimeToLive,
            "LLDPDUPortDescription": LLDPDUPortDescription,
            "LLDPDUSystemName": LLDPDUSystemName,
            "LLDPDUSystemDescription": LLDPDUSystemDescription,
            "LLDPDUManagementAddress": LLDPDUManagementAddress,
            "LLDPDUGenericOrganisationSpecific": LLDPDUGenericOrganisationSpecific,
            "LLDPDUSystemCapabilities": LLDPDUSystemCapabilities,
        }
    )
    return _scapy_classes


# LLDP constants
LLDP_MULTICAST_MAC = "01:80:c2:00:00:0e"
LLDP_ETHERTYPE = 0x88CC


@dataclass
class LLDPDevice:
    """Represents an LLDP-discovered device"""

    mac_address: str
    chassis_id: str = ""
    port_id: str = ""
    system_name: str = ""
    system_description: str = ""
    port_description: str = ""
    capabilities: List[str] = None
    management_addresses: List[str] = None
    organization_specific: Dict[str, Any] = None
    ttl: int = 0
    first_seen: str = ""
    last_seen: str = ""

    def __post_init__(self):
        if self.capabilities is None:
            self.capabilities = []
        if self.management_addresses is None:
            self.management_addresses = []
        if self.organization_specific is None:
            self.organization_specific = {}


protocol_options = {
    "interface": {
        "type": "string",
        "description": "Network interface to capture LLDP packets on",
        "required": True,
        "default": "eth0",
    },
    "capture-time": {
        "type": "int",
        "description": "Time in seconds to capture LLDP packets",
        "required": False,
        "default": 60,
    },
    "passive-only": {
        "type": "bool",
        "description": "Only listen for LLDP packets (don't send any)",
        "required": False,
        "default": True,
    },
    "filter-industrial": {
        "type": "bool",
        "description": "Filter and highlight industrial/automation devices",
        "required": False,
        "default": True,
    },
}


@register_protocol(
    name="LLDP Scanner",
    description="""Link Layer Discovery Protocol scanner""",
    authors=["f0rw4rd"],
    references=[
        {"type": "url", "ref": "https://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol"}
    ],
    protocol_options=protocol_options,
    protocol_type="serial",
)
class LLDPScanner(SerialScanner):
    """LLDP Scanner implementing the base scanner interface"""

    def __init__(self, args: Dict[str, Any]):
        # Set interface before super().__init__ since SerialScanner requires it
        args.setdefault("interface", args.get("target", "eth0"))
        super().__init__(args)

        self.capture_time = int(args.get("capture-time", 60))
        self.passive_only = parse_bool(args.get("passive-only", True))
        self.filter_industrial = parse_bool(args.get("filter-industrial", True))

        # Quiet mode - suppress progress output when used as sub-scanner
        self.quiet = parse_bool(args.get("quiet", False))

        # Internal state
        self.discovered_devices = {}
        self.packet_count = 0

    def get_protocol_name(self) -> str:
        return "LLDP"

    def get_default_port(self) -> int:
        return 0  # No port for LLDP

    def check_dependencies(self) -> bool:
        return _scapy.is_available

    def connect(self) -> Any:
        """Prepare LLDP capture interface"""
        # Load scapy classes on first use
        _load_scapy_classes()

        try:
            # Check for raw socket capabilities
            has_capability, error_msg = check_raw_socket_capability()
            if not has_capability:
                self.logger.fail(error_msg)
                return None

            # Try to validate interface exists using scapy
            interfaces = _scapy_classes["get_if_list"]()

            if self.interface not in interfaces:
                self.logger.fail(
                    f"Interface '{self.interface}' not found. Available: {', '.join(interfaces)}"
                )
                return None

            self.logger.debug(f"Using interface: {self.interface}")
            return self.interface

        except Exception as e:
            # If validation fails, just proceed anyway - scapy will error if interface doesn't exist
            self.logger.debug(f"Could not validate interface (proceeding anyway): {e}")
            return self.interface

    def disconnect(self, connection: Any) -> None:
        """Clean up LLDP capture"""
        # Nothing specific to clean up for LLDP

    def discover(self, connection: Any) -> Dict[str, Any]:
        """Perform LLDP discovery by sniffing network traffic"""
        results = {
            "devices": [],
            "security_analysis": {},
            "industrial_devices": [],
            "statistics": {},
        }

        try:
            if not connection:
                results["error"] = "No valid interface available"
                return results

            # Start packet capture
            results = self._capture_lldp_packets(connection)

            # Process discovered devices
            results["devices"] = list(self.discovered_devices.values())

            # Filter industrial devices if requested
            if self.filter_industrial:
                results["industrial_devices"] = self._filter_industrial_devices(results["devices"])

            # Security analysis
            results["security_analysis"] = self._analyze_security(results)

            # Capture statistics (device/vendor/capability distribution)
            results["statistics"] = self._generate_statistics()

            # Report findings
            self._report_findings(results)

        except Exception as e:
            module.log_exc(f"Error during LLDP discovery: {e}")
            self.logger.fail(f"Error during LLDP discovery: {e}")
            results["error"] = str(e)

        return results

    def _generate_statistics(self) -> Dict[str, Any]:
        """Generate capture statistics (device counts, vendor + capability distribution)."""
        vendor_counts: Dict[str, int] = {}
        capability_counts: Dict[str, int] = {}

        for device in self.discovered_devices.values():
            vendor = lookup_mac_vendor(device.mac_address)
            vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1
            for capability in device.capabilities:
                capability_counts[capability] = capability_counts.get(capability, 0) + 1

        return {
            "total_devices": len(self.discovered_devices),
            "total_packets": self.packet_count,
            "vendor_distribution": vendor_counts,
            "capability_distribution": capability_counts,
        }

    def _capture_lldp_packets(self, interface: str) -> Dict[str, Any]:
        """Capture and process LLDP packets"""
        results = {"capture_info": {}}

        sniffer = None
        try:
            if not self.quiet:
                self.logger.display(
                    f"Starting LLDP capture on {interface} for {self.capture_time} seconds"
                )

            # Set up packet filter for LLDP
            filter_str = f"ether dst {LLDP_MULTICAST_MAC} and ether proto 0x88cc"

            # Create sniffer
            sniffer = _scapy_classes["AsyncSniffer"](
                iface=interface,
                filter=filter_str,
                prn=self._process_lldp_packet,
                store=0,  # Don't store packets in memory
                timeout=self.capture_time,
            )

            # Start capture
            sniffer.start()

            # Wait for capture to complete
            if self.quiet:
                # Silent wait when used as sub-scanner
                sleep(self.capture_time)
            else:
                progress = ProgressTracker(
                    self.capture_time, threshold=5.0, interval=3.0, log_func=self.logger.info
                )
                for i in range(self.capture_time):
                    sleep(1)
                    progress.update()

        except Exception as e:
            module.log_exc(f"Error during packet capture: {e}")
            self.logger.fail(f"Error during packet capture: {e}")
            results["error"] = str(e)
        finally:
            # Always try to stop the sniffer if it was created
            if sniffer:
                try:
                    # Stop capture if still running
                    if hasattr(sniffer, "running") and sniffer.running:
                        sniffer.stop()
                except Exception:
                    # Ignore errors when stopping - sniffer might have already stopped
                    pass

            results["capture_info"] = {
                "interface": interface,
                "capture_duration": self.capture_time,
                "packets_captured": self.packet_count,
                "devices_discovered": len(self.discovered_devices),
            }

            if not self.quiet:
                self.logger.display(
                    f"Capture complete: {self.packet_count} LLDP packets, "
                    f"{len(self.discovered_devices)} devices discovered"
                )

        return results

    def _process_lldp_packet(self, packet) -> None:
        """Process a single LLDP packet"""
        try:
            self.packet_count += 1
            _load_scapy_classes()

            if not packet.haslayer(_scapy_classes["LLDPDU"]):
                return

            # Extract source MAC
            src_mac = packet[_scapy_classes["Ether"]].src

            # Check if this is a new device (for logging)
            is_new_device = src_mac not in self.discovered_devices

            # Initialize or update device info
            if is_new_device:
                self.discovered_devices[src_mac] = LLDPDevice(
                    mac_address=src_mac, first_seen=datetime.now().isoformat()
                )

            device = self.discovered_devices[src_mac]
            device.last_seen = datetime.now().isoformat()

            # Process LLDP TLVs
            lldp_layer = packet[_scapy_classes["LLDPDU"]]

            # Process the chain of TLVs
            current_tlv = lldp_layer
            tlv_count = 0

            while current_tlv and tlv_count < 50:  # Safety limit
                tlv_count += 1
                # Process this TLV
                self._process_lldp_tlv(device, current_tlv)

                # Move to next TLV in the chain
                if hasattr(current_tlv, "payload") and current_tlv.payload:
                    current_tlv = current_tlv.payload
                else:
                    break

            # Only log when a new device is discovered (avoid per-packet logging)
            if is_new_device and self.debug:
                self.logger.debug(
                    f"New device discovered: {src_mac} ({device.system_name or 'unnamed'})"
                )

        except Exception as e:
            module.log_exc(f"Error processing LLDP packet: {e}")

    def _process_lldp_tlv(self, device: LLDPDevice, tlv) -> None:
        """Process individual LLDP TLV"""
        try:
            if isinstance(tlv, _scapy_classes["LLDPDUChassisID"]):
                device.chassis_id = self._format_chassis_id(tlv)

            elif isinstance(tlv, _scapy_classes["LLDPDUPortID"]):
                device.port_id = self._format_port_id(tlv)

            elif isinstance(tlv, _scapy_classes["LLDPDUTimeToLive"]):
                device.ttl = tlv.ttl

            elif isinstance(tlv, _scapy_classes["LLDPDUSystemName"]):
                if hasattr(tlv, "system_name"):
                    device.system_name = tlv.system_name.decode("utf-8", errors="ignore")
                elif hasattr(tlv, "name"):
                    device.system_name = tlv.name.decode("utf-8", errors="ignore")

            elif isinstance(tlv, _scapy_classes["LLDPDUSystemDescription"]):
                if hasattr(tlv, "system_description"):
                    device.system_description = tlv.system_description.decode(
                        "utf-8", errors="ignore"
                    )
                elif hasattr(tlv, "description"):
                    device.system_description = tlv.description.decode("utf-8", errors="ignore")

            elif isinstance(tlv, _scapy_classes["LLDPDUPortDescription"]):
                if hasattr(tlv, "port_description"):
                    device.port_description = tlv.port_description.decode("utf-8", errors="ignore")
                elif hasattr(tlv, "description"):
                    device.port_description = tlv.description.decode("utf-8", errors="ignore")

            elif isinstance(tlv, _scapy_classes["LLDPDUSystemCapabilities"]):
                device.capabilities = self._parse_capabilities(tlv)

            elif isinstance(tlv, _scapy_classes["LLDPDUManagementAddress"]):
                mgmt_addr = self._parse_management_address(tlv)
                if mgmt_addr and mgmt_addr not in device.management_addresses:
                    device.management_addresses.append(mgmt_addr)

            elif isinstance(tlv, _scapy_classes["LLDPDUGenericOrganisationSpecific"]):
                org_data = self._parse_organization_specific(tlv)
                if org_data:
                    device.organization_specific.update(org_data)

            else:
                # Handle unknown TLV types generically
                unknown_data = self._parse_unknown_tlv(tlv)
                if unknown_data:
                    device.organization_specific.update(unknown_data)

        except Exception as e:
            self.logger.debug(f"Error processing TLV {type(tlv)}: {e}")

    def _format_chassis_id(self, tlv) -> str:
        """Format chassis ID based on subtype"""
        try:
            if hasattr(tlv, "id"):
                # Use 'id' field instead of 'chassis_id'
                if tlv.subtype == 4:  # MAC address
                    return ":".join(f"{b:02x}" for b in tlv.id)
                elif isinstance(tlv.id, bytes):
                    return tlv.id.decode("utf-8", errors="ignore")
                else:
                    return str(tlv.id)
            elif hasattr(tlv, "chassis_id"):
                if tlv.subtype == 4:  # MAC address
                    return ":".join(f"{b:02x}" for b in tlv.chassis_id)
                else:
                    return tlv.chassis_id.decode("utf-8", errors="ignore")
        except Exception as e:
            self.logger.debug(f"Error formatting chassis ID: {e}")
            return "Unknown"

    def _format_port_id(self, tlv) -> str:
        """Format port ID based on subtype"""
        try:
            if hasattr(tlv, "id"):
                # Use 'id' field instead of 'port_id'
                if tlv.subtype == 3:  # MAC address
                    return ":".join(f"{b:02x}" for b in tlv.id)
                elif isinstance(tlv.id, bytes):
                    return tlv.id.decode("utf-8", errors="ignore")
                else:
                    return str(tlv.id)
            elif hasattr(tlv, "port_id"):
                if tlv.subtype == 3:  # MAC address
                    return ":".join(f"{b:02x}" for b in tlv.port_id)
                else:
                    return tlv.port_id.decode("utf-8", errors="ignore")
        except Exception as e:
            self.logger.debug(f"Error formatting port ID: {e}")
            return "Unknown"

    def _parse_capabilities(self, tlv) -> List[str]:
        """Parse system capabilities"""
        capabilities = []
        try:
            # Check individual capability fields
            if hasattr(tlv, "mac_bridge_enabled") and tlv.mac_bridge_enabled:
                capabilities.append("Bridge")
            if hasattr(tlv, "station_only_enabled") and tlv.station_only_enabled:
                capabilities.append("Station Only")
            if hasattr(tlv, "repeater_enabled") and tlv.repeater_enabled:
                capabilities.append("Repeater")
            if hasattr(tlv, "router_enabled") and tlv.router_enabled:
                capabilities.append("Router")
            if hasattr(tlv, "wlan_access_point_enabled") and tlv.wlan_access_point_enabled:
                capabilities.append("WLAN AP")
            if hasattr(tlv, "telephone_enabled") and tlv.telephone_enabled:
                capabilities.append("Telephone")
            if hasattr(tlv, "docsis_cable_device_enabled") and tlv.docsis_cable_device_enabled:
                capabilities.append("DOCSIS")
            if hasattr(tlv, "c_vlan_component_enabled") and tlv.c_vlan_component_enabled:
                capabilities.append("C-VLAN")
            if hasattr(tlv, "s_vlan_component_enabled") and tlv.s_vlan_component_enabled:
                capabilities.append("S-VLAN")
        except Exception as e:
            self.logger.debug(f"Error parsing capabilities: {e}")

        return capabilities

    def _parse_management_address(self, tlv) -> Optional[str]:
        """Parse management address using socket for standard formatting"""
        try:
            import socket as _socket

            if hasattr(tlv, "management_address_subtype"):
                addr = tlv.management_address
                if tlv.management_address_subtype == 1:  # IPv4
                    if isinstance(addr, str) and len(addr) == 8:
                        # Hex string like 'c0a800d7' - convert to bytes first
                        addr = bytes.fromhex(addr)
                    if isinstance(addr, bytes) and len(addr) >= 4:
                        return _socket.inet_ntoa(addr[:4])
                elif tlv.management_address_subtype == 2:  # IPv6
                    if isinstance(addr, bytes) and len(addr) >= 16:
                        return _socket.inet_ntop(_socket.AF_INET6, addr[:16])
        except Exception as e:
            self.logger.debug(f"Error parsing management address: {e}")
        return None

    def _parse_organization_specific(self, tlv) -> Optional[Dict[str, Any]]:
        """Parse organization-specific TLV"""
        try:
            # org_code is an integer in scapy
            if hasattr(tlv, "org_code"):
                oui = tlv.org_code
                oui_name = str(tlv.org_code)  # Scapy provides the name
            else:
                return None

            # Parse based on OUI value
            if oui == 3791 or "PROFIBUS" in oui_name:  # PROFIBUS/PROFINET (0x000ecf = 3791)
                return self._parse_profinet_tlv(tlv, oui_name)
            elif oui == 4623 or "IEEE 802.3" in oui_name:  # IEEE 802.3 (0x00120f = 4623)
                return self._parse_ieee_802_3_tlv(tlv, oui_name)
            elif oui == 32962 or "IEEE 802.1" in oui_name:  # IEEE 802.1 (0x0080c2 = 32962)
                return self._parse_ieee_802_1_tlv(tlv, oui_name)
            elif oui == 4795 or "TIA" in oui_name:  # LLDP-MED (0x0012bb = 4795)
                return self._parse_lldp_med_tlv(tlv, oui_name)
            else:
                # Generic parsing for unknown OUIs
                oui_hex = f"{oui:#08x}" if isinstance(oui, int) else str(oui)
                org_name = self._get_oui_name(oui) if isinstance(oui, int) else oui_name

                org_data = {
                    "OUI": oui_hex,
                    "Organization": org_name,
                    "Subtype": f"{tlv.subtype:#04x}" if hasattr(tlv, "subtype") else "Unknown",
                    "Data": tlv.data.hex() if hasattr(tlv.data, "hex") else str(tlv.data),
                }

                # Try to interpret common data patterns
                if hasattr(tlv, "data") and len(tlv.data) >= 6:
                    # Check if it might be a MAC address
                    if len(tlv.data) == 6:
                        mac = ":".join(f"{b:02x}" for b in tlv.data)
                        org_data["Possible MAC"] = mac
                    # Check if it might be an IPv4 address
                    elif len(tlv.data) == 4:
                        import socket as _socket

                        ip = _socket.inet_ntoa(tlv.data)
                        org_data["Possible IPv4"] = ip

                return {f"Unknown OUI {org_name}": org_data}

        except Exception as e:
            self.logger.debug(f"Error parsing organization TLV: {e}")
            return None

    def _parse_profinet_tlv(self, tlv, oui_name: str) -> Dict[str, Any]:
        """Parse PROFINET specific TLVs"""
        result = {}
        try:
            if tlv.subtype == 0x02:  # Port Status
                if len(tlv.data) >= 2:
                    port_status = struct.unpack(">H", tlv.data[:2])[0]
                    result["PROFINET Port Status"] = f"RTClass2: {port_status:#06x}"
            elif tlv.subtype == 0x05:  # Chassis MAC
                if len(tlv.data) >= 6:
                    mac = ":".join(f"{b:02x}" for b in tlv.data[:6])
                    result["PROFINET Chassis MAC"] = mac
            else:
                result[f"PROFINET Subtype {tlv.subtype}"] = tlv.data.hex()
        except Exception as e:
            self.logger.debug(f"Error parsing PROFINET TLV: {e}")

        return result

    def _parse_ieee_802_3_tlv(self, tlv, oui_name: str) -> Dict[str, Any]:
        """Parse IEEE 802.3 specific TLVs"""
        result = {}
        try:
            if tlv.subtype == 0x01:  # MAC/PHY Configuration/Status
                if len(tlv.data) >= 5:
                    auto_neg = tlv.data[0]
                    pmd_capabilities = struct.unpack(">H", tlv.data[1:3])[0]
                    operational_mau = struct.unpack(">H", tlv.data[3:5])[0]

                    caps = []
                    if pmd_capabilities & 0x8000:
                        caps.append("1000BASE-T FD")
                    if pmd_capabilities & 0x4000:
                        caps.append("1000BASE-T HD")
                    if pmd_capabilities & 0x0400:
                        caps.append("100BASE-TX FD")
                    if pmd_capabilities & 0x0200:
                        caps.append("100BASE-TX HD")
                    if pmd_capabilities & 0x0080:
                        caps.append("10BASE-T FD")
                    if pmd_capabilities & 0x0040:
                        caps.append("10BASE-T HD")

                    result["IEEE 802.3 MAC/PHY"] = {
                        "Auto-negotiation": "Enabled" if auto_neg & 0x02 else "Disabled",
                        "Capabilities": ", ".join(caps) if caps else "None",
                        "Operational MAU": f"{operational_mau:#06x}",
                    }
            elif tlv.subtype == 0x04:  # Maximum Frame Size
                if len(tlv.data) >= 2:
                    max_frame = struct.unpack(">H", tlv.data[:2])[0]
                    result["IEEE 802.3 Max Frame Size"] = f"{max_frame} bytes"
            else:
                result[f"IEEE 802.3 Subtype {tlv.subtype}"] = tlv.data.hex()
        except Exception as e:
            self.logger.debug(f"Error parsing IEEE 802.3 TLV: {e}")

        return result

    def _get_oui_name(self, oui: int) -> str:
        """Get OUI organization name"""
        oui_names = {
            0x0080C2: "IEEE 802.1",
            0x00120F: "IEEE 802.3",
            0x0012BB: "TIA (LLDP-MED)",
            0x000ECF: "PROFIBUS International",
            0x30B216: "Hytec Geraetebau GmbH",
        }
        return oui_names.get(oui, f"OUI-{oui:06X}")

    def _parse_ieee_802_1_tlv(self, tlv, oui_name: str) -> Dict[str, Any]:
        """Parse IEEE 802.1 specific TLVs (VLANs, etc)"""
        result = {}
        subtype_names = {
            0x01: "Port VLAN ID",
            0x02: "Port and Protocol VLAN ID",
            0x03: "VLAN Name",
            0x04: "Protocol Identity",
            0x07: "Link Aggregation",
        }

        subtype_name = subtype_names.get(tlv.subtype, f"Subtype {tlv.subtype:#04x}")
        result[f"IEEE 802.1 {subtype_name}"] = (
            tlv.data.hex() if hasattr(tlv.data, "hex") else str(tlv.data)
        )

        # TODO: Add specific parsing for each subtype
        return result

    def _parse_lldp_med_tlv(self, tlv, oui_name: str) -> Dict[str, Any]:
        """Parse LLDP-MED TLVs"""
        result = {}
        subtype_names = {
            0x01: "LLDP-MED Capabilities",
            0x02: "Network Policy",
            0x03: "Location Identification",
            0x04: "Extended Power-via-MDI",
            0x05: "Hardware Revision",
            0x06: "Firmware Revision",
            0x07: "Software Revision",
            0x08: "Serial Number",
            0x09: "Manufacturer Name",
            0x0A: "Model Name",
            0x0B: "Asset ID",
        }

        subtype_name = subtype_names.get(tlv.subtype, f"Subtype {tlv.subtype:#04x}")
        result[f"LLDP-MED {subtype_name}"] = (
            tlv.data.hex() if hasattr(tlv.data, "hex") else str(tlv.data)
        )

        # TODO: Add specific parsing for each subtype
        return result

    def _parse_unknown_tlv(self, tlv) -> Optional[Dict[str, Any]]:
        """Parse unknown TLV types generically"""
        try:
            tlv_type = "Unknown"
            tlv_data = {}

            # Get TLV type if available
            if hasattr(tlv, "_type"):
                tlv_type = f"TLV Type {tlv._type}"
            elif hasattr(tlv, "type"):
                tlv_type = f"TLV Type {tlv.type}"
            else:
                tlv_type = tlv.__class__.__name__

            # Extract common fields
            fields_to_check = [
                "_type",
                "_length",
                "type",
                "length",
                "value",
                "data",
                "payload",
                "info",
                "id",
                "name",
                "description",
            ]

            for field in fields_to_check:
                if hasattr(tlv, field):
                    value = getattr(tlv, field)
                    if value is not None:
                        # Format the value appropriately
                        if isinstance(value, bytes):
                            if len(value) <= 32:
                                # Short binary data - show as hex
                                tlv_data[field] = value.hex()
                            else:
                                # Long binary data - truncate
                                tlv_data[field] = f"{value[:32].hex()}... ({len(value)} bytes)"
                        elif isinstance(value, (int, str, float)):
                            tlv_data[field] = value
                        else:
                            tlv_data[field] = str(value)

            # Also show all fields for debugging
            if self.debug:
                all_fields = [attr for attr in dir(tlv) if not attr.startswith("_")]
                tlv_data["all_fields"] = ", ".join(all_fields[:10])  # First 10 fields

            return {tlv_type: tlv_data}

        except Exception as e:
            self.logger.debug(f"Error parsing unknown TLV: {e}")
            return None

    def _filter_industrial_devices(self, devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter devices that appear to be industrial/automation related"""
        industrial_devices = []

        industrial_keywords = [
            "profinet",
            "ethernetip",
            "modbus",
            "siemens",
            "schneider",
            "rockwell",
            "allen-bradley",
            "phoenix",
            "beckhoff",
            "wago",
            "industrial",
            "automation",
            "plc",
            "hmi",
            "scada",
        ]

        for device in devices:
            # Devices already contains LLDPDevice objects

            # Check system description and name for industrial keywords
            text_to_check = (
                device.system_description.lower()
                + " "
                + device.system_name.lower()
                + " "
                + device.port_description.lower()
            )

            if any(keyword in text_to_check for keyword in industrial_keywords):
                industrial_devices.append(device)
                continue

            # Check for industrial OUIs
            mac_parts = device.mac_address.split(":")
            if len(mac_parts) >= 3:
                vendor = lookup_mac_vendor(device.mac_address)
                if (
                    vendor
                    and vendor != "Unknown"
                    and any(keyword in vendor.lower() for keyword in industrial_keywords)
                ):
                    industrial_devices.append(device)

        return industrial_devices

    def _analyze_security(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze security implications of discovered devices"""
        analysis = SecurityAnalyzer.assess_protocol_security(
            {
                "authentication": False,  # LLDP has no authentication
                "authorization": False,  # No authorization
                "encryption": False,  # Clear text protocol
                "integrity_check": False,  # No integrity checking
                "access_control": False,  # Broadcast protocol
            }
        )

        # Add LLDP specific findings (informational, not vulnerabilities)
        analysis["findings"] = []

        device_count = len(results.get("devices", []))
        if device_count > 0:
            analysis["findings"].append(
                f"Found {device_count} devices broadcasting LLDP information"
            )

        industrial_count = len(results.get("industrial_devices", []))
        if industrial_count > 0:
            analysis["findings"].append(
                f"Identified {industrial_count} industrial/automation devices"
            )

        # Check for information disclosure
        mgmt_addr_count = 0
        for device in results.get("devices", []):
            # Devices already contains LLDPDevice objects
            if device.management_addresses:
                mgmt_addr_count += 1

        if mgmt_addr_count > 0:
            analysis["findings"].append(
                f"Found {mgmt_addr_count} devices with management addresses"
            )

        return analysis

    def _report_findings(self, results: Dict[str, Any]) -> None:
        """Report scanner findings"""
        # Skip detailed output when used as sub-scanner
        if self.quiet:
            return

        # Report discovered devices
        for device in results.get("devices", []):
            # Devices already contains LLDPDevice objects
            vendor = lookup_mac_vendor(device.mac_address)

            # Report host with comprehensive info for each management address
            for mgmt_addr in device.management_addresses:
                self.report_host_info(
                    mgmt_addr,
                    vendor=vendor if vendor != "Unknown" else None,
                    device_name=device.system_name or None,
                    mac_address=device.mac_address,
                    capabilities=device.capabilities if device.capabilities else None,
                    system_description=device.system_description or None,
                )

            # Display detailed device information
            self.logger.display(f"\n{'=' * 60}")
            self.logger.display(f"LLDP Device: {device.mac_address}")
            self.logger.display(f"{'=' * 60}")

            # Always show these fields even if empty
            self.logger.display(f"Chassis ID:         {device.chassis_id or 'Not provided'}")
            self.logger.display(f"Port ID:            {device.port_id or 'Not provided'}")
            self.logger.display(f"System Name:        {device.system_name or 'Not provided'}")
            self.logger.display(
                f"System Description: {device.system_description or 'Not provided'}"
            )
            self.logger.display(f"Port Description:   {device.port_description or 'Not provided'}")

            # MAC vendor (already looked up above)
            if vendor != "Unknown":
                self.logger.display(f"MAC Vendor:         {vendor}")

            # Management addresses
            if device.management_addresses:
                self.logger.display(f"Management IPs:     {', '.join(device.management_addresses)}")

            # Capabilities
            if device.capabilities:
                self.logger.display(f"Capabilities:       {', '.join(device.capabilities)}")

            # Organization specific info (PROFINET, etc.)
            if device.organization_specific:
                self.logger.display("Organization Specific:")
                for org, data in device.organization_specific.items():
                    self.logger.display(f"  {org}: {data}")

            self.logger.display(f"TTL:                {device.ttl} seconds")
            self.logger.display(f"First Seen:         {device.first_seen}")
            self.logger.display(f"Last Seen:          {device.last_seen}")

        # Report security analysis as informational findings
        security_analysis = results.get("security_analysis", {})
        if security_analysis.get("findings"):
            self.logger.display("LLDP Analysis Summary:")
            for finding in security_analysis.get("findings", []):
                self.logger.display(f"  - {finding}")


class LLDPPassiveListener:
    """Passive LLDP traffic listener.

    Listens for LLDP frames on multicast MAC 01:80:c2:00:00:0e to discover:
    - Network infrastructure devices (switches, routers)
    - System names, descriptions, and capabilities
    - Port information and management addresses
    - PROFINET and industrial device information

    Note: This class uses custom __init__ due to LLDP's special scapy loading requirements,
    but still provides the same interface as PassiveListenerBase.

    Usage:
        # Live capture
        listener = LLDPPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        # Testing - feed packets directly
        listener = LLDPPassiveListener(interface="eth0")
        listener.feed_packet(mock_lldp_packet)
    """

    PROTOCOL_NAME = "lldp-passive"
    BPF_FILTER = f"ether dst {LLDP_MULTICAST_MAC} and ether proto 0x88cc"

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
    ):
        from .core import validate_interface, validate_timeout

        self.interface = validate_interface(interface)

        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, Any] = {}
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, Any]:
        """Run discovery via live capture."""
        return self._live_capture()

    def _live_capture(self) -> Dict[str, Any]:
        """Capture LLDP from live interface."""
        if not _scapy.is_available:
            return {}
        cls = _load_scapy_classes()
        scapy = _scapy()
        conf = scapy.all.conf
        conf.verb = 0
        sniffer = cls["AsyncSniffer"](
            iface=self.interface,
            filter=self.BPF_FILTER,
            prn=self._safe_process_packet,
            store=False,
        )

        sniffer.start()
        sleep(self.timeout)
        sniffer.stop()

        return self.discovered_devices

    def _safe_process_packet(self, packet) -> None:
        """Wrapper with error handling."""
        try:
            self.process_packet(packet)
        except Exception as e:
            logger.debug(f"process_packet failed: {e}")

    def feed_packet(self, packet) -> None:
        """Feed a single packet for testing."""
        self._safe_process_packet(packet)

    def feed_packets(self, packets) -> Dict[str, Any]:
        """Feed multiple packets and return discovered devices."""
        for pkt in packets:
            self._safe_process_packet(pkt)
        return self.discovered_devices

    def process_packet(self, packet) -> None:
        """Process captured LLDP packet."""
        _load_scapy_classes()
        Ether = _scapy_classes["Ether"]
        LLDPDU = _scapy_classes["LLDPDU"]

        if not packet.haslayer(Ether):
            return

        # Check for LLDP ethertype
        if packet[Ether].type != LLDP_ETHERTYPE:
            return

        if not packet.haslayer(LLDPDU):
            return

        src_mac = packet[Ether].src

        with self._lock:
            if src_mac not in self.discovered_devices:
                from .core import DiscoveredDevice

                device = DiscoveredDevice(
                    mac_address=src_mac,
                    ip_addresses=[],
                    name="",
                    manufacturer="",
                    model="",
                    device_type="Network Device",
                    discovered_by=["lldp-passive"],
                    first_seen=datetime.now().isoformat(),
                    last_seen=datetime.now().isoformat(),
                )

                # Initialize LLDP-specific data
                device.lldp_data = {
                    "chassis_id": "",
                    "port_id": "",
                    "system_name": "",
                    "system_description": "",
                    "port_description": "",
                    "capabilities": [],
                    "management_addresses": [],
                    "ttl": 0,
                }

                self.discovered_devices[src_mac] = device
            else:
                device = self.discovered_devices[src_mac]
                device.last_seen = datetime.now().isoformat()

            # Process LLDP TLVs
            self._process_tlvs(device, packet[_scapy_classes["LLDPDU"]])

    def _process_tlvs(self, device, lldp_layer) -> None:
        """Process LLDP TLV chain."""
        current_tlv = lldp_layer
        tlv_count = 0

        while current_tlv and tlv_count < 50:
            tlv_count += 1
            self._process_tlv(device, current_tlv)

            if hasattr(current_tlv, "payload") and current_tlv.payload:
                current_tlv = current_tlv.payload
            else:
                break

    def _process_tlv(self, device, tlv) -> None:
        """Process individual LLDP TLV."""
        try:
            if isinstance(tlv, _scapy_classes["LLDPDUChassisID"]):
                chassis_id = self._format_id(tlv, "id", "chassis_id", tlv.subtype == 4)
                device.lldp_data["chassis_id"] = chassis_id

            elif isinstance(tlv, _scapy_classes["LLDPDUPortID"]):
                port_id = self._format_id(tlv, "id", "port_id", tlv.subtype == 3)
                device.lldp_data["port_id"] = port_id

            elif isinstance(tlv, _scapy_classes["LLDPDUTimeToLive"]):
                device.lldp_data["ttl"] = tlv.ttl

            elif isinstance(tlv, _scapy_classes["LLDPDUSystemName"]):
                name = self._get_string_field(tlv, ["system_name", "name"])
                device.lldp_data["system_name"] = name
                device.name = name

            elif isinstance(tlv, _scapy_classes["LLDPDUSystemDescription"]):
                desc = self._get_string_field(tlv, ["system_description", "description"])
                device.lldp_data["system_description"] = desc
                device.description = desc

            elif isinstance(tlv, _scapy_classes["LLDPDUPortDescription"]):
                port_desc = self._get_string_field(tlv, ["port_description", "description"])
                device.lldp_data["port_description"] = port_desc

            elif isinstance(tlv, _scapy_classes["LLDPDUSystemCapabilities"]):
                caps = self._parse_capabilities(tlv)
                device.lldp_data["capabilities"] = caps
                if caps:
                    device.device_type = f"Network Device ({', '.join(caps)})"

            elif isinstance(tlv, _scapy_classes["LLDPDUManagementAddress"]):
                mgmt_addr = self._parse_management_address(tlv)
                if mgmt_addr and mgmt_addr not in device.lldp_data["management_addresses"]:
                    device.lldp_data["management_addresses"].append(mgmt_addr)
                    if mgmt_addr not in device.ip_addresses:
                        device.ip_addresses.append(mgmt_addr)

        except Exception as e:
            logger.debug(f"Operation failed: {e}")

    def _format_id(self, tlv, field1: str, field2: str, is_mac: bool) -> str:
        """Format chassis/port ID."""
        try:
            data = getattr(tlv, field1, None) or getattr(tlv, field2, None)
            if data:
                if is_mac:
                    return ":".join(f"{b:02x}" for b in data)
                elif isinstance(data, bytes):
                    return data.decode("utf-8", errors="ignore")
                return str(data)
        except Exception as e:
            logger.debug(f"LLDP: TLV chassis/port ID field extract failed: {e}")
        return ""

    def _get_string_field(self, tlv, field_names: list) -> str:
        """Get string field from TLV."""
        for name in field_names:
            if hasattr(tlv, name):
                val = getattr(tlv, name)
                if isinstance(val, bytes):
                    return val.decode("utf-8", errors="ignore")
                return str(val)
        return ""

    def _parse_capabilities(self, tlv) -> list:
        """Parse system capabilities."""
        caps = []
        cap_map = [
            ("mac_bridge_enabled", "Bridge"),
            ("station_only_enabled", "Station"),
            ("repeater_enabled", "Repeater"),
            ("router_enabled", "Router"),
            ("wlan_access_point_enabled", "WLAN AP"),
            ("telephone_enabled", "Telephone"),
        ]
        for attr, name in cap_map:
            if getattr(tlv, attr, False):
                caps.append(name)
        return caps

    def _parse_management_address(self, tlv) -> Optional[str]:
        """Parse management address using socket for standard formatting."""
        try:
            import socket as _socket

            if hasattr(tlv, "management_address"):
                addr = tlv.management_address
                if isinstance(addr, bytes):
                    if len(addr) == 4:  # IPv4
                        return _socket.inet_ntoa(addr)
                    elif len(addr) == 16:  # IPv6
                        return _socket.inet_ntop(_socket.AF_INET6, addr)
                return str(addr)
        except Exception as e:
            logger.debug(f"_socket address formatting failed: {e}")
        return None

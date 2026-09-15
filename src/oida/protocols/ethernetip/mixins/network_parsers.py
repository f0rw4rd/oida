"""
EtherNet/IP Network Parsers Mixin

Handles parsing of network-related CIP objects:
- TCP/IP Interface (0xF5) - IP config, hostname, DNS
- Ethernet Link (0xF6) - MAC, speed, duplex
- Assembly (0x04) - I/O connection points
- Program Name (0x64) - Rockwell Logix project name
- Wall Clock Time (0x8B) - Controller date/time
- Time Sync (0x43) - IEEE 1588 PTP support
"""

from __future__ import annotations

import struct
from typing import Any, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class NetworkParsersMixin(_ScannerBase):
    """Mixin providing network-related CIP object parsers."""

    def _parse_tcp_ip_interface(self, conn: Any) -> Dict[str, Any]:
        """
        Parse TCP/IP Interface object (0xF5) attributes.

        Extracts network configuration including IP, subnet, gateway, DNS, hostname.
        Reference: CIP Vol 2, Section 5-3
        """
        tcp_ip_info = {
            "object_id": 0xF5,
            "object_name": "TCP/IP Interface",
            "accessible": False,
            "status": None,
            "config_control": None,
            "ip_address": None,
            "network_mask": None,
            "gateway": None,
            "dns_primary": None,
            "dns_secondary": None,
            "domain_name": None,
            "hostname": None,
            "encap_timeout": None,
        }

        self.logger.display("Parsing TCP/IP Interface (0xF5)...")

        # Attribute mapping: ID -> name
        attrs_to_read = [
            (1, "status"),
            (3, "config_control"),
            (5, "interface_config"),
            (6, "hostname"),
            (13, "encap_timeout"),
        ]

        for attr_id, attr_name in attrs_to_read:
            try:
                # Use pycomm3 generic_message for CIP attribute reads
                data = self._read_cip_attribute(conn, 0xF5, 1, attr_id)

                if data is not None:
                    tcp_ip_info["accessible"] = True

                    if attr_name == "status":
                        if len(data) >= 4:
                            value = struct.unpack("<I", data[:4])[0]
                            tcp_ip_info["status"] = value
                            self.logger.debug(f"  Status: 0x{value:08X}")
                    elif attr_name == "config_control":
                        if len(data) >= 4:
                            value = struct.unpack("<I", data[:4])[0]
                            tcp_ip_info["config_control"] = value
                            # Bits 0-3 = Configuration Method (CIP Vol 2, Sec 5-3.2.2.1),
                            # not a single DHCP bit. Matches cli_runner._fetch_network_config.
                            config_method = value & 0x0F
                            config_methods = {0: "Static", 1: "BOOTP", 2: "DHCP"}
                            config_str = config_methods.get(
                                config_method, f"Unknown ({config_method})"
                            )
                            self.logger.display(f"  Config: {config_str}")
                    elif attr_name == "interface_config":
                        # Complex structure: IP, subnet, gateway, DNS1, DNS2, domain
                        self._parse_interface_config(tcp_ip_info, data)
                    elif attr_name == "hostname":
                        # CIP Short String: 2-byte length (UINT) + string data
                        if len(data) >= 2:
                            str_len = struct.unpack("<H", data[:2])[0]
                            if len(data) >= 2 + str_len:
                                hostname = data[2 : 2 + str_len].decode("ascii", errors="replace")
                                tcp_ip_info["hostname"] = hostname
                                if hostname:
                                    self.logger.display(f"  Hostname: {hostname}")
                    elif attr_name == "encap_timeout":
                        if len(data) >= 2:
                            value = struct.unpack("<H", data[:2])[0]
                            tcp_ip_info["encap_timeout"] = value
                            self.logger.debug(f"  Encap Timeout: {value}s")

            except Exception as e:
                self.logger.debug(f"Error reading TCP/IP attr {attr_id}: {e}")

        if tcp_ip_info["accessible"]:
            # Display summary
            if tcp_ip_info.get("ip_address"):
                self.logger.display(
                    f"  IP: {tcp_ip_info['ip_address']}/{tcp_ip_info.get('network_mask', '?')}"
                )
            if tcp_ip_info.get("gateway"):
                self.logger.display(f"  Gateway: {tcp_ip_info['gateway']}")
        else:
            self.logger.display("  TCP/IP Interface: Not accessible")

        return tcp_ip_info

    def _parse_interface_config(self, tcp_ip_info: Dict[str, Any], value: bytes) -> None:
        """Parse the interface configuration structure (attr 5).

        ``value`` is the raw bytes returned by ``_read_cip_attribute``.
        """
        try:
            # Structure: IP(4) + Subnet(4) + Gateway(4) + DNS1(4) + DNS2(4) + Domain(string)
            # CIP stores IP addresses in little-endian format (reversed byte order)
            if len(value) >= 20:
                # Reverse bytes to get correct IP address order
                tcp_ip_info["ip_address"] = f"{value[3]}.{value[2]}.{value[1]}.{value[0]}"
                tcp_ip_info["network_mask"] = f"{value[7]}.{value[6]}.{value[5]}.{value[4]}"
                tcp_ip_info["gateway"] = f"{value[11]}.{value[10]}.{value[9]}.{value[8]}"
                tcp_ip_info["dns_primary"] = f"{value[15]}.{value[14]}.{value[13]}.{value[12]}"
                tcp_ip_info["dns_secondary"] = f"{value[19]}.{value[18]}.{value[17]}.{value[16]}"
                if len(value) > 20:
                    tcp_ip_info["domain_name"] = (
                        value[20:].decode("utf-8", errors="ignore").rstrip("\x00")
                    )
        except Exception as e:
            self.logger.debug(f"Error parsing interface config: {e}")

    def _parse_ethernet_link(self, conn: Any) -> Dict[str, Any]:
        """
        Parse Ethernet Link object (0xF6) attributes.

        Extracts physical interface info: MAC, speed, duplex, counters.
        Reference: CIP Vol 2, Section 5-4
        """
        eth_link_info = {
            "object_id": 0xF6,
            "object_name": "Ethernet Link",
            "accessible": False,
            "interface_speed": None,
            "interface_flags": None,
            "physical_address": None,
            "interface_counters": None,
            "interface_type": None,
            "link_status": None,
            "duplex": None,
        }

        self.logger.display("Parsing Ethernet Link (0xF6)...")

        # Attribute mapping
        attrs_to_read = [
            (1, "interface_speed"),
            (2, "interface_flags"),
            (3, "physical_address"),
            (4, "interface_counters"),
            (7, "interface_type"),
        ]

        for attr_id, attr_name in attrs_to_read:
            try:
                # Use pycomm3 generic_message for CIP attribute reads
                data = self._read_cip_attribute(conn, 0xF6, 1, attr_id)

                if data is not None:
                    eth_link_info["accessible"] = True

                    if attr_name == "interface_speed":
                        if len(data) >= 4:
                            value = struct.unpack("<I", data[:4])[0]
                            eth_link_info["interface_speed"] = value
                            self.logger.display(f"  Speed: {value} Mbps")
                    elif attr_name == "interface_flags":
                        if len(data) >= 4:
                            value = struct.unpack("<I", data[:4])[0]
                            eth_link_info["interface_flags"] = value
                            # Bit 0: Link status, Bit 1: Full duplex
                            eth_link_info["link_status"] = "Up" if (value & 0x01) else "Down"
                            eth_link_info["duplex"] = "Full" if (value & 0x02) else "Half"
                            self.logger.display(
                                f"  Link: {eth_link_info['link_status']}, Duplex: {eth_link_info['duplex']}"
                            )
                    elif attr_name == "physical_address":
                        mac = self._parse_mac_address(data)
                        eth_link_info["physical_address"] = mac
                        if mac:
                            self.logger.display(f"  MAC: {mac}")
                    elif attr_name == "interface_counters":
                        eth_link_info["interface_counters"] = data.hex() if data else None
                        self.logger.debug(f"  Counters: {data.hex() if data else 'N/A'}")
                    elif attr_name == "interface_type":
                        if len(data) >= 1:
                            eth_link_info["interface_type"] = data[0]
                            self.logger.debug(f"  Type: {data[0]}")

            except Exception as e:
                self.logger.debug(f"Error reading Ethernet Link attr {attr_id}: {e}")

        if not eth_link_info["accessible"]:
            self.logger.display("  Ethernet Link: Not accessible")

        return eth_link_info

    def _parse_mac_address(self, value: bytes) -> Optional[str]:
        """Parse a MAC address from the raw 6-byte Physical Address attribute."""
        try:
            if value and len(value) >= 6:
                return ":".join(f"{b:02X}" for b in value[:6])
        except Exception as e:
            self.logger.debug(f"parse mac address failed: {e}")
        return None

    def _parse_assembly_instances(self, conn: Any) -> Dict[str, Any]:
        """
        Parse Assembly object (0x04) instances.

        Enumerates I/O connection points and their sizes.
        Reference: CIP Vol 1, Section 5-5
        """
        assembly_info: Dict[str, Any] = {
            "object_id": 0x04,
            "object_name": "Assembly",
            "accessible": False,
            "instances": {},
            "input_assemblies": [],
            "output_assemblies": [],
        }

        self.logger.display("Scanning Assembly instances (0x04)...")

        found_count = 0

        # Common assembly instance ranges: 1-10 (standard), 100-110 (vendor), 150-160 (config)
        instance_ranges = list(range(1, 11)) + list(range(100, 111)) + list(range(150, 161))

        for instance_id in instance_ranges:
            try:
                # Read attribute 4 (size) using unified method
                data = self._read_cip_attribute(conn, 0x04, instance_id, 4)

                if data is not None:
                    # Parse size (usually UINT)
                    if len(data) >= 2:
                        size = struct.unpack("<H", data[:2])[0]
                    elif len(data) >= 1:
                        size = data[0]
                    else:
                        size = 0

                    assembly_info["accessible"] = True
                    found_count += 1

                    instance_data = {
                        "instance_id": instance_id,
                        "size": size,
                        "type": "unknown",
                    }

                    # Classify based on common patterns
                    if instance_id < 100:
                        if instance_id % 2 == 0:
                            instance_data["type"] = "output"
                            assembly_info["output_assemblies"].append(instance_id)
                        else:
                            instance_data["type"] = "input"
                            assembly_info["input_assemblies"].append(instance_id)
                    elif instance_id >= 150:
                        instance_data["type"] = "config"

                    assembly_info["instances"][instance_id] = instance_data
                    self.logger.debug(
                        f"  Assembly {instance_id}: {size} bytes ({instance_data['type']})"
                    )

            except Exception as e:
                self.logger.debug(f"parse assembly instances failed: {e}")

        if found_count > 0:
            self.logger.display(f"  Found {found_count} assembly instances")
            self.logger.display(
                f"  Inputs: {assembly_info['input_assemblies']}, Outputs: {assembly_info['output_assemblies']}"
            )
        else:
            self.logger.display("  Assembly: No instances found")

        return assembly_info

    def _parse_program_name(self, conn: Any) -> Dict[str, Any]:
        """
        Parse Program Name object (0x64) - Rockwell Logix specific.

        Returns the name of the controller project loaded in the PLC.
        """
        program_info = {
            "object_id": 0x64,
            "object_name": "Program Name",
            "accessible": False,
            "program_name": None,
        }

        try:
            # Attribute 1 contains SHORT_STRING with program name
            data = self._read_cip_attribute(conn, 0x64, 1, 1)
            if data and len(data) > 1:
                program_info["accessible"] = True
                # SHORT_STRING format: 1-byte length + string
                str_len = data[0]
                if len(data) >= 1 + str_len:
                    name = data[1 : 1 + str_len].decode("ascii", errors="replace")
                    program_info["program_name"] = name
                    self.logger.display(f"Program Name: {name}")
        except Exception as e:
            self.logger.debug(f"Error reading Program Name: {e}")

        return program_info

    def _parse_wall_clock_time(self, conn: Any) -> Dict[str, Any]:
        """
        Parse Wall Clock Time object (0x8B) - Rockwell Logix specific.

        Returns the controller's current date/time.
        """
        time_info = {
            "object_id": 0x8B,
            "object_name": "Wall Clock Time",
            "accessible": False,
            "datetime": None,
            "datetime_str": None,
            "microseconds": None,
        }

        try:
            # Attribute 1 contains DATE_AND_TIME (8-byte microseconds since 1972-01-01)
            data = self._read_cip_attribute(conn, 0x8B, 1, 1)
            if data and len(data) >= 8:
                time_info["accessible"] = True
                usecs = struct.unpack("<Q", data[:8])[0]
                time_info["microseconds"] = usecs

                # Convert to datetime (CIP epoch is 1972-01-01)
                from datetime import datetime, timedelta

                cip_epoch = datetime(1972, 1, 1)
                dt = cip_epoch + timedelta(microseconds=usecs)
                time_info["datetime"] = dt.isoformat()
                time_info["datetime_str"] = dt.strftime("%Y-%m-%d %H:%M:%S")
                self.logger.display(f"Wall Clock Time: {time_info['datetime_str']}")
        except Exception as e:
            self.logger.debug(f"Error reading Wall Clock Time: {e}")

        return time_info

    def _parse_time_sync(self, conn: Any) -> Dict[str, Any]:
        """
        Parse Time Sync object (0x43) - IEEE 1588 PTP support.

        Returns PTP synchronization status and configuration.
        """
        time_sync_info = {
            "object_id": 0x43,
            "object_name": "Time Sync",
            "accessible": False,
            "ptp_enable": None,
            "clock_type": None,
            "offset_from_master": None,
        }

        try:
            # Attribute 1: PTP Enable
            data = self._read_cip_attribute(conn, 0x43, 1, 1)
            if data and len(data) >= 1:
                time_sync_info["accessible"] = True
                time_sync_info["ptp_enable"] = bool(data[0])

            # Attribute 3: Clock Type
            data = self._read_cip_attribute(conn, 0x43, 1, 3)
            if data and len(data) >= 2:
                clock_type = struct.unpack("<H", data[:2])[0]
                clock_types = {
                    0: "Ordinary Clock",
                    1: "Boundary Clock",
                    2: "Peer-to-Peer Transparent Clock",
                    3: "End-to-End Transparent Clock",
                    4: "Management Node",
                }
                time_sync_info["clock_type"] = clock_types.get(
                    clock_type, f"Unknown ({clock_type})"
                )

            if time_sync_info["accessible"]:
                ptp_status = "Enabled" if time_sync_info["ptp_enable"] else "Disabled"
                self.logger.display(f"Time Sync (PTP): {ptp_status}")
                if time_sync_info["clock_type"]:
                    self.logger.debug(f"Clock Type: {time_sync_info['clock_type']}")
        except Exception as e:
            self.logger.debug(f"Error reading Time Sync: {e}")

        return time_sync_info

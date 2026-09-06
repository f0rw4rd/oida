"""
DHCP (Dynamic Host Configuration Protocol) passive listener.

DHCP is used for automatic IP address assignment on networks.

DHCP uses:
- UDP port 67 (server) / port 68 (client)
- Broadcast communication
- BOOTP message format with DHCP options

Message types (option 53):
- 1: DISCOVER - Client looking for DHCP servers
- 2: OFFER - Server offering IP address
- 3: REQUEST - Client requesting offered IP
- 4: DECLINE - Client declining offer
- 5: ACK - Server confirming lease
- 6: NAK - Server denying request
- 7: RELEASE - Client releasing IP
- 8: INFORM - Client requesting config only

Useful for discovering:
- Client hostnames (option 12) and vendor classes (option 60)
- Client identifiers (option 61) - string or MAC-based
- DHCP servers and their configuration
- IP address assignments and lease times
- Network config (DNS, gateway, domain, NTP, WPAD)
- PXE/iPXE boot (TFTP server, boot file, arch, UUID)
- Relay agent info (option 82) - circuit/remote ID, link selection
- Vendor-specific data (option 43) - ICS device fingerprinting
- Vendor-identifying info (option 125/TR-111) - OUI, serial, product class
- Classless static routes (option 121)

tshark fields used:
- dhcp.hw.mac_addr, dhcp.option.hostname, dhcp.option.vendor_class_id
- dhcp.ip.your, dhcp.ip.server, dhcp.option.dhcp_server_id
- dhcp.option.subnet_mask, dhcp.option.router, dhcp.option.domain_name_server
- dhcp.option.domain_name, dhcp.option.ip_address_lease_time
- dhcp.option.requested_ip_address, dhcp.id
- dhcp.fqdn.name, dhcp.client_id.*, dhcp.client_id_undef
- dhcp.file, dhcp.server, dhcp.option.tftp_server_name
- dhcp.option.boot_file_name, dhcp.option.client_system_architecture
- dhcp.option.agent_information_option.agent_circuit_id (option 82:1)
- dhcp.option.agent_information_option.agent_remote_id (option 82:2)
- dhcp.option.agent_information_option.link_selection (option 82:5)
- dhcp.option.vendor.value, dhcp.vendor_specific_options (option 43)
- dhcp.option.vi.enterprise, dhcp.option.vi.tr111.* (option 125)
- dhcp.option.classless_static_route (option 121)
"""

from datetime import datetime
from typing import Any, Dict, List

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor, normalize_mac

# DHCP message type names
DHCP_MSG_TYPES = {
    "1": "DISCOVER",
    "2": "OFFER",
    "3": "REQUEST",
    "4": "DECLINE",
    "5": "ACK",
    "6": "NAK",
    "7": "RELEASE",
    "8": "INFORM",
}


class DHCPPassiveListener(PySharkListenerBase):
    """Passive DHCP traffic listener using PyShark.

    Listens for DHCP traffic to discover:
    - Client hostnames and vendor classes
    - DHCP servers and their configuration
    - IP address assignments (leases)
    - Network infrastructure (DNS, gateway, domain)

    Usage:
        # Live capture
        listener = DHCPPassiveListener(interface="eth0", timeout=30)
        devices = listener.scan()

        # Testing - feed packets directly
        listener = DHCPPassiveListener(interface="eth0")
        listener.feed_packet(mock_dhcp_packet)
    """

    PROTOCOL_NAME = "dhcp"
    DISPLAY_FILTER = "dhcp || bootp"
    REQUIRED_LAYERS = ("dhcp",)
    PROTOCOL_COLUMNS = (
        "message",
        "hostname",
        "client_id",
        "client_ip",
        "subnet_gw",
        "domain",
        "boot_pxe",
        "relay_vendor",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 30,
        nxc_logger=None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.dhcp_servers: Dict[str, Dict] = {}  # server_ip -> info

    def should_process_packet(self, packet) -> bool:
        """Check if packet has DHCP layer.

        DHCP may appear as 'dhcp' or 'bootp' layer in PyShark depending
        on the tshark version.
        """
        return hasattr(packet, "dhcp") or hasattr(packet, "bootp")

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format DHCP protocol-specific columns."""
        d = ix.details
        msg_name = d.get("msg_name", "")
        if not msg_name:
            msg_name = "?"
            self.logger.debug(f"Missing msg_name in DHCP interaction from {ix.src_ip}")
        hostname = d.get("hostname", "") or "-"
        client_id = d.get("client_id", "")
        client_ip = d.get("client_ip", "") or "-"
        # Subnet/GW: combine subnet mask + router for network overview
        subnet = d.get("subnet_mask", "")
        router = d.get("router", "")
        if subnet and router:
            subnet_gw = f"{subnet} gw {router}"
        elif subnet:
            subnet_gw = subnet
        elif router:
            subnet_gw = f"gw {router}"
        else:
            subnet_gw = "-"
        # Domain: combine domain name + vendor class
        domain = d.get("domain_name", "")
        vendor_class = d.get("vendor_class", "")
        if domain and vendor_class:
            domain_str = f"{domain} ({vendor_class})"
        elif domain:
            domain_str = domain
        elif vendor_class:
            domain_str = vendor_class
        else:
            domain_str = "-"
        # Boot/PXE info
        boot_parts: List[str] = []
        boot_file = d.get("boot_file", "")
        if boot_file:
            boot_parts.append(boot_file)
        tftp = d.get("tftp_server", "") or d.get("next_server", "")
        if tftp:
            boot_parts.append(f"tftp={tftp}")
        arch = d.get("client_arch", "")
        if arch:
            boot_parts.append(f"arch={arch}")
        uuid = d.get("client_uuid", "")
        if uuid:
            boot_parts.append(f"uuid={uuid}")
        boot_str = " ".join(boot_parts)

        # Relay/Vendor info (option 82, 43, 125)
        rv_parts: List[str] = []
        circuit_id = d.get("relay_circuit_id", "")
        if circuit_id:
            rv_parts.append(f"cid={circuit_id}")
        remote_id = d.get("relay_remote_id", "")
        if remote_id:
            rv_parts.append(f"rid={remote_id}")
        link_sel = d.get("relay_link_selection", "")
        if link_sel:
            rv_parts.append(f"link={link_sel}")
        vi_product = d.get("vi_tr111_product", "")
        if vi_product:
            rv_parts.append(vi_product)
        vi_serial = d.get("vi_tr111_serial", "")
        if vi_serial:
            rv_parts.append(f"sn={vi_serial}")
        vi_enterprise = d.get("vi_enterprise", "")
        if vi_enterprise and not vi_product:
            rv_parts.append(f"ent={vi_enterprise}")
        vendor_spec = d.get("vendor_specific", "")
        if vendor_spec and not rv_parts:
            # Show raw vendor-specific only if nothing else parsed
            rv_parts.append(vendor_spec)
        rv_str = " ".join(rv_parts)

        return [
            msg_name,
            hostname,
            client_id,
            client_ip,
            subnet_gw,
            domain_str,
            boot_str,
            rv_str,
        ]

    def process_packet(self, packet) -> None:
        """Process captured DHCP packet using PyShark."""
        # Get the DHCP layer (may be 'dhcp' or 'bootp')
        dhcp = None
        if hasattr(packet, "dhcp"):
            dhcp = packet.dhcp
        elif hasattr(packet, "bootp"):
            dhcp = packet.bootp

        if dhcp is None:
            return

        # Get IP info
        src_ip, dst_ip = self.get_ip_info(packet)
        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)

        # Extract DHCP fields
        msg_type_raw = str(self.get_field(dhcp, "option_dhcp", "") or "")
        if not msg_type_raw:
            msg_type_raw = str(self.get_field(dhcp, "option_message_type", "") or "")
        msg_name = DHCP_MSG_TYPES.get(msg_type_raw, f"Type({msg_type_raw})")

        # Client MAC address
        client_mac = str(self.get_field(dhcp, "hw_mac_addr", "") or "")
        # EK mode may return duplicate MACs (chaddr + option 61) as comma-separated
        if "," in client_mac:
            client_mac = client_mac.split(",")[0].strip()
        if client_mac:
            client_mac = normalize_mac(client_mac)

        # Client hostname (option 12)
        hostname = str(self.get_field(dhcp, "option_hostname", "") or "")

        # Vendor class (option 60)
        vendor_class = str(self.get_field(dhcp, "option_vendor_class_id", "") or "")

        # IP addresses
        your_ip = str(self.get_field(dhcp, "ip_your", "") or "")
        if your_ip == "0.0.0.0":
            your_ip = ""
        server_ip_field = str(self.get_field(dhcp, "option_dhcp_server_id", "") or "")
        if not server_ip_field:
            server_ip_field = str(self.get_field(dhcp, "ip_server", "") or "")
        if server_ip_field == "0.0.0.0":
            server_ip_field = ""

        # Requested IP (option 50)
        requested_ip = str(self.get_field(dhcp, "option_requested_ip_address", "") or "")

        # The effective client IP is your_ip (from offer/ack) or requested_ip (from request)
        client_ip = your_ip or requested_ip

        # Network config (from server responses)
        subnet_mask = str(self.get_field(dhcp, "option_subnet_mask", "") or "")
        router = str(self.get_field(dhcp, "option_router", "") or "")
        dns_server = str(self.get_field(dhcp, "option_domain_name_server", "") or "")
        domain_name = str(self.get_field(dhcp, "option_domain_name", "") or "")
        lease_time = str(self.get_field(dhcp, "option_ip_address_lease_time", "") or "")

        # Transaction ID -- correlates DHCP exchange packets
        transaction_id = str(self.get_field(dhcp, "id", "") or "")

        # Additional useful options
        # Option 55: Parameter Request List (client OS fingerprint)
        param_list = str(self.get_field(dhcp, "option_request_list_item", "") or "")
        # Option 61: Client Identifier
        # EK mode: client_id_undef for string-type (hw-type 0),
        # client_id_link_layer_address_ether for MAC-type
        client_id = str(self.get_field(dhcp, "client_id_undef", "") or "")
        if not client_id:
            client_id = str(self.get_field(dhcp, "option_client_id", "") or "")
        # Option 81: Client FQDN (option-level)
        fqdn = str(self.get_field(dhcp, "option_fqdn_name", "") or "")
        # Option 82: Relay Agent Info (parsed suboptions)
        relay_agent = str(self.get_field(dhcp, "option_agent_information_option", "") or "")
        relay_circuit_id = str(
            self.get_field(dhcp, "option_agent_information_option_agent_circuit_id", "") or ""
        )
        relay_remote_id = str(
            self.get_field(dhcp, "option_agent_information_option_agent_remote_id", "") or ""
        )
        relay_link_selection = str(
            self.get_field(dhcp, "option_agent_information_option_link_selection", "") or ""
        )
        # Option 119: Domain Search List
        domain_search = str(self.get_field(dhcp, "option_domain_search", "") or "")
        # Option 252: WPAD URL
        wpad = str(self.get_field(dhcp, "option_private_proxy_autodiscovery", "") or "")
        # Option 42: NTP server
        ntp_server = str(self.get_field(dhcp, "option_ntp_server", "") or "")

        # BOOTP / PXE / iPXE fields
        # Boot file name (BOOTP 'file' field, 128 bytes)
        boot_file = str(self.get_field(dhcp, "file", "") or "")
        # Next server (BOOTP 'siaddr' — TFTP server for boot file)
        next_server = str(self.get_field(dhcp, "ip_server", "") or "")
        if next_server == "0.0.0.0":
            next_server = ""
        # Server host name (BOOTP 'sname' field, 64 bytes)
        server_name = str(self.get_field(dhcp, "server", "") or "")
        # Option 66: TFTP Server Name (overrides sname)
        tftp_server = str(self.get_field(dhcp, "option_tftp_server_name", "") or "")
        # Option 67: Boot File Name (overrides 'file')
        boot_file_name = str(self.get_field(dhcp, "option_boot_file_name", "") or "")
        if boot_file_name:
            boot_file = boot_file_name
        # Option 93: Client System Architecture (PXE)
        client_arch = str(self.get_field(dhcp, "option_client_system_architecture", "") or "")
        # Option 97: Client Machine Identifier (UUID)
        client_uuid = str(self.get_field(dhcp, "client_id_uuid", "") or "")
        # BOOTP flag (dhcp.bootp — true when legacy BOOTP, no options)
        is_bootp = self.get_field(dhcp, "bootp", None)

        # Option 43: Vendor-Specific Information
        vendor_specific = str(self.get_field(dhcp, "option_vendor_value", "") or "")
        if not vendor_specific:
            vendor_specific = str(self.get_field(dhcp, "vendor_specific_options", "") or "")

        # Option 121: Classless Static Routes
        classless_routes = str(self.get_field(dhcp, "option_classless_static_route", "") or "")

        # Option 125: Vendor-Identifying Vendor-Specific
        vi_enterprise = str(self.get_field(dhcp, "option_vi_enterprise", "") or "")
        vi_tr111_oui = str(
            self.get_field(dhcp, "option_vi_tr111_device_manufacturer_oui", "") or ""
        )
        vi_tr111_serial = str(
            self.get_field(dhcp, "option_vi_tr111_device_serial_number", "") or ""
        )
        vi_tr111_product = str(
            self.get_field(dhcp, "option_vi_tr111_device_product_class", "") or ""
        )

        # FQDN parsed sub-fields (dhcp.fqdn.* -- separate from option-level)
        fqdn_name = str(self.get_field(dhcp, "fqdn_name", "") or "")
        fqdn_rcode1 = str(self.get_field(dhcp, "fqdn_rcode1", "") or "")
        fqdn_rcode2 = str(self.get_field(dhcp, "fqdn_rcode2", "") or "")

        # Client Identifier parsed sub-fields (dhcp.client_id.*)
        client_id_parsed = str(self.get_field(dhcp, "client_id", "") or "")
        client_id_iaid = str(self.get_field(dhcp, "client_id_iaid", "") or "")
        client_id_duid_ll_hw_type = str(self.get_field(dhcp, "client_id_duid_ll_hw_type", "") or "")
        client_id_link_layer_address = str(
            self.get_field(dhcp, "client_id_link_layer_address", "") or ""
        )

        # Use parsed FQDN name as fallback for hostname/fqdn when option-level is empty
        if not fqdn and fqdn_name:
            fqdn = fqdn_name

        # Record interaction
        now = datetime.now().isoformat()
        is_server_msg = msg_type_raw in ("2", "5", "6")
        direction = "response" if is_server_msg else "request"
        self._record_interaction(
            now,
            src_ip or "0.0.0.0",
            dst_ip or "255.255.255.255",
            direction,
            f"DHCP {msg_name}",
            {
                "client_mac": client_mac,
                "msg_type": msg_type_raw,
                "msg_name": msg_name,
                "hostname": hostname or fqdn,
                "vendor_class": vendor_class,
                "client_ip": client_ip,
                "server_ip": server_ip_field,
                "requested_ip": requested_ip,
                "subnet_mask": subnet_mask,
                "router": router,
                "dns_server": dns_server,
                "domain_name": domain_name,
                "lease_time": lease_time,
                "client_id": client_id,
                "fqdn": fqdn,
                "relay_agent": relay_agent,
                "domain_search": domain_search,
                "wpad": wpad,
                "ntp_server": ntp_server,
                "param_request_list": param_list,
                # Transaction ID
                "transaction_id": transaction_id,
                # FQDN parsed sub-fields
                "fqdn_name": fqdn_name,
                "fqdn_rcode1": fqdn_rcode1,
                "fqdn_rcode2": fqdn_rcode2,
                # Client ID parsed sub-fields
                "client_id_parsed": client_id_parsed,
                "client_id_iaid": client_id_iaid,
                "client_id_duid_ll_hw_type": client_id_duid_ll_hw_type,
                "client_id_link_layer_address": client_id_link_layer_address,
                # BOOTP / PXE / iPXE
                "boot_file": boot_file,
                "next_server": next_server,
                "server_name": server_name,
                "tftp_server": tftp_server,
                "client_arch": client_arch,
                "client_uuid": client_uuid,
                "is_bootp": bool(is_bootp),
                # Option 82: Relay Agent suboptions
                "relay_circuit_id": relay_circuit_id,
                "relay_remote_id": relay_remote_id,
                "relay_link_selection": relay_link_selection,
                # Option 43: Vendor-Specific
                "vendor_specific": vendor_specific,
                # Option 121: Classless Static Routes
                "classless_routes": classless_routes,
                # Option 125: Vendor-Identifying
                "vi_enterprise": vi_enterprise,
                "vi_tr111_oui": vi_tr111_oui,
                "vi_tr111_serial": vi_tr111_serial,
                "vi_tr111_product": vi_tr111_product,
            },
            f"DHCP {msg_name} mac={client_mac} host={hostname or fqdn} ip={client_ip}",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
        )

        # Process based on message type
        if is_server_msg:
            self._process_server_message(
                client_mac,
                client_ip,
                server_ip_field,
                msg_name,
                hostname,
                vendor_class,
                subnet_mask,
                router,
                dns_server,
                domain_name,
                lease_time,
            )
        else:
            self._process_client_message(
                client_mac,
                hostname,
                vendor_class,
                requested_ip,
                msg_name,
            )

    def _process_client_message(
        self,
        client_mac: str,
        hostname: str,
        vendor_class: str,
        requested_ip: str,
        msg_name: str,
    ) -> None:
        """Process DHCP client message (Discover/Request/Inform)."""
        if not client_mac:
            return

        device_key = f"dhcp:{client_mac}"
        mac_vendor = lookup_mac_vendor(client_mac) if client_mac else ""

        device, is_new = self._ensure_device(
            device_key,
            requested_ip if requested_ip else "",
            mac=client_mac,
            name=hostname,
            manufacturer=mac_vendor if mac_vendor and mac_vendor != "Unknown" else "",
        )
        if is_new:
            device.dhcp_data = {
                "hostname": hostname,
                "vendor_class": vendor_class,
                "requested_ip": requested_ip,
                "message_type": msg_name,
                "protocol": "DHCP/UDP",
            }
            self.logger.debug(
                f"DHCP: {client_mac} {msg_name} hostname={hostname} vendor={vendor_class}"
            )
        else:
            # Update hostname if we got a new one
            if hostname and not device.name:
                device.name = hostname
            if device.dhcp_data:
                if hostname:
                    device.dhcp_data["hostname"] = hostname
                if vendor_class:
                    device.dhcp_data["vendor_class"] = vendor_class

    def _process_server_message(
        self,
        client_mac: str,
        client_ip: str,
        server_ip: str,
        msg_name: str,
        hostname: str,
        vendor_class: str,
        subnet_mask: str,
        router: str,
        dns_server: str,
        domain_name: str,
        lease_time: str,
    ) -> None:
        """Process DHCP server message (Offer/ACK/NAK)."""
        # Track DHCP server
        if server_ip and is_valid_discovered_ip(server_ip):
            if server_ip not in self.dhcp_servers:
                self.dhcp_servers[server_ip] = {
                    "server_ip": server_ip,
                    "first_seen": datetime.now().isoformat(),
                    "offers": 0,
                    "acks": 0,
                }
                self.logger.debug(f"DHCP: Server detected at {server_ip}")

            if msg_name == "OFFER":
                self.dhcp_servers[server_ip]["offers"] = (
                    self.dhcp_servers[server_ip].get("offers", 0) + 1
                )
            elif msg_name == "ACK":
                self.dhcp_servers[server_ip]["acks"] = (
                    self.dhcp_servers[server_ip].get("acks", 0) + 1
                )

            # Add server as discovered device
            server_key = f"dhcp-server:{server_ip}"
            server_device, is_new = self._ensure_device(
                server_key,
                server_ip,
                device_type="DHCP Server",
            )
            if is_new:
                server_device.dhcp_data = {
                    "is_server": True,
                    "server_ip": server_ip,
                    "subnet_mask": subnet_mask,
                    "router": router,
                    "dns_server": dns_server,
                    "domain_name": domain_name,
                    "protocol": "DHCP/UDP",
                }

        # Update client device with assigned IP
        if client_mac:
            device_key = f"dhcp:{client_mac}"
            mac_vendor = lookup_mac_vendor(client_mac) if client_mac else ""
            device, is_new = self._ensure_device(
                device_key,
                client_ip if client_ip else "",
                mac=client_mac,
                name=hostname,
                manufacturer=mac_vendor if mac_vendor and mac_vendor != "Unknown" else "",
            )
            if is_new:
                device.dhcp_data = {
                    "hostname": hostname,
                    "vendor_class": vendor_class,
                    "assigned_ip": client_ip,
                    "dhcp_server": server_ip,
                    "message_type": msg_name,
                    "protocol": "DHCP/UDP",
                }
            else:
                # Update with assignment info
                if client_ip and client_ip not in device.ip_addresses:
                    device.ip_addresses.append(client_ip)
                if device.dhcp_data:
                    if client_ip:
                        device.dhcp_data["assigned_ip"] = client_ip
                    if server_ip:
                        device.dhcp_data["dhcp_server"] = server_ip
                    if lease_time:
                        device.dhcp_data["lease_time"] = lease_time

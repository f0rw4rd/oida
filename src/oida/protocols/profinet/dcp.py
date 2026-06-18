"""PROFINET DCP (Discovery and Configuration Protocol) operations."""

from datetime import datetime
from typing import List

from .models import ProfinetDevice
from .helpers import _get_profinet
from ...utils.vendor_maps import profinet_vendor_map

import logging

logger = logging.getLogger(__name__)


def discover_devices(
    interface: str,
    timeout: float,
    logger,
) -> List[ProfinetDevice]:
    """Perform DCP discovery on the specified interface.

    Args:
        interface: Network interface name (e.g., 'eth0')
        timeout: Discovery timeout in seconds
        logger: ICSLogger instance for output

    Returns:
        List of discovered ProfinetDevice objects
    """
    profinet_mod = _get_profinet()

    logger.display(f"DCP discovery on {interface}...")

    try:
        # Create socket and get MAC
        sock = profinet_mod.ethernet_socket(interface, 0x8892)
        my_mac = profinet_mod.get_mac(interface)

        # Send discover request
        profinet_mod.send_discover(sock, my_mac)

        # Use library's read_response for proper DCP parsing
        from profinet.dcp import read_response, DCPDeviceDescription

        responses = read_response(sock, my_mac, timeout_sec=int(timeout), once=False)
        sock.close()
        logger.display(f"DCP discovery completed ({len(responses)} response(s))")

        # Convert responses to ProfinetDevice objects
        devices = []
        for mac_bytes, blocks in responses.items():
            try:
                dcp_desc = DCPDeviceDescription(mac_bytes, blocks)
                device = dcp_to_device(dcp_desc, profinet_mod)
                devices.append(device)
            except Exception as e:
                logger.debug(f"Failed to parse device: {e}")

        return devices

    except Exception as e:
        logger.fail(f"DCP discovery failed: {e}")
        return []


def dcp_to_device(dcp_desc, profinet_mod) -> ProfinetDevice:
    """Convert DCPDeviceDescription to ProfinetDevice.

    Args:
        dcp_desc: DCPDeviceDescription from profinet-py
        profinet_mod: The profinet module

    Returns:
        ProfinetDevice instance
    """
    vendor_id = (dcp_desc.vendor_high << 8) | dcp_desc.vendor_low
    device_id = (dcp_desc.device_high << 8) | dcp_desc.device_low

    vendor_name = profinet_vendor_map.get(vendor_id, f"Unknown (0x{vendor_id:04X})")
    if vendor_name.startswith("Unknown") and hasattr(profinet_mod, "get_vendor_name"):
        try:
            pn_vendor = profinet_mod.get_vendor_name(vendor_id)
            if pn_vendor and not pn_vendor.startswith("Unknown"):
                vendor_name = pn_vendor
        except Exception as e:
            logger.debug(f"Failed to get pn_vendor: {e}")

    return ProfinetDevice(
        mac_address=dcp_desc.mac,
        name_of_station=dcp_desc.name,
        device_type=getattr(dcp_desc, "device_type", ""),
        ip_address=dcp_desc.ip,
        subnet_mask=dcp_desc.netmask,
        gateway=dcp_desc.gateway,
        vendor_id=vendor_id,
        vendor_name=vendor_name,
        device_id=device_id,
        device_roles=getattr(dcp_desc, "device_roles", []),
        device_instance=getattr(dcp_desc, "device_instance", (0, 0)),
        alias_name=getattr(dcp_desc, "alias_name", ""),
        supported_options=getattr(dcp_desc, "supported_options", []),
        first_seen=datetime.now().isoformat(),
        last_seen=datetime.now().isoformat(),
        _dcp_desc=dcp_desc,
    )


def flash_device(interface: str, mac_address: str, logger) -> bool:
    """Flash device LED for identification.

    Args:
        interface: Network interface
        mac_address: Target device MAC address
        logger: ICSLogger instance

    Returns:
        True if successful
    """
    profinet_mod = _get_profinet()

    try:
        sock = profinet_mod.ethernet_socket(interface, 0x8892)
        my_mac = profinet_mod.get_mac(interface)

        # Parse MAC address
        target_mac = bytes.fromhex(mac_address.replace(":", "").replace("-", ""))

        # Send flash signal
        profinet_mod.dcp.send_flash(sock, my_mac, target_mac)
        sock.close()

        logger.success(f"Flash signal sent to {mac_address}")
        return True

    except Exception as e:
        logger.fail(f"Failed to flash device: {e}")
        return False


def set_device_name(interface: str, mac_address: str, new_name: str, logger) -> bool:
    """Set device station name via DCP.

    Args:
        interface: Network interface
        mac_address: Target device MAC address
        new_name: New station name
        logger: ICSLogger instance

    Returns:
        True if successful
    """
    profinet_mod = _get_profinet()

    try:
        sock = profinet_mod.ethernet_socket(interface, 0x8892)
        my_mac = profinet_mod.get_mac(interface)

        target_mac = bytes.fromhex(mac_address.replace(":", "").replace("-", ""))

        profinet_mod.dcp.send_set_name(sock, my_mac, target_mac, new_name)
        sock.close()

        logger.success(f"Set name to '{new_name}' on {mac_address}")
        return True

    except Exception as e:
        logger.fail(f"Failed to set name: {e}")
        return False


def set_device_ip(
    interface: str, mac_address: str, ip: str, netmask: str, gateway: str, logger
) -> bool:
    """Set device IP address via DCP.

    Args:
        interface: Network interface
        mac_address: Target device MAC address
        ip: New IP address
        netmask: Subnet mask
        gateway: Default gateway
        logger: ICSLogger instance

    Returns:
        True if successful
    """
    profinet_mod = _get_profinet()

    try:
        sock = profinet_mod.ethernet_socket(interface, 0x8892)
        my_mac = profinet_mod.get_mac(interface)

        target_mac = bytes.fromhex(mac_address.replace(":", "").replace("-", ""))

        profinet_mod.dcp.send_set_ip(sock, my_mac, target_mac, ip, netmask, gateway)
        sock.close()

        logger.success(f"Set IP to {ip}/{netmask} gw {gateway} on {mac_address}")
        return True

    except Exception as e:
        logger.fail(f"Failed to set IP: {e}")
        return False


def factory_reset(interface: str, mac_address: str, logger) -> bool:
    """Reset device to factory defaults via DCP.

    Args:
        interface: Network interface
        mac_address: Target device MAC address
        logger: ICSLogger instance

    Returns:
        True if successful
    """
    profinet_mod = _get_profinet()

    try:
        sock = profinet_mod.ethernet_socket(interface, 0x8892)
        my_mac = profinet_mod.get_mac(interface)

        target_mac = bytes.fromhex(mac_address.replace(":", "").replace("-", ""))

        profinet_mod.dcp.send_reset_factory(sock, my_mac, target_mac)
        sock.close()

        logger.success(f"Factory reset sent to {mac_address}")
        return True

    except Exception as e:
        logger.fail(f"Failed to reset device: {e}")
        return False

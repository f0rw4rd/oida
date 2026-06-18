"""
IT infrastructure broadcast discovery scanners.

UDP broadcast probes for common IT services found on enterprise/OT networks.
All probes use 255.255.255.255 broadcasts and are safe for OT networks since
no OT device listens on these ports.

Contains:
- HIDScanner: HID Access Control (UDP 4070)
- MSSQLBrowserScanner: MS-SQL Browser Service (UDP 1434)
- BJNPScanner: Canon BJNP printers (UDP 8611/8612)
- SonicWallScanner: SonicWall firewalls (UDP 26214)
- DB2Scanner: IBM DB2 Discovery (UDP 523)
- SybaseScanner: Sybase ASA (UDP 2638)
- XDMCPScanner: XDMCP Display Manager (UDP 177)
- JenkinsScanner: Jenkins CI auto-discovery (UDP 33848)
- PCAnywhereScanner: Symantec pcAnywhere (UDP 5632)
"""

import os
import re
import socket
import struct
import threading
import time
from datetime import datetime
from typing import Any, Dict, Optional, Set

from .core import (
    DiscoveredDevice,
    create_udp_socket,
    get_all_broadcast_addresses,
    validate_interface,
    validate_timeout,
    validate_subnet,
)
from ...utils.rate_limiter import sendto
from ...utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)


class HIDScanner:
    """HID Access Control Discovery (UDP 4070).

    HID Global discoveryd service responds to broadcast probes with
    device information including MAC, name, model, firmware version.

    Protocol:
    - Request: ASCII "discover;013;"
    - Response: semicolon-delimited fields (MAC, name, IP, model, version, build_date)

    References:
    - nmap service probe for HID discoveryd
    """

    PORT = 4070
    DISCOVERY_PROBE = b"discover;013;"

    def __init__(
        self,
        interface: str,
        subnet: Optional[str] = None,
        timeout: float = 5.0,
    ):
        self.interface = validate_interface(interface)
        self.subnet = validate_subnet(subnet)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Send HID discovery broadcast and collect responses."""
        sock = None
        try:
            sock = create_udp_socket(self.interface, timeout=0.5, broadcast=True)

            broadcast_addrs = get_all_broadcast_addresses(self.interface, self.subnet)
            for i, broadcast_addr in enumerate(broadcast_addrs):
                sendto(sock, self.DISCOVERY_PROBE, (broadcast_addr, self.PORT))
                logger.debug(f"HID: Sent discovery to {broadcast_addr}:{self.PORT}")
                if i < len(broadcast_addrs) - 1:
                    time.sleep(0.1)

            start_time = time.time()
            seen_ips: Set[str] = set()

            while time.time() - start_time < self.timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    ip = addr[0]

                    if ip in seen_ips:
                        continue

                    device = self._parse_response(data, ip)
                    if device:
                        seen_ips.add(ip)
                        with self._lock:
                            self.discovered_devices[ip] = device
                            logger.debug(f"HID: Found device at {ip}")

                except TimeoutError:
                    continue
                except OSError as e:
                    logger.debug(f"HID socket error: {e}")

            logger.info(f"HID found {len(self.discovered_devices)} devices")

        except OSError as e:
            logger.warning(f"HID discovery socket error: {e}")
        except Exception as e:
            logger.warning(f"HID discovery failed: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except OSError as e:
                    logger.debug(f"sock.close(): {e}")

        return self.discovered_devices

    def _parse_response(self, data: bytes, ip: str) -> Optional[DiscoveredDevice]:
        """Parse HID discovery response.

        Response format (confirmed via Metasploit exploit module):
        discovered;length;MAC;name;IP;unknown;model;version;build_date
        - field[0] = "discovered" marker
        - field[1] = total response length (integrity check)
        - field[2] = MAC address
        - field[3] = device name
        - field[4] = IP address
        - field[5] = unknown (typically "1")
        - field[6] = model (e.g. "EH400", "V2-V2000")
        - field[7] = firmware version
        - field[8] = build date
        """
        try:
            text = data.decode("ascii", errors="replace").strip()
        except Exception as e:
            logger.debug(f"Eaton EH400 discovery response ASCII decode failed: {e}")
            return None

        if not text or ";" not in text:
            return None

        fields = text.split(";")

        # Validate response structure
        if len(fields) < 9:
            return None
        if fields[0] != "discovered":
            return None

        hid_data = {"raw_response": text, "fields": fields}

        mac = ""
        name = ""
        model = ""
        version = ""

        # Parse fields at correct offsets
        mac = fields[2].strip()
        hid_data["mac_address"] = mac
        name = fields[3].strip()
        hid_data["device_name"] = name
        hid_data["device_ip"] = fields[4].strip()
        model = fields[6].strip()
        hid_data["model"] = model
        version = fields[7].strip()
        hid_data["firmware_version"] = version
        hid_data["build_date"] = fields[8].strip()

        return DiscoveredDevice(
            mac_address=mac,
            ip_addresses=[ip],
            name=name or f"HID Device ({ip})",
            manufacturer="HID Global",
            model=model,
            device_type="Access Control",
            description=f"HID {model} {version}".strip(),
            discovered_by=["hid"],
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
            hid_data=hid_data,
        )


class MSSQLBrowserScanner:
    """MS-SQL Browser Service Discovery (UDP 1434).

    SQL Server Browser Service responds to broadcast probes with
    instance information including name, version, and TCP port.

    Protocol:
    - Request: single byte 0x02 (CLNT_BCAST_EX)
    - Response: semicolon-delimited key-value pairs

    References:
    - nmap ms-sql-info script
    - MS-SQLR protocol specification
    """

    PORT = 1434
    DISCOVERY_PROBE = b"\x02"

    def __init__(
        self,
        interface: str,
        subnet: Optional[str] = None,
        timeout: float = 5.0,
    ):
        self.interface = validate_interface(interface)
        self.subnet = validate_subnet(subnet)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Send MS-SQL Browser discovery broadcast and collect responses."""
        sock = None
        try:
            sock = create_udp_socket(self.interface, timeout=0.5, broadcast=True)

            broadcast_addrs = get_all_broadcast_addresses(self.interface, self.subnet)
            for i, broadcast_addr in enumerate(broadcast_addrs):
                sendto(sock, self.DISCOVERY_PROBE, (broadcast_addr, self.PORT))
                logger.debug(f"MSSQL: Sent discovery to {broadcast_addr}:{self.PORT}")
                if i < len(broadcast_addrs) - 1:
                    time.sleep(0.1)

            start_time = time.time()
            seen_ips: Set[str] = set()

            while time.time() - start_time < self.timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    ip = addr[0]

                    if ip in seen_ips:
                        continue

                    device = self._parse_response(data, ip)
                    if device:
                        seen_ips.add(ip)
                        with self._lock:
                            self.discovered_devices[ip] = device
                            logger.debug(f"MSSQL: Found instance at {ip}")

                except TimeoutError:
                    continue
                except OSError as e:
                    logger.debug(f"MSSQL socket error: {e}")

            logger.info(f"MSSQL found {len(self.discovered_devices)} instances")

        except OSError as e:
            logger.warning(f"MSSQL discovery socket error: {e}")
        except Exception as e:
            logger.warning(f"MSSQL discovery failed: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except OSError as e:
                    logger.debug(f"sock.close(): {e}")

        return self.discovered_devices

    def _parse_response(self, data: bytes, ip: str) -> Optional[DiscoveredDevice]:
        """Parse MS-SQL Browser response.

        Response starts with 0x05 header byte, then semicolon-delimited
        key-value pairs. Multiple instances separated by ;; (confirmed via
        Metasploit mssql_ping mixin).

        Format: ServerName;SRV;InstanceName;INST;Version;X.Y;tcp;1433;;ServerName;...
        """
        if len(data) < 3:
            return None

        # Skip header bytes (0x05 + 2-byte length)
        try:
            text = data[3:].decode("ascii", errors="replace").rstrip("\x00")
        except Exception as e:
            logger.debug(f"MSSQL SSRP response ASCII decode failed: {e}")
            return None

        if not text:
            return None

        # Split on ;; to handle multiple instances per host
        instance_texts = [s.strip(";") for s in text.split(";;") if s.strip(";")]
        if not instance_texts:
            return None

        instances = []
        for inst_text in instance_texts:
            parts = inst_text.split(";")
            kv = {}
            for j in range(0, len(parts) - 1, 2):
                key = parts[j].strip()
                val = parts[j + 1].strip()
                if key:
                    kv[key] = val
            if kv:
                instances.append(kv)

        if not instances:
            return None

        # Use first instance for primary device fields
        primary = instances[0]

        mssql_data = {
            "raw_response": data.hex(),
            "instances": instances,
            "instance_count": len(instances),
            "server_name": primary.get("ServerName", ""),
            "instance_name": primary.get("InstanceName", ""),
            "version": primary.get("Version", ""),
            "tcp_port": primary.get("tcp", ""),
            "named_pipe": primary.get("np", ""),
            "is_clustered": primary.get("IsClustered", ""),
        }

        name = primary.get("ServerName", "")
        instance = primary.get("InstanceName", "")
        version = primary.get("Version", "")
        desc = f"SQL Server {version}" if version else "SQL Server"
        if instance:
            desc += f" ({instance})"
        if len(instances) > 1:
            desc += f" +{len(instances) - 1} more"

        return DiscoveredDevice(
            ip_addresses=[ip],
            name=name or f"MSSQL Server ({ip})",
            manufacturer="Microsoft",
            device_type="Database Server",
            description=desc,
            discovered_by=["mssql"],
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
            mssql_data=mssql_data,
        )


class BJNPScanner:
    """Canon BJNP Printer Discovery (UDP 8611/8612).

    Canon printers and MFPs respond to BJNP broadcast probes.
    Port 8611 is for printing, 8612 for scanning.

    Protocol:
    - Request: 16-byte BJNP header (magic "BJNP" + type + code=1 + seq + session + length)
    - Response: BJNP header + payload; follow-up identity query for MFG/MDL/DES/VER

    References:
    - nmap bjnp-discover script
    - CUPS BJNP backend
    """

    PORTS = [8611, 8612]
    BJNP_MAGIC = b"BJNP"

    def __init__(
        self,
        interface: str,
        subnet: Optional[str] = None,
        timeout: float = 5.0,
    ):
        self.interface = validate_interface(interface)
        self.subnet = validate_subnet(subnet)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def _build_probe(self, dev_type: int = 1) -> bytes:
        """Build BJNP discovery probe packet.

        Header: BJNP(4) + type(1) + code(1) + seq(2) + session(2) + length(4) + padding(2)
        """
        # fields: type 1=print 2=scan, code 1=discover, seq/session 0, length 0
        return struct.pack(">4sBBHHI2x", self.BJNP_MAGIC, dev_type, 0x01, 0, 0, 0)

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Send BJNP discovery broadcast and collect responses."""
        sock = None
        try:
            sock = create_udp_socket(self.interface, timeout=0.5, broadcast=True)

            broadcast_addrs = get_all_broadcast_addresses(self.interface, self.subnet)
            for port in self.PORTS:
                dev_type = 1 if port == 8611 else 2
                probe = self._build_probe(dev_type)
                for i, broadcast_addr in enumerate(broadcast_addrs):
                    sendto(sock, probe, (broadcast_addr, port))
                    logger.debug(f"BJNP: Sent discovery to {broadcast_addr}:{port}")
                    if i < len(broadcast_addrs) - 1:
                        time.sleep(0.1)

            start_time = time.time()
            seen_ips: Set[str] = set()

            while time.time() - start_time < self.timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    ip = addr[0]

                    if ip in seen_ips:
                        continue

                    device = self._parse_response(data, ip)
                    if device:
                        seen_ips.add(ip)
                        with self._lock:
                            self.discovered_devices[ip] = device
                            logger.debug(f"BJNP: Found printer at {ip}")

                except TimeoutError:
                    continue
                except OSError as e:
                    logger.debug(f"BJNP socket error: {e}")

            # Try identity query on discovered devices for model details
            for ip, device in list(self.discovered_devices.items()):
                self._query_identity(ip, device)

            logger.info(f"BJNP found {len(self.discovered_devices)} printers")

        except OSError as e:
            logger.warning(f"BJNP discovery socket error: {e}")
        except Exception as e:
            logger.warning(f"BJNP discovery failed: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except OSError as e:
                    logger.debug(f"sock.close(): {e}")

        return self.discovered_devices

    def _parse_response(self, data: bytes, ip: str) -> Optional[DiscoveredDevice]:
        """Parse BJNP discovery response."""
        if len(data) < 16:
            return None

        # Verify BJNP magic
        if data[:4] != self.BJNP_MAGIC:
            return None

        bjnp_data = {
            "raw_response": data.hex(),
            "type": data[4],
            "code": data[5],
        }

        # Extract payload if present (length field is at offset 10 in BJNP header)
        payload_len = struct.unpack(">I", data[10:14])[0] if len(data) >= 14 else 0
        if payload_len > 0 and len(data) >= 16 + payload_len:
            bjnp_data["payload"] = data[16 : 16 + payload_len].hex()

        return DiscoveredDevice(
            ip_addresses=[ip],
            name=f"Canon Printer ({ip})",
            manufacturer="Canon",
            device_type="Printer",
            description="Canon BJNP printer/MFP",
            discovered_by=["bjnp"],
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
            bjnp_data=bjnp_data,
        )

    def _query_identity(self, ip: str, device: DiscoveredDevice) -> None:
        """Send BJNP identity query to get MFG/MDL/DES/VER."""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            # Identity query: type=1, code=0x30 (GET_ID)
            probe = struct.pack(">4sBBHHI2x", self.BJNP_MAGIC, 1, 0x30, 1, 0, 0)
            sendto(sock, probe, (ip, 8611))
            data, _ = sock.recvfrom(4096)

            if len(data) > 16:
                payload = data[16:]
                try:
                    # IEEE 1284 device ID string
                    id_str = payload.decode("ascii", errors="replace")
                    bjnp_data = device.bjnp_data or {}

                    # Parse key-value pairs (KEY:VALUE;)
                    for field in id_str.split(";"):
                        if ":" in field:
                            key, _, val = field.partition(":")
                            key = key.strip().upper()
                            val = val.strip()
                            if key == "MFG" or key == "MANUFACTURER":
                                device.manufacturer = val
                                bjnp_data["manufacturer"] = val
                            elif key == "MDL" or key == "MODEL":
                                device.model = val
                                bjnp_data["model"] = val
                                device.name = val
                            elif key == "DES" or key == "DESCRIPTION":
                                device.description = val
                                bjnp_data["description"] = val
                            elif key == "VER":
                                bjnp_data["version"] = val

                    bjnp_data["device_id"] = id_str
                    device.bjnp_data = bjnp_data
                except Exception as e:
                    logger.debug(f"Failed to get id_str: {e}")
        except OSError as e:
            logger.debug(f"BJNP identity query failed: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except OSError as e:
                    logger.debug(f"sock.close(): {e}")


class SonicWallScanner:
    """SonicWall Firewall Discovery (UDP 26214).

    SonicWall appliances respond to "ackfin ping" broadcast probes
    with device information at fixed binary offsets.

    Protocol:
    - Request: "ackfin ping\x00"
    - Response: binary structure with IP@40, netmask@44, serial@48, firmware@54

    References:
    - nmap sonicwall-discover script
    """

    PORT = 26214
    DISCOVERY_PROBE = b"ackfin ping\x00"

    def __init__(
        self,
        interface: str,
        subnet: Optional[str] = None,
        timeout: float = 5.0,
    ):
        self.interface = validate_interface(interface)
        self.subnet = validate_subnet(subnet)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Send SonicWall discovery broadcast and collect responses."""
        sock = None
        try:
            sock = create_udp_socket(self.interface, timeout=0.5, broadcast=True)

            broadcast_addrs = get_all_broadcast_addresses(self.interface, self.subnet)
            for i, broadcast_addr in enumerate(broadcast_addrs):
                sendto(sock, self.DISCOVERY_PROBE, (broadcast_addr, self.PORT))
                logger.debug(f"SonicWall: Sent discovery to {broadcast_addr}:{self.PORT}")
                if i < len(broadcast_addrs) - 1:
                    time.sleep(0.1)

            start_time = time.time()
            seen_ips: Set[str] = set()

            while time.time() - start_time < self.timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    ip = addr[0]

                    if ip in seen_ips:
                        continue

                    device = self._parse_response(data, ip)
                    if device:
                        seen_ips.add(ip)
                        with self._lock:
                            self.discovered_devices[ip] = device
                            logger.debug(f"SonicWall: Found device at {ip}")

                except TimeoutError:
                    continue
                except OSError as e:
                    logger.debug(f"SonicWall socket error: {e}")

            logger.info(f"SonicWall found {len(self.discovered_devices)} devices")

        except OSError as e:
            logger.warning(f"SonicWall discovery socket error: {e}")
        except Exception as e:
            logger.warning(f"SonicWall discovery failed: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except OSError as e:
                    logger.debug(f"sock.close(): {e}")

        return self.discovered_devices

    def _parse_response(self, data: bytes, ip: str) -> Optional[DiscoveredDevice]:
        """Parse SonicWall discovery response.

        Binary response with fixed offsets:
        - Bytes 40-43: Device IP address
        - Bytes 44-47: Subnet mask
        - Bytes 48-53: Serial number (6 bytes)
        - Bytes 54+: Firmware version (null-terminated string)
        """
        if len(data) < 54:
            return None

        sonicwall_data = {"raw_response": data.hex()}

        # Extract device IP
        try:
            device_ip = socket.inet_ntoa(data[40:44])
            sonicwall_data["device_ip"] = device_ip
        except Exception:
            device_ip = ""

        # Extract subnet mask
        try:
            netmask = socket.inet_ntoa(data[44:48])
            sonicwall_data["netmask"] = netmask
        except Exception as e:
            logger.debug(f"Failed to get netmask: {e}")

        # Extract serial number
        serial = data[48:54].hex()
        sonicwall_data["serial"] = serial

        # Extract firmware version
        firmware = ""
        if len(data) > 54:
            try:
                end = data.index(b"\x00", 54) if b"\x00" in data[54:] else len(data)
                firmware = data[54:end].decode("ascii", errors="replace").strip()
                sonicwall_data["firmware"] = firmware
            except Exception as e:
                logger.debug(f"SonicWall firmware string parse failed: {e}")

        desc = f"SonicWall (serial: {serial})"
        if firmware:
            desc += f" fw:{firmware}"

        return DiscoveredDevice(
            ip_addresses=[ip],
            name=f"SonicWall ({ip})",
            manufacturer="SonicWall",
            device_type="Firewall",
            description=desc,
            discovered_by=["sonicwall"],
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
            sonicwall_data=sonicwall_data,
        )


class DB2Scanner:
    """IBM DB2 Discovery Service (UDP 523).

    DB2 instances respond to DB2GETADDR broadcast probes with
    server name and version information.

    Protocol:
    - Request: "DB2GETADDR\x00SQL09010\x00"
    - Response: "DB2RETADDR" followed by version and server info

    References:
    - nmap db2-discover script
    - IBM DB2 Administration Server
    """

    PORT = 523
    DISCOVERY_PROBE = b"DB2GETADDR\x00SQL09010\x00"

    def __init__(
        self,
        interface: str,
        subnet: Optional[str] = None,
        timeout: float = 5.0,
    ):
        self.interface = validate_interface(interface)
        self.subnet = validate_subnet(subnet)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Send DB2 discovery broadcast and collect responses."""
        sock = None
        try:
            sock = create_udp_socket(self.interface, timeout=0.5, broadcast=True)

            broadcast_addrs = get_all_broadcast_addresses(self.interface, self.subnet)
            for i, broadcast_addr in enumerate(broadcast_addrs):
                sendto(sock, self.DISCOVERY_PROBE, (broadcast_addr, self.PORT))
                logger.debug(f"DB2: Sent discovery to {broadcast_addr}:{self.PORT}")
                if i < len(broadcast_addrs) - 1:
                    time.sleep(0.1)

            start_time = time.time()
            seen_ips: Set[str] = set()

            while time.time() - start_time < self.timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    ip = addr[0]

                    if ip in seen_ips:
                        continue

                    device = self._parse_response(data, ip)
                    if device:
                        seen_ips.add(ip)
                        with self._lock:
                            self.discovered_devices[ip] = device
                            logger.debug(f"DB2: Found instance at {ip}")

                except TimeoutError:
                    continue
                except OSError as e:
                    logger.debug(f"DB2 socket error: {e}")

            logger.info(f"DB2 found {len(self.discovered_devices)} instances")

        except OSError as e:
            logger.warning(f"DB2 discovery socket error: {e}")
        except Exception as e:
            logger.warning(f"DB2 discovery failed: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except OSError as e:
                    logger.debug(f"sock.close(): {e}")

        return self.discovered_devices

    def _parse_response(self, data: bytes, ip: str) -> Optional[DiscoveredDevice]:
        """Parse DB2 discovery response.

        Response contains "DB2RETADDR" marker followed by version and server info.
        """
        try:
            text = data.decode("ascii", errors="replace")
        except Exception as e:
            logger.debug(f"DB2 discovery response ASCII decode failed: {e}")
            return None

        if "DB2RETADDR" not in text:
            return None

        db2_data = {"raw_response": data.hex()}

        # Extract version (SQLxxxxx pattern)
        version_match = re.search(r"SQL\d+", text)
        if version_match:
            db2_data["version"] = version_match.group(0)

        # Extract server name (typically after null bytes)
        parts = text.split("\x00")
        server_name = ""
        for part in parts:
            part = part.strip()
            if part and part != "DB2RETADDR" and not part.startswith("SQL"):
                server_name = part
                break
        if server_name:
            db2_data["server_name"] = server_name

        version = db2_data.get("version", "")
        desc = f"IBM DB2 {version}" if version else "IBM DB2"

        return DiscoveredDevice(
            ip_addresses=[ip],
            name=server_name or f"DB2 Server ({ip})",
            manufacturer="IBM",
            device_type="Database Server",
            description=desc,
            discovered_by=["db2"],
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
            db2_data=db2_data,
        )


class SybaseScanner:
    """Sybase ASA Discovery (UDP 2638).

    Sybase Adaptive Server Anywhere responds to TDS connectionless
    ping packets with instance name and port.

    Protocol:
    - Request: TDS CONNECTIONLESS_TDS ping (~62 bytes)
    - Response: binary with instance name and port

    References:
    - nmap sybase-info script
    - TDS protocol specification
    """

    PORT = 2638

    def __init__(
        self,
        interface: str,
        subnet: Optional[str] = None,
        timeout: float = 5.0,
    ):
        self.interface = validate_interface(interface)
        self.subnet = validate_subnet(subnet)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def _build_probe(self) -> bytes:
        """Build TDS connectionless ping packet.

        TDS header: type(1)=0x04 (response) + status(1)=0x01 (EOM) +
        length(2) + channel(2) + packet_number(1) + window(1)
        Then TDS_PRELOGIN with version option.
        """
        # Minimal TDS 5.0 connectionless ping (SERVERINFO request)
        # This is the format used by nmap's sybase probe
        header = b"\x1a"  # TDS_MGMT type
        # DB-Library SERVERINFO request
        payload = b"\x00" * 15  # Padding
        payload += b"\x02"  # Command: SERVERINFO
        payload += b"\x00" * 44  # Remaining padding

        return header + payload

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Send Sybase discovery broadcast and collect responses."""
        sock = None
        try:
            sock = create_udp_socket(self.interface, timeout=0.5, broadcast=True)

            probe = self._build_probe()
            broadcast_addrs = get_all_broadcast_addresses(self.interface, self.subnet)
            for i, broadcast_addr in enumerate(broadcast_addrs):
                sendto(sock, probe, (broadcast_addr, self.PORT))
                logger.debug(f"Sybase: Sent discovery to {broadcast_addr}:{self.PORT}")
                if i < len(broadcast_addrs) - 1:
                    time.sleep(0.1)

            start_time = time.time()
            seen_ips: Set[str] = set()

            while time.time() - start_time < self.timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    ip = addr[0]

                    if ip in seen_ips:
                        continue

                    device = self._parse_response(data, ip)
                    if device:
                        seen_ips.add(ip)
                        with self._lock:
                            self.discovered_devices[ip] = device
                            logger.debug(f"Sybase: Found instance at {ip}")

                except TimeoutError:
                    continue
                except OSError as e:
                    logger.debug(f"Sybase socket error: {e}")

            logger.info(f"Sybase found {len(self.discovered_devices)} instances")

        except OSError as e:
            logger.warning(f"Sybase discovery socket error: {e}")
        except Exception as e:
            logger.warning(f"Sybase discovery failed: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except OSError as e:
                    logger.debug(f"sock.close(): {e}")

        return self.discovered_devices

    def _parse_response(self, data: bytes, ip: str) -> Optional[DiscoveredDevice]:
        """Parse Sybase discovery response.

        Response contains instance name and port in binary format.
        """
        if len(data) < 2:
            return None

        sybase_data: Dict[str, Any] = {"raw_response": data.hex()}

        # Try to extract readable strings for instance name
        try:
            text = data.decode("ascii", errors="replace")
            # Look for server name pattern
            readable = re.findall(r"[\x20-\x7e]{3,}", text)
            if readable:
                sybase_data["server_info"] = readable
                if len(readable) > 0:
                    sybase_data["instance_name"] = readable[0]
        except Exception as e:
            logger.debug(f"Sybase discovery response ASCII decode failed: {e}")

        # Try to find port number (usually a 2-byte big-endian value)
        if len(data) >= 4:
            # Common location for port in response
            for offset in range(len(data) - 1):
                port = struct.unpack(">H", data[offset : offset + 2])[0]
                if 1024 < port < 65535:
                    sybase_data["port"] = port
                    break

        instance = sybase_data.get("instance_name", "")
        desc = f"Sybase ASA ({instance})" if instance else "Sybase ASA"

        return DiscoveredDevice(
            ip_addresses=[ip],
            name=instance or f"Sybase Server ({ip})",
            manufacturer="SAP/Sybase",
            device_type="Database Server",
            description=desc,
            discovered_by=["sybase"],
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
            sybase_data=sybase_data,
        )


class XDMCPScanner:
    """XDMCP Display Manager Discovery (UDP 177).

    X Display Manager Control Protocol responds to BROADCAST_QUERY
    with WILLING messages containing hostname and status.

    Protocol:
    - Request: 6 bytes - version(2)=1 + opcode(2)=3 (BROADCAST_QUERY) + length(2)=1 + auth_name_len(1)=0
    - Response: WILLING - version(2) + opcode(2)=5 + length(2) + auth + hostname + status

    References:
    - nmap xdmcp-discover script
    - RFC 1148 (XDMCP)
    """

    PORT = 177

    def __init__(
        self,
        interface: str,
        subnet: Optional[str] = None,
        timeout: float = 5.0,
    ):
        self.interface = validate_interface(interface)
        self.subnet = validate_subnet(subnet)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def _build_probe(self) -> bytes:
        """Build XDMCP BROADCAST_QUERY packet.

        version=1, opcode=3 (BroadcastQuery), length=1, auth_count=0
        """
        return struct.pack(">HHH", 1, 3, 1) + b"\x00"

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Send XDMCP broadcast query and collect responses."""
        sock = None
        try:
            sock = create_udp_socket(self.interface, timeout=0.5, broadcast=True)

            probe = self._build_probe()
            broadcast_addrs = get_all_broadcast_addresses(self.interface, self.subnet)
            for i, broadcast_addr in enumerate(broadcast_addrs):
                sendto(sock, probe, (broadcast_addr, self.PORT))
                logger.debug(f"XDMCP: Sent broadcast query to {broadcast_addr}:{self.PORT}")
                if i < len(broadcast_addrs) - 1:
                    time.sleep(0.1)

            start_time = time.time()
            seen_ips: Set[str] = set()

            while time.time() - start_time < self.timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    ip = addr[0]

                    if ip in seen_ips:
                        continue

                    device = self._parse_response(data, ip)
                    if device:
                        seen_ips.add(ip)
                        with self._lock:
                            self.discovered_devices[ip] = device
                            logger.debug(f"XDMCP: Found display manager at {ip}")

                except TimeoutError:
                    continue
                except OSError as e:
                    logger.debug(f"XDMCP socket error: {e}")

            logger.info(f"XDMCP found {len(self.discovered_devices)} display managers")

        except OSError as e:
            logger.warning(f"XDMCP discovery socket error: {e}")
        except Exception as e:
            logger.warning(f"XDMCP discovery failed: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except OSError as e:
                    logger.debug(f"sock.close(): {e}")

        return self.discovered_devices

    def _parse_response(self, data: bytes, ip: str) -> Optional[DiscoveredDevice]:
        """Parse XDMCP WILLING response.

        Format: version(2) + opcode(2) + length(2) + auth_name_len(2) + auth_name +
                hostname_len(2) + hostname + status_len(2) + status
        """
        if len(data) < 6:
            return None

        version, opcode, length = struct.unpack(">HHH", data[:6])

        # Opcode 5 = WILLING
        if opcode != 5:
            return None

        xdmcp_data = {
            "raw_response": data.hex(),
            "version": version,
            "opcode": opcode,
        }

        offset = 6
        hostname = ""
        status = ""

        try:
            # Skip authentication name
            if offset + 2 <= len(data):
                auth_len = struct.unpack(">H", data[offset : offset + 2])[0]
                offset += 2 + auth_len

            # Read hostname
            if offset + 2 <= len(data):
                host_len = struct.unpack(">H", data[offset : offset + 2])[0]
                offset += 2
                if offset + host_len <= len(data):
                    hostname = data[offset : offset + host_len].decode("ascii", errors="replace")
                    xdmcp_data["hostname"] = hostname
                    offset += host_len

            # Read status
            if offset + 2 <= len(data):
                status_len = struct.unpack(">H", data[offset : offset + 2])[0]
                offset += 2
                if offset + status_len <= len(data):
                    status = data[offset : offset + status_len].decode("ascii", errors="replace")
                    xdmcp_data["status"] = status
        except Exception as e:
            logger.debug(f"if offset  2  len(data):: {e}")

        desc = f"XDMCP ({hostname})" if hostname else "XDMCP Display Manager"
        if status:
            desc += f" - {status}"

        return DiscoveredDevice(
            ip_addresses=[ip],
            name=hostname or f"XDMCP Host ({ip})",
            device_type="Display Manager",
            description=desc,
            discovered_by=["xdmcp"],
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
            xdmcp_data=xdmcp_data,
        )


class JenkinsScanner:
    """Jenkins CI Auto-Discovery (UDP 33848).

    Jenkins instances respond to any UDP packet on port 33848
    with an XML response containing version, server URL, and slave port.

    Protocol:
    - Request: any bytes (10 random bytes used)
    - Response: XML <hudson> document with version, url, server-id, slave-port

    References:
    - nmap jenkins-discover script
    - Jenkins auto-discovery protocol
    """

    PORT = 33848

    def __init__(
        self,
        interface: str,
        subnet: Optional[str] = None,
        timeout: float = 5.0,
    ):
        self.interface = validate_interface(interface)
        self.subnet = validate_subnet(subnet)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Send Jenkins discovery broadcast and collect responses."""
        sock = None
        try:
            sock = create_udp_socket(self.interface, timeout=0.5, broadcast=True)

            # Jenkins responds to any UDP data; use random bytes
            probe = os.urandom(10)
            broadcast_addrs = get_all_broadcast_addresses(self.interface, self.subnet)
            for i, broadcast_addr in enumerate(broadcast_addrs):
                sendto(sock, probe, (broadcast_addr, self.PORT))
                logger.debug(f"Jenkins: Sent discovery to {broadcast_addr}:{self.PORT}")
                if i < len(broadcast_addrs) - 1:
                    time.sleep(0.1)

            start_time = time.time()
            seen_ips: Set[str] = set()

            while time.time() - start_time < self.timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    ip = addr[0]

                    if ip in seen_ips:
                        continue

                    device = self._parse_response(data, ip)
                    if device:
                        seen_ips.add(ip)
                        with self._lock:
                            self.discovered_devices[ip] = device
                            logger.debug(f"Jenkins: Found instance at {ip}")

                except TimeoutError:
                    continue
                except OSError as e:
                    logger.debug(f"Jenkins socket error: {e}")

            logger.info(f"Jenkins found {len(self.discovered_devices)} instances")

        except OSError as e:
            logger.warning(f"Jenkins discovery socket error: {e}")
        except Exception as e:
            logger.warning(f"Jenkins discovery failed: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except OSError as e:
                    logger.debug(f"sock.close(): {e}")

        return self.discovered_devices

    def _parse_response(self, data: bytes, ip: str) -> Optional[DiscoveredDevice]:
        """Parse Jenkins discovery response.

        Response is XML: <hudson><version>...</version><url>...</url>
        <server-id>...</server-id><slave-port>...</slave-port></hudson>
        """
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception as e:
            logger.debug(f"Jenkins discovery response UTF-8 decode failed: {e}")
            return None

        if "<hudson>" not in text and "<jenkins>" not in text:
            return None

        jenkins_data = {"raw_response": text}

        # Parse XML fields with regex (avoid xml.etree for robustness)
        version_match = re.search(r"<version>([^<]+)</version>", text)
        url_match = re.search(r"<url>([^<]+)</url>", text)
        server_id_match = re.search(r"<server-id>([^<]+)</server-id>", text)
        slave_port_match = re.search(r"<slave-port>([^<]+)</slave-port>", text)

        if version_match:
            jenkins_data["version"] = version_match.group(1)
        if url_match:
            jenkins_data["url"] = url_match.group(1)
        if server_id_match:
            jenkins_data["server_id"] = server_id_match.group(1)
        if slave_port_match:
            jenkins_data["slave_port"] = slave_port_match.group(1)

        version = jenkins_data.get("version", "")
        desc = f"Jenkins {version}" if version else "Jenkins CI"

        return DiscoveredDevice(
            ip_addresses=[ip],
            name=f"Jenkins ({ip})",
            manufacturer="Jenkins/CloudBees",
            device_type="CI/CD Server",
            description=desc,
            discovered_by=["jenkins"],
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
            jenkins_data=jenkins_data,
        )


class PCAnywhereScanner:
    """Symantec pcAnywhere Discovery (UDP 5632).

    pcAnywhere hosts respond to "NQ" (Name Query) and "ST" (Status)
    broadcast probes.

    Protocol (confirmed via Metasploit auxiliary/scanner/pcanywhere/pcanywhere_udp):
    - NQ probe: "NQ" (2 bytes) -> NR response with 24-byte name + 8-byte capabilities
    - ST probe: "ST" (2 bytes) -> ST response with availability status at byte[4]

    Status byte values:
    - 0x43 (67) = Available
    - 0x0B (11) = Busy

    References:
    - Metasploit: auxiliary/scanner/pcanywhere/pcanywhere_udp
    - pcAnywhere protocol documentation
    """

    PORT = 5632
    NQ_PROBE = b"NQ"
    ST_PROBE = b"ST"
    DISCOVERY_PROBE = b"NQ"  # Primary probe for compatibility

    def __init__(
        self,
        interface: str,
        subnet: Optional[str] = None,
        timeout: float = 5.0,
    ):
        self.interface = validate_interface(interface)
        self.subnet = validate_subnet(subnet)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Send pcAnywhere NQ + ST discovery broadcasts and collect responses."""
        sock = None
        try:
            sock = create_udp_socket(self.interface, timeout=0.5, broadcast=True)

            broadcast_addrs = get_all_broadcast_addresses(self.interface, self.subnet)
            # Send both NQ and ST probes (like Metasploit)
            for probe in [self.NQ_PROBE, self.ST_PROBE]:
                for i, broadcast_addr in enumerate(broadcast_addrs):
                    sendto(sock, probe, (broadcast_addr, self.PORT))
                    logger.debug(
                        f"pcAnywhere: Sent {probe.decode()} to {broadcast_addr}:{self.PORT}"
                    )
                    if i < len(broadcast_addrs) - 1:
                        time.sleep(0.1)

            start_time = time.time()
            seen_ips: Set[str] = set()

            while time.time() - start_time < self.timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    ip = addr[0]

                    # Parse NR or ST responses
                    if data[:2] == b"NR" and ip not in seen_ips:
                        device = self._parse_nr_response(data, ip)
                        if device:
                            seen_ips.add(ip)
                            with self._lock:
                                self.discovered_devices[ip] = device
                                logger.debug(f"pcAnywhere: Found host at {ip}")
                    elif data[:2] == b"ST" and ip in self.discovered_devices:
                        self._parse_st_response(data, ip)

                except TimeoutError:
                    continue
                except OSError as e:
                    logger.debug(f"pcAnywhere socket error: {e}")

            logger.info(f"pcAnywhere found {len(self.discovered_devices)} hosts")

        except OSError as e:
            logger.warning(f"pcAnywhere discovery socket error: {e}")
        except Exception as e:
            logger.warning(f"pcAnywhere discovery failed: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except OSError as e:
                    logger.debug(f"sock.close(): {e}")

        return self.discovered_devices

    def _parse_response(self, data: bytes, ip: str) -> Optional[DiscoveredDevice]:
        """Parse pcAnywhere response (NR or ST).

        Dispatches to _parse_nr_response for NR packets.
        """
        if len(data) < 3:
            return None
        if data[:2] == b"NR":
            return self._parse_nr_response(data, ip)
        return None

    def _parse_nr_response(self, data: bytes, ip: str) -> Optional[DiscoveredDevice]:
        """Parse pcAnywhere NR (Name Response).

        Metasploit format: NR + 24-byte name field + 8-byte capabilities field.
        Name is padded with underscores/nulls.
        """
        if len(data) < 3:
            return None
        if data[:2] != b"NR":
            return None

        pcanywhere_data = {"raw_response": data.hex()}

        name_data = data[2:]
        server_name = ""
        capabilities = ""

        # Metasploit uses fixed-width fields: 24-byte name + 8-byte capabilities
        if len(name_data) >= 24:
            raw_name = name_data[:24]
            server_name = (
                raw_name.replace(b"_", b" ")
                .rstrip(b"\x00 ")
                .decode("ascii", errors="replace")
                .strip()
            )
            # Filter to printable chars
            server_name = "".join(c for c in server_name if 32 <= ord(c) < 127).strip()

            if len(name_data) >= 32:
                raw_caps = name_data[24:32]
                capabilities = (
                    raw_caps.replace(b"_", b" ")
                    .rstrip(b"\x00 ")
                    .decode("ascii", errors="replace")
                    .strip()
                )
                capabilities = "".join(c for c in capabilities if 32 <= ord(c) < 127).strip()
        else:
            # Short response, best-effort extraction
            try:
                clean = name_data.rstrip(b"\x00").decode("ascii", errors="replace")
                server_name = "".join(c for c in clean if 32 <= ord(c) < 127).strip()
            except Exception as e:
                logger.debug(f"Failed to get clean: {e}")

        if server_name:
            pcanywhere_data["server_name"] = server_name
        if capabilities:
            pcanywhere_data["capabilities"] = capabilities

        desc = f"pcAnywhere ({server_name})" if server_name else "pcAnywhere Host"

        return DiscoveredDevice(
            ip_addresses=[ip],
            name=server_name or f"pcAnywhere ({ip})",
            manufacturer="Symantec",
            device_type="Remote Access",
            description=desc,
            discovered_by=["pcanywhere"],
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
            pcanywhere_data=pcanywhere_data,
        )

    def _parse_st_response(self, data: bytes, ip: str) -> None:
        """Parse pcAnywhere ST (Status) response.

        Metasploit: byte[4] == 0x43 (67) = Available, 0x0B (11) = Busy.
        Updates existing device record with status.
        """
        if len(data) < 5:
            return

        status_byte = data[4]
        if status_byte == 0x43:
            status = "Available"
        elif status_byte == 0x0B:
            status = "Busy"
        else:
            status = f"Unknown (0x{status_byte:02x})"

        with self._lock:
            device = self.discovered_devices.get(ip)
            if device and device.pcanywhere_data is not None:
                device.pcanywhere_data["status"] = status
                logger.debug(f"pcAnywhere: {ip} status: {status}")

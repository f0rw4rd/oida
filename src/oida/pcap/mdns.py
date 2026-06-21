"""
mDNS (Multicast DNS) passive listener.

mDNS is used for local service discovery (Bonjour/Avahi/DNS-SD).

mDNS uses:
- Multicast: 224.0.0.251 (IPv4) / ff02::fb (IPv6)
- UDP port: 5353
- DNS message format

Useful for discovering:
- Service types (_http._tcp, _mqtt._tcp, _opcua-tcp._tcp, etc.)
- Hostnames and IP addresses
- TXT record metadata
- SRV records (port, target)
- Device types via service advertisements

Uses PyShark (tshark wrapper) for mDNS packet dissection.

PyShark mDNS/DNS field reference:
mDNS packets are dissected as "mdns" or "dns" layer:
- dns.qry.name: Query name
- dns.qry.type: Query type (1=A, 28=AAAA, 12=PTR, 33=SRV, 16=TXT)
- dns.resp.name: Response name
- dns.resp.type: Response type
- dns.a: IPv4 address (A record)
- dns.aaaa: IPv6 address (AAAA record)
- dns.ptr.domain_name: PTR record target
- dns.srv.name: SRV record name
- dns.srv.port: SRV port
- dns.srv.target: SRV target hostname
- dns.txt: TXT record data
"""

from datetime import datetime
from typing import Any, Dict, List, Set

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip

# mDNS constants
MDNS_MULTICAST_ADDR = "224.0.0.251"
MDNS_MULTICAST_V6 = "ff02::fb"
MDNS_PORT = 5353


class MDNSPassiveListener(PySharkListenerBase):
    """Passive mDNS traffic listener using PyShark.

    Listens for mDNS multicast traffic to discover:
    - Service types and instances
    - Hostnames and IP addresses
    - Service metadata (TXT records)
    - Service locations (SRV records)

    Usage:
        # Live capture
        listener = MDNSPassiveListener(interface="eth0", timeout=30)
        devices = listener.scan()

        # Testing - feed packets directly
        listener = MDNSPassiveListener(interface="eth0")
        listener.feed_packet(mock_mdns_packet)
    """

    PROTOCOL_NAME = "mdns"
    DISPLAY_FILTER = "mdns"
    REQUIRED_LAYERS = ("mdns",)
    PROTOCOL_COLUMNS = (
        "type",
        "name",
        "answer",
        "detail",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 30,
        nxc_logger=None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.services: Dict[str, Dict] = {}  # service_name -> info
        self._seen_records: Set[str] = set()  # dedup key for records

    def get_field(self, layer, field_name: str, default: Any = None) -> Any:
        """Get field from layer, handling mDNS EK-mode quirks.

        In EK mode, tshark outputs mDNS fields with a ``dns_dns_`` prefix
        (e.g. ``dns_dns_qry_name``) rather than the ``dns_`` prefix used in
        XML mode.  PyShark's EkLayer lacks type mappings for the ``mdns``
        protocol, so normal attribute access raises FieldNotFound.  This
        override falls back to reading ``_fields_dict`` directly when the
        standard path returns *default*.
        """
        val = super().get_field(layer, field_name, default)
        if val is not default:
            return val

        # EK fallback: try _fields_dict with dns_ prefix for mdns layers.
        fields_dict = getattr(layer, "_fields_dict", None)
        if fields_dict is None:
            return default

        # The caller passes e.g. "dns_qry_name"; EK dict key is "dns_dns_qry_name".
        ek_key = f"dns_{field_name}"
        raw = fields_dict.get(ek_key)
        if raw is None:
            return default

        # Flatten single-element lists to match XML-mode behaviour.
        if isinstance(raw, list):
            if len(raw) == 1:
                return str(raw[0])
            return ",".join(str(v) for v in raw)
        if isinstance(raw, bool):
            return str(raw)
        if isinstance(raw, (int, float)):
            return str(raw)
        return raw

    def should_process_packet(self, packet) -> bool:
        """Check if packet is mDNS traffic."""
        if hasattr(packet, "mdns"):
            return True
        # Fall back: DNS on port 5353
        if hasattr(packet, "dns") and hasattr(packet, "udp"):
            try:
                src_port = int(packet.udp.srcport)
                dst_port = int(packet.udp.dstport)
                if src_port == MDNS_PORT or dst_port == MDNS_PORT:
                    return True
            except (ValueError, AttributeError) as e:
                self.logger.debug(f"Failed to get src_port: {e}")
        return False

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format mDNS protocol-specific columns."""
        d = ix.details
        record_type = str(d.get("record_type", "") or "?")
        name = str(d.get("name", "") or "?")
        answer = str(d.get("data", "") or "-")
        # Build detail from extra metadata (port, TTL, TXT data, etc.)
        detail_parts = []
        ttl = d.get("ttl", "")
        if ttl:
            detail_parts.append(f"TTL={ttl}")
        detail = str("; ".join(detail_parts)) if detail_parts else "-"
        return [
            str(record_type),
            str(name),
            str(answer),
            str(detail),
        ]

    def process_packet(self, packet) -> None:
        """Process captured mDNS packet using PyShark."""
        # Get IP info
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        src_mac, _ = self.get_mac_info(packet)

        # Get the DNS/mDNS layer
        dns_layer = None
        if hasattr(packet, "mdns"):
            dns_layer = packet.mdns
        elif hasattr(packet, "dns"):
            dns_layer = packet.dns

        if dns_layer is None:
            return

        before = len(self.interactions)

        # Process answer records (responses contain the interesting data)
        self._process_answers(dns_layer, src_ip, dst_ip, src_mac, flow_id, src_port, dst_port)

        # Track queries to identify active devices
        self._process_queries(dns_layer, src_ip, dst_ip, src_mac, flow_id, src_port, dst_port)

        # Fallback: ensure every mDNS packet produces at least one interaction
        # (previous answers/queries may all have been deduped)
        if len(self.interactions) == before:
            now = datetime.now().isoformat()
            resp_name = str(self.get_field(dns_layer, "dns_resp_name", "") or "")
            qry_name = str(self.get_field(dns_layer, "dns_qry_name", "") or "")
            name = resp_name.rstrip(".") or qry_name.rstrip(".") or "?"
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response" if resp_name else "request",
                "mDNS Packet",
                {
                    "record_type": "repeat",
                    "name": name,
                    "data": "",
                    "ttl": "",
                },
                f"mDNS {name}",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
            )

    def _process_answers(
        self,
        dns_layer,
        src_ip: str,
        dst_ip: str,
        src_mac: str,
        flow_id: str,
        src_port: int = 0,
        dst_port: int = 0,
    ) -> None:
        """Process DNS answer records from mDNS response.

        PyShark mDNS layer uses ``dns_*`` attribute names (dots become underscores).
        E.g. ``dns.a`` -> ``dns_a``, ``dns.resp.name`` -> ``dns_resp_name``.
        """
        # A records
        a_records = self.get_field(dns_layer, "dns_a", None)
        if a_records is not None:
            resp_name = str(self.get_field(dns_layer, "dns_resp_name", "") or "")
            resp_ttl = str(self.get_field(dns_layer, "dns_resp_ttl", "") or "")
            ip_addr = str(a_records)
            dedup_key = f"A:{resp_name}:{ip_addr}"
            if dedup_key not in self._seen_records:
                self._seen_records.add(dedup_key)
                hostname = resp_name.rstrip(".")

                now = datetime.now().isoformat()
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "response",
                    "mDNS A Record",
                    {
                        "record_type": "A",
                        "name": hostname,
                        "data": ip_addr,
                        "ttl": resp_ttl,
                    },
                    f"mDNS A {hostname} -> {ip_addr}",
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                )

                self._create_device_from_record(ip_addr, hostname, src_mac, "A")

        # AAAA records
        aaaa_records = self.get_field(dns_layer, "dns_aaaa", None)
        if aaaa_records is not None:
            resp_name = str(self.get_field(dns_layer, "dns_resp_name", "") or "")
            resp_ttl = str(self.get_field(dns_layer, "dns_resp_ttl", "") or "")
            ip_addr = str(aaaa_records)
            dedup_key = f"AAAA:{resp_name}:{ip_addr}"
            if dedup_key not in self._seen_records:
                self._seen_records.add(dedup_key)
                hostname = resp_name.rstrip(".")

                now = datetime.now().isoformat()
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "response",
                    "mDNS AAAA Record",
                    {
                        "record_type": "AAAA",
                        "name": hostname,
                        "data": ip_addr,
                        "ttl": resp_ttl,
                    },
                    f"mDNS AAAA {hostname} -> {ip_addr}",
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                )

                self._create_device_from_record(ip_addr, hostname, src_mac, "AAAA")

        # PTR records (service pointers)
        ptr_name = self.get_field(dns_layer, "dns_ptr_domain_name", None)
        if ptr_name is not None:
            resp_name = str(self.get_field(dns_layer, "dns_resp_name", "") or "")
            resp_ttl = str(self.get_field(dns_layer, "dns_resp_ttl", "") or "")
            ptr_target = str(ptr_name).rstrip(".")
            service_type = resp_name.rstrip(".")
            dedup_key = f"PTR:{service_type}:{ptr_target}"
            if dedup_key not in self._seen_records:
                self._seen_records.add(dedup_key)

                now = datetime.now().isoformat()
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "response",
                    "mDNS PTR Record",
                    {
                        "record_type": "PTR",
                        "name": service_type,
                        "data": ptr_target,
                        "ttl": resp_ttl,
                    },
                    f"mDNS PTR {service_type} -> {ptr_target}",
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                )

                self.services[ptr_target] = {
                    "type": service_type,
                    "name": ptr_target,
                    "src_ip": src_ip,
                }

        # SRV records (service location)
        srv_port = self.get_field(dns_layer, "dns_srv_port", None)
        if srv_port is not None:
            resp_name = str(self.get_field(dns_layer, "dns_resp_name", "") or "")
            resp_ttl = str(self.get_field(dns_layer, "dns_resp_ttl", "") or "")
            srv_target = str(self.get_field(dns_layer, "dns_srv_target", "") or "").rstrip(".")
            port_str = str(srv_port)
            service_name = resp_name.rstrip(".")
            dedup_key = f"SRV:{service_name}:{srv_target}:{port_str}"
            if dedup_key not in self._seen_records:
                self._seen_records.add(dedup_key)

                now = datetime.now().isoformat()
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "response",
                    "mDNS SRV Record",
                    {
                        "record_type": "SRV",
                        "name": service_name,
                        "data": f"{srv_target}:{port_str}",
                        "ttl": resp_ttl,
                    },
                    f"mDNS SRV {service_name} -> {srv_target}:{port_str}",
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                )

                if service_name in self.services:
                    self.services[service_name]["target"] = srv_target
                    self.services[service_name]["port"] = port_str

        # TXT records (service properties)
        txt_data = self.get_field(dns_layer, "dns_txt", None)
        if txt_data is not None:
            resp_name = str(self.get_field(dns_layer, "dns_resp_name", "") or "")
            resp_ttl = str(self.get_field(dns_layer, "dns_resp_ttl", "") or "")
            txt_str = str(txt_data)
            service_name = resp_name.rstrip(".")
            dedup_key = f"TXT:{service_name}:{txt_str}"
            if dedup_key not in self._seen_records:
                self._seen_records.add(dedup_key)

                now = datetime.now().isoformat()
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "response",
                    "mDNS TXT Record",
                    {
                        "record_type": "TXT",
                        "name": service_name,
                        "data": txt_str,
                        "ttl": resp_ttl,
                    },
                    f"mDNS TXT {service_name} {txt_str}",
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                )

                if service_name in self.services:
                    self.services[service_name]["txt"] = txt_str

    def _process_queries(
        self,
        dns_layer,
        src_ip: str,
        dst_ip: str,
        src_mac: str,
        flow_id: str,
        src_port: int = 0,
        dst_port: int = 0,
    ) -> None:
        """Process DNS query records from mDNS query."""
        qry_name = self.get_field(dns_layer, "dns_qry_name", None)
        if qry_name is None:
            return

        qry_type = str(self.get_field(dns_layer, "dns_qry_type", "") or "")
        query_name = str(qry_name).rstrip(".")

        now = datetime.now().isoformat()
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            "mDNS Query",
            {
                "record_type": f"Query ({qry_type})",
                "name": query_name,
                "data": "",
                "ttl": "",
            },
            f"mDNS Query {query_name}",
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
        )

        # Track querier as a device
        if is_valid_discovered_ip(src_ip):
            device_key = src_mac if src_mac else f"mdns:{src_ip}"
            device, is_new = self._ensure_device(
                device_key,
                src_ip,
                mac=src_mac if src_mac else "",
            )
            if is_new:
                device.mdns_data = {
                    "querier": True,
                    "protocol": "mDNS/UDP",
                }

    def _create_device_from_record(
        self,
        ip_addr: str,
        hostname: str,
        src_mac: str,
        record_type: str,
    ) -> None:
        """Create a discovered device from an address record."""
        if not is_valid_discovered_ip(ip_addr):
            return

        device_key = src_mac if src_mac else f"mdns:{ip_addr}"
        device, is_new = self._ensure_device(
            device_key,
            ip_addr,
            mac=src_mac if src_mac else "",
            name=hostname,
        )
        if is_new:
            device.mdns_data = {
                "hostname": hostname,
                "services": [],
                "protocol": "mDNS/UDP",
                "record_type": record_type,
            }
            self.logger.debug(f"mDNS: {ip_addr} -> {hostname}")

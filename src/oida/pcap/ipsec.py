"""
IPsec/IKE Passive Listener for VPN infrastructure discovery.

Passively captures ISAKMP/IKE traffic to extract:
- IKE version (v1, v2)
- Exchange types (Main Mode, Aggressive Mode, Quick Mode, etc.)
- Vendor IDs revealing VPN product identification
- Crypto proposals (encryption, hash, DH group, key length)
- Certificate data when available
- NAT-T detection (port 4500)

IPsec/IKE is security-relevant because:
- Aggressive mode leaks PSK hashes that can be cracked offline
- Vendor IDs fingerprint VPN gateway products
- Weak crypto proposals reveal misconfiguration
- Certificate data may contain organizational info

tshark fields used (packet.isakmp.*):
- isakmp.version: IKE version
- isakmp.exchtype: Exchange type code
- isakmp.flags: ISAKMP flags
- isakmp.vendorid: Vendor ID payload
- isakmp.tf.attr.life_type: SA lifetime type
- isakmp.tf.attr.key_length: Proposed key length
- isakmp.cert.data: Certificate payload data
- isakmp.ispi / isakmp.rspi: Initiator/Responder SPIs
- isakmp.nextpayload: Next payload type
- isakmp.length: ISAKMP message length
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from oida.pcap.pyshark_base import ProtocolInteraction, PySharkListenerBase
from oida.protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

# IKE exchange types
EXCHANGE_TYPES = {
    "0": "NONE",
    "1": "Base",
    "2": "Identity Protection (Main Mode)",
    "3": "Authentication Only",
    "4": "Aggressive",
    "5": "Informational",
    "32": "Quick Mode",
    "33": "New Group Mode",
    # IKEv2 exchange types
    "34": "IKE_SA_INIT",
    "35": "IKE_AUTH",
    "36": "CREATE_CHILD_SA",
    "37": "INFORMATIONAL_V2",
}

# Short exchange type names for display
EXCHANGE_SHORT = {
    "0": "NONE",
    "1": "Base",
    "2": "Main",
    "3": "AuthOnly",
    "4": "Aggressive",
    "5": "Info",
    "32": "Quick",
    "33": "NewGroup",
    "34": "SA_INIT",
    "35": "AUTH",
    "36": "CHILD_SA",
    "37": "INFO_V2",
}

# Well-known Vendor IDs (partial list, first 8 bytes of hash)
WELL_KNOWN_VENDOR_IDS = {
    "4048b7d56ebce885": "RFC 3947 NAT-T",
    "90cb80913ebb696e": "draft-ietf-ipsec-nat-t-ike-02",
    "7d9419a65310ca6f": "draft-ietf-ipsec-nat-t-ike-03",
    "cd60464335df21f8": "draft-ietf-ipsec-nat-t-ike-08",
    "afcad71368a1f1c9": "Dead Peer Detection (DPD)",
    "4a131c81070358455c5728f20e95452f": "Cisco Unity",
    "1f07f70eaa6514d3b0fa96542a500100": "Cisco IOS",
    "12f5f28c457168a9702d9fe274cc0100": "Cisco VPN3000",
    "09002689dfd6b712": "XAUTH",
    "7d94dc207d56a8e7": "Fortigate",
    "4485152d18b6bbcd": "strongSwan",
    "882fe56d60560647": "Microsoft Windows 2000",
    "621b04bb098944d2": "Microsoft Windows Vista",
    "1e2b516905991c7d7c96fcbfb587e461": "Microsoft Windows 7/2008 R2",
    "fb1de3cdf341b7ea": "Microsoft Windows 8/2012",
}

# Payload types
PAYLOAD_TYPES = {
    "0": "NONE",
    "1": "SA",
    "2": "Proposal",
    "3": "Transform",
    "4": "Key Exchange",
    "5": "ID",
    "6": "Certificate",
    "7": "Certificate Request",
    "8": "Hash",
    "9": "Signature",
    "10": "Nonce",
    "11": "Notification",
    "12": "Delete",
    "13": "Vendor ID",
}


class IPsecPassiveListener(PySharkListenerBase):
    """Passive IPsec/IKE traffic listener for VPN infrastructure discovery.

    Captures ISAKMP/IKE traffic to extract:
    - IKE version and exchange type
    - Vendor IDs for VPN product fingerprinting
    - Crypto proposals (key length, algorithms)
    - Aggressive mode detection (PSK hash exposure)
    - NAT-T traversal indicators

    Usage:
        listener = IPsecPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for ix in listener.interactions:
            print(f"{ix.operation}: {ix.details}")
    """

    PROTOCOL_NAME = "ipsec"
    DISPLAY_FILTER = "isakmp"
    REQUIRED_LAYERS = ("isakmp",)
    PROTOCOL_COLUMNS = ("version", "exchange", "spi", "vendor_detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        # Track vendor IDs per endpoint
        self.vendor_ids: Dict[str, List[str]] = {}  # ip -> list of vendor names
        # Track Aggressive Mode flows (PSK hash exposure) for harvest alerts
        self._aggressive_flows: List[tuple] = []  # (src_ip, dst_ip)
        # Track the initiator IP per ISPI. The IKE initiator SPI is chosen
        # once by the initiator and stays constant for the entire exchange
        # (SA_INIT through IKE_AUTH/CREATE_CHILD_SA/INFORMATIONAL); rspi is
        # only all-zero on message 1, so it can't be used to tell requests
        # from responses beyond that single packet.
        self._initiator_by_ispi: Dict[str, str] = {}

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format IPsec/IKE interaction as protocol-specific table columns."""
        d = ix.details
        version = d.get("ike_version", "?")
        exchange = d.get("exchange_short", d.get("exchange_type_name", "?"))
        spi = d.get("initiator_spi", "") or "-"
        vendor = d.get("vendor_name", "") or d.get("key_length", "") or "-"
        return [version, exchange, spi, vendor]

    def process_packet(self, packet) -> None:
        """Process ISAKMP/IKE packet and extract version, exchange, and vendor info."""
        if not hasattr(packet, "isakmp"):
            return

        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        isakmp = packet.isakmp
        flow_id = self.get_flow_id(packet)
        stream_id = self.get_stream_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)

        # IKE version -- tshark uses isakmp.version (combined byte),
        # isakmp.mjver (major), isakmp.mnver (minor).  mjver is BASE_HEX:
        # pyshark renders it as "0x01"/"0x02" in XML mode (the live-capture
        # path) and as the int 1/2 in EK mode, so normalize through
        # _parse_int() instead of trusting the raw rendering.
        mjver = self.get_field(isakmp, "mjver", None)
        if mjver is not None:
            mjver_int = self._parse_int(mjver, None)
            ike_version = f"v{mjver_int}" if mjver_int is not None else f"v{mjver}"
        else:
            version_raw = self.get_field(isakmp, "version", None)
            if version_raw is not None:
                ver_str = str(version_raw)
                # IKEv1 has version 1.0 (0x10), IKEv2 has version 2.0 (0x20)
                if ver_str in ("16", "0x10", "1.0"):
                    ike_version = "v1"
                elif ver_str in ("32", "0x20", "2.0"):
                    ike_version = "v2"
                else:
                    ike_version = f"v{ver_str}"
            else:
                ike_version = "?"

        # Exchange type -- tshark field is isakmp.exchangetype
        exchtype_raw = self.get_field(isakmp, "exchangetype", None)
        if exchtype_raw is None:
            exchtype_raw = self.get_field(isakmp, "exchtype", None)
        exchtype_str = str(exchtype_raw) if exchtype_raw is not None else ""
        exchange_name = EXCHANGE_TYPES.get(exchtype_str, exchtype_str)
        exchange_short = EXCHANGE_SHORT.get(exchtype_str, exchtype_str)

        # SPIs
        ispi = str(self.get_field(isakmp, "ispi", "") or "")
        rspi = str(self.get_field(isakmp, "rspi", "") or "")

        # Determine direction. rspi is all-zero only on message 1 (SA_INIT
        # request); every later message in the exchange carries a populated
        # rspi, so that alone can't distinguish initiator requests from
        # responder responses past msg 1. Key on ispi instead -- it is
        # assigned once by the initiator and stays constant for the whole
        # exchange, so the endpoint that sent the all-zero-rspi packet (or,
        # failing that, whichever endpoint is seen first for this ispi when
        # capture starts mid-exchange) is the initiator for every later
        # message sharing that ispi.
        rspi_is_zero = rspi in ("", "0000000000000000", "00:00:00:00:00:00:00:00")
        if ispi:
            if rspi_is_zero or ispi not in self._initiator_by_ispi:
                self._initiator_by_ispi[ispi] = src_ip
            is_initiator = src_ip == self._initiator_by_ispi[ispi]
        else:
            is_initiator = rspi_is_zero
        direction = "request" if is_initiator else "response"

        # Flags
        flags = self.get_field(isakmp, "flags", None)
        flags_str = str(flags) if flags is not None else ""

        # Message length
        msg_length = self.get_field(isakmp, "length", None)
        msg_length_str = str(msg_length) if msg_length is not None else ""

        # Next payload
        next_payload = self.get_field(isakmp, "nextpayload", None)
        next_payload_str = str(next_payload) if next_payload is not None else ""
        next_payload_name = PAYLOAD_TYPES.get(next_payload_str, next_payload_str)

        # Vendor ID -- tshark uses isakmp.vid_bytes (hex) or isakmp.vid_string
        vendor_id = str(self.get_field(isakmp, "vid_bytes", "") or "")
        if not vendor_id:
            vendor_id = str(self.get_field(isakmp, "vendorid", "") or "")
        vendor_name = ""
        if vendor_id:
            vendor_clean = vendor_id.replace(":", "").lower()
            for known_id, known_name in WELL_KNOWN_VENDOR_IDS.items():
                if vendor_clean.startswith(known_id):
                    vendor_name = known_name
                    break
            if not vendor_name:
                vendor_name = f"Unknown ({vendor_clean})"

            # Track vendor per source IP
            if src_ip not in self.vendor_ids:
                self.vendor_ids[src_ip] = []
            if vendor_name not in self.vendor_ids[src_ip]:
                self.vendor_ids[src_ip].append(vendor_name)

        # Key length from transform attributes
        # tshark: isakmp.ike.attr.key_length or ike.attr.key_length
        key_length = self.get_field(isakmp, "ike_attr_key_length", None)
        if key_length is None:
            key_length = self.get_field(isakmp, "tf_attr_key_length", None)
        if key_length is None:
            key_length = self.get_field(isakmp, "attr_key_length", None)
        key_length_str = str(key_length) if key_length is not None else ""

        # Life type -- tshark: isakmp.ike.attr.life_type
        life_type = self.get_field(isakmp, "ike_attr_life_type", None)
        if life_type is None:
            life_type = self.get_field(isakmp, "tf_attr_life_type", None)
        if life_type is None:
            life_type = self.get_field(isakmp, "attr_life_type", None)
        life_type_str = str(life_type) if life_type is not None else ""

        # Encryption and hash algorithms from proposals
        enc_algo = self.get_field(isakmp, "ike_attr_encryption_algorithm", None)
        hash_algo = self.get_field(isakmp, "ike_attr_hash_algorithm", None)
        auth_method_ike = self.get_field(isakmp, "ike_attr_authentication_method", None)
        dh_group = self.get_field(isakmp, "ike_attr_group_description", None)

        # Build details
        details: Dict[str, Any] = {
            "ike_version": ike_version,
            "exchange_type": exchtype_str,
            "exchange_type_name": exchange_name,
            "exchange_short": exchange_short,
            "initiator_spi": ispi,
            "responder_spi": rspi,
            "flags": flags_str,
            "msg_length": msg_length_str,
            "next_payload": next_payload_str,
            "next_payload_name": next_payload_name,
        }
        if vendor_id:
            details["vendor_id"] = vendor_id
            details["vendor_name"] = vendor_name
        if key_length_str:
            details["key_length"] = key_length_str
        if life_type_str:
            details["life_type"] = life_type_str
        if enc_algo is not None:
            details["encryption_algorithm"] = str(enc_algo)
        if hash_algo is not None:
            details["hash_algorithm"] = str(hash_algo)
        if auth_method_ike is not None:
            details["auth_method"] = str(auth_method_ike)
        if dh_group is not None:
            details["dh_group"] = str(dh_group)

        # Build operation and summary
        operation = f"IKE {ike_version} {exchange_short}"
        summary = operation
        if vendor_name:
            summary += f" Vendor={vendor_name}"
        if key_length_str:
            summary += f" KeyLen={key_length_str}"

        now = datetime.now().isoformat()
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            operation,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Flag aggressive mode as security concern. Record the flow so harvest()
        # surfaces it as a structured alert that reaches the scanner pipeline
        # (not just a log line that never makes it into results/exports).
        if exchange_short == "Aggressive":
            pair = (src_ip, dst_ip)
            if pair not in self._aggressive_flows:
                self._aggressive_flows.append(pair)
            self.logger.debug(
                f"IKE Aggressive Mode detected: {src_ip} -> {dst_ip} (PSK hash may be captured)"
            )

        # Create device entries
        if is_initiator:
            initiator_ip, responder_ip = src_ip, dst_ip
            initiator_mac, responder_mac = src_mac, dst_mac
        else:
            initiator_ip, responder_ip = dst_ip, src_ip
            initiator_mac, responder_mac = dst_mac, src_mac

        if is_valid_discovered_ip(responder_ip):
            resp_vendor = lookup_mac_vendor(responder_mac) if responder_mac else ""
            device, is_new = self._ensure_device(
                f"ipsec-responder:{responder_ip}",
                responder_ip,
                mac=responder_mac or "",
                device_type="IPsec VPN Gateway",
                manufacturer=resp_vendor if resp_vendor != "Unknown" else "",
            )
            if is_new:
                device.ipsec_passive_data = {
                    "role": "responder",
                    "ike_version": ike_version,
                    "protocol": "IKE/UDP",
                    "exchanges_seen": [],
                }
            if hasattr(device, "ipsec_passive_data") and device.ipsec_passive_data:
                exchanges = device.ipsec_passive_data.get("exchanges_seen", [])
                if exchange_short and exchange_short not in exchanges:
                    exchanges.append(exchange_short)
                    device.ipsec_passive_data["exchanges_seen"] = exchanges

        if is_valid_discovered_ip(initiator_ip):
            init_vendor = lookup_mac_vendor(initiator_mac) if initiator_mac else ""
            device, is_new = self._ensure_device(
                f"ipsec-initiator:{initiator_ip}",
                initiator_ip,
                mac=initiator_mac or "",
                device_type="IPsec Client",
                manufacturer=init_vendor if init_vendor != "Unknown" else "",
            )
            if is_new:
                device.ipsec_passive_data = {
                    "role": "initiator",
                    "ike_version": ike_version,
                    "protocol": "IKE/UDP",
                    "exchanges_seen": [],
                }

        self.logger.debug(
            f"IKE: {ike_version} {exchange_short} {src_ip} -> {dst_ip} "
            f"(ispi={ispi if ispi else '?'})"
        )

    def harvest(self) -> Dict[str, Any]:
        """Return structured harvest data including vendor ID tables + alerts."""
        base = super().harvest() or {}
        tables = base.get("tables", [])
        alerts = base.get("alerts", [])

        # Add vendor ID table
        vendor_rows = []
        for ip, vendors in self.vendor_ids.items():
            for v in vendors:
                vendor_rows.append([ip, v])
        if vendor_rows:
            tables.append(
                {
                    "title": "IKE Vendor IDs",
                    "headers": ["Endpoint", "Vendor ID"],
                    "rows": vendor_rows,
                }
            )

        # Aggressive Mode -> structured alert (PSK hash crackable offline)
        for src_ip, dst_ip in self._aggressive_flows:
            alerts.append(
                {
                    "level": "fail",
                    "category": "ike_aggressive_mode",
                    "message": (
                        f"IKE AGGRESSIVE MODE: {src_ip} -> {dst_ip} "
                        "(PSK hash exposed in handshake, crackable offline)"
                    ),
                }
            )

        if tables:
            base["tables"] = tables
        if alerts:
            base["alerts"] = alerts
        return base

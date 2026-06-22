"""
DNS passive discovery listener.

Contains:
- DNSPassiveListener: Passive DNS traffic monitoring for hostname resolution mapping.

Inspired by BruteShark's passive network analysis - extracts hostname/IP mappings
from DNS traffic without sending any packets.

Uses PyShark (tshark wrapper) for packet dissection with Wireshark's DNS dissector.
"""

from typing import Any, Dict, List, Optional

from datetime import datetime

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip

# DNS record types
DNS_TYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    35: "NAPTR",
    44: "SSHFP",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    65: "HTTPS",
    249: "TKEY",
    250: "TSIG",
}


# Human-readable opcode names
DNS_OPCODE_NAMES = {
    0: "Query",
    1: "IQuery",
    2: "Status",
    4: "Notify",
    5: "Update",
}

# Human-readable RCODE names
DNS_RCODE_NAMES = {
    0: "No Error",
    1: "Format Error",
    2: "Server Failure",
    3: "Name Error (NXDOMAIN)",
    4: "Not Implemented",
    5: "Refused",
    6: "YXDomain",
    7: "YXRRSet",
    8: "NXRRSet",
    9: "NotAuth",
    10: "NotZone",
}


class DNSPassiveListener(PySharkListenerBase):
    """Passive DNS traffic listener using PyShark.

    Captures DNS queries and responses to build:
    - Hostname to IP address mappings (from A/AAAA records)
    - Reverse DNS mappings (from PTR records)
    - Alias mappings (from CNAME records)
    - DNS server identification

    Use cases:
    - Asset discovery via observed DNS traffic
    - Internal hostname enumeration
    - Network topology mapping
    - DNS server identification

    Usage:
        # Live capture
        listener = DNSPassiveListener(interface="eth0", timeout=30)
        devices = listener.scan()

        # Testing - feed packets directly
        listener = DNSPassiveListener(interface="eth0")
        listener.feed_packet(mock_dns_packet)

    Data structure stored in device.dns_passive_data:
        {
            "role": "server" | "client",
            "queries": ["hostname1", "hostname2", ...],
            "responses": [{"query": "host", "type": "A", "answer": "1.2.3.4"}, ...],
            "hostname_mappings": {"hostname": ["ip1", "ip2"]},
            "protocol": "DNS/UDP",
        }
    """

    PROTOCOL_NAME = "dns"
    DISPLAY_FILTER = "dns"
    REQUIRED_LAYERS = ("dns",)

    PROTOCOL_COLUMNS = ("type", "query", "answer", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 30,
        nxc_logger: Optional[Any] = None,
    ):
        """Initialize DNS passive listener.

        Args:
            interface: Network interface to capture on
            timeout: Capture timeout in seconds
            nxc_logger: Optional NXC-style logger for user-visible output
        """
        super().__init__(
            interface=interface,
            timeout=timeout,
            nxc_logger=nxc_logger,
        )
        # Track hostname to IP mappings globally
        self.hostname_mappings: Dict[str, List[str]] = {}

        # Track DNS servers and clients
        self.dns_servers: Dict[str, Dict] = {}
        self.dns_clients: Dict[str, Dict] = {}

    def should_process_packet(self, packet) -> bool:
        """Check if packet has DNS layer."""
        return hasattr(packet, "dns")

    def _extract_common_fields(self, dns) -> Dict[str, Any]:
        """Extract common DNS header fields present in every packet.

        Returns a dict of non-None fields suitable for merging into
        interaction details.
        """
        fields: Dict[str, Any] = {}

        # Transaction ID
        tx_id = self.get_field(dns, "id")
        if tx_id is not None:
            fields["id"] = str(tx_id)

        # Opcode (0=Query, 5=Update, etc.)
        opcode = self.get_field(dns, "flags_opcode")
        if opcode is not None:
            opcode_int = int(opcode) if str(opcode).isdigit() else None
            fields["opcode"] = str(opcode)
            if opcode_int is not None and opcode_int in DNS_OPCODE_NAMES:
                fields["opcode_name"] = DNS_OPCODE_NAMES[opcode_int]

        # Query type (numeric)
        qry_type = self.get_field(dns, "qry_type")
        if qry_type is not None:
            fields["qry_type"] = str(qry_type)
            qry_type_int = int(qry_type) if str(qry_type).isdigit() else None
            if qry_type_int is not None and qry_type_int in DNS_TYPE_NAMES:
                fields["qry_type_name"] = DNS_TYPE_NAMES[qry_type_int]

        # Response code (rcode)
        rcode = self.get_field(dns, "flags_rcode")
        if rcode is not None:
            fields["rcode"] = str(rcode)
            rcode_int = int(rcode) if str(rcode).isdigit() else None
            if rcode_int is not None and rcode_int in DNS_RCODE_NAMES:
                fields["rcode_name"] = DNS_RCODE_NAMES[rcode_int]

        # Authoritative answer flag
        aa = self.get_field(dns, "flags_authoritative")
        if aa is not None:
            fields["authoritative"] = str(aa).lower() in ("1", "true")

        # Checking disabled (CD) flag -- DNSSEC
        cd = self.get_field(dns, "flags_checkdisable")
        if cd is not None:
            fields["check_disabled"] = str(cd).lower() in ("1", "true")

        # Number of authoritative (NS) records in the packet header. A
        # non-zero count on a response marks an authoritative delegation /
        # zone transfer, useful for spotting authoritative servers.
        auth_rr = self.get_field(dns, "count_auth_rr")
        if auth_rr is not None:
            fields["count_auth_rr"] = str(auth_rr)

        return fields

    def process_packet(self, packet) -> None:
        """Process DNS packet and extract hostname/IP mappings."""
        # Get source and destination IP
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)

        dns = packet.dns

        # Extract common header fields shared by queries and responses
        common = self._extract_common_fields(dns)

        # Check if this is a query (qr=0) or response (qr=1)
        # PyShark represents flags differently - check dns.flags_response
        is_response = self._is_response(dns)

        if is_response:
            # DNS response - source is the DNS server
            qry_name = self.get_field(dns, "qry_name")
            a_record = self.get_field(dns, "a")
            now = datetime.now().isoformat()
            answer = str(a_record) if a_record else ""

            # Build response details with common fields
            details: Dict[str, Any] = {
                "query": str(qry_name) if qry_name else "",
                "answer": answer,
            }
            details.update(common)

            # Response-specific fields
            resp_type = self.get_field(dns, "resp_type")
            if resp_type is not None:
                details["resp_type"] = str(resp_type)
            resp_ttl = self.get_field(dns, "resp_ttl")
            if resp_ttl is not None:
                details["resp_ttl"] = str(resp_ttl)

            # EDNS0 version (OPT pseudo-RR)
            edns0_ver = self.get_field(dns, "resp_edns0_version")
            if edns0_ver is not None:
                details["edns0_version"] = str(edns0_ver)

            summary = (
                f"DNS Response: {qry_name} -> {answer}" if answer else f"DNS Response: {qry_name}"
            )
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                "DNS Response",
                details,
                summary,
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
            )
            self._process_dns_response(dns, src_ip, dst_ip)
        else:
            # DNS query - source is the client
            qry_name = self.get_field(dns, "qry_name")
            now = datetime.now().isoformat()

            details_q: Dict[str, Any] = {
                "query": str(qry_name) if qry_name else "",
            }
            details_q.update(common)

            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request",
                "DNS Query",
                details_q,
                f"DNS Query: {qry_name}" if qry_name else "DNS Query",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
            )
            self._process_dns_query(dns, src_ip, dst_ip)

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format a DNS interaction as protocol-specific table columns."""
        d = ix.details
        query = str(d.get("query", ""))
        qry_type_name = str(d.get("qry_type_name", ""))

        if ix.direction == "request":
            detail = str(d.get("opcode_name", ""))
            return [qry_type_name, query, "", detail]
        else:
            answer = str(d.get("answer", ""))
            rcode_name = d.get("rcode_name")
            resp_ttl = d.get("resp_ttl")
            if rcode_name:
                detail = str(rcode_name)
            elif resp_ttl:
                detail = f"TTL {resp_ttl}"
            else:
                detail = ""
            return [qry_type_name, query, answer, detail]

    def _is_response(self, dns) -> bool:
        """Check if DNS packet is a response.

        Args:
            dns: PyShark DNS layer

        Returns:
            True if response, False if query
        """
        # PyShark uses flags_response field - can be bool True/False or string "1"/"0"/"True"/"False"
        flags_response = self.get_field(dns, "flags_response")
        if flags_response is not None:
            val = str(flags_response).lower()
            return val in ("1", "true")

        # Fallback: check qr field directly
        qr = self.get_field(dns, "qr")
        if qr is not None:
            val = str(qr).lower()
            return val in ("1", "true")

        # If we have answers, it's likely a response
        return self.get_field(dns, "a") is not None or self.get_field(dns, "aaaa") is not None

    def _process_dns_query(self, dns, client_ip: str, server_ip: str) -> None:
        """Process DNS query packet (qr=0).

        Args:
            dns: PyShark DNS layer
            client_ip: Source IP (client making query)
            server_ip: Destination IP (DNS server)
        """
        queries = []

        # Get query name(s) from PyShark
        qry_name = self.get_field(dns, "qry_name")
        if qry_name:
            name = self._clean_name(str(qry_name))
            if name:
                queries.append(name)

        if not queries:
            return

        if not is_valid_discovered_ip(client_ip):
            return

        # Track the DNS client
        device_key = f"dns:{client_ip}"

        device, is_new = self._ensure_device(
            device_key,
            client_ip,
            device_type="DNS Client",
        )
        if is_new:
            device.dns_passive_data = {
                "role": "client",
                "queries": queries,
                "responses": [],
                "hostname_mappings": {},
                "protocol": "DNS/UDP",
            }

            # Track in clients dict
            self.dns_clients[client_ip] = {
                "first_seen": self._get_timestamp(),
                "query_count": len(queries),
            }

            self.logger.debug(f"DNS: Client {client_ip} queried {queries}")
        else:
            if device.dns_passive_data:
                # Add new queries
                for q in queries:
                    if q not in device.dns_passive_data["queries"]:
                        device.dns_passive_data["queries"].append(q)

                # Update client tracking
                if client_ip in self.dns_clients:
                    self.dns_clients[client_ip]["query_count"] += len(queries)

    def _process_dns_response(self, dns, server_ip: str, client_ip: str) -> None:
        """Process DNS response packet (qr=1).

        Args:
            dns: PyShark DNS layer
            server_ip: Source IP (DNS server sending response)
            client_ip: Destination IP (client receiving response)
        """
        responses = []
        hostname_mappings: Dict[str, List[str]] = {}

        # Parse A records (IPv4)
        self._parse_a_records(dns, responses, hostname_mappings)

        # Parse AAAA records (IPv6)
        self._parse_aaaa_records(dns, responses, hostname_mappings)

        # Parse PTR records (reverse DNS)
        self._parse_ptr_records(dns, responses, hostname_mappings)

        # Parse CNAME records (aliases)
        self._parse_cname_records(dns, responses)

        # Parse MX records (mail exchange)
        self._parse_mx_records(dns, responses)

        # Parse NS records (name server)
        self._parse_ns_records(dns, responses)

        # Parse SOA records (start of authority)
        self._parse_soa_records(dns, responses)

        # Parse TSIG records (transaction signature)
        self._parse_tsig_records(dns, responses)

        # Parse TKEY records (transaction key)
        self._parse_tkey_records(dns, responses)

        # Parse RRSIG records (DNSSEC)
        self._parse_rrsig_records(dns, responses)

        # Parse NSEC records (DNSSEC)
        self._parse_nsec_records(dns, responses)

        # Parse SVCB/HTTPS records
        self._parse_svcb_records(dns, responses)

        # Parse NAPTR records
        self._parse_naptr_records(dns, responses)

        # Parse LOC records
        self._parse_loc_records(dns, responses)

        if not responses:
            return

        # Update global hostname mappings
        with self._lock:
            for hostname, ips in hostname_mappings.items():
                if hostname not in self.hostname_mappings:
                    self.hostname_mappings[hostname] = []
                for ip in ips:
                    if ip not in self.hostname_mappings[hostname]:
                        self.hostname_mappings[hostname].append(ip)

        # Track the DNS server
        if not is_valid_discovered_ip(server_ip):
            return

        device_key = f"dns:{server_ip}"

        device, is_new = self._ensure_device(
            device_key,
            server_ip,
            device_type="DNS Server",
        )
        if is_new:
            device.dns_passive_data = {
                "role": "server",
                "queries": [],
                "responses": responses,
                "hostname_mappings": hostname_mappings,
                "protocol": "DNS/UDP",
            }

            # Track in servers dict
            self.dns_servers[server_ip] = {
                "first_seen": self._get_timestamp(),
                "response_count": len(responses),
            }

            self.logger.debug(f"DNS: Server {server_ip} with {len(responses)} responses")
        else:
            # Ensure role is server if we see responses
            if device.dns_passive_data:
                if device.dns_passive_data["role"] != "server":
                    device.dns_passive_data["role"] = "server"
                    device.device_type = "DNS Server"

                # Add new responses
                device.dns_passive_data["responses"].extend(responses)

                # Merge hostname mappings
                for hostname, ips in hostname_mappings.items():
                    if hostname not in device.dns_passive_data["hostname_mappings"]:
                        device.dns_passive_data["hostname_mappings"][hostname] = []
                    for ip in ips:
                        if ip not in device.dns_passive_data["hostname_mappings"][hostname]:
                            device.dns_passive_data["hostname_mappings"][hostname].append(ip)

            # Update server tracking
            if server_ip in self.dns_servers:
                self.dns_servers[server_ip]["response_count"] += len(responses)

    def _get_ttl(self, dns) -> Optional[str]:
        """Get response TTL if available."""
        ttl = self.get_field(dns, "resp_ttl")
        return str(ttl) if ttl is not None else None

    def _parse_a_records(
        self,
        dns,
        responses: List[Dict],
        hostname_mappings: Dict[str, List[str]],
    ) -> None:
        """Parse A records (IPv4 addresses) from DNS response."""
        resp_name = self.get_field(dns, "resp_name")
        a_record = self.get_field(dns, "a")

        if resp_name and a_record:
            rrname = self._clean_name(str(resp_name))
            answer = str(a_record)
            rec: Dict[str, Any] = {
                "query": rrname,
                "type": "A",
                "answer": answer,
            }
            ttl = self._get_ttl(dns)
            if ttl is not None:
                rec["ttl"] = ttl
            responses.append(rec)
            if rrname not in hostname_mappings:
                hostname_mappings[rrname] = []
            if answer not in hostname_mappings[rrname]:
                hostname_mappings[rrname].append(answer)
            self.logger.debug(f"DNS: A record {rrname} -> {answer}")

    def _parse_aaaa_records(
        self,
        dns,
        responses: List[Dict],
        hostname_mappings: Dict[str, List[str]],
    ) -> None:
        """Parse AAAA records (IPv6 addresses) from DNS response."""
        resp_name = self.get_field(dns, "resp_name")
        aaaa_record = self.get_field(dns, "aaaa")

        if resp_name and aaaa_record:
            rrname = self._clean_name(str(resp_name))
            answer = str(aaaa_record)
            rec: Dict[str, Any] = {
                "query": rrname,
                "type": "AAAA",
                "answer": answer,
            }
            ttl = self._get_ttl(dns)
            if ttl is not None:
                rec["ttl"] = ttl
            responses.append(rec)
            if rrname not in hostname_mappings:
                hostname_mappings[rrname] = []
            if answer not in hostname_mappings[rrname]:
                hostname_mappings[rrname].append(answer)
            self.logger.debug(f"DNS: AAAA record {rrname} -> {answer}")

    def _parse_ptr_records(
        self,
        dns,
        responses: List[Dict],
        hostname_mappings: Dict[str, List[str]],
    ) -> None:
        """Parse PTR records (reverse DNS) from DNS response."""
        ptr_record = self.get_field(dns, "ptr_domain_name")
        qry_name = self.get_field(dns, "qry_name")

        if ptr_record:
            rrname = self._clean_name(str(qry_name)) if qry_name else ""
            answer = self._clean_name(str(ptr_record))
            rec: Dict[str, Any] = {
                "query": rrname,
                "type": "PTR",
                "answer": answer,
            }
            ttl = self._get_ttl(dns)
            if ttl is not None:
                rec["ttl"] = ttl
            responses.append(rec)
            ip_from_ptr = self._ptr_to_ip(rrname)
            if ip_from_ptr and answer:
                if answer not in hostname_mappings:
                    hostname_mappings[answer] = []
                if ip_from_ptr not in hostname_mappings[answer]:
                    hostname_mappings[answer].append(ip_from_ptr)
            self.logger.debug(f"DNS: PTR record {rrname} -> {answer}")

    def _parse_cname_records(
        self,
        dns,
        responses: List[Dict],
    ) -> None:
        """Parse CNAME records (aliases) from DNS response."""
        cname_record = self.get_field(dns, "cname")
        resp_name = self.get_field(dns, "resp_name")

        if cname_record:
            rrname = self._clean_name(str(resp_name)) if resp_name else ""
            answer = self._clean_name(str(cname_record))
            rec: Dict[str, Any] = {
                "query": rrname,
                "type": "CNAME",
                "answer": answer,
            }
            ttl = self._get_ttl(dns)
            if ttl is not None:
                rec["ttl"] = ttl
            responses.append(rec)
            self.logger.debug(f"DNS: CNAME record {rrname} -> {answer}")

    def _parse_mx_records(
        self,
        dns,
        responses: List[Dict],
    ) -> None:
        """Parse MX records (mail exchange) from DNS response."""
        mx_exchange = self.get_field(dns, "mx_mail_exchange")
        mx_pref = self.get_field(dns, "mx_preference")

        if mx_exchange:
            exchange = self._clean_name(str(mx_exchange))
            rec: Dict[str, Any] = {
                "query": self._clean_name(str(self.get_field(dns, "resp_name") or "")),
                "type": "MX",
                "answer": exchange,
            }
            if mx_pref is not None:
                rec["preference"] = str(mx_pref)
            ttl = self._get_ttl(dns)
            if ttl is not None:
                rec["ttl"] = ttl
            responses.append(rec)
            self.logger.debug(f"DNS: MX record -> {exchange} (pref {mx_pref})")

    def _parse_ns_records(
        self,
        dns,
        responses: List[Dict],
    ) -> None:
        """Parse NS records (name server) from DNS response."""
        ns_record = self.get_field(dns, "ns")
        if ns_record:
            ns_name = self._clean_name(str(ns_record))
            rec: Dict[str, Any] = {
                "query": self._clean_name(str(self.get_field(dns, "resp_name") or "")),
                "type": "NS",
                "answer": ns_name,
            }
            ttl = self._get_ttl(dns)
            if ttl is not None:
                rec["ttl"] = ttl
            responses.append(rec)
            self.logger.debug(f"DNS: NS record -> {ns_name}")

    def _parse_soa_records(
        self,
        dns,
        responses: List[Dict],
    ) -> None:
        """Parse SOA records (start of authority) from DNS response."""
        soa_mname = self.get_field(dns, "soa_mname")
        soa_rname = self.get_field(dns, "soa_rname")

        if soa_mname or soa_rname:
            rec: Dict[str, Any] = {
                "query": self._clean_name(str(self.get_field(dns, "resp_name") or "")),
                "type": "SOA",
                "answer": self._clean_name(str(soa_mname)) if soa_mname else "",
            }
            if soa_mname:
                rec["mname"] = self._clean_name(str(soa_mname))
            if soa_rname:
                rec["rname"] = self._clean_name(str(soa_rname))
            # Email-form of the responsible-party name (first label becomes
            # the local part) -- the zone admin contact.
            soa_rname_email = self.get_field(dns, "soa_rname_name")
            if soa_rname_email:
                rec["rname_email"] = self._clean_name(str(soa_rname_email))
            ttl = self._get_ttl(dns)
            if ttl is not None:
                rec["ttl"] = ttl
            responses.append(rec)
            self.logger.debug(f"DNS: SOA record mname={soa_mname} rname={soa_rname}")

    def _parse_tsig_records(
        self,
        dns,
        responses: List[Dict],
    ) -> None:
        """Parse TSIG records (transaction signature) from DNS response."""
        tsig_algo = self.get_field(dns, "tsig_algorithm_name")
        tsig_error = self.get_field(dns, "tsig_error")

        if tsig_algo is not None or tsig_error is not None:
            rec: Dict[str, Any] = {
                "query": self._clean_name(str(self.get_field(dns, "resp_name") or "")),
                "type": "TSIG",
                "answer": self._clean_name(str(tsig_algo)) if tsig_algo else "",
            }
            if tsig_algo:
                rec["algorithm"] = self._clean_name(str(tsig_algo))
            if tsig_error is not None:
                rec["error"] = str(tsig_error)
            # Original transaction ID the TSIG signs over (dynamic update /
            # TKEY correlation key).
            tsig_orig_id = self.get_field(dns, "tsig_original_id")
            if tsig_orig_id is not None:
                rec["original_id"] = str(tsig_orig_id)
            responses.append(rec)
            self.logger.debug(f"DNS: TSIG algo={tsig_algo} error={tsig_error}")

    def _parse_tkey_records(
        self,
        dns,
        responses: List[Dict],
    ) -> None:
        """Parse TKEY records (transaction key) from DNS response."""
        tkey_algo = self.get_field(dns, "tkey_algo_name")
        tkey_error = self.get_field(dns, "tkey_error")

        if tkey_algo is not None or tkey_error is not None:
            rec: Dict[str, Any] = {
                "query": self._clean_name(str(self.get_field(dns, "resp_name") or "")),
                "type": "TKEY",
                "answer": self._clean_name(str(tkey_algo)) if tkey_algo else "",
            }
            if tkey_algo:
                rec["algorithm"] = self._clean_name(str(tkey_algo))
            if tkey_error is not None:
                rec["error"] = str(tkey_error)
            responses.append(rec)
            self.logger.debug(f"DNS: TKEY algo={tkey_algo} error={tkey_error}")

    def _parse_rrsig_records(
        self,
        dns,
        responses: List[Dict],
    ) -> None:
        """Parse RRSIG records (DNSSEC signatures) from DNS response."""
        signers_name = self.get_field(dns, "rrsig_signers_name")
        if signers_name:
            rec: Dict[str, Any] = {
                "query": self._clean_name(str(self.get_field(dns, "resp_name") or "")),
                "type": "RRSIG",
                "answer": self._clean_name(str(signers_name)),
            }
            rrsig_labels = self.get_field(dns, "rrsig_labels")
            if rrsig_labels is not None:
                rec["labels"] = str(rrsig_labels)
            rrsig_orig_ttl = self.get_field(dns, "rrsig_original_ttl")
            if rrsig_orig_ttl is not None:
                rec["original_ttl"] = str(rrsig_orig_ttl)
            responses.append(rec)
            self.logger.debug(f"DNS: RRSIG signer={signers_name}")

    def _parse_nsec_records(
        self,
        dns,
        responses: List[Dict],
    ) -> None:
        """Parse NSEC records (DNSSEC authenticated denial) from DNS response."""
        next_domain = self.get_field(dns, "nsec_next_domain_name")
        if next_domain:
            rec: Dict[str, Any] = {
                "query": self._clean_name(str(self.get_field(dns, "resp_name") or "")),
                "type": "NSEC",
                "answer": self._clean_name(str(next_domain)),
            }
            responses.append(rec)
            self.logger.debug(f"DNS: NSEC next_domain={next_domain}")

    def _parse_svcb_records(
        self,
        dns,
        responses: List[Dict],
    ) -> None:
        """Parse SVCB/HTTPS records from DNS response."""
        target = self.get_field(dns, "svcb_targetname")
        if target:
            target_clean = self._clean_name(str(target))
            # Skip <Root> placeholder targets
            if target_clean and target_clean != "<Root>":
                rec: Dict[str, Any] = {
                    "query": self._clean_name(str(self.get_field(dns, "resp_name") or "")),
                    "type": "SVCB",
                    "answer": target_clean,
                }
                responses.append(rec)
                self.logger.debug(f"DNS: SVCB target={target_clean}")

    def _parse_naptr_records(
        self,
        dns,
        responses: List[Dict],
    ) -> None:
        """Parse NAPTR records from DNS response."""
        naptr_service = self.get_field(dns, "naptr_service")
        if naptr_service:
            rec: Dict[str, Any] = {
                "query": self._clean_name(str(self.get_field(dns, "resp_name") or "")),
                "type": "NAPTR",
                "answer": str(naptr_service),
                "service": str(naptr_service),
            }
            responses.append(rec)
            self.logger.debug(f"DNS: NAPTR service={naptr_service}")

    def _parse_loc_records(
        self,
        dns,
        responses: List[Dict],
    ) -> None:
        """Parse LOC records (geographic location) from DNS response."""
        loc_version = self.get_field(dns, "loc_version")
        if loc_version is not None:
            rec: Dict[str, Any] = {
                "query": self._clean_name(str(self.get_field(dns, "resp_name") or "")),
                "type": "LOC",
                "answer": f"v{loc_version}",
                "version": str(loc_version),
            }
            responses.append(rec)
            self.logger.debug(f"DNS: LOC version={loc_version}")

    def _clean_name(self, name: str) -> str:
        """Clean DNS name by stripping trailing dot.

        Args:
            name: DNS name possibly with trailing dot

        Returns:
            Cleaned name without trailing dot
        """
        if not name:
            return ""
        return name.rstrip(".")

    def _ptr_to_ip(self, ptr_name: str) -> Optional[str]:
        """Extract IP address from PTR record name.

        Args:
            ptr_name: PTR record name (e.g., "1.0.168.192.in-addr.arpa")

        Returns:
            IP address string (e.g., "192.168.0.1") or None if invalid
        """
        try:
            ptr_name = ptr_name.lower().rstrip(".")

            # IPv4 reverse DNS
            if ptr_name.endswith(".in-addr.arpa"):
                # Remove suffix and reverse octets
                ip_part = ptr_name[: -len(".in-addr.arpa")]
                octets = ip_part.split(".")
                octets.reverse()
                if len(octets) == 4:
                    return ".".join(octets)

            # IPv6 reverse DNS (simplified)
            elif ptr_name.endswith(".ip6.arpa"):
                # IPv6 PTR parsing is complex, skip for now
                pass

        except Exception as e:
            self.logger.debug(f"DNS: PTR to IP parse error: {e}")

        return None

    def harvest(self) -> Dict[str, Any]:
        """Return DNS hostname data for the scanner pipeline.

        Custom info tables (hostname mappings, servers, clients) are kept.
        Interaction tables and credential tables are built centrally by the scanner.
        """
        mappings = self.hostname_mappings
        servers = self.dns_servers
        clients = self.dns_clients

        if not mappings and not servers and not clients:
            return {}

        tables: List[Dict[str, Any]] = []

        # Hostname mappings table
        if mappings:
            mapping_rows = []
            for hostname in sorted(mappings.keys()):
                ips = mappings[hostname]
                ips_str = ", ".join(ips)
                mapping_rows.append([hostname, ips_str])
            tables.append(
                {
                    "headers": ["Hostname", "IP Addresses"],
                    "rows": mapping_rows,
                    "title": f"DNS Hostname Mappings ({len(mappings)})",
                }
            )

        # DNS servers table
        if servers:
            srv_rows = []
            for server_ip, info in servers.items():
                srv_rows.append([server_ip, info.get("response_count", 0)])
            tables.append(
                {
                    "headers": ["Server IP", "Responses"],
                    "rows": srv_rows,
                    "title": f"DNS Servers ({len(srv_rows)})",
                }
            )

        # DNS clients table (query-only traffic)
        if clients:
            query_names: List[str] = []
            for dev in self.discovered_devices.values():
                if hasattr(dev, "dns_passive_data") and dev.dns_passive_data:
                    query_names.extend(dev.dns_passive_data.get("queries", []))
            unique_queries = sorted(set(query_names))
            if unique_queries:
                client_rows = []
                for client_ip, info in clients.items():
                    client_rows.append([client_ip, info.get("query_count", 0)])
                tables.append(
                    {
                        "headers": ["Client IP", "Queries"],
                        "rows": client_rows,
                        "title": f"DNS Clients ({len(client_rows)})",
                    }
                )

        results: Dict[str, Any] = {
            "dns": {
                "hostname_mappings": mappings,
                "dns_servers": list(servers.keys()),
                "dns_clients": list(clients.keys()),
                "total_hostnames": len(mappings),
            },
            "protocols_used_append": ["dns"],
        }

        return {
            "tables": tables,
            "results": results,
        }
